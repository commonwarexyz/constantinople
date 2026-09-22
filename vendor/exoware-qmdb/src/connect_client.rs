use crate::request::{validate_key_range, OperationWindow};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::marker::PhantomData;
use std::num::NonZeroU64;
use std::sync::Arc;

use crate::proto::qmdb::v1::{
    current_key_lookup_result, CurrentKeyExclusionProof as ProtoCurrentKeyExclusionProof,
    CurrentKeyValueProof as ProtoCurrentKeyValueProof,
    CurrentOperationRangeProof as ProtoCurrentOperationRangeProof, CurrentOperationServiceClient,
    GetCurrentOperationRangeRequest, GetManyRequest, GetOperationRangeRequest, GetRangeRequest,
    GetRangeResponse, GetRequest, HistoricalMultiProof, HistoricalOperationRangeProof,
    KeyLookupServiceClient, OperationLogServiceClient, OrderedKeyRangeServiceClient,
    SubscribeRequest, SubscribeResponseView,
};
use bytes::Bytes;
use commonware_codec::{Decode, DecodeExt, Encode, Read};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::{
    merkle::{Family, Graftable, Location, Proof},
    qmdb::{
        any::{
            ordered, unordered,
            value::{ValueEncoding, VariableEncoding},
        },
        current::ordered::proof::constant::ExclusionProof,
        current::proof::{OpsRootWitness, RangeProof, constant::OperationProof},
        operation::{Key as QmdbKey, Operation},
        sync::{
            FeedbackTx, Request as SyncRequest, Response as SyncResponse, Source,
            Target as SyncTarget,
        },
        verify::{verify_multi_proof, verify_proof_and_pinned_nodes},
    },
};
use commonware_utils::range::NonEmptyRange;
use connectrpc::client::{ClientConfig, ClientTransport, ServerStream};
use connectrpc::ConnectError;
use exoware_sdk::proto::PreferZstdHttpClient;
use exoware_sdk::ClientError;
use http_body::Body;

use crate::codec::decode_digest;
use crate::proof::{
    verify_ordered_exclusion_proof, VerifiedKeyLookup, VerifiedKeyRange, VerifiedKeyValue,
};
use crate::QmdbError;

#[derive(Clone)]
pub struct OrderedConnectClient<
    T,
    F: Graftable,
    H: Hasher,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> where
    ordered::Operation<F, K, E>: Read,
    ordered::Update<K, E>: Read,
{
    rpc: KeyLookupServiceClient<T>,
    range_rpc: OrderedKeyRangeServiceClient<T>,
    op_cfg: Arc<<ordered::Operation<F, K, E> as Read>::Cfg>,
    update_cfg: Arc<<ordered::Update<K, E> as Read>::Cfg>,
    key_cfg: Arc<K::Cfg>,
    value_cfg: Arc<V::Cfg>,
    _marker: PhantomData<(F, H, K, V, E)>,
}

impl<F, H, K, V, const N: usize, E> OrderedConnectClient<PreferZstdHttpClient, F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    ordered::Operation<F, K, E>: Decode + Encode + Read,
    ordered::Update<K, E>: Read,
    ExclusionProof<F, K, E, H::Digest, N>:
        Read<Cfg = (usize, <ordered::Update<K, E> as Read>::Cfg, V::Cfg)>,
{
    pub fn plaintext(
        base: &str,
        op_cfg: <ordered::Operation<F, K, E> as Read>::Cfg,
        update_cfg: <ordered::Update<K, E> as Read>::Cfg,
        key_cfg: K::Cfg,
        value_cfg: V::Cfg,
    ) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            op_cfg,
            update_cfg,
            key_cfg,
            value_cfg,
        )
    }
}

impl<T, F, H, K, V, const N: usize, E> OrderedConnectClient<T, F, H, K, V, N, E>
where
    T: ClientTransport + Clone,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    ordered::Operation<F, K, E>: Decode + Encode + Read,
    ordered::Update<K, E>: Read,
    ExclusionProof<F, K, E, H::Digest, N>:
        Read<Cfg = (usize, <ordered::Update<K, E> as Read>::Cfg, V::Cfg)>,
{
    pub fn new(
        transport: T,
        config: ClientConfig,
        op_cfg: <ordered::Operation<F, K, E> as Read>::Cfg,
        update_cfg: <ordered::Update<K, E> as Read>::Cfg,
        key_cfg: K::Cfg,
        value_cfg: V::Cfg,
    ) -> Self {
        Self::from_service_clients(
            KeyLookupServiceClient::new(transport.clone(), config.clone()),
            OrderedKeyRangeServiceClient::new(transport, config),
            op_cfg,
            update_cfg,
            key_cfg,
            value_cfg,
        )
    }

    pub fn from_service_clients(
        rpc: KeyLookupServiceClient<T>,
        range_rpc: OrderedKeyRangeServiceClient<T>,
        op_cfg: <ordered::Operation<F, K, E> as Read>::Cfg,
        update_cfg: <ordered::Update<K, E> as Read>::Cfg,
        key_cfg: K::Cfg,
        value_cfg: V::Cfg,
    ) -> Self {
        Self {
            rpc,
            range_rpc,
            op_cfg: Arc::new(op_cfg),
            update_cfg: Arc::new(update_cfg),
            key_cfg: Arc::new(key_cfg),
            value_cfg: Arc::new(value_cfg),
            _marker: PhantomData,
        }
    }

    pub async fn get(
        &self,
        request: GetRequest,
        expected_root: &H::Digest,
    ) -> Result<VerifiedKeyValue<H::Digest, ordered::Operation<F, K, E>, F>, QmdbError> {
        let requested_key = request.key.clone();
        let decoded_requested_key = K::decode_cfg(
            commonware_codec::Copying(requested_key.as_slice()),
            self.key_cfg.as_ref(),
        )
            .map_err(|err| {
                QmdbError::CorruptData(format!("failed to decode requested QMDB key: {err}"))
            })?;
        let response = self
            .rpc
            .get(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        let proof = response
            .proof
            .as_option()
            .ok_or_else(|| QmdbError::CorruptData("qmdb get response missing proof".to_string()))?;
        let verified = verify_key_value_from_proto::<F, H, ordered::Operation<F, K, E>, N>(
            proof,
            expected_root,
            self.op_cfg.as_ref(),
        )?;
        let ordered::Operation::Update(update) = &verified.operation else {
            return Err(QmdbError::CorruptData(
                "qmdb get proof did not verify an update".to_string(),
            ));
        };
        if update.key != decoded_requested_key {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentKeyValue,
            });
        }
        Ok(verified)
    }

    pub async fn get_many(
        &self,
        request: GetManyRequest,
        expected_root: &H::Digest,
    ) -> Result<Vec<VerifiedKeyLookup<H::Digest, K, V, F, E>>, QmdbError> {
        let requested_keys = request.keys.clone();
        let mut requested = BTreeSet::<&[u8]>::new();
        for key in &requested_keys {
            if !requested.insert(key.as_ref()) {
                return Err(QmdbError::DuplicateRequestedKey { key: key.clone() });
            }
        }
        let response = self
            .rpc
            .get_many(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        if response.results.len() != requested_keys.len() {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentKeyValue,
            });
        }
        response
            .results
            .iter()
            .zip(requested_keys.iter())
            .map(|(result, requested_key)| {
                let decoded_requested_key = K::decode_cfg(
                    commonware_codec::Copying(requested_key.as_slice()),
                    self.key_cfg.as_ref(),
                )
                .map_err(|err| {
                    QmdbError::CorruptData(format!("failed to decode requested QMDB key: {err}"))
                })?;
                match result.result.as_ref() {
                    Some(current_key_lookup_result::Result::Hit(proof)) => {
                        let verified =
                            verify_key_value_from_proto::<F, H, ordered::Operation<F, K, E>, N>(
                                proof,
                                expected_root,
                                self.op_cfg.as_ref(),
                            )?;
                        let ordered::Operation::Update(update) = &verified.operation else {
                            return Err(QmdbError::CorruptData(
                                "qmdb get_many hit proof did not verify an update".to_string(),
                            ));
                        };
                        if update.key != decoded_requested_key {
                            return Err(QmdbError::ProofVerification {
                                kind: crate::ProofKind::CurrentKeyValue,
                            });
                        }
                        Ok(VerifiedKeyLookup::Hit(verified))
                    }
                    Some(current_key_lookup_result::Result::Miss(proof)) => {
                        verify_key_exclusion_from_proto::<F, H, K, V, N, E>(
                            proof,
                            requested_key.as_slice(),
                            expected_root,
                            self.update_cfg.as_ref(),
                            self.key_cfg.as_ref(),
                            self.value_cfg.as_ref(),
                        )?;
                        Ok(VerifiedKeyLookup::Miss {
                            key: Bytes::from(requested_key.clone()),
                        })
                    }
                    None => Err(QmdbError::CorruptData(
                        "qmdb get_many result missing hit/miss proof".to_string(),
                    )),
                }
            })
            .collect()
    }

    pub async fn get_range(
        &self,
        request: GetRangeRequest,
        expected_root: &H::Digest,
    ) -> Result<VerifiedKeyRange<H::Digest, K, V, F, E>, QmdbError> {
        let start_key = request.start_key.clone();
        let end_key = request.end_key.clone();
        let limit = request.limit;
        let response = self
            .range_rpc
            .get_range(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        verify_get_range_from_proto::<F, H, K, V, N, E>(
            &response,
            expected_root,
            start_key.as_ref(),
            end_key.as_deref(),
            limit,
            self.op_cfg.as_ref(),
            self.update_cfg.as_ref(),
            self.key_cfg.as_ref(),
            self.value_cfg.as_ref(),
        )
    }
}

#[derive(Clone)]
pub struct UnorderedConnectClient<
    T,
    F: Graftable,
    H: Hasher,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> where
    unordered::Operation<F, K, E>: Read,
{
    rpc: KeyLookupServiceClient<T>,
    op_cfg: Arc<<unordered::Operation<F, K, E> as Read>::Cfg>,
    _marker: PhantomData<(F, H, K, V, E)>,
}

impl<F, H, K, V, const N: usize, E> UnorderedConnectClient<PreferZstdHttpClient, F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Decode + Encode + Read,
{
    pub fn plaintext(base: &str, op_cfg: <unordered::Operation<F, K, E> as Read>::Cfg) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            op_cfg,
        )
    }
}

impl<T, F, H, K, V, const N: usize, E> UnorderedConnectClient<T, F, H, K, V, N, E>
where
    T: ClientTransport + Clone,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Decode + Encode + Read,
{
    pub fn new(
        transport: T,
        config: ClientConfig,
        op_cfg: <unordered::Operation<F, K, E> as Read>::Cfg,
    ) -> Self {
        Self::from_service_client(KeyLookupServiceClient::new(transport, config), op_cfg)
    }

    pub fn from_service_client(
        rpc: KeyLookupServiceClient<T>,
        op_cfg: <unordered::Operation<F, K, E> as Read>::Cfg,
    ) -> Self {
        Self {
            rpc,
            op_cfg: Arc::new(op_cfg),
            _marker: PhantomData,
        }
    }

    pub async fn get(
        &self,
        request: GetRequest,
        expected_root: &H::Digest,
    ) -> Result<VerifiedKeyValue<H::Digest, unordered::Operation<F, K, E>, F>, QmdbError> {
        let requested_key = request.key.clone();
        let response = self
            .rpc
            .get(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        let proof = response
            .proof
            .as_option()
            .ok_or_else(|| QmdbError::CorruptData("qmdb get response missing proof".to_string()))?;
        verify_unordered_key_value_from_proto::<F, H, K, V, N, E>(
            proof,
            requested_key.as_slice(),
            expected_root,
            self.op_cfg.as_ref(),
        )
    }

    pub async fn get_many(
        &self,
        request: GetManyRequest,
        expected_root: &H::Digest,
    ) -> Result<Vec<VerifiedKeyValue<H::Digest, unordered::Operation<F, K, E>, F>>, QmdbError> {
        let requested_keys = request.keys.clone();
        let response = self
            .rpc
            .get_many(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        let mut requested = BTreeMap::<&[u8], usize>::new();
        for (index, key) in requested_keys.iter().enumerate() {
            if requested.insert(key.as_ref(), index).is_some() {
                return Err(QmdbError::DuplicateRequestedKey { key: key.clone() });
            }
        }
        let mut last_index = None;
        response
            .results
            .iter()
            .map(|result| {
                let verified = match result.result.as_ref() {
                    Some(current_key_lookup_result::Result::Hit(proof)) => {
                        verify_key_value_from_proto::<F, H, unordered::Operation<F, K, E>, N>(
                            proof,
                            expected_root,
                            self.op_cfg.as_ref(),
                        )?
                    }
                    Some(current_key_lookup_result::Result::Miss(_)) => {
                        return Err(QmdbError::CorruptData(
                            "unordered get_many response must not include miss proofs".to_string(),
                        ));
                    }
                    None => {
                        return Err(QmdbError::CorruptData(
                            "qmdb get_many result missing hit proof".to_string(),
                        ));
                    }
                };
                let unordered::Operation::Update(update) = &verified.operation else {
                    return Err(QmdbError::ProofVerification {
                        kind: crate::ProofKind::CurrentKeyValue,
                    });
                };
                let key = update.0.encode();
                let Some(&request_index) = requested.get(key.as_ref()) else {
                    return Err(QmdbError::ProofVerification {
                        kind: crate::ProofKind::CurrentKeyValue,
                    });
                };
                if last_index.is_some_and(|last| request_index <= last) {
                    return Err(QmdbError::ProofVerification {
                        kind: crate::ProofKind::CurrentKeyValue,
                    });
                }
                last_index = Some(request_index);
                Ok(verified)
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct OperationLogSubscribeProof<D: Digest, Op, F: Family> {
    pub resume_sequence_number: u64,
    pub tip: Location<F>,
    pub root: D,
    pub operations: Vec<(Location<F>, Op)>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OperationLogRangeProof<D: Digest, Op, F: Family> {
    /// Highest Store sequence observed while building the proof. Not authenticated by the root.
    pub sequence_number: u64,
    pub tip: Location<F>,
    pub root: D,
    pub start_location: Location<F>,
    pub operations: Vec<Op>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CurrentOperationRangeProof<D: Digest, Op, const N: usize, F: Graftable> {
    pub tip: Location<F>,
    pub root: D,
    pub start_location: Location<F>,
    pub operations: Vec<Op>,
    pub chunks: Vec<[u8; N]>,
}

impl<T, F, H, Op> Source for OperationLogClient<T, F, H, Op>
where
    T: ClientTransport + Clone + Send + Sync + 'static,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    F: Graftable + Send + Sync + 'static,
    H: Hasher + Send + Sync + 'static,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read + Send + Sync + 'static,
{
    type Family = F;
    type Digest = H::Digest;
    type Op = Op;
    type Error = QmdbError;

    async fn serve(
        &self,
        request: SyncRequest<Self::Family>,
    ) -> Result<
        (
            SyncResponse<Self::Family, Self::Op, Self::Digest>,
            FeedbackTx,
        ),
        Self::Error,
    > {
        let proto = self
            .operation_range_proto(request.size(), request.start(), request.max_ops())
            .await?;
        Ok((self.decode_sync_response(proto, request)?, None))
    }
}

pub struct OperationLogSubscription<B, F: Graftable, H: Hasher, Op: Decode + Encode + Read> {
    stream: ServerStream<B, SubscribeResponseView<'static>>,
    op_cfg: Arc<Op::Cfg>,
    _marker: PhantomData<(F, H, Op)>,
}

impl<B, F, H, Op> OperationLogSubscription<B, F, H, Op>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Display,
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read,
{
    pub async fn message_with_root<R>(
        &mut self,
        root_for_tip: R,
    ) -> Result<Option<OperationLogSubscribeProof<H::Digest, Op, F>>, QmdbError>
    where
        R: FnOnce(Location<F>) -> Result<H::Digest, QmdbError>,
    {
        let Some(frame) = self.stream.message().await.map_err(connect_error_to_qmdb)? else {
            return Ok(None);
        };
        let frame = frame.to_owned_message();
        let proof = frame.proof.as_option().ok_or_else(|| {
            QmdbError::CorruptData("qmdb subscribe response missing proof".to_string())
        })?;
        let max_digests = proof_digest_cap::<H::Digest>(&proof.proof);
        let merkle_proof = Proof::<F, H::Digest>::decode_cfg(
            commonware_codec::Copying(proof.proof.as_ref()),
            &max_digests,
        )
            .map_err(|err| {
                QmdbError::CorruptData(format!("failed to decode historical multi proof: {err}"))
            })?;
        let tip = merkle_proof.leaves.checked_sub(1).ok_or_else(|| {
            QmdbError::CorruptData("subscription proof has no leaves".to_string())
        })?;
        let expected_root = root_for_tip(tip)?;
        let (root, operations) = verify_multi_from_proto::<F, H, Op>(
            proof,
            &merkle_proof,
            self.op_cfg.as_ref(),
            &expected_root,
        )?;
        Ok(Some(OperationLogSubscribeProof {
            resume_sequence_number: frame.resume_sequence_number,
            tip,
            root,
            operations,
        }))
    }
}

/// Client for `qmdb.v1.CurrentOperationService`, parameterized on the Merkle
/// family and current-state operation type.
#[derive(Clone)]
pub struct CurrentOperationClient<T, F: Graftable, H: Hasher, Op: Encode + Read, const N: usize> {
    rpc: CurrentOperationServiceClient<T>,
    op_cfg: Arc<Op::Cfg>,
    _marker: PhantomData<(F, H, Op)>,
}

impl<F, H, Op, const N: usize> CurrentOperationClient<PreferZstdHttpClient, F, H, Op, N>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read,
{
    pub fn plaintext(base: &str, op_cfg: Op::Cfg) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            op_cfg,
        )
    }
}

impl<T, F, H, Op, const N: usize> CurrentOperationClient<T, F, H, Op, N>
where
    T: ClientTransport,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read,
{
    pub fn new(transport: T, config: ClientConfig, op_cfg: Op::Cfg) -> Self {
        Self::from_service_client(
            CurrentOperationServiceClient::new(transport, config),
            op_cfg,
        )
    }

    pub fn from_service_client(rpc: CurrentOperationServiceClient<T>, op_cfg: Op::Cfg) -> Self {
        Self {
            rpc,
            op_cfg: Arc::new(op_cfg),
            _marker: PhantomData,
        }
    }

    pub async fn get_current_operation_range(
        &self,
        request: GetCurrentOperationRangeRequest,
        expected_root: &H::Digest,
    ) -> Result<CurrentOperationRangeProof<H::Digest, Op, N, F>, QmdbError> {
        let tip = Location::<F>::new(request.tip);
        let window =
            OperationWindow::new(request.tip, request.start_location, request.max_locations)?;
        let response = self
            .rpc
            .get_current_operation_range(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        let proof = response.proof.as_option().ok_or_else(|| {
            QmdbError::CorruptData(
                "qmdb get_current_operation_range response missing proof".to_string(),
            )
        })?;
        let (root, operations, chunks) = verify_current_operation_range_from_proto::<F, H, Op, N>(
            proof,
            self.op_cfg.as_ref(),
            expected_root,
            window,
        )?;
        Ok(CurrentOperationRangeProof {
            tip,
            root,
            start_location: Location::<F>::new(proof.start_location),
            operations,
            chunks,
        })
    }
}

/// Client for `qmdb.v1.OperationLogService`, parameterized on the Merkle
/// family and backend operation type. Implements Commonware QMDB sync [`Source`].
/// Callers supply a target with an independently trusted operation-log root.
pub struct OperationLogClient<T, F: Graftable, H: Hasher, Op: Encode + Read> {
    rpc: OperationLogServiceClient<T>,
    op_cfg: Arc<Op::Cfg>,
    _marker: PhantomData<(F, H, Op)>,
}

impl<T, F, H, Op> Clone for OperationLogClient<T, F, H, Op>
where
    F: Graftable,
    H: Hasher,
    Op: Encode + Read,
    OperationLogServiceClient<T>: Clone,
{
    fn clone(&self) -> Self {
        Self {
            rpc: self.rpc.clone(),
            op_cfg: Arc::clone(&self.op_cfg),
            _marker: PhantomData,
        }
    }
}

impl<F, H, Op> OperationLogClient<PreferZstdHttpClient, F, H, Op>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read,
{
    pub fn plaintext(base: &str, op_cfg: Op::Cfg) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            op_cfg,
        )
    }
}

impl<T, F, H, Op> OperationLogClient<T, F, H, Op>
where
    T: ClientTransport,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read,
{
    pub fn new(transport: T, config: ClientConfig, op_cfg: Op::Cfg) -> Self {
        Self::from_service_client(OperationLogServiceClient::new(transport, config), op_cfg)
    }

    pub fn from_service_client(rpc: OperationLogServiceClient<T>, op_cfg: Op::Cfg) -> Self {
        Self {
            rpc,
            op_cfg: Arc::new(op_cfg),
            _marker: PhantomData,
        }
    }

    pub async fn get_operation_range(
        &self,
        request: GetOperationRangeRequest,
        expected_root: &H::Digest,
    ) -> Result<OperationLogRangeProof<H::Digest, Op, F>, QmdbError> {
        let tip = Location::<F>::new(request.tip);
        let window =
            OperationWindow::new(request.tip, request.start_location, request.max_locations)?;
        let (proof, sequence_number) = fetch_operation_range_proof(
            &self.rpc,
            request,
            "qmdb get_operation_range response missing proof",
        )
        .await?;
        let (root, operations) = verify_operation_range_from_proto::<F, H, Op>(
            &proof,
            self.op_cfg.as_ref(),
            expected_root,
            window,
        )?;
        Ok(OperationLogRangeProof {
            sequence_number,
            tip,
            root,
            start_location: Location::<F>::new(proof.start_location),
            operations,
        })
    }

    pub async fn subscribe(
        &self,
        request: SubscribeRequest,
    ) -> Result<OperationLogSubscription<T::ResponseBody, F, H, Op>, QmdbError> {
        let stream = self
            .rpc
            .subscribe(request)
            .await
            .map_err(connect_error_to_qmdb)?;
        Ok(OperationLogSubscription {
            stream,
            op_cfg: Arc::clone(&self.op_cfg),
            _marker: PhantomData,
        })
    }

    /// Derive a sync target by authenticating its operation root against a trusted current root
    pub async fn current_sync_target(
        &self,
        range: NonEmptyRange<Location<F>>,
        expected_current_root: &H::Digest,
    ) -> Result<SyncTarget<F, H::Digest>, QmdbError> {
        let proto = self
            .operation_range_proto(range.end(), range.start(), NonZeroU64::MIN)
            .await?;
        current_sync_target_from_witness::<F, H>(
            proto.ops_root.as_ref(),
            proto.ops_root_witness.as_ref(),
            expected_current_root,
            range,
        )
    }

    async fn operation_range_proto(
        &self,
        op_count: Location<F>,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<HistoricalOperationRangeProof, QmdbError> {
        let count = op_count.as_u64();
        let Some(tip) = count.checked_sub(1) else {
            return Err(QmdbError::CorruptData(
                "cannot fetch sync operations for an empty target".to_string(),
            ));
        };
        // The upstream maximum permits a smaller transport batch
        let max_locations = u32::try_from(max_ops.get()).unwrap_or(u32::MAX);
        let (proof, _) = fetch_operation_range_proof(
            &self.rpc,
            GetOperationRangeRequest {
                tip,
                start_location: start_loc.as_u64(),
                max_locations,
                ..Default::default()
            },
            "sync operation range response missing proof",
        )
        .await?;
        Ok(proof)
    }

    fn decode_sync_response(
        &self,
        proto: HistoricalOperationRangeProof,
        request: SyncRequest<F>,
    ) -> Result<SyncResponse<F, Op, H::Digest>, QmdbError> {
        let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
        let proof = Proof::<F, H::Digest>::decode_cfg(
            commonware_codec::Copying(proto.proof.as_ref()),
            &max_digests,
        ).map_err(
            |err| {
                QmdbError::CorruptData(format!(
                    "failed to decode sync operation range proof: {err}"
                ))
            },
        )?;
        let operations = proto
            .encoded_operations
            .iter()
            .map(|bytes| {
                Op::decode_cfg(commonware_codec::Copying(bytes.as_ref()), self.op_cfg.as_ref()).map_err(|err| {
                    QmdbError::CorruptData(format!("failed to decode sync operation: {err}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        match request {
            SyncRequest::Operations { .. } => Ok(SyncResponse::Operations { proof, operations }),
            SyncRequest::Boundary { .. } => {
                let [op] = operations.try_into().map_err(|operations: Vec<Op>| {
                    QmdbError::CorruptData(format!(
                        "sync boundary response contained {} operations instead of one",
                        operations.len()
                    ))
                })?;
                let pinned_nodes = proto
                    .pinned_nodes
                    .iter()
                    .map(|bytes| {
                        decode_digest::<H::Digest>(bytes.as_ref(), "operation sync pinned node")
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(SyncResponse::Boundary {
                    proof,
                    op,
                    pinned_nodes,
                })
            }
        }
    }
}

fn connect_error_to_qmdb(err: ConnectError) -> QmdbError {
    QmdbError::Client(ClientError::Rpc(Box::new(err)))
}

async fn fetch_operation_range_proof<T>(
    rpc: &OperationLogServiceClient<T>,
    request: GetOperationRangeRequest,
    missing_proof_message: &'static str,
) -> Result<(HistoricalOperationRangeProof, u64), QmdbError>
where
    T: ClientTransport,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
{
    let response = rpc
        .get_operation_range(request)
        .await
        .map_err(connect_error_to_qmdb)?
        .into_view()
        .to_owned_message();
    let proof = response
        .proof
        .as_option()
        .cloned()
        .ok_or_else(|| QmdbError::CorruptData(missing_proof_message.to_string()))?;
    Ok((proof, response.sequence_number))
}

fn proof_digest_cap<D: Digest>(encoded_proof: &[u8]) -> usize {
    encoded_proof.len() / D::SIZE + 1
}

/// Build the Commonware streaming-sync target for a current DB.
///
/// Current sync verifies fetched batches against the ops root, but Exoware
/// callers anchor trust in the canonical current root. The witness is the
/// bridge between those roots, so construct the sync target only after it
/// verifies.
fn current_sync_target_from_witness<F, H>(
    ops_root: &[u8],
    ops_root_witness: &[u8],
    current_root: &H::Digest,
    range: NonEmptyRange<Location<F>>,
) -> Result<SyncTarget<F, H::Digest>, QmdbError>
where
    F: Graftable,
    H::Digest: DecodeExt<()>,
    H: Hasher,
{
    let ops_root = decode_digest::<H::Digest>(ops_root, "current sync ops root")?;
    let witness = OpsRootWitness::<F, H::Digest>::decode(commonware_codec::Copying(ops_root_witness)).map_err(|err| {
        QmdbError::CorruptData(format!(
            "failed to decode current sync ops-root witness: {err}"
        ))
    })?;
    if !witness.verify::<H>(&ops_root, current_root) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::RangeCheckpoint,
        });
    }
    Ok(SyncTarget::new(ops_root, range))
}

fn historical_target_root<F, H>(
    ops_root: &[u8],
    ops_root_witness: &[u8],
    expected_root: &H::Digest,
) -> Result<H::Digest, QmdbError>
where
    F: Graftable,
    H::Digest: DecodeExt<()>,
    H: Hasher,
{
    if ops_root.is_empty() {
        return Err(QmdbError::CorruptData(
            "historical proof missing ops_root".to_string(),
        ));
    }
    let ops_root = decode_digest::<H::Digest>(ops_root, "historical ops root")?;
    if ops_root_witness.is_empty() {
        if ops_root != *expected_root {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::BatchMulti,
            });
        }
        return Ok(ops_root);
    }
    let witness = OpsRootWitness::<F, H::Digest>::decode(commonware_codec::Copying(ops_root_witness)).map_err(|err| {
        QmdbError::CorruptData(format!(
            "failed to decode historical ops-root witness: {err}"
        ))
    })?;
    if !witness.verify::<H>(&ops_root, expected_root) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::BatchMulti,
        });
    }
    Ok(ops_root)
}

fn verify_multi_from_proto<F, H, Op>(
    proto: &HistoricalMultiProof,
    proof: &Proof<F, H::Digest>,
    op_cfg: &Op::Cfg,
    root: &H::Digest,
) -> Result<(H::Digest, Vec<(Location<F>, Op)>), QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read,
{
    let operations = proto
        .operations
        .iter()
        .map(|op| {
            let decoded = Op::decode_cfg(
                commonware_codec::Copying(op.encoded_operation.as_ref()),
                op_cfg,
            ).map_err(|err| {
                QmdbError::CorruptData(format!(
                    "failed to decode multi-proof operation at {}: {err}",
                    op.location
                ))
            })?;
            Ok((Location::<F>::new(op.location), decoded))
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    let target_root =
        historical_target_root::<F, H>(&proto.ops_root, &proto.ops_root_witness, root)?;
    if !verify_multi_proof::<H, _, _>(proof, &operations, &target_root) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::BatchMulti,
        });
    }
    Ok((*root, operations))
}

fn verify_operation_range_from_proto<F, H, Op>(
    proto: &HistoricalOperationRangeProof,
    op_cfg: &Op::Cfg,
    root: &H::Digest,
    window: OperationWindow,
) -> Result<(H::Digest, Vec<Op>), QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read,
{
    if proto.encoded_operations.is_empty() {
        return Err(QmdbError::CorruptData(
            "historical operation range proof has no operations".to_string(),
        ));
    }
    let target_root =
        historical_target_root::<F, H>(&proto.ops_root, &proto.ops_root_witness, root)?;
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof =
        Proof::<F, H::Digest>::decode_cfg(
            commonware_codec::Copying(proto.proof.as_ref()),
            &max_digests,
        ).map_err(|err| {
            QmdbError::CorruptData(format!(
                "failed to decode historical operation range proof: {err}"
            ))
        })?;
    window
        .validate(
            proto.start_location,
            proto.encoded_operations.len(),
            proof.leaves.as_u64(),
        )
        .map_err(QmdbError::RangeMismatch)?;
    let start = Location::<F>::new(proto.start_location);
    let decoded_operations = proto
        .encoded_operations
        .iter()
        .map(|bytes| {
            let decoded = Op::decode_cfg(commonware_codec::Copying(bytes.as_ref()), op_cfg).map_err(|err| {
                QmdbError::CorruptData(format!("failed to decode operation range entry: {err}"))
            })?;
            Ok(decoded)
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    let pinned_nodes = proto
        .pinned_nodes
        .iter()
        .map(|bytes| {
            decode_digest::<H::Digest>(bytes.as_ref(), "historical operation range pinned node")
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    if !verify_proof_and_pinned_nodes::<H, _, _>(
        &proof,
        start,
        &decoded_operations,
        &pinned_nodes,
        &target_root,
    ) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::RangeCheckpoint,
        });
    }
    Ok((*root, decoded_operations))
}

fn verify_current_operation_range_from_proto<F, H, Op, const N: usize>(
    proto: &ProtoCurrentOperationRangeProof,
    op_cfg: &Op::Cfg,
    root: &H::Digest,
    window: OperationWindow,
) -> Result<(H::Digest, Vec<Op>, Vec<[u8; N]>), QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read,
{
    if proto.encoded_operations.is_empty() {
        return Err(QmdbError::CorruptData(
            "current operation range proof has no operations".to_string(),
        ));
    }
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = RangeProof::<F, H::Digest>::decode_cfg(
        commonware_codec::Copying(proto.proof.as_ref()),
        &max_digests,
    )
        .map_err(|err| {
            QmdbError::CorruptData(format!(
                "failed to decode current operation range proof: {err}"
            ))
        })?;
    window
        .validate(
            proto.start_location,
            proto.encoded_operations.len(),
            proof.proof.leaves.as_u64(),
        )
        .map_err(QmdbError::RangeMismatch)?;
    let start = Location::<F>::new(proto.start_location);
    let decoded_operations = proto
        .encoded_operations
        .iter()
        .map(|bytes| {
            let decoded = Op::decode_cfg(commonware_codec::Copying(bytes.as_ref()), op_cfg).map_err(|err| {
                QmdbError::CorruptData(format!(
                    "failed to decode current operation range entry: {err}"
                ))
            })?;
            Ok(decoded)
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    let chunks = proto
        .chunks
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            <[u8; N]>::decode(commonware_codec::Copying(bytes.as_ref())).map_err(|e| {
                QmdbError::CorruptData(format!(
                    "current operation range chunk {index} decode error: {e}"
                ))
            })
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    if !proof.verify::<H, _, N>(start, &decoded_operations, &chunks, root) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::CurrentRange,
        });
    }
    Ok((*root, decoded_operations, chunks))
}

fn verify_key_value_from_proto<F, H, Op, const N: usize>(
    proto: &ProtoCurrentKeyValueProof,
    root: &H::Digest,
    op_cfg: &Op::Cfg,
) -> Result<VerifiedKeyValue<H::Digest, Op, F>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: commonware_codec::Codec + Clone + Operation<F>,
{
    let operation = Op::decode_cfg(
        commonware_codec::Copying(proto.encoded_operation.as_ref()),
        op_cfg,
    ).map_err(|err| {
        QmdbError::CorruptData(format!(
            "failed to decode current key-value operation: {err}",
        ))
    })?;
    if !operation.is_update() {
        return Err(QmdbError::CorruptData(
            "current key-value proof operation must be an update".to_string(),
        ));
    }
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = OperationProof::<F, H::Digest, N>::decode_cfg(
        commonware_codec::Copying(proto.proof.as_ref()),
        &max_digests,
    )
        .map_err(|err| {
        QmdbError::CorruptData(format!("failed to decode current key-value proof: {err}"))
    })?;
    if !proof.verify::<H, _>(operation.clone(), root) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::CurrentKeyValue,
        });
    }
    Ok(VerifiedKeyValue {
        root: *root,
        location: proof.loc,
        operation,
    })
}

fn verify_unordered_key_value_from_proto<F, H, K, V, const N: usize, E>(
    proto: &ProtoCurrentKeyValueProof,
    requested_key: &[u8],
    root: &H::Digest,
    op_cfg: &<unordered::Operation<F, K, E> as Read>::Cfg,
) -> Result<VerifiedKeyValue<H::Digest, unordered::Operation<F, K, E>, F>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Decode + Encode + Read,
{
    let verified =
        verify_key_value_from_proto::<F, H, unordered::Operation<F, K, E>, N>(proto, root, op_cfg)?;
    if !matches!(&verified.operation, unordered::Operation::Update(update) if update.0.encode().as_ref() == requested_key)
    {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::CurrentKeyValue,
        });
    }
    Ok(verified)
}

/// Verify an exclusion proof and return the authenticated successor of the requested key
/// (`None` when the proof shows an empty database)
fn verify_key_exclusion_from_proto<F, H, K, V, const N: usize, E>(
    proto: &ProtoCurrentKeyExclusionProof,
    requested_key: &[u8],
    root: &H::Digest,
    update_cfg: &<ordered::Update<K, E> as Read>::Cfg,
    key_cfg: &K::Cfg,
    value_cfg: &V::Cfg,
) -> Result<Option<K>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    ordered::Operation<F, K, E>: Decode + Encode + Read,
    ordered::Update<K, E>: Read,
    ExclusionProof<F, K, E, H::Digest, N>:
        Read<Cfg = (usize, <ordered::Update<K, E> as Read>::Cfg, V::Cfg)>,
{
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = ExclusionProof::<F, K, E, H::Digest, N>::decode_cfg(
        commonware_codec::Copying(proto.proof.as_ref()),
        &(max_digests, update_cfg.clone(), value_cfg.clone()),
    )
    .map_err(|err| {
        QmdbError::CorruptData(format!(
            "failed to decode current key-exclusion proof: {err}"
        ))
    })?;
    let requested_key = K::decode_cfg(commonware_codec::Copying(requested_key), key_cfg).map_err(|err| {
        QmdbError::CorruptData(format!("failed to decode requested exclusion key: {err}"))
    })?;
    if !verify_ordered_exclusion_proof::<F, H, K, E, N>(&requested_key, &proof, root) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::CurrentKeyExclusion,
        });
    }
    Ok(match proof {
        ExclusionProof::KeyValue(_, update) => Some(update.next_key),
        ExclusionProof::Commit(_, _) => None,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_get_range_from_proto<F, H, K, V, const N: usize, E>(
    response: &GetRangeResponse,
    root: &H::Digest,
    start_key: &[u8],
    end_key: Option<&[u8]>,
    limit: u32,
    op_cfg: &<ordered::Operation<F, K, E> as Read>::Cfg,
    update_cfg: &<ordered::Update<K, E> as Read>::Cfg,
    key_cfg: &K::Cfg,
    value_cfg: &V::Cfg,
) -> Result<VerifiedKeyRange<H::Digest, K, V, F, E>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    ordered::Operation<F, K, E>: Decode + Encode + Read,
    ordered::Update<K, E>: Read,
    ExclusionProof<F, K, E, H::Digest, N>:
        Read<Cfg = (usize, <ordered::Update<K, E> as Read>::Cfg, V::Cfg)>,
{
    let encoded_start_key = start_key;
    let encoded_end_key = end_key;
    let start_key = K::decode_cfg(commonware_codec::Copying(encoded_start_key), key_cfg).map_err(|err| {
        QmdbError::CorruptData(format!("failed to decode range start key: {err}"))
    })?;
    let end_key = encoded_end_key
        .map(|key| {
            K::decode_cfg(commonware_codec::Copying(key), key_cfg).map_err(|err| {
                QmdbError::CorruptData(format!("failed to decode range end key: {err}"))
            })
        })
        .transpose()?;
    let mut entries = Vec::with_capacity(response.entries.len());
    for proof in &response.entries {
        entries.push(verify_key_value_from_proto::<
            F,
            H,
            ordered::Operation<F, K, E>,
            N,
        >(proof, root, op_cfg)?);
    }

    let keys = entries
        .iter()
        .map(|entry| match &entry.operation {
            ordered::Operation::Update(update) => (&update.key, &update.next_key),
            _ => unreachable!("range entries were checked as updates"),
        })
        .collect::<Vec<_>>();
    let start_successor = if keys.first().is_none_or(|(key, _)| **key != start_key) {
        let proof = response.start_proof.as_option().ok_or_else(|| {
            QmdbError::CorruptData("key range missing start boundary proof".into())
        })?;
        verify_key_exclusion_from_proto::<F, H, K, V, N, E>(
            proof,
            encoded_start_key,
            root,
            update_cfg,
            key_cfg,
            value_cfg,
        )?
    } else {
        None
    };
    let next_start_key = validate_key_range(
        &start_key,
        end_key.as_ref(),
        limit,
        &keys,
        start_successor.as_ref(),
    )
    .map_err(QmdbError::RangeMismatch)?
    .map(Encode::encode);

    Ok(VerifiedKeyRange {
        entries,
        next_start_key,
    })
}
