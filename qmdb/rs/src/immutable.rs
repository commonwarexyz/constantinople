use std::marker::PhantomData;

use commonware_codec::{Codec, Decode, Encode, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::{Family, Graftable, Location},
    qmdb::{
        any::value::{ValueEncoding, VariableEncoding},
        immutable,
        operation::Key as QmdbKey,
    },
};
use commonware_utils::Array;
use exoware_sdk::{Namespace, PrefixedStoreClient, SerializableReadSession, StoreClient};

use crate::auth::AuthenticatedBackendNamespace;
use crate::auth::{
    auth_inactive_peaks, compute_auth_root, decode_auth_immutable_update_location,
    load_auth_operation_at, load_auth_operation_bytes_range, load_latest_auth_immutable_update_row,
    read_latest_auth_watermark, require_published_auth_watermark,
};
use crate::codec::merkle_size_for_watermark;
use crate::connect::OperationKv;
use crate::core::retry_transient_post_ingest_query;
use crate::error::QmdbError;
use crate::proof::{OperationRangeCheckpoint, RawBatchMultiProof, VerifiedOperationRange};
use crate::storage::AuthKvMerkleStorage;
use crate::VersionedValue;

#[derive(Clone)]
pub struct ImmutableClient<
    F: Family,
    H: Hasher,
    K: QmdbKey + AsRef<[u8]>,
    V: Codec + Send + Sync,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> where
    immutable::Operation<F, K, E>: CodecRead,
{
    client: StoreClient,
    operation_cfg: <immutable::Operation<F, K, E> as CodecRead>::Cfg,
    _marker: PhantomData<(F, H, K, E)>,
}

impl<F, H, K, V, E> std::fmt::Debug for ImmutableClient<F, H, K, V, E>
where
    F: Family,
    H: Hasher,
    K: QmdbKey + AsRef<[u8]>,
    V: Codec + Send + Sync,
    E: ValueEncoding<Value = V>,
    immutable::Operation<F, K, E>: CodecRead,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImmutableClient").finish_non_exhaustive()
    }
}

impl<F, H, K, V, E> ImmutableClient<F, H, K, V, E>
where
    F: Graftable,
    H: Hasher,
    K: Array + Codec + Clone + AsRef<[u8]>,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    immutable::Operation<F, K, E>: Encode + Decode + Clone,
{
    pub fn new(
        url: &str,
        operation_cfg: <immutable::Operation<F, K, E> as CodecRead>::Cfg,
    ) -> Self {
        Self::from_client(StoreClient::new(url), operation_cfg)
    }

    /// Read client over the canonical [`Namespace::Qmdb`] keyspace (matches the
    /// writer default). Use [`Self::from_prefixed`] for a co-located QMDB log.
    pub fn from_client(
        client: StoreClient,
        operation_cfg: <immutable::Operation<F, K, E> as CodecRead>::Cfg,
    ) -> Self {
        Self::from_prefixed(client.for_namespace(Namespace::Qmdb), operation_cfg)
    }

    /// Read client over a caller-chosen namespace.
    pub fn from_prefixed(
        client: PrefixedStoreClient,
        operation_cfg: <immutable::Operation<F, K, E> as CodecRead>::Cfg,
    ) -> Self {
        Self::from_unprefixed(client.into_client(), operation_cfg)
    }

    /// Read client over a raw, un-namespaced client.
    pub fn from_unprefixed(
        client: StoreClient,
        operation_cfg: <immutable::Operation<F, K, E> as CodecRead>::Cfg,
    ) -> Self {
        Self {
            client,
            operation_cfg,
            _marker: PhantomData,
        }
    }

    pub(crate) fn store_client(&self) -> &StoreClient {
        &self.client
    }

    pub(crate) fn extract_operation_kv(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError>
    where
        V: AsRef<[u8]>,
    {
        let op = immutable::Operation::<F, K, E>::decode_cfg(bytes, &self.operation_cfg).map_err(
            |e| {
                QmdbError::CorruptData(format!(
                    "failed to decode immutable operation at location {location}: {e}"
                ))
            },
        )?;
        let key = op.key().map(|k| <K as AsRef<[u8]>>::as_ref(k).to_vec());
        let value = match &op {
            immutable::Operation::Set(_, value) => Some(value.as_ref().to_vec()),
            immutable::Operation::Commit(Some(value), _) => Some(value.as_ref().to_vec()),
            immutable::Operation::Commit(None, _) => None,
        };
        Ok(OperationKv { key, value })
    }

    pub async fn writer_location_watermark(&self) -> Result<Option<Location<F>>, QmdbError> {
        retry_transient_post_ingest_query(|| {
            let session = self.client.create_session();
            async move {
                read_latest_auth_watermark::<F>(&session, AuthenticatedBackendNamespace::Immutable)
                    .await
            }
        })
        .await
    }

    pub async fn root_at(&self, watermark: Location<F>) -> Result<H::Digest, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Immutable;
        let session = self.client.create_session();
        require_published_auth_watermark(&session, namespace, watermark).await?;
        let inactive_peaks = self.inactive_peaks_at(&session, watermark).await?;
        compute_auth_root::<F, H>(&session, namespace, watermark, inactive_peaks).await
    }

    pub async fn get_at(
        &self,
        key: &K,
        watermark: Location<F>,
    ) -> Result<Option<VersionedValue<K, V, F>>, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Immutable;
        let session = self.client.create_session();
        require_published_auth_watermark(&session, namespace, watermark).await?;
        let Some((row_key, _row_value)) =
            load_latest_auth_immutable_update_row(&session, watermark, key.as_ref()).await?
        else {
            return Ok(None);
        };
        let location = decode_auth_immutable_update_location::<F>(&row_key)?;
        let operation = load_auth_operation_at::<F, immutable::Operation<F, K, E>>(
            &session,
            namespace,
            location,
            &self.operation_cfg,
        )
        .await?;
        match operation {
            immutable::Operation::Set(operation_key, value) if operation_key == *key => {
                Ok(Some(VersionedValue {
                    key: operation_key,
                    location,
                    value: Some(value),
                }))
            }
            immutable::Operation::Set(_, _) => Err(QmdbError::CorruptData(format!(
                "authenticated immutable update row does not match operation key at location {location}"
            ))),
            immutable::Operation::Commit(_, _) => Err(QmdbError::CorruptData(format!(
                "authenticated immutable update row points at commit location {location}"
            ))),
        }
    }

    pub async fn operation_range_checkpoint(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<OperationRangeCheckpoint<H::Digest, F>, QmdbError> {
        let session = self.client.create_session();
        self.operation_range_checkpoint_in_session(
            &session,
            watermark,
            start_location,
            max_locations,
        )
        .await
    }

    pub(crate) async fn batch_multi_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location<F>,
        operations: Vec<(Location<F>, Vec<u8>)>,
    ) -> Result<RawBatchMultiProof<H::Digest, F>, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Immutable;
        let session = self
            .client
            .create_session_with_sequence(read_floor_sequence);
        require_published_auth_watermark(&session, namespace, watermark).await?;
        let storage = AuthKvMerkleStorage::<F, H::Digest> {
            session: &session,
            namespace,
            size: merkle_size_for_watermark(watermark)?,
            _marker: PhantomData::<H::Digest>,
        };
        let inactive_peaks = self.inactive_peaks_at(&session, watermark).await?;
        let root =
            compute_auth_root::<F, H>(&session, namespace, watermark, inactive_peaks).await?;
        crate::proof::build_batch_multi_proof::<F, H, _>(
            &storage,
            watermark,
            root,
            inactive_peaks,
            operations,
        )
        .await
    }

    async fn inactive_peaks_at(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
    ) -> Result<usize, QmdbError> {
        let operation = load_auth_operation_at::<F, immutable::Operation<F, K, E>>(
            session,
            AuthenticatedBackendNamespace::Immutable,
            watermark,
            &self.operation_cfg,
        )
        .await?;
        let immutable::Operation::Commit(_, floor) = operation else {
            return Err(QmdbError::CorruptData(format!(
                "immutable watermark {watermark} does not point at a Commit operation"
            )));
        };
        auth_inactive_peaks(watermark, floor)
    }

    async fn operation_range_checkpoint_in_session(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<OperationRangeCheckpoint<H::Digest, F>, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Immutable;
        require_published_auth_watermark(session, namespace, watermark).await?;
        let end = crate::proof::resolve_range_bounds(watermark, start_location, max_locations)?;
        let storage = AuthKvMerkleStorage::<F, H::Digest> {
            session,
            namespace,
            size: merkle_size_for_watermark(watermark)?,
            _marker: PhantomData::<H::Digest>,
        };
        let inactive_peaks = self.inactive_peaks_at(session, watermark).await?;
        let root = compute_auth_root::<F, H>(session, namespace, watermark, inactive_peaks).await?;
        let encoded_operations =
            load_auth_operation_bytes_range(session, namespace, start_location, end).await?;
        crate::proof::build_operation_range_checkpoint::<F, H, _>(
            &storage,
            watermark,
            start_location,
            end,
            root,
            inactive_peaks,
            encoded_operations,
        )
        .await
    }

    /// Verified contiguous range of operations.
    pub async fn operation_range_proof(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<VerifiedOperationRange<H::Digest, immutable::Operation<F, K, E>, F>, QmdbError>
    {
        let checkpoint = self
            .operation_range_checkpoint(watermark, start_location, max_locations)
            .await?;
        let operations = checkpoint
            .encoded_operations
            .iter()
            .enumerate()
            .map(|(offset, bytes)| {
                let location = checkpoint.start_location + offset as u64;
                immutable::Operation::<F, K, E>::decode_cfg(bytes.as_slice(), &self.operation_cfg)
                    .map_err(|e| {
                        QmdbError::CorruptData(format!(
                            "failed to decode authenticated operation at location {location}: {e}"
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(VerifiedOperationRange {
            root: checkpoint.root,
            start_location: checkpoint.start_location,
            operations,
        })
    }
}
