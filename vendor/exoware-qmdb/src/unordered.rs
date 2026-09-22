use std::collections::BTreeSet;
use std::marker::PhantomData;

use commonware_codec::{Codec, Decode, DecodeExt, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::merkle::{Graftable, Location};
use commonware_storage::qmdb::{
    any::{
        unordered,
        value::{ValueEncoding, VariableEncoding},
    },
    current::proof::{OpsRootWitness, RangeProof, constant::OperationProof},
    operation::{Key as QmdbKey, Operation as _},
};
use exoware_sdk::keys::Key;
use exoware_sdk::{PrefixedStoreClient, RangeMode, SerializableReadSession};

use crate::codec::{
    chunk_index_for_location, clear_below_floor, decode_current_boundary_metadata,
    decode_update_index_value_present, decode_update_location, encode_chunk_key,
    encode_current_meta_key, encode_ops_root_witness_key, merkle_size_for_watermark,
    op_count_for_watermark, CurrentBoundaryMetadata,
};
use crate::connect::OperationKv;
use crate::core::HistoricalOpsClientCore;
use crate::error::{error_key, QmdbError};
use crate::proof::{
    CurrentOperationRangeProofResult, OperationRangeCheckpoint, RawBatchMultiProof,
    RawKeyValueProof, VerifiedKeyValue, VerifiedOperationRange,
};
use crate::storage::{KvCurrentStorage, KvMerkleStorage, ProofBitmap};
use crate::VersionedValue;

#[derive(Clone)]
pub struct UnorderedClient<
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> where
    unordered::Operation<F, K, E>: commonware_codec::Read,
{
    client: PrefixedStoreClient,
    op_cfg: <unordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
    _marker: PhantomData<(F, H, K, E)>,
}

impl<
        F: Graftable,
        H: Hasher,
        K: QmdbKey + Codec,
        V: Codec + Clone + Send + Sync,
        E: ValueEncoding<Value = V>,
    > std::fmt::Debug for UnorderedClient<F, H, K, V, E>
where
    unordered::Operation<F, K, E>: commonware_codec::Read,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnorderedClient").finish_non_exhaustive()
    }
}

impl<F, H, K, V, E> crate::core::LatestValueResolver<F, K, V> for UnorderedClient<F, H, K, V, E>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Encode + Decode,
{
    async fn resolve_latest_value(
        &self,
        session: &SerializableReadSession,
        location: Location<F>,
        requested_key: &[u8],
    ) -> Result<VersionedValue<K, V, F>, QmdbError> {
        let (key, value) = match self.load_operation_at(session, location).await? {
            unordered::Operation::Update(update) => (update.0, Some(update.1)),
            unordered::Operation::Delete(key) => (key, None),
            unordered::Operation::CommitFloor(_, _) => {
                return Err(QmdbError::CorruptData(format!(
                    "latest update row at {location} points to a commit operation"
                )));
            }
        };
        if key.as_ref() != requested_key {
            return Err(QmdbError::CorruptData(format!(
                "latest update row at {location} points to a different key"
            )));
        }
        Ok(VersionedValue {
            key,
            location,
            value,
        })
    }
}

impl<F, H, K, V, E> UnorderedClient<F, H, K, V, E>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Encode + Decode,
{
    fn core(&self) -> HistoricalOpsClientCore<'_, F, H::Digest, K, V> {
        HistoricalOpsClientCore {
            client: &self.client,
            _marker: PhantomData,
        }
    }

    /// Read client over `client`'s namespace prefix.
    pub fn new(
        client: PrefixedStoreClient,
        op_cfg: <unordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
    ) -> Self {
        Self {
            client,
            op_cfg,
            _marker: PhantomData,
        }
    }

    pub(crate) fn store_client(&self) -> &PrefixedStoreClient {
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
        let op = unordered::Operation::<F, K, E>::decode_cfg(commonware_codec::Copying(bytes), &self.op_cfg).map_err(|e| {
            QmdbError::CorruptData(format!(
                "failed to decode unordered operation at location {location}: {e}"
            ))
        })?;
        let key = op.key().map(|k| <K as AsRef<[u8]>>::as_ref(k).to_vec());
        let value = match &op {
            unordered::Operation::Update(update) => Some(update.1.as_ref().to_vec()),
            unordered::Operation::CommitFloor(Some(value), _) => Some(value.as_ref().to_vec()),
            unordered::Operation::Delete(_) | unordered::Operation::CommitFloor(None, _) => None,
        };
        Ok(OperationKv { key, value })
    }

    pub async fn writer_location_watermark(&self) -> Result<Option<Location<F>>, QmdbError> {
        self.core().writer_location_watermark().await
    }

    pub async fn query_many_at<Q: AsRef<[u8]>>(
        &self,
        keys: &[Q],
        watermark: Location<F>,
    ) -> Result<Vec<Option<VersionedValue<K, V, F>>>, QmdbError> {
        self.core().query_many_at(keys, watermark, self).await
    }

    pub async fn root_at(&self, watermark: Location<F>) -> Result<H::Digest, QmdbError> {
        let session = self.client.create_session();
        self.core()
            .require_published_watermark(&session, watermark)
            .await?;
        self.compute_ops_root(&session, watermark).await
    }

    pub async fn current_root_at(&self, watermark: Location<F>) -> Result<H::Digest, QmdbError> {
        let session = self.client.create_session();
        self.core()
            .require_published_watermark(&session, watermark)
            .await?;
        self.core()
            .require_batch_boundary(&session, watermark)
            .await?;
        self.load_current_boundary_root(&session, watermark).await
    }

    pub async fn operation_range_checkpoint(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<OperationRangeCheckpoint<H::Digest, F>, QmdbError> {
        let (proof, _) = self
            .operation_range_checkpoint_with_read_floor(0, watermark, start_location, max_locations)
            .await?;
        Ok(proof)
    }

    pub(crate) async fn operation_range_checkpoint_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<(OperationRangeCheckpoint<H::Digest, F>, u64), QmdbError> {
        let session = self
            .client
            .create_session_with_sequence(read_floor_sequence);
        self.core()
            .require_published_watermark(&session, watermark)
            .await?;
        let end = crate::proof::resolve_range_bounds(watermark, start_location, max_locations)?;
        let storage = KvMerkleStorage::<F, H::Digest> {
            session: &session,
            size: merkle_size_for_watermark(watermark)?,
            _marker: PhantomData,
        };
        let inactive_peaks = self.ops_inactive_peaks_at(&session, watermark).await?;
        let root = self
            .core()
            .compute_ops_root_with_inactive_peaks::<H>(&session, watermark, inactive_peaks)
            .await?;
        let encoded_operations = self
            .core()
            .load_operation_bytes_range(&session, start_location, end)
            .await?;
        let mut checkpoint = crate::proof::build_operation_range_checkpoint::<F, H, _>(
            &storage,
            watermark,
            start_location,
            end,
            root,
            inactive_peaks,
            encoded_operations,
        )
        .await?;
        checkpoint.ops_root_witness = self.load_ops_root_witness(&session, watermark).await?;
        let sequence_number = session.evaluated_sequence().unwrap_or_default();
        Ok((checkpoint, sequence_number))
    }

    pub(crate) async fn batch_multi_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location<F>,
        operations: Vec<(Location<F>, Vec<u8>)>,
    ) -> Result<RawBatchMultiProof<H::Digest, F>, QmdbError> {
        let session = self
            .client
            .create_session_with_sequence(read_floor_sequence);
        self.core()
            .require_published_watermark(&session, watermark)
            .await?;
        let storage = KvMerkleStorage::<F, H::Digest> {
            session: &session,
            size: merkle_size_for_watermark(watermark)?,
            _marker: PhantomData,
        };
        let inactive_peaks = self.ops_inactive_peaks_at(&session, watermark).await?;
        let root = self
            .core()
            .compute_ops_root_with_inactive_peaks::<H>(&session, watermark, inactive_peaks)
            .await?;
        let mut proof = crate::proof::build_batch_multi_proof::<F, H, _>(
            &storage,
            watermark,
            root,
            inactive_peaks,
            operations,
        )
        .await?;
        proof.ops_root_witness = self.load_ops_root_witness(&session, watermark).await?;
        Ok(proof)
    }

    /// Verified contiguous range of operations.
    pub async fn operation_range_proof(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<VerifiedOperationRange<H::Digest, unordered::Operation<F, K, E>, F>, QmdbError>
    {
        let checkpoint = self
            .operation_range_checkpoint(watermark, start_location, max_locations)
            .await?;
        let mut operations = Vec::with_capacity(checkpoint.encoded_operations.len());
        for (offset, value) in checkpoint.encoded_operations.iter().enumerate() {
            let location = checkpoint.start_location + offset as u64;
            let op = unordered::Operation::<F, K, E>::decode_cfg(
                commonware_codec::Copying(value.as_slice()),
                &self.op_cfg,
            )
                .map_err(|e| {
                    QmdbError::CorruptData(format!(
                        "failed to decode unordered operation at location {location}: {e}"
                    ))
                })?;
            operations.push(op);
        }
        Ok(VerifiedOperationRange {
            root: checkpoint.root,
            start_location: checkpoint.start_location,
            operations,
        })
    }

    async fn current_operation_range_proof_raw_in_session<const N: usize>(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<
        CurrentOperationRangeProofResult<H::Digest, unordered::Operation<F, K, E>, N, F>,
        QmdbError,
    > {
        self.core()
            .require_published_watermark(session, watermark)
            .await?;
        self.core()
            .require_batch_boundary(session, watermark)
            .await?;
        let end = crate::proof::resolve_range_bounds(watermark, start_location, max_locations)?;
        let proof = self
            .build_current_range_proof::<N>(session, watermark, start_location, end)
            .await?;
        let root = self.load_current_boundary_root(session, watermark).await?;
        let operations = self
            .load_operation_range(session, start_location, end)
            .await?;
        let chunks = self
            .load_bitmap_chunks::<N>(session, watermark, start_location, end)
            .await?;
        let raw = CurrentOperationRangeProofResult {
            watermark,
            root,
            start_location,
            proof,
            operations,
            chunks,
        };
        if !raw.verify::<H>() {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentRange,
            });
        }
        Ok(raw)
    }

    /// Verified raw current-state proof for a contiguous operation range.
    pub async fn current_operation_range_proof_raw_at<const N: usize>(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<
        CurrentOperationRangeProofResult<H::Digest, unordered::Operation<F, K, E>, N, F>,
        QmdbError,
    > {
        let session = self.client.create_session();
        self.current_operation_range_proof_raw_in_session::<N>(
            &session,
            watermark,
            start_location,
            max_locations,
        )
        .await
    }

    async fn key_value_proof_raw_in_session<const N: usize, Q: AsRef<[u8]>>(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        key: Q,
    ) -> Result<RawKeyValueProof<H::Digest, unordered::Operation<F, K, E>, N, F>, QmdbError> {
        self.core()
            .require_published_watermark(session, watermark)
            .await?;
        self.core()
            .require_batch_boundary(session, watermark)
            .await?;

        let key_bytes = error_key(&key);
        let Some((row_key, row_value)) = self
            .load_latest_update_row(session, watermark, key.as_ref())
            .await?
        else {
            return Err(QmdbError::ProofKeyNotFound {
                watermark: watermark.as_u64(),
                key: key_bytes,
            });
        };
        let location = decode_update_location(&row_key)?;
        if !decode_update_index_value_present(row_value.as_ref())? {
            return Err(QmdbError::KeyNotActive {
                watermark: watermark.as_u64(),
                key: key_bytes.clone(),
            });
        }

        let operation = self.load_operation_at(session, location).await?;
        let unordered::Operation::Update(update) = &operation else {
            return Err(QmdbError::KeyNotActive {
                watermark: watermark.as_u64(),
                key: key_bytes,
            });
        };
        if update.0.as_ref() != key.as_ref() {
            return Err(QmdbError::CorruptData(format!(
                "latest active unordered key row at {location} points to a different key"
            )));
        }

        let root = self.load_current_boundary_root(session, watermark).await?;
        let proof = self
            .build_current_operation_proof::<N>(session, watermark, location)
            .await?;

        let raw = RawKeyValueProof {
            watermark,
            root,
            proof,
            operation,
        };
        if !raw.verify::<H>() {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentKeyValue,
            });
        }
        Ok(raw)
    }

    /// Verified raw current-state proof for a single active unordered key.
    pub async fn key_value_proof_raw_at<const N: usize, Q: AsRef<[u8]>>(
        &self,
        watermark: Location<F>,
        key: Q,
    ) -> Result<RawKeyValueProof<H::Digest, unordered::Operation<F, K, E>, N, F>, QmdbError> {
        let session = self.client.create_session();
        self.key_value_proof_raw_in_session::<N, _>(&session, watermark, key)
            .await
    }

    /// Verified current-state proof for a single active unordered key.
    pub async fn key_value_proof_at<const N: usize, Q: AsRef<[u8]>>(
        &self,
        watermark: Location<F>,
        key: Q,
    ) -> Result<VerifiedKeyValue<H::Digest, unordered::Operation<F, K, E>, F>, QmdbError> {
        let raw = self.key_value_proof_raw_at::<N, _>(watermark, key).await?;
        Ok(VerifiedKeyValue {
            root: raw.root,
            location: raw.proof.loc,
            operation: raw.operation,
        })
    }

    /// Verified current-state hit proofs for explicit active keys, preserving
    /// request order among returned hits. Unordered QMDB does not have
    /// missing-key exclusion proofs, so missing or inactive requested keys are
    /// omitted rather than proven.
    pub async fn key_lookup_proofs_raw_at<const N: usize, Q: AsRef<[u8]>>(
        &self,
        watermark: Location<F>,
        keys: &[Q],
    ) -> Result<Vec<RawKeyValueProof<H::Digest, unordered::Operation<F, K, E>, N, F>>, QmdbError>
    {
        if keys.is_empty() {
            return Err(QmdbError::EmptyProofRequest);
        }

        let session = self.client.create_session();
        let mut seen = BTreeSet::<Vec<u8>>::new();
        let mut proofs = Vec::with_capacity(keys.len());
        for key in keys {
            let key_bytes = error_key(key);
            if !seen.insert(key_bytes.clone()) {
                return Err(QmdbError::DuplicateRequestedKey { key: key_bytes });
            }
            match self
                .key_value_proof_raw_in_session::<N, _>(&session, watermark, key.as_ref())
                .await
            {
                Ok(proof) => proofs.push(proof),
                Err(QmdbError::ProofKeyNotFound { .. } | QmdbError::KeyNotActive { .. }) => {
                    continue;
                }
                Err(err) => return Err(err),
            }
        }
        Ok(proofs)
    }

    async fn load_current_boundary_metadata(
        &self,
        session: &SerializableReadSession,
        location: Location<F>,
    ) -> Result<CurrentBoundaryMetadata<H::Digest>, QmdbError> {
        let Some(bytes) = session.get(&encode_current_meta_key(location)).await? else {
            return Err(QmdbError::CurrentBoundaryStateMissing {
                location: location.as_u64(),
            });
        };
        decode_current_boundary_metadata::<H::Digest>(
            bytes.as_ref(),
            format!("current boundary metadata at {location}"),
        )
    }

    async fn load_current_boundary_root(
        &self,
        session: &SerializableReadSession,
        location: Location<F>,
    ) -> Result<H::Digest, QmdbError> {
        Ok(self
            .load_current_boundary_metadata(session, location)
            .await?
            .root)
    }

    async fn load_ops_root_witness(
        &self,
        session: &SerializableReadSession,
        location: Location<F>,
    ) -> Result<Option<OpsRootWitness<F, H::Digest>>, QmdbError> {
        let Some(bytes) = session.get(&encode_ops_root_witness_key(location)).await? else {
            return Ok(None);
        };
        OpsRootWitness::<F, H::Digest>::decode(commonware_codec::Copying(bytes.as_ref()))
            .map(Some)
            .map_err(|e| {
                QmdbError::CorruptData(format!(
                    "current ops-root witness at {location} decode error: {e}"
                ))
            })
    }

    async fn proof_bitmap<const N: usize>(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        inactivity_floor: Location<F>,
        location: Option<Location<F>>,
    ) -> Result<ProofBitmap<N>, QmdbError> {
        let metadata = self
            .load_current_boundary_metadata(session, watermark)
            .await?;
        ProofBitmap::load(watermark, metadata.pruned_chunks, location, |chunk| {
            self.load_bitmap_chunk_with_floor::<N>(session, watermark, inactivity_floor, chunk)
        })
        .await
    }

    async fn build_current_operation_proof<const N: usize>(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        location: Location<F>,
    ) -> Result<OperationProof<F, H::Digest, N>, QmdbError> {
        self.core()
            .require_published_watermark(session, watermark)
            .await?;
        self.core()
            .require_batch_boundary(session, watermark)
            .await?;
        let inactivity_floor = self.load_inactivity_floor_at(session, watermark).await?;
        let status = self
            .proof_bitmap::<N>(session, watermark, inactivity_floor, Some(location))
            .await?;
        let storage = KvCurrentStorage::<F, H, N> {
            session,
            watermark,
            pruned_chunks: status.pruned_chunks as u64,
            size: merkle_size_for_watermark(watermark)?,
            _marker: PhantomData,
        };
        OperationProof::new::<H, _>(
            &status,
            &storage,
            inactivity_floor,
            location,
            self.compute_ops_root(session, watermark).await?,
        )
        .await
        .map_err(crate::error::current_proof_error)
    }

    async fn build_current_range_proof<const N: usize>(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        start_location: Location<F>,
        end_location_exclusive: Location<F>,
    ) -> Result<RangeProof<F, H::Digest>, QmdbError> {
        let inactivity_floor = self.load_inactivity_floor_at(session, watermark).await?;
        let status = self
            .proof_bitmap::<N>(session, watermark, inactivity_floor, None)
            .await?;
        let storage = KvCurrentStorage::<F, H, N> {
            session,
            watermark,
            pruned_chunks: status.pruned_chunks as u64,
            size: merkle_size_for_watermark(watermark)?,
            _marker: PhantomData,
        };
        RangeProof::new::<H, _, N>(
            &status,
            &storage,
            inactivity_floor,
            start_location..end_location_exclusive,
            self.compute_ops_root(session, watermark).await?,
        )
        .await
        .map_err(crate::error::current_proof_error)
    }

    async fn load_inactivity_floor_at(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
    ) -> Result<Location<F>, QmdbError> {
        let operation = self.load_operation_at(session, watermark).await?;
        match operation {
            unordered::Operation::CommitFloor(_, floor) => Ok(floor),
            _ => Err(QmdbError::CorruptData(format!(
                "expected CommitFloor at watermark {watermark}"
            ))),
        }
    }

    async fn load_ops_inactivity_floor_at(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
    ) -> Result<Location<F>, QmdbError> {
        let mut location = watermark;
        loop {
            if let unordered::Operation::CommitFloor(_, floor) =
                self.load_operation_at(session, location).await?
            {
                return Ok(floor);
            }
            if *location == 0 {
                return Err(QmdbError::CorruptData(format!(
                    "no CommitFloor found at or before watermark {watermark}"
                )));
            }
            location -= 1;
        }
    }

    async fn compute_ops_root(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
    ) -> Result<H::Digest, QmdbError> {
        let inactive_peaks = self.ops_inactive_peaks_at(session, watermark).await?;
        self.core()
            .compute_ops_root_with_inactive_peaks::<H>(session, watermark, inactive_peaks)
            .await
    }

    async fn ops_inactive_peaks_at(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
    ) -> Result<usize, QmdbError> {
        let inactivity_floor = self
            .load_ops_inactivity_floor_at(session, watermark)
            .await?;
        Ok(F::inactive_peaks(
            op_count_for_watermark(watermark)?,
            inactivity_floor,
        ))
    }

    async fn load_bitmap_chunk_with_floor<const N: usize>(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        inactivity_floor: Location<F>,
        chunk_index: u64,
    ) -> Result<[u8; N], QmdbError> {
        let start = encode_chunk_key(chunk_index, Location::<F>::new(0));
        let end = encode_chunk_key(chunk_index, watermark);
        let rows = session
            .range_with_mode(&start, &end, 1, RangeMode::Reverse)
            .await?;
        let mut chunk = match rows.into_iter().next() {
            Some((_, bytes)) => <[u8; N]>::decode(commonware_codec::Copying(bytes.as_ref())).map_err(|e| {
                QmdbError::CorruptData(format!("bitmap chunk {chunk_index} decode error: {e}"))
            })?,
            None => {
                return Err(QmdbError::CorruptData(format!(
                    "missing bitmap chunk {chunk_index} at watermark {watermark}"
                )));
            }
        };
        clear_below_floor::<F, N>(&mut chunk, chunk_index, inactivity_floor);
        Ok(chunk)
    }

    async fn load_bitmap_chunks<const N: usize>(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        start_location: Location<F>,
        end_location_exclusive: Location<F>,
    ) -> Result<Vec<[u8; N]>, QmdbError> {
        let floor = self.load_inactivity_floor_at(session, watermark).await?;
        let start_chunk = chunk_index_for_location::<F, N>(start_location);
        let end_chunk = chunk_index_for_location::<F, N>(end_location_exclusive - 1);
        futures::future::try_join_all((start_chunk..=end_chunk).map(|chunk_index| {
            self.load_bitmap_chunk_with_floor::<N>(session, watermark, floor, chunk_index)
        }))
        .await
    }

    async fn load_operation_at(
        &self,
        session: &SerializableReadSession,
        location: Location<F>,
    ) -> Result<unordered::Operation<F, K, E>, QmdbError> {
        let bytes = self
            .core()
            .load_operation_bytes_at(session, location)
            .await?;
        unordered::Operation::<F, K, E>::decode_cfg(
            commonware_codec::Copying(bytes.as_slice()),
            &self.op_cfg,
        ).map_err(|e| {
            QmdbError::CorruptData(format!(
                "failed to decode unordered operation at location {location}: {e}"
            ))
        })
    }

    async fn load_operation_range(
        &self,
        session: &SerializableReadSession,
        start_location: Location<F>,
        end_location_exclusive: Location<F>,
    ) -> Result<Vec<unordered::Operation<F, K, E>>, QmdbError> {
        let rows = self
            .core()
            .load_operation_bytes_range(session, start_location, end_location_exclusive)
            .await?;
        rows.into_iter()
            .enumerate()
            .map(|(offset, bytes)| {
                let location = start_location + offset as u64;
                unordered::Operation::<F, K, E>::decode_cfg(
                    commonware_codec::Copying(bytes.as_slice()),
                    &self.op_cfg,
                ).map_err(
                    |e| {
                        QmdbError::CorruptData(format!(
                            "failed to decode unordered operation at location {location}: {e}"
                        ))
                    },
                )
            })
            .collect()
    }

    async fn load_latest_update_row(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        key: &[u8],
    ) -> Result<Option<(Key, Vec<u8>)>, QmdbError> {
        self.core()
            .load_latest_update_row(session, watermark, key)
            .await
    }
}
