use std::marker::PhantomData;

use commonware_codec::{Codec, Decode, Encode, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::{Family, Graftable, Location},
    qmdb::{
        any::value::{ValueEncoding, VariableEncoding},
        keyless,
    },
};
use exoware_sdk::{PrefixedStoreClient, SerializableReadSession};

use crate::auth::{
    auth_inactive_peaks, compute_auth_root, load_auth_operation_at,
    load_auth_operation_bytes_range, read_latest_auth_watermark, require_published_auth_watermark,
};
use crate::codec::merkle_size_for_watermark;
use crate::connect::OperationKv;
use crate::core::retry_transient_post_ingest_query;
use crate::error::QmdbError;
use crate::proof::{OperationRangeCheckpoint, RawBatchMultiProof, VerifiedOperationRange};
use crate::storage::KvMerkleStorage;

pub struct KeylessClient<
    F: Family,
    H: Hasher,
    V: Codec + Send + Sync,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> where
    keyless::Operation<F, E>: CodecRead,
{
    client: PrefixedStoreClient,
    op_cfg: <keyless::Operation<F, E> as CodecRead>::Cfg,
    _marker: PhantomData<(F, H, E)>,
}

impl<F, H, V, E> Clone for KeylessClient<F, H, V, E>
where
    F: Family,
    H: Hasher,
    V: Codec + Send + Sync,
    E: ValueEncoding<Value = V>,
    keyless::Operation<F, E>: CodecRead,
{
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            op_cfg: self.op_cfg.clone(),
            _marker: PhantomData,
        }
    }
}

impl<F, H, V, E> std::fmt::Debug for KeylessClient<F, H, V, E>
where
    F: Family,
    H: Hasher,
    V: Codec + Send + Sync,
    E: ValueEncoding<Value = V>,
    keyless::Operation<F, E>: CodecRead,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeylessClient").finish_non_exhaustive()
    }
}

impl<F, H, V, E> KeylessClient<F, H, V, E>
where
    F: Graftable,
    H: Hasher,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    keyless::Operation<F, E>: Encode + Decode + Clone,
{
    /// Read client over `client`'s namespace prefix.
    pub fn new(
        client: PrefixedStoreClient,
        op_cfg: <keyless::Operation<F, E> as CodecRead>::Cfg,
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
        let op = keyless::Operation::<F, E>::decode_cfg(commonware_codec::Copying(bytes), &self.op_cfg).map_err(|e| {
            QmdbError::CorruptData(format!(
                "failed to decode keyless operation at location {location}: {e}"
            ))
        })?;
        let value = match &op {
            keyless::Operation::Append(value) => Some(value.as_ref().to_vec()),
            keyless::Operation::Commit(Some(value), _) => Some(value.as_ref().to_vec()),
            keyless::Operation::Commit(None, _) => None,
        };
        Ok(OperationKv { key: None, value })
    }

    pub async fn writer_location_watermark(&self) -> Result<Option<Location<F>>, QmdbError> {
        retry_transient_post_ingest_query(|| {
            let session = self.client.create_session();
            async move { read_latest_auth_watermark::<F>(&session).await }
        })
        .await
    }

    pub async fn root_at(&self, watermark: Location<F>) -> Result<H::Digest, QmdbError> {
        let session = self.client.create_session();
        require_published_auth_watermark(&session, watermark).await?;
        let inactive_peaks = self.inactive_peaks_at(&session, watermark).await?;
        compute_auth_root::<F, H>(&session, watermark, inactive_peaks).await
    }

    pub async fn get_at(
        &self,
        location: Location<F>,
        watermark: Location<F>,
    ) -> Result<Option<V>, QmdbError> {
        let session = self.client.create_session();
        require_published_auth_watermark(&session, watermark).await?;
        let count = watermark
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        if location >= count {
            return Err(QmdbError::RangeStartOutOfBounds {
                start: location.as_u64(),
                count: count.as_u64(),
            });
        }
        let operation =
            load_auth_operation_at::<F, keyless::Operation<F, E>>(&session, location, &self.op_cfg)
                .await?;
        Ok(operation.into_value())
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
        require_published_auth_watermark(&session, watermark).await?;
        let end = crate::proof::resolve_range_bounds(watermark, start_location, max_locations)?;
        let storage = KvMerkleStorage::<F, H::Digest> {
            session: &session,
            size: merkle_size_for_watermark(watermark)?,
            _marker: PhantomData::<H::Digest>,
        };
        let inactive_peaks = self.inactive_peaks_at(&session, watermark).await?;
        let root = compute_auth_root::<F, H>(&session, watermark, inactive_peaks).await?;
        let encoded_operations =
            load_auth_operation_bytes_range(&session, start_location, end).await?;
        let proof = crate::proof::build_operation_range_checkpoint::<F, H, _>(
            &storage,
            watermark,
            start_location,
            end,
            root,
            inactive_peaks,
            encoded_operations,
        )
        .await?;
        let sequence_number = session.evaluated_sequence().unwrap_or_default();
        Ok((proof, sequence_number))
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
        require_published_auth_watermark(&session, watermark).await?;
        let storage = KvMerkleStorage::<F, H::Digest> {
            session: &session,
            size: merkle_size_for_watermark(watermark)?,
            _marker: PhantomData::<H::Digest>,
        };
        let inactive_peaks = self.inactive_peaks_at(&session, watermark).await?;
        let root = compute_auth_root::<F, H>(&session, watermark, inactive_peaks).await?;
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
        let operation =
            load_auth_operation_at::<F, keyless::Operation<F, E>>(session, watermark, &self.op_cfg)
                .await?;
        let keyless::Operation::Commit(_, floor) = operation else {
            return Err(QmdbError::CorruptData(format!(
                "keyless watermark {watermark} does not point at a Commit operation"
            )));
        };
        auth_inactive_peaks(watermark, floor)
    }

    /// Verified contiguous range of operations.
    pub async fn operation_range_proof(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<VerifiedOperationRange<H::Digest, keyless::Operation<F, E>, F>, QmdbError> {
        let checkpoint = self
            .operation_range_checkpoint(watermark, start_location, max_locations)
            .await?;
        let operations = checkpoint
            .encoded_operations
            .iter()
            .enumerate()
            .map(|(offset, bytes)| {
                let location = checkpoint.start_location + offset as u64;
                keyless::Operation::<F, E>::decode_cfg(
                    commonware_codec::Copying(bytes.as_slice()),
                    &self.op_cfg,
                ).map_err(
                    |e| {
                        QmdbError::CorruptData(format!(
                            "failed to decode authenticated operation at location {location}: {e}"
                        ))
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(VerifiedOperationRange {
            root: checkpoint.root,
            start_location: checkpoint.start_location,
            operations,
        })
    }
}
