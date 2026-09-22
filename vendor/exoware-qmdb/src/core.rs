use std::marker::PhantomData;
use std::time::Duration;

use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_storage::merkle::{
    hasher::Hasher as MerkleHasher, mem::Mem, Family, Location, Position,
};
use exoware_sdk::keys::Key;
use exoware_sdk::{ClientError, PrefixedStoreClient, RangeMode, SerializableReadSession};

use crate::codec::{
    decode_digest, decode_operation_location_key, decode_update_location,
    decode_watermark_location, encode_node_key, encode_operation_key, encode_presence_key,
    encode_update_key, encode_watermark_key, ensure_encoded_value_size, merkle_size_for_watermark,
    WATERMARK_PREFIX,
};
use crate::error::QmdbError;
use crate::VersionedValue;

const POST_INGEST_QUERY_RETRY_MAX_ATTEMPTS: usize = 6;
const POST_INGEST_QUERY_RETRY_INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const POST_INGEST_QUERY_RETRY_MAX_BACKOFF: Duration = Duration::from_millis(1_000);

pub(crate) fn is_transient_post_ingest_query_error(err: &QmdbError) -> bool {
    match err {
        QmdbError::Client(ClientError::Http(_)) => true,
        QmdbError::Client(err) => err.rpc_code().is_some_and(|code| {
            matches!(
                code,
                connectrpc::ErrorCode::Aborted
                    | connectrpc::ErrorCode::ResourceExhausted
                    | connectrpc::ErrorCode::Unavailable
            )
        }),
        _ => false,
    }
}

pub(crate) fn post_ingest_query_retry_backoff(attempt: usize) -> Duration {
    let exponent = (attempt.saturating_sub(1)).min(20) as u32;
    let factor = 1u128 << exponent;
    let base_ms = POST_INGEST_QUERY_RETRY_INITIAL_BACKOFF.as_millis();
    let capped_ms = base_ms
        .saturating_mul(factor)
        .min(POST_INGEST_QUERY_RETRY_MAX_BACKOFF.as_millis());
    Duration::from_millis(capped_ms.min(u64::MAX as u128) as u64)
}

pub(crate) async fn retry_transient_post_ingest_query<F, Fut, T>(mut op: F) -> Result<T, QmdbError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, QmdbError>>,
{
    let mut attempt = 1usize;
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err)
                if attempt < POST_INGEST_QUERY_RETRY_MAX_ATTEMPTS
                    && is_transient_post_ingest_query_error(&err) =>
            {
                tokio::time::sleep(post_ingest_query_retry_backoff(attempt)).await;
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct HistoricalOpsClientCore<'a, F: Family, D: Digest, K: Codec, V: Codec> {
    pub(crate) client: &'a PrefixedStoreClient,
    pub(crate) _marker: PhantomData<(F, D, K, V)>,
}

/// Maps the operation recorded at an update-index row's location into a
/// `VersionedValue`, verifying it matches the requested key. Each QMDB variant
/// loads and matches its own operation enum. The shared scan-and-await pipeline
/// lives in [`HistoricalOpsClientCore::query_many_at`].
pub(crate) trait LatestValueResolver<F: Family, K: Codec, V: Codec> {
    fn resolve_latest_value(
        &self,
        session: &SerializableReadSession,
        location: Location<F>,
        requested_key: &[u8],
    ) -> impl std::future::Future<Output = Result<VersionedValue<K, V, F>, QmdbError>>;
}

impl<'a, F: Family, D: Digest, K: Codec, V: Codec> HistoricalOpsClientCore<'a, F, D, K, V> {
    pub(crate) async fn writer_location_watermark(&self) -> Result<Option<Location<F>>, QmdbError> {
        retry_transient_post_ingest_query(|| {
            let session = self.client.create_session();
            async move { self.read_latest_watermark(&session).await }
        })
        .await
    }

    pub(crate) async fn read_latest_watermark(
        &self,
        session: &SerializableReadSession,
    ) -> Result<Option<Location<F>>, QmdbError> {
        let (start, end) = WATERMARK_PREFIX.bounds();
        let rows = session
            .range_with_mode(&start, &end, 1, RangeMode::Reverse)
            .await?;
        match rows.into_iter().next() {
            Some((key, _)) => Ok(Some(decode_watermark_location(&key)?)),
            None => Ok(None),
        }
    }

    pub(crate) async fn require_published_watermark(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
    ) -> Result<(), QmdbError> {
        let available = self
            .read_latest_watermark(session)
            .await?
            .unwrap_or(Location::new(0));
        let watermark_exists = session
            .get(&encode_watermark_key(watermark))
            .await?
            .is_some();
        if available < watermark
            || (!watermark_exists && available == Location::new(0) && watermark == Location::new(0))
        {
            return Err(QmdbError::WatermarkTooLow {
                requested: watermark.as_u64(),
                available: available.as_u64(),
            });
        }
        Ok(())
    }

    pub(crate) async fn require_batch_boundary(
        &self,
        session: &SerializableReadSession,
        location: Location<F>,
    ) -> Result<(), QmdbError> {
        if session.get(&encode_presence_key(location)).await?.is_some() {
            Ok(())
        } else {
            Err(QmdbError::CurrentProofRequiresBatchBoundary {
                location: location.as_u64(),
            })
        }
    }

    pub(crate) async fn load_latest_update_row(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        key: &[u8],
    ) -> Result<Option<(Key, Vec<u8>)>, QmdbError> {
        let start = encode_update_key(key, Location::<F>::new(0))?;
        let end = encode_update_key(key, watermark)?;
        let rows = session
            .range_with_mode(&start, &end, 1, RangeMode::Reverse)
            .await?;
        Ok(rows
            .into_iter()
            .next()
            .map(|(key, value)| (key, value.to_vec())))
    }

    /// Concurrently resolve the latest value for each key at `watermark`:
    /// reverse-scan each key's update index for its newest location, then defer
    /// to `resolver` to load and verify the operation there. Returns `None` per
    /// key with no update row.
    pub(crate) async fn query_many_at<Q, R>(
        &self,
        keys: &[Q],
        watermark: Location<F>,
        resolver: &R,
    ) -> Result<Vec<Option<VersionedValue<K, V, F>>>, QmdbError>
    where
        Q: AsRef<[u8]>,
        R: LatestValueResolver<F, K, V>,
    {
        let session = self.client.create_session();
        self.require_published_watermark(&session, watermark)
            .await?;

        let futs = keys.iter().map(|key| {
            let key_bytes = key.as_ref();
            let session = &session;
            async move {
                let Some((row_key, _row_value)) = self
                    .load_latest_update_row(session, watermark, key_bytes)
                    .await?
                else {
                    return Ok(None);
                };
                let location = decode_update_location(&row_key)?;
                Ok(Some(
                    resolver
                        .resolve_latest_value(session, location, key_bytes)
                        .await?,
                ))
            }
        });
        futures::future::join_all(futs).await.into_iter().collect()
    }

    pub(crate) async fn compute_ops_root_with_inactive_peaks<H: Hasher<Digest = D>>(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        inactive_peaks: usize,
    ) -> Result<D, QmdbError> {
        let size = merkle_size_for_watermark(watermark)?;
        let leaves = watermark
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        let peak_positions: Vec<(Position<F>, u32)> = F::peaks(size).collect();
        let fetched = if peak_positions.is_empty() {
            std::collections::HashMap::new()
        } else {
            let peak_keys: Vec<Key> = peak_positions
                .iter()
                .map(|(pos, _)| encode_node_key(*pos))
                .collect();
            let peak_key_refs: Vec<&Key> = peak_keys.iter().collect();
            session
                .get_many(&peak_key_refs, peak_key_refs.len() as u32)
                .await?
                .collect()
                .await?
        };
        let mut peaks = Vec::with_capacity(peak_positions.len());
        for (peak_pos, _) in &peak_positions {
            let Some(bytes) = fetched.get(&encode_node_key(*peak_pos)) else {
                return Err(QmdbError::CorruptData(format!(
                    "missing Merkle peak node at position {peak_pos}"
                )));
            };
            peaks.push(decode_digest(
                bytes.as_ref(),
                format!("Merkle peak node at position {peak_pos}"),
            )?);
        }
        let hasher = commonware_storage::qmdb::hasher::<H>();
        hasher
            .root(leaves, inactive_peaks, peaks.iter())
            .map_err(|e| QmdbError::CommonwareMerkle(e.to_string()))
    }

    pub(crate) async fn load_operation_bytes_at(
        &self,
        session: &SerializableReadSession,
        location: Location<F>,
    ) -> Result<Vec<u8>, QmdbError> {
        let Some(bytes) = session.get(&encode_operation_key(location)).await? else {
            return Err(QmdbError::CorruptData(format!(
                "missing operation row at location {location}"
            )));
        };
        Ok(bytes.to_vec())
    }

    pub(crate) async fn load_operation_bytes_range(
        &self,
        session: &SerializableReadSession,
        start_location: Location<F>,
        end_location_exclusive: Location<F>,
    ) -> Result<Vec<Vec<u8>>, QmdbError> {
        if start_location >= end_location_exclusive {
            return Ok(Vec::new());
        }
        let start = encode_operation_key(start_location);
        let end = encode_operation_key(end_location_exclusive - 1);
        let rows = session
            .range(
                &start,
                &end,
                (*end_location_exclusive - *start_location) as usize,
            )
            .await?;
        if rows.len() != (*end_location_exclusive - *start_location) as usize {
            return Err(QmdbError::CorruptData(format!(
                "expected {} operation rows in location range [{start_location}, {end_location_exclusive}), found {}",
                *end_location_exclusive - *start_location,
                rows.len()
            )));
        }
        let mut encoded = Vec::with_capacity(rows.len());
        for (offset, (key, value)) in rows.into_iter().enumerate() {
            let expected_location = start_location + offset as u64;
            let location = decode_operation_location_key(&key)?;
            if location != expected_location {
                return Err(QmdbError::CorruptData(format!(
                    "operation row order mismatch: expected {expected_location}, got {location}"
                )));
            }
            encoded.push(value.to_vec());
        }
        Ok(encoded)
    }
}

/// Extend a pinned prefix with encoded operations, returning the root, frontier,
/// and every new node needed to serve proofs.
pub(crate) struct MerkleExtension<F: Family, D: Digest> {
    pub(crate) size: Position<F>,
    pub(crate) peaks: Vec<(Position<F>, u32, D)>,
    pub(crate) root: D,
    pub(crate) new_nodes: Vec<(Position<F>, D)>,
}

pub(crate) fn extend_merkle_from_pinned_nodes<F, H, S, I>(
    pinned_nodes: Vec<H::Digest>,
    pruning_boundary: Location<F>,
    encoded_operations: I,
    inactive_peaks: usize,
    strategy: &S,
) -> Result<MerkleExtension<F, H::Digest>, QmdbError>
where
    F: Family,
    H: Hasher,
    S: Strategy,
    I: IntoIterator + Send,
    I::Item: AsRef<[u8]> + Send,
    I::IntoIter: Send,
{
    let previous_size = Position::try_from(pruning_boundary)
        .map_err(|e| QmdbError::CorruptData(format!("invalid incremental ops size {e}")))?;

    let hasher = commonware_storage::qmdb::hasher::<H>();
    let mem = Mem::<F, H::Digest>::from_components(Vec::new(), pruning_boundary, pinned_nodes)
        .map_err(|e| QmdbError::CommonwareMerkle(e.to_string()))?;
    let leaf_digests = strategy.try_map_collect_vec(
        encoded_operations.into_iter().enumerate(),
        |(offset, encoded)| {
            let encoded = encoded.as_ref();
            ensure_encoded_value_size(encoded.len())?;
            let offset = u64::try_from(offset)
                .map_err(|_| QmdbError::CorruptData("operation offset exceeds u64".into()))?;
            let location = pruning_boundary
                .checked_add(offset)
                .ok_or_else(|| QmdbError::CorruptData("operation location overflow".into()))?;
            let position = Position::try_from(location).map_err(|e| {
                QmdbError::CorruptData(format!("invalid operation location {location}. {e}"))
            })?;
            Ok::<_, QmdbError>(hasher.leaf_digest(position, encoded))
        },
    )?;

    let batch = mem
        .new_batch_with_strategy(strategy.clone())
        .add_leaf_digests(leaf_digests);
    let batch = batch.merkleize(&mem, &hasher);
    let size = batch.size();
    let new_nodes = (*previous_size..*size)
        .map(|raw_pos| {
            let pos = Position::new(raw_pos);
            let digest = batch.get_node(pos).ok_or_else(|| {
                QmdbError::CorruptData(format!("missing node {pos} after merkle extension"))
            })?;
            Ok((pos, digest))
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    let peaks = F::peaks(size)
        .map(|(pos, height)| {
            let digest = batch
                .get_node(pos)
                .or_else(|| mem.get_node(pos))
                .ok_or_else(|| {
                    QmdbError::CorruptData(format!("missing peak {pos} after merkle extension"))
                })?;
            Ok((pos, height, digest))
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    let root = batch
        .root(&mem, &hasher, inactive_peaks)
        .map_err(|e| QmdbError::CommonwareMerkle(e.to_string()))?;
    Ok(MerkleExtension {
        size,
        peaks,
        root,
        new_nodes,
    })
}
