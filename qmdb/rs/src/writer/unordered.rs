//! Single-writer helper for the unordered QMDB variant (uses the
//! unauthenticated key family shared with the ordered variant).

use std::marker::PhantomData;

use commonware_codec::{Codec, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::merkle::{Graftable, Location, Position};
use commonware_storage::qmdb::{
    any::{
        unordered,
        value::{ValueEncoding, VariableEncoding},
    },
    operation::Key as QmdbKey,
};
use exoware_sdk::keys::Key;
use exoware_sdk::{
    Namespace, PrefixedStoreClient, StoreBatchPublication, StoreBatchUpload, StoreClient,
    StorePublicationFrontierWriter, StoreWriteBatch,
};
use futures::future::BoxFuture;

use crate::codec::{encode_node_key, encode_watermark_key};
use crate::core::{
    extend_merkle_from_peaks_with_inactive_peaks, PreparedCurrentBoundaryUpload,
    PreparedUpload as CorePreparedUpload,
};
use crate::error::QmdbError;
use crate::writer::core::{Cache, WriterCore};
use crate::{CurrentBoundaryState, PublishedCheckpoint, UploadReceipt, WriterState};

/// Deterministic output of an unordered row-build.
#[derive(Clone, Debug)]
pub struct BuiltUnorderedUpload<D, F: Graftable> {
    pub rows: Vec<(Key, Vec<u8>)>,
    pub new_peaks: Vec<(Position<F>, u32, D)>,
    pub new_ops_size: Position<F>,
    pub new_root: D,
    pub latest_location: Location<F>,
    pub operation_count: u32,
    pub keyed_operation_count: u32,
    pub includes_watermark: bool,
}

/// Pure row-build for an unordered batch. Produces op rows, update-index
/// rows for keyed ops, presence row, Merkle node rows, and (optionally) the
/// watermark row.
pub fn build_unordered_upload<F, H, K, V, E>(
    peaks: Vec<(Position<F>, u32, H::Digest)>,
    prev_ops_size: Position<F>,
    latest_location: Location<F>,
    ops: &[unordered::Operation<F, K, E>],
    watermark_at: Option<Location<F>>,
) -> Result<BuiltUnorderedUpload<H::Digest, F>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Encode,
{
    if ops.is_empty() {
        return Err(QmdbError::EmptyBatch);
    }
    let prepared = CorePreparedUpload::build_unordered(latest_location, ops)?;
    let inactive_peaks = unordered_inactive_peaks(latest_location, ops)?;
    let ext = extend_merkle_from_peaks_with_inactive_peaks::<F, H, _>(
        peaks,
        prev_ops_size,
        prepared.op_bytes(),
        inactive_peaks,
    )?;
    let operation_count = prepared.operation_count;
    let keyed_operation_count = prepared.keyed_operation_count;

    let mut rows = prepared.into_all_rows();
    for (pos, digest) in &ext.new_nodes {
        rows.push((encode_node_key(*pos), digest.encode().to_vec()));
    }
    if let Some(loc) = watermark_at {
        rows.push((encode_watermark_key(loc), Vec::new()));
    }
    Ok(BuiltUnorderedUpload {
        rows,
        new_peaks: ext.peaks,
        new_ops_size: ext.size,
        new_root: ext.root,
        latest_location,
        operation_count,
        keyed_operation_count,
        includes_watermark: watermark_at.is_some(),
    })
}

fn unordered_inactive_peaks<F, K, V, E>(
    latest_location: Location<F>,
    ops: &[unordered::Operation<F, K, E>],
) -> Result<usize, QmdbError>
where
    F: Graftable,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
{
    let floor = match ops.last() {
        Some(unordered::Operation::CommitFloor(_, floor)) => *floor,
        _ => {
            return Err(QmdbError::CorruptData(
                "unordered upload operations must end with CommitFloor".to_string(),
            ));
        }
    };
    Ok(F::inactive_peaks(
        crate::codec::merkle_size_for_watermark(latest_location)?,
        floor,
    ))
}

pub fn build_unordered_current_upload<F, H, K, V, const N: usize, E>(
    peaks: Vec<(Position<F>, u32, H::Digest)>,
    prev_ops_size: Position<F>,
    latest_location: Location<F>,
    ops: &[unordered::Operation<F, K, E>],
    current_boundary: &CurrentBoundaryState<H::Digest, N, F>,
    watermark_at: Option<Location<F>>,
) -> Result<BuiltUnorderedUpload<H::Digest, F>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Encode,
{
    let mut built = build_unordered_upload::<F, H, K, V, E>(
        peaks,
        prev_ops_size,
        latest_location,
        ops,
        watermark_at,
    )?;
    let prepared_current = PreparedCurrentBoundaryUpload::build(latest_location, current_boundary)?;
    built.rows.extend(prepared_current.rows);
    Ok(built)
}

/// Sole-writer unordered QMDB helper. Pipelining, flushing, failure, and
/// sole-writer contract are identical to
/// [`KeylessWriter`](crate::KeylessWriter) — see its docs for details.
pub struct UnorderedWriter<
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> {
    client: StoreClient,
    core: WriterCore<H::Digest, F>,
    _marker: PhantomData<(F, K, V, E)>,
}

impl<F, H, K, V, E> UnorderedWriter<F, H, K, V, E>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Encode,
{
    /// Construct a writer over the canonical [`Namespace::Qmdb`] keyspace from
    /// caller-supplied frontier state (no store I/O). For more than one QMDB
    /// log in one Store, use [`Self::prefixed`] with distinct
    /// [`Namespace::sub`] instances.
    pub fn new(client: StoreClient, state: WriterState<H::Digest, F>) -> Self {
        Self::prefixed(client.for_namespace(Namespace::Qmdb), state)
    }

    /// Construct a writer over a caller-chosen namespace (e.g. one
    /// [`Namespace::sub`] per co-located QMDB log).
    pub fn prefixed(client: PrefixedStoreClient, state: WriterState<H::Digest, F>) -> Self {
        Self::unprefixed(client.into_client(), state)
    }

    /// Construct a writer directly over a raw, un-namespaced client. Escape
    /// hatch for a Store this writer owns exclusively.
    pub fn unprefixed(client: StoreClient, state: WriterState<H::Digest, F>) -> Self {
        Self {
            client,
            core: WriterCore::from_cache(Cache::from_writer_state(state)),
            _marker: PhantomData,
        }
    }

    pub fn empty(client: StoreClient) -> Self {
        Self::new(client, WriterState::empty())
    }

    pub async fn latest_published_watermark(&self) -> Option<Location<F>> {
        self.core.latest_published().await
    }

    pub async fn latest_published_checkpoint(&self) -> Option<PublishedCheckpoint<F>> {
        self.core.latest_published_checkpoint().await
    }

    pub async fn prepare_upload(
        &self,
        ops: &[unordered::Operation<F, K, E>],
    ) -> Result<super::PreparedUpload<F>, QmdbError> {
        let prepared = self
            .core
            .prepare(ops.len() as u64, |ctx| {
                let built = build_unordered_upload::<F, H, K, V, E>(
                    ctx.peaks,
                    ctx.ops_size,
                    ctx.latest_location,
                    ops,
                    ctx.watermark_at,
                )?;
                Ok(crate::writer::core::BuildResult {
                    new_peaks: built.new_peaks,
                    new_ops_size: built.new_ops_size,
                    output: built.rows,
                })
            })
            .await?;
        Ok(super::PreparedUpload::<F> {
            dispatch_id: prepared.dispatch_id,
            latest_location: prepared.latest_location,
            writer_location_watermark: prepared.watermark_at,
            rows: prepared.output,
        })
    }

    pub async fn prepare_current_upload<const N: usize>(
        &self,
        ops: &[unordered::Operation<F, K, E>],
        current_boundary: &CurrentBoundaryState<H::Digest, N, F>,
    ) -> Result<super::PreparedUpload<F>, QmdbError> {
        let prepared = self
            .core
            .prepare(ops.len() as u64, |ctx| {
                let built = build_unordered_current_upload::<F, H, K, V, N, E>(
                    ctx.peaks,
                    ctx.ops_size,
                    ctx.latest_location,
                    ops,
                    current_boundary,
                    ctx.watermark_at,
                )?;
                Ok(crate::writer::core::BuildResult {
                    new_peaks: built.new_peaks,
                    new_ops_size: built.new_ops_size,
                    output: built.rows,
                })
            })
            .await?;
        Ok(super::PreparedUpload::<F> {
            dispatch_id: prepared.dispatch_id,
            latest_location: prepared.latest_location,
            writer_location_watermark: prepared.watermark_at,
            rows: prepared.output,
        })
    }

    pub fn stage_upload(
        &self,
        prepared: &mut super::PreparedUpload<F>,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), QmdbError> {
        super::stage_rows(&self.client, batch, prepared.rows.drain(..))
    }

    pub async fn mark_upload_persisted(
        &self,
        prepared: super::PreparedUpload<F>,
        sequence_number: u64,
    ) -> UploadReceipt<F> {
        self.core
            .ack_success(prepared.dispatch_id, sequence_number)
            .await;
        super::upload_receipt(&prepared, sequence_number)
    }

    pub async fn mark_upload_failed(&self, prepared: super::PreparedUpload<F>, err: impl ToString) {
        let msg = format!(
            "unordered upload ending at {} failed: {}",
            prepared.latest_location,
            err.to_string()
        );
        self.core.ack_failure(msg).await;
    }

    pub async fn prepare_flush(&self) -> Result<Option<super::PreparedWatermark<F>>, QmdbError> {
        let Some(target) = self.core.pending_watermark().await? else {
            return Ok(None);
        };
        Ok(Some(super::PreparedWatermark::<F> {
            location: target,
            row: (encode_watermark_key(target), Vec::new()),
        }))
    }

    /// Prepare a watermark row to stage into the same Store batch as `uploads`.
    ///
    /// This may publish through the provided uploads because their rows and the
    /// watermark row commit atomically in the caller's Store batch.
    pub async fn prepare_flush_for_uploads<'a>(
        &self,
        uploads: impl IntoIterator<Item = &'a super::PreparedUpload<F>>,
    ) -> Result<Option<super::PreparedWatermark<F>>, QmdbError>
    where
        F: 'a,
    {
        let uploads = uploads
            .into_iter()
            .map(|upload| (upload.dispatch_id, upload.latest_location))
            .collect::<Vec<_>>();
        let Some(target) = self.core.pending_watermark_for_uploads(&uploads).await? else {
            return Ok(None);
        };
        Ok(Some(super::PreparedWatermark::<F> {
            location: target,
            row: (encode_watermark_key(target), Vec::new()),
        }))
    }

    pub fn stage_flush(
        &self,
        prepared: &super::PreparedWatermark<F>,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), QmdbError> {
        super::stage_watermark(&self.client, batch, prepared)
    }

    pub async fn mark_flush_persisted(
        &self,
        prepared: super::PreparedWatermark<F>,
        sequence_number: u64,
    ) -> PublishedCheckpoint<F> {
        self.core
            .mark_watermark_published(prepared.location, sequence_number)
            .await;
        PublishedCheckpoint {
            location: prepared.location,
            sequence_number,
        }
    }

    pub async fn flush_with_receipt(&self) -> Result<Option<PublishedCheckpoint<F>>, QmdbError> {
        self.core.await_drain().await;
        let Some(prepared) = self.prepare_flush().await? else {
            return Ok(None);
        };
        Ok(Some(self.commit_publication(&self.client, prepared).await?))
    }

    pub async fn flush(&self) -> Result<(), QmdbError> {
        self.flush_with_receipt().await.map(|_| ())
    }
}

impl<F, H, K, V, E> std::fmt::Debug for UnorderedWriter<F, H, K, V, E>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnorderedWriter").finish_non_exhaustive()
    }
}

impl<F, H, K, V, E> StoreBatchUpload for UnorderedWriter<F, H, K, V, E>
where
    F: Graftable,
    H: Hasher + Sync,
    K: QmdbKey + Codec + Sync,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    E: ValueEncoding<Value = V> + Sync,
    unordered::Operation<F, K, E>: Encode,
{
    type Prepared = super::PreparedUpload<F>;
    type Receipt = UploadReceipt<F>;
    type Error = QmdbError;

    fn stage_upload(
        &self,
        prepared: &mut Self::Prepared,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), Self::Error> {
        UnorderedWriter::stage_upload(self, prepared, batch)
    }

    fn commit_error(&self, error: exoware_sdk::ClientError) -> Self::Error {
        QmdbError::Client(error)
    }

    fn mark_upload_persisted<'a>(
        &'a self,
        prepared: Self::Prepared,
        sequence_number: u64,
    ) -> BoxFuture<'a, Self::Receipt>
    where
        Self: Sync + 'a,
        Self::Prepared: 'a,
    {
        Box::pin(async move {
            UnorderedWriter::mark_upload_persisted(self, prepared, sequence_number).await
        })
    }

    fn mark_upload_failed<'a>(
        &'a self,
        prepared: Self::Prepared,
        error: String,
    ) -> BoxFuture<'a, ()>
    where
        Self: Sync + 'a,
        Self::Prepared: 'a,
    {
        Box::pin(async move {
            UnorderedWriter::mark_upload_failed(self, prepared, error).await;
        })
    }
}

impl<F, H, K, V, E> StoreBatchPublication for UnorderedWriter<F, H, K, V, E>
where
    F: Graftable,
    H: Hasher + Sync,
    K: QmdbKey + Codec + Sync,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    E: ValueEncoding<Value = V> + Sync,
    unordered::Operation<F, K, E>: Encode,
{
    type PreparedPublication = super::PreparedWatermark<F>;
    type PublicationReceipt = PublishedCheckpoint<F>;
    type Error = QmdbError;

    fn stage_publication(
        &self,
        prepared: &Self::PreparedPublication,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), Self::Error> {
        UnorderedWriter::stage_flush(self, prepared, batch)
    }

    fn publication_commit_error(&self, error: exoware_sdk::ClientError) -> Self::Error {
        QmdbError::Client(error)
    }

    fn mark_publication_persisted<'a>(
        &'a self,
        prepared: Self::PreparedPublication,
        sequence_number: u64,
    ) -> BoxFuture<'a, Self::PublicationReceipt>
    where
        Self: Sync + 'a,
        Self::PreparedPublication: 'a,
    {
        Box::pin(async move {
            UnorderedWriter::mark_flush_persisted(self, prepared, sequence_number).await
        })
    }
}

impl<F, H, K, V, E> StorePublicationFrontierWriter for UnorderedWriter<F, H, K, V, E>
where
    F: Graftable,
    H: Hasher + Sync,
    K: QmdbKey + Codec + Sync,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    E: ValueEncoding<Value = V> + Sync,
    unordered::Operation<F, K, E>: Encode,
{
    fn latest_publication_receipt<'a>(&'a self) -> BoxFuture<'a, Option<PublishedCheckpoint<F>>>
    where
        Self: Sync + 'a,
    {
        Box::pin(async move { UnorderedWriter::latest_published_checkpoint(self).await })
    }

    fn prepare_publication<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Option<super::PreparedWatermark<F>>, QmdbError>>
    where
        Self: Sync + 'a,
    {
        Box::pin(async move { UnorderedWriter::prepare_flush(self).await })
    }

    fn flush_publication_with_receipt<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Option<PublishedCheckpoint<F>>, QmdbError>>
    where
        Self: Sync + 'a,
    {
        Box::pin(async move { UnorderedWriter::flush_with_receipt(self).await })
    }
}
