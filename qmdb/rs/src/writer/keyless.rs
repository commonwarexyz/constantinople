//! Single-writer helper for the keyless QMDB variant.

use std::marker::PhantomData;

use commonware_codec::{Codec, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::merkle::{Family, Location, Position};
use commonware_storage::qmdb::{
    any::value::{ValueEncoding, VariableEncoding},
    keyless,
};
use exoware_sdk::keys::Key;
use exoware_sdk::{
    Namespace, PrefixedStoreClient, StoreBatchPublication, StoreBatchUpload, StoreClient,
    StorePublicationFrontierWriter, StoreWriteBatch,
};
use futures::future::BoxFuture;

use crate::auth::{
    build_auth_upload_rows, encode_auth_node_key, encode_auth_watermark_key,
    AuthenticatedBackendNamespace,
};
use crate::core::extend_merkle_from_peaks_with_inactive_peaks;
use crate::error::QmdbError;
use crate::writer::core::{Cache, WriterCore};
use crate::{PublishedCheckpoint, UploadReceipt, WriterState};

const NAMESPACE: AuthenticatedBackendNamespace = AuthenticatedBackendNamespace::Keyless;

/// Deterministic output of a keyless row-build.
#[derive(Clone, Debug)]
pub struct BuiltKeylessUpload<D, F: Family> {
    pub rows: Vec<(Key, Vec<u8>)>,
    pub new_peaks: Vec<(Position<F>, u32, D)>,
    pub new_ops_size: Position<F>,
    pub new_root: D,
    pub latest_location: Location<F>,
    pub operation_count: u32,
    pub includes_watermark: bool,
}

/// Pure function: from the Merkle peaks preceding the batch, compute every
/// store row needed to persist `ops` as a single atomic PUT. No I/O.
///
/// `watermark_at`, if `Some(loc)`, emits a watermark row at that location.
/// The caller is responsible for ensuring `loc` is safe to publish (i.e. the
/// entire prefix up to `loc` has committed); `WriterCore::prepare` computes
/// this safely for in-writer use.
pub fn build_keyless_upload<F, H, V, E>(
    peaks: Vec<(Position<F>, u32, H::Digest)>,
    prev_ops_size: Position<F>,
    latest_location: Location<F>,
    ops: &[keyless::Operation<F, E>],
    watermark_at: Option<Location<F>>,
) -> Result<BuiltKeylessUpload<H::Digest, F>, QmdbError>
where
    F: Family,
    H: Hasher,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    keyless::Operation<F, E>: Encode,
{
    if ops.is_empty() {
        return Err(QmdbError::EmptyBatch);
    }
    let encoded: Vec<Vec<u8>> = ops.iter().map(|op| op.encode().to_vec()).collect();
    let prepared = build_auth_upload_rows(NAMESPACE, latest_location, encoded)?;
    let inactive_peaks = keyless_inactive_peaks(latest_location, ops)?;
    let ext = extend_merkle_from_peaks_with_inactive_peaks::<F, H, _>(
        peaks,
        prev_ops_size,
        prepared.op_bytes(),
        inactive_peaks,
    )?;
    let operation_count = prepared.operation_count;
    let mut rows = prepared.into_all_rows();
    for (pos, digest) in &ext.new_nodes {
        rows.push((
            encode_auth_node_key(NAMESPACE, *pos),
            digest.as_ref().to_vec(),
        ));
    }
    if let Some(loc) = watermark_at {
        rows.push((encode_auth_watermark_key(NAMESPACE, loc), Vec::new()));
    }
    Ok(BuiltKeylessUpload {
        rows,
        new_peaks: ext.peaks,
        new_ops_size: ext.size,
        new_root: ext.root,
        latest_location,
        operation_count,
        includes_watermark: watermark_at.is_some(),
    })
}

fn keyless_inactive_peaks<F, V, E>(
    latest_location: Location<F>,
    ops: &[keyless::Operation<F, E>],
) -> Result<usize, QmdbError>
where
    F: Family,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
{
    let floor = match ops.last() {
        Some(keyless::Operation::Commit(_, floor)) => *floor,
        _ => {
            return Err(QmdbError::CorruptData(
                "keyless upload operations must end with Commit".to_string(),
            ));
        }
    };
    crate::auth::auth_inactive_peaks(latest_location, floor)
}

/// Sole-writer keyless QMDB helper.
///
/// ## Pipelining
///
/// Multiple [`prepare_upload`](Self::prepare_upload) calls can be in flight
/// simultaneously — the writer's mutex is released before any Store write
/// awaits, so independent Store batches can run concurrently on the transport.
///
/// Each dispatched batch's PUT carries a watermark row at the **latest safe
/// location**:
///
/// - Pipeline empty at dispatch → this batch's own `latest_location` (our PUT
///   is the only one in flight, so our own latest is safe to publish once the
///   PUT commits).
/// - Pipeline non-empty, some prefix ACKd → the last location of the
///   contiguous-acked prefix (every predecessor batch has returned Ok).
/// - Pipeline non-empty, nothing ACKd yet → no watermark row in this PUT.
///
/// Under steady-state saturation (bounded concurrency with ~constant ACK
/// latency) this keeps the published watermark lagging the dispatch frontier
/// by at most the pipeline depth — never unbounded. The [`flush`](Self::flush)
/// method is only needed to publish the trailing watermark after the final
/// batch dispatch and its ACKs drain.
///
/// ## Failure handling
///
/// Any PUT error poisons the writer. The caller must construct a fresh writer
/// from a caller-owned committed frontier before any further uploads can
/// proceed. PUT rows are
/// content-addressed and Merkle math is deterministic, so re-submitting the
/// batches the caller still considers pending is always safe.
///
/// ## Sole-writer contract
///
/// Concurrent publishers against the same store namespace race on peak
/// extension and will corrupt each other's Merkle state. The contract assumed
/// throughout is "one writer per namespace." The store's ingest layer is not
/// aware of this constraint; it's the caller's responsibility.
pub struct KeylessWriter<
    F: Family,
    H: Hasher,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> {
    client: StoreClient,
    core: WriterCore<H::Digest, F>,
    _marker: PhantomData<(F, E)>,
}

impl<F, H, V, E> KeylessWriter<F, H, V, E>
where
    F: Family,
    H: Hasher,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    keyless::Operation<F, E>: Encode,
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
        ops: &[keyless::Operation<F, E>],
    ) -> Result<super::PreparedUpload<F>, QmdbError> {
        let prepared = self
            .core
            .prepare(ops.len() as u64, |ctx| {
                let built = build_keyless_upload::<F, H, V, E>(
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
            "keyless upload ending at {} failed: {}",
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
            row: (encode_auth_watermark_key(NAMESPACE, target), Vec::new()),
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
            row: (encode_auth_watermark_key(NAMESPACE, target), Vec::new()),
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

impl<F, H, V, E> std::fmt::Debug for KeylessWriter<F, H, V, E>
where
    F: Family,
    H: Hasher,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeylessWriter").finish_non_exhaustive()
    }
}

impl<F, H, V, E> StoreBatchUpload for KeylessWriter<F, H, V, E>
where
    F: Family,
    H: Hasher + Sync,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V> + Sync,
    keyless::Operation<F, E>: Encode,
{
    type Prepared = super::PreparedUpload<F>;
    type Receipt = UploadReceipt<F>;
    type Error = QmdbError;

    fn stage_upload(
        &self,
        prepared: &mut Self::Prepared,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), Self::Error> {
        KeylessWriter::stage_upload(self, prepared, batch)
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
            KeylessWriter::mark_upload_persisted(self, prepared, sequence_number).await
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
            KeylessWriter::mark_upload_failed(self, prepared, error).await;
        })
    }
}

impl<F, H, V, E> StoreBatchPublication for KeylessWriter<F, H, V, E>
where
    F: Family,
    H: Hasher + Sync,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V> + Sync,
    keyless::Operation<F, E>: Encode,
{
    type PreparedPublication = super::PreparedWatermark<F>;
    type PublicationReceipt = PublishedCheckpoint<F>;
    type Error = QmdbError;

    fn stage_publication(
        &self,
        prepared: &Self::PreparedPublication,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), Self::Error> {
        KeylessWriter::stage_flush(self, prepared, batch)
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
            KeylessWriter::mark_flush_persisted(self, prepared, sequence_number).await
        })
    }
}

impl<F, H, V, E> StorePublicationFrontierWriter for KeylessWriter<F, H, V, E>
where
    F: Family,
    H: Hasher + Sync,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V> + Sync,
    keyless::Operation<F, E>: Encode,
{
    fn latest_publication_receipt<'a>(&'a self) -> BoxFuture<'a, Option<PublishedCheckpoint<F>>>
    where
        Self: Sync + 'a,
    {
        Box::pin(async move { KeylessWriter::latest_published_checkpoint(self).await })
    }

    fn prepare_publication<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Option<super::PreparedWatermark<F>>, QmdbError>>
    where
        Self: Sync + 'a,
    {
        Box::pin(async move { KeylessWriter::prepare_flush(self).await })
    }

    fn flush_publication_with_receipt<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Option<PublishedCheckpoint<F>>, QmdbError>>
    where
        Self: Sync + 'a,
    {
        Box::pin(async move { KeylessWriter::flush_with_receipt(self).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Sha256;
    use commonware_storage::merkle::mmr;

    type TestEncoding = VariableEncoding<Vec<u8>>;
    type TestOp = keyless::Operation<mmr::Family, TestEncoding>;

    fn op(v: &[u8]) -> TestOp {
        keyless::Operation::Append(v.to_vec())
    }

    fn commit(floor: u64) -> TestOp {
        keyless::Operation::Commit(None, Location::new(floor))
    }

    #[test]
    fn build_from_empty_peaks_includes_all_expected_row_families() {
        let ops = vec![op(b"one"), op(b"two"), op(b"three"), commit(0)];
        let built = build_keyless_upload::<mmr::Family, Sha256, Vec<u8>, TestEncoding>(
            Vec::new(),
            Position::new(0),
            Location::new(3),
            &ops,
            Some(Location::new(3)),
        )
        .expect("build");
        assert_eq!(built.operation_count, 4);
        assert_eq!(built.latest_location, Location::new(3));
        assert!(built.includes_watermark);
        assert!(built.rows.len() >= 5);
    }

    #[test]
    fn excluding_watermark_row_drops_exactly_one_row() {
        let ops = vec![op(b"x"), op(b"y"), commit(0)];
        let with_wm = build_keyless_upload::<mmr::Family, Sha256, Vec<u8>, TestEncoding>(
            Vec::new(),
            Position::new(0),
            Location::new(2),
            &ops,
            Some(Location::new(2)),
        )
        .expect("with wm");
        let without_wm = build_keyless_upload::<mmr::Family, Sha256, Vec<u8>, TestEncoding>(
            Vec::new(),
            Position::new(0),
            Location::new(2),
            &ops,
            None,
        )
        .expect("without wm");
        assert_eq!(with_wm.rows.len(), without_wm.rows.len() + 1);
    }

    #[test]
    fn build_is_deterministic_on_same_inputs() {
        let ops = vec![op(b"a"), op(b"b"), op(b"c"), op(b"d"), commit(0)];
        let a = build_keyless_upload::<mmr::Family, Sha256, Vec<u8>, TestEncoding>(
            Vec::new(),
            Position::new(0),
            Location::new(4),
            &ops,
            Some(Location::new(4)),
        )
        .expect("a");
        let b = build_keyless_upload::<mmr::Family, Sha256, Vec<u8>, TestEncoding>(
            Vec::new(),
            Position::new(0),
            Location::new(4),
            &ops,
            Some(Location::new(4)),
        )
        .expect("b");
        assert_eq!(a.rows, b.rows);
        assert_eq!(a.new_peaks, b.new_peaks);
        assert_eq!(a.new_ops_size, b.new_ops_size);
        assert_eq!(a.new_root, b.new_root);
    }

    #[test]
    fn incremental_fold_matches_single_fold() {
        let all = vec![op(b"p"), commit(0), op(b"q"), op(b"r"), commit(1)];
        let single = build_keyless_upload::<mmr::Family, Sha256, Vec<u8>, TestEncoding>(
            Vec::new(),
            Position::new(0),
            Location::new(4),
            &all,
            None,
        )
        .expect("single");

        let first = build_keyless_upload::<mmr::Family, Sha256, Vec<u8>, TestEncoding>(
            Vec::new(),
            Position::new(0),
            Location::new(1),
            &all[..2],
            None,
        )
        .expect("first");
        let second = build_keyless_upload::<mmr::Family, Sha256, Vec<u8>, TestEncoding>(
            first.new_peaks.clone(),
            first.new_ops_size,
            Location::new(4),
            &all[2..],
            None,
        )
        .expect("second");

        assert_eq!(single.new_peaks, second.new_peaks);
        assert_eq!(single.new_ops_size, second.new_ops_size);
        assert_eq!(single.new_root, second.new_root);
    }

    #[test]
    fn empty_batch_rejected() {
        let res = build_keyless_upload::<mmr::Family, Sha256, Vec<u8>, TestEncoding>(
            Vec::new(),
            Position::new(0),
            Location::new(0),
            &[],
            Some(Location::new(0)),
        );
        assert!(matches!(res, Err(QmdbError::EmptyBatch)));
    }

    #[test]
    fn missing_commit_rejected() {
        let ops = vec![op(b"x")];
        let res = build_keyless_upload::<mmr::Family, Sha256, Vec<u8>, TestEncoding>(
            Vec::new(),
            Position::new(0),
            Location::new(0),
            &ops,
            Some(Location::new(0)),
        );
        assert!(matches!(res, Err(QmdbError::CorruptData(_))));
    }
}
