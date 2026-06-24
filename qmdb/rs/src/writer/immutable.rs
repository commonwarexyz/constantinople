//! Single-writer helper for the immutable QMDB variant (authenticated,
//! single-Set-per-key semantics).

use std::marker::PhantomData;

use commonware_codec::{Codec, Decode, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::merkle::{Family, Location, Position};
use commonware_storage::qmdb::{
    any::value::{ValueEncoding, VariableEncoding},
    immutable,
};
use commonware_utils::Array;
use exoware_sdk::keys::Key;
use exoware_sdk::{
    Namespace, PrefixedStoreClient, StoreBatchPublication, StoreBatchUpload, StoreClient,
    StorePublicationFrontierWriter, StoreWriteBatch,
};
use futures::future::BoxFuture;

use crate::auth::{
    build_auth_immutable_upload_rows, encode_auth_node_key, encode_auth_watermark_key,
    AuthenticatedBackendNamespace,
};
use crate::core::extend_merkle_from_peaks_with_inactive_peaks;
use crate::error::QmdbError;
use crate::writer::core::{Cache, WriterCore};
use crate::{PublishedCheckpoint, UploadReceipt, WriterState};

const NAMESPACE: AuthenticatedBackendNamespace = AuthenticatedBackendNamespace::Immutable;

#[derive(Clone, Debug)]
pub struct BuiltImmutableUpload<D, F: Family> {
    pub rows: Vec<(Key, Vec<u8>)>,
    pub new_peaks: Vec<(Position<F>, u32, D)>,
    pub new_ops_size: Position<F>,
    pub new_root: D,
    pub latest_location: Location<F>,
    pub operation_count: u32,
    pub keyed_operation_count: u32,
    pub includes_watermark: bool,
}

pub fn build_immutable_upload<F, H, K, V, E>(
    peaks: Vec<(Position<F>, u32, H::Digest)>,
    prev_ops_size: Position<F>,
    latest_location: Location<F>,
    ops: &[immutable::Operation<F, K, E>],
    watermark_at: Option<Location<F>>,
) -> Result<BuiltImmutableUpload<H::Digest, F>, QmdbError>
where
    F: Family,
    H: Hasher,
    K: Array + Codec + Clone + AsRef<[u8]>,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    immutable::Operation<F, K, E>: Encode,
{
    if ops.is_empty() {
        return Err(QmdbError::EmptyBatch);
    }
    let prepared = build_auth_immutable_upload_rows(latest_location, ops)?;
    let inactive_peaks = immutable_inactive_peaks(latest_location, ops)?;
    let ext = extend_merkle_from_peaks_with_inactive_peaks::<F, H, _>(
        peaks,
        prev_ops_size,
        prepared.op_bytes(),
        inactive_peaks,
    )?;
    let keyed_operation_count = prepared.keyed_operation_count;
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
    Ok(BuiltImmutableUpload {
        rows,
        new_peaks: ext.peaks,
        new_ops_size: ext.size,
        new_root: ext.root,
        latest_location,
        operation_count: ops.len() as u32,
        keyed_operation_count,
        includes_watermark: watermark_at.is_some(),
    })
}

fn immutable_inactive_peaks<F, K, V, E>(
    latest_location: Location<F>,
    ops: &[immutable::Operation<F, K, E>],
) -> Result<usize, QmdbError>
where
    F: Family,
    K: Array + Codec + Clone + AsRef<[u8]>,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
{
    let floor = match ops.last() {
        Some(immutable::Operation::Commit(_, floor)) => *floor,
        _ => {
            return Err(QmdbError::CorruptData(
                "immutable upload operations must end with Commit".to_string(),
            ));
        }
    };
    crate::auth::auth_inactive_peaks(latest_location, floor)
}

/// Sole-writer immutable QMDB helper. Pipelining, flushing, failure, and
/// sole-writer contract are identical to
/// [`KeylessWriter`](crate::KeylessWriter) — see its docs for details.
pub struct ImmutableWriter<
    F: Family,
    H: Hasher,
    K: Array + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> {
    client: StoreClient,
    core: WriterCore<H::Digest, F>,
    _marker: PhantomData<(F, K, E)>,
}

impl<F, H, K, V, E> ImmutableWriter<F, H, K, V, E>
where
    F: Family,
    H: Hasher,
    K: Array + Codec + Clone + AsRef<[u8]>,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    K::Cfg: Clone,
    E: ValueEncoding<Value = V>,
    immutable::Operation<F, K, E>: Encode + Decode + Clone,
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
        ops: &[immutable::Operation<F, K, E>],
    ) -> Result<super::PreparedUpload<F>, QmdbError> {
        let prepared = self
            .core
            .prepare(ops.len() as u64, |ctx| {
                let built = build_immutable_upload::<F, H, K, V, E>(
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
            "immutable upload ending at {} failed: {}",
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

impl<F, H, K, V, E> std::fmt::Debug for ImmutableWriter<F, H, K, V, E>
where
    F: Family,
    H: Hasher,
    K: Array + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImmutableWriter").finish_non_exhaustive()
    }
}

impl<F, H, K, V, E> StoreBatchUpload for ImmutableWriter<F, H, K, V, E>
where
    F: Family,
    H: Hasher + Sync,
    K: Array + Codec + Clone + AsRef<[u8]> + Sync,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    K::Cfg: Clone,
    E: ValueEncoding<Value = V> + Sync,
    immutable::Operation<F, K, E>: Encode + Decode + Clone,
{
    type Prepared = super::PreparedUpload<F>;
    type Receipt = UploadReceipt<F>;
    type Error = QmdbError;

    fn stage_upload(
        &self,
        prepared: &mut Self::Prepared,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), Self::Error> {
        ImmutableWriter::stage_upload(self, prepared, batch)
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
            ImmutableWriter::mark_upload_persisted(self, prepared, sequence_number).await
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
            ImmutableWriter::mark_upload_failed(self, prepared, error).await;
        })
    }
}

impl<F, H, K, V, E> StoreBatchPublication for ImmutableWriter<F, H, K, V, E>
where
    F: Family,
    H: Hasher + Sync,
    K: Array + Codec + Clone + AsRef<[u8]> + Sync,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    K::Cfg: Clone,
    E: ValueEncoding<Value = V> + Sync,
    immutable::Operation<F, K, E>: Encode + Decode + Clone,
{
    type PreparedPublication = super::PreparedWatermark<F>;
    type PublicationReceipt = PublishedCheckpoint<F>;
    type Error = QmdbError;

    fn stage_publication(
        &self,
        prepared: &Self::PreparedPublication,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), Self::Error> {
        ImmutableWriter::stage_flush(self, prepared, batch)
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
            ImmutableWriter::mark_flush_persisted(self, prepared, sequence_number).await
        })
    }
}

impl<F, H, K, V, E> StorePublicationFrontierWriter for ImmutableWriter<F, H, K, V, E>
where
    F: Family,
    H: Hasher + Sync,
    K: Array + Codec + Clone + AsRef<[u8]> + Sync,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    K::Cfg: Clone,
    E: ValueEncoding<Value = V> + Sync,
    immutable::Operation<F, K, E>: Encode + Decode + Clone,
{
    fn latest_publication_receipt<'a>(&'a self) -> BoxFuture<'a, Option<PublishedCheckpoint<F>>>
    where
        Self: Sync + 'a,
    {
        Box::pin(async move { ImmutableWriter::latest_published_checkpoint(self).await })
    }

    fn prepare_publication<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Option<super::PreparedWatermark<F>>, QmdbError>>
    where
        Self: Sync + 'a,
    {
        Box::pin(async move { ImmutableWriter::prepare_flush(self).await })
    }

    fn flush_publication_with_receipt<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Option<PublishedCheckpoint<F>>, QmdbError>>
    where
        Self: Sync + 'a,
    {
        Box::pin(async move { ImmutableWriter::flush_with_receipt(self).await })
    }
}
