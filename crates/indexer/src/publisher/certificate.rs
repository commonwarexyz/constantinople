//! Simplex block and finalization uploader backed by the chain Store.
//!
//! Consensus finalizes marshal commitments. Each commitment embeds the digest
//! of the Constantinople block header it certifies. This uploader writes full
//! block `{ header, body }` data by header digest for body reads, and writes
//! finalization artifacts with only the commitment-tagged header so
//! height/latest verification does not fetch the full body.

use commonware_codec::{Buf, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_consensus::{Block, Heightable, simplex, types::Height};
use commonware_cryptography::{Digestible, Hasher, PublicKey, certificate::Scheme};
use commonware_runtime::{
    Handle, Metrics as RuntimeMetrics, Spawner,
    telemetry::metrics::{Gauge, Histogram, MetricsExt as _},
};
use constantinople_engine::types::{EngineBlock, EngineCommitment, EngineHeader};
use exoware_sdk::{StoreBatchUpload, StoreWriteBatch};
use exoware_simplex::{Finalized, PreparedUpload, SimplexWriter};
use futures::{StreamExt, stream::FuturesUnordered};
use std::{sync::Arc, time::Instant};
use tokio::sync::{mpsc, oneshot};
use tracing::{
    Dispatch, Instrument as _, Span, debug, field, info_span, instrument::WithSubscriber as _,
};

/// Cloneable handle to the background uploader for finalized Simplex blocks.
pub struct CertificateReporter<H, P, S>
where
    H: Hasher + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send,
{
    tx: mpsc::Sender<QueuedUpload<H, P, S>>,
    metrics: SimplexUploadMetrics,
}

/// Latency buckets cover local queueing through retrying remote persistence.
const UPLOAD_DURATION_BUCKETS: [f64; 16] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
];

/// Body buckets span certificate-only uploads through the previous 64 MiB limit.
const UPLOAD_BODY_BYTES_BUCKETS: [f64; 11] = [
    0.0,
    1024.0,
    4096.0,
    16384.0,
    65536.0,
    262144.0,
    1048576.0,
    4194304.0,
    16777216.0,
    67108864.0,
    134217728.0,
];

#[derive(Clone)]
struct SimplexUploadMetrics {
    queue_depth: Gauge,
    input_queue_wait_duration: Histogram,
    block_persist_duration: Histogram,
    body_bytes: Histogram,
}

impl SimplexUploadMetrics {
    fn new(context: &impl RuntimeMetrics) -> Self {
        Self {
            queue_depth: context.gauge(
                "queue_depth",
                "Simplex inputs waiting in the uploader channel",
            ),
            input_queue_wait_duration: context.histogram(
                "input_queue_wait_duration",
                "Time from Simplex input submission until uploader dequeue (s)",
                UPLOAD_DURATION_BUCKETS,
            ),
            block_persist_duration: context.histogram(
                "block_persist_duration",
                "Time from finalized block submission until persistence completion (s)",
                UPLOAD_DURATION_BUCKETS,
            ),
            body_bytes: context.histogram(
                "body_bytes",
                "Encoded block-body bytes in each Simplex Store commit",
                UPLOAD_BODY_BYTES_BUCKETS,
            ),
        }
    }

    fn observe_dequeued<H, P, S>(&self, upload: &QueuedUpload<H, P, S>)
    where
        H: Hasher,
        P: PublicKey,
        S: Scheme,
    {
        self.queue_depth.dec();
        self.input_queue_wait_duration
            .observe(upload.queued_at.elapsed().as_secs_f64());
    }
}

/// The Simplex uploader stopped before accepting or persisting an upload.
#[derive(Debug, thiserror::Error)]
#[error("Simplex certificate uploader stopped")]
pub struct CertificateUploaderStopped;

/// Failure to submit a finalized block for durable upload.
#[derive(Debug, thiserror::Error)]
pub enum PublishFinalizedBlockError {
    /// The finalization certifies a different Constantinople block.
    #[error("Simplex finalization commitment does not embed the block seal")]
    CommitmentBlockMismatch,
    /// The background uploader stopped before accepting the finalized block.
    #[error(transparent)]
    UploaderStopped(#[from] CertificateUploaderStopped),
}

/// Completion signal for an exact finalized block upload.
#[must_use = "persistence is not complete until this completion resolves"]
pub struct FinalizedBlockUploadCompletion {
    rx: oneshot::Receiver<()>,
}

impl FinalizedBlockUploadCompletion {
    /// Wait until the block and its exact finalization are durable.
    pub async fn wait(self) -> Result<(), CertificateUploaderStopped> {
        self.rx.await.map_err(|_| CertificateUploaderStopped)
    }
}

impl<H, P, S> CertificateReporter<H, P, S>
where
    H: Hasher,
    P: PublicKey,
    S: Scheme,
{
    /// Build a reporter and background uploader.
    pub fn connect<Cx: RuntimeMetrics + Spawner>(
        context: Cx,
        store_url: &str,
        api_key: Option<&str>,
        max_in_flight: usize,
    ) -> Result<(Self, Handle<()>), crate::StoreClientBuildError>
    where
        H: Hasher + Send + Sync + 'static,
        P: PublicKey + Send + Sync + 'static,
        S: Scheme + Send + Sync + 'static,
        S::Certificate: Send + Sync,
    {
        assert!(
            max_in_flight > 0,
            "Simplex upload concurrency must be positive"
        );
        let store_client = crate::store::writer_store_client(store_url, api_key)?;
        let client = SimplexWriter::new(
            crate::namespaces::simplex_client(&store_client)
                .expect("simplex namespace prefix must be valid"),
        );
        let (tx, rx) = mpsc::channel(max_in_flight);
        let metrics = SimplexUploadMetrics::new(&context);
        let commit_metrics = super::StoreCommitMetrics::new(&context);
        let uploader_metrics = metrics.clone();
        let join = context.spawn(move |context| {
            run_uploader::<Cx, H, P, S>(
                context,
                client,
                rx,
                max_in_flight,
                commit_metrics,
                uploader_metrics,
            )
        });
        Ok((Self { tx, metrics }, join))
    }

    /// Queue a block and its exact finalization for one durable Store commit.
    pub async fn publish_finalized_block(
        &self,
        block: Arc<EngineBlock<H, P>>,
        finalization: simplex::types::Finalization<S, EngineCommitment<H, P>>,
    ) -> Result<FinalizedBlockUploadCompletion, PublishFinalizedBlockError>
    where
        H: Hasher,
        P: PublicKey,
    {
        if finalization.proposal.payload.block() != *block.seal() {
            return Err(PublishFinalizedBlockError::CommitmentBlockMismatch);
        }

        let (completion, rx) = oneshot::channel();
        let upload = QueuedUpload::new(block, finalization, completion);
        enqueue_upload(&self.tx, &self.metrics, upload).await?;
        Ok(FinalizedBlockUploadCompletion { rx })
    }
}

impl<H, P, S> Clone for CertificateReporter<H, P, S>
where
    H: Hasher,
    P: PublicKey,
    S: Scheme,
{
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

async fn enqueue_upload<H, P, S>(
    tx: &mpsc::Sender<QueuedUpload<H, P, S>>,
    metrics: &SimplexUploadMetrics,
    mut upload: QueuedUpload<H, P, S>,
) -> Result<(), CertificateUploaderStopped>
where
    H: Hasher + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send,
{
    let permit = tx
        .reserve()
        .instrument(upload.trace.enqueue_wait_span())
        .await
        .map_err(|_| CertificateUploaderStopped)?;
    metrics.queue_depth.inc();
    upload.prepare_wait = Some(upload.trace.prepare_wait_span());
    permit.send(upload);
    Ok(())
}

struct QueuedUpload<H, P, S>
where
    H: Hasher,
    P: PublicKey,
    S: Scheme,
{
    block: Arc<EngineBlock<H, P>>,
    finalization: simplex::types::Finalization<S, EngineCommitment<H, P>>,
    completion: oneshot::Sender<()>,
    queued_at: Instant,
    trace: SimplexTrace,
    prepare_wait: Option<Span>,
}

impl<H, P, S> QueuedUpload<H, P, S>
where
    H: Hasher,
    P: PublicKey,
    S: Scheme,
{
    fn new(
        block: Arc<EngineBlock<H, P>>,
        finalization: simplex::types::Finalization<S, EngineCommitment<H, P>>,
        completion: oneshot::Sender<()>,
    ) -> Self {
        let trace = SimplexTrace::new(block.height().get());
        Self {
            block,
            finalization,
            completion,
            queued_at: Instant::now(),
            trace,
            prepare_wait: None,
        }
    }
}

#[derive(Clone)]
struct SimplexTrace {
    parent: Span,
    dispatch: Dispatch,
    height: u64,
    body_bytes: Option<usize>,
}

impl SimplexTrace {
    fn new(height: u64) -> Self {
        Self {
            parent: Span::current(),
            dispatch: tracing::dispatcher::get_default(Clone::clone),
            height,
            body_bytes: None,
        }
    }

    const fn with_body_bytes(mut self, body_bytes: usize) -> Self {
        self.body_bytes = Some(body_bytes);
        self
    }

    fn enqueue_wait_span(&self) -> Span {
        let span = info_span!(
            parent: &self.parent,
            "indexer.simplex.enqueue_wait",
            height = field::Empty,
        );
        self.record_fields(&span);
        span
    }

    fn prepare_wait_span(&self) -> Span {
        let span = info_span!(
            parent: &self.parent,
            "indexer.simplex.prepare_wait",
            height = field::Empty,
        );
        self.record_fields(&span);
        span
    }

    fn prepare_span(&self) -> Span {
        let span = info_span!(
            parent: &self.parent,
            "indexer.simplex.prepare",
            height = field::Empty,
        );
        self.record_fields(&span);
        span
    }

    fn encode_body_span(&self) -> Span {
        let span = info_span!(
            parent: &self.parent,
            "indexer.simplex.encode_body",
            height = field::Empty,
            body_bytes = field::Empty,
        );
        self.record_fields(&span);
        span
    }

    fn prepare_rows_span(&self) -> Span {
        let span = info_span!(
            parent: &self.parent,
            "indexer.simplex.prepare_rows",
            height = field::Empty,
            body_bytes = field::Empty,
        );
        self.record_fields(&span);
        span
    }

    fn stage_rows_span(&self) -> Span {
        let span = info_span!(
            parent: &self.parent,
            "indexer.simplex.stage_rows",
            height = field::Empty,
            body_bytes = field::Empty,
        );
        self.record_fields(&span);
        span
    }

    fn persist_span(&self) -> Span {
        let span = info_span!(
            parent: &self.parent,
            "indexer.simplex.persist",
            height = field::Empty,
            body_bytes = field::Empty,
        );
        self.record_fields(&span);
        span
    }

    fn record_fields(&self, span: &Span) {
        span.record("height", self.height);
        if let Some(body_bytes) = self.body_bytes {
            span.record("body_bytes", body_bytes);
        }
    }
}

async fn run_uploader<Cx, H, P, S>(
    context: Cx,
    client: SimplexWriter,
    mut rx: mpsc::Receiver<QueuedUpload<H, P, S>>,
    max_in_flight: usize,
    commit_metrics: super::StoreCommitMetrics,
    metrics: SimplexUploadMetrics,
) where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send + Sync,
{
    let mut uploads = FuturesUnordered::<Handle<()>>::new();
    let mut rx_open = true;

    // Each upload carries its own block and finalization, so uploads share no
    // state and only the in-flight bound limits how many run at once.
    while rx_open || !uploads.is_empty() {
        tokio::select! {
            result = uploads.next(), if !uploads.is_empty() => {
                result
                    .expect("non-empty Simplex upload set must yield a task")
                    .expect("Simplex upload task failed");
            }
            upload = rx.recv(), if rx_open && uploads.len() < max_in_flight => {
                match upload {
                    Some(upload) => {
                        metrics.observe_dequeued(&upload);
                        spawn_upload(
                            &mut uploads,
                            context.child("upload"),
                            &client,
                            &commit_metrics,
                            &metrics,
                            upload,
                        );
                    }
                    None => rx_open = false,
                }
            }
        }
    }
    debug!("simplex certificate uploader task exiting after channel closure");
}

fn spawn_upload<Cx, H, P, S>(
    uploads: &mut FuturesUnordered<Handle<()>>,
    context: Cx,
    client: &SimplexWriter,
    commit_metrics: &super::StoreCommitMetrics,
    metrics: &SimplexUploadMetrics,
    upload: QueuedUpload<H, P, S>,
) where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send + Sync,
{
    let client = client.clone();
    let commit_metrics = commit_metrics.clone();
    let metrics = metrics.clone();
    let dispatch = upload.trace.dispatch.clone();
    uploads.push(context.shared(true).spawn(move |_| {
        async move {
            let QueuedUpload {
                block,
                finalization,
                completion,
                queued_at,
                trace,
                prepare_wait,
            } = upload;
            drop(prepare_wait);

            let body_bytes = block.body.encode_size();
            let trace = trace.with_body_bytes(body_bytes);
            let mut prepared = trace
                .prepare_span()
                .in_scope(|| prepare_upload(&client, &trace, &block, finalization));
            metrics.body_bytes.observe(body_bytes as f64);

            let mut batch = StoreWriteBatch::new();
            trace.stage_rows_span().in_scope(|| {
                client
                    .stage_upload(&mut prepared, &mut batch)
                    .expect("prepared simplex upload must stage");
            });
            let receipt = async {
                let seq = super::commit_with_retry(
                    client.store_client().client(),
                    &batch,
                    super::CommitKind::Simplex,
                    &commit_metrics,
                )
                .await
                .expect("Simplex Store commit was rejected");
                client.mark_upload_persisted(prepared, seq).await
            }
            .instrument(trace.persist_span())
            .await;

            metrics
                .block_persist_duration
                .observe(queued_at.elapsed().as_secs_f64());
            let _ = completion.send(());
            debug!(
                headers = receipt.summary.headers,
                blocks = receipt.summary.blocks,
                finalizations = receipt.summary.finalizations,
                store_sequence = receipt.store_sequence_number,
                "indexer uploaded simplex data"
            );
        }
        .with_subscriber(dispatch)
    }));
}

/// Prepares the block and its finalization as one Store upload.
fn prepare_upload<H, P, S>(
    client: &SimplexWriter,
    trace: &SimplexTrace,
    block: &EngineBlock<H, P>,
    finalization: simplex::types::Finalization<S, EngineCommitment<H, P>>,
) -> PreparedUpload
where
    H: Hasher,
    P: PublicKey,
    S: Scheme,
{
    let certified = CertifiedHeader::new(finalization.proposal.payload, block);
    let finalized = Finalized::new(finalization, certified)
        .expect("validated finalization must match its certified header");
    let (header, body) = trace
        .encode_body_span()
        .in_scope(|| crate::simplex_block::encode_simplex_block_parts(block));
    trace.prepare_rows_span().in_scope(|| {
        let mut prepared = client.prepare_block(&header, body);
        prepared.extend(
            client
                .prepare_finalized(&finalized)
                .expect("validated finalization upload must prepare"),
        );
        prepared
    })
}

/// A finalized header tagged with the marshal commitment certified by Simplex.
#[derive(Debug, PartialEq, Eq)]
pub struct CertifiedHeader<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    commitment: EngineCommitment<H, P>,
    header: EngineHeader<H, P>,
}

impl<H, P> Clone for CertifiedHeader<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment,
            header: self.header.clone(),
        }
    }
}

impl<H, P> CertifiedHeader<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn new(commitment: EngineCommitment<H, P>, block: &EngineBlock<H, P>) -> Self {
        debug_assert_eq!(commitment.block(), *block.seal());
        let header = EngineHeader::<H, P>::new_unchecked(block.header.clone(), *block.seal());
        Self { commitment, header }
    }

    /// Return the certified Constantinople block header.
    pub const fn header(&self) -> &EngineHeader<H, P> {
        &self.header
    }

    /// Return the certified block digest embedded in the marshal commitment.
    pub fn block_digest(&self) -> H::Digest {
        self.commitment.block()
    }
}

impl<H, P> Heightable for CertifiedHeader<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn height(&self) -> Height {
        self.header.height()
    }
}

impl<H, P> Digestible for CertifiedHeader<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    type Digest = EngineCommitment<H, P>;

    fn digest(&self) -> Self::Digest {
        self.commitment
    }
}

impl<H, P> Block for CertifiedHeader<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn parent(&self) -> Self::Digest {
        self.header.context.parent.1
    }
}

impl<H, P> EncodeSize for CertifiedHeader<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn encode_size(&self) -> usize {
        self.commitment.encode_size() + self.header.encode_size()
    }
}

impl<H, P> Write for CertifiedHeader<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.commitment.write(buf);
        self.header.write(buf);
    }
}

impl<H, P> Read for CertifiedHeader<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let commitment = EngineCommitment::<H, P>::read(buf)?;
        let header = EngineHeader::<H, P>::read(buf)?;
        if commitment.block() != *header.seal() {
            return Err(CodecError::Invalid(
                "CertifiedHeader",
                "commitment block digest does not match header",
            ));
        }
        Ok(Self { commitment, header })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode as _;
    use commonware_consensus::{
        simplex::{
            scheme::bls12381_threshold::standard,
            types::{Context as SimplexContext, Finalization, Finalize, Proposal},
        },
        types::{Round, View},
    };
    use commonware_cryptography::{
        Digest as _, Signer as _,
        bls12381::primitives::variant::MinSig,
        ed25519,
        sha256::{Digest as Sha256Digest, Sha256},
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, Supervisor as _, telemetry::metrics::has_metric_value};
    use commonware_utils::{NZU16, non_empty_range};
    use constantinople_engine::ThresholdScheme;
    use constantinople_primitives::{
        Block, Header, Sealable, TRANSACTION_NAMESPACE, Transaction, TransactionPublicKey,
    };
    use exoware_simplex::SimplexReader;
    use rand::{SeedableRng, rngs::StdRng};
    use std::{num::NonZeroU64, time::Duration};

    type TestReporter = CertificateReporter<
        Sha256,
        ed25519::PublicKey,
        ThresholdScheme<ed25519::PublicKey, MinSig>,
    >;
    type TestCommitment = EngineCommitment<Sha256, ed25519::PublicKey>;

    #[test]
    fn finalized_block_completion_implies_exact_persistence() {
        commonware_runtime::tokio::Runner::new(
            commonware_runtime::tokio::Config::default().with_worker_threads(1),
        )
        .start(|context| async move {
            let store = crate::test_store::GatedIngestStore::open()
                .await
                .expect("spawn gated Store");
            let (reporter, uploader) =
                TestReporter::connect(context.child("metrics"), &store.url, None, 1)
                    .expect("reporter connects");
            let block = test_block(1);
            let digest = *block.seal();
            let body_bytes = block.body.encode_size();
            let finalization = test_finalization(&block);
            let (expected_header, expected_body) =
                crate::simplex_block::encode_simplex_block_parts(&block);
            let expected_block =
                exoware_simplex::encode_block_data(&expected_header, &expected_body);
            let expected = Finalized::new(
                finalization.clone(),
                CertifiedHeader::new(finalization.proposal.payload, &block),
            )
            .expect("finalization matches block")
            .encode();

            let completion = reporter
                .publish_finalized_block(block, finalization)
                .await
                .expect("uploader accepts finalized block");
            let mut wait = Box::pin(completion.wait());
            store.wait_for_first_ingest().await;
            assert!(
                tokio::time::timeout(Duration::from_millis(10), wait.as_mut())
                    .await
                    .is_err(),
                "completion resolved before Store persistence"
            );
            store.release_first_ingest();
            wait.await.expect("finalized block upload completes");

            let client = SimplexReader::new(
                crate::namespaces::simplex_client(
                    &crate::store_client(&store.url, None).expect("Store client builds"),
                )
                .expect("simplex namespace"),
            );
            assert_eq!(
                client
                    .get_block_raw(&digest)
                    .await
                    .expect("read uploaded block")
                    .expect("block is persisted"),
                expected_block
            );
            assert_eq!(
                client
                    .get_finalized_by_height_raw(Height::new(1))
                    .await
                    .expect("read uploaded finalization")
                    .expect("finalization is persisted"),
                expected
            );
            let encoded_metrics = context.encode();
            assert!(
                has_metric_value(&encoded_metrics, "store_commits_total", 1),
                "{encoded_metrics}"
            );
            assert!(has_metric_value(&encoded_metrics, "queue_depth", 0));
            assert!(has_metric_value(
                &encoded_metrics,
                "input_queue_wait_duration_count",
                1
            ));
            assert!(has_metric_value(
                &encoded_metrics,
                "block_persist_duration_count",
                1
            ));
            assert!(has_metric_value(&encoded_metrics, "body_bytes_count", 1));
            assert!(
                has_metric_value(
                    &encoded_metrics,
                    "body_bytes_sum",
                    format!("{body_bytes}.0")
                ),
                "{encoded_metrics}"
            );

            drop(reporter);
            uploader.await.expect("uploader exits cleanly");
            store.shutdown().await;
        });
    }

    #[test]
    fn publish_finalized_block_rejects_commitment_mismatch() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (server, url) = exoware_simulator::open_temp()
                .await
                .expect("spawn simulator");
            let (reporter, uploader) =
                TestReporter::connect(context.child("metrics"), &url, None, 1)
                    .expect("reporter connects");
            let finalization = test_finalization(&test_block(2));

            assert!(matches!(
                reporter
                    .publish_finalized_block(test_block(1), finalization)
                    .await,
                Err(PublishFinalizedBlockError::CommitmentBlockMismatch)
            ));
            let encoded_metrics = context.encode();
            assert!(has_metric_value(&encoded_metrics, "queue_depth", 0));

            drop(reporter);
            uploader.await.expect("uploader exits cleanly");
            server.abort();
        });
    }

    #[test]
    fn publish_finalized_block_reports_stopped_uploader() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (reporter, uploader) =
                TestReporter::connect(context.child("metrics"), "http://127.0.0.1:1", None, 1)
                    .expect("reporter connects");
            uploader.abort();
            let _ = uploader.await;
            let block = test_block(1);
            let finalization = test_finalization(&block);

            assert!(matches!(
                reporter.publish_finalized_block(block, finalization).await,
                Err(PublishFinalizedBlockError::UploaderStopped(
                    CertificateUploaderStopped
                ))
            ));
        });
    }

    #[test]
    fn finalized_block_completion_reports_stopped_uploader() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (reporter, uploader) =
                TestReporter::connect(context.child("metrics"), "http://127.0.0.1:1", None, 1)
                    .expect("reporter connects");
            let block = test_block(1);
            let finalization = test_finalization(&block);
            let completion = reporter
                .publish_finalized_block(block, finalization)
                .await
                .expect("uploader accepts finalized block");
            uploader.abort();
            let _ = uploader.await;

            assert!(matches!(
                completion.wait().await,
                Err(CertificateUploaderStopped)
            ));
        });
    }

    #[test]
    fn reporter_sends_configured_credentials() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let store = crate::test_store::ObservedStore::open("writer-key")
                .await
                .expect("spawn observed Store");
            let (reporter, uploader) =
                TestReporter::connect(context.child("metrics"), &store.url, Some("writer-key"), 1)
                    .expect("reporter connects");
            let block = test_block(1);
            let finalization = test_finalization(&block);

            let completion = reporter
                .publish_finalized_block(block, finalization)
                .await
                .expect("uploader accepts finalized block");
            completion
                .wait()
                .await
                .expect("finalized block upload completes");

            let requests = store.requests();
            assert!(!requests.is_empty());
            assert!(requests.iter().all(|request| request.authorized));
            assert!(
                requests
                    .iter()
                    .any(|request| request.path.starts_with("/log.ingest.v1.Service/")),
                "Simplex upload should reach Store ingest. Observed RPCs were {requests:?}",
            );

            drop(reporter);
            uploader.await.expect("uploader exits cleanly");
            store.shutdown().await;
        });
    }

    #[test]
    fn queued_blocks_commit_separately() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (server, url) = exoware_simulator::open_temp()
                .await
                .expect("spawn simulator");
            let metrics_context = context.child("metrics");
            let metrics = SimplexUploadMetrics::new(&metrics_context);
            let commit_metrics = super::super::StoreCommitMetrics::new(&metrics_context);
            let client = SimplexWriter::new(
                crate::namespaces::simplex_client(
                    &crate::store::writer_store_client(&url, None).expect("Store client builds"),
                )
                .expect("simplex namespace"),
            );
            let (tx, rx) = mpsc::channel(2);
            let (first_tx, first_rx) = oneshot::channel();
            let (second_tx, second_rx) = oneshot::channel();
            let first_block = test_block(1);
            let first_finalization = test_finalization(&first_block);
            let second_block = test_block(2);
            let second_finalization = test_finalization(&second_block);

            enqueue_upload(
                &tx,
                &metrics,
                QueuedUpload::new(first_block, first_finalization, first_tx),
            )
            .await
            .expect("queue first block");
            enqueue_upload(
                &tx,
                &metrics,
                QueuedUpload::new(second_block, second_finalization, second_tx),
            )
            .await
            .expect("queue second block");
            drop(tx);

            run_uploader::<
                _,
                Sha256,
                ed25519::PublicKey,
                ThresholdScheme<ed25519::PublicKey, MinSig>,
            >(
                context.child("uploader"),
                client,
                rx,
                1,
                commit_metrics.clone(),
                metrics.clone(),
            )
            .await;
            first_rx.await.expect("first block upload completes");
            second_rx.await.expect("second block upload completes");

            let encoded_metrics = context.encode();
            assert!(
                has_metric_value(&encoded_metrics, "store_commits_total", 2),
                "{encoded_metrics}"
            );
            server.abort();
        });
    }

    #[test]
    fn later_upload_proceeds_while_earlier_commit_is_pending() {
        commonware_runtime::tokio::Runner::new(
            commonware_runtime::tokio::Config::default().with_worker_threads(1),
        )
        .start(|context| async move {
            let store = crate::test_store::GatedIngestStore::open()
                .await
                .expect("spawn gated Store");
            let metrics_context = context.child("metrics");
            let metrics = SimplexUploadMetrics::new(&metrics_context);
            let commit_metrics = super::super::StoreCommitMetrics::new(&metrics_context);
            let client = SimplexWriter::new(
                crate::namespaces::simplex_client(
                    &crate::store::writer_store_client(&store.url, None)
                        .expect("Store client builds"),
                )
                .expect("simplex namespace"),
            );
            let (tx, rx) = mpsc::channel(2);
            let uploader = tokio::spawn(run_uploader::<
                _,
                Sha256,
                ed25519::PublicKey,
                ThresholdScheme<ed25519::PublicKey, MinSig>,
            >(
                context.child("uploader"),
                client,
                rx,
                2,
                commit_metrics,
                metrics.clone(),
            ));
            let first_block = test_block(1);
            let first_finalization = test_finalization(&first_block);
            let second_block = test_block(2);
            let second_finalization = test_finalization(&second_block);
            let (first_completion, first_completion_rx) = oneshot::channel();
            let (second_completion, second_completion_rx) = oneshot::channel();

            enqueue_upload(
                &tx,
                &metrics,
                QueuedUpload::new(first_block, first_finalization, first_completion),
            )
            .await
            .expect("queue first block");
            store.wait_for_first_ingest().await;
            enqueue_upload(
                &tx,
                &metrics,
                QueuedUpload::new(second_block, second_finalization, second_completion),
            )
            .await
            .expect("queue second block");

            let second_upload_started = store
                .later_ingest_arrives_within(Duration::from_millis(250))
                .await;
            store.release_first_ingest();
            first_completion_rx
                .await
                .expect("first block upload completes");
            second_completion_rx
                .await
                .expect("second block upload completes");
            drop(tx);
            uploader.await.expect("uploader exits cleanly");
            store.shutdown().await;

            assert!(
                second_upload_started,
                "pending Store commit blocked a later upload within the in-flight limit"
            );
        });
    }

    fn test_block(height: u64) -> Arc<EngineBlock<Sha256, ed25519::PublicKey>> {
        let leader = ed25519::PrivateKey::from_seed(1).public_key();
        let signer = ed25519::PrivateKey::from_seed(2);
        let sender = TransactionPublicKey::ed25519(signer.public_key());
        let transaction = Transaction::<Sha256Digest>::new(
            sender.clone(),
            sender,
            NonZeroU64::new(1).expect("transaction value is non-zero"),
            0,
        )
        .seal_and_sign(&signer, TRANSACTION_NAMESPACE, &mut Sha256::default());
        let header = Header {
            context: SimplexContext {
                round: Round::zero(),
                leader,
                parent: (View::zero(), TestCommitment::EMPTY),
            },
            parent: Sha256Digest::EMPTY,
            height,
            timestamp: 0,
            state_root: Sha256Digest::EMPTY,
            state_range: non_empty_range!(0, 2),
            transactions_root: Sha256Digest::EMPTY,
            transactions_range: non_empty_range!(0, 2),
        };
        let block = Block::new(header, vec![transaction]).seal(&mut Sha256::default());
        Arc::new(EngineBlock::from(block))
    }

    fn test_finalization(
        block: &EngineBlock<Sha256, ed25519::PublicKey>,
    ) -> Finalization<ThresholdScheme<ed25519::PublicKey, MinSig>, TestCommitment> {
        let mut rng = StdRng::from_seed([7; 32]);
        let fixture = standard::fixture::<MinSig, _>(&mut rng, b"indexer-test", 4);
        let commitment = TestCommitment::from((
            *block.seal(),
            Sha256Digest::EMPTY,
            Sha256Digest::EMPTY,
            commonware_coding::Config {
                minimum_shards: NZU16!(1),
                extra_shards: NZU16!(1),
            },
        ));
        let proposal = Proposal::new(
            block.header.context.round,
            block.header.context.parent.0,
            commitment,
        );
        let finalizes = fixture
            .schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("sign finalization"))
            .collect::<Vec<_>>();
        let finalizes = commonware_utils::iter::NonEmpty::try_new(finalizes.iter())
            .expect("test finalizations are non-empty");
        Finalization::from_finalizes(&fixture.verifier, finalizes, &Sequential)
            .expect("assemble finalization")
    }
}
