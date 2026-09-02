//! Simplex certificate reporter backed by the chain Store.
//!
//! Consensus finalizes marshal commitments. Each commitment embeds the digest
//! of the Constantinople block header it certifies. This reporter writes full
//! block `{ header, body }` data by header digest for body reads, and writes
//! certificate artifacts with only the commitment-tagged header so height/latest
//! verification does not fetch the full body.

use ahash::AHashMap;
use bytes::Buf;
use commonware_actor::Feedback;
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_consensus::{
    Block, Heightable, Reporter,
    simplex::{self, types::Activity},
    types::Height,
};
use commonware_cryptography::{Digestible, Hasher, PublicKey, certificate::Scheme};
use commonware_runtime::{
    Metrics as RuntimeMetrics,
    telemetry::metrics::{Gauge, Histogram, MetricsExt as _},
};
use constantinople_engine::types::{EngineBlock, EngineCommitment, EngineHeader};
use exoware_sdk::StoreWriteBatch;
use exoware_simplex::{Finalized, Notarized, PreparedUpload, SimplexClient};
use std::{collections::VecDeque, sync::Arc, time::Instant};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
};
use tracing::{debug, warn};

/// Cloneable reporter over Simplex activity.
pub struct CertificateReporter<H, P, S>
where
    H: Hasher + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send,
{
    tx: mpsc::Sender<QueuedSimplexInput<H, P, S>>,
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

    fn observe_dequeued<H, P, S>(&self, input: &QueuedSimplexInput<H, P, S>)
    where
        H: Hasher,
        P: PublicKey,
        S: Scheme,
    {
        self.queue_depth.dec();
        self.input_queue_wait_duration
            .observe(input.queued_at.elapsed().as_secs_f64());
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

/// Completion signal for a digest-addressed Simplex block upload.
pub struct BlockUploadCompletion {
    rx: oneshot::Receiver<()>,
}

impl BlockUploadCompletion {
    /// Wait until the block upload has been marked persisted.
    pub async fn wait(self) -> Result<(), CertificateUploaderStopped> {
        self.rx.await.map_err(|_| CertificateUploaderStopped)
    }
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
    pub fn connect(
        context: &impl RuntimeMetrics,
        store_url: &str,
        api_key: Option<&str>,
        max_in_flight: usize,
    ) -> Result<(Self, JoinHandle<()>), crate::StoreClientBuildError>
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
        let client = SimplexClient::new(
            crate::namespaces::simplex_client(&store_client)
                .expect("simplex namespace prefix must be valid"),
        );
        let (tx, rx) = mpsc::channel(max_in_flight);
        let metrics = SimplexUploadMetrics::new(context);
        let join = tokio::spawn(run_uploader::<H, P, S>(
            client,
            rx,
            max_in_flight,
            super::StoreCommitMetrics::new(context),
            metrics.clone(),
        ));
        Ok((Self { tx, metrics }, join))
    }

    /// Queue a finalized block for digest-addressed block upload and later
    /// certificate pairing.
    pub async fn publish_block(
        &self,
        block: Arc<EngineBlock<H, P>>,
    ) -> Result<BlockUploadCompletion, CertificateUploaderStopped>
    where
        H: Hasher,
        P: PublicKey,
    {
        let (completion, rx) = oneshot::channel();
        let input = QueuedSimplexInput::new(SimplexInput::Block { block, completion });
        enqueue_input(&self.tx, &self.metrics, input).await?;
        Ok(BlockUploadCompletion { rx })
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
        let input = QueuedSimplexInput::new(SimplexInput::FinalizedBlock {
            block,
            finalization,
            completion,
        });
        enqueue_input(&self.tx, &self.metrics, input).await?;
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

impl<H, P, S> Reporter for CertificateReporter<H, P, S>
where
    H: Hasher + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send,
    simplex::types::Notarization<S, EngineCommitment<H, P>>: Send,
    simplex::types::Finalization<S, EngineCommitment<H, P>>: Send,
{
    type Activity = Activity<S, EngineCommitment<H, P>>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match activity {
            Activity::Notarization(notarization) => {
                dispatch_input(
                    &self.tx,
                    &self.metrics,
                    SimplexInput::Notarization(notarization),
                );
            }
            Activity::Finalization(finalization) => {
                dispatch_input(
                    &self.tx,
                    &self.metrics,
                    SimplexInput::Finalization(finalization),
                );
            }
            _ => {}
        }
        Feedback::Ok
    }
}

async fn enqueue_input<H, P, S>(
    tx: &mpsc::Sender<QueuedSimplexInput<H, P, S>>,
    metrics: &SimplexUploadMetrics,
    input: QueuedSimplexInput<H, P, S>,
) -> Result<(), CertificateUploaderStopped>
where
    H: Hasher + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send,
{
    let permit = tx.reserve().await.map_err(|_| CertificateUploaderStopped)?;
    metrics.queue_depth.inc();
    permit.send(input);
    Ok(())
}

fn dispatch_input<H, P, S>(
    tx: &mpsc::Sender<QueuedSimplexInput<H, P, S>>,
    metrics: &SimplexUploadMetrics,
    input: SimplexInput<H, P, S>,
) where
    H: Hasher + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send,
{
    let tx = tx.clone();
    let metrics = metrics.clone();
    let input = QueuedSimplexInput::new(input);
    tokio::spawn(async move {
        if let Err(error) = enqueue_input(&tx, &metrics, input).await {
            warn!("simplex certificate uploader stopped; dropping activity: {error}");
        }
    });
}

struct QueuedSimplexInput<H, P, S>
where
    H: Hasher,
    P: PublicKey,
    S: Scheme,
{
    queued_at: Instant,
    input: SimplexInput<H, P, S>,
}

impl<H, P, S> QueuedSimplexInput<H, P, S>
where
    H: Hasher,
    P: PublicKey,
    S: Scheme,
{
    fn new(input: SimplexInput<H, P, S>) -> Self {
        Self {
            queued_at: Instant::now(),
            input,
        }
    }
}

enum SimplexInput<H, P, S>
where
    H: Hasher,
    P: PublicKey,
    S: Scheme,
{
    Block {
        block: Arc<EngineBlock<H, P>>,
        completion: oneshot::Sender<()>,
    },
    FinalizedBlock {
        block: Arc<EngineBlock<H, P>>,
        finalization: simplex::types::Finalization<S, EngineCommitment<H, P>>,
        completion: oneshot::Sender<()>,
    },
    Notarization(simplex::types::Notarization<S, EngineCommitment<H, P>>),
    Finalization(simplex::types::Finalization<S, EngineCommitment<H, P>>),
}

struct PendingBlockCertificates<H, P, S>
where
    H: Hasher,
    P: PublicKey,
    S: Scheme,
{
    block: Option<Arc<EngineBlock<H, P>>>,
    block_persisted: Option<watch::Receiver<bool>>,
    notarization: Option<simplex::types::Notarization<S, EngineCommitment<H, P>>>,
    finalization: Option<simplex::types::Finalization<S, EngineCommitment<H, P>>>,
}

impl<H, P, S> Default for PendingBlockCertificates<H, P, S>
where
    H: Hasher,
    P: PublicKey,
    S: Scheme,
{
    fn default() -> Self {
        Self {
            block: None,
            block_persisted: None,
            notarization: None,
            finalization: None,
        }
    }
}

struct ReadyUpload {
    prepared: PreparedUpload,
    body_bytes: usize,
    kind: ReadyUploadKind,
}

enum ReadyUploadKind {
    Block {
        persisted: watch::Sender<bool>,
        completion: oneshot::Sender<()>,
        queued_at: Instant,
    },
    FinalizedBlock {
        completion: oneshot::Sender<()>,
        queued_at: Instant,
    },
    Certificate {
        block_persisted: watch::Receiver<bool>,
    },
}

impl ReadyUpload {
    const fn block(
        prepared: PreparedUpload,
        body_bytes: usize,
        persisted: watch::Sender<bool>,
        completion: oneshot::Sender<()>,
        queued_at: Instant,
    ) -> Self {
        Self {
            prepared,
            body_bytes,
            kind: ReadyUploadKind::Block {
                persisted,
                completion,
                queued_at,
            },
        }
    }

    const fn finalized_block(
        prepared: PreparedUpload,
        body_bytes: usize,
        completion: oneshot::Sender<()>,
        queued_at: Instant,
    ) -> Self {
        Self {
            prepared,
            body_bytes,
            kind: ReadyUploadKind::FinalizedBlock {
                completion,
                queued_at,
            },
        }
    }

    const fn certificate(prepared: PreparedUpload, block_persisted: watch::Receiver<bool>) -> Self {
        Self {
            prepared,
            body_bytes: 0,
            kind: ReadyUploadKind::Certificate { block_persisted },
        }
    }

    fn can_start(&self) -> bool {
        match &self.kind {
            ReadyUploadKind::Block { .. } | ReadyUploadKind::FinalizedBlock { .. } => true,
            ReadyUploadKind::Certificate { block_persisted } => *block_persisted.borrow(),
        }
    }
}

async fn run_uploader<H, P, S>(
    client: SimplexClient,
    mut rx: mpsc::Receiver<QueuedSimplexInput<H, P, S>>,
    max_in_flight: usize,
    commit_metrics: super::StoreCommitMetrics,
    metrics: SimplexUploadMetrics,
) where
    H: Hasher + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send + Sync,
{
    let mut pending: AHashMap<Vec<u8>, PendingBlockCertificates<H, P, S>> = AHashMap::new();
    let mut uploads = JoinSet::new();
    let mut ready_uploads = VecDeque::new();
    let mut rx_open = true;
    loop {
        while uploads.len() < max_in_flight {
            let Some(index) = ready_uploads.iter().position(ReadyUpload::can_start) else {
                break;
            };
            let upload = ready_uploads
                .remove(index)
                .expect("ready Simplex upload index must exist");
            spawn_upload(&mut uploads, &client, &commit_metrics, &metrics, upload);
        }
        if !rx_open && uploads.is_empty() && ready_uploads.is_empty() {
            break;
        }
        let upload_waits_for_capacity = ready_uploads.iter().any(ReadyUpload::can_start);
        tokio::select! {
            result = uploads.join_next(), if !uploads.is_empty() => {
                result
                    .expect("non-empty Simplex upload set must yield a task")
                    .expect("Simplex upload task failed");
            }
            input = rx.recv(), if rx_open && !upload_waits_for_capacity => {
                match input {
                    Some(input) => {
                        metrics.observe_dequeued(&input);
                        ready_uploads.extend(prepare_input(&client, &mut pending, input));
                    }
                    None => rx_open = false,
                }
            }
        }
    }
    debug!("simplex certificate uploader task exiting after channel closure");
}

fn prepare_input<H, P, S>(
    client: &SimplexClient,
    pending: &mut AHashMap<Vec<u8>, PendingBlockCertificates<H, P, S>>,
    queued: QueuedSimplexInput<H, P, S>,
) -> Vec<ReadyUpload>
where
    H: Hasher + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send + Sync,
{
    let QueuedSimplexInput { queued_at, input } = queued;
    let input = match input {
        SimplexInput::FinalizedBlock {
            block,
            finalization,
            completion,
        } => {
            let body_bytes = block.body.encode_size();
            let commitment = finalization.proposal.payload;
            let certified = CertifiedHeader::new(commitment, &block);
            let finalized = Finalized::new(finalization, certified)
                .expect("validated finalization must match its certified header");
            let (header, body) = crate::simplex_block::encode_simplex_block_parts(&block);
            let mut prepared = client.prepare_block(&header, body);
            prepared.extend(
                client
                    .prepare_finalized(&finalized)
                    .expect("validated finalization upload must prepare"),
            );
            return vec![ReadyUpload::finalized_block(
                prepared, body_bytes, completion, queued_at,
            )];
        }
        input => input,
    };
    let key = input.block_digest_key();
    let entry = pending.entry(key.clone()).or_default();
    let mut ready = Vec::with_capacity(3);
    match input {
        SimplexInput::Block { block, completion } => {
            let body_bytes = block.body.encode_size();
            let (header, body) = crate::simplex_block::encode_simplex_block_parts(&block);
            let (block_persisted, block_persisted_rx) = watch::channel(false);
            ready.push(ReadyUpload::block(
                client.prepare_block(&header, body),
                body_bytes,
                block_persisted,
                completion,
                queued_at,
            ));
            entry.block = Some(block);
            entry.block_persisted = Some(block_persisted_rx);
        }
        SimplexInput::Notarization(notarization) => entry.notarization = Some(notarization),
        SimplexInput::Finalization(finalization) => entry.finalization = Some(finalization),
        SimplexInput::FinalizedBlock { .. } => unreachable!(),
    }
    let (certificates, finalized) = prepare_ready_certificates(client, entry);
    if !certificates.is_empty() {
        let block_persisted = entry
            .block_persisted
            .as_ref()
            .expect("ready certificates have a block persistence gate");
        ready.extend(
            certificates
                .into_iter()
                .map(|prepared| ReadyUpload::certificate(prepared, block_persisted.clone())),
        );
    }
    if finalized {
        pending.remove(&key);
    }
    ready
}

fn spawn_upload(
    uploads: &mut JoinSet<()>,
    client: &SimplexClient,
    commit_metrics: &super::StoreCommitMetrics,
    metrics: &SimplexUploadMetrics,
    upload: ReadyUpload,
) {
    let ReadyUpload {
        prepared,
        body_bytes,
        kind,
    } = upload;
    let (block_persisted, block_completion) = match kind {
        ReadyUploadKind::Block {
            persisted,
            completion,
            queued_at,
        } => (None, Some((Some(persisted), completion, queued_at))),
        ReadyUploadKind::FinalizedBlock {
            completion,
            queued_at,
        } => (None, Some((None, completion, queued_at))),
        ReadyUploadKind::Certificate { block_persisted } => (Some(block_persisted), None),
    };
    let mut batch = StoreWriteBatch::new();
    client
        .stage_upload(&prepared, &mut batch)
        .expect("prepared simplex upload must stage");
    metrics.body_bytes.observe(body_bytes as f64);
    let client = client.clone();
    let commit_metrics = commit_metrics.clone();
    let metrics = metrics.clone();
    uploads.spawn(async move {
        if let Some(mut block_persisted) = block_persisted {
            wait_for_block_persistence(&mut block_persisted).await;
        }
        let seq = super::commit_with_retry(
            client.store_client().client(),
            &batch,
            "simplex upload",
            &commit_metrics,
        )
        .await
        .expect("Simplex Store commit was rejected");
        let receipt = client.mark_upload_persisted(prepared, seq).await;
        if let Some((persisted, completion, queued_at)) = block_completion {
            if let Some(persisted) = persisted {
                persisted.send_replace(true);
            }
            metrics
                .block_persist_duration
                .observe(queued_at.elapsed().as_secs_f64());
            let _ = completion.send(());
        }
        debug!(
            headers = receipt.summary.headers,
            blocks = receipt.summary.blocks,
            notarizations = receipt.summary.notarizations,
            finalizations = receipt.summary.finalizations,
            store_sequence = receipt.store_sequence_number,
            "indexer uploaded simplex data"
        );
    });
}

async fn wait_for_block_persistence(persisted: &mut watch::Receiver<bool>) {
    if *persisted.borrow_and_update() {
        return;
    }
    persisted
        .changed()
        .await
        .expect("block upload stopped before dependent certificate persistence");
    assert!(
        *persisted.borrow_and_update(),
        "block persistence gate changed without completing"
    );
}

impl<H, P, S> SimplexInput<H, P, S>
where
    H: Hasher,
    P: PublicKey,
    S: Scheme,
{
    fn block_digest_key(&self) -> Vec<u8> {
        match self {
            Self::Block { block, .. } => block.seal().as_ref().to_vec(),
            Self::FinalizedBlock { block, .. } => block.seal().as_ref().to_vec(),
            Self::Notarization(notarization) => {
                block_digest_key::<H, P>(&notarization.proposal.payload)
            }
            Self::Finalization(finalization) => {
                block_digest_key::<H, P>(&finalization.proposal.payload)
            }
        }
    }
}

fn block_digest_key<H, P>(commitment: &EngineCommitment<H, P>) -> Vec<u8>
where
    H: Hasher,
    P: PublicKey,
{
    commitment.block().as_ref().to_vec()
}

/// Prepares the entry's ready certificates and reports when the entry is complete.
fn prepare_ready_certificates<H, P, S>(
    client: &SimplexClient,
    entry: &mut PendingBlockCertificates<H, P, S>,
) -> (Vec<PreparedUpload>, bool)
where
    H: Hasher + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send + Sync,
{
    let Some(block) = entry.block.as_deref() else {
        return (Vec::new(), false);
    };

    let mut prepared = Vec::with_capacity(2);
    if let Some(notarization) = entry.notarization.take() {
        let certified = CertifiedHeader::new(notarization.proposal.payload, block);
        let notarized =
            Notarized::new(notarization, certified).expect("notarization matches certified header");
        prepared.push(
            client
                .prepare_notarized(&notarized)
                .expect("notarization upload must prepare"),
        );
    }

    let mut staged_finalization = false;
    if let Some(finalization) = entry.finalization.take() {
        staged_finalization = true;
        let certified = CertifiedHeader::new(finalization.proposal.payload, block);
        let finalized =
            Finalized::new(finalization, certified).expect("finalization matches certified header");
        prepared.push(
            client
                .prepare_finalized(&finalized)
                .expect("finalization upload must prepare"),
        );
    }
    (prepared, staged_finalization)
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
    use rand::{SeedableRng, rngs::StdRng};
    use std::{num::NonZeroU64, time::Duration};

    type TestReporter = CertificateReporter<
        Sha256,
        ed25519::PublicKey,
        ThresholdScheme<ed25519::PublicKey, MinSig>,
    >;
    type TestCommitment = EngineCommitment<Sha256, ed25519::PublicKey>;

    #[test]
    fn block_completion_implies_store_persistence() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (server, url) = exoware_simulator::open_temp()
                .await
                .expect("spawn simulator");
            let (reporter, uploader) =
                TestReporter::connect(&context.child("metrics"), &url, None, 1)
                    .expect("reporter connects");
            let block = test_block(1);
            let digest = *block.seal();
            let body_bytes = block.body.encode_size();

            let completion = reporter
                .publish_block(block)
                .await
                .expect("uploader accepts block");
            completion.wait().await.expect("block upload completes");

            let encoded_metrics = context.encode();
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
            let client = SimplexClient::new(
                crate::namespaces::simplex_client(
                    &crate::store_client(&url, None).expect("Store client builds"),
                )
                .expect("simplex namespace"),
            );
            assert!(
                client
                    .get_block_raw(&digest)
                    .await
                    .expect("read uploaded block")
                    .is_some()
            );

            drop(reporter);
            uploader.await.expect("uploader exits cleanly");
            server.abort();
        });
    }

    #[test]
    fn finalized_block_completion_implies_exact_persistence() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let store = crate::test_store::GatedIngestStore::open()
                .await
                .expect("spawn gated Store");
            let (reporter, uploader) =
                TestReporter::connect(&context.child("metrics"), &store.url, None, 1)
                    .expect("reporter connects");
            let block = test_block(1);
            let digest = *block.seal();
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

            let client = SimplexClient::new(
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
                TestReporter::connect(&context.child("metrics"), &url, None, 1)
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
                TestReporter::connect(&context.child("metrics"), "http://127.0.0.1:1", None, 1)
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
                TestReporter::connect(&context.child("metrics"), "http://127.0.0.1:1", None, 1)
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
                TestReporter::connect(&context.child("metrics"), &store.url, Some("writer-key"), 1)
                    .expect("reporter connects");

            let completion = reporter
                .publish_block(test_block(1))
                .await
                .expect("uploader accepts block");
            completion.wait().await.expect("block upload completes");

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
            let client = SimplexClient::new(
                crate::namespaces::simplex_client(
                    &crate::store::writer_store_client(&url, None).expect("Store client builds"),
                )
                .expect("simplex namespace"),
            );
            let (tx, rx) = mpsc::channel(2);
            let (first_tx, first_rx) = oneshot::channel();
            let (second_tx, second_rx) = oneshot::channel();

            enqueue_input(
                &tx,
                &metrics,
                QueuedSimplexInput::new(SimplexInput::Block {
                    block: test_block(1),
                    completion: first_tx,
                }),
            )
            .await
            .expect("queue first block");
            enqueue_input(
                &tx,
                &metrics,
                QueuedSimplexInput::new(SimplexInput::Block {
                    block: test_block(2),
                    completion: second_tx,
                }),
            )
            .await
            .expect("queue second block");
            drop(tx);

            run_uploader::<Sha256, ed25519::PublicKey, ThresholdScheme<ed25519::PublicKey, MinSig>>(
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
    fn certificate_upload_waits_for_block_persistence() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let store = crate::test_store::GatedIngestStore::open()
                .await
                .expect("spawn gated Store");
            let metrics_context = context.child("metrics");
            let metrics = SimplexUploadMetrics::new(&metrics_context);
            let commit_metrics = super::super::StoreCommitMetrics::new(&metrics_context);
            let client = SimplexClient::new(
                crate::namespaces::simplex_client(
                    &crate::store::writer_store_client(&store.url, None)
                        .expect("Store client builds"),
                )
                .expect("simplex namespace"),
            );
            let (tx, rx) = mpsc::channel(2);
            let uploader = tokio::spawn(run_uploader::<
                Sha256,
                ed25519::PublicKey,
                ThresholdScheme<ed25519::PublicKey, MinSig>,
            >(
                client, rx, 2, commit_metrics, metrics.clone()
            ));
            let block = test_block(1);
            let finalization = test_finalization(&block);
            let (completion, completion_rx) = oneshot::channel();

            enqueue_input(
                &tx,
                &metrics,
                QueuedSimplexInput::new(SimplexInput::Block { block, completion }),
            )
            .await
            .expect("queue block");
            store.wait_for_first_ingest().await;
            enqueue_input(
                &tx,
                &metrics,
                QueuedSimplexInput::new(SimplexInput::Finalization(finalization)),
            )
            .await
            .expect("queue finalization");

            let certificate_overtook = store
                .later_ingest_arrives_within(Duration::from_millis(250))
                .await;
            store.release_first_ingest();
            completion_rx.await.expect("block upload completes");
            drop(tx);
            uploader.await.expect("uploader exits cleanly");
            let encoded_metrics = context.encode();
            assert!(
                encoded_metrics.lines().any(|line| {
                    line.contains("body_bytes_bucket{le=\"0.0\"}") && line.ends_with(" 1")
                }),
                "{encoded_metrics}"
            );
            assert!(
                !encoded_metrics.contains("inputs_per_commit"),
                "{encoded_metrics}"
            );
            store.shutdown().await;

            assert!(
                !certificate_overtook,
                "certificate upload reached Store before its block persisted"
            );
        });
    }

    #[test]
    fn unrelated_block_upload_ignores_certificate_dependency_waiters() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let store = crate::test_store::GatedIngestStore::open()
                .await
                .expect("spawn gated Store");
            let metrics_context = context.child("metrics");
            let metrics = SimplexUploadMetrics::new(&metrics_context);
            let commit_metrics = super::super::StoreCommitMetrics::new(&metrics_context);
            let client = SimplexClient::new(
                crate::namespaces::simplex_client(
                    &crate::store::writer_store_client(&store.url, None)
                        .expect("Store client builds"),
                )
                .expect("simplex namespace"),
            );
            let (tx, rx) = mpsc::channel(2);
            let uploader = tokio::spawn(run_uploader::<
                Sha256,
                ed25519::PublicKey,
                ThresholdScheme<ed25519::PublicKey, MinSig>,
            >(
                client, rx, 2, commit_metrics, metrics.clone()
            ));
            let first_block = test_block(1);
            let finalization = test_finalization(&first_block);
            let (first_completion, first_completion_rx) = oneshot::channel();
            let (second_completion, second_completion_rx) = oneshot::channel();

            enqueue_input(
                &tx,
                &metrics,
                QueuedSimplexInput::new(SimplexInput::Block {
                    block: first_block,
                    completion: first_completion,
                }),
            )
            .await
            .expect("queue first block");
            store.wait_for_first_ingest().await;
            enqueue_input(
                &tx,
                &metrics,
                QueuedSimplexInput::new(SimplexInput::Finalization(finalization)),
            )
            .await
            .expect("queue finalization");
            enqueue_input(
                &tx,
                &metrics,
                QueuedSimplexInput::new(SimplexInput::Block {
                    block: test_block(2),
                    completion: second_completion,
                }),
            )
            .await
            .expect("queue unrelated block");

            let unrelated_block_started = store
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
                unrelated_block_started,
                "certificate dependency waiter blocked an unrelated block upload"
            );
        });
    }

    #[test]
    fn publish_block_reports_stopped_uploader() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (reporter, uploader) =
                TestReporter::connect(&context.child("metrics"), "http://127.0.0.1:1", None, 1)
                    .expect("reporter connects");
            uploader.abort();
            let _ = uploader.await;

            assert!(matches!(
                reporter.publish_block(test_block(1)).await,
                Err(CertificateUploaderStopped)
            ));
        });
    }

    #[test]
    fn block_completion_reports_stopped_uploader() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (reporter, uploader) =
                TestReporter::connect(&context.child("metrics"), "http://127.0.0.1:1", None, 1)
                    .expect("reporter connects");
            let completion = reporter
                .publish_block(test_block(1))
                .await
                .expect("uploader accepts block");
            uploader.abort();
            let _ = uploader.await;

            assert!(matches!(
                completion.wait().await,
                Err(CertificateUploaderStopped)
            ));
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
