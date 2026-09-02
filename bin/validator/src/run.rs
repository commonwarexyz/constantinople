//! Starts a validator from a YAML config.

use crate::{
    config::{
        IndexerConfig, LoadedConfig, StartupModeConfig, load_deployer_config, load_local_config,
    },
    state_reader::StateDbReader,
};
use commonware_actor::Feedback;
use commonware_codec::{Encode, FixedSize, Read, ReadExt as _, Write};
use commonware_consensus::{Reporter, simplex::elector::RoundRobin, types::Epoch};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig,
    certificate::ConstantProvider,
    ed25519::{self, Batch, PublicKey},
    sha256::Sha256,
};
use commonware_formatting::hex;
use commonware_glue::stateful::{
    PruneConfig,
    db::SyncEngineConfig,
    probe::{Config as ProbeConfig, Probe},
};
use commonware_p2p::{
    Ingress, Manager as _, TrackedPeers,
    authenticated::{self, discovery},
};
use commonware_parallel::Rayon;
use commonware_runtime::{
    BufferPoolConfig, Metrics, Quota, Runner as _, Strategizer as _, Supervisor as _,
    buffer::paged::{self, CacheRef},
    telemetry::metrics::{Counter, Gauge, Histogram, MetricsExt as _},
    tokio::{
        Context as RuntimeContext,
        telemetry::{self, Logs},
        tracing::Config as TracesConfig,
    },
};
use commonware_storage::{
    metadata::{Config as MetadataConfig, Metadata},
    queue,
};
use commonware_utils::{
    NZDuration, NZU32, NZU64, NZUsize, Probability, TryCollect, ordered::Set, sequence::U64, union,
};
use constantinople_application::consensus::FinalizedHookFn;
use constantinople_engine::{
    CERTIFICATE_CHANNEL, Channels, Config as EngineConfig, Engine, MARSHAL_CHANNEL,
    MARSHAL_RESOLVER_CHANNEL, PROBE_CHANNEL, RESOLVER_CHANNEL, STATE_RESOLVER_CHANNEL, StartupMode,
    TRANSACTION_RESOLVER_CHANNEL, ThresholdScheme, VOTE_CHANNEL,
    types::{EngineActivity, EngineBlock, EngineCommitment, EngineMarshalMailbox},
};
use constantinople_indexer::{
    CertificateReporter, Publisher, StoreClientBuildError,
    namespaces::{
        PUBLICATION_TARGET_PREFIX_VALUE, SIMPLEX_PREFIX_VALUE, SQL_META_PREFIX_VALUE,
        STATE_QMDB_PREFIX_VALUE, TRANSACTIONS_QMDB_PREFIX_VALUE,
    },
    publisher::{
        PublisherMetrics,
        certificate::{CertificateUploaderStopped, PublishFinalizedBlockError},
        qmdb::{
            PublishError, QueuedFinalizedUpload, QueuedFinalizedUploadCfg, StoredFinalizedUpload,
        },
    },
    sql_schema::meta_schema_fingerprint,
};
use constantinople_mempool::webserver::{self, AccountReader, Mailbox};
use constantinople_primitives::PublicKeyCache;
use std::{
    collections::BTreeMap,
    future::Future,
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    path::PathBuf,
    pin::Pin,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use tokio::{
    sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, TryAcquireError, watch},
    task::{JoinHandle, JoinSet},
};
use tracing::{info, warn};

const MEMPOOL_MAILBOX_SIZE: usize = 65_536;

const STATE_SYNC_APPLY_BATCH_SIZE: NonZeroU64 = NZU64!(1024);
const PRUNE_CONFIG: PruneConfig = PruneConfig {
    maintenance_interval: NZUsize!(1024),
    retained_marshal_blocks: 1024,
    retained_qmdb_blocks: 32,
};
const PRUNABLE_ITEMS_PER_SECTION: NonZeroU64 = NZU64!(4_096);
const FINALIZED_QUEUE_ITEMS_PER_SECTION: NonZeroU64 = NZU64!(128);
const FINALIZED_QUEUE_PAGE_SIZE: NonZeroU16 = paged::page_size(65_536);
const FINALIZED_QUEUE_WRITE_BUFFER: NonZeroUsize = NZUsize!(1024 * 1024);
const NETWORK_BUFFER_POOL_MAX_SIZE: NonZeroUsize = NZUsize!(2 * 1024 * 1024);
const NETWORK_BUFFER_POOL_MAX_PER_CLASS: NonZeroU32 = NZU32!(1_024);
const NETWORK_CHANNEL_MAILBOX_BUDGET: usize = 1_024;
const STORAGE_BUFFER_POOL_MAX_PER_CLASS: NonZeroU32 = NZU32!(128);
const MAX_FINALIZED_QUEUE_UPLOADS: usize = 64;
const FINALIZED_UPLOAD_AMPLIFICATION: u64 = 8;
const FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES: u64 = 64 * 1024;
const FINALIZED_UPLOAD_DURATION_BUCKETS: [f64; 14] = [
    0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 15.0,
];
const CAPTURE_RECEIPT_KEY: U64 = U64::new(0);
const INITIAL_QMDB_END: u64 = 1;

/// Returns the default finalized-block window before a proposed mempool batch
/// is marked dropped.
///
/// The window covers two full primary-validator rotations after the batch's
/// proposed height. This gives late-finalizing proposals time to land before
/// the submitting client retries the batch.
fn default_mempool_drop_grace_blocks(num_validators: usize) -> u64 {
    u64::try_from(num_validators)
        .expect("validator count must fit in u64")
        .checked_mul(2)
        .expect("mempool drop grace block count overflowed")
}

fn buffer_pool_configs(
    worker_threads: usize,
    max_blocking_threads: usize,
) -> (BufferPoolConfig, BufferPoolConfig) {
    let storage_parallelism = worker_threads
        .checked_add(max_blocking_threads)
        .expect("storage buffer pool parallelism overflowed");
    let network_parallelism =
        NonZeroUsize::new(worker_threads).expect("network buffer pool parallelism is zero");
    let storage_parallelism =
        NonZeroUsize::new(storage_parallelism).expect("storage buffer pool parallelism is zero");

    let network_cfg = BufferPoolConfig::for_network()
        .with_size_class_range(
            NZUsize!(1024),
            NETWORK_BUFFER_POOL_MAX_SIZE,
            NETWORK_BUFFER_POOL_MAX_PER_CLASS,
        )
        .with_parallelism(network_parallelism);
    // Storage I/O can run on Tokio's blocking pool. Include those threads so
    // the pool's automatic TLS cache sizing does not strand scarce storage
    // buffers outside the global freelist under load.
    let storage_cfg = BufferPoolConfig::for_storage()
        .with_parallelism(storage_parallelism)
        .with_max_per_class(STORAGE_BUFFER_POOL_MAX_PER_CLASS);

    (network_cfg, storage_cfg)
}

/// Concrete type the engine sees in the `simplex_observer` slot.
///
/// We always pin `O` to the indexer's certificate publisher so the engine type
/// stays the same whether or not the indexer is enabled. Validators that opt
/// out simply pass `simplex_observer: None`.
type EngineCertReporter =
    CertificateReporter<Sha256, PublicKey, ThresholdScheme<PublicKey, MinSig>>;
type EnginePublisher = Publisher<Sha256, PublicKey>;
type EngineQueuedUpload = QueuedFinalizedUpload<Sha256, PublicKey, MinSig>;
type EngineStoredUpload = StoredFinalizedUpload<Sha256, PublicKey, MinSig>;
type FinalizedQueueWriter = queue::Writer<RuntimeContext, EngineStoredUpload>;
type FinalizedQueueReader = queue::Reader<RuntimeContext, EngineStoredUpload>;
type EngineMarshal = EngineMarshalMailbox<Sha256, PublicKey, MinSig>;
type CaptureMetadata = Metadata<RuntimeContext, U64, LatestCaptureReceipt>;
type CriticalTask = Pin<Box<dyn Future<Output = ()> + Send>>;
type ValidatorFinalizedHook =
    FinalizedHookFn<EngineCommitment<Sha256, PublicKey>, Sha256, PublicKey>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LatestCaptureReceipt {
    height: u64,
    block_digest: commonware_cryptography::sha256::Digest,
    state_end: u64,
    transaction_end: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CapturePosition {
    Captured,
    Next,
}

impl LatestCaptureReceipt {
    fn from_upload(upload: &EngineQueuedUpload) -> Self {
        Self {
            height: upload.height(),
            block_digest: *upload.block().seal(),
            state_end: upload.state_end(),
            transaction_end: upload.transaction_end(),
        }
    }

    fn matches_block(&self, block: &EngineBlock<Sha256, PublicKey>) -> bool {
        self.height == block.header.height
            && self.block_digest == *block.seal()
            && self.state_end == block.header.state_range.end()
            && self.transaction_end == block.header.transactions_range.end()
    }
}

impl FixedSize for LatestCaptureReceipt {
    const SIZE: usize =
        u64::SIZE + commonware_cryptography::sha256::Digest::SIZE + u64::SIZE + u64::SIZE;
}

impl Write for LatestCaptureReceipt {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.height.write(buf);
        self.block_digest.write(buf);
        self.state_end.write(buf);
        self.transaction_end.write(buf);
    }
}

impl Read for LatestCaptureReceipt {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            height: u64::read(buf)?,
            block_digest: commonware_cryptography::sha256::Digest::read(buf)?,
            state_end: u64::read(buf)?,
            transaction_end: u64::read(buf)?,
        })
    }
}

struct FinalizedReceiptStore {
    context: RuntimeContext,
    config: MetadataConfig<()>,
    metadata: Mutex<Option<CaptureMetadata>>,
}

#[derive(Clone)]
struct UploadBudgetMetrics {
    _configured_bytes: Gauge,
    reserved_bytes: Gauge,
    waiting_bytes: Gauge,
    admitted: Gauge,
    admission_blocked: Counter,
    oversized: Counter,
    reservation_held: Histogram,
}

impl UploadBudgetMetrics {
    fn new(context: &impl Metrics, configured_bytes: u64) -> Self {
        let configured = context.gauge(
            "configured_bytes",
            "Configured finalized upload memory budget in bytes",
        );
        configured.set(metric_bytes(configured_bytes));
        Self {
            _configured_bytes: configured,
            reserved_bytes: context.gauge(
                "reserved_bytes",
                "Estimated finalized upload bytes currently reserved",
            ),
            waiting_bytes: context.gauge(
                "waiting_bytes",
                "Estimated bytes for the finalized upload waiting for admission",
            ),
            admitted: context.gauge("admitted", "Finalized uploads currently admitted"),
            admission_blocked: context.counter(
                "admission_blocked",
                "Finalized uploads blocked by the byte budget",
            ),
            oversized: context.counter(
                "oversized",
                "Finalized uploads admitted exclusively above the byte budget",
            ),
            reservation_held: context.histogram(
                "reservation_held_duration",
                "Time finalized uploads hold an admission reservation (s)",
                FINALIZED_UPLOAD_DURATION_BUCKETS,
            ),
        }
    }
}

#[derive(Clone)]
struct UploadBudget {
    permits: Arc<Semaphore>,
    total_units: u32,
    metrics: UploadBudgetMetrics,
}

impl UploadBudget {
    fn new(context: &impl Metrics, configured_bytes: u64) -> Self {
        assert!(
            configured_bytes > 0,
            "finalized upload budget must be greater than zero"
        );
        let total_units = configured_bytes.div_ceil(FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES);
        let total_units =
            u32::try_from(total_units).expect("finalized upload budget exceeds semaphore capacity");
        let total_units_usize = usize::try_from(total_units)
            .expect("finalized upload budget does not fit this platform");
        Self {
            permits: Arc::new(Semaphore::new(total_units_usize)),
            total_units,
            metrics: UploadBudgetMetrics::new(context, configured_bytes),
        }
    }

    fn charge(&self, encoded_len: usize) -> UploadCharge {
        let encoded_bytes = u64::try_from(encoded_len).unwrap_or(u64::MAX);
        let estimated_bytes = encoded_bytes.saturating_mul(FINALIZED_UPLOAD_AMPLIFICATION);
        let estimated_units = estimated_bytes
            .div_ceil(FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES)
            .max(1);
        let oversized = estimated_units > u64::from(self.total_units);
        let permit_units = if oversized {
            self.total_units
        } else {
            u32::try_from(estimated_units).expect("admission charge exceeds semaphore capacity")
        };
        UploadCharge {
            estimated_bytes,
            permit_units,
            oversized,
        }
    }

    fn try_reserve(&self, charge: UploadCharge) -> Option<UploadReservation> {
        match self
            .permits
            .clone()
            .try_acquire_many_owned(charge.permit_units)
        {
            Ok(permit) => Some(self.finish_reservation(charge, permit)),
            Err(TryAcquireError::NoPermits) => None,
            Err(TryAcquireError::Closed) => panic!("finalized upload budget closed"),
        }
    }

    async fn reserve(&self, charge: UploadCharge) -> UploadReservation {
        let permit = self
            .permits
            .clone()
            .acquire_many_owned(charge.permit_units)
            .await
            .expect("finalized upload budget closed");
        self.finish_reservation(charge, permit)
    }

    fn finish_reservation(
        &self,
        charge: UploadCharge,
        permit: OwnedSemaphorePermit,
    ) -> UploadReservation {
        let estimated_bytes = metric_bytes(charge.estimated_bytes);
        self.metrics.reserved_bytes.inc_by(estimated_bytes);
        self.metrics.admitted.inc();
        if charge.oversized {
            self.metrics.oversized.inc();
        }
        UploadReservation {
            _permit: permit,
            metrics: self.metrics.clone(),
            estimated_bytes,
            started_at: Some(Instant::now()),
        }
    }

    fn mark_waiting(&self, charge: UploadCharge) {
        self.metrics
            .waiting_bytes
            .set(metric_bytes(charge.estimated_bytes));
        self.metrics.admission_blocked.inc();
    }

    fn clear_waiting(&self) {
        self.metrics.waiting_bytes.set(0);
    }
}

#[derive(Clone, Copy)]
struct UploadCharge {
    estimated_bytes: u64,
    permit_units: u32,
    oversized: bool,
}

struct UploadReservation {
    _permit: OwnedSemaphorePermit,
    metrics: UploadBudgetMetrics,
    estimated_bytes: i64,
    started_at: Option<Instant>,
}

impl UploadReservation {
    const fn without_held_duration(mut self) -> Self {
        self.started_at = None;
        self
    }
}

impl Drop for UploadReservation {
    fn drop(&mut self) {
        if let Some(started_at) = self.started_at {
            self.metrics
                .reservation_held
                .observe(started_at.elapsed().as_secs_f64());
        }
        self.metrics.reserved_bytes.dec_by(self.estimated_bytes);
        self.metrics.admitted.dec();
    }
}

#[derive(Clone)]
struct FinalizedUploadMetrics {
    queue_read: Histogram,
    completion: Histogram,
}

impl FinalizedUploadMetrics {
    fn new(context: &impl Metrics) -> Self {
        Self {
            queue_read: context.histogram(
                "queue_read_duration",
                "Durable queue read time for one finalized upload (s)",
                FINALIZED_UPLOAD_DURATION_BUCKETS,
            ),
            completion: context.histogram(
                "completion_duration",
                "Finalized upload queue acknowledgement and sync time (s)",
                FINALIZED_UPLOAD_DURATION_BUCKETS,
            ),
        }
    }
}

#[derive(Clone)]
struct FinalizedQueueMetrics {
    pending_uploads: Gauge,
}

impl FinalizedQueueMetrics {
    fn new(context: &impl Metrics) -> Self {
        Self {
            pending_uploads: context.gauge(
                "pending_uploads",
                "Finalized queue entries not yet durably acknowledged",
            ),
        }
    }
}

struct FinalizedUploadConsumer {
    publisher: Arc<LazyPublisher>,
    cert_reporter: EngineCertReporter,
    writer: FinalizedQueueWriter,
    reader: FinalizedQueueReader,
    admitted: watch::Receiver<Option<u64>>,
    queue_ready: Arc<Notify>,
    max_active: usize,
    budget: UploadBudget,
    metrics: FinalizedUploadMetrics,
    queue_metrics: FinalizedQueueMetrics,
}

struct PendingQueuedUpload {
    position: u64,
    upload: EngineStoredUpload,
    charge: UploadCharge,
}

impl PendingQueuedUpload {
    fn new(position: u64, upload: EngineStoredUpload, budget: &UploadBudget) -> Self {
        let charge = budget.charge(upload.encoded_len());
        Self {
            position,
            upload,
            charge,
        }
    }
}

fn metric_bytes(bytes: u64) -> i64 {
    i64::try_from(bytes).unwrap_or(i64::MAX)
}

fn metric_usize(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn finalized_queue_page_cache_capacity(upload_budget_bytes: u64) -> NonZeroUsize {
    let encoded_backlog_bytes = upload_budget_bytes
        .div_ceil(FINALIZED_UPLOAD_AMPLIFICATION)
        .max(1);
    let pages = encoded_backlog_bytes.div_ceil(u64::from(FINALIZED_QUEUE_PAGE_SIZE.get()));
    let pages = usize::try_from(pages).unwrap_or(usize::MAX);
    NonZeroUsize::new(pages).expect("finalized queue page cache must contain one page")
}

#[derive(Clone)]
enum SimplexObserver {
    Relayer(crate::relayer::Observer),
}

impl Reporter for SimplexObserver {
    type Activity = EngineActivity<PublicKey, MinSig>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match self {
            Self::Relayer(reporter) => reporter.report(activity),
        }
    }
}

/// Bundle of indexer state that needs to outlive engine startup.
struct IndexerHandle {
    finalized_producer: FinalizedUploadProducer,
    marshal: Arc<OnceLock<EngineMarshal>>,
    critical_task: Option<CriticalTask>,
}

/// Connects the indexer publisher only when finalized data is ready to upload.
struct LazyPublisher {
    context: RuntimeContext,
    store_url: String,
    api_key: Option<String>,
    buffer: usize,
    metrics: PublisherMetrics,
    strategy: Rayon,
    require_fresh: bool,
    publisher: Mutex<Option<Arc<EnginePublisher>>>,
}

impl LazyPublisher {
    fn new(
        context: RuntimeContext,
        store_url: String,
        api_key: Option<String>,
        buffer: usize,
        strategy: Rayon,
        require_fresh: bool,
    ) -> Self {
        // Registered once here: `connect` is retried on failure and must not
        // re-register.
        let metrics = PublisherMetrics::new(&context);
        Self {
            context,
            store_url,
            api_key,
            buffer,
            metrics,
            strategy,
            require_fresh,
            publisher: Mutex::new(None),
        }
    }

    async fn publisher(&self) -> Arc<EnginePublisher> {
        loop {
            if let Some(publisher) = self.publisher.lock().await.as_ref().cloned() {
                return publisher;
            }

            let connect = if self.require_fresh {
                EnginePublisher::connect_fresh_with_strategy(
                    self.context.child("publisher"),
                    &self.store_url,
                    self.api_key.as_deref(),
                    self.buffer,
                    self.metrics.clone(),
                    self.strategy.clone(),
                )
                .await
            } else {
                EnginePublisher::connect_with_strategy(
                    self.context.child("publisher"),
                    &self.store_url,
                    self.api_key.as_deref(),
                    self.buffer,
                    self.metrics.clone(),
                    self.strategy.clone(),
                )
                .await
            };
            match connect {
                Ok(publisher) => {
                    let publisher = Arc::new(publisher);
                    *self.publisher.lock().await = Some(publisher.clone());
                    return publisher;
                }
                Err(error @ PublishError::NonFreshNamespace { .. }) => {
                    panic!("fresh namespace validation failed. {error}")
                }
                Err(error) => {
                    warn!(
                        error = %error,
                        chain_indexer_url = %self.store_url,
                        "indexer publisher connection failed, retrying",
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
}

#[derive(Clone)]
struct FinalizedUploadProducer {
    writer: FinalizedQueueWriter,
    receipt_store: Arc<FinalizedReceiptStore>,
    receipt: Arc<Mutex<Option<LatestCaptureReceipt>>>,
    publisher: Arc<LazyPublisher>,
    admitted: watch::Sender<Option<u64>>,
    queue_ready: Arc<Notify>,
    queue_metrics: FinalizedQueueMetrics,
    marshal: Arc<OnceLock<EngineMarshal>>,
}

impl FinalizedUploadProducer {
    async fn enqueue(
        self,
        block: &EngineBlock<Sha256, PublicKey>,
        artifacts: constantinople_application::consensus::FinalizedArtifacts<Sha256>,
    ) {
        let mut current = self.receipt.lock().await;
        match capture_position(*current, block.header.height) {
            CapturePosition::Captured => {
                if let Some(receipt) = *current
                    && receipt.height == block.header.height
                {
                    assert!(
                        receipt.matches_block(block),
                        "finalized replay conflicts with the durable capture receipt"
                    );
                }
                return;
            }
            CapturePosition::Next => {}
        }

        validate_next_capture(*current, block, &artifacts);
        if requires_fresh_namespace_validation(*current) {
            self.publisher.publisher().await;
        }
        let marshal = self
            .marshal
            .get()
            .expect("marshal mailbox must be installed before engine start");
        let finalization = marshal
            .get_finalization(commonware_consensus::types::Height::new(
                block.header.height,
            ))
            .await
            .unwrap_or_else(|| {
                panic!(
                    "marshal is missing the durable finalization at height {}",
                    block.header.height
                )
            });
        let upload = EngineQueuedUpload::from_finalized_artifacts(
            block,
            finalization,
            current_time_micros(),
            artifacts,
        )
        .expect("captured finalized artifacts must form a valid queue entry");
        let receipt = LatestCaptureReceipt::from_upload(&upload);
        let position = self
            .writer
            .enqueue(upload.into())
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "failed to durably enqueue finalized index upload at height {}. {error}",
                    block.header.height
                )
            });
        persist_capture_receipt(&self.receipt_store, receipt).await;
        *current = Some(receipt);
        self.queue_metrics.pending_uploads.inc();
        self.admitted.send_replace(Some(position));
        self.queue_ready.notify_one();
        info!(
            height = block.header.height,
            position,
            state_end = receipt.state_end,
            transaction_end = receipt.transaction_end,
            "queued finalized index upload"
        );
    }
}

fn capture_position(current: Option<LatestCaptureReceipt>, height: u64) -> CapturePosition {
    assert_ne!(height, 0, "genesis must not invoke finalized capture");

    let Some(receipt) = current else {
        assert_eq!(height, 1, "first finalized capture must have height one");
        return CapturePosition::Next;
    };
    if height <= receipt.height {
        return CapturePosition::Captured;
    }
    assert_eq!(
        height,
        receipt
            .height
            .checked_add(1)
            .expect("finalized capture height must not overflow"),
        "finalized capture height must advance without gaps"
    );
    CapturePosition::Next
}

fn validate_next_capture(
    current: Option<LatestCaptureReceipt>,
    block: &EngineBlock<Sha256, PublicKey>,
    artifacts: &constantinople_application::consensus::FinalizedArtifacts<Sha256>,
) {
    let (expected_height, expected_state_start, expected_transaction_start) =
        current.map_or((1, INITIAL_QMDB_END, INITIAL_QMDB_END), |receipt| {
            (
                receipt
                    .height
                    .checked_add(1)
                    .expect("finalized height must not overflow"),
                receipt.state_end,
                receipt.transaction_end,
            )
        });
    assert_eq!(block.header.height, expected_height);
    assert_eq!(artifacts.state.start.as_u64(), expected_state_start);
    assert_eq!(
        artifacts.transactions.start.as_u64(),
        expected_transaction_start
    );
}

async fn persist_capture_receipt(store: &FinalizedReceiptStore, receipt: LatestCaptureReceipt) {
    let mut metadata = store.metadata.lock().await;
    loop {
        let mut current = metadata
            .take()
            .expect("finalized capture metadata must be present while locked");
        current.put(CAPTURE_RECEIPT_KEY, receipt);
        match current.sync().await {
            Ok(current) => {
                *metadata = Some(current);
                return;
            }
            Err(error) => {
                warn!(
                    error = %error,
                    height = receipt.height,
                    "failed to persist finalized capture receipt"
                );
            }
        }

        loop {
            match Metadata::init(
                store.context.child("finalized_capture_receipt"),
                store.config.clone(),
            )
            .await
            {
                Ok(current) => {
                    *metadata = Some(current);
                    break;
                }
                Err(error) => {
                    warn!(
                        error = %error,
                        "failed to reopen finalized capture receipt"
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
}

async fn scan_finalized_queue_receipt(
    reader: &mut FinalizedQueueReader,
    budget: &UploadBudget,
) -> Option<(LatestCaptureReceipt, u64, usize)> {
    let mut tail: Option<(LatestCaptureReceipt, u64, usize)> = None;
    loop {
        match reader.try_recv().await {
            Ok(Some((position, upload))) => {
                let charge = budget.charge(upload.encoded_len());
                let reservation = budget.reserve(charge).await.without_held_duration();
                let upload = decode_finalized_queue_entry(position, upload);
                assert_eq!(
                    upload.height(),
                    position
                        .checked_add(1)
                        .expect("finalized queue position must not overflow")
                );
                if position == 0 {
                    assert_eq!(upload.state_start(), INITIAL_QMDB_END);
                    assert_eq!(upload.transaction_start(), INITIAL_QMDB_END);
                }
                if let Some((previous, _, _)) = tail {
                    assert_eq!(upload.height(), previous.height + 1);
                    assert_eq!(upload.state_start(), previous.state_end);
                    assert_eq!(upload.transaction_start(), previous.transaction_end);
                }
                let pending_uploads = tail.map_or(1, |(_, _, count)| {
                    count
                        .checked_add(1)
                        .expect("finalized queue length must not overflow")
                });
                tail = Some((
                    LatestCaptureReceipt::from_upload(&upload),
                    position,
                    pending_uploads,
                ));
                drop(reservation);
            }
            Ok(None) => {
                reader
                    .reset()
                    .await
                    .expect("failed to reset finalized index queue reader");
                return tail;
            }
            Err(error) => panic!("failed to scan finalized index queue. {error}"),
        }
    }
}

fn recover_capture_receipt(
    metadata: Option<LatestCaptureReceipt>,
    queue: Option<LatestCaptureReceipt>,
) -> Option<LatestCaptureReceipt> {
    match (metadata, queue) {
        (Some(metadata), Some(queue)) if metadata.height == queue.height => {
            assert_eq!(metadata, queue, "capture receipt conflicts with queue tail");
            Some(metadata)
        }
        (Some(metadata), Some(queue)) if metadata.height > queue.height => {
            panic!("capture receipt is ahead of the durable queue tail")
        }
        (_, Some(queue)) => Some(queue),
        (Some(metadata), None) => Some(metadata),
        (None, None) => None,
    }
}

const fn requires_fresh_namespace_validation(
    capture_receipt: Option<LatestCaptureReceipt>,
) -> bool {
    capture_receipt.is_none()
}

const fn requires_fresh_validation_before_receipt_recovery(
    capture_receipt: Option<LatestCaptureReceipt>,
    has_queue_tail: bool,
) -> bool {
    requires_fresh_namespace_validation(capture_receipt) && has_queue_tail
}

fn current_time_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_micros() as i64)
        .unwrap_or(0)
}

async fn run_finalized_upload_consumer(consumer: FinalizedUploadConsumer) {
    let FinalizedUploadConsumer {
        publisher,
        cert_reporter,
        writer,
        mut reader,
        mut admitted,
        queue_ready,
        max_active,
        budget,
        metrics,
        queue_metrics,
    } = consumer;
    let mut active = JoinSet::new();
    let mut completed = BTreeMap::new();
    let mut next_ack = None;
    let mut waiting = None;
    let max_active = max_active.max(1);

    loop {
        while waiting.is_none() && active.len() < max_active {
            let item = match try_read_finalized_queue_entry(&mut reader, &metrics).await {
                Ok(item) => item,
                Err(error) => {
                    warn!(error = %error, "failed to read finalized index queue, retrying");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    break;
                }
            };
            let Some((position, upload)) = item else {
                break;
            };
            wait_for_queue_admission(position, &mut admitted).await;
            next_ack.get_or_insert(position);
            let pending = PendingQueuedUpload::new(position, upload, &budget);
            if let Some(pending) = try_admit_queued_upload(
                &mut active,
                publisher.clone(),
                cert_reporter.clone(),
                &budget,
                pending,
            )
            .await
            {
                waiting = Some(pending);
            }
        }

        let waiting_charge = waiting.as_ref().map(|pending| pending.charge);
        tokio::select! {
            reservation = async {
                budget
                    .reserve(waiting_charge.expect("waiting upload has an admission charge"))
                    .await
            }, if waiting_charge.is_some() && active.len() < max_active => {
                budget.clear_waiting();
                let pending = waiting.take().expect("waiting upload exists");
                start_queued_upload(
                    &mut active,
                    publisher.clone(),
                    cert_reporter.clone(),
                    pending,
                    reservation,
                )
                .await;
            }
            () = queue_ready.notified(), if waiting.is_none() && active.len() < max_active => {}
            result = active.join_next(), if !active.is_empty() => {
                let (position, height, reservation) = result
                    .expect("active upload set is not empty")
                    .expect("finalized index upload task panicked");
                let replaced = completed.insert(position, (height, reservation));
                assert!(replaced.is_none(), "queue position completed more than once");
                while let Some(position) = next_ack {
                    let Some((height, reservation)) = completed.remove(&position) else {
                        break;
                    };
                    let completion_started = Instant::now();
                    ack_finalized_queue_entry(&reader, &writer, position, height).await;
                    metrics
                        .completion
                        .observe(completion_started.elapsed().as_secs_f64());
                    queue_metrics.pending_uploads.dec();
                    drop(reservation);
                    next_ack = Some(
                        position
                            .checked_add(1)
                            .expect("finalized queue position must not overflow"),
                    );
                }
            }
        }
    }
}

async fn try_read_finalized_queue_entry(
    reader: &mut FinalizedQueueReader,
    metrics: &FinalizedUploadMetrics,
) -> Result<Option<(u64, EngineStoredUpload)>, queue::Error> {
    let started = Instant::now();
    let item = reader.try_recv().await?;
    if item.is_some() {
        metrics.queue_read.observe(started.elapsed().as_secs_f64());
    }
    Ok(item)
}

async fn wait_for_queue_admission(position: u64, admitted: &mut watch::Receiver<Option<u64>>) {
    loop {
        if admitted
            .borrow_and_update()
            .is_some_and(|floor| floor >= position)
        {
            return;
        }
        admitted
            .changed()
            .await
            .expect("finalized capture admission gate closed");
    }
}

async fn try_admit_queued_upload(
    active: &mut JoinSet<(u64, u64, UploadReservation)>,
    publisher: Arc<LazyPublisher>,
    cert_reporter: EngineCertReporter,
    budget: &UploadBudget,
    pending: PendingQueuedUpload,
) -> Option<PendingQueuedUpload> {
    let Some(reservation) = budget.try_reserve(pending.charge) else {
        budget.mark_waiting(pending.charge);
        return Some(pending);
    };
    start_queued_upload(active, publisher, cert_reporter, pending, reservation).await;
    None
}

async fn ack_finalized_queue_entry(
    reader: &FinalizedQueueReader,
    writer: &FinalizedQueueWriter,
    position: u64,
    height: u64,
) {
    loop {
        match reader.ack(position).await {
            Ok(()) => break,
            Err(error) => {
                warn!(
                    error = %error,
                    position,
                    height,
                    "failed to ack finalized index queue entry, retrying",
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
    loop {
        match writer.sync().await {
            Ok(()) => break,
            Err(error) => {
                warn!(
                    error = %error,
                    position,
                    height,
                    "failed to sync finalized index queue ack, retrying",
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

async fn start_queued_upload(
    active: &mut JoinSet<(u64, u64, UploadReservation)>,
    publisher: Arc<LazyPublisher>,
    cert_reporter: EngineCertReporter,
    pending: PendingQueuedUpload,
    reservation: UploadReservation,
) {
    let position = pending.position;
    let upload = decode_finalized_queue_entry(position, pending.upload);
    let height = upload.height();
    assert_eq!(
        height,
        position
            .checked_add(1)
            .expect("finalized queue position must not overflow")
    );
    let block = Arc::new(upload.block().clone());
    let finalization = upload.finalization();

    // Admission fixes queue order before independent persistence work begins.
    let engine_publisher = publisher.publisher().await;
    let completion = engine_publisher
        .enqueue_queued_finalized(upload)
        .await
        .unwrap_or_else(|error| {
            panic!("failed to start finalized index upload at height {height}. {error}")
        });

    active.spawn(async move {
        let simplex_completion = cert_reporter
            .publish_finalized_block(block, finalization)
            .await
            .unwrap_or_else(|error| match error {
                PublishFinalizedBlockError::CommitmentBlockMismatch => {
                    panic!("queued finalization does not match block at height {height}")
                }
                PublishFinalizedBlockError::UploaderStopped(error) => {
                    panic!("failed to start finalized block upload at height {height}. {error}")
                }
            });
        match wait_for_finalized_uploads(completion.wait(), simplex_completion.wait()).await {
            Ok(()) => (position, height, reservation),
            Err(FinalizedUploadFailure::Qmdb(error)) => {
                panic!("QMDB upload failed at height {height}. {error}")
            }
            Err(FinalizedUploadFailure::Simplex(error)) => {
                panic!("finalized block upload failed at height {height}. {error}")
            }
        }
    });
}

fn decode_finalized_queue_entry(position: u64, upload: EngineStoredUpload) -> EngineQueuedUpload {
    upload.into_decoded().unwrap_or_else(|error| {
        panic!("failed to decode finalized index queue entry at position {position}. {error}")
    })
}

#[derive(Debug)]
enum FinalizedUploadFailure {
    Qmdb(PublishError),
    Simplex(CertificateUploaderStopped),
}

async fn wait_for_finalized_uploads<Q, S, T>(
    qmdb: Q,
    simplex: S,
) -> Result<(), FinalizedUploadFailure>
where
    Q: Future<Output = Result<T, PublishError>>,
    S: Future<Output = Result<(), CertificateUploaderStopped>>,
{
    tokio::try_join!(
        async { qmdb.await.map_err(FinalizedUploadFailure::Qmdb) },
        async { simplex.await.map_err(FinalizedUploadFailure::Simplex) },
    )?;
    Ok(())
}

fn indexer_critical_task(
    cert_join: JoinHandle<()>,
    finalized_join: JoinHandle<()>,
) -> CriticalTask {
    Box::pin(async move {
        let (task, result) = tokio::select! {
            result = cert_join => ("Simplex certificate uploader", result),
            result = finalized_join => ("finalized index uploader", result),
        };
        match result {
            Ok(()) => warn!(task, "critical indexer task exited"),
            Err(error) => warn!(task, error = %error, "critical indexer task failed"),
        }
    })
}

/// Build the indexer wiring iff the secondary validator opted in.
async fn maybe_build_indexer(
    context: RuntimeContext,
    strategy: Rayon,
    is_primary: bool,
    indexer: Option<IndexerConfig>,
    partition_prefix: &str,
) -> Result<Option<IndexerHandle>, StoreClientBuildError> {
    let Some(cfg) = indexer else {
        return Ok(None);
    };
    if is_primary {
        return Ok(None);
    }

    let max_active_uploads = cfg
        .upload_max_in_flight
        .clamp(1, MAX_FINALIZED_QUEUE_UPLOADS);
    let queue_page_cache_capacity = finalized_queue_page_cache_capacity(cfg.upload_budget_bytes);
    info!(
        chain_indexer_url = %cfg.chain_indexer_url,
        upload_budget_bytes = cfg.upload_budget_bytes,
        upload_max_in_flight = max_active_uploads,
        configured_upload_max_in_flight = cfg.upload_max_in_flight,
        upload_amplification = FINALIZED_UPLOAD_AMPLIFICATION,
        upload_budget_quantum_bytes = FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
        queue_page_cache_pages = queue_page_cache_capacity.get(),
        "starting full indexer uploaders",
    );
    info!(
        schema_fingerprint = %meta_schema_fingerprint(),
        state_qmdb_prefix = %format_args!("0x{STATE_QMDB_PREFIX_VALUE:02x}"),
        transactions_qmdb_prefix = %format_args!("0x{TRANSACTIONS_QMDB_PREFIX_VALUE:02x}"),
        simplex_prefix = %format_args!("0x{SIMPLEX_PREFIX_VALUE:02x}"),
        sql_meta_prefix = %format_args!("0x{SQL_META_PREFIX_VALUE:02x}"),
        publication_target_prefix = %format_args!("0x{PUBLICATION_TARGET_PREFIX_VALUE:02x}"),
        "indexer Store layout",
    );
    let budget = UploadBudget::new(
        &context.child("finalized_upload_budget"),
        cfg.upload_budget_bytes,
    );
    let upload_metrics = FinalizedUploadMetrics::new(&context.child("finalized_upload"));
    let queue_metrics = FinalizedQueueMetrics::new(&context.child("finalized_queue"));
    let (cert_reporter, cert_join) = EngineCertReporter::connect(
        &context.child("simplex_upload"),
        &cfg.chain_indexer_url,
        cfg.api_key.as_deref(),
        max_active_uploads,
    )?;
    let page_cache = CacheRef::from_pooler(
        &context,
        FINALIZED_QUEUE_PAGE_SIZE,
        queue_page_cache_capacity,
    );
    let (queue_writer, mut queue_reader) = queue::shared::init(
        context.child("finalized_queue"),
        queue::Config {
            partition: format!("{partition_prefix}-finalized-index-queue"),
            items_per_section: FINALIZED_QUEUE_ITEMS_PER_SECTION,
            compression: None,
            codec_config: QueuedFinalizedUploadCfg::default(),
            page_cache,
            write_buffer: FINALIZED_QUEUE_WRITE_BUFFER,
            replay_buffer: FINALIZED_QUEUE_WRITE_BUFFER,
        },
    )
    .await
    .expect("failed to initialize finalized index queue");
    let metadata_config = MetadataConfig {
        partition: format!("{partition_prefix}-finalized-capture-receipt"),
        codec_config: (),
    };
    let mut metadata = Metadata::init(
        context.child("finalized_capture_receipt"),
        metadata_config.clone(),
    )
    .await
    .expect("failed to initialize finalized capture receipt");
    let metadata_receipt = metadata.get(&CAPTURE_RECEIPT_KEY).copied();
    let queue_tail = scan_finalized_queue_receipt(&mut queue_reader, &budget).await;
    queue_metrics
        .pending_uploads
        .set(queue_tail.map_or(0, |(_, _, count)| metric_usize(count)));
    let require_fresh = requires_fresh_namespace_validation(metadata_receipt);
    let publisher = Arc::new(LazyPublisher::new(
        context.child("publisher"),
        cfg.chain_indexer_url,
        cfg.api_key,
        max_active_uploads,
        strategy,
        require_fresh,
    ));
    if requires_fresh_validation_before_receipt_recovery(metadata_receipt, queue_tail.is_some()) {
        publisher.publisher().await;
    }
    let receipt =
        recover_capture_receipt(metadata_receipt, queue_tail.map(|(receipt, _, _)| receipt));
    if metadata_receipt != receipt {
        metadata.put(
            CAPTURE_RECEIPT_KEY,
            receipt.expect("queue recovery must produce a capture receipt"),
        );
        metadata = metadata
            .sync()
            .await
            .expect("failed to persist recovered capture receipt");
    }
    let receipt_store = Arc::new(FinalizedReceiptStore {
        context,
        config: metadata_config,
        metadata: Mutex::new(Some(metadata)),
    });
    let (admitted, admitted_rx) = watch::channel(queue_tail.map(|(_, position, _)| position));
    let queue_ready = Arc::new(Notify::new());
    let marshal = Arc::new(OnceLock::new());
    let finalized_producer = FinalizedUploadProducer {
        writer: queue_writer.clone(),
        receipt_store,
        receipt: Arc::new(Mutex::new(receipt)),
        publisher: publisher.clone(),
        admitted,
        queue_ready: queue_ready.clone(),
        queue_metrics: queue_metrics.clone(),
        marshal: marshal.clone(),
    };
    let finalized_join = tokio::spawn(run_finalized_upload_consumer(FinalizedUploadConsumer {
        publisher,
        cert_reporter: cert_reporter.clone(),
        writer: queue_writer,
        reader: queue_reader,
        admitted: admitted_rx,
        queue_ready,
        max_active: max_active_uploads,
        budget,
        metrics: upload_metrics,
        queue_metrics,
    }));
    Ok(Some(IndexerHandle {
        finalized_producer,
        marshal,
        critical_task: Some(indexer_critical_task(cert_join, finalized_join)),
    }))
}

fn indexer_finalized_hook(indexer: Option<&IndexerHandle>) -> Option<ValidatorFinalizedHook> {
    let indexer = indexer?;
    let finalized_producer = indexer.finalized_producer.clone();
    Some(Arc::new(move |block, artifacts| {
        let block = EngineBlock::from(block.clone());
        let finalized_producer = finalized_producer.clone();
        Box::pin(async move { finalized_producer.enqueue(&block, artifacts).await })
    }))
}

pub fn run_local(peers_path: PathBuf, config_path: PathBuf) {
    let loaded = load_local_config(&peers_path, &config_path);
    run_with_config(loaded, config_path);
}

pub fn run_deployer(hosts_path: PathBuf, config_path: PathBuf) {
    let loaded = load_deployer_config(&hosts_path, &config_path);
    run_with_config(loaded, config_path);
}

fn run_with_config(config: LoadedConfig, config_path: PathBuf) {
    let LoadedConfig {
        decoded,
        startup,
        log_level,
        worker_threads,
        rayon_threads,
        http_listen,
        metrics_listen,
        max_propose_bytes,
        max_pool_bytes,
        state_page_cache_bytes,
        other_page_cache_bytes,
        public_key_cache_size,
        otel,
        json_logs,
        deployer_managed,
        indexer,
        relayer,
    } = config;

    let config_dir = config_path
        .parent()
        .expect("config file has no parent directory");
    let storage_dir = config_dir.join(&decoded.partition_prefix);
    let runtime_cfg = commonware_runtime::tokio::Config::new()
        .with_storage_directory(storage_dir)
        .with_worker_threads(worker_threads);
    let (network_buffer_pool_cfg, storage_buffer_pool_cfg) =
        buffer_pool_configs(worker_threads, runtime_cfg.max_blocking_threads());
    let runtime_cfg = runtime_cfg
        .with_network_buffer_pool_config(network_buffer_pool_cfg)
        .with_storage_buffer_pool_config(storage_buffer_pool_cfg);
    let runner = commonware_runtime::tokio::Runner::new(runtime_cfg);

    runner.start(|context| async move {
        telemetry::init(
            context.child("telemetry"),
            Logs {
                level: log_level.parse().expect("bad log_level in config"),
                json: json_logs,
            },
            Some(metrics_listen),
            otel.map(|(endpoint, rate)| TracesConfig {
                endpoint,
                name: hex(&decoded.public_key.encode()),
                rate: Probability::try_from(rate).expect("trace rate must be between zero and one"),
            }),
        );

        info!(
            validator = %hex(&decoded.public_key.encode()),
            listen_bind = %decoded.listen_bind,
            listen_advertise = %decoded.listen_advertise,
            http_listen = %http_listen,
            metrics_listen = %metrics_listen,
            "starting validator"
        );
        let strategy = context.strategy(NZUsize!(rayon_threads));
        let public_key_cache = PublicKeyCache::new(
            context.child("public_key_cache"),
            NonZeroUsize::new(public_key_cache_size)
                .expect("public_key_cache_size must be non-zero"),
        );

        let max_peers_per_set = authenticated::peer_set_limit(
            decoded
                .primary_participants
                .iter()
                .chain(&decoded.secondary_participants),
            &decoded.public_key,
        );
        let p2p_config = if deployer_managed {
            discovery::Config::recommended(
                decoded.signer.clone(),
                b"constantinople",
                decoded.listen_bind,
                Ingress::Socket(decoded.listen_advertise),
                decoded.bootstrappers,
                max_peers_per_set,
                32 * 1024 * 1024,
            )
        } else {
            discovery::Config::local(
                decoded.signer.clone(),
                b"constantinople",
                decoded.listen_bind,
                Ingress::Socket(decoded.listen_advertise),
                decoded.bootstrappers,
                max_peers_per_set,
                32 * 1024 * 1024,
            )
        };

        // Registration multiplies the burst by the retained-peer bound. Divide the
        // channel budget across peers to keep every channel mailbox bounded.
        let retained_peer_bound = max_peers_per_set
            .get()
            .checked_mul(p2p_config.tracked_peer_sets.get())
            .and_then(|count| count.checked_add(p2p_config.bootstrappers.len()))
            .expect("retained peer bound overflow");
        let channel_burst =
            u32::try_from((NETWORK_CHANNEL_MAILBOX_BUDGET / retained_peer_bound).max(1))
                .expect("network channel burst exceeds u32");
        let quota = Quota::per_second(NonZeroU32::MAX).allow_burst(
            NonZeroU32::new(channel_burst).expect("network channel burst must be non-zero"),
        );

        let (mut network, mut oracle) = discovery::Network::new(context.child("p2p"), p2p_config);

        let mempool_drop_grace_blocks =
            default_mempool_drop_grace_blocks(decoded.primary_participants.len());
        let primary: Set<ed25519::PublicKey> = decoded
            .primary_participants
            .into_iter()
            .try_collect()
            .unwrap();
        let secondary: Set<ed25519::PublicKey> = decoded
            .secondary_participants
            .into_iter()
            .try_collect()
            .unwrap();
        oracle.track(0, TrackedPeers::new(primary, secondary));

        let channels = Channels {
            votes: network.register(VOTE_CHANNEL, quota),
            certificates: network.register(CERTIFICATE_CHANNEL, quota),
            resolver: network.register(RESOLVER_CHANNEL, quota),
            marshal: network.register(MARSHAL_CHANNEL, quota),
            marshal_resolver: network.register(MARSHAL_RESOLVER_CHANNEL, quota),
            state_resolver: network.register(STATE_RESOLVER_CHANNEL, quota),
            transaction_resolver: network.register(TRANSACTION_RESOLVER_CHANNEL, quota),
        };
        let probe_network = network.register(PROBE_CHANNEL, quota);
        let provider =
            ConstantProvider::new(ThresholdScheme::<ed25519::PublicKey, MinSig>::verifier(
                &union(b"constantinople", b"_CONSENSUS"),
                decoded.dkg_output.players().clone(),
                decoded.dkg_output.public().clone(),
            ));
        let (probe, probe_mailbox) = Probe::new(ProbeConfig {
            context: context.child("probe"),
            provider,
            strategy: strategy.clone(),
            capacity: NZUsize!(32),
            blocker: oracle.clone(),
            minimum_epoch: Epoch::zero(),
            retry_timeout: NZDuration!(Duration::from_secs(1)),
        });
        let probe_handle = probe.start(probe_network);
        let probe_handle: CriticalTask = Box::pin(async move {
            let _ = probe_handle.await;
        });
        let network_handle = network.start();

        let relayer_view = relayer.as_ref().map(|_| crate::relayer::Observer::new());
        let relayer_view_clock = relayer_view
            .as_ref()
            .map(|(_, view_clock)| view_clock.clone());
        let relayer_observer = relayer_view.map(|(observer, _)| observer);

        let (mempool_mailbox, mempool_receiver) = Mailbox::channel(MEMPOOL_MAILBOX_SIZE);
        let account_reader: Arc<OnceLock<Arc<dyn AccountReader>>> = Arc::new(OnceLock::new());
        let mempool_actor = webserver::Actor::new(
            context.child("mempool"),
            webserver::Config {
                max_pool_bytes,
                max_propose_bytes,
                namespace: constantinople_primitives::TRANSACTION_NAMESPACE,
                drop_grace_blocks: mempool_drop_grace_blocks,
                strategy: strategy.clone(),
                public_key_cache: public_key_cache.clone(),
            },
            mempool_mailbox.clone(),
            mempool_receiver,
            account_reader.clone(),
        );
        let is_primary = decoded.share.is_some();
        let mempool_handle: Pin<Box<dyn Future<Output = ()> + Send>> = if is_primary {
            let listener = tokio::net::TcpListener::bind(http_listen)
                .await
                .expect("failed to bind mempool HTTP listener");
            info!(%http_listen, "mempool webserver listening");
            let handle = mempool_actor.start(listener);
            Box::pin(async move {
                let _ = handle.await;
            })
        } else if let Some(relayer_config) = relayer.clone() {
            let view_clock = relayer_view_clock.expect("relayer view clock exists");
            drop(mempool_actor);
            info!(%http_listen, "relayer webserver listening");
            Box::pin(crate::relayer::serve(crate::relayer::ServerConfig {
                listen: http_listen,
                relayer: relayer_config,
                account_reader: account_reader.clone(),
                view_clock,
                strategy: strategy.clone(),
                max_batch_bytes: max_propose_bytes,
            }))
        } else {
            info!("secondary node: skipping mempool webserver");
            drop(mempool_actor);
            Box::pin(std::future::pending())
        };

        let startup = match startup {
            StartupModeConfig::MarshalSync => StartupMode::MarshalSync,
            StartupModeConfig::StateSync => StartupMode::StateSync,
        };
        let startup_mode = match &startup {
            StartupMode::MarshalSync => "marshal_sync",
            StartupMode::StateSync => "state_sync",
        };
        info!(startup_mode, "requested validator startup mode");

        // Build the indexer wiring up-front. This consumes `indexer` from the
        // loaded config and returns `None` for primaries or validators that
        // did not declare an `indexer` block.
        let indexer_partition_prefix = decoded.partition_prefix.clone();
        let mut indexer_handle = maybe_build_indexer(
            context.child("indexer"),
            strategy.clone(),
            is_primary,
            indexer,
            &indexer_partition_prefix,
        )
        .await
        .expect("failed to configure indexer Store client");
        let finalized_hook = indexer_finalized_hook(indexer_handle.as_ref());
        let indexer_task = indexer_handle
            .as_mut()
            .and_then(|handle| handle.critical_task.take());

        info!("initializing engine");
        let engine = Engine::<
            _,
            _,
            _,
            _,
            Sha256,
            MinSig,
            RoundRobin<Sha256>,
            Rayon,
            _,
            Batch,
            SimplexObserver,
        >::new(
            context.child("engine"),
            EngineConfig {
                signer: decoded.signer,
                manager: oracle.clone(),
                blocker: oracle,
                namespace: b"constantinople".to_vec(),
                output: decoded.dkg_output,
                share: decoded.share,
                input: mempool_mailbox.clone(),
                partition_prefix: decoded.partition_prefix,
                strategy,
                public_key_cache,
                startup,
                sync_config: production_sync_config(),
                prune_config: Some(PRUNE_CONFIG),
                genesis_leader: decoded.genesis_leader,
                transaction_namespace: constantinople_primitives::TRANSACTION_NAMESPACE,
                block_codec: Default::default(),
                max_block_transaction_bytes: max_propose_bytes,
                prunable_items_per_section: PRUNABLE_ITEMS_PER_SECTION,
                state_page_cache_bytes,
                other_page_cache_bytes,
                probe: Some(probe_mailbox.clone()),
                simplex_observer: relayer_observer.map(SimplexObserver::Relayer),
                finalized_hook,
            },
        )
        .await;

        if let Some(indexer) = indexer_handle.as_ref() {
            assert!(
                indexer.marshal.set(engine.marshal_mailbox()).is_ok(),
                "marshal mailbox must be installed exactly once"
            );
        }

        // Install the account reader as soon as the stateful actor attaches
        // its databases. Runs concurrently with engine.start so the HTTP
        // listener can come up immediately; account lookups return 503 until
        // the cell is populated.
        let subscribe_fut = engine.subscribe_databases_detached();
        let account_reader_setter = account_reader.clone();
        let _account_reader_setup = tokio::spawn(async move {
            let db = subscribe_fut.await;
            let reader: Arc<dyn AccountReader> = Arc::new(StateDbReader::new(db));
            let _ = account_reader_setter.set(reader);
            info!("account reader attached");
        });

        info!("starting engine");
        // Primaries report to the local mempool. Secondaries upload index data
        // from the finalized hook and do not need marshal updates here.
        let reporter: Option<Mailbox<EngineCommitment<Sha256, PublicKey>, PublicKey, Sha256>> =
            if is_primary {
                Some(mempool_mailbox.clone())
            } else {
                None
            };
        let engine_handle = engine.start(channels, reporter);

        wait_for_critical_task_exit(
            Some(probe_handle),
            indexer_task,
            engine_handle,
            mempool_handle,
            network_handle,
        )
        .await;
    });
}

async fn wait_for_critical_task_exit<E, M, N>(
    probe_handle: Option<CriticalTask>,
    indexer_handle: Option<CriticalTask>,
    engine_handle: E,
    mempool_handle: M,
    network_handle: N,
) where
    E: Future,
    M: Future,
    N: Future,
{
    let mut probe_handle = probe_handle.unwrap_or_else(|| Box::pin(std::future::pending()));
    let mut indexer_handle = indexer_handle.unwrap_or_else(|| Box::pin(std::future::pending()));
    tokio::select! {
        _ = probe_handle.as_mut() => tracing::warn!("probe exited"),
        _ = indexer_handle.as_mut() => panic!("critical indexer task exited"),
        _ = engine_handle => tracing::warn!("engine exited"),
        _ = mempool_handle => tracing::warn!("mempool exited"),
        _ = network_handle => tracing::warn!("network exited"),
    }
}

const fn production_sync_config() -> SyncEngineConfig {
    SyncEngineConfig {
        fetch_batch_size: NZU64!(1024),
        apply_batch_size: STATE_SYNC_APPLY_BATCH_SIZE,
        max_outstanding_requests: 8,
        update_channel_size: NZUsize!(256),
        max_retained_roots: 32,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CapturePosition, CertificateUploaderStopped, FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
        FinalizedUploadFailure, LatestCaptureReceipt, PublishError, StoreClientBuildError,
        UploadBudget, capture_position, default_mempool_drop_grace_blocks, indexer_critical_task,
        maybe_build_indexer, recover_capture_receipt, requires_fresh_namespace_validation,
        requires_fresh_validation_before_receipt_recovery, wait_for_critical_task_exit,
        wait_for_finalized_uploads,
    };
    use crate::config::IndexerConfig;
    use commonware_codec::{DecodeExt as _, Encode as _, FixedSize as _};
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_runtime::{Runner as _, Strategizer as _, Supervisor as _};
    use commonware_utils::NZUsize;
    use std::{future::pending, time::Duration};
    use tokio::sync::oneshot;

    #[test]
    fn mempool_drop_grace_defaults_to_twice_validator_count() {
        assert_eq!(default_mempool_drop_grace_blocks(1), 2);
        assert_eq!(default_mempool_drop_grace_blocks(4), 8);
        assert_eq!(default_mempool_drop_grace_blocks(50), 100);
    }

    #[tokio::test]
    async fn completed_setup_task_is_not_a_runtime_exit_condition() {
        let setup_task = tokio::spawn(async {});
        setup_task.await.expect("setup task should complete");

        let result = tokio::time::timeout(
            Duration::from_millis(10),
            wait_for_critical_task_exit(
                None,
                None,
                pending::<()>(),
                pending::<()>(),
                pending::<()>(),
            ),
        )
        .await;

        assert!(
            result.is_err(),
            "completed setup work must not terminate the validator runtime",
        );
    }

    #[tokio::test]
    async fn finalized_upload_waits_for_both_destinations() {
        for qmdb_first in [true, false] {
            let (qmdb_tx, qmdb_rx) = oneshot::channel();
            let (simplex_tx, simplex_rx) = oneshot::channel();
            let qmdb = async move {
                qmdb_rx
                    .await
                    .map_err(|_| PublishError::CommitterStopped { height: 1 })
            };
            let simplex = async move { simplex_rx.await.map_err(|_| CertificateUploaderStopped) };
            let mut completion = Box::pin(wait_for_finalized_uploads(qmdb, simplex));
            let mut qmdb_tx = Some(qmdb_tx);
            let mut simplex_tx = Some(simplex_tx);

            if qmdb_first {
                qmdb_tx.take().expect("QMDB gate exists").send(()).ok();
            } else {
                simplex_tx
                    .take()
                    .expect("Simplex gate exists")
                    .send(())
                    .ok();
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(10), completion.as_mut())
                    .await
                    .is_err()
            );

            if qmdb_first {
                simplex_tx
                    .take()
                    .expect("Simplex gate exists")
                    .send(())
                    .ok();
            } else {
                qmdb_tx.take().expect("QMDB gate exists").send(()).ok();
            }
            completion.await.expect("both uploads complete");
        }
    }

    #[tokio::test]
    async fn finalized_upload_failure_does_not_wait_for_other_destination() {
        let (_simplex_tx, simplex_rx) = oneshot::channel::<()>();
        let qmdb = async { Err::<(), _>(PublishError::CommitterStopped { height: 7 }) };
        let simplex = async move { simplex_rx.await.map_err(|_| CertificateUploaderStopped) };

        let result = tokio::time::timeout(
            Duration::from_millis(10),
            wait_for_finalized_uploads(qmdb, simplex),
        )
        .await
        .expect("QMDB failure returns promptly");
        assert!(matches!(
            result,
            Err(FinalizedUploadFailure::Qmdb(
                PublishError::CommitterStopped { height: 7 }
            ))
        ));
    }

    #[tokio::test]
    async fn indexer_uploader_exit_fails_the_runtime() {
        let certificate_uploader = tokio::spawn(async {});
        let finalized_uploader = tokio::spawn(pending::<()>());
        let indexer_task = indexer_critical_task(certificate_uploader, finalized_uploader);

        let runtime = tokio::spawn(wait_for_critical_task_exit(
            None,
            Some(indexer_task),
            pending::<()>(),
            pending::<()>(),
            pending::<()>(),
        ));
        let error = tokio::time::timeout(Duration::from_secs(1), runtime)
            .await
            .expect("indexer failure returns promptly")
            .expect_err("indexer failure must panic the runtime");
        assert!(error.is_panic());
    }

    #[test]
    fn publisher_does_not_block_secondary_startup_on_connect_failure() {
        let runner =
            commonware_runtime::tokio::Runner::new(commonware_runtime::tokio::Config::default());
        runner.start(|context| async move {
            let indexer = IndexerConfig {
                chain_indexer_url: "http://127.0.0.1:1".to_string(),
                api_key: None,
                upload_max_in_flight: 1,
                upload_budget_bytes: super::FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
            };
            let strategy = context.strategy(NZUsize!(2));

            let handle = tokio::time::timeout(
                Duration::from_secs(2),
                maybe_build_indexer(context, strategy, false, Some(indexer), "test"),
            )
            .await
            .expect("publisher connection should not block startup")
            .expect("indexer Store client should build")
            .expect("secondary should keep indexer wiring");

            assert!(handle.critical_task.is_some());
        });
    }

    #[test]
    fn invalid_indexer_api_key_fails_secondary_startup() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let indexer = IndexerConfig {
                chain_indexer_url: "http://127.0.0.1:1".to_string(),
                api_key: Some("invalid\nkey".to_string()),
                upload_max_in_flight: 1,
                upload_budget_bytes: FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
            };
            let strategy = context.strategy(NZUsize!(2));

            let error = maybe_build_indexer(context, strategy, false, Some(indexer), "test")
                .await
                .err()
                .expect("invalid API key should fail startup");

            assert!(matches!(error, StoreClientBuildError::InvalidApiKey));
        });
    }

    #[test]
    fn capture_receipt_round_trips() {
        let receipt = capture_receipt(7, 11, 13);
        assert_eq!(
            LatestCaptureReceipt::decode(receipt.encode()).expect("receipt decodes"),
            receipt
        );
    }

    #[test]
    fn capture_receipt_covers_older_replays() {
        let receipt = capture_receipt(7, 11, 13);

        assert_eq!(capture_position(None, 1), CapturePosition::Next);
        assert_eq!(
            capture_position(Some(receipt), 6),
            CapturePosition::Captured
        );
        assert_eq!(
            capture_position(Some(receipt), 7),
            CapturePosition::Captured
        );
        assert_eq!(capture_position(Some(receipt), 8), CapturePosition::Next);
    }

    #[test]
    #[should_panic(expected = "genesis must not invoke finalized capture")]
    fn capture_receipt_rejects_genesis() {
        let _ = capture_position(None, 0);
    }

    #[test]
    #[should_panic(expected = "finalized capture height must advance without gaps")]
    fn capture_receipt_rejects_future_gap() {
        let _ = capture_position(Some(capture_receipt(7, 11, 13)), 9);
    }

    #[test]
    fn queue_tail_repairs_an_older_capture_receipt() {
        let metadata = capture_receipt(7, 11, 13);
        let queue = capture_receipt(8, 14, 17);

        assert_eq!(
            recover_capture_receipt(Some(metadata), Some(queue)),
            Some(queue)
        );
        assert_eq!(recover_capture_receipt(None, Some(queue)), Some(queue));
        assert_eq!(
            recover_capture_receipt(Some(metadata), None),
            Some(metadata)
        );
    }

    #[test]
    fn fresh_validation_precedes_unreceipted_queue_recovery() {
        let queue = capture_receipt(1, 2, 3);

        assert!(requires_fresh_namespace_validation(None));
        assert!(requires_fresh_validation_before_receipt_recovery(
            None, true
        ));
        assert_eq!(recover_capture_receipt(None, Some(queue)), Some(queue));
        assert!(!requires_fresh_namespace_validation(Some(queue)));
        assert!(!requires_fresh_validation_before_receipt_recovery(
            Some(queue),
            true
        ));
    }

    #[test]
    fn fresh_validation_is_deferred_to_first_enqueue_on_empty_startup() {
        assert!(requires_fresh_namespace_validation(None));
        assert!(!requires_fresh_validation_before_receipt_recovery(
            None, false
        ));
    }

    #[test]
    #[should_panic(expected = "capture receipt is ahead of the durable queue tail")]
    fn capture_receipt_cannot_advance_past_a_nonempty_queue() {
        let metadata = capture_receipt(8, 14, 17);
        let queue = capture_receipt(7, 11, 13);

        let _ = recover_capture_receipt(Some(metadata), Some(queue));
    }

    #[test]
    #[should_panic(expected = "capture receipt conflicts with queue tail")]
    fn capture_receipt_must_match_the_queue_tail() {
        let metadata = capture_receipt(7, 11, 13);
        let queue = capture_receipt(7, 12, 13);

        let _ = recover_capture_receipt(Some(metadata), Some(queue));
    }

    #[test]
    fn upload_budget_blocks_until_reservations_drop() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let budget = UploadBudget::new(
                &context.child("upload_budget"),
                2 * FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
            );
            let one_unit_encoded = usize::try_from(FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES / 8)
                .expect("test charge fits usize");
            let one_unit = budget.charge(one_unit_encoded);
            let two_units = budget.charge(one_unit_encoded + 1);

            let first = budget
                .try_reserve(one_unit)
                .expect("first charge fits budget");
            assert!(budget.try_reserve(two_units).is_none());
            budget.mark_waiting(two_units);
            assert_eq!(budget.metrics.admission_blocked.get(), 1);
            assert_eq!(
                budget.metrics.waiting_bytes.get(),
                i64::try_from(two_units.estimated_bytes).expect("test charge fits metric")
            );
            assert_eq!(budget.metrics.admitted.get(), 1);

            drop(first);
            let second = budget
                .try_reserve(two_units)
                .expect("released capacity admits waiting charge");
            budget.clear_waiting();
            assert_eq!(budget.metrics.waiting_bytes.get(), 0);
            assert_eq!(budget.metrics.admitted.get(), 1);
            assert_eq!(
                budget.metrics.reserved_bytes.get(),
                i64::try_from(two_units.estimated_bytes).expect("test charge fits metric")
            );

            drop(second);
            assert_eq!(budget.metrics.reserved_bytes.get(), 0);
            assert_eq!(budget.metrics.admitted.get(), 0);
            assert_eq!(budget.permits.available_permits(), 2);
        });
    }

    #[test]
    fn oversized_upload_reserves_the_entire_budget() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let configured_bytes = 2 * FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES;
            let budget = UploadBudget::new(&context.child("upload_budget"), configured_bytes);
            let one_unit_encoded = usize::try_from(FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES / 8)
                .expect("test charge fits usize");
            let regular_charge = budget.charge(one_unit_encoded);
            let oversized_encoded =
                usize::try_from(configured_bytes / 8 + 1).expect("test charge fits usize");
            let oversized_charge = budget.charge(oversized_encoded);
            assert!(oversized_charge.oversized);

            let regular = budget
                .try_reserve(regular_charge)
                .expect("regular charge fits budget");
            assert!(budget.try_reserve(oversized_charge).is_none());
            drop(regular);

            let oversized = budget
                .try_reserve(oversized_charge)
                .expect("oversized charge runs alone");
            assert_eq!(budget.permits.available_permits(), 0);
            assert!(budget.try_reserve(regular_charge).is_none());
            assert_eq!(budget.metrics.oversized.get(), 1);
            assert!(
                budget.metrics.reserved_bytes.get()
                    > i64::try_from(configured_bytes).expect("test budget fits metric")
            );

            drop(oversized);
            assert!(budget.try_reserve(regular_charge).is_some());
        });
    }

    #[test]
    fn completed_task_keeps_its_upload_reservation() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let budget = UploadBudget::new(
                &context.child("upload_budget"),
                FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
            );
            let encoded = usize::try_from(FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES / 8)
                .expect("test charge fits usize");
            let charge = budget.charge(encoded);
            let reservation = budget.try_reserve(charge).expect("test charge fits budget");
            let mut active = tokio::task::JoinSet::new();
            active.spawn(async move { (0, 0, reservation) });

            let (_, _, reservation) = active
                .join_next()
                .await
                .expect("completed upload exists")
                .expect("completed upload succeeds");
            assert_eq!(budget.permits.available_permits(), 0);
            assert!(budget.try_reserve(charge).is_none());

            drop(reservation);
            assert_eq!(budget.permits.available_permits(), 1);
        });
    }

    fn capture_receipt(height: u64, state_end: u64, transaction_end: u64) -> LatestCaptureReceipt {
        LatestCaptureReceipt {
            height,
            block_digest: Sha256Digest::from([height as u8; Sha256Digest::SIZE]),
            state_end,
            transaction_end,
        }
    }
}
