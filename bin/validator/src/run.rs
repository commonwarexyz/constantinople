//! Starts a validator from a YAML config.

use crate::{
    config::{
        IndexerConfig, LoadedConfig, StartupModeConfig, load_deployer_config, load_local_config,
    },
    finalized_payloads::{PayloadCleanup, PayloadDescriptor, PayloadStore},
    state_reader::StateDbReader,
};
use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_codec::{Decode as _, Encode, FixedSize, Read, ReadExt as _, Write};
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
            CapturedFinalizedUpload, OperationList, PublishError, QueuedFinalizedUpload,
            QueuedFinalizedUploadCfg,
        },
    },
    sql_schema::meta_schema_fingerprint,
};
use constantinople_mempool::webserver::{self, AccountReader, Mailbox};
use constantinople_primitives::PublicKeyCache;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    path::PathBuf,
    pin::Pin,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use tokio::{
    sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, TryAcquireError, oneshot},
    task::{JoinHandle, JoinSet},
};
use tracing::{Instrument as _, info, info_span, warn};

const MEMPOOL_MAILBOX_SIZE: usize = 65_536;

const STATE_SYNC_APPLY_BATCH_SIZE: NonZeroU64 = NZU64!(1024);
const PRUNE_CONFIG: PruneConfig = PruneConfig {
    maintenance_interval: NZUsize!(1024),
    retained_marshal_blocks: 1024,
    retained_qmdb_blocks: 32,
};
const PRUNABLE_ITEMS_PER_SECTION: NonZeroU64 = NZU64!(4_096);
// Queue records are under a hundred bytes. Small sections keep the payload
// blobs of acknowledged entries on disk only until their section prunes.
const FINALIZED_QUEUE_ITEMS_PER_SECTION: NonZeroU64 = NZU64!(16);
const FINALIZED_QUEUE_PAGE_SIZE: NonZeroU16 = paged::page_size(4_096);
const FINALIZED_QUEUE_PAGE_CACHE_PAGES: NonZeroUsize = NZUsize!(256);
const FINALIZED_QUEUE_WRITE_BUFFER: NonZeroUsize = NZUsize!(64 * 1024);
const NETWORK_BUFFER_POOL_MAX_SIZE: NonZeroUsize = NZUsize!(2 * 1024 * 1024);
const NETWORK_BUFFER_POOL_MAX_PER_CLASS: NonZeroU32 = NZU32!(1_024);
const NETWORK_CHANNEL_MAILBOX_BUDGET: usize = 1_024;
const STORAGE_BUFFER_POOL_MAX_PER_CLASS: NonZeroU32 = NZU32!(128);
const MAX_FINALIZED_QUEUE_UPLOADS: usize = 64;
const FINALIZED_UPLOAD_AMPLIFICATION: u64 = 8;
const FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES: u64 = 64 * 1024;
const FINALIZED_UPLOAD_DURATION_BUCKETS: [f64; 27] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.0625, 0.08, 0.1, 0.125, 0.16, 0.2, 0.25, 0.315, 0.4,
    0.5, 0.63, 0.8, 1.0, 1.25, 1.6, 2.0, 2.5, 5.0, 10.0, 30.0, 60.0,
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
type EngineCapturedUpload = CapturedFinalizedUpload<Sha256, PublicKey, MinSig>;
type FinalizedQueueWriter = queue::Writer<RuntimeContext, FinalizedQueueRecord>;
type FinalizedQueueReader = queue::Reader<RuntimeContext, FinalizedQueueRecord>;
type FinalizedPayloads = PayloadStore<RuntimeContext>;
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
    fn from_upload<S: OperationList, T: OperationList>(
        upload: &QueuedFinalizedUpload<Sha256, PublicKey, MinSig, S, T>,
    ) -> Self {
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

/// Durable queue entry for one finalized block.
///
/// The queue holds only this record. The encoded upload lives in the payload
/// partition, so the consumer reads it outside the shared queue lock and a
/// restart recovers the queue without reading any payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FinalizedQueueRecord {
    receipt: LatestCaptureReceipt,
    state_start: u64,
    transaction_start: u64,
    payload: PayloadDescriptor,
}

impl FinalizedQueueRecord {
    const fn height(&self) -> u64 {
        self.receipt.height
    }
}

impl FixedSize for FinalizedQueueRecord {
    const SIZE: usize = LatestCaptureReceipt::SIZE + u64::SIZE + u64::SIZE + u64::SIZE + u32::SIZE;
}

impl Write for FinalizedQueueRecord {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.receipt.write(buf);
        self.state_start.write(buf);
        self.transaction_start.write(buf);
        self.payload.len.write(buf);
        self.payload.crc.write(buf);
    }
}

impl Read for FinalizedQueueRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            receipt: LatestCaptureReceipt::read(buf)?,
            state_start: u64::read(buf)?,
            transaction_start: u64::read(buf)?,
            payload: PayloadDescriptor {
                len: u64::read(buf)?,
                crc: u32::read(buf)?,
            },
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
    admitted_bytes: Gauge,
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
            admitted_bytes: context.gauge(
                "admitted_bytes",
                "Encoded payload bytes of admitted finalized uploads, the amplification base",
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

    fn charge(&self, encoded_bytes: u64) -> UploadCharge {
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
            encoded_bytes,
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
        let encoded_bytes = metric_bytes(charge.encoded_bytes);
        self.metrics.reserved_bytes.inc_by(estimated_bytes);
        self.metrics.admitted_bytes.inc_by(encoded_bytes);
        self.metrics.admitted.inc();
        if charge.oversized {
            self.metrics.oversized.inc();
        }
        UploadReservation {
            _permit: permit,
            metrics: self.metrics.clone(),
            estimated_bytes,
            encoded_bytes,
            started_at: Instant::now(),
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
    encoded_bytes: u64,
    estimated_bytes: u64,
    permit_units: u32,
    oversized: bool,
}

struct UploadReservation {
    _permit: OwnedSemaphorePermit,
    metrics: UploadBudgetMetrics,
    estimated_bytes: i64,
    encoded_bytes: i64,
    started_at: Instant,
}

impl Drop for UploadReservation {
    fn drop(&mut self) {
        self.metrics
            .reservation_held
            .observe(self.started_at.elapsed().as_secs_f64());
        self.metrics.reserved_bytes.dec_by(self.estimated_bytes);
        self.metrics.admitted_bytes.dec_by(self.encoded_bytes);
        self.metrics.admitted.dec();
    }
}

#[derive(Clone)]
struct FinalizedUploadMetrics {
    queue_read: Histogram,
    active_capacity_wait: Histogram,
    admission_wait: Histogram,
    decode_schedule_wait: Histogram,
    decode: Histogram,
    turn_wait: Histogram,
    completion: Histogram,
    receipt_sync: Histogram,
    queue_sync: Histogram,
}

impl FinalizedUploadMetrics {
    fn new(context: &impl Metrics) -> Self {
        Self {
            queue_read: context.histogram(
                "queue_read_duration",
                "Finalized queue record read time (s)",
                FINALIZED_UPLOAD_DURATION_BUCKETS,
            ),
            active_capacity_wait: context.histogram(
                "active_capacity_wait_duration",
                "Consumer wait for an upload task while at the active limit (s)",
                FINALIZED_UPLOAD_DURATION_BUCKETS,
            ),
            admission_wait: context.histogram(
                "admission_wait_duration",
                "Time from queue record read to byte budget admission (s)",
                FINALIZED_UPLOAD_DURATION_BUCKETS,
            ),
            decode_schedule_wait: context.histogram(
                "decode_schedule_wait_duration",
                "Payload decode wait for a blocking worker (s)",
                FINALIZED_UPLOAD_DURATION_BUCKETS,
            ),
            decode: context.histogram(
                "decode_duration",
                "Payload decode wall time inside the blocking worker (s)",
                FINALIZED_UPLOAD_DURATION_BUCKETS,
            ),
            turn_wait: context.histogram(
                "turn_wait_duration",
                "Decoded upload wait for predecessor publisher admission (s)",
                FINALIZED_UPLOAD_DURATION_BUCKETS,
            ),
            completion: context.histogram(
                "completion_duration",
                "Finalized upload queue acknowledgement time (s)",
                FINALIZED_UPLOAD_DURATION_BUCKETS,
            ),
            receipt_sync: context.histogram(
                "receipt_sync_duration",
                "Capture receipt sync time before a section prune (s)",
                FINALIZED_UPLOAD_DURATION_BUCKETS,
            ),
            queue_sync: context.histogram(
                "queue_sync_duration",
                "Finalized queue sync and prune time per acknowledged section (s)",
                FINALIZED_UPLOAD_DURATION_BUCKETS,
            ),
        }
    }
}

/// Stage timings for the finalized hook, which runs on the stateful actor's
/// critical path. Lock wait on the shared queue is `record_enqueue` minus the
/// queue journal's own append and commit timers.
#[derive(Clone)]
struct FinalizedCaptureMetrics {
    finalization_lookup: Histogram,
    construct: Histogram,
    record_enqueue: Histogram,
    total: Histogram,
}

impl FinalizedCaptureMetrics {
    fn new(context: &impl Metrics) -> Self {
        Self {
            finalization_lookup: context.histogram(
                "finalization_lookup_duration",
                "Marshal finalization lookup time in the finalized hook (s)",
                FINALIZED_UPLOAD_DURATION_BUCKETS,
            ),
            construct: context.histogram(
                "construct_duration",
                "Queue payload construction and encoding time in the finalized hook (s)",
                FINALIZED_UPLOAD_DURATION_BUCKETS,
            ),
            record_enqueue: context.histogram(
                "record_enqueue_duration",
                "Finalized queue record enqueue time including lock wait (s)",
                FINALIZED_UPLOAD_DURATION_BUCKETS,
            ),
            total: context.histogram(
                "duration",
                "Finalized hook time from artifact handoff to durable capture (s)",
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
    payloads: FinalizedPayloads,
    cleanup: PayloadCleanup,
    receipt_store: Arc<FinalizedReceiptStore>,
    queue_ready: Arc<Notify>,
    max_active: usize,
    budget: UploadBudget,
    metrics: FinalizedUploadMetrics,
    queue_metrics: FinalizedQueueMetrics,
    payload_floor: u64,
}

struct PendingQueuedUpload {
    position: u64,
    record: FinalizedQueueRecord,
    charge: UploadCharge,
    admission_started: Instant,
    metrics: FinalizedUploadMetrics,
}

impl PendingQueuedUpload {
    fn new(
        position: u64,
        record: FinalizedQueueRecord,
        budget: &UploadBudget,
        metrics: &FinalizedUploadMetrics,
    ) -> Self {
        let charge = budget.charge(record.payload.len);
        Self {
            position,
            record,
            charge,
            admission_started: Instant::now(),
            metrics: metrics.clone(),
        }
    }

    fn try_reserve(&self, budget: &UploadBudget) -> Option<UploadReservation> {
        let reservation = budget.try_reserve(self.charge)?;
        self.observe_admission();
        Some(reservation)
    }

    async fn reserve(&self, budget: &UploadBudget) -> UploadReservation {
        let reservation = budget.reserve(self.charge).await;
        self.observe_admission();
        reservation
    }

    fn observe_admission(&self) {
        self.metrics
            .admission_wait
            .observe(self.admission_started.elapsed().as_secs_f64());
    }
}

fn metric_bytes(bytes: u64) -> i64 {
    i64::try_from(bytes).unwrap_or(i64::MAX)
}

fn metric_usize(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
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

    /// Connect on first use. The slot lock is held across the connect so
    /// concurrent callers share one publisher instead of racing to create two.
    async fn publisher(&self) -> Arc<EnginePublisher> {
        let mut slot = self.publisher.lock().await;
        if let Some(publisher) = slot.as_ref() {
            return publisher.clone();
        }
        loop {
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
                    *slot = Some(publisher.clone());
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
    payloads: FinalizedPayloads,
    receipt: Arc<Mutex<Option<LatestCaptureReceipt>>>,
    publisher: Arc<LazyPublisher>,
    queue_ready: Arc<Notify>,
    queue_metrics: FinalizedQueueMetrics,
    capture_metrics: FinalizedCaptureMetrics,
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
        let height = block.header.height;
        let started = Instant::now();
        let marshal = self
            .marshal
            .get()
            .expect("marshal mailbox must be installed before engine start");
        let finalization = marshal
            .get_finalization(commonware_consensus::types::Height::new(height))
            .instrument(info_span!("indexer.capture.finalization_lookup", height))
            .await
            .unwrap_or_else(|| {
                panic!("marshal is missing the durable finalization at height {height}")
            });
        self.capture_metrics
            .finalization_lookup
            .observe(started.elapsed().as_secs_f64());

        // Construction is synchronous, so the span guard never crosses an await.
        let construct_started = Instant::now();
        let (record_header, encoded) = {
            let _span = info_span!("indexer.capture.construct", height).entered();
            let upload = EngineCapturedUpload::from_finalized_artifacts(
                block,
                finalization,
                current_time_micros(),
                artifacts,
            )
            .expect("captured finalized artifacts must form a valid queue entry");
            let header = (
                LatestCaptureReceipt::from_upload(&upload),
                upload.state_start(),
                upload.transaction_start(),
            );
            (header, upload.encode())
        };
        let (receipt, state_start, transaction_start) = record_header;
        self.capture_metrics
            .construct
            .observe(construct_started.elapsed().as_secs_f64());

        // The payload is durable before its record commits, so a committed
        // record never points at bytes a crash could lose.
        let payload = self
            .payloads
            .write(height, encoded)
            .instrument(info_span!("indexer.capture.payload_write", height))
            .await
            .unwrap_or_else(|error| {
                panic!("failed to persist finalized index payload at height {height}. {error}")
            });
        let record = FinalizedQueueRecord {
            receipt,
            state_start,
            transaction_start,
            payload,
        };

        // Count the capture before the consumer can complete it.
        self.queue_metrics.pending_uploads.inc();
        let enqueue_started = Instant::now();
        let position = self
            .writer
            .enqueue(record)
            .instrument(info_span!("indexer.capture.record_enqueue", height))
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "failed to durably enqueue finalized index upload at height {height}. {error}"
                )
            });
        self.capture_metrics
            .record_enqueue
            .observe(enqueue_started.elapsed().as_secs_f64());

        // The queue tail is the receipt while any record exists. The consumer
        // persists a receipt only when a section prunes, so the hook pays for
        // two fsyncs per block instead of three.
        *current = Some(receipt);
        self.capture_metrics
            .total
            .observe(started.elapsed().as_secs_f64());
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

/// Read every unacknowledged record in order and rewind the reader.
///
/// Records are tiny, so a restart with a deep backlog recovers without
/// touching a payload.
async fn scan_finalized_queue_records(
    reader: &mut FinalizedQueueReader,
) -> Vec<(u64, FinalizedQueueRecord)> {
    let mut records: Vec<(u64, FinalizedQueueRecord)> = Vec::new();
    loop {
        match reader.try_recv().await {
            Ok(Some((position, record))) => {
                assert_eq!(
                    record.height(),
                    position
                        .checked_add(1)
                        .expect("finalized queue position must not overflow")
                );
                if position == 0 {
                    assert_eq!(record.state_start, INITIAL_QMDB_END);
                    assert_eq!(record.transaction_start, INITIAL_QMDB_END);
                }
                if let Some((_, previous)) = records.last() {
                    assert_eq!(record.height(), previous.height() + 1);
                    assert_eq!(record.state_start, previous.receipt.state_end);
                    assert_eq!(record.transaction_start, previous.receipt.transaction_end);
                }
                records.push((position, record));
            }
            Ok(None) => {
                reader
                    .reset()
                    .await
                    .expect("failed to reset finalized index queue reader");
                return records;
            }
            Err(error) => panic!("failed to scan finalized index queue. {error}"),
        }
    }
}

/// Reconcile payload blobs with the scanned records.
///
/// Every record must have a payload of the recorded length. A blob without a
/// record is left over from a crash between a payload sync and its record
/// commit, or from a removal that failed after its section pruned, and is
/// removed here.
async fn sweep_finalized_payloads(
    payloads: &FinalizedPayloads,
    records: &[(u64, FinalizedQueueRecord)],
) {
    let on_disk = payloads
        .heights()
        .await
        .expect("failed to list finalized index payloads");
    let mut referenced = BTreeSet::new();
    let mut retained_bytes = 0u64;
    for (_, record) in records {
        let height = record.height();
        assert!(
            on_disk.contains(&height),
            "finalized queue record at height {height} has no payload"
        );
        let len = payloads
            .len(height)
            .await
            .expect("failed to open finalized index payload");
        assert_eq!(
            len, record.payload.len,
            "finalized index payload at height {height} does not match its record"
        );
        referenced.insert(height);
        retained_bytes = retained_bytes.saturating_add(len);
    }
    for height in on_disk.difference(&referenced) {
        info!(height, "removing orphaned finalized index payload");
        payloads
            .remove(*height, 0)
            .await
            .expect("failed to remove orphaned finalized index payload");
    }
    payloads.set_retained(referenced.len(), retained_bytes);
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
        payloads,
        cleanup,
        receipt_store,
        queue_ready,
        max_active,
        budget,
        metrics,
        queue_metrics,
        mut payload_floor,
    } = consumer;
    let mut active = JoinSet::new();
    let mut completed = BTreeMap::new();
    let mut retained_records = BTreeMap::new();
    let mut next_ack = None;
    let mut waiting = None;
    let mut admission_turn = None;
    let max_active = max_active.max(1);

    loop {
        while waiting.is_none() && active.len() < max_active {
            let item = match try_read_finalized_queue_entry(&mut reader, &metrics).await {
                Ok(item) => item,
                Err(error) => {
                    // Retry even if the producer never enqueues another entry.
                    warn!(error = %error, "failed to read finalized index queue, retrying");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    queue_ready.notify_one();
                    break;
                }
            };
            let Some((position, record)) = item else {
                break;
            };
            next_ack.get_or_insert(position);
            retained_records.insert(position, record);
            let pending = PendingQueuedUpload::new(position, record, &budget, &metrics);
            if let Some(pending) = try_admit_queued_upload(
                &mut active,
                publisher.clone(),
                cert_reporter.clone(),
                &payloads,
                &mut admission_turn,
                &budget,
                pending,
            )
            .await
            {
                waiting = Some(pending);
            }
        }

        tokio::select! {
            reservation = async {
                waiting
                    .as_ref()
                    .expect("waiting upload exists")
                    .reserve(&budget)
                    .await
            }, if waiting.is_some() && active.len() < max_active => {
                budget.clear_waiting();
                let pending = waiting.take().expect("waiting upload exists");
                start_queued_upload(
                    &mut active,
                    publisher.clone(),
                    cert_reporter.clone(),
                    &payloads,
                    &mut admission_turn,
                    pending,
                    reservation,
                )
                .await;
            }
            () = queue_ready.notified(), if waiting.is_none() && active.len() < max_active => {}
            result = next_completed_upload(&mut active, max_active, &metrics), if !active.is_empty() => {
                let (position, height) = result;
                let replaced = completed.insert(position, height);
                assert!(replaced.is_none(), "queue position completed more than once");
                while let Some(position) = next_ack {
                    let Some(height) = completed.remove(&position) else {
                        break;
                    };
                    let completion_started = Instant::now();
                    ack_finalized_queue_entry(&reader, position, height).await;
                    metrics
                        .completion
                        .observe(completion_started.elapsed().as_secs_f64());
                    prune_finalized_queue(
                        &reader,
                        &writer,
                        &cleanup,
                        &receipt_store,
                        &metrics,
                        &mut retained_records,
                        &mut payload_floor,
                    )
                    .await;
                    queue_metrics.pending_uploads.dec();
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

async fn next_completed_upload(
    active: &mut JoinSet<(u64, u64)>,
    max_active: usize,
    metrics: &FinalizedUploadMetrics,
) -> (u64, u64) {
    let capacity_wait_started = (active.len() >= max_active).then(Instant::now);
    let result = active.join_next().await;
    if let Some(started) = capacity_wait_started {
        metrics
            .active_capacity_wait
            .observe(started.elapsed().as_secs_f64());
    }
    result
        .expect("active upload set is not empty")
        .expect("finalized index upload task panicked")
}

async fn try_read_finalized_queue_entry(
    reader: &mut FinalizedQueueReader,
    metrics: &FinalizedUploadMetrics,
) -> Result<Option<(u64, FinalizedQueueRecord)>, queue::Error> {
    let started = Instant::now();
    let item = reader.try_recv().await?;
    if item.is_some() {
        metrics.queue_read.observe(started.elapsed().as_secs_f64());
    }
    Ok(item)
}

async fn try_admit_queued_upload(
    active: &mut JoinSet<(u64, u64)>,
    publisher: Arc<LazyPublisher>,
    cert_reporter: EngineCertReporter,
    payloads: &FinalizedPayloads,
    admission_turn: &mut Option<oneshot::Receiver<()>>,
    budget: &UploadBudget,
    pending: PendingQueuedUpload,
) -> Option<PendingQueuedUpload> {
    let Some(reservation) = pending.try_reserve(budget) else {
        budget.mark_waiting(pending.charge);
        return Some(pending);
    };
    start_queued_upload(
        active,
        publisher,
        cert_reporter,
        payloads,
        admission_turn,
        pending,
        reservation,
    )
    .await;
    None
}

async fn ack_finalized_queue_entry(reader: &FinalizedQueueReader, position: u64, height: u64) {
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
}

/// Persist the receipt, sync the queue, and delete payloads once a whole record
/// section is acknowledged.
///
/// Acknowledgements live in memory, and a restart redelivers every record above
/// the queue's pruning boundary, so payloads outlive their acknowledgement until
/// the section holding their record prunes. The receipt for the last record in
/// the pruned range is synced first. A crash after that leaves a receipt behind
/// a still-present tail, which recovery accepts, while a crash between a prune
/// and its receipt would leave an empty queue with no boundary. Syncing once per
/// section rather than per acknowledgement removes most consumer fsyncs. A
/// payload removal that fails leaves an orphan for the next startup sweep.
async fn prune_finalized_queue(
    reader: &FinalizedQueueReader,
    writer: &FinalizedQueueWriter,
    cleanup: &PayloadCleanup,
    receipt_store: &FinalizedReceiptStore,
    metrics: &FinalizedUploadMetrics,
    retained: &mut BTreeMap<u64, FinalizedQueueRecord>,
    payload_floor: &mut u64,
) {
    let ack_floor = match reader.ack_floor().await {
        Ok(floor) => floor,
        Err(error) => {
            warn!(error = %error, "failed to read finalized index queue floor");
            return;
        }
    };
    let boundary = pruned_record_boundary(ack_floor);
    if boundary <= *payload_floor {
        return;
    }
    let last_pruned = boundary
        .checked_sub(1)
        .expect("a pruning boundary above the payload floor is positive");
    let receipt = retained
        .get(&last_pruned)
        .expect("every acknowledged record was read by the consumer")
        .receipt;

    let receipt_started = Instant::now();
    persist_capture_receipt(receipt_store, receipt).await;
    metrics
        .receipt_sync
        .observe(receipt_started.elapsed().as_secs_f64());

    let sync_started = Instant::now();
    loop {
        match writer.sync().await {
            Ok(()) => break,
            Err(error) => {
                warn!(error = %error, "failed to sync finalized index queue, retrying");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
    metrics
        .queue_sync
        .observe(sync_started.elapsed().as_secs_f64());

    // Deletion may lag the durable prune. Startup removes any orphaned payloads.
    // Queue position `p` holds the block at height `p + 1`.
    while *payload_floor < boundary {
        let position = *payload_floor;
        let height = position
            .checked_add(1)
            .expect("finalized queue position must not overflow");
        let len = retained
            .remove(&position)
            .map_or(0, |record| record.payload.len);
        cleanup.enqueue(height, len).await;
        *payload_floor = height;
    }
}

/// First position still recoverable after the queue prunes below `ack_floor`.
const fn pruned_record_boundary(ack_floor: u64) -> u64 {
    let section = FINALIZED_QUEUE_ITEMS_PER_SECTION.get();
    ack_floor / section * section
}

/// Spawn the upload for an admitted record.
///
/// Payload reads and decodes run concurrently across admitted uploads so the
/// consumer loop never waits on them. The publisher still needs heights in
/// queue order, so each task waits for its predecessor to finish admitting
/// before it admits its own block, then hands the turn to its successor.
async fn start_queued_upload(
    active: &mut JoinSet<(u64, u64)>,
    publisher: Arc<LazyPublisher>,
    cert_reporter: EngineCertReporter,
    payloads: &FinalizedPayloads,
    admission_turn: &mut Option<oneshot::Receiver<()>>,
    pending: PendingQueuedUpload,
    reservation: UploadReservation,
) {
    let position = pending.position;
    let record = pending.record;
    let metrics = pending.metrics;
    let height = record.height();
    assert_eq!(
        height,
        position
            .checked_add(1)
            .expect("finalized queue position must not overflow")
    );
    let payloads = payloads.clone();
    let (admitted_tx, admitted_rx) = oneshot::channel();
    let turn = admission_turn.replace(admitted_rx);

    active.spawn(async move {
        let bytes = read_finalized_payload(&payloads, height, record.payload).await;

        // Decoding is CPU work over hundreds of thousands of operations, so it
        // runs on the blocking pool instead of a runtime worker.
        let upload = decode_finalized_payload(height, bytes, &metrics).await;
        assert_eq!(
            LatestCaptureReceipt::from_upload(&upload),
            record.receipt,
            "finalized index payload at height {height} does not match its record"
        );
        let block = Arc::new(upload.block().clone());
        let finalization = upload.finalization();

        wait_for_upload_turn(turn, &metrics).await;
        let engine_publisher = publisher.publisher().await;
        let mut completion = engine_publisher
            .enqueue_queued_finalized(upload)
            .await
            .unwrap_or_else(|error| {
                panic!("failed to start finalized index upload at height {height}. {error}")
            });
        let _ = admitted_tx.send(());

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
        release_reservation_after_uploads(
            height,
            completion.persisted(),
            simplex_completion.wait(),
            reservation,
        )
        .await;
        completion.published().await.unwrap_or_else(|error| {
            panic!("finalized index publication failed at height {height}. {error}")
        });
        (position, height)
    });
}

async fn wait_for_upload_turn(
    turn: Option<oneshot::Receiver<()>>,
    metrics: &FinalizedUploadMetrics,
) {
    let started = Instant::now();
    if let Some(turn) = turn {
        turn.await
            .expect("earlier finalized index upload exited before admitting its block");
    }
    metrics.turn_wait.observe(started.elapsed().as_secs_f64());
}

/// Hold the admission reservation only until this block's own uploads are durable.
///
/// Publication of the contiguous prefix is ordered and can wait on earlier
/// blocks. Holding memory through it would let one slow block pin the budget
/// of everything admitted behind it.
async fn release_reservation_after_uploads<Q, S>(
    height: u64,
    persisted: Q,
    simplex: S,
    reservation: UploadReservation,
) where
    Q: Future<Output = Result<(), PublishError>>,
    S: Future<Output = Result<(), CertificateUploaderStopped>>,
{
    match wait_for_finalized_uploads(persisted, simplex).await {
        Ok(()) => drop(reservation),
        Err(FinalizedUploadFailure::Qmdb(error)) => {
            panic!("QMDB upload failed at height {height}. {error}")
        }
        Err(FinalizedUploadFailure::Simplex(error)) => {
            panic!("finalized block upload failed at height {height}. {error}")
        }
    }
}

/// Read the payload for a queue record.
///
/// This panics on failure. The record committed only after the payload was
/// synced, so a mismatch is corruption rather than an expected state.
async fn read_finalized_payload(
    payloads: &FinalizedPayloads,
    height: u64,
    descriptor: PayloadDescriptor,
) -> Bytes {
    payloads
        .read(height, descriptor)
        .await
        .unwrap_or_else(|error| {
            panic!("failed to read finalized index payload at height {height}. {error}")
        })
}

async fn decode_finalized_payload(
    height: u64,
    bytes: Bytes,
    metrics: &FinalizedUploadMetrics,
) -> EngineQueuedUpload {
    let metrics = metrics.clone();
    let scheduled = Instant::now();
    tokio::task::spawn_blocking(move || {
        metrics
            .decode_schedule_wait
            .observe(scheduled.elapsed().as_secs_f64());
        let started = Instant::now();
        let upload = EngineQueuedUpload::decode_cfg(bytes, &QueuedFinalizedUploadCfg::default());
        metrics.decode.observe(started.elapsed().as_secs_f64());
        upload.unwrap_or_else(|error| {
            panic!("failed to decode finalized index payload at height {height}. {error}")
        })
    })
    .await
    .expect("finalized index payload decode task panicked")
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
    cert_join: commonware_runtime::Handle<()>,
    finalized_join: JoinHandle<()>,
    cleanup_join: commonware_runtime::Handle<()>,
) -> CriticalTask {
    Box::pin(async move {
        let (task, result) = tokio::select! {
            result = cert_join => ("Simplex certificate uploader", result.map_err(|error| error.to_string())),
            result = finalized_join => ("finalized index uploader", result.map_err(|error| error.to_string())),
            result = cleanup_join => ("finalized payload cleanup", result.map_err(|error| error.to_string())),
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
    info!(
        chain_indexer_url = %cfg.chain_indexer_url,
        upload_budget_bytes = cfg.upload_budget_bytes,
        upload_max_in_flight = max_active_uploads,
        configured_upload_max_in_flight = cfg.upload_max_in_flight,
        publisher_rayon_threads = cfg.publisher_rayon_threads.get(),
        upload_amplification = FINALIZED_UPLOAD_AMPLIFICATION,
        upload_budget_quantum_bytes = FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
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
    let capture_metrics = FinalizedCaptureMetrics::new(&context.child("finalized_capture"));
    let (cert_reporter, cert_join) = EngineCertReporter::connect(
        context.child("simplex_upload"),
        &cfg.chain_indexer_url,
        cfg.api_key.as_deref(),
        max_active_uploads,
    )?;
    let page_cache = CacheRef::from_pooler(
        &context,
        FINALIZED_QUEUE_PAGE_SIZE,
        FINALIZED_QUEUE_PAGE_CACHE_PAGES,
    );
    let (queue_writer, mut queue_reader) = queue::shared::init(
        context.child("finalized_queue"),
        queue::Config {
            partition: format!("{partition_prefix}-finalized-index-records"),
            items_per_section: FINALIZED_QUEUE_ITEMS_PER_SECTION,
            compression: None,
            codec_config: (),
            page_cache,
            write_buffer: FINALIZED_QUEUE_WRITE_BUFFER,
            replay_buffer: FINALIZED_QUEUE_WRITE_BUFFER,
        },
    )
    .await
    .expect("failed to initialize finalized index queue");
    let payloads = PayloadStore::new(
        context.child("finalized_payloads"),
        format!("{partition_prefix}-finalized-index-payloads"),
    );
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
    let records = scan_finalized_queue_records(&mut queue_reader).await;
    let payload_floor = queue_reader
        .ack_floor()
        .await
        .expect("failed to read finalized index queue floor");
    sweep_finalized_payloads(&payloads, &records).await;
    let queue_tail = records.last().map(|(_, record)| record.receipt);
    queue_metrics
        .pending_uploads
        .set(metric_usize(records.len()));
    let receipt = recover_capture_receipt(metadata_receipt, queue_tail);

    // Records exist only after a capture, and a captured block may already be
    // uploaded, so the remote namespaces are validated as fresh only when
    // nothing was ever captured.
    let require_fresh = requires_fresh_namespace_validation(receipt);
    let strategy = context.strategy(cfg.publisher_rayon_threads);
    let publisher = Arc::new(LazyPublisher::new(
        context.child("publisher"),
        cfg.chain_indexer_url,
        cfg.api_key,
        max_active_uploads,
        strategy,
        require_fresh,
    ));
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
    let (cleanup, cleanup_join) =
        payloads.start_cleanup(context.child("finalized_payload_cleanup"));
    let receipt_store = Arc::new(FinalizedReceiptStore {
        context,
        config: metadata_config,
        metadata: Mutex::new(Some(metadata)),
    });
    let queue_ready = Arc::new(Notify::new());
    let marshal = Arc::new(OnceLock::new());
    let finalized_producer = FinalizedUploadProducer {
        writer: queue_writer.clone(),
        payloads: payloads.clone(),
        receipt: Arc::new(Mutex::new(receipt)),
        publisher: publisher.clone(),
        queue_ready: queue_ready.clone(),
        queue_metrics: queue_metrics.clone(),
        capture_metrics,
        marshal: marshal.clone(),
    };
    let finalized_join = tokio::spawn(run_finalized_upload_consumer(FinalizedUploadConsumer {
        publisher,
        cert_reporter: cert_reporter.clone(),
        writer: queue_writer,
        reader: queue_reader,
        payloads,
        cleanup,
        receipt_store,
        queue_ready,
        max_active: max_active_uploads,
        budget,
        metrics: upload_metrics,
        queue_metrics,
        payload_floor,
    }));
    Ok(Some(IndexerHandle {
        finalized_producer,
        marshal,
        critical_task: Some(indexer_critical_task(
            cert_join,
            finalized_join,
            cleanup_join,
        )),
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
        CapturePosition, CertificateUploaderStopped, FINALIZED_QUEUE_ITEMS_PER_SECTION,
        FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES, FinalizedQueueRecord, FinalizedUploadFailure,
        LatestCaptureReceipt, PublishError, StoreClientBuildError, UploadBudget, capture_position,
        default_mempool_drop_grace_blocks, indexer_critical_task, maybe_build_indexer,
        pruned_record_boundary, recover_capture_receipt, release_reservation_after_uploads,
        requires_fresh_namespace_validation, wait_for_critical_task_exit,
        wait_for_finalized_uploads,
    };
    use crate::{config::IndexerConfig, finalized_payloads::PayloadDescriptor};
    use commonware_codec::{DecodeExt as _, Encode as _, FixedSize as _};
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_runtime::{Metrics as _, Runner as _, Spawner as _, Supervisor as _};
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

    #[test]
    fn indexer_uploader_or_cleanup_exit_fails_the_runtime() {
        for cleanup_exits in [false, true] {
            commonware_runtime::tokio::Runner::default().start(|context| async move {
                let certificate_uploader =
                    context.child("certificate").spawn(move |_| async move {
                        if cleanup_exits {
                            pending::<()>().await;
                        }
                    });
                let cleanup = context.child("cleanup").spawn(move |_| async move {
                    if !cleanup_exits {
                        pending::<()>().await;
                    }
                });
                let finalized_uploader = tokio::spawn(pending::<()>());
                let indexer_task =
                    indexer_critical_task(certificate_uploader, finalized_uploader, cleanup);

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
            });
        }
    }

    #[test]
    fn publisher_does_not_block_secondary_startup_on_connect_failure() {
        let runner =
            commonware_runtime::tokio::Runner::new(commonware_runtime::tokio::Config::default());
        runner.start(|context| async move {
            let indexer = IndexerConfig {
                chain_indexer_url: "http://127.0.0.1:1".to_string(),
                api_key: None,
                publisher_rayon_threads: NZUsize!(2),
                upload_max_in_flight: 1,
                upload_budget_bytes: super::FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
            };
            let handle = tokio::time::timeout(
                Duration::from_secs(2),
                maybe_build_indexer(context, false, Some(indexer), "test"),
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
                publisher_rayon_threads: NZUsize!(2),
                upload_max_in_flight: 1,
                upload_budget_bytes: FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
            };
            let error = maybe_build_indexer(context, false, Some(indexer), "test")
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
    fn queue_record_round_trips() {
        let record = FinalizedQueueRecord {
            receipt: capture_receipt(7, 11, 13),
            state_start: 5,
            transaction_start: 6,
            payload: PayloadDescriptor {
                len: 31_000_000,
                crc: 0xdead_beef,
            },
        };
        let encoded = record.encode();
        assert_eq!(encoded.len(), FinalizedQueueRecord::SIZE);
        assert_eq!(
            FinalizedQueueRecord::decode(encoded).expect("record decodes"),
            record
        );
    }

    #[test]
    fn restart_sweeps_payloads_left_after_durable_prune() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let queue_config = commonware_storage::queue::Config {
                partition: "cleanup-test-records".into(),
                items_per_section: FINALIZED_QUEUE_ITEMS_PER_SECTION,
                compression: None,
                codec_config: (),
                page_cache: commonware_runtime::buffer::paged::CacheRef::from_pooler(
                    &context,
                    super::FINALIZED_QUEUE_PAGE_SIZE,
                    super::FINALIZED_QUEUE_PAGE_CACHE_PAGES,
                ),
                write_buffer: super::FINALIZED_QUEUE_WRITE_BUFFER,
                replay_buffer: super::FINALIZED_QUEUE_WRITE_BUFFER,
            };
            let (writer, mut reader) = commonware_storage::queue::shared::init(
                context.child("queue"),
                queue_config.clone(),
            )
            .await
            .unwrap();
            let payloads = crate::finalized_payloads::PayloadStore::new(
                context.child("payloads"),
                "cleanup-test-payloads".into(),
            );
            let section = FINALIZED_QUEUE_ITEMS_PER_SECTION.get();
            let mut retained = std::collections::BTreeMap::new();
            for height in 1..=section + 1 {
                let payload = payloads
                    .write(height, bytes::Bytes::from_static(b"payload"))
                    .await
                    .unwrap();
                let record = FinalizedQueueRecord {
                    receipt: capture_receipt(height, height + 1, height + 1),
                    state_start: height,
                    transaction_start: height,
                    payload,
                };
                assert_eq!(writer.append(record).await.unwrap(), height - 1);
                retained.insert(height - 1, record);
            }
            writer.sync().await.unwrap();
            for position in 0..section {
                assert_eq!(reader.try_recv().await.unwrap().unwrap().0, position);
                reader.ack(position).await.unwrap();
            }
            let metadata_config = commonware_storage::metadata::Config {
                partition: "cleanup-test-receipt".into(),
                codec_config: (),
            };
            let metadata = commonware_storage::metadata::Metadata::init(
                context.child("metadata"),
                metadata_config.clone(),
            )
            .await
            .unwrap();
            let receipt_store = super::FinalizedReceiptStore {
                context: context.child("receipt"),
                config: metadata_config.clone(),
                metadata: tokio::sync::Mutex::new(Some(metadata)),
            };
            let metrics = super::FinalizedUploadMetrics::new(&context.child("upload"));
            let (cleanup, task) = payloads.start_cleanup(context.child("cleanup"));
            let mut payload_floor = 0;
            super::prune_finalized_queue(
                &reader,
                &writer,
                &cleanup,
                &receipt_store,
                &metrics,
                &mut retained,
                &mut payload_floor,
            )
            .await;
            assert_eq!(payload_floor, section);
            assert_eq!(retained.keys().copied().collect::<Vec<_>>(), vec![section]);
            task.abort();
            let _ = task.await;
            drop(cleanup);

            // Recreate a pending deletion if cleanup won the race before cancellation.
            if !payloads.heights().await.unwrap().contains(&1) {
                payloads
                    .write(1, bytes::Bytes::from_static(b"payload"))
                    .await
                    .unwrap();
            }
            drop((writer, reader, receipt_store, payloads));
            let (_writer, mut reader) = commonware_storage::queue::shared::init(
                context.child("recovered_queue"),
                queue_config,
            )
            .await
            .unwrap();
            let metadata = commonware_storage::metadata::Metadata::init(
                context.child("recovered_metadata"),
                metadata_config,
            )
            .await
            .unwrap();
            assert_eq!(
                metadata.get(&super::CAPTURE_RECEIPT_KEY).copied(),
                Some(capture_receipt(section, section + 1, section + 1))
            );
            let records = super::scan_finalized_queue_records(&mut reader).await;
            assert_eq!(records, retained.into_iter().collect::<Vec<_>>());
            let payloads = crate::finalized_payloads::PayloadStore::new(
                context.child("recovered_payloads"),
                "cleanup-test-payloads".into(),
            );
            assert!(payloads.heights().await.unwrap().contains(&1));
            super::sweep_finalized_payloads(&payloads, &records).await;
            assert_eq!(payloads.heights().await.unwrap(), [section + 1].into());
            assert_eq!(
                payloads
                    .read(section + 1, records[0].1.payload)
                    .await
                    .unwrap(),
                b"payload"[..]
            );
        });
    }

    #[test]
    fn pruned_record_boundary_rounds_down_to_a_section() {
        let section = FINALIZED_QUEUE_ITEMS_PER_SECTION.get();
        assert_eq!(pruned_record_boundary(0), 0);
        assert_eq!(pruned_record_boundary(section - 1), 0);
        assert_eq!(pruned_record_boundary(section), section);
        assert_eq!(pruned_record_boundary(3 * section + 5), 3 * section);
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
    fn fresh_validation_only_precedes_the_first_capture() {
        assert!(requires_fresh_namespace_validation(None));
        assert!(!requires_fresh_namespace_validation(Some(capture_receipt(
            1, 2, 3
        ))));
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
    fn admission_timer_survives_a_cancelled_budget_wait() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let metrics = super::FinalizedUploadMetrics::new(&context.child("upload"));
            let budget = UploadBudget::new(
                &context.child("budget"),
                FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
            );
            let occupied = budget.try_reserve(budget.charge(1)).unwrap();
            let record = FinalizedQueueRecord {
                receipt: capture_receipt(1, 1, 1),
                state_start: 0,
                transaction_start: 0,
                payload: PayloadDescriptor { len: 1, crc: 0 },
            };
            let pending = super::PendingQueuedUpload::new(0, record, &budget, &metrics);
            assert!(pending.try_reserve(&budget).is_none());
            let mut reservation = Box::pin(pending.reserve(&budget));
            assert!(futures::poll!(reservation.as_mut()).is_pending());
            assert!(
                context
                    .encode()
                    .contains("upload_admission_wait_duration_count 0")
            );
            drop(reservation);

            drop(occupied);
            let reservation = pending.reserve(&budget).await;
            assert!(
                context
                    .encode()
                    .contains("upload_admission_wait_duration_count 1")
            );
            assert!(context.encode().contains("upload_decode_duration_count 0"));
            drop(reservation);
        });
    }

    #[test]
    fn active_capacity_timer_only_counts_waits_at_the_limit() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let metrics = super::FinalizedUploadMetrics::new(&context.child("upload"));
            let mut active = tokio::task::JoinSet::new();
            let (release, blocked) = oneshot::channel();
            active.spawn(async move {
                blocked.await.unwrap();
                (0, 1)
            });
            let mut completion = Box::pin(super::next_completed_upload(&mut active, 1, &metrics));
            assert!(futures::poll!(completion.as_mut()).is_pending());
            assert!(
                context
                    .encode()
                    .contains("upload_active_capacity_wait_duration_count 0")
            );
            release.send(()).unwrap();
            assert_eq!(completion.await, (0, 1));
            assert!(
                context
                    .encode()
                    .contains("upload_active_capacity_wait_duration_count 1")
            );

            active.spawn(async { (1, 2) });
            assert_eq!(
                super::next_completed_upload(&mut active, 2, &metrics).await,
                (1, 2)
            );
            assert!(
                context
                    .encode()
                    .contains("upload_active_capacity_wait_duration_count 1")
            );
        });
    }

    #[test]
    fn turn_timer_observes_only_after_the_predecessor_releases() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let metrics = super::FinalizedUploadMetrics::new(&context.child("upload"));
            let (release, turn) = oneshot::channel();
            let mut waiting = Box::pin(super::wait_for_upload_turn(Some(turn), &metrics));
            assert!(futures::poll!(waiting.as_mut()).is_pending());
            assert!(
                context
                    .encode()
                    .contains("upload_turn_wait_duration_count 0")
            );
            release.send(()).unwrap();
            waiting.await;
            assert!(
                context
                    .encode()
                    .contains("upload_turn_wait_duration_count 1")
            );

            super::wait_for_upload_turn(None, &metrics).await;
            assert!(
                context
                    .encode()
                    .contains("upload_turn_wait_duration_count 2")
            );
        });
    }

    #[test]
    fn failed_decode_records_worker_scheduling_and_decode_separately() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            // Retain the registration after the failing task releases its handles.
            let metrics = super::FinalizedUploadMetrics::new(&context.child("upload"));
            let decode_metrics = metrics.clone();
            let result = tokio::spawn(async move {
                super::decode_finalized_payload(1, bytes::Bytes::new(), &decode_metrics).await
            })
            .await;
            assert!(result.err().expect("invalid payload must fail").is_panic());
            let encoded = context.encode();
            assert!(encoded.contains("upload_decode_schedule_wait_duration_count 1"));
            assert!(encoded.contains("upload_decode_duration_count 1"));
            assert!(encoded.contains("upload_turn_wait_duration_count 0"));
            drop(metrics);
        });
    }

    #[test]
    fn upload_budget_blocks_until_reservations_drop() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let budget = UploadBudget::new(
                &context.child("upload_budget"),
                2 * FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
            );
            let one_unit_encoded = FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES / 8;
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
            let regular_charge = budget.charge(FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES / 8);
            let oversized_charge = budget.charge(configured_bytes / 8 + 1);
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
    fn reservation_is_released_once_both_uploads_are_durable() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let budget = UploadBudget::new(
                &context.child("upload_budget"),
                FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
            );
            let charge = budget.charge(FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES / 8);
            let reservation = budget.try_reserve(charge).expect("test charge fits budget");
            let (qmdb_tx, qmdb_rx) = oneshot::channel();
            let (simplex_tx, simplex_rx) = oneshot::channel();
            let mut release = Box::pin(release_reservation_after_uploads(
                1,
                async move {
                    qmdb_rx
                        .await
                        .map_err(|_| PublishError::CommitterStopped { height: 1 })
                },
                async move { simplex_rx.await.map_err(|_| CertificateUploaderStopped) },
                reservation,
            ));

            qmdb_tx.send(()).expect("QMDB gate is open");
            assert!(
                tokio::time::timeout(Duration::from_millis(10), release.as_mut())
                    .await
                    .is_err()
            );
            assert_eq!(budget.permits.available_permits(), 0);

            simplex_tx.send(()).expect("Simplex gate is open");
            release.await;
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
