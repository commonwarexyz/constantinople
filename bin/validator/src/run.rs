//! Starts a validator from a YAML config.

use crate::{
    config::{
        IndexerConfig, LoadedConfig, StartupModeConfig, load_deployer_config, load_local_config,
    },
    state_reader::StateDbReader,
};
use commonware_actor::Feedback;
use commonware_codec::Encode;
use commonware_consensus::{
    Reporter,
    simplex::elector::RoundRobin,
    types::{Epoch, coding::Commitment},
};
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
    buffer::paged::CacheRef,
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
    tokio::{
        Context as RuntimeContext,
        telemetry::{self, Logs},
        tracing::Config as TracesConfig,
    },
};
use commonware_storage::{
    metadata::{Config as MetadataConfig, Metadata},
    queue,
    translator::EightCap,
};
use commonware_utils::{
    NZDuration, NZU16, NZU32, NZU64, NZUsize, TryCollect, ordered::Set, sequence::U64, union,
};
use constantinople_application::consensus::{DatabaseReaders, FinalizedHookFn};
use constantinople_engine::{
    CERTIFICATE_CHANNEL, Channels, Config as EngineConfig, Engine, MARSHAL_CHANNEL,
    MARSHAL_RESOLVER_CHANNEL, PROBE_CHANNEL, RESOLVER_CHANNEL, STATE_RESOLVER_CHANNEL, StartupMode,
    TRANSACTION_RESOLVER_CHANNEL, ThresholdScheme, VOTE_CHANNEL,
    types::{EngineActivity, EngineBlock},
};
use constantinople_indexer::{
    CertificateReporter, Publisher, StoreClientBuildError,
    publisher::{
        PublisherMetrics,
        certificate::CertificateUploaderStopped,
        qmdb::{
            PublishError, QueuedFinalizedUpload, QueuedFinalizedUploadCfg, StoredFinalizedUpload,
        },
    },
};
use constantinople_mempool::webserver::{self, AccountReader, Mailbox};
use constantinople_primitives::PublicKeyCache;
use std::{
    future::Future,
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    path::PathBuf,
    pin::Pin,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, TryAcquireError},
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
const FINALIZED_QUEUE_PAGE_SIZE: NonZeroU16 = NZU16!(4_096);
const FINALIZED_QUEUE_PAGE_CACHE_CAPACITY: NonZeroUsize = NZUsize!(8_192);
const FINALIZED_QUEUE_WRITE_BUFFER: NonZeroUsize = NZUsize!(1024 * 1024);
const NETWORK_BUFFER_POOL_MAX_SIZE: NonZeroUsize = NZUsize!(2 * 1024 * 1024);
const NETWORK_BUFFER_POOL_MAX_PER_CLASS: NonZeroU32 = NZU32!(1_024);
const NETWORK_CHANNEL_MAILBOX_BUDGET: usize = 1_024;
const STORAGE_BUFFER_POOL_MAX_PER_CLASS: NonZeroU32 = NZU32!(128);
const MAX_FINALIZED_QUEUE_UPLOADS: usize = 64;
const FINALIZED_UPLOAD_AMPLIFICATION: u64 = 8;
const FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES: u64 = 64 * 1024;
const CURSOR_STATE_KEY: U64 = U64::new(0);
const CURSOR_TRANSACTION_KEY: U64 = U64::new(1);

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
type EngineDatabaseReaders =
    DatabaseReaders<commonware_runtime::tokio::Context, Sha256, EightCap, Rayon>;
type EngineQueuedUpload = QueuedFinalizedUpload<Sha256, PublicKey>;
type EngineStoredUpload = StoredFinalizedUpload<Sha256, PublicKey>;
type FinalizedQueueWriter = queue::Writer<RuntimeContext, EngineStoredUpload>;
type FinalizedQueueReader = queue::Reader<RuntimeContext, EngineStoredUpload>;
type CursorMetadata = Metadata<RuntimeContext, U64, U64>;
type CriticalTask = Pin<Box<dyn Future<Output = ()> + Send>>;

struct FinalizedCursorStore {
    context: RuntimeContext,
    config: MetadataConfig<()>,
    metadata: Mutex<Option<CursorMetadata>>,
}

#[derive(Clone)]
struct UploadBudgetMetrics {
    _configured_bytes: Gauge,
    reserved_bytes: Gauge,
    waiting_bytes: Gauge,
    admitted: Gauge,
    admission_blocked: Counter,
    oversized: Counter,
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
}

impl Drop for UploadReservation {
    fn drop(&mut self) {
        self.metrics.reserved_bytes.dec_by(self.estimated_bytes);
        self.metrics.admitted.dec();
    }
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

#[derive(Clone)]
enum SimplexObserver {
    Indexer(EngineCertReporter),
    Relayer(crate::relayer::Observer),
}

impl Reporter for SimplexObserver {
    type Activity = EngineActivity<PublicKey, MinSig>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match self {
            Self::Indexer(reporter) => reporter.report(activity),
            Self::Relayer(reporter) => reporter.report(activity),
        }
    }
}

/// Bundle of indexer state that needs to outlive engine startup.
struct IndexerHandle {
    cert_reporter: EngineCertReporter,
    finalized_producer: FinalizedUploadProducer,
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
    publisher: Mutex<Option<Arc<EnginePublisher>>>,
}

impl LazyPublisher {
    fn new(
        context: RuntimeContext,
        store_url: String,
        api_key: Option<String>,
        buffer: usize,
        strategy: Rayon,
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
            publisher: Mutex::new(None),
        }
    }

    async fn publisher(&self) -> Arc<EnginePublisher> {
        loop {
            if let Some(publisher) = self.publisher.lock().await.as_ref().cloned() {
                return publisher;
            }

            match EnginePublisher::connect_with_strategy(
                self.context.child("publisher"),
                &self.store_url,
                self.api_key.as_deref(),
                self.buffer,
                self.metrics.clone(),
                self.strategy.clone(),
            )
            .await
            {
                Ok(publisher) => {
                    let publisher = Arc::new(publisher);
                    *self.publisher.lock().await = Some(publisher.clone());
                    return publisher;
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

    #[cfg(test)]
    async fn shutdown(&self) {
        let publisher = self.publisher.lock().await.take();
        if let Some(publisher) = publisher {
            Arc::try_unwrap(publisher)
                .expect("test owns the last publisher reference")
                .shutdown()
                .await;
        }
    }
}

#[derive(Clone)]
struct FinalizedUploadProducer {
    writer: FinalizedQueueWriter,
    metadata: Arc<FinalizedCursorStore>,
    cursor: Arc<Mutex<FinalizedUploadCursor>>,
    publisher: Arc<LazyPublisher>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct FinalizedUploadCursor {
    state_next: u64,
    transaction_next: u64,
}

impl FinalizedUploadCursor {
    fn from_metadata(metadata: &CursorMetadata) -> Option<Self> {
        let state_next = metadata.get(&CURSOR_STATE_KEY).cloned().map(u64::from);
        let transaction_next = metadata
            .get(&CURSOR_TRANSACTION_KEY)
            .cloned()
            .map(u64::from);
        Self::from_parts(state_next, transaction_next)
    }

    const fn from_parts(state_next: Option<u64>, transaction_next: Option<u64>) -> Option<Self> {
        match (state_next, transaction_next) {
            (Some(state_next), Some(transaction_next)) => Some(Self {
                state_next,
                transaction_next,
            }),
            _ => None,
        }
    }

    fn from_upload(upload: &EngineQueuedUpload) -> Self {
        Self {
            state_next: upload.state_end(),
            transaction_next: upload.transaction_end(),
        }
    }

    /// Return the later finalized-upload frontier as a whole cursor pair.
    ///
    /// Do not max fields independently: `state_next` and `transaction_next`
    /// are captured from one finalized block, so mixing halves from different
    /// sources can create a frontier that never existed.
    const fn max(self, other: Self) -> Self {
        if other.state_next > self.state_next
            || (other.state_next == self.state_next
                && other.transaction_next > self.transaction_next)
        {
            other
        } else {
            self
        }
    }
}

fn recovered_finalized_upload_cursor(
    metadata: Option<FinalizedUploadCursor>,
    queue: Option<FinalizedUploadCursor>,
) -> FinalizedUploadCursor {
    metadata.unwrap_or_default().max(queue.unwrap_or_default())
}

impl FinalizedUploadProducer {
    async fn enqueue(
        self,
        block: &EngineBlock<Sha256, PublicKey>,
        databases: &EngineDatabaseReaders,
    ) {
        loop {
            let mut cursor = self.cursor.lock().await;
            let upload = match EnginePublisher::build_queued_finalized_upload(
                cursor.state_next,
                cursor.transaction_next,
                block,
                databases,
            )
            .await
            {
                Ok(Some(upload)) => upload,
                Ok(None) => {
                    info!(
                        height = block.header.height,
                        state_next = cursor.state_next,
                        transaction_next = cursor.transaction_next,
                        "finalized block already uploaded, skipping index capture"
                    );
                    return;
                }
                Err(PublishError::StoreEmptyPastGenesis { .. }) if cursor.state_next == 0 => {
                    let publisher = self.publisher.publisher().await;
                    let (state_next, transaction_next) = publisher.next_locations().await;
                    if state_next == 0 && transaction_next == 0 {
                        warn!(
                            height = block.header.height,
                            "finalized index cursor is empty and remote Store has no cursor, retrying",
                        );
                        drop(cursor);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                    *cursor = FinalizedUploadCursor {
                        state_next,
                        transaction_next,
                    };
                    continue;
                }
                Err(error) => {
                    warn!(
                        height = block.header.height,
                        error = %error,
                        "failed to prepare finalized index queue entry, retrying",
                    );
                    drop(cursor);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            let next = FinalizedUploadCursor::from_upload(&upload);
            match self.writer.enqueue(upload.into()).await {
                Ok(position) => {
                    persist_finalized_cursor(&self.metadata, next).await;
                    *cursor = next;
                    info!(
                        height = block.header.height,
                        position,
                        state_next = next.state_next,
                        transaction_next = next.transaction_next,
                        "queued finalized index upload"
                    );
                    return;
                }
                Err(error) => {
                    warn!(
                        height = block.header.height,
                        error = %error,
                        "failed to enqueue finalized index upload, retrying",
                    );
                }
            }
            drop(cursor);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

async fn persist_finalized_cursor(store: &FinalizedCursorStore, cursor: FinalizedUploadCursor) {
    let mut metadata = store.metadata.lock().await;
    loop {
        let mut current = metadata
            .take()
            .expect("finalized cursor metadata must be present while locked");
        current.put(CURSOR_STATE_KEY, U64::new(cursor.state_next));
        current.put(CURSOR_TRANSACTION_KEY, U64::new(cursor.transaction_next));
        match current.sync().await {
            Ok(current) => {
                *metadata = Some(current);
                return;
            }
            Err(error) => {
                warn!(
                    error = %error,
                    state_next = cursor.state_next,
                    transaction_next = cursor.transaction_next,
                    "failed to persist finalized index cursor, retrying",
                );
            }
        }

        loop {
            match Metadata::init(
                store.context.child("finalized_cursor"),
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
                        "failed to reopen finalized index cursor, retrying",
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
}

async fn scan_finalized_queue_cursor(
    reader: &mut FinalizedQueueReader,
    budget: &UploadBudget,
) -> Option<FinalizedUploadCursor> {
    let mut cursor = None;
    loop {
        match reader.try_recv().await {
            Ok(Some((position, upload))) => {
                let charge = budget.charge(upload.encoded_len());
                let reservation = budget.reserve(charge).await;
                let upload = decode_finalized_queue_entry(position, upload);
                cursor = Some(FinalizedUploadCursor::from_upload(&upload));
                drop(reservation);
            }
            Ok(None) => {
                reader
                    .reset()
                    .await
                    .expect("failed to reset finalized index queue reader");
                return cursor;
            }
            Err(error) => {
                panic!("failed to scan finalized index queue: {error}");
            }
        }
    }
}

async fn run_finalized_upload_consumer(
    publisher: Arc<LazyPublisher>,
    cert_reporter: EngineCertReporter,
    writer: FinalizedQueueWriter,
    mut reader: FinalizedQueueReader,
    max_active: usize,
    budget: UploadBudget,
) {
    let mut active = JoinSet::new();
    let mut waiting = None;
    let mut reader_closed = false;
    let max_active = max_active.max(1);

    loop {
        while waiting.is_none() && active.len() < max_active {
            let item = match reader.try_recv().await {
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
            let pending = PendingQueuedUpload::new(position, upload, &budget);
            if let Err(pending) = try_admit_queued_upload(
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

        if reader_closed && active.is_empty() && waiting.is_none() {
            break;
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
            item = reader.recv(), if !reader_closed && waiting.is_none() && active.len() < max_active => {
                match item {
                    Ok(Some((position, upload))) => {
                        let pending = PendingQueuedUpload::new(position, upload, &budget);
                        if let Err(pending) = try_admit_queued_upload(
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
                    Ok(None) => reader_closed = true,
                    Err(error) => {
                        warn!(error = %error, "failed to read finalized index queue, retrying");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
            completed = active.join_next(), if !active.is_empty() => {
                let (position, height, reservation) = completed
                    .expect("active upload set is not empty")
                    .expect("finalized index upload task panicked");
                ack_finalized_queue_entry(&reader, &writer, position, height).await;
                drop(reservation);
            }
        }

        if reader_closed && active.is_empty() && waiting.is_none() {
            break;
        }
    }
}

async fn try_admit_queued_upload(
    active: &mut JoinSet<(u64, u64, UploadReservation)>,
    publisher: Arc<LazyPublisher>,
    cert_reporter: EngineCertReporter,
    budget: &UploadBudget,
    pending: PendingQueuedUpload,
) -> Result<(), PendingQueuedUpload> {
    let Some(reservation) = budget.try_reserve(pending.charge) else {
        budget.mark_waiting(pending.charge);
        return Err(pending);
    };
    start_queued_upload(active, publisher, cert_reporter, pending, reservation).await;
    Ok(())
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
    let block = upload.block();

    // QMDB admission advances strict cursors and must follow durable queue order.
    // Persistence waits can run concurrently after the cursor reservation succeeds.
    let engine_publisher = publisher.publisher().await;
    let completion = engine_publisher
        .enqueue_queued_finalized(upload)
        .await
        .unwrap_or_else(|error| {
            panic!("failed to start finalized index upload at height {height}. {error}")
        });

    active.spawn(async move {
        let simplex_completion = cert_reporter
            .publish_block(block)
            .await
            .unwrap_or_else(|error| {
                panic!("failed to start Simplex block upload at height {height}. {error}")
            });
        match wait_for_finalized_uploads(completion.wait(), simplex_completion.wait()).await {
            Ok(()) => (position, height, reservation),
            Err(FinalizedUploadFailure::Qmdb(error)) => {
                panic!("QMDB upload failed at height {height}. {error}")
            }
            Err(FinalizedUploadFailure::Simplex(error)) => {
                panic!("Simplex block upload failed at height {height}. {error}")
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

async fn wait_for_finalized_uploads<Q, S>(qmdb: Q, simplex: S) -> Result<(), FinalizedUploadFailure>
where
    Q: Future<Output = Result<(), PublishError>>,
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
    info!(
        chain_indexer_url = %cfg.chain_indexer_url,
        upload_budget_bytes = cfg.upload_budget_bytes,
        upload_max_in_flight = max_active_uploads,
        configured_upload_max_in_flight = cfg.upload_max_in_flight,
        upload_amplification = FINALIZED_UPLOAD_AMPLIFICATION,
        upload_budget_quantum_bytes = FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
        "starting full indexer uploaders",
    );
    let budget = UploadBudget::new(
        &context.child("finalized_upload_budget"),
        cfg.upload_budget_bytes,
    );
    let (cert_reporter, cert_join) = EngineCertReporter::connect(
        &context.child("simplex_upload"),
        &cfg.chain_indexer_url,
        cfg.api_key.as_deref(),
        max_active_uploads,
    )?;
    let publisher = Arc::new(LazyPublisher::new(
        context.child("publisher"),
        cfg.chain_indexer_url,
        cfg.api_key,
        max_active_uploads,
        strategy,
    ));
    let page_cache = CacheRef::from_pooler(
        &context,
        FINALIZED_QUEUE_PAGE_SIZE,
        FINALIZED_QUEUE_PAGE_CACHE_CAPACITY,
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
        },
    )
    .await
    .expect("failed to initialize finalized index queue");
    let metadata_config = MetadataConfig {
        partition: format!("{partition_prefix}-finalized-index-cursor"),
        codec_config: (),
    };
    let mut metadata = Metadata::init(context.child("finalized_cursor"), metadata_config.clone())
        .await
        .expect("failed to initialize finalized index cursor");
    let metadata_cursor = FinalizedUploadCursor::from_metadata(&metadata);
    let queue_cursor = scan_finalized_queue_cursor(&mut queue_reader, &budget).await;
    let cursor = recovered_finalized_upload_cursor(metadata_cursor, queue_cursor);
    if metadata_cursor != Some(cursor) {
        metadata.put(CURSOR_STATE_KEY, U64::new(cursor.state_next));
        metadata.put(CURSOR_TRANSACTION_KEY, U64::new(cursor.transaction_next));
        metadata = metadata
            .sync()
            .await
            .expect("failed to persist finalized index cursor");
    }
    let metadata = Arc::new(FinalizedCursorStore {
        context,
        config: metadata_config,
        metadata: Mutex::new(Some(metadata)),
    });
    let finalized_producer = FinalizedUploadProducer {
        writer: queue_writer.clone(),
        metadata,
        cursor: Arc::new(Mutex::new(cursor)),
        publisher: publisher.clone(),
    };
    let finalized_join = tokio::spawn(run_finalized_upload_consumer(
        publisher.clone(),
        cert_reporter.clone(),
        queue_writer,
        queue_reader,
        max_active_uploads,
        budget,
    ));
    Ok(Some(IndexerHandle {
        cert_reporter,
        finalized_producer,
        critical_task: Some(indexer_critical_task(cert_join, finalized_join)),
    }))
}

fn indexer_finalized_hook(
    indexer: Option<&IndexerHandle>,
) -> Option<FinalizedHookFn<commonware_runtime::tokio::Context, Commitment, Sha256, PublicKey, Rayon>>
{
    let indexer = indexer?;
    let finalized_producer = indexer.finalized_producer.clone();
    Some(Arc::new(move |block, databases| {
        Box::pin(finalized_producer.clone().enqueue(block, databases))
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
                rate,
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
                simplex_observer: relayer_observer.map(SimplexObserver::Relayer).or_else(|| {
                    indexer_handle
                        .as_ref()
                        .map(|h| h.cert_reporter.clone())
                        .map(SimplexObserver::Indexer)
                }),
                finalized_hook,
            },
        )
        .await;

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
        let reporter: Option<Mailbox<Commitment, PublicKey, Sha256>> = if is_primary {
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
        CertificateUploaderStopped, EngineCertReporter, EngineQueuedUpload,
        FINALIZED_QUEUE_ITEMS_PER_SECTION, FINALIZED_QUEUE_PAGE_CACHE_CAPACITY,
        FINALIZED_QUEUE_PAGE_SIZE, FINALIZED_QUEUE_WRITE_BUFFER,
        FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES, FinalizedQueueReader, FinalizedQueueWriter,
        FinalizedUploadCursor, FinalizedUploadFailure, LazyPublisher, PendingQueuedUpload,
        PublishError, StoreClientBuildError, UploadBudget, decode_finalized_queue_entry,
        default_mempool_drop_grace_blocks, indexer_critical_task, maybe_build_indexer,
        recovered_finalized_upload_cursor, scan_finalized_queue_cursor, start_queued_upload,
        wait_for_critical_task_exit, wait_for_finalized_uploads,
    };
    use crate::config::IndexerConfig;
    use commonware_codec::{Encode as _, FixedSize as _, Read as _, Write as _};
    use commonware_consensus::{
        marshal::coding::types::coding_config_for_participants,
        simplex::types::Context as SimplexContext,
        types::{Round, View, coding::Commitment},
    };
    use commonware_cryptography::{
        Digest as _, Signer as _,
        ed25519::PrivateKey,
        sha256::{Digest as Sha256Digest, Sha256},
    };
    use commonware_runtime::{Runner as _, Spawner as _, Strategizer as _, Supervisor as _};
    use commonware_storage::{
        merkle::mmr,
        qmdb::any::{
            unordered::{Operation as UnorderedOperation, Update as UnorderedUpdate},
            value::FixedEncoding,
        },
        queue,
    };
    use commonware_utils::{NZUsize, non_empty_range, sequence::FixedBytes};
    use constantinople_primitives::{
        Account, AccountKey, Block, Header, Sealable, SignedTransaction,
    };
    use std::{future::pending, sync::Arc, time::Duration};
    use tokio::sync::oneshot;

    type TestAccountValue = FixedBytes<{ Account::SIZE }>;
    type TestStateOperation =
        UnorderedOperation<mmr::Family, AccountKey, FixedEncoding<TestAccountValue>>;
    type LegacyFinalizedQueueWriter = queue::Writer<super::RuntimeContext, EngineQueuedUpload>;
    type LegacyFinalizedQueueReader = queue::Reader<super::RuntimeContext, EngineQueuedUpload>;

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
    fn finalized_upload_cursor_keeps_furthest_recovery_position() {
        let older = FinalizedUploadCursor {
            state_next: 10,
            transaction_next: 20,
        };
        let newer_state = FinalizedUploadCursor {
            state_next: 11,
            transaction_next: 1,
        };
        let newer_transaction = FinalizedUploadCursor {
            state_next: 10,
            transaction_next: 21,
        };

        assert_eq!(older.max(newer_state), newer_state);
        assert_eq!(older.max(newer_transaction), newer_transaction);
        assert_eq!(newer_state.max(older), newer_state);
        assert_eq!(newer_transaction.max(older), newer_transaction);
    }

    #[test]
    fn recovered_finalized_upload_cursor_uses_furthest_whole_frontier() {
        let metadata = FinalizedUploadCursor {
            state_next: 10,
            transaction_next: 20,
        };
        let queue = FinalizedUploadCursor {
            state_next: 11,
            transaction_next: 1,
        };

        assert_eq!(
            recovered_finalized_upload_cursor(None, None),
            Default::default()
        );
        assert_eq!(
            recovered_finalized_upload_cursor(Some(metadata), None),
            metadata
        );
        assert_eq!(recovered_finalized_upload_cursor(None, Some(queue)), queue);
        assert_eq!(
            recovered_finalized_upload_cursor(Some(metadata), Some(queue)),
            queue
        );
        assert_eq!(
            recovered_finalized_upload_cursor(Some(queue), Some(metadata)),
            queue
        );
    }

    #[test]
    fn finalized_upload_cursor_ignores_partial_metadata_pairs() {
        assert_eq!(FinalizedUploadCursor::from_parts(None, None), None);
        assert_eq!(FinalizedUploadCursor::from_parts(Some(10), None), None);
        assert_eq!(FinalizedUploadCursor::from_parts(None, Some(20)), None);
        assert_eq!(
            FinalizedUploadCursor::from_parts(Some(10), Some(20)),
            Some(FinalizedUploadCursor {
                state_next: 10,
                transaction_next: 20,
            }),
        );
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

    #[test]
    fn queued_uploads_reserve_qmdb_cursors_before_completion_tasks_spawn() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (store, url) = exoware_simulator::open_temp()
                .await
                .expect("spawn simulator");
            let publisher = Arc::new(LazyPublisher::new(
                context.child("publisher"),
                url.clone(),
                None,
                2,
                context.strategy(NZUsize!(2)),
            ));
            let engine_publisher = publisher.publisher().await;
            let (cert_reporter, cert_join) =
                EngineCertReporter::connect(&context.child("simplex_upload"), &url, None, 2)
                    .expect("reporter connects");
            let budget = UploadBudget::new(
                &context.child("upload_budget"),
                2 * FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
            );
            let mut active = tokio::task::JoinSet::new();

            let first = publishable_queued_upload(1, 0, 0);
            let first = PendingQueuedUpload::new(0, first.into(), &budget);
            let first_reservation = budget
                .try_reserve(first.charge)
                .expect("first upload fits budget");
            start_queued_upload(
                &mut active,
                publisher.clone(),
                cert_reporter.clone(),
                first,
                first_reservation,
            )
            .await;
            assert_eq!(engine_publisher.next_locations().await, (2, 2));

            let second = publishable_queued_upload(2, 2, 2);
            let second = PendingQueuedUpload::new(1, second.into(), &budget);
            let second_reservation = budget
                .try_reserve(second.charge)
                .expect("second upload fits budget");
            start_queued_upload(
                &mut active,
                publisher.clone(),
                cert_reporter,
                second,
                second_reservation,
            )
            .await;
            assert_eq!(engine_publisher.next_locations().await, (4, 3));
            assert_eq!(active.len(), 2);
            assert_eq!(budget.metrics.admitted.get(), 2);

            while let Some(completed) = active.join_next().await {
                let (_, _, reservation) = completed.expect("queued upload completes");
                drop(reservation);
            }
            assert_eq!(budget.metrics.admitted.get(), 0);
            cert_join.abort();
            let _ = cert_join.await;
            drop(engine_publisher);
            publisher.shutdown().await;
            drop(publisher);
            store.abort();
            let _ = store.await;
            context
                .stop(0, Some(Duration::from_secs(1)))
                .await
                .expect("runtime stops after strategy threads exit");
        });
    }

    #[test]
    fn finalized_queue_scan_recovers_last_cursor_and_resets_reader() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let budget = UploadBudget::new(
                &context.child("upload_budget"),
                FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
            );
            let (writer, mut reader): (FinalizedQueueWriter, FinalizedQueueReader) =
                queue::shared::init(
                    context.child("finalized_queue"),
                    finalized_queue_config(&context, "finalized-queue-scan-recovers-last-cursor"),
                )
                .await
                .expect("queue initializes");
            let first = queued_upload(1, 0, 2, 0, 2);
            let second = queued_upload(2, 2, 5, 2, 3);
            writer
                .enqueue(first.clone().into())
                .await
                .expect("enqueue first");
            writer
                .enqueue(second.clone().into())
                .await
                .expect("enqueue second");

            assert_eq!(
                scan_finalized_queue_cursor(&mut reader, &budget).await,
                Some(FinalizedUploadCursor::from_upload(&second))
            );
            assert_eq!(budget.permits.available_permits(), 1);

            let (position, upload) = reader
                .try_recv()
                .await
                .expect("read after scan")
                .expect("scan reset leaves first item readable");
            let upload = decode_finalized_queue_entry(position, upload);
            assert_eq!(
                FinalizedUploadCursor::from_upload(&upload),
                FinalizedUploadCursor::from_upload(&first)
            );
        });
    }

    #[test]
    fn finalized_queue_codec_is_upgrade_and_rollback_compatible() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let expected = queued_upload(1, 0, 2, 0, 2);
            let expected_bytes = expected.encode();

            {
                let (writer, _reader): (LegacyFinalizedQueueWriter, LegacyFinalizedQueueReader) =
                    queue::shared::init(
                        context.child("legacy_upgrade_writer"),
                        finalized_queue_config(&context, "finalized-queue-codec-upgrade"),
                    )
                    .await
                    .expect("legacy queue initializes");
                writer
                    .enqueue(expected.clone())
                    .await
                    .expect("legacy queue accepts upload");
                writer.sync().await.expect("legacy queue syncs");
            }

            {
                let (_writer, mut reader): (FinalizedQueueWriter, FinalizedQueueReader) =
                    queue::shared::init(
                        context.child("stored_upgrade_reader"),
                        finalized_queue_config(&context, "finalized-queue-codec-upgrade"),
                    )
                    .await
                    .expect("stored queue reopens legacy data");
                let (position, stored) = reader
                    .try_recv()
                    .await
                    .expect("stored queue reads legacy data")
                    .expect("legacy upload remains queued");
                assert_eq!(position, 0);
                assert_eq!(stored.encoded_len(), expected_bytes.len());
                assert_eq!(stored.encode(), expected_bytes);
                let decoded = decode_finalized_queue_entry(position, stored);
                assert_eq!(decoded.encode(), expected_bytes);
            }

            {
                let (writer, _reader): (FinalizedQueueWriter, FinalizedQueueReader) =
                    queue::shared::init(
                        context.child("stored_rollback_writer"),
                        finalized_queue_config(&context, "finalized-queue-codec-rollback"),
                    )
                    .await
                    .expect("stored queue initializes");
                writer
                    .enqueue(expected.clone().into())
                    .await
                    .expect("stored queue accepts upload");
                writer.sync().await.expect("stored queue syncs");
            }

            let (_writer, mut reader): (LegacyFinalizedQueueWriter, LegacyFinalizedQueueReader) =
                queue::shared::init(
                    context.child("legacy_rollback_reader"),
                    finalized_queue_config(&context, "finalized-queue-codec-rollback"),
                )
                .await
                .expect("legacy queue reopens stored data");
            let (position, decoded) = reader
                .try_recv()
                .await
                .expect("legacy queue reads stored data")
                .expect("stored upload remains queued");
            assert_eq!(position, 0);
            assert_eq!(decoded.encode(), expected_bytes);
        });
    }

    fn finalized_queue_config(
        context: &super::RuntimeContext,
        partition: &str,
    ) -> queue::Config<super::QueuedFinalizedUploadCfg> {
        let page_cache = commonware_runtime::buffer::paged::CacheRef::from_pooler(
            context,
            FINALIZED_QUEUE_PAGE_SIZE,
            FINALIZED_QUEUE_PAGE_CACHE_CAPACITY,
        );
        queue::Config {
            partition: partition.to_string(),
            items_per_section: FINALIZED_QUEUE_ITEMS_PER_SECTION,
            compression: None,
            codec_config: super::QueuedFinalizedUploadCfg::default(),
            page_cache,
            write_buffer: FINALIZED_QUEUE_WRITE_BUFFER,
        }
    }

    fn queued_upload(
        height: u64,
        state_start: u64,
        state_end: u64,
        transaction_start: u64,
        transaction_end: u64,
    ) -> EngineQueuedUpload {
        let leader = PrivateKey::from_seed(height).public_key();
        let parent_commitment = Commitment::from((
            Sha256Digest::EMPTY,
            Sha256Digest::EMPTY,
            Sha256Digest::EMPTY,
            coding_config_for_participants(4),
        ));
        let header = Header {
            context: SimplexContext {
                round: Round::zero(),
                leader,
                parent: (View::zero(), parent_commitment),
            },
            parent: Sha256Digest::EMPTY,
            height,
            timestamp: 0,
            state_root: Sha256Digest::EMPTY,
            state_range: non_empty_range!(state_start, state_end),
            transactions_root: Sha256Digest::EMPTY,
            transactions_range: non_empty_range!(transaction_start, transaction_end),
        };
        let block = Block::new(header, Vec::<SignedTransaction<Sha256>>::new())
            .seal(&mut Sha256::default());
        let state_delta: Vec<TestStateOperation> = vec![TestStateOperation::CommitFloor(
            None,
            mmr::Location::new(state_start),
        )];
        let mut encoded = bytes::BytesMut::new();
        block.write(&mut encoded);
        0i64.write(&mut encoded);
        state_start.write(&mut encoded);
        transaction_start.write(&mut encoded);
        state_delta.write(&mut encoded);

        let mut encoded = encoded.freeze();
        EngineQueuedUpload::read_cfg(&mut encoded, &super::QueuedFinalizedUploadCfg::default())
            .expect("queued upload decodes")
    }

    fn publishable_queued_upload(
        height: u64,
        state_start: u64,
        transaction_start: u64,
    ) -> EngineQueuedUpload {
        let transaction_ops = if transaction_start == 0 { 2 } else { 1 };
        let seed = u8::try_from(height).expect("test height fits account key");
        let key = AccountKey::from([seed; AccountKey::SIZE]);
        let account = Account {
            balance: height,
            ..Account::default()
        };
        let account = account.encode();
        let mut encoded_account = [0; Account::SIZE];
        encoded_account.copy_from_slice(&account);
        let state_delta = vec![
            TestStateOperation::Update(UnorderedUpdate(key, FixedBytes::new(encoded_account))),
            TestStateOperation::CommitFloor(None, mmr::Location::new(0)),
        ];

        let leader = PrivateKey::from_seed(height).public_key();
        let parent_commitment = Commitment::from((
            Sha256Digest::EMPTY,
            Sha256Digest::EMPTY,
            Sha256Digest::EMPTY,
            coding_config_for_participants(4),
        ));
        let header = Header {
            context: SimplexContext {
                round: Round::zero(),
                leader,
                parent: (View::zero(), parent_commitment),
            },
            parent: Sha256Digest::EMPTY,
            height,
            timestamp: 0,
            state_root: Sha256Digest::EMPTY,
            state_range: non_empty_range!(state_start, state_start + 2),
            transactions_root: Sha256Digest::EMPTY,
            transactions_range: non_empty_range!(
                transaction_start,
                transaction_start + transaction_ops
            ),
        };
        let block = Block::new(header, Vec::<SignedTransaction<Sha256>>::new())
            .seal(&mut Sha256::default());
        let mut encoded = bytes::BytesMut::new();
        block.write(&mut encoded);
        0i64.write(&mut encoded);
        state_start.write(&mut encoded);
        transaction_start.write(&mut encoded);
        state_delta.write(&mut encoded);

        let mut encoded = encoded.freeze();
        EngineQueuedUpload::read_cfg(&mut encoded, &super::QueuedFinalizedUploadCfg::default())
            .expect("publishable queued upload decodes")
    }
}
