//! Starts a validator from a YAML config.

use crate::{
    config::{
        IndexerConfig, LoadedConfig, StartupModeConfig, load_deployer_config, load_local_config,
    },
    state_reader::{BridgedAccountReader, serve_account_reads},
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
use commonware_macros::boxed;
use commonware_p2p::{Ingress, Manager as _, TrackedPeers, authenticated::discovery};
use commonware_parallel::Rayon;
use commonware_runtime::{
    BufferPoolConfig, Clock as _, Quota, Runner as _, Spawner as _, Strategizer as _,
    Supervisor as _,
    buffer::paged::CacheRef,
    iouring::{Config as RuntimeConfig, Context as RuntimeContext, Runner as RuntimeRunner},
    tokio::{telemetry::Logs, tracing::Config as TracesConfig},
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
    CertificateReporter, Publisher,
    publisher::{
        StoreCommitMetrics,
        qmdb::{PublishError, QueuedFinalizedUpload, QueuedFinalizedUploadCfg},
    },
};
use constantinople_mempool::webserver::{self, AccountReader, Mailbox};
use constantinople_primitives::PublicKeyCache;
use futures::{StreamExt as _, future::BoxFuture, stream::FuturesUnordered};
use std::{
    future::Future,
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    path::PathBuf,
    pin::Pin,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{sync::Mutex, task::JoinHandle};
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
const STORAGE_BUFFER_POOL_MAX_PER_CLASS: NonZeroU32 = NZU32!(128);
const P2P_MESSAGE_RATE: NonZeroU32 = NZU32!(1_024);
const MAX_FINALIZED_QUEUE_UPLOADS: usize = 64;
const CURSOR_STATE_KEY: U64 = U64::new(0);
const CURSOR_TRANSACTION_KEY: U64 = U64::new(1);
/// Account lookups buffered between the HTTP runtime and the consensus
/// runtime before submitters see backpressure.
const ACCOUNT_READ_QUEUE_SIZE: usize = 256;

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

fn buffer_pool_configs(rayon_threads: usize) -> (BufferPoolConfig, BufferPoolConfig) {
    // Ring I/O is staged from the single io_uring runtime thread, but pool
    // buffers can be released from the Rayon workers that compute over them.
    // Count those threads so the automatic TLS cache sizing does not hand any
    // single thread an oversized share of a scarce class.
    let parallelism = rayon_threads
        .checked_add(1)
        .and_then(NonZeroUsize::new)
        .expect("buffer pool parallelism overflowed");

    let network_cfg = BufferPoolConfig::for_network()
        .with_parallelism(parallelism)
        .with_size_class_range(
            NZUsize!(1024),
            NETWORK_BUFFER_POOL_MAX_SIZE,
            NETWORK_BUFFER_POOL_MAX_PER_CLASS,
        );
    let storage_cfg = BufferPoolConfig::for_storage()
        .with_parallelism(parallelism)
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
type EngineDatabaseReaders = DatabaseReaders<RuntimeContext, Sha256, EightCap, Rayon>;
type EngineQueuedUpload = QueuedFinalizedUpload<Sha256, PublicKey>;
type FinalizedQueueWriter = queue::Writer<RuntimeContext, EngineQueuedUpload>;
type FinalizedQueueReader = queue::Reader<RuntimeContext, EngineQueuedUpload>;
type CursorMetadata = Metadata<RuntimeContext, U64, U64>;

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
    publisher: Arc<LazyPublisher>,
    finalized_producer: FinalizedUploadProducer,
    /// Resolves if either indexer worker exits unexpectedly.
    critical_task: Option<CriticalTask>,
}

/// Connects the indexer publisher only when finalized data is ready to upload.
struct LazyPublisher {
    context: RuntimeContext,
    /// Hosts the publisher's Store HTTP client and background workers, which
    /// need a tokio reactor the consensus runtime does not provide.
    sidecar: tokio::runtime::Handle,
    store_url: String,
    buffer: usize,
    commit_metrics: StoreCommitMetrics,
    publisher: Mutex<Option<Arc<EnginePublisher>>>,
}

impl LazyPublisher {
    fn new(
        context: RuntimeContext,
        sidecar: tokio::runtime::Handle,
        store_url: String,
        buffer: usize,
    ) -> Self {
        // Registered once here: `connect` is retried on failure and must not
        // re-register.
        let commit_metrics = StoreCommitMetrics::new(&context);
        Self {
            context,
            sidecar,
            store_url,
            buffer,
            commit_metrics,
            publisher: Mutex::new(None),
        }
    }

    async fn publisher(&self) -> Arc<EnginePublisher> {
        let mut publisher_slot = self.publisher.lock().await;
        if let Some(publisher) = publisher_slot.as_ref().cloned() {
            return publisher;
        }

        loop {
            let store_url = self.store_url.clone();
            let buffer = self.buffer;
            let commit_metrics = self.commit_metrics.clone();
            let connect = self.sidecar.spawn(async move {
                EnginePublisher::connect(&store_url, buffer, commit_metrics).await
            });
            match connect.await {
                Ok(Ok(publisher)) => {
                    let publisher = Arc::new(publisher);
                    *publisher_slot = Some(publisher.clone());
                    return publisher;
                }
                Ok(Err(error)) => {
                    warn!(
                        error = %error,
                        chain_indexer_url = %self.store_url,
                        "indexer publisher connection failed, retrying",
                    );
                }
                Err(error) => {
                    warn!(
                        error = %error,
                        chain_indexer_url = %self.store_url,
                        "indexer publisher connect task failed, retrying",
                    );
                }
            }
            self.context.sleep(Duration::from_secs(1)).await;
        }
    }
}

#[derive(Clone)]
struct FinalizedUploadProducer {
    writer: FinalizedQueueWriter,
    metadata: Arc<Mutex<Option<CursorMetadata>>>,
    metadata_partition: Arc<str>,
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
        context: RuntimeContext,
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
                Ok(upload) => upload,
                Err(PublishError::StoreEmptyPastGenesis { .. }) if cursor.state_next == 0 => {
                    let publisher = self.publisher.publisher().await;
                    let (state_next, transaction_next) = publisher.next_locations().await;
                    if state_next == 0 && transaction_next == 0 {
                        warn!(
                            height = block.header.height,
                            "finalized index cursor is empty and remote Store has no cursor, retrying",
                        );
                        drop(cursor);
                        context.sleep(Duration::from_secs(1)).await;
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
                    context.sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            let next = FinalizedUploadCursor::from_upload(&upload);
            match self.writer.enqueue(upload).await {
                Ok(position) => {
                    persist_finalized_cursor(
                        &context,
                        &self.metadata,
                        &self.metadata_partition,
                        next,
                    )
                    .await;
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
            context.sleep(Duration::from_secs(1)).await;
        }
    }
}

async fn persist_finalized_cursor(
    context: &RuntimeContext,
    metadata: &Arc<Mutex<Option<CursorMetadata>>>,
    partition: &str,
    cursor: FinalizedUploadCursor,
) {
    loop {
        let stored = metadata.lock().await.take();
        let mut stored = match stored {
            Some(stored) => stored,
            None => match Metadata::init(
                context.child("reopen"),
                MetadataConfig {
                    partition: partition.to_string(),
                    codec_config: (),
                },
            )
            .await
            {
                Ok(stored) => stored,
                Err(error) => {
                    warn!(
                        error = %error,
                        state_next = cursor.state_next,
                        transaction_next = cursor.transaction_next,
                        "failed to reopen finalized index cursor, retrying",
                    );
                    context.sleep(Duration::from_secs(1)).await;
                    continue;
                }
            },
        };
        stored.put(CURSOR_STATE_KEY, U64::new(cursor.state_next));
        stored.put(CURSOR_TRANSACTION_KEY, U64::new(cursor.transaction_next));
        match stored.sync().await {
            Ok(stored) => {
                *metadata.lock().await = Some(stored);
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
        context.sleep(Duration::from_secs(1)).await;
    }
}

async fn scan_finalized_queue_cursor(
    reader: &mut FinalizedQueueReader,
) -> Option<FinalizedUploadCursor> {
    let mut cursor = None;
    loop {
        match reader.try_recv().await {
            Ok(Some((_position, upload))) => {
                cursor = Some(FinalizedUploadCursor::from_upload(&upload));
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

/// Uploads awaiting remote completion, resolving to (queue position, height).
type ActiveUploads = FuturesUnordered<BoxFuture<'static, (u64, u64)>>;

/// Drives finalized-queue uploads on the consensus runtime.
///
/// Queue reads/acks are consensus-runtime storage ops. The uploads themselves
/// complete on the sidecar (via the publisher) and are awaited here through
/// channel-backed futures.
async fn run_finalized_upload_consumer(
    context: RuntimeContext,
    publisher: Arc<LazyPublisher>,
    cert_reporter: EngineCertReporter,
    writer: FinalizedQueueWriter,
    mut reader: FinalizedQueueReader,
    max_active: usize,
) {
    let mut active = ActiveUploads::new();
    let mut reader_closed = false;
    let max_active = max_active.max(1);

    loop {
        while active.len() < max_active {
            let item = match reader.try_recv().await {
                Ok(item) => item,
                Err(error) => {
                    warn!(error = %error, "failed to read finalized index queue, retrying");
                    context.sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            let Some((position, upload)) = item else {
                break;
            };
            start_queued_upload(
                &context,
                &mut active,
                publisher.clone(),
                cert_reporter.clone(),
                position,
                upload,
            )
            .await;
        }

        if reader_closed && active.is_empty() {
            break;
        }

        tokio::select! {
            item = reader.recv(), if !reader_closed && active.len() < max_active => {
                match item {
                    Ok(Some((position, upload))) => {
                        start_queued_upload(
                            &context,
                            &mut active,
                            publisher.clone(),
                            cert_reporter.clone(),
                            position,
                            upload,
                        )
                        .await;
                    }
                    Ok(None) => reader_closed = true,
                    Err(error) => {
                        warn!(error = %error, "failed to read finalized index queue, retrying");
                        context.sleep(Duration::from_secs(1)).await;
                    }
                }
            }
            completed = active.next(), if !active.is_empty() => {
                let (position, height) = completed.expect("active upload set is not empty");
                ack_finalized_queue_entry(&context, &reader, &writer, position, height).await;
            }
        }

        if reader_closed && active.is_empty() {
            break;
        }
    }
}

async fn ack_finalized_queue_entry(
    context: &RuntimeContext,
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
                context.sleep(Duration::from_secs(1)).await;
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
                context.sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

#[boxed]
async fn start_queued_upload(
    context: &RuntimeContext,
    active: &mut ActiveUploads,
    publisher: Arc<LazyPublisher>,
    cert_reporter: EngineCertReporter,
    position: u64,
    upload: EngineQueuedUpload,
) {
    let height = upload.height();
    let completion = loop {
        let engine_publisher = publisher.publisher().await;
        match engine_publisher
            .enqueue_queued_finalized(upload.clone())
            .await
        {
            Ok(completion) => break completion,
            // The publisher's sidecar workers died (their panics are
            // swallowed by the sidecar runtime). Retrying can never succeed,
            // so fail loudly instead of stalling the indexer silently.
            Err(error @ PublishError::CommitterStopped { .. }) => {
                panic!("finalized index upload workers stopped: {error}");
            }
            Err(error) => {
                warn!(
                    height,
                    position,
                    error = %error,
                    "failed to start finalized index upload, retrying",
                );
                context.sleep(Duration::from_secs(1)).await;
            }
        }
    };

    active.push(Box::pin(async move {
        if completion.wait().await {
            cert_reporter.publish_block(upload.block()).await;
            return (position, height);
        }
        warn!(
            height,
            position, "finalized index uploader stopped after accepting upload",
        );
        // Never resolves: the entry must not be acked, and the consumer's
        // in-flight budget should stay consumed, matching the pre-existing
        // stall-forever behavior.
        std::future::pending().await
    }));
}

/// Build the indexer wiring iff the secondary validator opted in.
async fn maybe_build_indexer(
    context: RuntimeContext,
    sidecar: tokio::runtime::Handle,
    is_primary: bool,
    indexer: Option<IndexerConfig>,
    partition_prefix: &str,
) -> Option<IndexerHandle> {
    let cfg = indexer?;
    if is_primary {
        return None;
    }

    info!(
        chain_indexer_url = %cfg.chain_indexer_url,
        "starting full indexer uploaders",
    );
    let (cert_reporter, cert_join) = EngineCertReporter::connect(
        &cfg.chain_indexer_url,
        cfg.upload_buffer,
        StoreCommitMetrics::new(&context.child("simplex_upload")),
        sidecar.clone(),
    );
    let publisher = Arc::new(LazyPublisher::new(
        context.child("publisher"),
        sidecar,
        cfg.chain_indexer_url,
        cfg.upload_buffer,
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
    let metadata_partition = format!("{partition_prefix}-finalized-index-cursor");
    let mut metadata = Metadata::init(
        context.child("finalized_cursor"),
        MetadataConfig {
            partition: metadata_partition.clone(),
            codec_config: (),
        },
    )
    .await
    .expect("failed to initialize finalized index cursor");
    let metadata_cursor = FinalizedUploadCursor::from_metadata(&metadata);
    let queue_cursor = scan_finalized_queue_cursor(&mut queue_reader).await;
    let cursor = recovered_finalized_upload_cursor(metadata_cursor, queue_cursor);
    if metadata_cursor != Some(cursor) {
        metadata.put(CURSOR_STATE_KEY, U64::new(cursor.state_next));
        metadata.put(CURSOR_TRANSACTION_KEY, U64::new(cursor.transaction_next));
        metadata = metadata
            .sync()
            .await
            .expect("failed to persist finalized index cursor");
    }
    let metadata = Arc::new(Mutex::new(Some(metadata)));
    let finalized_producer = FinalizedUploadProducer {
        writer: queue_writer.clone(),
        metadata,
        metadata_partition: Arc::from(metadata_partition),
        cursor: Arc::new(Mutex::new(cursor)),
        publisher: publisher.clone(),
    };
    let max_active_uploads = cfg.upload_buffer.clamp(1, MAX_FINALIZED_QUEUE_UPLOADS);
    let consumer_publisher = publisher.clone();
    let consumer_cert_reporter = cert_reporter.clone();
    let finalized_consumer = context.child("finalized_consumer").spawn(move |context| {
        run_finalized_upload_consumer(
            context,
            consumer_publisher,
            consumer_cert_reporter,
            queue_writer,
            queue_reader,
            max_active_uploads,
        )
    });
    let critical_task: CriticalTask = Box::pin(async move {
        tokio::select! {
            _ = cert_join => {}
            _ = finalized_consumer => {}
        }
    });
    Some(IndexerHandle {
        cert_reporter,
        publisher,
        finalized_producer,
        critical_task: Some(critical_task),
    })
}

fn indexer_finalized_hook(
    indexer: Option<&IndexerHandle>,
) -> Option<FinalizedHookFn<RuntimeContext, Commitment, Sha256, PublicKey, Rayon>> {
    let indexer = indexer?;
    let publisher = indexer.publisher.clone();
    let finalized_producer = indexer.finalized_producer.clone();
    Some(Arc::new(move |block, databases| {
        Box::pin(finalized_producer.clone().enqueue(
            publisher.context.child("finalized_queue"),
            block,
            databases,
        ))
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

    // The consensus engine, p2p, and storage run on the single-threaded
    // io_uring runtime. Anything needing a tokio reactor (axum webservers,
    // Store uploads, OTLP export) runs on this sidecar tokio runtime, sized
    // by the config's `worker_threads`.
    let sidecar = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .thread_name("sidecar")
        .build()
        .expect("failed to build sidecar tokio runtime");
    let sidecar_handle = sidecar.handle().clone();

    let (network_buffer_pool_cfg, storage_buffer_pool_cfg) = buffer_pool_configs(rayon_threads);
    let runtime_cfg = RuntimeConfig::new()
        .with_storage_directory(storage_dir)
        // Preserve the io_uring runtime's original dial budget. The latest
        // runtime separates this from the read/write timeout and defaults it
        // to 10 seconds.
        .with_connect_timeout(Duration::from_secs(60))
        .with_network_buffer_pool_config(network_buffer_pool_cfg)
        .with_storage_buffer_pool_config(storage_buffer_pool_cfg);
    let runner = RuntimeRunner::new(runtime_cfg);

    runner.start(|context| async move {
        crate::telemetry::init(
            context.child("telemetry"),
            sidecar_handle.clone(),
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

        let max_peers_per_set = decoded
            .primary_participants
            .len()
            .checked_add(decoded.secondary_participants.len())
            .and_then(NonZeroUsize::new)
            .expect("validator peer set must not be empty");
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

        let quota = Quota::per_second(P2P_MESSAGE_RATE);
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

        let (mempool_mailbox, mempool_receiver) =
            Mailbox::channel(MEMPOOL_MAILBOX_SIZE, sidecar_handle.clone());
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
        let mut relayer_task: Option<JoinHandle<()>> = None;
        let mempool_handle: CriticalTask = if is_primary {
            // Bind on the sidecar: the listener registers with its reactor.
            let listener = sidecar_handle
                .spawn(tokio::net::TcpListener::bind(http_listen))
                .await
                .expect("sidecar bind task panicked")
                .expect("failed to bind mempool HTTP listener");
            info!(%http_listen, "mempool webserver listening");
            let handle = mempool_actor.start(listener, sidecar_handle.clone());
            Box::pin(async move {
                let _ = handle.await;
            })
        } else if let Some(relayer_config) = relayer.clone() {
            let view_clock = relayer_view_clock.expect("relayer view clock exists");
            drop(mempool_actor);
            info!(%http_listen, "relayer webserver listening");
            // The relayer is an axum + reqwest server. It lives wholesale on
            // the sidecar. Its exit (clean or panicked) is a critical-task
            // exit either way.
            relayer_task = Some(sidecar_handle.spawn(crate::relayer::serve(
                crate::relayer::ServerConfig {
                    listen: http_listen,
                    relayer: relayer_config,
                    account_reader: account_reader.clone(),
                    view_clock,
                    strategy: strategy.clone(),
                    max_batch_bytes: max_propose_bytes,
                },
            )));
            Box::pin(std::future::pending())
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
            sidecar_handle.clone(),
            is_primary,
            indexer,
            &indexer_partition_prefix,
        )
        .await;
        let finalized_hook = indexer_finalized_hook(indexer_handle.as_ref());

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
        // the cell is populated. Lookups arrive from the sidecar's HTTP
        // handlers over a channel and are answered here, on the runtime that
        // owns the state database's storage.
        let subscribe_fut = engine.subscribe_databases_detached();
        let account_reader_setter = account_reader.clone();
        let (bridged_reader, account_requests) =
            BridgedAccountReader::channel(ACCOUNT_READ_QUEUE_SIZE);
        let _account_reader_setup =
            context
                .child("account_reader")
                .spawn(move |context| async move {
                    let db = subscribe_fut.await;
                    let reader: Arc<dyn AccountReader> = Arc::new(bridged_reader);
                    let _ = account_reader_setter.set(reader);
                    info!("account reader attached");
                    serve_account_reads(context, db, account_requests).await;
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
        let indexer_task = indexer_handle
            .as_mut()
            .and_then(|handle| handle.critical_task.take())
            .unwrap_or_else(|| Box::pin(std::future::pending()));

        let critical_exit = wait_for_critical_task_exit(
            Some(probe_handle),
            engine_handle,
            mempool_handle,
            network_handle,
            indexer_task,
            relayer_task.as_mut(),
        )
        .await;
        if critical_exit != CriticalTaskExit::Relayer
            && let Some(relayer_task) = relayer_task
        {
            relayer_task.abort();
            let _ = relayer_task.await;
        }
    });

    // Dropped only after the consensus runtime has fully shut down: dropping
    // a tokio runtime from within an async context panics.
    drop(sidecar);
}

type CriticalTask = Pin<Box<dyn Future<Output = ()> + Send>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CriticalTaskExit {
    Probe,
    Engine,
    Mempool,
    Network,
    Indexer,
    Relayer,
}

async fn wait_for_critical_task_exit<E, M, N, I>(
    probe_handle: Option<CriticalTask>,
    engine_handle: E,
    mempool_handle: M,
    network_handle: N,
    indexer_handle: I,
    relayer_handle: Option<&mut JoinHandle<()>>,
) -> CriticalTaskExit
where
    E: Future,
    M: Future,
    N: Future,
    I: Future,
{
    let mut probe_handle = probe_handle.unwrap_or_else(|| Box::pin(std::future::pending()));
    let relayer_handle = async move {
        match relayer_handle {
            Some(handle) => {
                let _ = handle.await;
            }
            None => std::future::pending().await,
        }
    };
    tokio::pin!(relayer_handle);
    tokio::select! {
        _ = probe_handle.as_mut() => {
            tracing::warn!("probe exited");
            CriticalTaskExit::Probe
        },
        _ = engine_handle => {
            tracing::warn!("engine exited");
            CriticalTaskExit::Engine
        },
        _ = mempool_handle => {
            tracing::warn!("mempool exited");
            CriticalTaskExit::Mempool
        },
        _ = network_handle => {
            tracing::warn!("network exited");
            CriticalTaskExit::Network
        },
        _ = indexer_handle => {
            tracing::warn!("indexer exited");
            CriticalTaskExit::Indexer
        },
        _ = &mut relayer_handle => {
            tracing::warn!("relayer exited");
            CriticalTaskExit::Relayer
        },
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
        CriticalTaskExit, EngineQueuedUpload, FINALIZED_QUEUE_ITEMS_PER_SECTION,
        FINALIZED_QUEUE_PAGE_CACHE_CAPACITY, FINALIZED_QUEUE_PAGE_SIZE,
        FINALIZED_QUEUE_WRITE_BUFFER, FinalizedQueueReader, FinalizedQueueWriter,
        FinalizedUploadCursor, default_mempool_drop_grace_blocks, maybe_build_indexer,
        recovered_finalized_upload_cursor, scan_finalized_queue_cursor,
        wait_for_critical_task_exit,
    };
    use crate::config::IndexerConfig;
    use commonware_codec::{FixedSize as _, Read as _, Write as _};
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
    use commonware_runtime::{Clock as _, Runner as _, Supervisor as _};
    use commonware_storage::{
        merkle::mmr,
        qmdb::any::{unordered::Operation as UnorderedOperation, value::FixedEncoding},
        queue,
    };
    use commonware_utils::{non_empty_range, sequence::FixedBytes};
    use constantinople_primitives::{
        Account, AccountKey, Block, Header, Sealable, SignedTransaction,
    };
    use std::{future::pending, time::Duration};

    type TestAccountValue = FixedBytes<{ Account::SIZE }>;
    type TestStateOperation =
        UnorderedOperation<mmr::Family, AccountKey, FixedEncoding<TestAccountValue>>;

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
                pending::<()>(),
                pending::<()>(),
                pending::<()>(),
                pending::<()>(),
                None,
            ),
        )
        .await;

        assert!(
            result.is_err(),
            "completed setup work must not terminate the validator runtime",
        );
    }

    #[tokio::test]
    async fn completed_indexer_task_is_a_runtime_exit_condition() {
        let result = wait_for_critical_task_exit(
            None,
            pending::<()>(),
            pending::<()>(),
            pending::<()>(),
            std::future::ready(()),
            None,
        )
        .await;

        assert_eq!(result, CriticalTaskExit::Indexer);
    }

    #[test]
    fn publisher_does_not_block_secondary_startup_on_connect_failure() {
        let sidecar = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("sidecar runtime builds");
        let sidecar_handle = sidecar.handle().clone();
        let runner = commonware_runtime::iouring::Runner::default();
        runner.start(|context| async move {
            let indexer = IndexerConfig {
                chain_indexer_url: "http://127.0.0.1:1".to_string(),
                upload_buffer: 1,
            };

            let timeout = context.child("timeout").sleep(Duration::from_secs(2));
            let handle = tokio::select! {
                handle = maybe_build_indexer(
                    context,
                    sidecar_handle,
                    false,
                    Some(indexer),
                    "test",
                ) => handle,
                () = timeout => panic!("publisher connection should not block startup"),
            };
            handle.expect("secondary should keep indexer wiring");
        });
        drop(sidecar);
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
    fn finalized_queue_scan_recovers_last_cursor_and_resets_reader() {
        commonware_runtime::iouring::Runner::default().start(|context| async move {
            let page_cache = commonware_runtime::buffer::paged::CacheRef::from_pooler(
                &context,
                FINALIZED_QUEUE_PAGE_SIZE,
                FINALIZED_QUEUE_PAGE_CACHE_CAPACITY,
            );
            let (writer, mut reader): (FinalizedQueueWriter, FinalizedQueueReader) =
                queue::shared::init(
                    context.child("finalized_queue"),
                    queue::Config {
                        partition: "finalized-queue-scan-recovers-last-cursor".to_string(),
                        items_per_section: FINALIZED_QUEUE_ITEMS_PER_SECTION,
                        compression: None,
                        codec_config: super::QueuedFinalizedUploadCfg::default(),
                        page_cache,
                        write_buffer: FINALIZED_QUEUE_WRITE_BUFFER,
                    },
                )
                .await
                .expect("queue initializes");
            let first = queued_upload(1, 0, 2, 0, 2);
            let second = queued_upload(2, 2, 5, 2, 3);
            writer.enqueue(first.clone()).await.expect("enqueue first");
            writer
                .enqueue(second.clone())
                .await
                .expect("enqueue second");

            assert_eq!(
                scan_finalized_queue_cursor(&mut reader).await,
                Some(FinalizedUploadCursor::from_upload(&second))
            );

            let (_position, upload) = reader
                .try_recv()
                .await
                .expect("read after scan")
                .expect("scan reset leaves first item readable");
            assert_eq!(
                FinalizedUploadCursor::from_upload(&upload),
                FinalizedUploadCursor::from_upload(&first)
            );
        });
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
}
