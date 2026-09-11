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
use commonware_macros::boxed;
use commonware_p2p::{Ingress, Manager as _, TrackedPeers, authenticated::discovery};
use commonware_parallel::Rayon;
use commonware_runtime::{
    BufferPoolConfig, Quota, Runner as _, Strategizer as _, Supervisor as _,
    buffer::paged::CacheRef,
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
        StoreCommitMetrics,
        qmdb::{PublishError, QueuedFinalizedUpload, QueuedFinalizedUploadCfg},
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
    sync::Mutex,
    task::{JoinHandle, JoinSet},
};
use tracing::{info, warn};

const MEMPOOL_MAILBOX_SIZE: usize = 65_536;
const P2P_MESSAGES_PER_SECOND: NonZeroU32 = NZU32!(1024);

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
const MAX_FINALIZED_QUEUE_UPLOADS: usize = 64;
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
type EngineDatabases = DatabaseReaders<commonware_runtime::tokio::Context, Sha256, EightCap, Rayon>;
type EngineQueuedUpload = QueuedFinalizedUpload<Sha256, PublicKey>;
type FinalizedQueueWriter = queue::Writer<RuntimeContext, EngineQueuedUpload>;
type FinalizedQueueReader = queue::Reader<RuntimeContext, EngineQueuedUpload>;
type CursorMetadata = Metadata<RuntimeContext, U64, U64>;

struct FinalizedCursorStore {
    context: RuntimeContext,
    config: MetadataConfig<()>,
    metadata: Mutex<Option<CursorMetadata>>,
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
    uploaders: Vec<JoinHandle<()>>,
}

/// Connects the indexer publisher only when finalized data is ready to upload.
struct LazyPublisher {
    context: RuntimeContext,
    store_url: String,
    api_key: Option<String>,
    buffer: usize,
    commit_metrics: StoreCommitMetrics,
    publisher: Mutex<Option<Arc<EnginePublisher>>>,
}

impl LazyPublisher {
    fn new(
        context: RuntimeContext,
        store_url: String,
        api_key: Option<String>,
        buffer: usize,
    ) -> Self {
        // Registered once here: `connect` is retried on failure and must not
        // re-register.
        let commit_metrics = StoreCommitMetrics::new(&context);
        Self {
            context,
            store_url,
            api_key,
            buffer,
            commit_metrics,
            publisher: Mutex::new(None),
        }
    }

    async fn publisher(&self) -> Arc<EnginePublisher> {
        loop {
            if let Some(publisher) = self.publisher.lock().await.as_ref().cloned() {
                return publisher;
            }

            match EnginePublisher::connect(
                self.context.child("publisher"),
                &self.store_url,
                self.api_key.as_deref(),
                self.buffer,
                self.commit_metrics.clone(),
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
    fn covers(self, block: &EngineBlock<Sha256, PublicKey>) -> bool {
        self.state_next >= block.header.state_range.end()
            && self.transaction_next >= block.header.transactions_range.end()
    }

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
        block: Arc<EngineBlock<Sha256, PublicKey>>,
        databases: &EngineDatabases,
    ) {
        loop {
            let mut cursor = self.cursor.lock().await;

            // Capture can be durable before the database and marshal replay frontier.
            if cursor.covers(&block) {
                return;
            }
            let upload = match EnginePublisher::build_queued_finalized_upload(
                cursor.state_next,
                cursor.transaction_next,
                block.clone(),
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

            // A failed queue mutation consumes the shared handle. Restart to reopen it.
            let next = FinalizedUploadCursor::from_upload(&upload);
            let position = self
                .writer
                .enqueue(upload)
                .await
                .expect("failed to enqueue finalized index upload");
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
    }
}

async fn persist_finalized_cursor(store: &FinalizedCursorStore, cursor: FinalizedUploadCursor) {
    let mut metadata = store.metadata.lock().await;
    loop {
        // A failed sync consumes its handle. Reopen before retrying the same cursor.
        let mut current = match metadata.take() {
            Some(current) => current,
            None => {
                match Metadata::init(store.context.child("storage"), store.config.clone()).await {
                    Ok(current) => current,
                    Err(error) => {
                        warn!(error = %error, "failed to reopen finalized index cursor, retrying");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                }
            }
        };
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
        tokio::time::sleep(Duration::from_secs(1)).await;
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
                    .expect("failed to rewind finalized index queue");
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
) {
    let mut active = JoinSet::new();
    let mut reader_closed = false;
    let max_active = max_active.max(1);

    loop {
        while active.len() < max_active {
            let item = match reader.try_recv().await {
                Ok(item) => item,
                Err(error) => {
                    warn!(error = %error, "failed to read finalized index queue, retrying");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            let Some((position, upload)) = item else {
                break;
            };
            start_queued_upload(
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
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
            completed = active.join_next(), if !active.is_empty() => {
                let (position, height) = completed
                    .expect("active upload set is not empty")
                    .expect("finalized index upload task panicked");
                ack_finalized_queue_entry(&reader, &writer, position, height).await;
            }
        }

        if reader_closed && active.is_empty() {
            break;
        }
    }
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
    writer
        .sync()
        .await
        .expect("failed to sync finalized index queue acknowledgement");
}

#[boxed]
async fn start_queued_upload(
    active: &mut JoinSet<(u64, u64)>,
    publisher: Arc<LazyPublisher>,
    cert_reporter: EngineCertReporter,
    position: u64,
    upload: EngineQueuedUpload,
) {
    let height = upload.height();
    let block = upload.block();

    // Admission errors cannot recover against the same cached publisher.
    let engine_publisher = publisher.publisher().await;
    let completion = engine_publisher
        .enqueue_queued_finalized(upload)
        .await
        .expect("failed to admit finalized index upload");

    active.spawn(async move {
        assert!(
            completion.wait().await,
            "finalized uploader stopped before persistence"
        );
        cert_reporter.publish_block(block).await;
        (position, height)
    });
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

    info!(
        chain_indexer_url = %cfg.chain_indexer_url,
        "starting full indexer uploaders",
    );
    let (cert_reporter, cert_join) = EngineCertReporter::connect(
        &cfg.chain_indexer_url,
        cfg.api_key.as_deref(),
        cfg.upload_buffer,
        StoreCommitMetrics::new(&context.child("simplex_upload")),
    )?;
    let publisher = Arc::new(LazyPublisher::new(
        context.child("publisher"),
        cfg.chain_indexer_url,
        cfg.api_key,
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
    let metadata_context = context.child("finalized_cursor");
    let metadata_config = MetadataConfig {
        partition: format!("{partition_prefix}-finalized-index-cursor"),
        codec_config: (),
    };
    let mut metadata = Metadata::init(metadata_context.child("storage"), metadata_config.clone())
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
    let metadata = Arc::new(FinalizedCursorStore {
        context: metadata_context,
        config: metadata_config,
        metadata: Mutex::new(Some(metadata)),
    });
    let finalized_producer = FinalizedUploadProducer {
        writer: queue_writer.clone(),
        metadata,
        cursor: Arc::new(Mutex::new(cursor)),
        publisher: publisher.clone(),
    };
    let max_active_uploads = cfg.upload_buffer.clamp(1, MAX_FINALIZED_QUEUE_UPLOADS);
    let finalized_join = tokio::spawn(run_finalized_upload_consumer(
        publisher.clone(),
        cert_reporter.clone(),
        queue_writer,
        queue_reader,
        max_active_uploads,
    ));
    Ok(Some(IndexerHandle {
        cert_reporter,
        finalized_producer,
        uploaders: vec![cert_join, finalized_join],
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
                rate: commonware_utils::Probability::try_from(rate)
                    .expect("trace rate must be between zero and one"),
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

        let max_peers_per_set = commonware_p2p::authenticated::peer_set_limit(
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

        // The burst size also bounds each retained peer's mailbox allocation.
        let quota = Quota::per_second(P2P_MESSAGES_PER_SECOND);
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
        let indexer_handle = maybe_build_indexer(
            context.child("indexer"),
            is_primary,
            indexer,
            &indexer_partition_prefix,
        )
        .await
        .expect("failed to configure indexer Store client");
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
            indexer_handle
                .map(|handle| handle.uploaders)
                .unwrap_or_default(),
            engine_handle,
            mempool_handle,
            network_handle,
        )
        .await;
    });
}

type CriticalTask = Pin<Box<dyn Future<Output = ()> + Send>>;

async fn wait_for_critical_task_exit<E, M, N>(
    probe_handle: Option<CriticalTask>,
    uploaders: Vec<JoinHandle<()>>,
    engine_handle: E,
    mempool_handle: M,
    network_handle: N,
) where
    E: Future,
    M: Future,
    N: Future,
{
    let mut probe_handle = probe_handle.unwrap_or_else(|| Box::pin(std::future::pending()));
    let uploader_exit = async move {
        if uploaders.is_empty() {
            std::future::pending::<()>().await;
        }
        let (result, index, _) = futures::future::select_all(uploaders).await;
        panic!("indexer uploader {index} exited unexpectedly with {result:?}");
    };
    tokio::select! {
        _ = probe_handle.as_mut() => tracing::warn!("probe exited"),
        _ = uploader_exit => unreachable!("uploader exit panics"),
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
        EngineQueuedUpload, FINALIZED_QUEUE_ITEMS_PER_SECTION, FINALIZED_QUEUE_PAGE_CACHE_CAPACITY,
        FINALIZED_QUEUE_PAGE_SIZE, FINALIZED_QUEUE_WRITE_BUFFER, FinalizedQueueReader,
        FinalizedQueueWriter, FinalizedUploadCursor, StoreClientBuildError,
        default_mempool_drop_grace_blocks, maybe_build_indexer, recovered_finalized_upload_cursor,
        scan_finalized_queue_cursor, wait_for_critical_task_exit,
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
    use commonware_runtime::{Runner as _, Supervisor as _};
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

    #[test]
    fn p2p_channel_registration_has_bounded_capacity() {
        let quota = commonware_runtime::Quota::per_second(super::P2P_MESSAGES_PER_SECOND);
        let retained_peers = 4 * 5;
        let capacity = retained_peers * u64::from(quota.burst_size().get());
        assert!(capacity <= 65_536, "per-channel capacity is {capacity}");

        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let signer = PrivateKey::from_seed(0);
            let participants: Vec<_> = (0..5)
                .map(|seed| PrivateKey::from_seed(seed).public_key())
                .collect();
            let max_peers = commonware_p2p::authenticated::peer_set_limit(
                participants.iter(),
                &signer.public_key(),
            );
            let listen = "127.0.0.1:0".parse().expect("listen address");
            let config = commonware_p2p::authenticated::discovery::Config::local(
                signer,
                b"constantinople",
                listen,
                commonware_p2p::Ingress::Socket(listen),
                Vec::new(),
                max_peers,
                32 * 1024 * 1024,
            );
            let (mut network, _) =
                commonware_p2p::authenticated::discovery::Network::new(context, config);
            for channel in constantinople_engine::CHANNELS {
                let _ = network.register(channel, quota);
            }
        });
    }

    #[tokio::test]
    async fn completed_setup_task_is_not_a_runtime_exit_condition() {
        let setup_task = tokio::spawn(async {});
        setup_task.await.expect("setup task should complete");

        let result = tokio::time::timeout(
            Duration::from_millis(10),
            wait_for_critical_task_exit(
                None,
                Vec::new(),
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
    async fn any_uploader_exit_is_fatal() {
        for index in 0..2 {
            for failure in 0..3 {
                let mut uploaders =
                    vec![tokio::spawn(pending::<()>()), tokio::spawn(pending::<()>())];
                uploaders[index].abort();
                uploaders[index] = tokio::spawn(async move {
                    match failure {
                        0 => {}
                        1 => panic!("injected uploader failure"),
                        _ => pending::<()>().await,
                    }
                });
                if failure == 2 {
                    uploaders[index].abort();
                }
                let supervisor = tokio::spawn(wait_for_critical_task_exit(
                    None,
                    uploaders,
                    pending::<()>(),
                    pending::<()>(),
                    pending::<()>(),
                ));
                let error = tokio::time::timeout(Duration::from_secs(1), supervisor)
                    .await
                    .expect("uploader exit must reach supervision")
                    .expect_err("uploader exit must fail the validator");
                assert!(error.is_panic());
            }
        }
    }

    #[test]
    fn cancelled_upload_fails_supervision_without_acknowledgement() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (store, url) = exoware_simulator::open_temp().await.expect("Store starts");
            let publisher = std::sync::Arc::new(super::LazyPublisher::new(
                context.child("publisher"),
                url.clone(),
                None,
                1,
            ));
            let connected = publisher.publisher().await;

            // Prevent persistence from completing before worker cancellation.
            store.abort();
            let _ = store.await;
            let (reporter, certificate_uploader) = super::EngineCertReporter::connect(
                &url,
                None,
                1,
                super::StoreCommitMetrics::new(&context.child("certificates")),
            )
            .expect("reporter builds");
            let config = queue::Config {
                partition: "cancelled-finalized-upload".to_string(),
                items_per_section: FINALIZED_QUEUE_ITEMS_PER_SECTION,
                compression: None,
                codec_config: super::QueuedFinalizedUploadCfg::default(),
                page_cache: commonware_runtime::buffer::paged::CacheRef::from_pooler(
                    &context,
                    FINALIZED_QUEUE_PAGE_SIZE,
                    FINALIZED_QUEUE_PAGE_CACHE_CAPACITY,
                ),
                write_buffer: FINALIZED_QUEUE_WRITE_BUFFER,
            };
            let (writer, reader) = queue::shared::init(context.child("queue"), config.clone())
                .await
                .expect("queue opens");
            writer
                .enqueue(queued_upload(1, 0, 1, 0, 2))
                .await
                .expect("capture is durable");
            let consumer = tokio::spawn(super::run_finalized_upload_consumer(
                publisher.clone(),
                reporter,
                writer,
                reader,
                1,
            ));
            let supervisor = tokio::spawn(wait_for_critical_task_exit(
                None,
                vec![consumer],
                pending::<()>(),
                pending::<()>(),
                pending::<()>(),
            ));
            tokio::time::timeout(Duration::from_secs(2), async {
                while connected.next_locations().await != (1, 2) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("upload is admitted");

            // Dropping the last Publisher aborts its workers and cancels completion.
            drop(publisher.publisher.lock().await.take());
            drop(connected);
            let error = tokio::time::timeout(Duration::from_secs(2), supervisor)
                .await
                .expect("cancelled completion must reach supervision")
                .expect_err("supervision must fail the validator");
            assert!(error.is_panic());
            tokio::time::timeout(Duration::from_secs(2), certificate_uploader)
                .await
                .expect("no certificate upload may be waiting on the stopped Store")
                .expect("certificate uploader exits without publication");

            let (_writer, mut reader) = queue::shared::init::<_, EngineQueuedUpload>(
                context.child("reopened_queue"),
                config,
            )
            .await
            .expect("queue reopens");
            let (_, upload) = reader
                .try_recv()
                .await
                .expect("queue reads")
                .expect("failed upload remains unacknowledged");
            assert_eq!(upload.height(), 1);
        });
    }

    #[test]
    fn publisher_does_not_block_secondary_startup_on_connect_failure() {
        let runner =
            commonware_runtime::tokio::Runner::new(commonware_runtime::tokio::Config::default());
        runner.start(|context| async move {
            let indexer = IndexerConfig {
                chain_indexer_url: "http://127.0.0.1:1".to_string(),
                api_key: None,
                upload_buffer: 1,
            };

            let handle = tokio::time::timeout(
                Duration::from_secs(2),
                maybe_build_indexer(context, false, Some(indexer), "test"),
            )
            .await
            .expect("publisher connection should not block startup")
            .expect("indexer Store client should build")
            .expect("secondary should keep indexer wiring");

            assert_eq!(handle.uploaders.len(), 2);
        });
    }

    #[test]
    fn invalid_indexer_api_key_fails_secondary_startup() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let indexer = IndexerConfig {
                chain_indexer_url: "http://127.0.0.1:1".to_string(),
                api_key: Some("invalid\nkey".to_string()),
                upload_buffer: 1,
            };
            let error = maybe_build_indexer(context, false, Some(indexer), "test")
                .await
                .err()
                .expect("invalid API key should fail startup");

            assert!(matches!(error, StoreClientBuildError::InvalidApiKey));
        });
    }

    #[test]
    fn finalized_cursor_reopens_and_persists_both_positions() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let store = super::FinalizedCursorStore {
                context,
                config: commonware_storage::metadata::Config {
                    partition: "cursor-reopen-test".to_string(),
                    codec_config: (),
                },
                metadata: tokio::sync::Mutex::new(None),
            };
            let first = FinalizedUploadCursor {
                state_next: 7,
                transaction_next: 9,
            };
            super::persist_finalized_cursor(&store, first).await;
            let current = store
                .metadata
                .lock()
                .await
                .take()
                .expect("cursor should exist");
            assert_eq!(FinalizedUploadCursor::from_metadata(&current), Some(first));
            drop(current);

            let second = FinalizedUploadCursor {
                state_next: 11,
                transaction_next: 15,
            };
            super::persist_finalized_cursor(&store, second).await;
            drop(store.metadata.lock().await.take());
            let reopened =
                super::CursorMetadata::init(store.context.child("storage"), store.config)
                    .await
                    .expect("cursor should reopen");
            assert_eq!(
                FinalizedUploadCursor::from_metadata(&reopened),
                Some(second)
            );
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
    fn recovered_capture_covers_replayed_prefix_only_when_both_frontiers_match() {
        let first = queued_upload(1, 0, 2, 0, 2);
        let second = queued_upload(2, 2, 5, 2, 3);
        let next = queued_upload(3, 5, 7, 3, 4);
        let cursor = recovered_finalized_upload_cursor(
            Some(FinalizedUploadCursor::from_upload(&second)),
            None,
        );
        assert!(cursor.covers(&first.block()));
        assert!(cursor.covers(&second.block()));
        assert!(!cursor.covers(&next.block()));
        assert!(
            !FinalizedUploadCursor {
                state_next: 5,
                transaction_next: 2
            }
            .covers(&second.block())
        );
        assert!(
            !FinalizedUploadCursor {
                state_next: 2,
                transaction_next: 3
            }
            .covers(&second.block())
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
    fn failed_queue_mutations_require_reopening_shared_handles() {
        for fail_enqueue in [true, false] {
            commonware_runtime::deterministic::Runner::default().start(|context| async move {
                let page_cache = commonware_runtime::buffer::paged::CacheRef::from_pooler(
                    &context,
                    FINALIZED_QUEUE_PAGE_SIZE,
                    FINALIZED_QUEUE_PAGE_CACHE_CAPACITY,
                );
                let config = queue::Config {
                    partition: "failed-finalized-queue".to_string(),
                    items_per_section: FINALIZED_QUEUE_ITEMS_PER_SECTION,
                    compression: None,
                    codec_config: super::QueuedFinalizedUploadCfg::default(),
                    page_cache,
                    write_buffer: FINALIZED_QUEUE_WRITE_BUFFER,
                };
                let (writer, mut reader) =
                    queue::shared::init(context.child("queue"), config.clone())
                        .await
                        .expect("queue opens");
                writer
                    .enqueue(queued_upload(1, 0, 2, 0, 2))
                    .await
                    .expect("first capture is durable");
                let faults = context.storage_fault_config();
                faults.write().sync_rate = Some(commonware_utils::probability!(1.0));
                let result = if fail_enqueue {
                    writer
                        .enqueue(queued_upload(2, 2, 5, 2, 3))
                        .await
                        .map(|_| ())
                } else {
                    writer.sync().await
                };
                assert!(result.is_err());
                faults.write().sync_rate = None;
                assert!(matches!(
                    writer.sync().await,
                    Err(commonware_storage::queue::Error::Unavailable)
                ));
                assert!(matches!(
                    reader.try_recv().await,
                    Err(commonware_storage::queue::Error::Unavailable)
                ));
                drop(writer);
                drop(reader);

                let (writer, mut reader) = queue::shared::init::<_, EngineQueuedUpload>(
                    context.child("reopened_queue"),
                    config,
                )
                .await
                .expect("queue reopens after storage recovers");
                let (_, upload) = reader
                    .try_recv()
                    .await
                    .expect("read succeeds")
                    .expect("durable capture survives");
                assert_eq!(upload.height(), 1);
                writer.sync().await.expect("replacement handle works");
            });
        }
    }

    #[test]
    fn finalized_queue_scan_recovers_last_cursor_and_resets_reader() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
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
