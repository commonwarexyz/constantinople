//! Starts a validator from a YAML config.

use crate::{
    config::{
        IndexerConfig, LoadedConfig, StartupModeConfig, load_deployer_config, load_local_config,
    },
    state_reader::StateDbReader,
};
use commonware_actor::Feedback;
use commonware_codec::{Encode, RangeCfg};
use commonware_consensus::{
    Heightable as _, Reporter, Reporters,
    marshal::Update,
    simplex::elector::RoundRobin,
    types::{Epoch, coding::Commitment},
};
use commonware_cryptography::{
    Digestible as _, PublicKey as CryptographicPublicKey,
    bls12381::primitives::variant::MinSig,
    ed25519::{self, Batch, PublicKey},
    sha256::Sha256,
};
use commonware_formatting::hex;
use commonware_glue::{
    dkg::{
        network::Addresses,
        types::{EpochInfo, EpochOutcome, Payload},
    },
    stateful::{PruneConfig, db::SyncEngineConfig},
};
use commonware_macros::boxed;
use commonware_p2p::{
    Address, AddressableManager, AddressableTrackedPeers, Ingress, PeerSetSubscription, Provider,
    TrackedPeers, authenticated::lookup,
};
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
    Acknowledgement as _, NZU16, NZU32, NZU64, NZUsize, TryCollect,
    acknowledgement::Exact,
    ordered::{Map, Set},
    sequence::U64,
};
use constantinople_application::consensus::{Databases, FinalizedHookFn};
use constantinople_engine::{
    CERTIFICATE_CHANNEL, COMMITTEE_RESOLVER_CHANNEL, Channels, Config as EngineConfig, DKG_CHANNEL,
    DKG_PROBE_CHANNEL, EPOCH_LENGTH, Engine, MARSHAL_CHANNEL, MARSHAL_RESOLVER_CHANNEL,
    MAX_PENDING_ACKS, RESOLVER_CHANNEL, STATE_RESOLVER_CHANNEL, StartupMode,
    TRANSACTION_RESOLVER_CHANNEL, ThresholdScheme, VOTE_CHANNEL,
    secret_store::FileSecretStore,
    types::{EngineBlock, EngineMarshalMailbox},
};
use constantinople_indexer::{
    CertificateReporter, EligiblePeer as IndexedEligiblePeer, Publisher,
    publisher::{
        StoreCommitMetrics,
        qmdb::{PublishError, QueuedFinalizedUpload, QueuedFinalizedUploadCfg},
    },
};
use constantinople_mempool::webserver::{self, AccountReader, Mailbox};
use constantinople_primitives::{
    Block as ChainBlock, Header as ChainHeader, PublicKeyCache, Sealable as _, SealedBlock,
};
use std::{
    fmt,
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
const DKG_NAMESPACE: &[u8] = b"_CONSTANTINOPLE_DKG";
// Leave room for block headers and DKG payloads when the transaction budget is tiny.
const SHARD_SIZE_FLOOR: usize = 1024 * 1024;

const STATE_SYNC_APPLY_BATCH_SIZE: usize = 1024;
const PRUNE_CONFIG: PruneConfig = PruneConfig {
    max_pending_acks: MAX_PENDING_ACKS,
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
const CURSOR_COMMITTEE_KEY: U64 = U64::new(2);

/// Keeps explicitly configured service nodes available as network-policy
/// secondaries without changing the epoch IDs registered by DKG.
#[derive(Clone)]
struct BootstrapSecondaries<M>
where
    M: AddressableManager,
{
    inner: M,
    persistent: Map<M::PublicKey, Address>,
}

impl<M> BootstrapSecondaries<M>
where
    M: AddressableManager,
{
    const fn new(inner: M, persistent: Map<M::PublicKey, Address>) -> Self {
        Self { inner, persistent }
    }
}

impl<M> fmt::Debug for BootstrapSecondaries<M>
where
    M: AddressableManager,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BootstrapSecondaries")
            .field("persistent", &self.persistent.len())
            .finish_non_exhaustive()
    }
}

impl<M> Provider for BootstrapSecondaries<M>
where
    M: AddressableManager,
{
    type PublicKey = M::PublicKey;

    fn peer_set(
        &mut self,
        id: u64,
    ) -> impl Future<Output = Option<TrackedPeers<Self::PublicKey>>> + Send {
        self.inner.peer_set(id)
    }

    fn subscribe(&mut self) -> impl Future<Output = PeerSetSubscription<Self::PublicKey>> + Send {
        self.inner.subscribe()
    }
}

impl<M> AddressableManager for BootstrapSecondaries<M>
where
    M: AddressableManager,
{
    fn track<R>(&mut self, id: u64, peers: R) -> Feedback
    where
        R: Into<AddressableTrackedPeers<Self::PublicKey>> + Send,
    {
        self.inner.track(
            id,
            add_persistent_secondaries(peers.into(), &self.persistent),
        )
    }

    fn overwrite(&mut self, peers: Map<Self::PublicKey, Address>) -> Feedback {
        self.inner.overwrite(peers)
    }
}

fn add_persistent_secondaries<P: CryptographicPublicKey>(
    peers: AddressableTrackedPeers<P>,
    persistent: &Map<P, Address>,
) -> AddressableTrackedPeers<P> {
    let secondary = Map::from_iter_dedup(
        peers
            .secondary
            .iter_pairs()
            .chain(persistent.iter_pairs())
            .filter(|(peer, _)| peers.primary.get_value(peer).is_none())
            .map(|(peer, address)| (peer.clone(), address.clone())),
    );
    AddressableTrackedPeers::new(peers.primary, secondary)
}

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

type EngineCertReporter =
    CertificateReporter<Sha256, ed25519::PrivateKey, MinSig, ThresholdScheme<PublicKey, MinSig>>;
type EnginePublisher = Publisher<Sha256, ed25519::PrivateKey, MinSig>;
type EngineDatabases = Databases<commonware_runtime::tokio::Context, Sha256, EightCap, Rayon>;
type ValidatorPayload = Payload<MinSig, ed25519::PrivateKey, Addresses<PublicKey>>;
type ValidatorEngineBlock = EngineBlock<Sha256, ed25519::PrivateKey, MinSig>;
type ValidatorMarshalMailbox = EngineMarshalMailbox<Sha256, ed25519::PrivateKey, MinSig>;
type EngineFinalizedHook = FinalizedHookFn<
    commonware_runtime::tokio::Context,
    Commitment,
    Sha256,
    PublicKey,
    ValidatorPayload,
    Rayon,
>;
type EngineQueuedUpload = QueuedFinalizedUpload<Sha256, ed25519::PrivateKey, MinSig>;
type FinalizedQueueWriter = queue::Writer<RuntimeContext, EngineQueuedUpload>;
type FinalizedQueueReader = queue::Reader<RuntimeContext, EngineQueuedUpload>;
type CursorMetadata<E = RuntimeContext> = Metadata<E, U64, U64>;

/// Logs every finalized block delivered by marshal.
///
/// This mirrors Commonware's `examples/reshare` reporter and participates in
/// the native acknowledgement tree so logging never holds back pruning.
#[derive(Clone)]
struct FinalizedBlockLogger;

impl Reporter for FinalizedBlockLogger {
    type Activity = Update<ValidatorEngineBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Update::Block(block, acknowledgement) = activity {
            info!(
                epoch = block.header.context.round.epoch().get(),
                height = block.height().get(),
                digest = %hex(&block.digest()),
                "finalized block"
            );
            acknowledgement.acknowledge();
        }
        Feedback::Ok
    }
}

/// Adapts ordered marshal block updates to the certificate stream consumed by
/// the indexer. The engine itself only sees this as a native marshal reporter.
#[derive(Clone)]
struct IndexerReporter {
    sender: tokio::sync::mpsc::UnboundedSender<(Arc<ValidatorEngineBlock>, Exact)>,
}

impl IndexerReporter {
    fn new(
        marshal: ValidatorMarshalMailbox,
        reporter: EngineCertReporter,
    ) -> (Self, JoinHandle<()>) {
        let (sender, mut receiver) =
            tokio::sync::mpsc::unbounded_channel::<(Arc<ValidatorEngineBlock>, Exact)>();
        let handle = tokio::spawn(async move {
            while let Some((block, acknowledgement)) = receiver.recv().await {
                let height = block.height();
                let finalization = marshal
                    .get_finalization(height)
                    .await
                    .unwrap_or_else(|| panic!("marshal finalization missing at height {height}"));
                if !reporter.publish_finalization(finalization).await {
                    break;
                }
                acknowledgement.acknowledge();
            }
        });
        (Self { sender }, handle)
    }
}

impl Reporter for IndexerReporter {
    type Activity = Update<ValidatorEngineBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let Update::Block(block, acknowledgement) = activity else {
            return Feedback::Ok;
        };
        // Marshal reports the trusted genesis block to applications, but
        // genesis has no Simplex finalization certificate to publish.
        if block.height().get() == 0 {
            acknowledgement.acknowledge();
            return Feedback::Ok;
        }
        if self.sender.send((block, acknowledgement)).is_ok() {
            Feedback::Ok
        } else {
            Feedback::Closed
        }
    }
}

/// Adapts payload-bearing engine blocks to the execution-only block view used
/// by the mempool's finalized-batch tracker.
#[derive(Clone)]
struct MempoolReporter(Mailbox<Commitment, PublicKey, Sha256>);

impl Reporter for MempoolReporter {
    type Activity = Update<ValidatorEngineBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let activity = match activity {
            Update::Tip(round, height, digest) => Update::Tip(round, height, digest),
            Update::Block(block, acknowledgement) => {
                let header = ChainHeader {
                    context: block.header.context.clone(),
                    parent: block.header.parent,
                    height: block.header.height,
                    timestamp: block.header.timestamp,
                    eligible_peers_root: block.header.eligible_peers_root,
                    state_root: block.header.state_root,
                    state_range: block.header.state_range.clone(),
                    transactions_root: block.header.transactions_root,
                    transactions_range: block.header.transactions_range.clone(),
                    committee_root: block.header.committee_root,
                    committee_range: block.header.committee_range.clone(),
                    payload: None,
                };
                let block: SealedBlock<Commitment, PublicKey, Sha256> = ChainBlock {
                    header,
                    body: block.body.clone(),
                }
                .seal(&mut Sha256::default());
                Update::Block(Arc::new(block), acknowledgement)
            }
        };
        self.0.report(activity)
    }
}

/// Bundle of indexer state that needs to outlive engine startup.
struct IndexerHandle {
    cert_reporter: EngineCertReporter,
    publisher: Arc<LazyPublisher>,
    finalized_producer: FinalizedUploadProducer,
    /// Kept alive so the uploader tasks are not aborted while the validator runs.
    _uploaders: Vec<JoinHandle<()>>,
}

/// Connects the indexer publisher only when finalized data is ready to upload.
struct LazyPublisher {
    context: RuntimeContext,
    store_url: String,
    buffer: usize,
    commit_metrics: StoreCommitMetrics,
    eligible_peers: Arc<[IndexedEligiblePeer]>,
    publisher: Mutex<Option<Arc<EnginePublisher>>>,
}

impl LazyPublisher {
    fn new(
        context: RuntimeContext,
        store_url: String,
        buffer: usize,
        eligible_peers: Arc<[IndexedEligiblePeer]>,
    ) -> Self {
        // Registered once here: `connect` is retried on failure and must not
        // re-register.
        let commit_metrics = StoreCommitMetrics::new(&context);
        Self {
            context,
            store_url,
            buffer,
            commit_metrics,
            eligible_peers,
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
                self.buffer,
                self.commit_metrics.clone(),
                self.eligible_peers.clone(),
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
    metadata: Arc<Mutex<Option<CursorMetadata>>>,
    metadata_partition: Arc<str>,
    cursor: Arc<Mutex<FinalizedUploadCursor>>,
    publisher: Arc<LazyPublisher>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct FinalizedUploadCursor {
    state_next: u64,
    transaction_next: u64,
    committee_next: u64,
}

impl FinalizedUploadCursor {
    fn from_metadata<E>(metadata: &CursorMetadata<E>) -> Option<Self>
    where
        E: commonware_storage::Context,
    {
        let state_next = metadata.get(&CURSOR_STATE_KEY).cloned().map(u64::from);
        let transaction_next = metadata
            .get(&CURSOR_TRANSACTION_KEY)
            .cloned()
            .map(u64::from);
        let committee_next = metadata.get(&CURSOR_COMMITTEE_KEY).cloned().map(u64::from);
        Self::from_parts(state_next, transaction_next, committee_next)
    }

    const fn from_parts(
        state_next: Option<u64>,
        transaction_next: Option<u64>,
        committee_next: Option<u64>,
    ) -> Option<Self> {
        match (state_next, transaction_next, committee_next) {
            (Some(state_next), Some(transaction_next), Some(committee_next)) => Some(Self {
                state_next,
                transaction_next,
                committee_next,
            }),
            _ => None,
        }
    }

    fn from_upload(upload: &EngineQueuedUpload) -> Self {
        Self {
            state_next: upload.state_end(),
            transaction_next: upload.transaction_end(),
            committee_next: upload.committee_end(),
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
                && (other.transaction_next > self.transaction_next
                    || (other.transaction_next == self.transaction_next
                        && other.committee_next > self.committee_next)))
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
        block: &ValidatorEngineBlock,
        databases: &EngineDatabases,
    ) {
        loop {
            let mut cursor = self.cursor.lock().await;
            let upload = match EnginePublisher::build_queued_finalized_upload_with_context(
                context.child("build"),
                cursor.state_next,
                cursor.transaction_next,
                cursor.committee_next,
                block,
                databases,
            )
            .await
            {
                Ok(upload) => upload,
                Err(PublishError::StoreEmptyPastGenesis { .. }) if cursor.state_next == 0 => {
                    let publisher = self.publisher.publisher().await;
                    let (state_next, transaction_next, committee_next) =
                        publisher.next_locations().await;
                    if state_next == 0 && transaction_next == 0 && committee_next == 0 {
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
                        committee_next,
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
            match self.writer.enqueue(upload).await {
                Ok(position) => {
                    persist_finalized_cursor(
                        self.publisher.context.child("finalized_cursor_retry"),
                        &self.metadata_partition,
                        &self.metadata,
                        next,
                    )
                    .await;
                    *cursor = next;
                    info!(
                        height = block.header.height,
                        position,
                        state_next = next.state_next,
                        transaction_next = next.transaction_next,
                        committee_next = next.committee_next,
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

async fn persist_finalized_cursor<E>(
    context: E,
    partition: &str,
    metadata: &Arc<Mutex<Option<CursorMetadata<E>>>>,
    cursor: FinalizedUploadCursor,
) where
    E: commonware_storage::Context,
{
    loop {
        let mut slot = metadata.lock().await;
        let mut store = match slot.take() {
            Some(store) => store,
            None => match Metadata::init(
                context.child("reopen"),
                MetadataConfig {
                    partition: partition.to_string(),
                    codec_config: (),
                },
            )
            .await
            {
                Ok(store) => store,
                Err(error) => {
                    warn!(
                        error = %error,
                        cursor.state_next,
                        cursor.transaction_next,
                        cursor.committee_next,
                        "failed to reopen finalized index cursor, retrying",
                    );
                    drop(slot);
                    context.sleep(Duration::from_secs(1)).await;
                    continue;
                }
            },
        };
        store.put(CURSOR_STATE_KEY, U64::new(cursor.state_next));
        store.put(CURSOR_TRANSACTION_KEY, U64::new(cursor.transaction_next));
        store.put(CURSOR_COMMITTEE_KEY, U64::new(cursor.committee_next));

        match store.sync().await {
            Ok(store) => {
                *slot = Some(store);
                return;
            }
            Err(error) => {
                warn!(
                    error = %error,
                    cursor.state_next,
                    cursor.transaction_next,
                    cursor.committee_next,
                    "failed to persist finalized index cursor, retrying",
                );
            }
        }
        drop(slot);
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

#[boxed]
async fn start_queued_upload(
    active: &mut JoinSet<(u64, u64)>,
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
            Err(error) => {
                warn!(
                    height,
                    position,
                    error = %error,
                    "failed to start finalized index upload, retrying",
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    };

    active.spawn(async move {
        if completion.wait().await {
            cert_reporter.publish_block(upload.block()).await;
            return (position, height);
        }
        warn!(
            height,
            position, "finalized index uploader stopped after accepting upload",
        );
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}

/// Build the indexer wiring when this genesis-secondary opted in.
///
/// The peer metadata seeded here is the genesis/bootstrap directory. Future
/// committee membership and p2p addresses come from finalized snapshots.
async fn maybe_build_indexer(
    context: RuntimeContext,
    indexer: Option<IndexerConfig>,
    partition_prefix: &str,
    eligible_peers: &Map<ed25519::PublicKey, Address>,
) -> Option<IndexerHandle> {
    let cfg = indexer?;

    info!(
        chain_indexer_url = %cfg.chain_indexer_url,
        "starting full indexer uploaders",
    );
    let (cert_reporter, cert_join) = EngineCertReporter::connect(
        &cfg.chain_indexer_url,
        cfg.upload_buffer,
        StoreCommitMetrics::new(&context.child("simplex_upload")),
    );
    let publisher = Arc::new(LazyPublisher::new(
        context.child("publisher"),
        cfg.chain_indexer_url,
        cfg.upload_buffer,
        indexed_eligible_peers(eligible_peers),
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
    let metadata_partition: Arc<str> = format!("{partition_prefix}-finalized-index-cursor").into();
    let mut metadata = Metadata::init(
        context.child("finalized_cursor"),
        MetadataConfig {
            partition: metadata_partition.to_string(),
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
        metadata.put(CURSOR_COMMITTEE_KEY, U64::new(cursor.committee_next));
        metadata = metadata
            .sync()
            .await
            .expect("failed to persist finalized index cursor");
    }
    let metadata = Arc::new(Mutex::new(Some(metadata)));
    let finalized_producer = FinalizedUploadProducer {
        writer: queue_writer.clone(),
        metadata,
        metadata_partition,
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
    Some(IndexerHandle {
        cert_reporter,
        publisher,
        finalized_producer,
        _uploaders: vec![cert_join, finalized_join],
    })
}

fn indexed_eligible_peers(
    eligible_peers: &Map<ed25519::PublicKey, Address>,
) -> Arc<[IndexedEligiblePeer]> {
    eligible_peers
        .iter_pairs()
        .map(|(public_key, address)| {
            let encoded = public_key.encode();
            IndexedEligiblePeer {
                public_key: encoded
                    .as_ref()
                    .try_into()
                    .expect("Ed25519 public key has fixed width"),
                address: match address.ingress() {
                    Ingress::Socket(address) => address.to_string(),
                    Ingress::Dns { host, port } => format!("{host}:{port}"),
                },
            }
        })
        .collect::<Vec<_>>()
        .into()
}

fn indexer_finalized_hook(indexer: Option<&IndexerHandle>) -> Option<EngineFinalizedHook> {
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
    let secret_store_dir = storage_dir.join("dkg-secrets");
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
            secondary_participants = decoded.secondary_participants.len(),
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

        let p2p_config = if deployer_managed {
            lookup::Config::recommended(
                decoded.signer.clone(),
                b"constantinople",
                decoded.listen_bind,
                32 * 1024 * 1024,
            )
        } else {
            lookup::Config::local(
                decoded.signer.clone(),
                b"constantinople",
                decoded.listen_bind,
                32 * 1024 * 1024,
            )
        };

        let (mut network, oracle) = lookup::Network::new(context.child("p2p"), p2p_config);

        let mempool_drop_grace_blocks =
            default_mempool_drop_grace_blocks(decoded.primary_participants.len());
        let primary: Set<ed25519::PublicKey> = decoded
            .primary_participants
            .iter()
            .cloned()
            .try_collect()
            .unwrap();
        assert_eq!(
            &primary,
            decoded.dkg_output.players(),
            "configured primary validators must match the epoch-zero DKG output",
        );
        let primary_addresses = Map::from_iter_dedup(primary.iter().map(|peer| {
            let address = decoded
                .eligible_peers
                .get_value(peer)
                .expect("primary participant missing eligible address")
                .clone();
            (peer.clone(), address)
        }));
        let genesis = EpochInfo {
            outcome: EpochOutcome::Success,
            epoch: Epoch::zero(),
            output: decoded.dkg_output.clone(),
            players: primary.clone(),
            next_players: primary.clone(),
            directory: Addresses::from(primary_addresses),
        };

        // TODO: Add reasonable RL
        let quota = Quota::per_second(std::num::NonZeroU32::MAX);
        let backlog = 1024;
        let channels = Channels {
            votes: network.register(VOTE_CHANNEL, quota, backlog),
            certificates: network.register(CERTIFICATE_CHANNEL, quota, backlog),
            resolver: network.register(RESOLVER_CHANNEL, quota, backlog),
            marshal: network.register(MARSHAL_CHANNEL, quota, backlog),
            marshal_resolver: network.register(MARSHAL_RESOLVER_CHANNEL, quota, backlog),
            state_resolver: network.register(STATE_RESOLVER_CHANNEL, quota, backlog),
            transaction_resolver: network.register(TRANSACTION_RESOLVER_CHANNEL, quota, backlog),
            committee_resolver: network.register(COMMITTEE_RESOLVER_CHANNEL, quota, backlog),
            dkg: network.register(DKG_CHANNEL, quota, backlog),
        };
        let dkg_probe_network = network.register(DKG_PROBE_CHANNEL, quota, backlog);
        let network_handle = network.start();

        let relayer_view = relayer
            .as_ref()
            .map(|_| crate::relayer::Observer::new(&primary));
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
        let mempool_listener = if relayer.is_some() {
            // The relayer owns the public port. Its own catalog entry is
            // rewritten below to this private listener, avoiding a forwarding
            // loop when this validator joins the active committee.
            tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("failed to bind internal mempool listener")
        } else {
            tokio::net::TcpListener::bind(http_listen)
                .await
                .expect("failed to bind mempool HTTP listener")
        };
        let mempool_listen = mempool_listener
            .local_addr()
            .expect("mempool listener must have a local address");
        if relayer.is_none() {
            info!(%http_listen, "mempool webserver listening");
        }
        let mempool_actor_handle = mempool_actor.start(mempool_listener);
        let mempool_handle = async move {
            let _ = mempool_actor_handle.await;
        };
        let role_http_handle: Pin<Box<dyn Future<Output = ()> + Send>> =
            if let Some(mut relayer_config) = relayer.clone() {
                let view_clock = relayer_view_clock.expect("relayer view clock exists");
                let local_key = hex(&decoded.public_key.encode());
                let local = relayer_config
                    .leaders
                    .iter_mut()
                    .find(|leader| leader.public_key == local_key)
                    .expect("relayer leader catalog must include the local validator");
                local.url = format!("http://{mempool_listen}");
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

        // FileSecretStore persists plaintext threshold material with restrictive
        // local permissions. This is explicit bootstrap wiring, not production-
        // grade secret management; deployments requiring encryption, rotation,
        // or hardware isolation must replace it before handling real value.
        let secret_store = FileSecretStore::load(secret_store_dir)
            .expect("failed to initialize validator-local DKG secret store");

        // Build indexer wiring from the genesis/bootstrap metadata up-front.
        // Config loading rejects indexer wiring on genesis primaries, so the
        // uploader can never start as part of the epoch-zero committee.
        let indexer_partition_prefix = decoded.partition_prefix.clone();
        let mut indexer_handle = maybe_build_indexer(
            context.child("indexer"),
            indexer,
            &indexer_partition_prefix,
            &decoded.eligible_peers,
        )
        .await;
        let finalized_hook = indexer_finalized_hook(indexer_handle.as_ref());
        let persistent_secondaries =
            Map::from_iter_dedup(decoded.secondary_participants.iter().map(|peer| {
                let address = decoded
                    .eligible_peers
                    .get_value(peer)
                    .expect("bootstrap secondary missing eligible address")
                    .clone();
                (peer.clone(), address)
            }));
        let engine_manager = BootstrapSecondaries::new(oracle.clone(), persistent_secondaries);

        info!("initializing engine");
        let engine =
            Engine::<_, _, _, _, Sha256, MinSig, RoundRobin<Sha256>, Rayon, _, Batch>::new(
                context.child("engine"),
                EngineConfig {
                    signer: decoded.signer,
                    manager: engine_manager,
                    blocker: oracle,
                    namespace: b"constantinople".to_vec(),
                    output: decoded.dkg_output,
                    share: decoded.share,
                    genesis,
                    eligible_peers: decoded.eligible_peers.clone(),
                    secret_store,
                    dkg_namespace: DKG_NAMESPACE,
                    input: mempool_mailbox.clone(),
                    partition_prefix: decoded.partition_prefix,
                    strategy,
                    public_key_cache,
                    startup,
                    blocks_per_epoch: EPOCH_LENGTH,
                    simplex_timeouts: constantinople_engine::SimplexTimeouts::default(),
                    sync_config: production_sync_config(),
                    prune_config: Some(PRUNE_CONFIG),
                    genesis_leader: decoded.genesis_leader,
                    transaction_namespace: constantinople_primitives::TRANSACTION_NAMESPACE,
                    block_codec: constantinople_primitives::BlockCfg {
                        max_transactions: RangeCfg::new(0..=usize::MAX),
                        payload: (
                            NZU32!(64),
                            commonware_cryptography::bls12381::primitives::sharing::ModeVersion::v0(
                            ),
                            RangeCfg::new(0..=192),
                        ),
                    },
                    maximum_shard_size: max_propose_bytes.max(SHARD_SIZE_FLOOR),
                    prunable_items_per_section: PRUNABLE_ITEMS_PER_SECTION,
                    state_page_cache_bytes,
                    other_page_cache_bytes,
                    finalized_hook,
                },
                dkg_probe_network,
            )
            .await;

        // Install the account reader as soon as the stateful actor attaches
        // its databases. Runs concurrently with engine.start so the HTTP
        // listener can come up immediately; account lookups return 503 until
        // the cell is populated.
        let subscribe_fut = engine.subscribe_databases_detached();
        let account_reader_setter = account_reader.clone();
        let _account_reader_setup = tokio::spawn(async move {
            let reader: Arc<dyn AccountReader> = Arc::new(StateDbReader::new(subscribe_fut.await));
            let _ = account_reader_setter.set(reader);
            info!("account state reader attached");
        });

        info!("starting engine");
        // Every running validator maintains the same finalized mempool view,
        // so a later promotion never starts from stale transaction status.
        let mempool_reporter = MempoolReporter(mempool_mailbox.clone());
        let indexer_reporter = if relayer_observer.is_none() {
            indexer_handle.as_mut().map(|handle| {
                let (reporter, join) =
                    IndexerReporter::new(engine.marshal_mailbox(), handle.cert_reporter.clone());
                handle._uploaders.push(join);
                reporter
            })
        } else {
            None
        };
        type ObserverReporters =
            Reporters<Update<ValidatorEngineBlock>, crate::relayer::Observer, IndexerReporter>;
        let observer_reporters: Option<ObserverReporters> =
            if relayer_observer.is_some() || indexer_reporter.is_some() {
                Some(Reporters::from((relayer_observer, indexer_reporter)))
            } else {
                None
            };
        type EngineReporters =
            Reporters<Update<ValidatorEngineBlock>, MempoolReporter, LogAndObserverReporters>;
        type LogAndObserverReporters =
            Reporters<Update<ValidatorEngineBlock>, FinalizedBlockLogger, ObserverReporters>;
        let reporter: EngineReporters = Reporters::from((
            mempool_reporter,
            Reporters::from((FinalizedBlockLogger, observer_reporters)),
        ));
        let engine_handle = engine.start(channels, Some(reporter));

        wait_for_critical_task_exit(
            engine_handle,
            mempool_handle,
            role_http_handle,
            network_handle,
        )
        .await;
    });
}

async fn wait_for_critical_task_exit<E, M, H, N>(
    engine_handle: E,
    mempool_handle: M,
    role_http_handle: H,
    network_handle: N,
) where
    E: Future,
    M: Future,
    H: Future,
    N: Future,
{
    tokio::select! {
        _ = engine_handle => tracing::warn!("engine exited"),
        _ = mempool_handle => tracing::warn!("mempool exited"),
        _ = role_http_handle => tracing::warn!("role HTTP server exited"),
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
        FINALIZED_QUEUE_PAGE_SIZE, FINALIZED_QUEUE_WRITE_BUFFER, FinalizedBlockLogger,
        FinalizedQueueReader, FinalizedQueueWriter, FinalizedUploadCursor, IndexerReporter,
        ValidatorPayload, add_persistent_secondaries, default_mempool_drop_grace_blocks,
        maybe_build_indexer, persist_finalized_cursor, recovered_finalized_upload_cursor,
        scan_finalized_queue_cursor, wait_for_critical_task_exit,
    };
    use crate::config::IndexerConfig;
    use commonware_actor::Feedback;
    use commonware_codec::{FixedSize as _, Read as _, Write as _};
    use commonware_consensus::{
        Reporter as _,
        marshal::{Update, coding::types::coding_config_for_participants},
        simplex::types::Context as SimplexContext,
        types::{Round, View, coding::Commitment},
    };
    use commonware_cryptography::{
        Digest as _, Signer as _,
        ed25519::{PrivateKey, PublicKey},
        sha256::{Digest as Sha256Digest, Sha256},
    };
    use commonware_p2p::{Address, AddressableTrackedPeers};
    use commonware_runtime::{
        Clock as _, Runner as _, Spawner as _, Supervisor as _, deterministic,
        mocks::{WriteFaultContext, WriteFaults},
    };
    use commonware_storage::{
        merkle::mmr,
        metadata::{Config as MetadataConfig, Metadata},
        qmdb::any::{unordered::Operation as UnorderedOperation, value::FixedEncoding},
        queue,
    };
    use commonware_utils::{
        Acknowledgement as _, acknowledgement::Exact, non_empty_range, ordered::Map,
        sequence::FixedBytes,
    };
    use constantinople_primitives::{
        Account, AccountKey, Block, Header, Sealable, SignedTransaction,
    };
    use futures::FutureExt as _;
    use std::{future::pending, sync::Arc, time::Duration};
    use tokio::sync::Mutex;

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
    fn bootstrap_secondaries_remain_tracked_across_committee_rotations() {
        let primary = PrivateKey::from_seed(1).public_key();
        let scheduled = PrivateKey::from_seed(2).public_key();
        let indexer = PrivateKey::from_seed(3).public_key();
        let primary_address: Address = "127.0.0.1:1001"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into();
        let scheduled_address: Address = "127.0.0.1:1002"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into();
        let indexer_address: Address = "127.0.0.1:1003"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into();
        let initial = AddressableTrackedPeers::new(
            Map::from_iter_dedup([(primary.clone(), primary_address)]),
            Map::from_iter_dedup([(scheduled.clone(), scheduled_address.clone())]),
        );
        let persistent = Map::from_iter_dedup([(indexer.clone(), indexer_address.clone())]);

        let initial = add_persistent_secondaries(initial, &persistent);

        assert!(initial.primary.get_value(&primary).is_some());
        assert!(initial.secondary.get_value(&primary).is_none());
        assert!(initial.secondary.get_value(&scheduled).is_some());
        assert_eq!(
            initial.secondary.get_value(&indexer),
            Some(&indexer_address)
        );

        let promoted = AddressableTrackedPeers::new(
            Map::from_iter_dedup([(indexer.clone(), indexer_address.clone())]),
            Map::default(),
        );
        let promoted = add_persistent_secondaries(promoted, &persistent);
        assert!(promoted.primary.get_value(&indexer).is_some());
        assert!(promoted.secondary.get_value(&indexer).is_none());

        let rotated = AddressableTrackedPeers::new(
            Map::from_iter_dedup([(scheduled, scheduled_address)]),
            Map::default(),
        );
        let rotated = add_persistent_secondaries(rotated, &persistent);
        assert_eq!(
            rotated.secondary.get_value(&indexer),
            Some(&indexer_address)
        );
    }

    #[test]
    fn finalized_block_logger_acknowledges_delivery() {
        let block = queued_upload(7, 0, 1, 0, 1, 0, 1).block();
        let (acknowledgement, waiter) = Exact::handle();
        let mut reporter = FinalizedBlockLogger;

        assert_eq!(
            reporter.report(Update::Block(block, acknowledgement)),
            Feedback::Ok
        );
        assert!(waiter.now_or_never().unwrap().is_ok());
    }

    #[test]
    fn indexer_reporter_acknowledges_genesis_without_requesting_a_finalization() {
        let block = queued_upload(0, 0, 1, 0, 1, 0, 1).block();
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let mut reporter = IndexerReporter { sender };
        let (acknowledgement, waiter) = Exact::handle();

        assert_eq!(
            reporter.report(Update::Block(block, acknowledgement)),
            Feedback::Ok
        );
        assert!(waiter.now_or_never().unwrap().is_ok());
        assert!(
            receiver.try_recv().is_err(),
            "genesis must not enter the finalization lookup queue"
        );
    }

    #[tokio::test]
    async fn completed_setup_task_is_not_a_runtime_exit_condition() {
        let setup_task = tokio::spawn(async {});
        setup_task.await.expect("setup task should complete");

        let result = tokio::time::timeout(
            Duration::from_millis(10),
            wait_for_critical_task_exit(
                pending::<()>(),
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

    #[test]
    fn publisher_does_not_block_secondary_startup_on_connect_failure() {
        let runner =
            commonware_runtime::tokio::Runner::new(commonware_runtime::tokio::Config::default());
        runner.start(|context| async move {
            let indexer = IndexerConfig {
                chain_indexer_url: "http://127.0.0.1:1".to_string(),
                upload_buffer: 1,
            };

            let handle = tokio::time::timeout(
                Duration::from_secs(2),
                maybe_build_indexer(context, Some(indexer), "test", &Map::default()),
            )
            .await
            .expect("publisher connection should not block startup")
            .expect("secondary should keep indexer wiring");

            assert_eq!(handle._uploaders.len(), 2);
        });
    }

    #[test]
    fn finalized_upload_cursor_keeps_furthest_recovery_position() {
        let older = FinalizedUploadCursor {
            state_next: 10,
            transaction_next: 20,
            committee_next: 30,
        };
        let newer_state = FinalizedUploadCursor {
            state_next: 11,
            transaction_next: 1,
            committee_next: 1,
        };
        let newer_transaction = FinalizedUploadCursor {
            state_next: 10,
            transaction_next: 21,
            committee_next: 1,
        };
        let newer_committee = FinalizedUploadCursor {
            state_next: 10,
            transaction_next: 20,
            committee_next: 31,
        };

        assert_eq!(older.max(newer_state), newer_state);
        assert_eq!(older.max(newer_transaction), newer_transaction);
        assert_eq!(older.max(newer_committee), newer_committee);
        assert_eq!(newer_state.max(older), newer_state);
        assert_eq!(newer_transaction.max(older), newer_transaction);
        assert_eq!(newer_committee.max(older), newer_committee);
    }

    #[test]
    fn recovered_finalized_upload_cursor_uses_furthest_whole_frontier() {
        let metadata = FinalizedUploadCursor {
            state_next: 10,
            transaction_next: 20,
            committee_next: 30,
        };
        let queue = FinalizedUploadCursor {
            state_next: 11,
            transaction_next: 1,
            committee_next: 1,
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
    fn finalized_upload_cursor_ignores_partial_metadata_triples() {
        assert_eq!(FinalizedUploadCursor::from_parts(None, None, None), None);
        assert_eq!(
            FinalizedUploadCursor::from_parts(Some(10), None, None),
            None
        );
        assert_eq!(
            FinalizedUploadCursor::from_parts(None, Some(20), None),
            None
        );
        assert_eq!(
            FinalizedUploadCursor::from_parts(None, None, Some(30)),
            None
        );
        assert_eq!(
            FinalizedUploadCursor::from_parts(Some(10), Some(20), None),
            None,
        );
        assert_eq!(
            FinalizedUploadCursor::from_parts(Some(10), Some(20), Some(30)),
            Some(FinalizedUploadCursor {
                state_next: 10,
                transaction_next: 20,
                committee_next: 30,
            }),
        );
    }

    #[test]
    fn finalized_cursor_reopens_after_sync_failure() {
        deterministic::Runner::default().start(|context| async move {
            let faults = WriteFaults::default();
            let context = WriteFaultContext {
                inner: context.child("metadata"),
                faults: faults.clone(),
            };
            let partition = "finalized-cursor-retry";
            let metadata = Metadata::init(
                context.child("initial"),
                MetadataConfig {
                    partition: partition.to_string(),
                    codec_config: (),
                },
            )
            .await
            .expect("metadata initializes");
            let metadata = Arc::new(Mutex::new(Some(metadata)));
            let expected = FinalizedUploadCursor {
                state_next: 10,
                transaction_next: 20,
                committee_next: 30,
            };

            faults.arm();
            let monitor_metadata = metadata.clone();
            let monitor_faults = faults.clone();
            let monitor =
                context
                    .inner
                    .child("sync_failure_monitor")
                    .spawn(move |context| async move {
                        loop {
                            if monitor_metadata.lock().await.is_none() {
                                monitor_faults.disarm();
                                return;
                            }
                            context.sleep(Duration::from_millis(1)).await;
                        }
                    });

            persist_finalized_cursor(context.child("retry"), partition, &metadata, expected).await;
            monitor.await.expect("sync failure monitor completes");

            let metadata = metadata.lock().await;
            let metadata = metadata.as_ref().expect("metadata reopens after failure");
            assert_eq!(
                FinalizedUploadCursor::from_metadata(metadata),
                Some(expected)
            );
        });
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
            let first = queued_upload(1, 0, 2, 0, 2, 0, 2);
            let second = queued_upload(2, 2, 5, 2, 3, 2, 4);
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
        committee_start: u64,
        committee_end: u64,
    ) -> EngineQueuedUpload {
        let leader = PrivateKey::from_seed(height).public_key();
        let parent_commitment = Commitment::from((
            Sha256Digest::EMPTY,
            Sha256Digest::EMPTY,
            Sha256Digest::EMPTY,
            coding_config_for_participants(4),
        ));
        let header: Header<Commitment, Sha256Digest, PublicKey, ValidatorPayload> = Header {
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
            committee_root: Sha256Digest::EMPTY,
            committee_range: non_empty_range!(committee_start, committee_end),
            eligible_peers_root: Sha256Digest::EMPTY,
            payload: None,
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
        committee_start.write(&mut encoded);
        state_delta.write(&mut encoded);
        Vec::<constantinople_application::consensus::CommitteeOperation>::new().write(&mut encoded);

        let mut encoded = encoded.freeze();
        EngineQueuedUpload::read_cfg(&mut encoded, &super::QueuedFinalizedUploadCfg::default())
            .expect("queued upload decodes")
    }
}
