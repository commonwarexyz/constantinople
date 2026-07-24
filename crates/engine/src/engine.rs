//! Epoch-orchestrated engine assembly.
//!
//! The engine keeps the consensus stack deliberately small:
//!
//! - `constantinople-application` owns execution
//! - `commonware-glue::stateful` owns QMDB lifecycle and startup sync
//! - erasure-coded marshal owns finalized block availability
//! - continuous DKG reshare prepares the next epoch's threshold scheme
//! - the orchestrator starts one simplex actor per 64-block epoch

use crate::{
    CommitteeParticipants, DynamicProvider, Registrar, dkg::encode_finalized_application_height,
    types::*,
};
use commonware_codec::{Encode as _, RangeCfg, Read};
use commonware_coding::CodecConfig;
use commonware_consensus::{
    Reporter, Reporters,
    marshal::{
        self, Update,
        coding::{Marshaled, MarshaledConfig, shards, types::coding_config_for_participants},
        core::{Actor as MarshalActor, Variant as MarshalVariant},
        resolver::p2p as marshal_resolver,
    },
    simplex::{self, elector::Config as Elector, types::Finalization},
    types::{Epoch, FixedEpocher, Height, ViewDelta, coding::Commitment},
};
#[cfg(all(test, feature = "test-utils"))]
use commonware_cryptography::Committable;
use commonware_cryptography::{
    BatchVerifier, Digest, Digestible, Hasher, PublicKey, Signer,
    bls12381::{
        dkg::feldman_desmedt::Output,
        primitives::{group, sharing::Mode, variant::Variant},
    },
    certificate::Verifier,
    ed25519,
};
use commonware_glue::{
    dkg::{
        ReshareBlock, SecretStore as _,
        fence::Fence,
        network, orchestrator, probe, reshare,
        state_sync::{Config as DkgStateSyncConfig, Plan as DkgStateSyncPlan, StateSync},
        types::{EpochInfo, Payload},
    },
    stateful::{
        Config as StatefulConfig, PruneConfig, Stateful, SyncPlan,
        db::{ManagedDb, SyncEngineConfig, p2p as qmdb_resolver},
    },
};
use commonware_macros::boxed;
use commonware_p2p::{Address, AddressableManager, Blocker, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Network, Spawner, Storage,
    buffer::paged::CacheRef, spawn_cell,
};
use commonware_storage::{
    archive::{prunable, prunable::Archive as PrunableArchive},
    journal::contiguous::{
        fixed::Config as FixedJournalConfig, variable::Config as VariableJournalConfig,
    },
    merkle::full::Config as MmrConfig,
    mmr,
    qmdb::{any::FixedConfig, keyless::fixed as keyless_fixed},
    translator::EightCap,
};
use commonware_utils::{
    NZDuration, NZU16, NZU32, NZU64, NZUsize, non_empty_range, ordered::Map, union,
};
use constantinople_application::consensus::{
    Application, CommitteeSyncTarget, FinalizedHookFn, StateSyncTarget, TransactionHistoryTarget,
};
use constantinople_mempool::TransactionSource;
use constantinople_primitives::{BLOCKS_PER_EPOCH, PublicKeyCache};
use futures::future::try_join_all;
use rand::CryptoRng;
use std::{
    net::SocketAddr,
    num::{NonZero, NonZeroU16},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tracing::{error, info, warn};

/// The fixed threshold scheme used by simplex and marshal.
pub type ThresholdScheme<P, V> = simplex::scheme::bls12381_threshold::standard::Scheme<P, V>;

/// Number of finalized blocks in each production epoch.
pub const EPOCH_LENGTH: NonZero<u64> = NonZero::new(BLOCKS_PER_EPOCH).unwrap();
const MAX_DKG_PARTICIPANTS: NonZero<u32> = NZU32!(64);
const DKG_MUXER_SIZE: usize = 128;
const MAILBOX_SIZE: NonZero<usize> = NZUsize!(1024);
const ACTIVITY_TIMEOUT: ViewDelta = ViewDelta::new(256);
const FREEZER_VALUE_COMPRESSION: Option<u8> = None;
const REPLAY_BUFFER: NonZero<usize> = NZUsize!(8 * 1024 * 1024);
const WRITE_BUFFER: NonZero<usize> = NZUsize!(1024 * 1024);
const PAGE_CACHE_PAGE_SIZE: NonZeroU16 = NZU16!(8192); // 8 KiB
const ITEMS_PER_BLOB: NonZero<u64> = NZU64!(1_048_576 * 25); // ~1gb
const MAX_REPAIR: NonZero<usize> = NZUsize!(200);
pub const MAX_PENDING_ACKS: NonZero<usize> = NZUsize!(4);
const WITNESS_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(64);
const SHARD_BACKGROUND_CHANNEL_CAPACITY: NonZero<usize> = NZUsize!(1024);
const SHARD_PEER_BUFFER_SIZE: NonZero<usize> = NZUsize!(64);
const DB_WRITE_BUFFER: NonZero<usize> = NZUsize!(8 * 1024 * 1024);
const STATE_INIT_CACHE_SIZE: NonZero<usize> = NZUsize!(1 << 18);
const STATE_SYNC_INITIAL: Duration = Duration::from_secs(1);
const STATE_SYNC_TIMEOUT: Duration = Duration::from_secs(2);
const STATE_SYNC_RETRY: Duration = Duration::from_millis(100);
const ELIGIBLE_PEERS_DOMAIN: &[u8] = b"constantinople/eligible-peers/v1";

/// Local Simplex timing policy used by each epoch actor.
#[derive(Clone, Copy, Debug)]
pub struct SimplexTimeouts {
    /// Time to wait for the current leader to propose a block.
    pub leader: Duration,
    /// Time to wait for a proposal to become certified.
    pub certification: Duration,
    /// Delay before retrying a failed consensus action.
    pub retry: Duration,
    /// Time to wait while fetching missing consensus data.
    pub fetch: Duration,
    /// Time to wait before advancing past an inactive view.
    pub skip: Duration,
}

impl Default for SimplexTimeouts {
    fn default() -> Self {
        Self {
            leader: Duration::from_secs(4),
            certification: Duration::from_secs(8),
            retry: Duration::from_secs(10),
            fetch: Duration::from_secs(4),
            skip: Duration::from_secs(11),
        }
    }
}

fn genesis_directory_root<H, P>(bootstrap_peers: &Map<P, Address>) -> H::Digest
where
    H: Hasher,
    P: PublicKey,
{
    H::hash(&[ELIGIBLE_PEERS_DOMAIN, &bootstrap_peers.encode()])
}

fn bootstrap_socket_addresses<P>(bootstrap_peers: &Map<P, Address>) -> Map<P, SocketAddr>
where
    P: PublicKey,
{
    Map::from_iter_dedup(bootstrap_peers.iter_pairs().map(|(peer, address)| {
        let Address::Symmetric(socket) = address else {
            panic!("genesis/bootstrap peer {peer:?} must have a symmetric socket address");
        };
        (peer.clone(), *socket)
    }))
}

/// Vote channel id.
pub const VOTE_CHANNEL: u64 = 0;
/// Certificate channel id.
pub const CERTIFICATE_CHANNEL: u64 = 1;
/// Simplex resolver channel id.
pub const RESOLVER_CHANNEL: u64 = 2;
/// Marshal shard channel id.
pub const MARSHAL_CHANNEL: u64 = 3;
/// Marshal backfill resolver channel id.
pub const MARSHAL_RESOLVER_CHANNEL: u64 = 4;
/// State database sync resolver channel id.
pub const STATE_RESOLVER_CHANNEL: u64 = 5;
/// Transaction history database sync resolver channel id.
pub const TRANSACTION_RESOLVER_CHANNEL: u64 = 6;
/// Committee database sync resolver channel id.
pub const COMMITTEE_RESOLVER_CHANNEL: u64 = 7;
/// Private DKG reshare traffic channel id.
pub const DKG_CHANNEL: u64 = 8;
/// DKG state-sync probe channel id.
pub const DKG_PROBE_CHANNEL: u64 = 9;
/// Backwards-compatible name for the DKG state-sync probe channel.
pub const PROBE_CHANNEL: u64 = DKG_PROBE_CHANNEL;

/// All channel ids used by the engine, including the state-sync probe.
pub const CHANNELS: [u64; 10] = [
    VOTE_CHANNEL,
    CERTIFICATE_CHANNEL,
    RESOLVER_CHANNEL,
    MARSHAL_CHANNEL,
    MARSHAL_RESOLVER_CHANNEL,
    STATE_RESOLVER_CHANNEL,
    TRANSACTION_RESOLVER_CHANNEL,
    COMMITTEE_RESOLVER_CHANNEL,
    DKG_CHANNEL,
    DKG_PROBE_CHANNEL,
];

/// Registered physical channels required by the engine.
#[derive(Debug)]
pub struct Channels<P, S, R>
where
    P: PublicKey,
    S: Sender<PublicKey = P>,
    R: Receiver<PublicKey = P>,
{
    pub votes: (S, R),
    pub certificates: (S, R),
    pub resolver: (S, R),
    pub marshal: (S, R),
    pub marshal_resolver: (S, R),
    pub state_resolver: (S, R),
    pub transaction_resolver: (S, R),
    pub committee_resolver: (S, R),
    pub dkg: (S, R),
}

/// Requested engine startup behavior.
///
/// The engine resolves this request against its durable [`SyncPlan`]. A state-sync
/// request only probes for a floor when the plan determines state sync is needed.
pub enum StartupMode {
    /// Recover consensus and application state from local storage.
    MarshalSync,
    /// Request state sync from peers when required by the durable sync plan.
    StateSync,
}

pub struct Config<E, C, M, B, V, St, I, H>
where
    E: BufferPooler + Storage + Clock + Metrics,
    C: Signer<PublicKey = ed25519::PublicKey>,
    M: AddressableManager<PublicKey = C::PublicKey>,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    St: Strategy,
    H: Hasher,
{
    pub signer: C,
    pub manager: M,
    pub blocker: B,
    pub namespace: Vec<u8>,
    pub output: Output<V, C::PublicKey>,
    pub share: Option<group::Share>,
    /// Canonical epoch-zero DKG artifact embedded in genesis.
    pub genesis: EpochInfo<V, C::PublicKey, network::Addresses<C::PublicKey>>,
    /// Immutable genesis/bootstrap peer directory committed by genesis.
    /// Finalized committee snapshots provide addresses for later committees.
    pub eligible_peers: Map<C::PublicKey, Address>,
    /// Plaintext validator-local storage for DKG private material.
    ///
    /// [`crate::secret_store::FileSecretStore`] is explicitly not a
    /// production-grade secret manager.
    pub secret_store: crate::secret_store::FileSecretStore,
    /// Static namespace used for DKG transcripts.
    pub dkg_namespace: &'static [u8],
    pub input: I,
    pub partition_prefix: String,
    pub strategy: St,
    pub public_key_cache: PublicKeyCache,
    pub startup: StartupMode,
    /// Finalized blocks per epoch.
    ///
    /// Production validators use [`EPOCH_LENGTH`]. Keeping this explicit lets
    /// deterministic actor-level tests exercise several resharing boundaries
    /// without finalizing thousands of blocks.
    pub blocks_per_epoch: NonZero<u64>,
    /// Local liveness timings for each epoch's Simplex actor.
    pub simplex_timeouts: SimplexTimeouts,
    pub sync_config: SyncEngineConfig,
    pub prune_config: Option<PruneConfig>,
    pub genesis_leader: C::PublicKey,
    pub transaction_namespace: &'static [u8],
    pub block_codec: EngineBlockCfg<C, V>,
    /// Maximum non-fixed-size bytes accepted in an erasure-coded block shard.
    ///
    /// This must accommodate shards produced by the application's maximum
    /// proposal size. It remains explicit because the block codec constrains
    /// transaction count, not total encoded bytes.
    pub maximum_shard_size: usize,
    pub prunable_items_per_section: NonZero<u64>,
    /// Capacity in bytes of the state QMDB page cache.
    ///
    /// Must hold the state journal's working set: 512 MiB thrashed once the
    /// live account set passed ~2M (build/verify doubled on ~200k journal
    /// cache misses/s/node).
    pub state_page_cache_bytes: usize,
    /// Capacity in bytes of the page cache for everything else (block and
    /// certificate archives, transaction history, simplex journal). Separate
    /// from the state cache so backfill and replay scans cannot evict its
    /// working set.
    pub other_page_cache_bytes: usize,
    /// Optional hook that observes finalized blocks after local database
    /// application and before state pruning.
    #[expect(
        clippy::type_complexity,
        reason = "the hook is parameterized by the engine's full block payload"
    )]
    pub finalized_hook: Option<
        FinalizedHookFn<
            E,
            Commitment,
            H,
            C::PublicKey,
            Payload<V, C, network::Addresses<C::PublicKey>>,
            St,
        >,
    >,
}

/// Fully assembled validator engine.
pub struct Engine<E, C, M, B, H, V, L, St, I, BV>
where
    E: BufferPooler + Spawner + Metrics + CryptoRng + Clock + Storage + Network,
    C: Signer<PublicKey = ed25519::PublicKey>,
    M: AddressableManager<PublicKey = C::PublicKey>,
    B: Blocker<PublicKey = C::PublicKey>,
    H: Hasher,
    V: Variant,
    L: Elector<ThresholdScheme<C::PublicKey, V>>,
    St: Strategy,
    I: TransactionSource<Commitment, C::PublicKey, H> + Sync,
    BV: BatchVerifier<PublicKey = C::PublicKey> + Send + Sync + 'static,
    EngineBlock<H, C, V>: ReshareBlock<Variant = V, Signer = C, Directory = network::Addresses<C::PublicKey>>
        + Digestible<Digest = H::Digest>
        + Read<Cfg = EngineBlockCfg<C, V>>,
    CodingBlock<H, C, V>: Digestible<Digest = H::Digest>,
{
    context: ContextCell<E>,
    signer: C,
    manager: M,
    blocker: B,
    state_resolver: StateResolverActor<E, C::PublicKey, M, B, H, St>,
    transaction_resolver: TransactionResolverActor<E, C::PublicKey, M, B, H, St>,
    committee_resolver: CommitteeResolverActor<E, C::PublicKey, M, B, H, St>,
    probe: Handle<()>,
    stateful: StatefulApp<E, H, C, V, I, St>,
    stateful_mailbox: AppMailbox<E, H, C, V, I, St>,
    shards: ShardsEngine<E, B, M, H, C, V, St>,
    shard_mailbox: ShardsMailbox<H, C, V>,
    #[expect(
        clippy::type_complexity,
        reason = "marshal actor type is inherently complex"
    )]
    marshal: MarshalActor<
        E,
        EngineVariant<H, C, V>,
        SchemeProvider<C::PublicKey, V>,
        PrunableArchive<
            EightCap,
            E,
            H::Digest,
            Finalization<ThresholdScheme<C::PublicKey, V>, Commitment>,
        >,
        PrunableArchive<EightCap, E, H::Digest, CodingBlock<H, C, V>>,
        FixedEpocher,
        St,
    >,
    marshal_mailbox: EngineMarshalMailbox<H, C, V>,
    #[cfg(all(test, feature = "test-utils"))]
    genesis_commitment: Commitment,
    reshare: DkgReshareActor<E, M, B, H, V, C, St, BV>,
    reshare_mailbox: reshare::Mailbox<EngineBlock<H, C, V>, V, C>,
    orchestrator: DkgOrchestratorActor<E, M, B, H, V, C, L, St, I>,
    orchestrator_mailbox: orchestrator::Mailbox<EngineBlock<H, C, V>>,
}

impl<E, C, M, B, H, V, L, St, I, BV> Engine<E, C, M, B, H, V, L, St, I, BV>
where
    E: BufferPooler + Spawner + Metrics + CryptoRng + Clock + Storage + Network,
    C: Signer<PublicKey = ed25519::PublicKey>,
    M: AddressableManager<PublicKey = C::PublicKey>,
    B: Blocker<PublicKey = C::PublicKey>,
    H: Hasher,
    V: Variant,
    L: Elector<ThresholdScheme<C::PublicKey, V>>,
    St: Strategy,
    I: TransactionSource<Commitment, C::PublicKey, H> + Sync,
    BV: BatchVerifier<PublicKey = C::PublicKey> + Send + Sync + 'static,
    EngineBlock<H, C, V>: ReshareBlock<Variant = V, Signer = C, Directory = network::Addresses<C::PublicKey>>
        + Digestible<Digest = H::Digest>
        + Read<Cfg = EngineBlockCfg<C, V>>,
    CodingBlock<H, C, V>: Digestible<Digest = H::Digest>,
{
    /// Returns a clone of the marshal mailbox.
    ///
    /// Callers may use this before [`start`](Self::start) to wire reporters
    /// that need access to finalized blocks or certificates.
    pub fn marshal_mailbox(&self) -> EngineMarshalMailbox<H, C, V> {
        self.marshal_mailbox.clone()
    }

    #[cfg(all(test, feature = "test-utils"))]
    pub(crate) const fn genesis_commitment(&self) -> Commitment {
        self.genesis_commitment
    }

    /// Returns the state database once the stateful actor has initialized it.
    /// Blocks until the database is ready.
    pub async fn subscribe_databases(&self) -> StateSyncDb<E, H, St> {
        self.stateful_mailbox.subscribe_databases().await.0
    }

    /// Returns the committed committee database once stateful initialization
    /// completes.
    pub async fn subscribe_committee(&self) -> CommitteeSyncDb<E, H, St> {
        self.stateful_mailbox.subscribe_databases().await.2
    }

    /// Returns a standalone future that resolves to the state database once
    /// the stateful actor has initialized it.
    ///
    /// Unlike [`subscribe_databases`](Self::subscribe_databases), the returned
    /// future borrows nothing from `self`, so callers can poll it concurrently
    /// with [`start`](Self::start) (which consumes the engine).
    pub fn subscribe_databases_detached(
        &self,
    ) -> impl std::future::Future<Output = StateSyncDb<E, H, St>> + Send + 'static {
        let mailbox = self.stateful_mailbox.clone();
        async move { mailbox.subscribe_databases().await.0 }
    }

    /// Returns a standalone future for the committed committee database.
    pub fn subscribe_committee_detached(
        &self,
    ) -> impl std::future::Future<Output = CommitteeSyncDb<E, H, St>> + Send + 'static {
        let mailbox = self.stateful_mailbox.clone();
        async move { mailbox.subscribe_databases().await.2 }
    }

    /// Initializes the full engine stack and starts the DKG probe on its
    /// dedicated physical channel.
    #[boxed]
    pub async fn new<Sx, Rx>(
        context: E,
        config: Config<E, C, M, B, V, St, I, H>,
        dkg_probe_network: (Sx, Rx),
    ) -> Self
    where
        Sx: Sender<PublicKey = C::PublicKey>,
        Rx: Receiver<PublicKey = C::PublicKey>,
    {
        let page_cache = CacheRef::from_pooler(
            &context.child("other"),
            PAGE_CACHE_PAGE_SIZE,
            NonZero::new(config.other_page_cache_bytes / usize::from(PAGE_CACHE_PAGE_SIZE.get()))
                .expect("page cache must hold at least one page"),
        );
        let storage_page_cache = CacheRef::from_pooler(
            &context.child("state"),
            PAGE_CACHE_PAGE_SIZE,
            NonZero::new(config.state_page_cache_bytes / usize::from(PAGE_CACHE_PAGE_SIZE.get()))
                .expect("state page cache must hold at least one page"),
        );
        let consensus_namespace = union(&config.namespace, b"_CONSENSUS");
        let eligible_peers_root = genesis_directory_root::<H, C::PublicKey>(&config.eligible_peers);
        let bootstrap_addresses = bootstrap_socket_addresses(&config.eligible_peers);
        let epocher = FixedEpocher::new(config.blocks_per_epoch);
        let mut secret_store = config.secret_store.clone();
        if let Some(share) = config.share.clone() {
            secret_store
                .put_initial_share(Epoch::zero(), share)
                .expect("failed to durably seed the initial DKG share");
        }
        let epoch_zero_share = secret_store.get_share(Epoch::zero()).await;
        let scheme =
            threshold_scheme::<C, V>(&consensus_namespace, &config.output, epoch_zero_share);
        let provider = DynamicProvider::default();
        provider.register(Epoch::zero(), scheme);

        assert_eq!(
            config.genesis.epoch,
            Epoch::zero(),
            "genesis must describe epoch zero"
        );
        assert_eq!(
            config.genesis.output, config.output,
            "genesis DKG output must match engine configuration",
        );
        let dkg_manager = network::AddressableManager::new(config.manager.clone());
        let (probe_actor, probe_mailbox) = probe::Actor::new(probe::Config {
            context: context.child("dkg_probe"),
            manager: dkg_manager.clone(),
            bootstrap: probe::Bootstrap {
                epoch: Epoch::zero(),
                participants: config.genesis.participants(),
                directory: config.genesis.directory.clone(),
            },
            verifier: threshold_scheme::<C, V>(&consensus_namespace, &config.output, None),
            genesis: config.genesis.clone(),
            strategy: config.strategy.clone(),
            blocker: config.blocker.clone(),
            blocks_per_epoch: config.blocks_per_epoch,
            retry_timeout: NZDuration!(Duration::from_millis(500)),
            mailbox_size: MAILBOX_SIZE,
            block_codec_config: config.block_codec.clone(),
        });
        let probe_handle = probe_actor.start(dkg_probe_network);

        let (state_resolver, state_sync_resolver) =
            StateResolverActor::<_, C::PublicKey, _, _, H, St>::new(
                context.child("state_resolver"),
                qmdb_resolver::standard::Config {
                    peer_provider: config.manager.clone(),
                    blocker: config.blocker.clone(),
                    database: None,
                    mailbox_size: MAILBOX_SIZE,
                    me: Some(config.signer.public_key()),
                    initial: STATE_SYNC_INITIAL,
                    timeout: STATE_SYNC_TIMEOUT,
                    fetch_retry_timeout: STATE_SYNC_RETRY,
                    priority_requests: false,
                    priority_responses: false,
                    max_serve_ops: NZU64!(4096),
                },
            );
        let (transaction_resolver, transaction_sync_resolver) =
            TransactionResolverActor::<_, C::PublicKey, _, _, H, St>::new(
                context.child("transaction_resolver"),
                qmdb_resolver::compact::Config {
                    peer_provider: config.manager.clone(),
                    blocker: config.blocker.clone(),
                    database: None,
                    mailbox_size: MAILBOX_SIZE,
                    me: Some(config.signer.public_key()),
                    initial: STATE_SYNC_INITIAL,
                    timeout: STATE_SYNC_TIMEOUT,
                    fetch_retry_timeout: STATE_SYNC_RETRY,
                    priority_requests: false,
                    priority_responses: false,
                },
            );
        let (committee_resolver, committee_sync_resolver) =
            CommitteeResolverActor::<_, C::PublicKey, _, _, H, St>::new(
                context.child("committee_resolver"),
                qmdb_resolver::standard::Config {
                    peer_provider: config.manager.clone(),
                    blocker: config.blocker.clone(),
                    database: None,
                    mailbox_size: MAILBOX_SIZE,
                    me: Some(config.signer.public_key()),
                    initial: STATE_SYNC_INITIAL,
                    timeout: STATE_SYNC_TIMEOUT,
                    fetch_retry_timeout: STATE_SYNC_RETRY,
                    priority_requests: false,
                    priority_responses: false,
                    max_serve_ops: NZU64!(4096),
                },
            );
        let n_participants = u16::try_from(config.output.players().len())
            .expect("participant count must fit in u16");
        let coding_config = coding_config_for_participants(n_participants);
        let genesis_parent = Commitment::from((
            H::Digest::EMPTY,
            H::Digest::EMPTY,
            H::Digest::EMPTY,
            coding_config,
        ));

        let prunable_items_per_section = config.prunable_items_per_section;
        let (finalizations_by_height, finalized_blocks) = futures::join!(
            init_finalizations_archive::<E, H, C::PublicKey, V>(
                &context,
                &page_cache,
                &config.partition_prefix,
                prunable_items_per_section,
            ),
            init_finalized_blocks_archive::<E, H, C, V>(
                &context,
                &page_cache,
                &config.partition_prefix,
                &config.block_codec,
                prunable_items_per_section,
            ),
        );
        let transaction_db_config = transaction_db_config(
            &config.partition_prefix,
            &page_cache,
            config.strategy.clone(),
        );
        let committee_db_config = committee_db_config(
            &config.partition_prefix,
            &storage_page_cache,
            config.strategy.clone(),
        );
        let stateful_partition_prefix = format!("{}_stateful", config.partition_prefix);
        let stateful_startup_context = context.child("stateful_startup");
        let mut startup_plan =
            SyncPlan::<E, ThresholdScheme<C::PublicKey, V>, EngineVariant<H, C, V>>::init(
                &stateful_startup_context,
                stateful_partition_prefix.clone(),
            )
            .await;

        // The durable plan distinguishes normal recovery from peer state sync. Normal recovery
        // stays floorless so marshal restores its acknowledged progress; only a requested or
        // interrupted state sync discovers a new floor.
        let state_sync_requested = matches!(&config.startup, StartupMode::StateSync);
        let probe_artifact = if startup_plan.should_state_sync(state_sync_requested) {
            let artifact = probe_mailbox
                .subscribe()
                .await
                .expect("probe actor exited before selecting a state-sync floor");
            provider.register(
                artifact.info.epoch,
                threshold_scheme::<C, V>(&consensus_namespace, &artifact.info.output, None),
            );
            startup_plan = startup_plan.with_floor(artifact.floor.clone());
            Some(artifact)
        } else {
            None
        };

        // The canonical genesis is a pure function of configuration: the leader, the
        // participant-derived coding config, immutable genesis/bootstrap directory, and the
        // canonical empty-database roots.
        let genesis_block = constantinople_application::consensus::genesis_block_with_parent(
            &mut H::default(),
            config.genesis_leader.clone(),
            (commonware_consensus::types::View::zero(), genesis_parent),
            0,
            <StateDb<E, H, St> as ManagedDb<E>>::initial_sync_target(),
            <TransactionDb<E, H, St> as ManagedDb<E>>::initial_sync_target(),
            <constantinople_application::consensus::CommitteeDb<E, H, EightCap, St> as ManagedDb<
                E,
            >>::initial_sync_target(),
            eligible_peers_root,
            Payload::EpochInfo(config.genesis.clone()),
        );
        let coded_genesis =
            EngineCodedBlock::<H, C, V>::new(genesis_block, coding_config, &config.strategy);
        let application_genesis =
            <EngineVariant<H, C, V> as MarshalVariant>::into_inner(coded_genesis.clone());
        let (
            application_state_target,
            application_transactions_target,
            application_committee_target,
        ) = block_targets(&application_genesis);

        #[cfg(all(test, feature = "test-utils"))]
        let genesis_commitment = coded_genesis.commitment();
        let marshal_start = startup_plan.marshal_start(coded_genesis);

        let (marshal, marshal_mailbox, recovered_processed_height) = MarshalActor::init(
            context.child("marshal"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider: provider.clone(),
                epocher: epocher.clone(),
                start: marshal_start,
                partition_prefix: format!("{}_marshal", config.partition_prefix),
                mailbox_size: MAILBOX_SIZE,
                view_retention: ACTIVITY_TIMEOUT,
                prunable_items_per_section,
                page_cache: page_cache.clone(),
                replay_buffer: REPLAY_BUFFER,
                key_write_buffer: WRITE_BUFFER,
                value_write_buffer: WRITE_BUFFER,
                block_codec_config: config.block_codec.clone(),
                max_repair: MAX_REPAIR,
                max_pending_acks: MAX_PENDING_ACKS,
                strategy: config.strategy.clone(),
            },
        )
        .await;
        let finalized_application_height = Arc::new(AtomicU64::new(
            encode_finalized_application_height(recovered_processed_height),
        ));
        probe_mailbox.attach(marshal_mailbox.clone());

        let (shards, shard_mailbox) = shards::Engine::new(
            context.child("shards"),
            shards::Config {
                scheme_provider: provider.clone(),
                blocker: config.blocker.clone(),
                shard_codec_cfg: CodecConfig {
                    maximum_shard_size: config.maximum_shard_size,
                },
                block_codec_cfg: config.block_codec.clone(),
                strategy: config.strategy.clone(),
                mailbox_size: MAILBOX_SIZE,
                peer_buffer_size: SHARD_PEER_BUFFER_SIZE,
                background_channel_capacity: SHARD_BACKGROUND_CHANNEL_CAPACITY,
                peer_provider: config.manager.clone(),
            },
        );
        let external_finalized_hook = config.finalized_hook;
        let finalized_application_height_for_hook = finalized_application_height.clone();
        #[expect(
            clippy::type_complexity,
            reason = "the hook is parameterized by the engine's full block payload"
        )]
        let finalized_hook: FinalizedHookFn<
            E,
            Commitment,
            H,
            C::PublicKey,
            Payload<V, C, network::Addresses<C::PublicKey>>,
            St,
        > = Arc::new(move |block, databases| {
            // Stateful invokes this hook only after committing the finalized
            // batch to every managed database. Publish before invoking the
            // optional external hook so its latency cannot delay DKG readers.
            finalized_application_height_for_hook.fetch_max(
                encode_finalized_application_height(Some(Height::new(block.header.height))),
                Ordering::Release,
            );
            let external_finalized_hook = external_finalized_hook.clone();
            Box::pin(async move {
                if let Some(hook) = external_finalized_hook {
                    hook(block, databases).await;
                }
            })
        });
        let application = Application::new(
            context.child("application"),
            config.strategy.clone(),
            config.genesis_leader.clone(),
            genesis_parent,
            config.transaction_namespace,
            config.public_key_cache,
            application_state_target,
            application_transactions_target,
            application_committee_target,
            config.genesis.clone(),
            eligible_peers_root,
            config.blocks_per_epoch,
            bootstrap_addresses.clone(),
            Some(finalized_hook),
        );
        let state_sync = probe_artifact.map(|artifact| StateSync {
            info: artifact.info,
            floor: startup_plan
                .floor()
                .cloned()
                .expect("DKG state sync requires a stateful floor"),
        });
        let fence_epoch = state_sync
            .as_ref()
            .map_or_else(Epoch::zero, |state_sync| state_sync.info.epoch);
        let dkg_state_sync = DkgStateSyncPlan::init(
            context.child("dkg_state_sync_plan"),
            DkgStateSyncConfig {
                partition_prefix: config.partition_prefix.clone(),
                max_participants: MAX_DKG_PARTICIPANTS,
                max_supported_mode:
                    commonware_cryptography::bls12381::primitives::sharing::ModeVersion::v0(),
                directory_codec_config: RangeCfg::new(0..=MAX_DKG_PARTICIPANTS.get() as usize * 3),
            },
            state_sync,
        )
        .await;

        let (stateful_actor, stateful_mailbox) = Stateful::init(
            context.child("stateful"),
            StatefulConfig {
                application,
                db_config: (
                    state_db_config(
                        &config.partition_prefix,
                        &storage_page_cache,
                        config.strategy.clone(),
                    ),
                    transaction_db_config,
                    committee_db_config,
                ),
                provider: config.input,
                marshal: marshal_mailbox.clone(),
                mailbox_size: MAILBOX_SIZE,
                plan: startup_plan,
                resolvers: (
                    state_sync_resolver,
                    transaction_sync_resolver,
                    committee_sync_resolver,
                ),
                sync_config: config.sync_config,
                prune_config: config.prune_config,
            },
        );
        let committee_subscription = {
            let stateful_mailbox = stateful_mailbox.clone();
            async move { stateful_mailbox.subscribe_databases().await.2 }
        };
        let participants_provider = CommitteeParticipants::new(
            context.child("committee_participants"),
            committee_subscription,
            config.genesis.players.clone(),
            config.genesis.next_players.clone(),
            bootstrap_addresses,
            finalized_application_height,
            config.blocks_per_epoch,
        );
        let registrar = Registrar::new(consensus_namespace, provider.clone());
        let (fence, gate) = Fence::new(fence_epoch);
        let (reshare_actor, reshare_mailbox) = reshare::Actor::new(
            context.child("reshare"),
            reshare::Config {
                signer: config.signer.clone(),
                manager: dkg_manager.clone(),
                blocker: config.blocker.clone(),
                participants_provider,
                secret_store,
                strategy: config.strategy.clone(),
                registrar,
                marshal: marshal_mailbox.clone(),
                state_sync: dkg_state_sync.clone(),
                fence,
                namespace: config.dkg_namespace,
                sharing_mode: Mode::NonZeroCounter,
                mailbox_size: MAILBOX_SIZE,
                partition_prefix: format!("{}_reshare", config.partition_prefix),
                max_participants: MAX_DKG_PARTICIPANTS,
                blocks_per_epoch: config.blocks_per_epoch,
                batch_verifier: std::marker::PhantomData::<BV>,
            },
        );

        let reshare_application = reshare::Application::new(
            stateful_mailbox.clone(),
            reshare_mailbox.clone(),
            config.blocks_per_epoch,
        );
        let application = Marshaled::new(
            context.child("application"),
            MarshaledConfig {
                application: reshare_application,
                marshal: marshal_mailbox.clone(),
                shards: shard_mailbox.clone(),
                scheme_provider: provider.clone(),
                strategy: config.strategy.clone(),
                epocher: epocher.clone(),
            },
        );
        let (orchestrator_actor, orchestrator_mailbox) = orchestrator::Actor::new(
            context.child("orchestrator"),
            orchestrator::Config {
                oracle: config.blocker.clone(),
                manager: dkg_manager,
                provider,
                marshal: marshal_mailbox.clone(),
                application,
                strategy: config.strategy.clone(),
                simplex: orchestrator::SimplexConfig {
                    elector: L::default(),
                    mailbox_size: MAILBOX_SIZE,
                    replay_buffer: REPLAY_BUFFER,
                    write_buffer: WRITE_BUFFER,
                    page_cache_page_size: PAGE_CACHE_PAGE_SIZE,
                    page_cache_pages: NonZero::new(
                        config.other_page_cache_bytes / usize::from(PAGE_CACHE_PAGE_SIZE.get()),
                    )
                    .expect("simplex page cache must hold at least one page"),
                    leader_timeout: config.simplex_timeouts.leader,
                    certification_timeout: config.simplex_timeouts.certification,
                    timeout_retry: config.simplex_timeouts.retry,
                    fetch_timeout: config.simplex_timeouts.fetch,
                    fetch_concurrent: NZUsize!(32),
                    view_retention: ACTIVITY_TIMEOUT,
                    skip_timeout: config.simplex_timeouts.skip,
                    forwarding: simplex::ForwardingPolicy::Disabled,
                },
                gate,
                state_sync: dkg_state_sync,
                blocks_per_epoch: config.blocks_per_epoch,
                muxer_size: DKG_MUXER_SIZE,
                mailbox_size: MAILBOX_SIZE,
                partition_prefix: format!("{}_orchestrator", config.partition_prefix),
            },
        );
        Self {
            context: ContextCell::new(context),
            signer: config.signer,
            manager: config.manager,
            blocker: config.blocker,
            state_resolver,
            transaction_resolver,
            committee_resolver,
            probe: probe_handle,
            stateful: stateful_actor,
            stateful_mailbox,
            shards,
            shard_mailbox,
            marshal,
            marshal_mailbox,
            #[cfg(all(test, feature = "test-utils"))]
            genesis_commitment,
            reshare: reshare_actor,
            reshare_mailbox,
            orchestrator: orchestrator_actor,
            orchestrator_mailbox,
        }
    }

    /// Starts all engine actors on the provided channels.
    pub fn start<Sx, Rx, Rep>(
        mut self,
        channels: Channels<C::PublicKey, Sx, Rx>,
        reporter: Option<Rep>,
    ) -> Handle<()>
    where
        Sx: Sender<PublicKey = C::PublicKey> + Send + 'static,
        Rx: Receiver<PublicKey = C::PublicKey> + Send + 'static,
        Rep: Reporter<Activity = Update<EngineBlock<H, C, V>>>,
    {
        spawn_cell!(self.context, self.run(channels, reporter))
    }

    async fn run<Sx, Rx, Rep>(self, channels: Channels<C::PublicKey, Sx, Rx>, reporter: Option<Rep>)
    where
        Sx: Sender<PublicKey = C::PublicKey>,
        Rx: Receiver<PublicKey = C::PublicKey>,
        Rep: Reporter<Activity = Update<EngineBlock<H, C, V>>>,
    {
        let resolver_context = self.context.into_present();
        let marshal_resolver = marshal_resolver::init(
            resolver_context,
            marshal_resolver::Config {
                public_key: self.signer.public_key(),
                peer_provider: self.manager.clone(),
                blocker: self.blocker.clone(),
                mailbox_size: MAILBOX_SIZE,
                initial: STATE_SYNC_INITIAL,
                timeout: STATE_SYNC_TIMEOUT,
                fetch_retry_timeout: STATE_SYNC_RETRY,
                priority_requests: false,
                priority_responses: false,
            },
            channels.marshal_resolver,
        );

        let state_resolver_handle = self.state_resolver.start(channels.state_resolver);
        let transaction_resolver_handle = self
            .transaction_resolver
            .start(channels.transaction_resolver);
        let committee_resolver_handle = self.committee_resolver.start(channels.committee_resolver);
        let shard_handle = self.shards.start(channels.marshal);
        let stateful_handle = self.stateful.start();
        let probe_handle = self.probe;
        let reshare_handle = self.reshare.start(channels.dkg);
        let orchestrator_handle =
            self.orchestrator
                .start(channels.votes, channels.certificates, channels.resolver);
        #[expect(
            clippy::type_complexity,
            reason = "the annotation selects the reporter/Option Reporters constructor"
        )]
        let reshare_reporters: Reporters<
            Update<EngineBlock<H, C, V>>,
            reshare::Mailbox<EngineBlock<H, C, V>, V, C>,
            Rep,
        > = Reporters::from((self.reshare_mailbox, reporter));
        let reporters = Reporters::from((
            self.stateful_mailbox,
            Reporters::from((self.orchestrator_mailbox, reshare_reporters)),
        ));
        let marshal_handle = self
            .marshal
            .start(reporters, self.shard_mailbox, marshal_resolver);

        let handles = vec![
            probe_handle,
            state_resolver_handle,
            transaction_resolver_handle,
            committee_resolver_handle,
            shard_handle,
            stateful_handle,
            reshare_handle,
            orchestrator_handle,
            marshal_handle,
        ];
        if let Err(error) = try_join_all(handles).await {
            error!(?error, "engine task failed");
        } else {
            warn!("engine stopped");
        }
    }
}

fn threshold_scheme<C, V>(
    namespace: &[u8],
    output: &Output<V, C::PublicKey>,
    share: Option<group::Share>,
) -> ThresholdScheme<C::PublicKey, V>
where
    C: Signer,
    V: Variant,
{
    let participants = output.players().clone();
    match share {
        Some(share) => {
            ThresholdScheme::signer(namespace, participants, output.public().clone(), share)
                .expect("share must belong to the configured threshold output")
        }
        None => ThresholdScheme::verifier(namespace, participants, output.public().clone()),
    }
}

type BlockTargets<D> = (
    StateSyncTarget<D>,
    TransactionHistoryTarget<D>,
    CommitteeSyncTarget<D>,
);

fn block_targets<H, C, V>(block: &EngineBlock<H, C, V>) -> BlockTargets<H::Digest>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    (
        StateSyncTarget::new(
            block.header.state_root,
            non_empty_range!(
                mmr::Location::new(block.header.state_range.start()),
                mmr::Location::new(block.header.state_range.end())
            ),
        ),
        TransactionHistoryTarget {
            root: block.header.transactions_root,
            leaf_count: mmr::Location::new(block.header.transactions_range.end()),
        },
        CommitteeSyncTarget::new(
            block.header.committee_root,
            non_empty_range!(
                mmr::Location::new(block.header.committee_range.start()),
                mmr::Location::new(block.header.committee_range.end())
            ),
        ),
    )
}

async fn init_finalizations_archive<E, H, P, V>(
    context: &E,
    page_cache: &CacheRef,
    partition_prefix: &str,
    items_per_section: NonZero<u64>,
) -> PrunableArchive<EightCap, E, H::Digest, Finalization<ThresholdScheme<P, V>, Commitment>>
where
    E: BufferPooler + Spawner + Metrics + CryptoRng + Clock + Storage + Network,
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    let start = Instant::now();
    let archive = prunable::Archive::init(
        context.child("finalizations_by_height"),
        prunable::Config {
            translator: EightCap,
            key_partition: format!("{partition_prefix}-finalizations-by-height-key"),
            key_page_cache: page_cache.clone(),
            value_partition: format!("{partition_prefix}-finalizations-by-height-value"),
            compression: FREEZER_VALUE_COMPRESSION,
            items_per_section,
            codec_config: ThresholdScheme::<P, V>::certificate_codec_config_unbounded(),
            replay_buffer: REPLAY_BUFFER,
            key_write_buffer: WRITE_BUFFER,
            value_write_buffer: WRITE_BUFFER,
        },
    )
    .await
    .expect("failed to initialize finalizations archive");
    info!(elapsed = ?start.elapsed(), "restored finalizations archive");
    archive
}

async fn init_finalized_blocks_archive<E, H, C, V>(
    context: &E,
    page_cache: &CacheRef,
    partition_prefix: &str,
    block_codec: &EngineBlockCfg<C, V>,
    items_per_section: NonZero<u64>,
) -> PrunableArchive<EightCap, E, H::Digest, CodingBlock<H, C, V>>
where
    E: BufferPooler + Spawner + Metrics + CryptoRng + Clock + Storage + Network,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    let start = Instant::now();
    let archive = prunable::Archive::init(
        context.child("finalized_blocks"),
        prunable::Config {
            translator: EightCap,
            key_partition: format!("{partition_prefix}-finalized-blocks-key"),
            key_page_cache: page_cache.clone(),
            value_partition: format!("{partition_prefix}-finalized-blocks-value"),
            compression: FREEZER_VALUE_COMPRESSION,
            items_per_section,
            codec_config: block_codec.clone(),
            replay_buffer: REPLAY_BUFFER,
            key_write_buffer: WRITE_BUFFER,
            value_write_buffer: WRITE_BUFFER,
        },
    )
    .await
    .expect("failed to initialize finalized blocks archive");
    info!(elapsed = ?start.elapsed(), "restored finalized blocks archive");
    archive
}

fn state_db_config<T>(
    partition_prefix: &str,
    page_cache: &CacheRef,
    strategy: T,
) -> FixedConfig<EightCap, T>
where
    T: Strategy,
{
    FixedConfig {
        merkle_config: MmrConfig {
            journal_partition: format!("{partition_prefix}-state-journal"),
            metadata_partition: format!("{partition_prefix}-state-metadata"),
            items_per_blob: ITEMS_PER_BLOB,
            write_buffer: DB_WRITE_BUFFER,
            strategy,
            page_cache: page_cache.clone(),
        },
        journal_config: FixedJournalConfig {
            partition: format!("{partition_prefix}-state-log"),
            items_per_blob: ITEMS_PER_BLOB,
            page_cache: page_cache.clone(),
            write_buffer: DB_WRITE_BUFFER,
        },
        translator: EightCap,
        init_cache_size: Some(STATE_INIT_CACHE_SIZE),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

fn transaction_db_config<T>(
    partition_prefix: &str,
    page_cache: &CacheRef,
    strategy: T,
) -> keyless_fixed::CompactConfig<T>
where
    T: Strategy,
{
    keyless_fixed::CompactConfig {
        strategy,
        witness: VariableJournalConfig {
            partition: format!("{partition_prefix}-transactions-witness"),
            items_per_section: WITNESS_ITEMS_PER_SECTION,
            compression: None,
            codec_config: (),
            page_cache: page_cache.clone(),
            write_buffer: DB_WRITE_BUFFER,
        },
        commit_codec_config: (),
    }
}

fn committee_db_config<T>(
    partition_prefix: &str,
    page_cache: &CacheRef,
    strategy: T,
) -> FixedConfig<EightCap, T>
where
    T: Strategy,
{
    FixedConfig {
        merkle_config: MmrConfig {
            journal_partition: format!("{partition_prefix}-committee-journal"),
            metadata_partition: format!("{partition_prefix}-committee-metadata"),
            items_per_blob: ITEMS_PER_BLOB,
            write_buffer: DB_WRITE_BUFFER,
            strategy,
            page_cache: page_cache.clone(),
        },
        journal_config: FixedJournalConfig {
            partition: format!("{partition_prefix}-committee-log"),
            items_per_blob: ITEMS_PER_BLOB,
            page_cache: page_cache.clone(),
            write_buffer: DB_WRITE_BUFFER,
        },
        translator: EightCap,
        init_cache_size: Some(STATE_INIT_CACHE_SIZE),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

#[cfg(test)]
mod catalog_tests {
    use super::{bootstrap_socket_addresses, genesis_directory_root};
    use commonware_cryptography::{Signer as _, ed25519, sha256};
    use commonware_p2p::Address;
    use commonware_utils::ordered::Map;
    use std::net::SocketAddr;

    fn address(port: u16) -> Address {
        format!("127.0.0.1:{port}")
            .parse::<SocketAddr>()
            .unwrap()
            .into()
    }

    #[test]
    fn genesis_directory_root_is_canonical_and_commits_keys_and_addresses() {
        let a = ed25519::PrivateKey::from_seed(1).public_key();
        let b = ed25519::PrivateKey::from_seed(2).public_key();
        let canonical =
            Map::try_from([(a.clone(), address(1001)), (b.clone(), address(1002))]).unwrap();
        let reordered =
            Map::try_from([(b.clone(), address(1002)), (a.clone(), address(1001))]).unwrap();
        let changed_address =
            Map::try_from([(b.clone(), address(1003)), (a, address(1001))]).unwrap();
        let changed_key = Map::try_from([(b, address(1002))]).unwrap();

        let root = genesis_directory_root::<sha256::Sha256, _>(&canonical);
        assert_eq!(
            root,
            genesis_directory_root::<sha256::Sha256, _>(&reordered)
        );
        assert_ne!(
            root,
            genesis_directory_root::<sha256::Sha256, _>(&changed_address)
        );
        assert_ne!(
            root,
            genesis_directory_root::<sha256::Sha256, _>(&changed_key)
        );
    }

    #[test]
    fn bootstrap_addresses_convert_symmetric_sockets() {
        let peer = ed25519::PrivateKey::from_seed(1).public_key();
        let socket: SocketAddr = "127.0.0.1:1001".parse().unwrap();
        let addresses = bootstrap_socket_addresses(&Map::from_iter_dedup([(
            peer.clone(),
            Address::Symmetric(socket),
        )]));

        assert_eq!(addresses.get_value(&peer), Some(&socket));
    }

    #[test]
    #[should_panic(expected = "must have a symmetric socket address")]
    fn bootstrap_addresses_reject_asymmetric_addresses() {
        let peer = ed25519::PrivateKey::from_seed(1).public_key();
        let socket: SocketAddr = "127.0.0.1:1001".parse().unwrap();
        let asymmetric = Address::Asymmetric {
            ingress: socket.into(),
            egress: socket,
        };

        let _ = bootstrap_socket_addresses(&Map::from_iter_dedup([(peer, asymmetric)]));
    }
}
