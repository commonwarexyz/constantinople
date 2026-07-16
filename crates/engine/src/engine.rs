//! Fixed-epoch engine assembly.
//!
//! The engine keeps the consensus stack deliberately small:
//!
//! - `constantinople-application` owns execution
//! - `commonware-glue::stateful` owns QMDB lifecycle and startup sync
//! - erasure-coded marshal owns finalized block availability
//! - one simplex engine runs forever in epoch zero
//!
//! There is no DKG actor and no epoch orchestrator. The validator set and
//! threshold scheme are fixed at startup from the supplied threshold output and
//! optional local share.

use crate::types::*;
use commonware_coding::CodecConfig;
use commonware_consensus::{
    Reporter, Reporters,
    marshal::{
        self, Update,
        coding::{Marshaled, MarshaledConfig, shards, types::coding_config_for_participants},
        core::{Actor as MarshalActor, Variant as MarshalVariant},
        resolver::p2p as marshal_resolver,
    },
    simplex::{
        self, config::Floor as SimplexFloor, elector::Config as Elector, types::Finalization,
    },
    types::{Epoch, FixedEpocher, ViewDelta, coding::Commitment},
};
use commonware_cryptography::{
    BatchVerifier, Committable, Digest, Hasher, PublicKey, Signer,
    bls12381::{
        dkg::feldman_desmedt::Output,
        primitives::{group, variant::Variant},
    },
    certificate::{ConstantProvider, Verifier},
};
use commonware_glue::stateful::{
    Config as StatefulConfig, PruneConfig, Stateful, SyncPlan,
    db::{ManagedDb, SyncEngineConfig, p2p as qmdb_resolver},
};
use commonware_macros::boxed;
use commonware_p2p::{Blocker, Manager, Receiver, Sender};
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
use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range, union};
use constantinople_application::consensus::{
    Application, FinalizedHookFn, StateSyncTarget, TransactionHistoryTarget,
};
use constantinople_mempool::TransactionSource;
use constantinople_primitives::{BlockCfg, PublicKeyCache};
use futures::future::try_join_all;
use rand::CryptoRng;
use std::{
    num::{NonZero, NonZeroU16},
    time::{Duration, Instant},
};
use tracing::{error, info, warn};

/// The fixed threshold scheme used by simplex and marshal.
pub type ThresholdScheme<P, V> = simplex::scheme::bls12381_threshold::standard::Scheme<P, V>;

const FIXED_EPOCH_LENGTH: NonZero<u64> = NZU64!(u64::MAX);
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
/// State-sync probe channel id.
pub const PROBE_CHANNEL: u64 = 7;

/// All channel ids used by the engine, including the state-sync probe.
pub const CHANNELS: [u64; 8] = [
    VOTE_CHANNEL,
    CERTIFICATE_CHANNEL,
    RESOLVER_CHANNEL,
    MARSHAL_CHANNEL,
    MARSHAL_RESOLVER_CHANNEL,
    STATE_RESOLVER_CHANNEL,
    TRANSACTION_RESOLVER_CHANNEL,
    PROBE_CHANNEL,
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

pub struct Config<E, C, M, B, V, St, I, H, O>
where
    E: BufferPooler + Storage + Clock + Metrics,
    C: Signer,
    M: Manager<PublicKey = C::PublicKey>,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    St: Strategy,
    H: Hasher,
    O: Reporter<Activity = EngineActivity<C::PublicKey, V>>,
{
    pub signer: C,
    pub manager: M,
    pub blocker: B,
    pub namespace: Vec<u8>,
    pub output: Output<V, C::PublicKey>,
    pub share: Option<group::Share>,
    pub input: I,
    pub partition_prefix: String,
    pub strategy: St,
    pub public_key_cache: PublicKeyCache,
    pub startup: StartupMode,
    pub sync_config: SyncEngineConfig,
    pub prune_config: Option<PruneConfig>,
    pub genesis_leader: C::PublicKey,
    pub transaction_namespace: &'static [u8],
    pub block_codec: BlockCfg,
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
    pub probe: Option<EngineProbeMailbox<H, C::PublicKey, V>>,
    /// Optional external observer of the simplex activity stream. The marshal
    /// reporter is always wired up; this slot is fanned out via
    /// [`commonware_consensus::Reporters`] so primaries that pass `None`
    /// behave exactly as before.
    pub simplex_observer: Option<O>,
    /// Optional hook that observes finalized blocks after local database
    /// application and before state pruning.
    pub finalized_hook: Option<FinalizedHookFn<E, Commitment, H, C::PublicKey, St>>,
}

/// Fully assembled validator engine.
pub struct Engine<E, C, M, B, H, V, L, St, I, BV, O>
where
    E: BufferPooler + Spawner + Metrics + CryptoRng + Clock + Storage + Network,
    C: Signer,
    M: Manager<PublicKey = C::PublicKey>,
    B: Blocker<PublicKey = C::PublicKey>,
    H: Hasher,
    V: Variant,
    L: Elector<ThresholdScheme<C::PublicKey, V>>,
    St: Strategy,
    I: TransactionSource<Commitment, C::PublicKey, H> + Sync,
    BV: BatchVerifier<PublicKey = C::PublicKey> + Send + Sync + 'static,
    O: Reporter<Activity = EngineActivity<C::PublicKey, V>>,
{
    context: ContextCell<E>,
    signer: C,
    manager: M,
    blocker: B,
    state_resolver: StateResolverActor<E, C::PublicKey, M, B, H, St>,
    transaction_resolver: TransactionResolverActor<E, C::PublicKey, M, B, H, St>,
    stateful: StatefulApp<E, H, C::PublicKey, V, I, BV, St>,
    stateful_mailbox: AppMailbox<E, H, C::PublicKey, V, I, BV, St>,
    shards: ShardsEngine<E, B, M, H, C::PublicKey, V, St>,
    shard_mailbox: ShardsMailbox<H, C::PublicKey>,
    #[expect(
        clippy::type_complexity,
        reason = "marshal actor type is inherently complex"
    )]
    marshal: MarshalActor<
        E,
        EngineVariant<H, C::PublicKey>,
        SchemeProvider<C::PublicKey, V>,
        PrunableArchive<
            EightCap,
            E,
            H::Digest,
            Finalization<ThresholdScheme<C::PublicKey, V>, Commitment>,
        >,
        PrunableArchive<EightCap, E, H::Digest, CodingBlock<H, C::PublicKey>>,
        FixedEpocher,
        St,
    >,
    #[cfg(all(test, feature = "test-utils"))]
    marshal_mailbox: EngineMarshalMailbox<H, C::PublicKey, V>,
    #[cfg(all(test, feature = "test-utils"))]
    startup_sync_floor: Option<EngineFinalization<C::PublicKey, V>>,
    #[cfg(all(test, feature = "test-utils"))]
    genesis_commitment: Commitment,
    simplex: SimplexEngine<E, B, H, C::PublicKey, V, L, St, I, BV, O>,
}

impl<E, C, M, B, H, V, L, St, I, BV, O> Engine<E, C, M, B, H, V, L, St, I, BV, O>
where
    E: BufferPooler + Spawner + Metrics + CryptoRng + Clock + Storage + Network,
    C: Signer,
    M: Manager<PublicKey = C::PublicKey>,
    B: Blocker<PublicKey = C::PublicKey>,
    H: Hasher,
    V: Variant,
    L: Elector<ThresholdScheme<C::PublicKey, V>>,
    St: Strategy,
    I: TransactionSource<Commitment, C::PublicKey, H> + Sync,
    BV: BatchVerifier<PublicKey = C::PublicKey> + Send + Sync + 'static,
    O: Reporter<Activity = EngineActivity<C::PublicKey, V>>,
{
    #[cfg(all(test, feature = "test-utils"))]
    pub(crate) fn marshal_mailbox(&self) -> EngineMarshalMailbox<H, C::PublicKey, V> {
        self.marshal_mailbox.clone()
    }

    #[cfg(all(test, feature = "test-utils"))]
    pub(crate) fn startup_sync_floor(&self) -> Option<EngineFinalization<C::PublicKey, V>> {
        self.startup_sync_floor.clone()
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

    /// Initializes the full engine stack.
    #[boxed]
    pub async fn new(context: E, config: Config<E, C, M, B, V, St, I, H, O>) -> Self {
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
        let epocher = FixedEpocher::new(FIXED_EPOCH_LENGTH);
        let scheme =
            threshold_scheme::<C, V>(&consensus_namespace, &config.output, config.share.clone());
        let provider =
            ConstantProvider::<ThresholdScheme<C::PublicKey, V>, Epoch>::new(scheme.clone());

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
            init_finalized_blocks_archive::<E, H, C::PublicKey>(
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
        let stateful_partition_prefix = format!("{}_stateful", config.partition_prefix);
        let stateful_startup_context = context.child("stateful_startup");
        let mut startup_plan =
            SyncPlan::<E, ThresholdScheme<C::PublicKey, V>, EngineVariant<H, C::PublicKey>>::init(
                &stateful_startup_context,
                stateful_partition_prefix.clone(),
            )
            .await;

        // The durable plan distinguishes normal recovery from peer state sync. Normal recovery
        // stays floorless so marshal restores its acknowledged progress; only a requested or
        // interrupted state sync discovers a new floor.
        let state_sync_requested = matches!(&config.startup, StartupMode::StateSync);
        if startup_plan.should_state_sync(state_sync_requested) {
            let finalization = config
                .probe
                .as_ref()
                .expect("state sync requires a probe mailbox")
                .subscribe()
                .await
                .expect("probe actor exited before selecting a state-sync floor");
            startup_plan = startup_plan.with_floor(finalization);
        }

        // The canonical genesis is a pure function of configuration: the leader, the
        // participant-derived coding config, and the canonical empty-database roots.
        let genesis_block = constantinople_application::consensus::genesis_block_with_parent(
            &mut H::default(),
            config.genesis_leader.clone(),
            (commonware_consensus::types::View::zero(), genesis_parent),
            0,
            <StateDb<E, H, St> as ManagedDb<E>>::initial_sync_target(),
            <TransactionDb<E, H, St> as ManagedDb<E>>::initial_sync_target(),
        );
        let coded_genesis = EngineCodedBlock::new(genesis_block, coding_config, &config.strategy);
        let application_genesis =
            <EngineVariant<H, C::PublicKey> as MarshalVariant>::into_inner(coded_genesis.clone());
        let (application_state_target, application_transactions_target) =
            block_targets(&application_genesis);

        #[cfg(all(test, feature = "test-utils"))]
        let startup_sync_floor = startup_plan.floor().cloned();
        // Simplex adopts the peer floor only for state sync. Otherwise it independently replays
        // its journal from canonical genesis while marshal restores application progress.
        let genesis_commitment = coded_genesis.commitment();
        let simplex_floor = startup_plan.floor().map_or_else(
            || SimplexFloor::Genesis(genesis_commitment),
            |finalization| SimplexFloor::Finalized(finalization.clone()),
        );
        let marshal_start = startup_plan.marshal_start(coded_genesis);

        let (marshal, marshal_mailbox, _) = MarshalActor::init(
            context.child("marshal"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider: provider.clone(),
                epocher: epocher.clone(),
                start: marshal_start,
                partition_prefix: format!("{}_marshal", config.partition_prefix),
                mailbox_size: MAILBOX_SIZE,
                view_retention_timeout: ACTIVITY_TIMEOUT,
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
        if let Some(probe) = &config.probe {
            probe.attach(marshal_mailbox.clone());
        }

        let (shards, shard_mailbox) = shards::Engine::new(
            context.child("shards"),
            shards::Config {
                scheme_provider: provider.clone(),
                blocker: config.blocker.clone(),
                shard_codec_cfg: CodecConfig {
                    maximum_shard_size: 1024 * 1024,
                },
                block_codec_cfg: config.block_codec.clone(),
                strategy: config.strategy.clone(),
                mailbox_size: MAILBOX_SIZE,
                peer_buffer_size: SHARD_PEER_BUFFER_SIZE,
                background_channel_capacity: SHARD_BACKGROUND_CHANNEL_CAPACITY,
                peer_provider: config.manager.clone(),
            },
        );
        let application = Application::new(
            context.child("application"),
            config.strategy.clone(),
            config.genesis_leader.clone(),
            genesis_parent,
            config.transaction_namespace,
            config.public_key_cache,
            application_state_target,
            application_transactions_target,
            config.finalized_hook,
        );
        let (stateful, stateful_mailbox) = Stateful::init(
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
                ),
                input_provider: config.input,
                marshal: marshal_mailbox.clone(),
                mailbox_size: MAILBOX_SIZE,
                plan: startup_plan,
                resolvers: (state_sync_resolver, transaction_sync_resolver),
                sync_config: config.sync_config,
                prune_config: config.prune_config,
            },
        );

        let application = Marshaled::new(
            context.child("application"),
            MarshaledConfig {
                application: stateful_mailbox.clone(),
                marshal: marshal_mailbox.clone(),
                shards: shard_mailbox.clone(),
                scheme_provider: provider,
                strategy: config.strategy.clone(),
                epocher,
            },
        );
        // Fan simplex activity to the marshal mailbox and any external
        // observer (e.g. the indexer's certificate publisher). When
        // `simplex_observer` is `None`, this combinator is equivalent to
        // forwarding activity to the marshal mailbox alone — primaries that
        // pass `None` see exactly the previous behavior.
        #[cfg(all(test, feature = "test-utils"))]
        let simplex_reporter: SimplexReporter<H, C::PublicKey, V, O> =
            Reporters::from((marshal_mailbox.clone(), config.simplex_observer));
        #[cfg(not(all(test, feature = "test-utils")))]
        let simplex_reporter: SimplexReporter<H, C::PublicKey, V, O> =
            Reporters::from((marshal_mailbox, config.simplex_observer));

        let simplex = simplex::Engine::new(
            context.child("simplex"),
            simplex::Config {
                scheme,
                elector: L::default(),
                blocker: config.blocker.clone(),
                automaton: application.clone(),
                relay: application,
                reporter: simplex_reporter,
                strategy: config.strategy.clone(),
                partition: format!("{}_simplex", config.partition_prefix),
                mailbox_size: MAILBOX_SIZE,
                epoch: Epoch::zero(),
                floor: simplex_floor,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache,
                leader_timeout: Duration::from_secs(4),
                certification_timeout: Duration::from_secs(8),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(4),
                activity_timeout: ACTIVITY_TIMEOUT,
                skip_timeout: ViewDelta::new(10),
                fetch_concurrent: NZUsize!(32),
                forwarding: simplex::ForwardingPolicy::Disabled,
            },
        );

        Self {
            context: ContextCell::new(context),
            signer: config.signer,
            manager: config.manager,
            blocker: config.blocker,
            state_resolver,
            transaction_resolver,
            stateful,
            stateful_mailbox,
            shards,
            shard_mailbox,
            marshal,
            #[cfg(all(test, feature = "test-utils"))]
            marshal_mailbox,
            #[cfg(all(test, feature = "test-utils"))]
            startup_sync_floor,
            #[cfg(all(test, feature = "test-utils"))]
            genesis_commitment,
            simplex,
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
        Rep: Reporter<Activity = Update<EngineBlock<H, C::PublicKey>>>,
    {
        spawn_cell!(self.context, self.run(channels, reporter))
    }

    async fn run<Sx, Rx, Rep>(self, channels: Channels<C::PublicKey, Sx, Rx>, reporter: Option<Rep>)
    where
        Sx: Sender<PublicKey = C::PublicKey>,
        Rx: Receiver<PublicKey = C::PublicKey>,
        Rep: Reporter<Activity = Update<EngineBlock<H, C::PublicKey>>>,
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
        let shard_handle = self.shards.start(channels.marshal);
        let stateful_handle = self.stateful.start();

        let reporters: Reporters<Update<EngineBlock<H, C::PublicKey>>, _, Rep> =
            Reporters::from((self.stateful_mailbox, reporter));
        let marshal_handle = self
            .marshal
            .start(reporters, self.shard_mailbox, marshal_resolver);
        let simplex_handle =
            self.simplex
                .start(channels.votes, channels.certificates, channels.resolver);

        if let Err(error) = try_join_all(vec![
            state_resolver_handle,
            transaction_resolver_handle,
            shard_handle,
            stateful_handle,
            marshal_handle,
            simplex_handle,
        ])
        .await
        {
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

fn block_targets<H, P>(
    block: &EngineBlock<H, P>,
) -> (
    StateSyncTarget<H::Digest>,
    TransactionHistoryTarget<H::Digest>,
)
where
    H: Hasher,
    P: PublicKey,
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

async fn init_finalized_blocks_archive<E, H, P>(
    context: &E,
    page_cache: &CacheRef,
    partition_prefix: &str,
    block_codec: &BlockCfg,
    items_per_section: NonZero<u64>,
) -> PrunableArchive<EightCap, E, H::Digest, CodingBlock<H, P>>
where
    E: BufferPooler + Spawner + Metrics + CryptoRng + Clock + Storage + Network,
    H: Hasher,
    P: PublicKey,
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
