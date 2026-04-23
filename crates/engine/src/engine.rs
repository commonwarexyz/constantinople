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

use crate::{bootstrapper, types::*};
use commonware_coding::CodecConfig;
use commonware_consensus::{
    Reporter, Reporters,
    marshal::{
        self, Update,
        coding::{Marshaled, MarshaledConfig, shards},
        core::Actor as MarshalActor,
        resolver::p2p as marshal_resolver,
    },
    simplex::{self, elector::Config as Elector, types::Finalization},
    types::{Epoch, FixedEpocher, ViewDelta, coding::Commitment},
};
use commonware_cryptography::{
    BatchVerifier, Hasher, PublicKey, Signer,
    bls12381::{
        dkg::Output,
        primitives::{group, variant::Variant},
    },
    certificate::{ConstantProvider, Scheme},
};
use commonware_glue::stateful::{
    Config as StatefulConfig, StartupMode, Stateful,
    db::{ManagedDb, SyncEngineConfig, p2p as qmdb_resolver},
};
use commonware_p2p::{Blocker, Manager, Receiver, Sender};
use commonware_parallel::{Strategy, ThreadPool};
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Network, Spawner, Storage, ThreadPooler,
    buffer::paged::CacheRef, spawn_cell,
};
use commonware_storage::{
    archive::immutable,
    journal::contiguous::fixed::Config as FixedJournalConfig,
    mmr::{self, journaled::Config as MmrConfig},
    qmdb::{any::FixedConfig, keyless::fixed as keyless_fixed},
    translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, union};
use constantinople_application::consensus::Application;
use constantinople_mempool::TransactionSource;
use constantinople_primitives::BlockCfg;
use futures::future::try_join_all;
use rand_core::CryptoRngCore;
use std::{
    num::{NonZero, NonZeroU16, NonZeroU64},
    time::{Duration, Instant},
};
use tracing::{error, info, warn};

/// The fixed threshold VRF scheme used by simplex and marshal.
pub type ThresholdScheme<P, V> = simplex::scheme::bls12381_threshold::vrf::Scheme<P, V>;

const FIXED_EPOCH_LENGTH: NonZero<u64> = NZU64!(u64::MAX);
const MAILBOX_SIZE: usize = 1024;
const ACTIVITY_TIMEOUT: ViewDelta = ViewDelta::new(256);
const PRUNABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(4_096);
const IMMUTABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(262_144);
const FREEZER_TABLE_RESIZE_FREQUENCY: u8 = 4;
const FREEZER_TABLE_RESIZE_CHUNK_SIZE: u32 = 2u32.pow(16);
const FREEZER_VALUE_TARGET_SIZE: u64 = 1024 * 1024 * 1024;
const FREEZER_VALUE_COMPRESSION: Option<u8> = Some(3);
const REPLAY_BUFFER: NonZero<usize> = NZUsize!(8 * 1024 * 1024);
const WRITE_BUFFER: NonZero<usize> = NZUsize!(1024 * 1024);
const PAGE_CACHE_PAGE_SIZE: NonZeroU16 = NZU16!(8192); // 8 KiB
const PAGE_CACHE_CAPACITY: NonZero<usize> = NZUsize!(65536); // 512 MiB
const ITEMS_PER_BLOB: NonZero<u64> = NZU64!(1_048_576 * 25); // ~1gb
const MAX_REPAIR: NonZero<usize> = NZUsize!(200);
const MAX_PENDING_ACKS: NonZero<usize> = NZUsize!(16);
const SHARD_BACKGROUND_CHANNEL_CAPACITY: usize = 1024;
const SHARD_PEER_BUFFER_SIZE: NonZero<usize> = NZUsize!(64);
const DB_WRITE_BUFFER: NonZero<usize> = NZUsize!(1_048_576);
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
/// Bootstrapper channel id.
pub const BOOTSTRAPPER_CHANNEL: u64 = 7;

/// All channel ids used by the engine, including the bootstrapper.
pub const CHANNELS: [u64; 8] = [
    VOTE_CHANNEL,
    CERTIFICATE_CHANNEL,
    RESOLVER_CHANNEL,
    MARSHAL_CHANNEL,
    MARSHAL_RESOLVER_CHANNEL,
    STATE_RESOLVER_CHANNEL,
    TRANSACTION_RESOLVER_CHANNEL,
    BOOTSTRAPPER_CHANNEL,
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

/// Engine initialization parameters.
pub struct Config<C, M, B, V, T, I, H>
where
    C: Signer,
    M: Manager<PublicKey = C::PublicKey>,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    T: Strategy,
    H: Hasher,
{
    pub signer: C,
    pub manager: M,
    pub blocker: B,
    pub namespace: Vec<u8>,
    pub output: Output<V, C::PublicKey>,
    pub share: Option<group::Share>,
    pub input: I,
    pub partition_prefix: String,
    pub freezer_table_initial_size: u32,
    pub strategy: T,
    pub startup: StartupMode<EngineBlock<H, C::PublicKey>>,
    pub sync_config: SyncEngineConfig,
    pub genesis_leader: C::PublicKey,
    pub transaction_namespace: &'static [u8],
    pub transaction_history_prune_cadence: Option<NonZeroU64>,
    pub block_codec: BlockCfg,
    pub bootstrapper: bootstrapper::Mailbox<H, C::PublicKey, V>,
}

/// Fully assembled validator engine.
pub struct Engine<E, C, M, B, H, V, L, T, I, BV>
where
    E: BufferPooler + Spawner + Metrics + CryptoRngCore + Clock + Storage + Network + ThreadPooler,
    C: Signer,
    M: Manager<PublicKey = C::PublicKey>,
    B: Blocker<PublicKey = C::PublicKey>,
    H: Hasher,
    V: Variant,
    L: Elector<ThresholdScheme<C::PublicKey, V>>,
    T: Strategy,
    I: TransactionSource<Commitment, C::PublicKey, H> + Sync,
    BV: BatchVerifier<PublicKey = C::PublicKey> + Send + Sync + 'static,
{
    context: ContextCell<E>,
    signer: C,
    manager: M,
    blocker: B,
    state_resolver: qmdb_resolver::Actor<E, C::PublicKey, M, B, mmr::Family, StateDb<E, H>>,
    transaction_resolver:
        qmdb_resolver::Actor<E, C::PublicKey, M, B, mmr::Family, TransactionDb<E, H>>,
    stateful: StatefulApp<E, H, C::PublicKey, V, I, BV, T>,
    stateful_mailbox: AppMailbox<E, H, C::PublicKey, V, I, BV, T>,
    shards: ShardsEngine<E, B, M, H, C::PublicKey, V, T>,
    shard_mailbox: ShardsMailbox<H, C::PublicKey>,
    #[expect(
        clippy::type_complexity,
        reason = "marshal actor type is inherently complex"
    )]
    marshal: MarshalActor<
        E,
        EngineVariant<H, C::PublicKey>,
        SchemeProvider<C::PublicKey, V>,
        immutable::Archive<
            E,
            H::Digest,
            Finalization<ThresholdScheme<C::PublicKey, V>, Commitment>,
        >,
        immutable::Archive<E, H::Digest, CodingBlock<H, C::PublicKey>>,
        FixedEpocher,
        T,
    >,
    #[cfg(all(test, feature = "test-utils"))]
    marshal_mailbox: EngineMarshalMailbox<H, C::PublicKey, V>,
    simplex: SimplexEngine<E, B, H, C::PublicKey, V, L, T, I, BV>,
}

impl<E, C, M, B, H, V, L, T, I, BV> Engine<E, C, M, B, H, V, L, T, I, BV>
where
    E: BufferPooler + Spawner + Metrics + CryptoRngCore + Clock + Storage + Network + ThreadPooler,
    C: Signer,
    M: Manager<PublicKey = C::PublicKey>,
    B: Blocker<PublicKey = C::PublicKey>,
    H: Hasher,
    V: Variant,
    L: Elector<ThresholdScheme<C::PublicKey, V>>,
    T: Strategy,
    I: TransactionSource<Commitment, C::PublicKey, H> + Sync,
    BV: BatchVerifier<PublicKey = C::PublicKey> + Send + Sync + 'static,
{
    #[cfg(all(test, feature = "test-utils"))]
    pub(crate) fn marshal_mailbox(&self) -> EngineMarshalMailbox<H, C::PublicKey, V> {
        self.marshal_mailbox.clone()
    }

    /// Returns the state database once the stateful actor has initialized it.
    /// Blocks until the database is ready.
    pub async fn subscribe_databases(&self) -> StateSyncDb<E, H> {
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
    ) -> impl std::future::Future<Output = StateSyncDb<E, H>> + Send + 'static {
        let mailbox = self.stateful_mailbox.clone();
        async move { mailbox.subscribe_databases().await.0 }
    }

    /// Initializes the full engine stack.
    pub async fn new(context: E, config: Config<C, M, B, V, T, I, H>) -> Self {
        let page_cache = CacheRef::from_pooler(
            &context.with_label("other"),
            PAGE_CACHE_PAGE_SIZE,
            PAGE_CACHE_CAPACITY,
        );
        let storage_page_cache = CacheRef::from_pooler(
            &context.with_label("state"),
            PAGE_CACHE_PAGE_SIZE,
            PAGE_CACHE_CAPACITY,
        );
        let merkle_thread_pool = qmdb_merkle_thread_pool(&context, &config.strategy);
        let consensus_namespace = union(&config.namespace, b"_CONSENSUS");
        let epocher = FixedEpocher::new(FIXED_EPOCH_LENGTH);
        let scheme =
            threshold_scheme::<C, V>(&consensus_namespace, &config.output, config.share.clone());
        let provider =
            ConstantProvider::<ThresholdScheme<C::PublicKey, V>, Epoch>::new(scheme.clone());

        let (state_resolver, state_sync_resolver) =
            qmdb_resolver::Actor::<_, C::PublicKey, _, _, _, StateDb<E, H>>::new(
                context.with_label("state_resolver"),
                qmdb_resolver::Config {
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
            qmdb_resolver::Actor::<_, C::PublicKey, _, _, _, TransactionDb<E, H>>::new(
                context.with_label("transaction_resolver"),
                qmdb_resolver::Config {
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

        let (finalizations_by_height, finalized_blocks) = futures::join!(
            init_finalizations_archive::<E, H, C::PublicKey, V>(
                &context,
                &page_cache,
                &config.partition_prefix,
                config.freezer_table_initial_size,
            ),
            init_finalized_blocks_archive::<E, H, C::PublicKey>(
                &context,
                &page_cache,
                &config.partition_prefix,
                config.freezer_table_initial_size,
                &config.block_codec,
            ),
        );

        let (marshal, marshal_mailbox, _) = MarshalActor::init(
            context.with_label("marshal"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider: provider.clone(),
                epocher: epocher.clone(),
                partition_prefix: format!("{}_marshal", config.partition_prefix),
                mailbox_size: MAILBOX_SIZE,
                view_retention_timeout: ACTIVITY_TIMEOUT,
                prunable_items_per_section: PRUNABLE_ITEMS_PER_SECTION,
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
        config.bootstrapper.attach(marshal_mailbox.clone()).await;

        let (shards, shard_mailbox) = shards::Engine::new(
            context.with_label("shards"),
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
        let transaction_db_config = transaction_db_config(
            &config.partition_prefix,
            &storage_page_cache,
            merkle_thread_pool.as_ref(),
        );
        let genesis_transaction_db = TransactionDb::<E, H>::init(
            context.with_label("genesis_transactions"),
            transaction_db_config.clone(),
        )
        .await
        .expect("transaction history db must initialize for genesis target");
        let genesis_transactions_target =
            <TransactionDb<E, H> as ManagedDb<E>>::sync_target(&genesis_transaction_db).await;

        let application = Application::new(
            context.with_label("application"),
            config.strategy.clone(),
            config.genesis_leader.clone(),
            config.transaction_namespace,
            genesis_transactions_target,
            config.transaction_history_prune_cadence,
        );
        let (stateful, stateful_mailbox) = Stateful::init(
            context.with_label("stateful"),
            StatefulConfig {
                app: application,
                db_config: (
                    state_db_config(
                        &config.partition_prefix,
                        &storage_page_cache,
                        merkle_thread_pool.as_ref(),
                    ),
                    transaction_db_config,
                ),
                input_provider: config.input,
                marshal: marshal_mailbox.clone(),
                mailbox_size: MAILBOX_SIZE,
                partition_prefix: format!("{}_stateful", config.partition_prefix),
                startup: config.startup,
                resolvers: (state_sync_resolver, transaction_sync_resolver),
                sync_config: config.sync_config,
            },
        );

        let application = Marshaled::new(
            context.with_label("application"),
            MarshaledConfig {
                application: stateful_mailbox.clone(),
                marshal: marshal_mailbox.clone(),
                shards: shard_mailbox.clone(),
                scheme_provider: provider,
                strategy: config.strategy.clone(),
                epocher,
            },
        );
        #[cfg(all(test, feature = "test-utils"))]
        let simplex_reporter = marshal_mailbox.clone();
        #[cfg(not(all(test, feature = "test-utils")))]
        let simplex_reporter = marshal_mailbox;

        let simplex = simplex::Engine::new(
            context.with_label("simplex"),
            simplex::Config {
                scheme,
                elector: L::default(),
                blocker: config.blocker.clone(),
                automaton: application.clone(),
                relay: application,
                reporter: simplex_reporter,
                strategy: config.strategy,
                partition: format!("{}_simplex", config.partition_prefix),
                mailbox_size: MAILBOX_SIZE,
                epoch: Epoch::zero(),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache,
                leader_timeout: Duration::from_secs(4),
                certification_timeout: Duration::from_secs(8),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(4),
                activity_timeout: ACTIVITY_TIMEOUT,
                skip_timeout: ViewDelta::new(10),
                fetch_concurrent: 32,
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
        let marshal_resolver = marshal_resolver::init(
            self.context.as_present(),
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

async fn init_finalizations_archive<E, H, P, V>(
    context: &E,
    page_cache: &CacheRef,
    partition_prefix: &str,
    freezer_table_initial_size: u32,
) -> immutable::Archive<E, H::Digest, Finalization<ThresholdScheme<P, V>, Commitment>>
where
    E: BufferPooler + Spawner + Metrics + CryptoRngCore + Clock + Storage + Network,
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    let start = Instant::now();
    let archive = immutable::Archive::init(
        context.with_label("finalizations_by_height"),
        immutable::Config {
            metadata_partition: format!("{partition_prefix}-finalizations-by-height-metadata"),
            freezer_table_partition: format!(
                "{partition_prefix}-finalizations-by-height-freezer-table"
            ),
            freezer_table_initial_size,
            freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
            freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
            freezer_key_partition: format!(
                "{partition_prefix}-finalizations-by-height-freezer-key"
            ),
            freezer_key_page_cache: page_cache.clone(),
            freezer_value_partition: format!(
                "{partition_prefix}-finalizations-by-height-freezer-value"
            ),
            freezer_value_target_size: FREEZER_VALUE_TARGET_SIZE,
            freezer_value_compression: FREEZER_VALUE_COMPRESSION,
            ordinal_partition: format!("{partition_prefix}-finalizations-by-height-ordinal"),
            items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
            codec_config: ThresholdScheme::<P, V>::certificate_codec_config_unbounded(),
            replay_buffer: REPLAY_BUFFER,
            freezer_key_write_buffer: WRITE_BUFFER,
            freezer_value_write_buffer: WRITE_BUFFER,
            ordinal_write_buffer: WRITE_BUFFER,
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
    freezer_table_initial_size: u32,
    block_codec: &BlockCfg,
) -> immutable::Archive<E, H::Digest, CodingBlock<H, P>>
where
    E: BufferPooler + Spawner + Metrics + CryptoRngCore + Clock + Storage + Network,
    H: Hasher,
    P: PublicKey,
{
    let start = Instant::now();
    let archive = immutable::Archive::init(
        context.with_label("finalized_blocks"),
        immutable::Config {
            metadata_partition: format!("{partition_prefix}-finalized-blocks-metadata"),
            freezer_table_partition: format!("{partition_prefix}-finalized-blocks-freezer-table"),
            freezer_table_initial_size,
            freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
            freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
            freezer_key_partition: format!("{partition_prefix}-finalized-blocks-freezer-key"),
            freezer_key_page_cache: page_cache.clone(),
            freezer_value_partition: format!("{partition_prefix}-finalized-blocks-freezer-value"),
            freezer_value_target_size: FREEZER_VALUE_TARGET_SIZE,
            freezer_value_compression: FREEZER_VALUE_COMPRESSION,
            ordinal_partition: format!("{partition_prefix}-finalized-blocks-ordinal"),
            items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
            codec_config: block_codec.clone(),
            replay_buffer: REPLAY_BUFFER,
            freezer_key_write_buffer: WRITE_BUFFER,
            freezer_value_write_buffer: WRITE_BUFFER,
            ordinal_write_buffer: WRITE_BUFFER,
        },
    )
    .await
    .expect("failed to initialize finalized blocks archive");
    info!(elapsed = ?start.elapsed(), "restored finalized blocks archive");
    archive
}

fn qmdb_merkle_thread_pool<E, T>(context: &E, strategy: &T) -> Option<ThreadPool>
where
    E: ThreadPooler,
    T: Strategy,
{
    let parallelism = strategy.parallelism_hint();
    if parallelism <= 1 {
        return None;
    }

    let concurrency = NonZero::new(parallelism).expect("parallelism hint must be non-zero");
    Some(
        context
            .with_label("qmdb_merkle")
            .create_thread_pool(concurrency)
            .expect("failed to create QMDB merkleization thread pool"),
    )
}

fn state_db_config(
    partition_prefix: &str,
    page_cache: &CacheRef,
    thread_pool: Option<&ThreadPool>,
) -> FixedConfig<EightCap> {
    FixedConfig {
        merkle_config: MmrConfig {
            journal_partition: format!("{partition_prefix}-state-journal"),
            metadata_partition: format!("{partition_prefix}-state-metadata"),
            items_per_blob: ITEMS_PER_BLOB,
            write_buffer: DB_WRITE_BUFFER,
            thread_pool: thread_pool.cloned(),
            page_cache: page_cache.clone(),
        },
        journal_config: FixedJournalConfig {
            partition: format!("{partition_prefix}-state-log"),
            items_per_blob: ITEMS_PER_BLOB,
            page_cache: page_cache.clone(),
            write_buffer: DB_WRITE_BUFFER,
        },
        translator: EightCap,
    }
}

fn transaction_db_config(
    partition_prefix: &str,
    page_cache: &CacheRef,
    thread_pool: Option<&ThreadPool>,
) -> keyless_fixed::Config {
    keyless_fixed::Config {
        merkle: MmrConfig {
            journal_partition: format!("{partition_prefix}-transactions-journal"),
            metadata_partition: format!("{partition_prefix}-transactions-metadata"),
            items_per_blob: ITEMS_PER_BLOB,
            write_buffer: DB_WRITE_BUFFER,
            thread_pool: thread_pool.cloned(),
            page_cache: page_cache.clone(),
        },
        log: FixedJournalConfig {
            partition: format!("{partition_prefix}-transactions-log"),
            items_per_blob: ITEMS_PER_BLOB,
            page_cache: page_cache.clone(),
            write_buffer: DB_WRITE_BUFFER,
        },
    }
}
