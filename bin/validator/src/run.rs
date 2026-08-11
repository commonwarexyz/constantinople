//! Starts a validator from a YAML config.

use crate::{
    config::{LoadedConfig, StartupModeConfig, load_deployer_config, load_local_config},
    state_reader::StateDbReader,
};
use commonware_codec::Encode;
use commonware_consensus::{
    simplex::elector::RoundRobin,
    types::{Epoch, TermLength, ViewDelta, coding::Commitment},
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
use commonware_p2p::{Ingress, Manager as _, TrackedPeers, authenticated::discovery};
use commonware_parallel::Rayon;
use commonware_runtime::{
    BufferPoolConfig, Quota, Runner as _, Strategizer as _, Supervisor as _,
    tokio::{
        telemetry::{self, Logs},
        tracing::Config as TracesConfig,
    },
};
use commonware_utils::{NZDuration, NZU32, NZU64, NZUsize, TryCollect, ordered::Set, union};
use constantinople_engine::{
    CERTIFICATE_CHANNEL, Channels, Config as EngineConfig, Engine, MARSHAL_CHANNEL,
    MARSHAL_RESOLVER_CHANNEL, PROBE_CHANNEL, RESOLVER_CHANNEL, STATE_RESOLVER_CHANNEL, StartupMode,
    TRANSACTION_RESOLVER_CHANNEL, ThresholdScheme, VOTE_CHANNEL,
};
use constantinople_mempool::webserver::{self, AccountReader, Mailbox};
use constantinople_primitives::PublicKeyCache;
use std::{
    future::Future,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    path::PathBuf,
    pin::Pin,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tracing::info;

const MEMPOOL_MAILBOX_SIZE: usize = 65_536;
const STABLE_LEADER_STALL_TIMEOUT: Duration = Duration::from_secs(12);
const STABLE_LEADER_OPTIMISTIC_VIEWS: ViewDelta = ViewDelta::new(4);
const SIMPLEX_LEADER_TIMEOUT: Duration = Duration::from_secs(4);
const SIMPLEX_CERTIFICATION_TIMEOUT: Duration = Duration::from_secs(8);
const SIMPLEX_TIMEOUT_RETRY: Duration = Duration::from_secs(10);
const SIMPLEX_SKIP_TIMEOUT: Duration = Duration::from_secs(12);

const STATE_SYNC_APPLY_BATCH_SIZE: NonZeroU64 = NZU64!(1024);
const PRUNE_CONFIG: PruneConfig = PruneConfig {
    maintenance_interval: NZUsize!(1024),
    retained_marshal_blocks: 1024,
    retained_qmdb_blocks: 32,
};
const PRUNABLE_ITEMS_PER_SECTION: NonZeroU64 = NZU64!(4_096);
const NETWORK_BUFFER_POOL_MAX_SIZE: NonZeroUsize = NZUsize!(2 * 1024 * 1024);
const NETWORK_BUFFER_POOL_MAX_PER_CLASS: NonZeroU32 = NZU32!(1_024);
const STORAGE_BUFFER_POOL_MAX_PER_CLASS: NonZeroU32 = NZU32!(128);
// Commonware sizes authenticated channel mailboxes from the quota burst for every peer.
const P2P_MESSAGE_QUOTA: Quota = Quota::per_second(NZU32!(1_024));
// This validator runs one fixed participant set for the lifetime of the process.
const P2P_TRACKED_PEER_SETS: NonZeroUsize = NZUsize!(1);

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
        .with_parallelism(network_parallelism)
        .with_size_class_range(
            NZUsize!(1024),
            NETWORK_BUFFER_POOL_MAX_SIZE,
            NETWORK_BUFFER_POOL_MAX_PER_CLASS,
        );
    // Storage I/O can run on Tokio's blocking pool. Include those threads so
    // the pool's automatic TLS cache sizing does not strand scarce storage
    // buffers outside the global freelist under load.
    let storage_cfg = BufferPoolConfig::for_storage()
        .with_parallelism(storage_parallelism)
        .with_max_per_class(STORAGE_BUFFER_POOL_MAX_PER_CLASS);

    (network_cfg, storage_cfg)
}

pub fn run_local(peers_path: PathBuf, config_path: PathBuf) {
    let loaded = load_local_config(&peers_path, &config_path);
    run_with_config(loaded, config_path);
}

pub fn run_deployer(hosts_path: PathBuf, config_path: PathBuf) {
    let loaded = load_deployer_config(&hosts_path, &config_path);
    run_with_config(loaded, config_path);
}

fn leader_elector(term_length: TermLength) -> RoundRobin<Sha256> {
    if term_length == TermLength::ONE {
        return RoundRobin::default();
    }
    RoundRobin::default().with_term(
        term_length,
        STABLE_LEADER_STALL_TIMEOUT,
        STABLE_LEADER_OPTIMISTIC_VIEWS,
    )
}

fn run_with_config(config: LoadedConfig, config_path: PathBuf) {
    assert!(
        config.indexer.is_none(),
        "indexer configuration is unsupported in this Exoware-free validator build",
    );
    let LoadedConfig {
        decoded,
        startup,
        log_level,
        worker_threads,
        rayon_threads,
        http_listen,
        metrics_listen,
        max_propose_bytes,
        leader_term_length,
        leader_delay_ms,
        max_pool_bytes,
        state_page_cache_bytes,
        other_page_cache_bytes,
        public_key_cache_size,
        otel,
        json_logs,
        deployer_managed,
        indexer: _,
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
            leader_term_length = leader_term_length.get(),
            leader_delay_ms = leader_delay_ms.get(),
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
        let mut p2p_config = if deployer_managed {
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
        p2p_config.tracked_peer_sets = P2P_TRACKED_PEER_SETS;

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
            votes: network.register(VOTE_CHANNEL, P2P_MESSAGE_QUOTA),
            certificates: network.register(CERTIFICATE_CHANNEL, P2P_MESSAGE_QUOTA),
            resolver: network.register(RESOLVER_CHANNEL, P2P_MESSAGE_QUOTA),
            marshal: network.register(MARSHAL_CHANNEL, P2P_MESSAGE_QUOTA),
            marshal_resolver: network.register(MARSHAL_RESOLVER_CHANNEL, P2P_MESSAGE_QUOTA),
            state_resolver: network.register(STATE_RESOLVER_CHANNEL, P2P_MESSAGE_QUOTA),
            transaction_resolver: network.register(TRANSACTION_RESOLVER_CHANNEL, P2P_MESSAGE_QUOTA),
        };
        let probe_network = network.register(PROBE_CHANNEL, P2P_MESSAGE_QUOTA);
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

        let relayer_view = relayer
            .as_ref()
            .map(|_| crate::relayer::Observer::new(leader_term_length));
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
            crate::relayer::Observer,
        >::new(
            context.child("engine"),
            EngineConfig {
                signer: decoded.signer,
                manager: oracle.clone(),
                blocker: oracle,
                namespace: b"constantinople".to_vec(),
                output: decoded.dkg_output,
                share: decoded.share,
                elector: leader_elector(leader_term_length),
                input: mempool_mailbox.clone(),
                partition_prefix: decoded.partition_prefix,
                strategy,
                proposal_delay_ms: leader_delay_ms,
                public_key_cache,
                startup,
                sync_config: production_sync_config(),
                prune_config: Some(PRUNE_CONFIG),
                genesis_leader: decoded.genesis_leader,
                transaction_namespace: constantinople_primitives::TRANSACTION_NAMESPACE,
                block_codec: Default::default(),
                prunable_items_per_section: PRUNABLE_ITEMS_PER_SECTION,
                leader_timeout: SIMPLEX_LEADER_TIMEOUT,
                certification_timeout: SIMPLEX_CERTIFICATION_TIMEOUT,
                timeout_retry: SIMPLEX_TIMEOUT_RETRY,
                skip_timeout: SIMPLEX_SKIP_TIMEOUT,
                state_page_cache_bytes,
                other_page_cache_bytes,
                probe: Some(probe_mailbox.clone()),
                simplex_observer: relayer_observer,
                finalized_hook: None,
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
        // Primaries report to the local mempool. Secondaries do not need
        // marshal updates here.
        let reporter: Option<Mailbox<Commitment, PublicKey, Sha256>> = if is_primary {
            Some(mempool_mailbox.clone())
        } else {
            None
        };
        let engine_handle = engine.start(channels, reporter);

        wait_for_critical_task_exit(
            Some(probe_handle),
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
    engine_handle: E,
    mempool_handle: M,
    network_handle: N,
) where
    E: Future,
    M: Future,
    N: Future,
{
    let mut probe_handle = probe_handle.unwrap_or_else(|| Box::pin(std::future::pending()));
    tokio::select! {
        _ = probe_handle.as_mut() => tracing::warn!("probe exited"),
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
        P2P_MESSAGE_QUOTA, P2P_TRACKED_PEER_SETS, STABLE_LEADER_OPTIMISTIC_VIEWS,
        default_mempool_drop_grace_blocks, wait_for_critical_task_exit,
    };
    use commonware_consensus::types::ViewDelta;
    use commonware_utils::{NZU32, NZUsize};
    use constantinople_engine::MAX_PENDING_ACKS;
    use std::{future::pending, time::Duration};

    #[test]
    fn p2p_settings_keep_authenticated_mailboxes_bounded() {
        assert_eq!(P2P_MESSAGE_QUOTA.burst_size(), NZU32!(1_024));
        assert_eq!(P2P_TRACKED_PEER_SETS, NZUsize!(1));
    }

    #[test]
    fn stable_leader_pipeline_keeps_acknowledgement_headroom() {
        assert_eq!(STABLE_LEADER_OPTIMISTIC_VIEWS, ViewDelta::new(4));
        assert_eq!(
            MAX_PENDING_ACKS.get(),
            usize::try_from(STABLE_LEADER_OPTIMISTIC_VIEWS.get())
                .expect("optimistic view count must fit in usize")
                * 2,
        );
    }

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
            wait_for_critical_task_exit(None, pending::<()>(), pending::<()>(), pending::<()>()),
        )
        .await;

        assert!(
            result.is_err(),
            "completed setup work must not terminate the validator runtime",
        );
    }
}
