//! Starts a validator from a YAML config.

use crate::config::{LoadedConfig, StartupModeConfig, load_deployer_config, load_local_config};
use commonware_codec::Encode;
use commonware_consensus::simplex::elector::RoundRobin;
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::variant::MinSig,
    ed25519::{self, Batch},
};
use commonware_glue::stateful::{StartupMode, db::SyncEngineConfig};
use commonware_p2p::{Ingress, Manager as _, authenticated::discovery};
use commonware_parallel::Rayon;
use commonware_runtime::{
    Metrics as _, Quota, Runner as _, ThreadPooler as _,
    tokio::telemetry::{self, Logging},
};
use commonware_utils::{NZU64, NZUsize, TryCollect, hex, ordered::Set, union};
use constantinople_engine::{
    BOOTSTRAPPER_CHANNEL, CERTIFICATE_CHANNEL, Channels, Config as EngineConfig, Engine,
    MARSHAL_CHANNEL, MARSHAL_RESOLVER_CHANNEL, RESOLVER_CHANNEL, STATE_RESOLVER_CHANNEL,
    VOTE_CHANNEL, bootstrapper,
};
use constantinople_mempool::webserver;
use std::{future::Future, path::PathBuf, sync::Arc, time::Duration};
use tracing::info;

const STATE_SYNC_APPLY_BATCH_SIZE: usize = 1024;
const MAX_POOL_BYTES: usize = 256 * 1024 * 1024;
const MAX_PROPOSE_BYTES: usize = 4 * 1024 * 1024;

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
        json_logs,
        deployer_managed,
    } = config;

    let config_dir = config_path
        .parent()
        .expect("config file has no parent directory");
    let storage_dir = config_dir.join(&decoded.partition_prefix);
    let runtime_cfg = commonware_runtime::tokio::Config::new()
        .with_storage_directory(storage_dir)
        .with_worker_threads(worker_threads);
    let runner = commonware_runtime::tokio::Runner::new(runtime_cfg);

    runner.start(|context| async move {
        telemetry::init(
            context.with_label("telemetry"),
            Logging {
                level: log_level.parse().expect("bad log_level in config"),
                json: json_logs,
            },
            Some(metrics_listen),
            None,
        );

        info!(
            validator = %hex(&decoded.public_key.encode()),
            listen_bind = %decoded.listen_bind,
            listen_advertise = %decoded.listen_advertise,
            http_listen = %http_listen,
            metrics_listen = %metrics_listen,
            "starting validator"
        );
        let strategy = context
            .clone()
            .create_strategy(NZUsize!(rayon_threads))
            .expect("failed to create parallel strategy");

        let p2p_config = if deployer_managed {
            discovery::Config::recommended(
                decoded.signer.clone(),
                b"constantinople",
                decoded.listen_bind,
                Ingress::Socket(decoded.listen_advertise),
                decoded.bootstrappers,
                16 * 1024 * 1024,
            )
        } else {
            discovery::Config::local(
                decoded.signer.clone(),
                b"constantinople",
                decoded.listen_bind,
                Ingress::Socket(decoded.listen_advertise),
                decoded.bootstrappers,
                16 * 1024 * 1024,
            )
        };

        let (mut network, mut oracle) =
            discovery::Network::new(context.with_label("p2p"), p2p_config);

        oracle
            .track(
                0,
                decoded
                    .participants
                    .clone()
                    .into_iter()
                    .try_collect::<Set<ed25519::PublicKey>>()
                    .unwrap(),
            )
            .await;

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
        };
        let bootstrapper_network = network.register(BOOTSTRAPPER_CHANNEL, quota, backlog);

        let (bootstrapper, bootstrapper_mailbox) = bootstrapper::Actor::new(
            context.with_label("bootstrapper"),
            bootstrapper::Config {
                public_key: decoded.public_key.clone(),
                peer_provider: oracle.clone(),
                blocker: oracle.clone(),
                scheme:
                    constantinople_engine::ThresholdScheme::<ed25519::PublicKey, MinSig>::verifier(
                        &union(b"constantinople", b"_CONSENSUS"),
                        decoded.dkg_output.players().clone(),
                        decoded.dkg_output.public().clone(),
                    ),
                mailbox_size: 32,
                round_timeout: Duration::from_secs(1),
                retry_interval: Duration::from_secs(1),
                block_codec: Default::default(),
            },
        );
        let bootstrapper_handle = bootstrapper.start(bootstrapper_network);
        let network_handle = network.start();

        let (mempool_actor, mempool_mailbox) = webserver::Actor::new(webserver::Config {
            max_pool_bytes: MAX_POOL_BYTES,
            max_propose_bytes: MAX_PROPOSE_BYTES,
            mailbox_size: 65536,
        });
        let mempool_handle = mempool_actor.start();

        let app_state = Arc::new(webserver::AppState {
            mailbox: mempool_mailbox.clone(),
            namespace: b"constantinople-tx",
        });
        let app = webserver::router(app_state);
        let listener = tokio::net::TcpListener::bind(http_listen)
            .await
            .expect("failed to bind mempool HTTP listener");
        info!(%http_listen, "mempool webserver listening");
        let http_handle = tokio::spawn(axum::serve(listener, app).into_future());

        let startup =
            resolve_startup_mode(startup, || bootstrapper_mailbox.fetch_initial_target()).await;
        let startup_mode = match &startup {
            StartupMode::MarshalSync => "marshal_sync",
            StartupMode::StateSync { .. } => "state_sync",
        };
        info!(startup_mode, "selected validator startup mode");

        info!("initializing engine");
        let engine =
            Engine::<_, _, _, _, Sha256, MinSig, RoundRobin<Sha256>, Rayon, _, Batch>::new(
                context.with_label("engine"),
                EngineConfig {
                    signer: decoded.signer,
                    manager: oracle.clone(),
                    blocker: oracle,
                    namespace: b"constantinople".to_vec(),
                    output: decoded.dkg_output,
                    share: Some(decoded.share),
                    input: mempool_mailbox.clone(),
                    partition_prefix: decoded.partition_prefix,
                    freezer_table_initial_size: 1024,
                    strategy,
                    startup,
                    sync_config: production_sync_config(),
                    genesis_leader: decoded.genesis_leader,
                    transaction_namespace: b"constantinople-tx",
                    block_codec: Default::default(),
                    bootstrapper: bootstrapper_mailbox.clone(),
                },
            )
            .await;

        info!("starting engine");
        let engine_handle = engine.start(channels, Some(mempool_mailbox));

        tokio::select! {
            _ = bootstrapper_handle => tracing::warn!("bootstrapper exited"),
            _ = engine_handle => tracing::warn!("engine exited"),
            _ = mempool_handle => tracing::warn!("mempool actor exited"),
            _ = http_handle => tracing::warn!("mempool http server exited"),
            _ = network_handle => tracing::warn!("network exited"),
        }
    });
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

async fn resolve_startup_mode<T, F, Fut>(
    requested: StartupModeConfig,
    fetch_initial_target: F,
) -> StartupMode<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    match requested {
        StartupModeConfig::MarshalSync => StartupMode::MarshalSync,
        StartupModeConfig::StateSync => {
            let block = fetch_initial_target()
                .await
                .expect("bootstrapper actor exited before selecting a state-sync target");
            StartupMode::StateSync { block }
        }
    }
}
