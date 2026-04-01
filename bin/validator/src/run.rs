//! Starts a validator from a YAML config.

use crate::config::{LoadedConfig, load_deployer_config, load_local_config};
use commonware_codec::Encode;
use commonware_consensus::{
    Reporter, marshal::Update, simplex::elector::RoundRobin, types::coding::Commitment,
};
use commonware_cryptography::{Hasher, Sha256, bls12381::primitives::variant::MinSig, ed25519};
use commonware_glue::stateful::{StartupMode, db::SyncEngineConfig};
use commonware_p2p::{Ingress, Manager as _, authenticated::discovery};
use commonware_parallel::Rayon;
use commonware_runtime::{
    Metrics as _, Quota, Runner as _, ThreadPooler as _,
    tokio::telemetry::{self, Logging},
};
use commonware_utils::{Acknowledgement, NZU64, NZUsize, TryCollect, hex, union};
use constantinople_application::consensus::TransactionCallback;
use constantinople_engine::{
    BOOTSTRAPPER_CHANNEL, CERTIFICATE_CHANNEL, Channels, Config as EngineConfig, Engine,
    MARSHAL_CHANNEL, MARSHAL_RESOLVER_CHANNEL, RESOLVER_CHANNEL, STATE_RESOLVER_CHANNEL,
    TRANSACTION_RESOLVER_CHANNEL, VOTE_CHANNEL, bootstrapper,
};
use constantinople_mempool::server::{Mempool, MempoolConfig, router};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tracing::info;

#[derive(Clone, Copy, Debug, Default)]
struct NoopReporter;

impl Reporter for NoopReporter {
    type Activity = Update<
        constantinople_primitives::Sealed<
            constantinople_primitives::Block<Commitment, ed25519::PublicKey, Sha256>,
            Sha256,
        >,
    >;

    async fn report(&mut self, activity: Self::Activity) {
        if let Update::Block(_, response) = activity {
            response.acknowledge();
        }
    }
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
        log_level,
        worker_threads,
        rayon_threads,
        http_listen,
        json_logs,
        deployer_managed,
        max_propose_bytes,
        max_pool_bytes,
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
            None,
            None,
        );

        info!(
            validator = %hex(&decoded.public_key.encode()),
            listen_bind = %decoded.listen_bind,
            listen_advertise = %decoded.listen_advertise,
            http_listen = %http_listen,
            "starting validator"
        );

        let all_pks = {
            let mut pks = vec![decoded.public_key.clone()];
            pks.extend(decoded.bootstrappers.iter().map(|(pk, _)| pk.clone()));
            pks
        };
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
                12 * 1024 * 1024,
            )
        } else {
            discovery::Config::local(
                decoded.signer.clone(),
                b"constantinople",
                decoded.listen_bind,
                Ingress::Socket(decoded.listen_advertise),
                decoded.bootstrappers,
                12 * 1024 * 1024,
            )
        };

        let (mut network, mut oracle) =
            discovery::Network::new(context.with_label("p2p"), p2p_config);

        oracle
            .track(0, all_pks.into_iter().try_collect().unwrap())
            .await;

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

        let mempool = Mempool::<Commitment, ed25519::PublicKey, Sha256>::new(
            b"constantinople-tx",
            MempoolConfig {
                max_propose_bytes,
                max_pool_bytes,
            },
        );

        let callback_mempool = mempool.clone();
        let transaction_callback: TransactionCallback<<Sha256 as Hasher>::Digest> =
            Arc::new(move |height, transaction_hashes, included| {
                let mempool = callback_mempool.clone();
                tokio::spawn(async move {
                    if included {
                        mempool.notify_included(height, &transaction_hashes).await;
                        return;
                    }

                    mempool.notify_rejected(&transaction_hashes).await;
                });
            });

        let router = router(&mempool);
        let http_listener = tokio::net::TcpListener::bind(http_listen)
            .await
            .expect("failed to bind HTTP listener");
        info!(listen = %http_listen, "HTTP server listening");
        let http_handle = tokio::spawn(async move {
            axum::serve(http_listener, router)
                .await
                .expect("HTTP server failed");
        });

        info!("initializing engine");
        let engine = Engine::<_, _, _, _, Sha256, MinSig, RoundRobin<Sha256>, Rayon, _>::new(
            context.with_label("engine"),
            EngineConfig {
                signer: decoded.signer,
                manager: oracle.clone(),
                blocker: oracle,
                namespace: b"constantinople".to_vec(),
                output: decoded.dkg_output,
                share: Some(decoded.share),
                input: mempool,
                partition_prefix: decoded.partition_prefix,
                freezer_table_initial_size: 1024,
                strategy,
                startup: StartupMode::MarshalSync,
                sync_config: SyncEngineConfig {
                    fetch_batch_size: NZU64!(16),
                    apply_batch_size: 64,
                    max_outstanding_requests: 8,
                    update_channel_size: NZUsize!(256),
                    max_retained_roots: 32,
                },
                genesis_leader: decoded.genesis_leader,
                transaction_namespace: b"constantinople-tx",
                block_codec: Default::default(),
                transaction_callback: Some(transaction_callback),
                bootstrapper: bootstrapper_mailbox.clone(),
            },
        )
        .await;

        info!("starting engine");
        let engine_handle = engine.start(channels, None::<NoopReporter>);

        tokio::select! {
            _ = bootstrapper_handle => tracing::warn!("bootstrapper exited"),
            _ = engine_handle => tracing::warn!("engine exited"),
            _ = network_handle => tracing::warn!("network exited"),
            _ = http_handle => tracing::warn!("http server exited"),
        }
    });
}
