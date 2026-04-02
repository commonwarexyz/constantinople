//! Starts a validator from a YAML config.

use crate::config::{LoadedConfig, StartupModeConfig, load_deployer_config, load_local_config};
use commonware_codec::Encode;
use commonware_consensus::{simplex::elector::RoundRobin, types::coding::Commitment};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinSig, ed25519};
use commonware_glue::stateful::{StartupMode, db::SyncEngineConfig};
use commonware_p2p::{Ingress, Manager as _, authenticated::discovery};
use commonware_parallel::Rayon;
use commonware_runtime::{
    Metrics as _, Quota, Runner as _, ThreadPooler as _,
    tokio::telemetry::{self, Logging},
};
use commonware_utils::{NZU64, NZUsize, TryCollect, hex, union};
use constantinople_engine::{
    BOOTSTRAPPER_CHANNEL, CERTIFICATE_CHANNEL, Channels, Config as EngineConfig, Engine,
    MARSHAL_CHANNEL, MARSHAL_RESOLVER_CHANNEL, RESOLVER_CHANNEL, STATE_RESOLVER_CHANNEL,
    TRANSACTION_RESOLVER_CHANNEL, VOTE_CHANNEL, bootstrapper,
};
use constantinople_mempool::server::{Mempool, MempoolConfig, router};
use std::{future::Future, path::PathBuf, time::Duration};
use tracing::info;

const STATE_SYNC_APPLY_BATCH_SIZE: usize = 1024;
// Validator mempools are local, so a leased batch must survive at least one
// full leader rotation before it becomes eligible for reproposal.
const ESTIMATED_PROPOSAL_CADENCE: Duration = Duration::from_millis(250);
const MEMPOOL_PROPOSAL_LEASE_MARGIN: Duration = Duration::from_millis(500);

fn mempool_proposal_lease_duration(participant_count: usize) -> Duration {
    let participant_count =
        u32::try_from(participant_count.max(1)).expect("participant count should fit into u32");
    ESTIMATED_PROPOSAL_CADENCE
        .saturating_mul(participant_count)
        .saturating_add(MEMPOOL_PROPOSAL_LEASE_MARGIN)
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
            .track(
                0,
                decoded
                    .participants
                    .clone()
                    .into_iter()
                    .try_collect()
                    .unwrap(),
            )
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
                proposal_lease_duration: mempool_proposal_lease_duration(
                    decoded.participants.len(),
                ),
            },
        );
        let finalized_reporter = mempool.clone();

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

        let startup =
            resolve_startup_mode(startup, || bootstrapper_mailbox.fetch_initial_target()).await;
        let startup_mode = match &startup {
            StartupMode::MarshalSync => "marshal_sync",
            StartupMode::StateSync { .. } => "state_sync",
        };
        info!(startup_mode, "selected validator startup mode");

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
        let engine_handle = engine.start(channels, Some(finalized_reporter));

        tokio::select! {
            _ = bootstrapper_handle => tracing::warn!("bootstrapper exited"),
            _ = engine_handle => tracing::warn!("engine exited"),
            _ = network_handle => tracing::warn!("network exited"),
            _ = http_handle => tracing::warn!("http server exited"),
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

#[cfg(test)]
mod tests {
    use super::{
        ESTIMATED_PROPOSAL_CADENCE, MEMPOOL_PROPOSAL_LEASE_MARGIN, STATE_SYNC_APPLY_BATCH_SIZE,
        mempool_proposal_lease_duration, production_sync_config, resolve_startup_mode,
    };
    use crate::config::StartupModeConfig;
    use axum::{body::Body, http::Request};
    use commonware_codec::{Encode, ReadExt};
    use commonware_consensus::{
        Reporter,
        marshal::Update,
        simplex::types::Context,
        types::{Epoch, Round, View, coding::Commitment},
    };
    use commonware_cryptography::{Digest, Hasher, Sha256, Signer, ed25519};
    use commonware_glue::stateful::StartupMode;
    use commonware_utils::{Acknowledgement, acknowledgement::Exact, hex};
    use constantinople_mempool::{
        SealedBlock, TransactionSource,
        server::{Mempool, MempoolConfig, router},
    };
    use constantinople_primitives::{Address, Block, Header, Sealable, Signed, Transaction};
    use core::{marker::PhantomData, num::NonZeroU64};
    use std::time::Duration;
    use tower::util::ServiceExt;

    const TEST_TRANSACTION_NAMESPACE: &[u8] = b"constantinople-tx";

    fn test_context() -> Context<Commitment, ed25519::PublicKey> {
        Context {
            round: Round::new(Epoch::zero(), View::zero()),
            leader: ed25519::PrivateKey::from_seed(13).public_key(),
            parent: (View::zero(), Commitment::EMPTY),
        }
    }

    fn test_parent() -> Header<Commitment, <Sha256 as Hasher>::Digest, ed25519::PublicKey> {
        Header {
            context: test_context(),
            parent: <Sha256 as Hasher>::Digest::EMPTY,
            height: 0,
            timestamp: 0,
            state_root: <Sha256 as Hasher>::Digest::EMPTY,
            state_range: commonware_utils::non_empty_range!(0, 1),
            transactions_root: <Sha256 as Hasher>::Digest::EMPTY,
            transactions_range: commonware_utils::non_empty_range!(0, 1),
        }
    }

    fn signed_bytes(nonce: u64) -> Vec<u8> {
        let key = ed25519::PrivateKey::from_seed(7);
        Transaction {
            sender: key.public_key(),
            to: Address::EMPTY,
            value: NonZeroU64::new(1).expect("test value should be non-zero"),
            nonce,
            _digest: PhantomData::<<Sha256 as Hasher>::Digest>,
        }
        .seal_and_sign_verified(&key, TEST_TRANSACTION_NAMESPACE, &mut Sha256::default())
        .encode()
        .to_vec()
    }

    fn finalized_block_with_nonce(
        nonce: u64,
        height: u64,
    ) -> SealedBlock<Commitment, ed25519::PublicKey, Sha256> {
        let bytes = signed_bytes(nonce);
        let signed = Signed::<
            Transaction<<Sha256 as Hasher>::Digest, ed25519::PublicKey>,
            Sha256,
            ed25519::Signature,
        >::read(&mut &bytes[..])
        .expect("test transaction should decode");
        let mut header = test_parent();
        header.height = height;

        Block::new(header, vec![signed]).seal(&mut Sha256::default())
    }

    #[tokio::test]
    async fn state_sync_requests_bootstrap_target() {
        let startup =
            resolve_startup_mode(StartupModeConfig::StateSync, || async { Some(42_u64) }).await;

        match startup {
            StartupMode::StateSync { block } => assert_eq!(block, 42),
            StartupMode::MarshalSync => panic!("expected state sync startup"),
        }
    }

    #[tokio::test]
    async fn marshal_sync_skips_bootstrap_target() {
        let startup: StartupMode<u64> =
            resolve_startup_mode(StartupModeConfig::MarshalSync, || async {
                panic!("marshal sync should not fetch a bootstrap target")
            })
            .await;

        assert!(matches!(startup, StartupMode::MarshalSync));
    }

    #[test]
    fn production_sync_config_uses_large_rebuild_batches() {
        let config = production_sync_config();

        assert_eq!(config.apply_batch_size, STATE_SYNC_APPLY_BATCH_SIZE);
        assert!(
            config.apply_batch_size >= 1024,
            "production rebuild batches should stay large enough to avoid prolonged post-sync replay",
        );
    }

    #[test]
    fn proposal_lease_duration_covers_one_full_leader_rotation() {
        assert_eq!(
            mempool_proposal_lease_duration(4),
            ESTIMATED_PROPOSAL_CADENCE
                .saturating_mul(4)
                .saturating_add(MEMPOOL_PROPOSAL_LEASE_MARGIN),
        );
        assert_eq!(
            mempool_proposal_lease_duration(1),
            ESTIMATED_PROPOSAL_CADENCE.saturating_add(MEMPOOL_PROPOSAL_LEASE_MARGIN),
        );
    }

    #[tokio::test]
    async fn mempool_reporter_removes_included_transactions_before_next_proposal() {
        let mut mempool = Mempool::<Commitment, ed25519::PublicKey, Sha256>::new(
            TEST_TRANSACTION_NAMESPACE,
            MempoolConfig {
                max_propose_bytes: 1024 * 1024,
                max_pool_bytes: 1024 * 1024,
                proposal_lease_duration: Duration::from_secs(1),
            },
        );
        let app = router(&mempool);
        let bytes = signed_bytes(0);
        let request = Request::post("/tx/accept")
            .body(Body::from(hex(&bytes)))
            .expect("request should build");

        let response = app
            .oneshot(request)
            .await
            .expect("accept route should respond");
        assert!(response.status().is_success());

        let (acknowledgement, waiter) = Exact::handle();
        mempool
            .report(Update::Block(
                finalized_block_with_nonce(0, 1),
                acknowledgement,
            ))
            .await;
        waiter
            .await
            .expect("finalized block should be acknowledged");

        let next = mempool.propose(&test_parent(), &test_context()).await;
        assert!(next.is_empty());
    }
}
