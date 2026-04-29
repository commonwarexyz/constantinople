//! Starts a validator from a YAML config.

use crate::{
    config::{
        IndexerConfig, LoadedConfig, StartupModeConfig, load_deployer_config, load_local_config,
    },
    state_reader::StateDbReader,
};
use commonware_codec::Encode;
use commonware_consensus::{
    Reporter, marshal::Update, simplex::elector::RoundRobin, types::coding::Commitment,
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig,
    ed25519::{self, Batch, PublicKey},
    sha256::Sha256,
};
use commonware_glue::stateful::{StartupMode, db::SyncEngineConfig};
use commonware_p2p::{Ingress, Manager as _, TrackedPeers, authenticated::discovery};
use commonware_parallel::Rayon;
use commonware_runtime::{
    Metrics as _, Quota, Runner as _, ThreadPooler as _,
    tokio::telemetry::{self, Logging},
};
use commonware_utils::{NZU64, NZUsize, TryCollect, hex, ordered::Set, union};
use constantinople_engine::{
    BOOTSTRAPPER_CHANNEL, CERTIFICATE_CHANNEL, Channels, Config as EngineConfig, Engine,
    MARSHAL_CHANNEL, MARSHAL_RESOLVER_CHANNEL, RESOLVER_CHANNEL, STATE_RESOLVER_CHANNEL,
    TRANSACTION_RESOLVER_CHANNEL, ThresholdScheme, VOTE_CHANNEL, bootstrapper, types::EngineBlock,
};
use constantinople_indexer::{BlockReporter, CertificateReporter, UploaderHandle, spawn_uploader};
use constantinople_mempool::webserver::{self, AccountReader, Mailbox};
use std::{
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tracing::info;

const MEMPOOL_MAILBOX_SIZE: usize = 65_536;

const STATE_SYNC_APPLY_BATCH_SIZE: usize = 1024;
const MAX_POOL_BYTES: usize = 256 * 1024 * 1024;
const MAX_PROPOSE_BYTES: usize = 8 * 1024 * 1024;

/// Concrete type the engine sees in the `simplex_observer` slot.
///
/// We always pin `O` to the indexer's certificate publisher so the engine type
/// stays the same whether or not the indexer is enabled. Validators that opt
/// out simply pass `simplex_observer: None`.
type EngineCertReporter = CertificateReporter<ThresholdScheme<PublicKey, MinSig>, Commitment>;

/// Concrete type the engine sees in `engine.start(_, reporter)`.
///
/// Primaries report finalized blocks to the local mempool; secondaries with an
/// indexer enabled report them to the indexer. The two reporter implementations
/// have unrelated types, so we tee them through this small dispatch enum.
#[derive(Clone)]
enum BlockUpdateReporter {
    Mempool(Mailbox<Commitment, PublicKey, Sha256>),
    Indexer(BlockReporter<Sha256, PublicKey>),
}

impl Reporter for BlockUpdateReporter {
    type Activity = Update<EngineBlock<Sha256, PublicKey>>;

    async fn report(&mut self, activity: Self::Activity) {
        match self {
            Self::Mempool(m) => m.report(activity).await,
            Self::Indexer(i) => i.report(activity).await,
        }
    }
}

/// Bundle of indexer state that needs to outlive engine startup.
struct IndexerHandle {
    block_reporter: BlockReporter<Sha256, PublicKey>,
    cert_reporter: EngineCertReporter,
    /// Kept alive so the uploader task is not aborted while the validator runs.
    _uploader: UploaderHandle,
}

/// Build the indexer wiring iff the secondary validator opted in.
fn maybe_build_indexer(is_primary: bool, indexer: Option<IndexerConfig>) -> Option<IndexerHandle> {
    let cfg = indexer?;
    if !cfg.enabled || is_primary {
        return None;
    }

    info!(exoware_url = %cfg.exoware_url, "starting indexer uploader");
    let store = constantinople_indexer::standard_store_client(&cfg.exoware_url);
    let uploader = spawn_uploader(store, cfg.upload_buffer);
    let block_reporter = BlockReporter::<Sha256, PublicKey>::new(uploader.tx.clone());
    let cert_reporter = EngineCertReporter::new(uploader.tx.clone());
    Some(IndexerHandle {
        block_reporter,
        cert_reporter,
        _uploader: uploader,
    })
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
        indexer,
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
        oracle.track(0, TrackedPeers::new(primary, secondary)).await;

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

        let (mempool_mailbox, mempool_receiver) = Mailbox::channel(MEMPOOL_MAILBOX_SIZE);
        let account_reader: Arc<OnceLock<Arc<dyn AccountReader<ed25519::PublicKey>>>> =
            Arc::new(OnceLock::new());
        let mempool_actor = webserver::Actor::new(
            context.with_label("mempool"),
            webserver::Config {
                max_pool_bytes: MAX_POOL_BYTES,
                max_propose_bytes: MAX_PROPOSE_BYTES,
                namespace: constantinople_primitives::TRANSACTION_NAMESPACE,
                drop_grace_blocks: 3,
                strategy: strategy.clone(),
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
            let handle = mempool_actor.start::<Batch>(listener);
            Box::pin(async move {
                let _ = handle.await;
            })
        } else {
            info!("secondary node: skipping mempool webserver");
            drop(mempool_actor);
            Box::pin(std::future::pending())
        };

        let startup =
            resolve_startup_mode(startup, || bootstrapper_mailbox.fetch_initial_target()).await;
        let startup_mode = match &startup {
            StartupMode::MarshalSync => "marshal_sync",
            StartupMode::StateSync { .. } => "state_sync",
        };
        info!(startup_mode, "selected validator startup mode");

        // Build the indexer wiring up-front. This consumes `indexer` from the
        // loaded config and returns `None` for primaries, validators that did
        // not declare an `indexer` block, or those that declared one with
        // `enabled: false`.
        let indexer_handle = maybe_build_indexer(is_primary, indexer);

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
            EngineCertReporter,
        >::new(
            context.with_label("engine"),
            EngineConfig {
                signer: decoded.signer,
                manager: oracle.clone(),
                blocker: oracle,
                namespace: b"constantinople".to_vec(),
                output: decoded.dkg_output,
                share: decoded.share,
                input: mempool_mailbox.clone(),
                partition_prefix: decoded.partition_prefix,
                freezer_table_initial_size: 1024,
                strategy,
                startup,
                sync_config: production_sync_config(),
                genesis_leader: decoded.genesis_leader,
                transaction_namespace: constantinople_primitives::TRANSACTION_NAMESPACE,
                block_codec: Default::default(),
                bootstrapper: bootstrapper_mailbox.clone(),
                simplex_observer: indexer_handle.as_ref().map(|h| h.cert_reporter.clone()),
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
            let reader: Arc<dyn AccountReader<ed25519::PublicKey>> =
                Arc::new(StateDbReader::new(db));
            let _ = account_reader_setter.set(reader);
            info!("account reader attached");
        });

        info!("starting engine");
        // Primaries report to the local mempool; secondaries with an indexer
        // configured report to the indexer; secondaries without report to no
        // one. The three cases share a single dispatch enum so the engine
        // type is fixed regardless of role.
        let reporter: Option<BlockUpdateReporter> = if is_primary {
            Some(BlockUpdateReporter::Mempool(mempool_mailbox.clone()))
        } else {
            indexer_handle
                .as_ref()
                .map(|h| BlockUpdateReporter::Indexer(h.block_reporter.clone()))
        };
        let engine_handle = engine.start(channels, reporter);

        wait_for_critical_task_exit(
            bootstrapper_handle,
            engine_handle,
            mempool_handle,
            network_handle,
        )
        .await;
    });
}

async fn wait_for_critical_task_exit<B, E, M, N>(
    bootstrapper_handle: B,
    engine_handle: E,
    mempool_handle: M,
    network_handle: N,
) where
    B: Future,
    E: Future,
    M: Future,
    N: Future,
{
    tokio::select! {
        _ = bootstrapper_handle => tracing::warn!("bootstrapper exited"),
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
    use super::wait_for_critical_task_exit;
    use std::{future::pending, time::Duration};

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
}
