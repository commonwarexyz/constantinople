//! Starts a validator from a YAML config.

use crate::{
    config::{
        IndexerConfig, IndexerMode, LoadedConfig, StartupModeConfig, load_deployer_config,
        load_local_config,
    },
    state_reader::StateDbReader,
};
use commonware_actor::Feedback;
use commonware_codec::Encode;
use commonware_consensus::{
    Reporter, marshal::Update, simplex::elector::RoundRobin, types::coding::Commitment,
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig,
    ed25519::{self, Batch, PublicKey},
    sha256::Sha256,
};
use commonware_formatting::hex;
use commonware_glue::stateful::db::SyncEngineConfig;
use commonware_p2p::{Ingress, Manager as _, TrackedPeers, authenticated::discovery};
use commonware_parallel::Rayon;
use commonware_runtime::{
    Quota, Runner as _, Supervisor as _, ThreadPooler as _,
    tokio::telemetry::{self, Logging},
};
use commonware_utils::{NZU64, NZUsize, TryCollect, ordered::Set, union};
use constantinople_application::consensus::FinalizedHookFn;
use constantinople_engine::{
    BOOTSTRAPPER_CHANNEL, CERTIFICATE_CHANNEL, Channels, Config as EngineConfig, Engine,
    MARSHAL_CHANNEL, MARSHAL_RESOLVER_CHANNEL, RESOLVER_CHANNEL, STATE_RESOLVER_CHANNEL,
    StartupMode, TRANSACTION_RESOLVER_CHANNEL, ThresholdScheme, VOTE_CHANNEL, bootstrapper,
    types::{EngineActivity, EngineBlock},
};
use constantinople_indexer::{BlockReporter, CertificateReporter, QmdbPublisher, spawn_uploaders};
use constantinople_mempool::webserver::{self, AccountReader, Mailbox};
use std::{
    future::Future,
    num::NonZeroU64,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::task::JoinHandle;
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
type EngineCertReporter =
    CertificateReporter<Sha256, PublicKey, ThresholdScheme<PublicKey, MinSig>>;

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

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match self {
            Self::Mempool(m) => m.report(activity),
            Self::Indexer(i) => i.report(activity),
        }
    }
}

/// Bundle of indexer state that needs to outlive engine startup.
struct IndexerHandle {
    block_reporter: Option<BlockReporter<Sha256, PublicKey>>,
    cert_reporter: Option<EngineCertReporter>,
    qmd_publisher: Option<Arc<QmdbPublisher<Sha256, PublicKey>>>,
    /// Kept alive so the uploader tasks are not aborted while the validator runs.
    _uploaders: Vec<JoinHandle<()>>,
}

/// Build the indexer wiring iff the secondary validator opted in.
async fn maybe_build_indexer(
    is_primary: bool,
    indexer: Option<IndexerConfig>,
) -> Option<IndexerHandle> {
    let cfg = indexer?;
    if is_primary {
        return None;
    }

    info!(
        mode = ?cfg.mode,
        chain_indexer_url = %cfg.chain_indexer_url,
        "starting indexer uploaders",
    );
    match cfg.mode {
        IndexerMode::Full => {
            let raw_store = constantinople_indexer::standard_store_client(&cfg.chain_indexer_url);
            let (cert_reporter, cert_join) =
                EngineCertReporter::connect(&cfg.chain_indexer_url, cfg.upload_buffer);
            let cert_reporter = Some(cert_reporter);
            if cfg.qmdb_upload {
                let qmd_publisher = Some(Arc::new(
                    QmdbPublisher::connect(&cfg.chain_indexer_url, cfg.upload_buffer)
                        .await
                        .expect("failed to initialize qmd publisher"),
                ));
                Some(IndexerHandle {
                    block_reporter: None,
                    cert_reporter,
                    qmd_publisher,
                    _uploaders: vec![cert_join],
                })
            } else {
                let sql_store =
                    constantinople_indexer::standard_store_client(&cfg.chain_indexer_url);
                let uploaders = spawn_uploaders(raw_store, sql_store, cfg.upload_buffer);
                let block_reporter = BlockReporter::<Sha256, PublicKey>::new(
                    uploaders.raw.clone(),
                    uploaders.sql.clone(),
                );
                let mut joins = Vec::from(uploaders.joins);
                joins.push(cert_join);
                Some(IndexerHandle {
                    block_reporter: Some(block_reporter),
                    cert_reporter,
                    qmd_publisher: None,
                    _uploaders: joins,
                })
            }
        }
        IndexerMode::MetadataOnly => {
            let sql_store = constantinople_indexer::standard_store_client(&cfg.chain_indexer_url);
            let (sql, sql_join) =
                constantinople_indexer::publisher::spawn_sql_uploader(sql_store, cfg.upload_buffer);
            Some(IndexerHandle {
                block_reporter: Some(BlockReporter::<Sha256, PublicKey>::metadata_only(sql)),
                cert_reporter: None,
                qmd_publisher: None,
                _uploaders: vec![sql_join],
            })
        }
    }
}

fn indexer_finalized_hook(
    indexer: Option<&IndexerHandle>,
) -> Option<FinalizedHookFn<commonware_runtime::tokio::Context, Commitment, Sha256, PublicKey, Rayon>>
{
    let indexer = indexer?;
    let publisher = indexer.qmd_publisher.clone();
    let cert_reporter = indexer.cert_reporter.clone();
    if publisher.is_none() && cert_reporter.is_none() {
        return None;
    }
    Some(Arc::new(move |block, databases| {
        let publisher = publisher.clone();
        let cert_reporter = cert_reporter.clone();
        Box::pin(async move {
            if let Some(publisher) = publisher {
                publisher
                    .upload_finalized(block, databases)
                    .await
                    .expect("finalized index upload failed");
            }
            if let Some(cert_reporter) = cert_reporter {
                cert_reporter.publish_block(block).await;
            }
        })
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
        prune_cadence_blocks,
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
    let runner = commonware_runtime::tokio::Runner::new(runtime_cfg);

    runner.start(|context| async move {
        telemetry::init(
            context.child("telemetry"),
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
        let signature_strategy = context
            .create_strategy(NZUsize!(rayon_threads))
            .expect("failed to create signature verification strategy");
        let hash_strategy = context
            .create_strategy(NZUsize!(rayon_threads))
            .expect("failed to create hashing strategy");

        let p2p_config = if deployer_managed {
            discovery::Config::recommended(
                decoded.signer.clone(),
                b"constantinople",
                decoded.listen_bind,
                Ingress::Socket(decoded.listen_advertise),
                decoded.bootstrappers,
                32 * 1024 * 1024,
            )
        } else {
            discovery::Config::local(
                decoded.signer.clone(),
                b"constantinople",
                decoded.listen_bind,
                Ingress::Socket(decoded.listen_advertise),
                decoded.bootstrappers,
                32 * 1024 * 1024,
            )
        };

        let (mut network, mut oracle) = discovery::Network::new(context.child("p2p"), p2p_config);

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
        let should_bootstrap = matches!(startup, StartupModeConfig::StateSync);
        let (bootstrapper_handle, bootstrapper_mailbox) = if should_bootstrap {
            let bootstrapper_network = network.register(BOOTSTRAPPER_CHANNEL, quota, backlog);
            let (bootstrapper, bootstrapper_mailbox) = bootstrapper::Actor::new(
                context.child("bootstrapper"),
                bootstrapper::Config {
                    public_key: decoded.public_key.clone(),
                    peer_provider: oracle.clone(),
                    blocker: oracle.clone(),
                    scheme: constantinople_engine::ThresholdScheme::<
                        ed25519::PublicKey,
                        MinSig,
                    >::verifier(
                        &union(b"constantinople", b"_CONSENSUS"),
                        decoded.dkg_output.players().clone(),
                        decoded.dkg_output.public().clone(),
                    ),
                    mailbox_size: 32,
                    round_timeout: Duration::from_secs(1),
                    retry_interval: Duration::from_secs(1),
                },
            );
            let handle = bootstrapper.start(bootstrapper_network);
            let handle: CriticalTask = Box::pin(async move {
                let _ = handle.await;
            });
            (Some(handle), Some(bootstrapper_mailbox))
        } else {
            (None, None)
        };
        let network_handle = network.start();

        let relayer_view = relayer
            .as_ref()
            .map(|_| crate::relayer::Observer::new());
        let relayer_view_clock = relayer_view
            .as_ref()
            .map(|(_, view_clock)| view_clock.clone());
        let relayer_observer = relayer_view.map(|(observer, _)| observer);

        let (mempool_mailbox, mempool_receiver) = Mailbox::channel(MEMPOOL_MAILBOX_SIZE);
        let account_reader: Arc<OnceLock<Arc<dyn AccountReader>>> = Arc::new(OnceLock::new());
        let mempool_actor = webserver::Actor::new(
            context.child("mempool"),
            webserver::Config {
                max_pool_bytes: MAX_POOL_BYTES,
                max_propose_bytes: MAX_PROPOSE_BYTES,
                namespace: constantinople_primitives::TRANSACTION_NAMESPACE,
                drop_grace_blocks: 3,
                signature_strategy: signature_strategy.clone(),
                hash_strategy: hash_strategy.clone(),
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
            }))
        } else {
            info!("secondary node: skipping mempool webserver");
            drop(mempool_actor);
            Box::pin(std::future::pending())
        };

        let startup = match startup {
            StartupModeConfig::MarshalSync => StartupMode::MarshalSync,
            StartupModeConfig::StateSync => {
                let finalization = bootstrapper_mailbox
                    .as_ref()
                    .expect("state-sync startup requires a bootstrapper")
                    .fetch_initial_target()
                    .await
                    .expect("bootstrapper actor exited before selecting a state-sync floor");
                StartupMode::StateSync { finalization }
            }
        };
        let startup_mode = match &startup {
            StartupMode::MarshalSync => "marshal_sync",
            StartupMode::StateSync { .. } => "state_sync",
        };
        info!(startup_mode, "selected validator startup mode");

        // Build the indexer wiring up-front. This consumes `indexer` from the
        // loaded config and returns `None` for primaries, validators that did
        // not declare an `indexer` block, or those that declared one with
        // `enabled: false`.
        let indexer_handle = maybe_build_indexer(is_primary, indexer).await;
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
                signature_strategy,
                hash_strategy,
                startup,
                sync_config: production_sync_config(),
                prune_cadence_blocks: NonZeroU64::new(prune_cadence_blocks)
                    .expect("prune_cadence_blocks must be non-zero"),
                genesis_leader: decoded.genesis_leader,
                transaction_namespace: constantinople_primitives::TRANSACTION_NAMESPACE,
                block_codec: Default::default(),
                bootstrapper: bootstrapper_mailbox.clone(),
                simplex_observer: relayer_observer
                    .map(SimplexObserver::Relayer)
                    .or_else(|| {
                        indexer_handle
                            .as_ref()
                            .and_then(|h| h.cert_reporter.clone())
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
        // Primaries report to the local mempool; secondaries with an indexer
        // configured report to the indexer; secondaries without report to no
        // one. The three cases share a single dispatch enum so the engine
        // type is fixed regardless of role.
        let reporter: Option<BlockUpdateReporter> = if is_primary {
            Some(BlockUpdateReporter::Mempool(mempool_mailbox.clone()))
        } else {
            indexer_handle
                .as_ref()
                .and_then(|h| h.block_reporter.clone())
                .map(BlockUpdateReporter::Indexer)
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

type CriticalTask = Pin<Box<dyn Future<Output = ()> + Send>>;

async fn wait_for_critical_task_exit<E, M, N>(
    bootstrapper_handle: Option<CriticalTask>,
    engine_handle: E,
    mempool_handle: M,
    network_handle: N,
) where
    E: Future,
    M: Future,
    N: Future,
{
    let mut bootstrapper_handle =
        bootstrapper_handle.unwrap_or_else(|| Box::pin(std::future::pending()));
    tokio::select! {
        _ = bootstrapper_handle.as_mut() => tracing::warn!("bootstrapper exited"),
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
    use super::wait_for_critical_task_exit;
    use std::{future::pending, time::Duration};

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
