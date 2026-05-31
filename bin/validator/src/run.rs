//! Starts a validator from a YAML config.

use crate::{
    config::{
        IndexerConfig, LoadedConfig, StartupModeConfig, load_deployer_config, load_local_config,
    },
    state_reader::StateDbReader,
};
use commonware_actor::Feedback;
use commonware_codec::Encode;
use commonware_consensus::{Reporter, simplex::elector::RoundRobin, types::coding::Commitment};
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
    tokio::{
        Context as RuntimeContext,
        telemetry::{self, Logging},
    },
};
use commonware_storage::translator::EightCap;
use commonware_utils::{NZU64, NZUsize, TryCollect, ordered::Set, union};
use constantinople_application::consensus::{Databases, FinalizedHookFn};
use constantinople_engine::{
    BOOTSTRAPPER_CHANNEL, CERTIFICATE_CHANNEL, Channels, Config as EngineConfig, Engine,
    MARSHAL_CHANNEL, MARSHAL_RESOLVER_CHANNEL, RESOLVER_CHANNEL, STATE_RESOLVER_CHANNEL,
    StartupMode, TRANSACTION_RESOLVER_CHANNEL, ThresholdScheme, VOTE_CHANNEL, bootstrapper,
    types::{EngineActivity, EngineBlock},
};
use constantinople_indexer::{CertificateReporter, Publisher, publisher::qmdb::UploadPlan};
use constantinople_mempool::webserver::{self, AccountReader, Mailbox};
use std::{
    future::Future,
    num::NonZeroU64,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc},
    task::{JoinHandle, JoinSet},
};
use tracing::{error, info, warn};

const MEMPOOL_MAILBOX_SIZE: usize = 65_536;

const STATE_SYNC_APPLY_BATCH_SIZE: usize = 1024;
const MAX_POOL_BYTES: usize = 256 * 1024 * 1024;
const MAX_PROPOSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_FINALIZED_UPLOAD_BACKLOG: usize = 64;

/// Concrete type the engine sees in the `simplex_observer` slot.
///
/// We always pin `O` to the indexer's certificate publisher so the engine type
/// stays the same whether or not the indexer is enabled. Validators that opt
/// out simply pass `simplex_observer: None`.
type EngineCertReporter =
    CertificateReporter<Sha256, PublicKey, ThresholdScheme<PublicKey, MinSig>>;
type EnginePublisher = Publisher<Sha256, PublicKey>;
type EngineDatabases = Databases<commonware_runtime::tokio::Context, Sha256, EightCap, Rayon>;

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

/// Bundle of indexer state that needs to outlive engine startup.
struct IndexerHandle {
    cert_reporter: EngineCertReporter,
    finalized_tx: mpsc::Sender<FinalizedIndexUpload>,
    finalized_backlog: Arc<Semaphore>,
    /// Kept alive so the uploader tasks are not aborted while the validator runs.
    _uploaders: Vec<JoinHandle<()>>,
}

struct FinalizedIndexUpload {
    block: EngineBlock<Sha256, PublicKey>,
    databases: EngineDatabases,
    permit: OwnedSemaphorePermit,
}

/// Connects the indexer publisher only when finalized data is ready to upload.
struct LazyPublisher {
    context: RuntimeContext,
    store_url: String,
    buffer: usize,
    publisher: Mutex<Option<Arc<EnginePublisher>>>,
}

impl LazyPublisher {
    fn new(context: RuntimeContext, store_url: String, buffer: usize) -> Self {
        Self {
            context,
            store_url,
            buffer,
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

async fn run_finalized_uploader(
    context: RuntimeContext,
    publisher: Arc<LazyPublisher>,
    cert_reporter: EngineCertReporter,
    mut rx: mpsc::Receiver<FinalizedIndexUpload>,
) {
    let mut uploads = JoinSet::new();
    let mut rx_closed = false;
    loop {
        tokio::select! {
            maybe_upload = rx.recv(), if !rx_closed => {
                match maybe_upload {
                    Some(upload) => {
                        let publisher = publisher.publisher().await;
                        match publisher.plan_finalized(&upload.block).await {
                            Ok(plan) => {
                                uploads.spawn(upload_finalized_index(
                                    context.child("upload_finalized_index"),
                                    publisher,
                                    cert_reporter.clone(),
                                    upload,
                                    plan,
                                ));
                            }
                            Err(error) => {
                                warn!(
                                    height = upload.block.header.height,
                                    error = %error,
                                    "finalized index upload failed",
                                );
                                cert_reporter.publish_block(&upload.block).await;
                            }
                        }
                    }
                    None => rx_closed = true,
                }
            }
            maybe_done = uploads.join_next(), if !uploads.is_empty() => {
                if let Some(Err(error)) = maybe_done {
                    warn!(%error, "finalized index upload task panicked");
                }
            }
            else => break,
        }
    }
}

async fn upload_finalized_index(
    context: RuntimeContext,
    publisher: Arc<EnginePublisher>,
    cert_reporter: EngineCertReporter,
    upload: FinalizedIndexUpload,
    plan: UploadPlan,
) {
    let FinalizedIndexUpload {
        block,
        databases,
        permit,
    } = upload;

    match publisher
        .enqueue_planned_finalized_with_context(context, plan, &block, &databases)
        .await
    {
        Ok(completion) => completion.wait().await,
        Err(error) => {
            warn!(
                height = block.header.height,
                error = %error,
                "finalized index upload failed",
            );
        }
    }
    drop(permit);

    cert_reporter.publish_block(&block).await;
}

async fn acquire_finalized_upload_slot(backlog: Arc<Semaphore>) -> OwnedSemaphorePermit {
    backlog
        .acquire_owned()
        .await
        .expect("finalized upload backlog semaphore is never closed")
}

/// Build the indexer wiring iff the secondary validator opted in.
async fn maybe_build_indexer(
    context: RuntimeContext,
    is_primary: bool,
    indexer: Option<IndexerConfig>,
) -> Option<IndexerHandle> {
    let cfg = indexer?;
    if is_primary {
        return None;
    }

    info!(
        chain_indexer_url = %cfg.chain_indexer_url,
        "starting full indexer uploaders",
    );
    let (cert_reporter, cert_join) =
        EngineCertReporter::connect(&cfg.chain_indexer_url, cfg.upload_buffer);
    let publisher = Arc::new(LazyPublisher::new(
        context.child("publisher"),
        cfg.chain_indexer_url,
        cfg.upload_buffer,
    ));
    let finalized_backlog = Arc::new(Semaphore::new(MAX_FINALIZED_UPLOAD_BACKLOG));
    let (finalized_tx, finalized_rx) = mpsc::channel(MAX_FINALIZED_UPLOAD_BACKLOG);
    let finalized_join = tokio::spawn(run_finalized_uploader(
        context.child("finalized_uploader"),
        publisher,
        cert_reporter.clone(),
        finalized_rx,
    ));
    Some(IndexerHandle {
        cert_reporter,
        finalized_tx,
        finalized_backlog,
        _uploaders: vec![cert_join, finalized_join],
    })
}

fn indexer_finalized_hook(
    indexer: Option<&IndexerHandle>,
) -> Option<FinalizedHookFn<commonware_runtime::tokio::Context, Commitment, Sha256, PublicKey, Rayon>>
{
    let indexer = indexer?;
    let finalized_tx = indexer.finalized_tx.clone();
    let finalized_backlog = indexer.finalized_backlog.clone();
    let cert_reporter = indexer.cert_reporter.clone();
    Some(Arc::new(move |block, databases| {
        let finalized_tx = finalized_tx.clone();
        let finalized_backlog = finalized_backlog.clone();
        let cert_reporter = cert_reporter.clone();
        let block = block.clone();
        let databases = databases.clone();
        Box::pin(async move {
            let permit = acquire_finalized_upload_slot(finalized_backlog).await;
            let upload = FinalizedIndexUpload {
                block,
                databases,
                permit,
            };
            if let Err(upload) = enqueue_finalized_upload(&finalized_tx, upload).await {
                error!(
                    height = upload.block.header.height,
                    "finalized index uploader stopped; continuing consensus without index upload",
                );
                cert_reporter.publish_block(&upload.block).await;
            }
        })
    }))
}

async fn enqueue_finalized_upload<T>(tx: &mpsc::Sender<T>, upload: T) -> Result<(), T> {
    tx.send(upload)
        .await
        .map_err(|mpsc::error::SendError(upload)| upload)
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
        let bootstrapper_network = network.register(BOOTSTRAPPER_CHANNEL, quota, backlog);
        let (bootstrapper, bootstrapper_mailbox) = bootstrapper::Actor::new(
            context.child("bootstrapper"),
            bootstrapper::Config {
                public_key: decoded.public_key.clone(),
                peer_provider: oracle.clone(),
                blocker: oracle.clone(),
                scheme: ThresholdScheme::<ed25519::PublicKey, MinSig>::verifier(
                    &union(b"constantinople", b"_CONSENSUS"),
                    decoded.dkg_output.players().clone(),
                    decoded.dkg_output.public().clone(),
                ),
                mailbox_size: 32,
                round_timeout: Duration::from_secs(1),
                retry_interval: Duration::from_secs(1),
            },
        );
        let bootstrapper_handle = bootstrapper.start(bootstrapper_network);
        let bootstrapper_handle: CriticalTask = Box::pin(async move {
            let _ = bootstrapper_handle.await;
        });
        let network_handle = network.start();

        let relayer_view = relayer.as_ref().map(|_| crate::relayer::Observer::new());
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
        // loaded config and returns `None` for primaries or validators that
        // did not declare an `indexer` block.
        let indexer_handle =
            maybe_build_indexer(context.child("indexer"), is_primary, indexer).await;
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
                bootstrapper: Some(bootstrapper_mailbox.clone()),
                simplex_observer: relayer_observer.map(SimplexObserver::Relayer).or_else(|| {
                    indexer_handle
                        .as_ref()
                        .map(|h| h.cert_reporter.clone())
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
        // Primaries report to the local mempool. Secondaries upload index data
        // from the finalized hook and do not need marshal updates here.
        let reporter: Option<Mailbox<Commitment, PublicKey, Sha256>> = if is_primary {
            Some(mempool_mailbox.clone())
        } else {
            None
        };
        let engine_handle = engine.start(channels, reporter);

        wait_for_critical_task_exit(
            Some(bootstrapper_handle),
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
    use super::{
        MAX_FINALIZED_UPLOAD_BACKLOG, acquire_finalized_upload_slot, enqueue_finalized_upload,
        maybe_build_indexer, wait_for_critical_task_exit,
    };
    use crate::config::IndexerConfig;
    use commonware_runtime::Runner as _;
    use std::{future::pending, sync::Arc, time::Duration};
    use tokio::sync::Semaphore;

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
                Duration::from_millis(50),
                maybe_build_indexer(context, false, Some(indexer)),
            )
            .await
            .expect("publisher connection should not block startup")
            .expect("secondary should keep indexer wiring");

            assert_eq!(
                handle.finalized_backlog.available_permits(),
                MAX_FINALIZED_UPLOAD_BACKLOG
            );
        });
    }

    #[tokio::test]
    async fn finalized_upload_enqueue_returns_payload_when_uploader_stopped() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        drop(rx);

        let payload = enqueue_finalized_upload(&tx, 7)
            .await
            .expect_err("closed uploader should return the payload");

        assert_eq!(payload, 7);
    }

    #[tokio::test]
    async fn finalized_backlog_waits_after_64_outstanding_uploads() {
        let backlog = Arc::new(Semaphore::new(MAX_FINALIZED_UPLOAD_BACKLOG));
        let mut permits = Vec::with_capacity(MAX_FINALIZED_UPLOAD_BACKLOG);

        for _ in 0..MAX_FINALIZED_UPLOAD_BACKLOG {
            permits.push(acquire_finalized_upload_slot(backlog.clone()).await);
        }

        let full = tokio::time::timeout(
            Duration::from_millis(10),
            acquire_finalized_upload_slot(backlog.clone()),
        )
        .await;
        assert!(
            full.is_err(),
            "65th finalized upload must wait while 64 uploads are outstanding",
        );

        drop(permits.pop().expect("a held upload slot should exist"));
        let _permit = tokio::time::timeout(
            Duration::from_secs(1),
            acquire_finalized_upload_slot(backlog.clone()),
        )
        .await
        .expect("freed upload slot should admit the next finalized block");
    }
}
