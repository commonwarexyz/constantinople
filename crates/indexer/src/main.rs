//! Shared backing-store binary for the indexer stack.
//!
//! `chain-indexer` wraps the exoware simulator store. It supports both
//! direct local invocations (`--port`, `--data-dir`) and commonware-deployer's
//! `--hosts ... --config ...` convention for remote bundles.

use axum::{Router, routing::get};
use bytes::Bytes;
use clap::{ArgGroup, Parser};
use exoware_server::QueryExtra;
use exoware_simulator::{AppState, Ingest, Log, Prune, Query, RocksStore, Sequence, connect_stack};
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Parser)]
#[command(
    name = "chain-indexer",
    about = "Run the shared Constantinople indexer store"
)]
#[command(group(
    ArgGroup::new("mode")
        .required(true)
        .args(["data_dir", "hosts"])
))]
struct Cli {
    /// TCP port to bind on `0.0.0.0`.
    #[arg(long, default_value_t = 8090)]
    port: u16,

    /// Directory used by the simulator's RocksDB engine.
    #[arg(long, conflicts_with_all = ["hosts", "config"])]
    data_dir: Option<PathBuf>,

    /// Path to the deployer-generated hosts file.
    #[arg(long, requires = "config", conflicts_with = "data_dir")]
    hosts: Option<PathBuf>,

    /// Path to the deployer-provided chain-indexer config YAML.
    #[arg(long, requires = "hosts", conflicts_with = "data_dir")]
    config: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct DeployerConfig {
    port: u16,
    data_dir: PathBuf,
}

fn load_deployer_config(path: &Path) -> DeployerConfig {
    let raw = fs::read_to_string(path).expect("failed to read chain-indexer config");
    serde_yaml::from_str(&raw).expect("failed to parse chain-indexer config")
}

fn resolve_data_dir(config_path: &Path, data_dir: PathBuf) -> PathBuf {
    if data_dir.is_absolute() {
        return data_dir;
    }

    config_path
        .parent()
        .expect("config file has no parent directory")
        .join(data_dir)
}

fn load_settings(cli: Cli) -> (PathBuf, u16) {
    if let Some(config_path) = cli.config {
        let config = load_deployer_config(&config_path);
        return (resolve_data_dir(&config_path, config.data_dir), config.port);
    }

    (
        cli.data_dir
            .expect("clap should require --data-dir or --hosts"),
        cli.port,
    )
}

#[derive(Clone)]
struct OrderedStore<E> {
    inner: E,
    put_lock: Arc<Mutex<()>>,
}

impl<E> OrderedStore<E> {
    fn new(inner: E) -> Self {
        Self {
            inner,
            put_lock: Arc::new(Mutex::new(())),
        }
    }
}

impl<E> Sequence for OrderedStore<E>
where
    E: Sequence,
{
    fn current_sequence(&self) -> u64 {
        self.inner.current_sequence()
    }
}

impl<E> Ingest for OrderedStore<E>
where
    E: Ingest,
{
    async fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> Result<u64, String> {
        let _permit = self.put_lock.lock().await;
        self.inner.put_batch(kvs).await
    }
}

impl<E> Query for OrderedStore<E>
where
    E: Query,
{
    type RangeScan = E::RangeScan;

    async fn get(&self, key: Bytes) -> Result<(Option<Vec<u8>>, QueryExtra), String> {
        self.inner.get(key).await
    }

    async fn range_scan(
        &self,
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    ) -> Result<Self::RangeScan, String> {
        self.inner.range_scan(start, end, limit, forward).await
    }

    async fn get_many(
        &self,
        keys: Vec<Bytes>,
    ) -> Result<(Vec<(Vec<u8>, Option<Vec<u8>>)>, QueryExtra), String> {
        self.inner.get_many(keys).await
    }
}

impl<E> Prune for OrderedStore<E>
where
    E: Prune,
{
    async fn apply_prune_policies(
        &self,
        document: exoware_sdk::prune_policy::PrunePolicyDocument,
    ) -> Result<(), String> {
        self.inner.apply_prune_policies(document).await
    }
}

impl<E> Log for OrderedStore<E>
where
    E: Log,
{
    async fn get_batch(&self, sequence_number: u64) -> Result<Option<Vec<(Bytes, Bytes)>>, String> {
        self.inner.get_batch(sequence_number).await
    }

    async fn oldest_retained_batch(&self) -> Result<Option<u64>, String> {
        self.inner.oldest_retained_batch().await
    }
}

async fn health() -> &'static str {
    "ok"
}

async fn run(data_dir: &Path, port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let engine = Arc::new(OrderedStore::new(RocksStore::open(data_dir)?));
    let connect = connect_stack(AppState::new(engine));
    let app = Router::new()
        .route("/health", get(health))
        .fallback_service(connect)
        .layer(CorsLayer::very_permissive());

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    info!(%addr, directory = %data_dir.display(), "chain indexer listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let (data_dir, port) = load_settings(cli);
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    runtime.block_on(async move {
        if let Err(error) = run(&data_dir, port).await {
            eprintln!("chain-indexer exited with error: {error}");
            std::process::exit(1);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{Cli, OrderedStore, load_settings};
    use bytes::Bytes;
    use clap::Parser;
    use exoware_simulator::{Ingest, Sequence};
    use std::{
        fs,
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{SystemTime, UNIX_EPOCH},
    };
    use tokio::time::{Duration, sleep};

    fn temp_path(prefix: &str, suffix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{unique}{suffix}"))
    }

    #[derive(Clone, Default)]
    struct ConcurrentPutProbe {
        active: Arc<AtomicUsize>,
        max_active: Arc<AtomicUsize>,
        next_sequence: Arc<AtomicUsize>,
    }

    impl Sequence for ConcurrentPutProbe {
        fn current_sequence(&self) -> u64 {
            self.next_sequence.load(Ordering::SeqCst) as u64
        }
    }

    impl Ingest for ConcurrentPutProbe {
        async fn put_batch(&self, _kvs: Vec<(Bytes, Bytes)>) -> Result<u64, String> {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(active, Ordering::SeqCst);
            sleep(Duration::from_millis(5)).await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(self.next_sequence.fetch_add(1, Ordering::SeqCst) as u64 + 1)
        }
    }

    #[test]
    fn parses_local_invocation() {
        let cli = Cli::try_parse_from([
            "chain-indexer",
            "--port",
            "8090",
            "--data-dir",
            "./chain-indexer",
        ])
        .expect("local invocation should parse");

        assert_eq!(cli.port, 8090);
        assert_eq!(cli.data_dir, Some(PathBuf::from("./chain-indexer")));
        assert!(cli.hosts.is_none());
        assert!(cli.config.is_none());
    }

    #[test]
    fn parses_deployer_invocation() {
        let cli = Cli::try_parse_from([
            "chain-indexer",
            "--hosts",
            "hosts.yaml",
            "--config",
            "config.conf",
        ])
        .expect("deployer invocation should parse");

        assert_eq!(cli.hosts, Some(PathBuf::from("hosts.yaml")));
        assert_eq!(cli.config, Some(PathBuf::from("config.conf")));
        assert!(cli.data_dir.is_none());
    }

    #[test]
    fn deployer_mode_reads_port_and_relative_data_dir_from_config() {
        let config_path = temp_path("chain-indexer", ".yaml");
        fs::write(&config_path, "port: 18090\ndata_dir: chain-indexer\n")
            .expect("config should write");

        let cli = Cli::try_parse_from([
            "chain-indexer",
            "--hosts",
            "hosts.yaml",
            "--config",
            config_path.to_str().expect("utf-8 path"),
        ])
        .expect("deployer invocation should parse");

        let (data_dir, port) = load_settings(cli);

        assert_eq!(port, 18_090);
        assert_eq!(
            data_dir,
            config_path.parent().unwrap().join("chain-indexer")
        );

        let _ = fs::remove_file(config_path);
    }

    #[tokio::test]
    async fn ordered_store_serializes_backend_puts() {
        let probe = ConcurrentPutProbe::default();
        let store = OrderedStore::new(probe.clone());
        let mut puts = Vec::new();

        for _ in 0..16 {
            let store = store.clone();
            puts.push(tokio::spawn(async move {
                store
                    .put_batch(vec![(Bytes::from_static(b"k"), Bytes::from_static(b"v"))])
                    .await
                    .expect("put should succeed");
            }));
        }
        for put in puts {
            put.await.expect("put task should not panic");
        }

        assert_eq!(probe.max_active.load(Ordering::SeqCst), 1);
    }
}
