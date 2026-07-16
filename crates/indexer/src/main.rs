//! Shared backing-store binary for the indexer stack.
//!
//! `chain-indexer` serves the exoware simulator store. It supports both
//! direct local invocations (`--port`, `--data-dir`) and commonware-deployer's
//! `--hosts ... --config ...` convention for remote bundles.

use axum::{
    Router,
    extract::{Request, State},
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use clap::{ArgGroup, Parser};
use exoware_simulator::{
    AppState, RocksConfig, RocksStore, RocksWritePipelineConfig, connect_stack, rocksdb::Options,
};
use prometheus_client::{
    encoding::text::encode,
    metrics::{counter::Counter, gauge::Gauge, histogram::Histogram},
    registry::Registry,
};
use serde::Deserialize;
use std::{
    fs,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};
use tower_http::cors::CorsLayer;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

const ROCKS_MAX_SUBCOMPACTIONS: u32 = 8;
const ROCKS_SYNC_BYTES: u64 = 8 * 1024 * 1024;
const ROCKS_COMPACTION_READAHEAD_SIZE: usize = 8 * 1024 * 1024;
const ROCKS_MAX_COMMIT_BATCH_BYTES: usize = 256 * 1024 * 1024;
const ROCKS_STAGE_WORKERS: usize = 4;
const ROCKS_MAX_QUEUED_WAVES: usize = 4;

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

    /// RocksDB parallelism (background compaction/flush jobs). Leaves
    /// RocksDB's stock parallelism when omitted.
    #[arg(long, conflicts_with_all = ["hosts", "config"])]
    db_parallelism: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct DeployerConfig {
    port: u16,
    data_dir: PathBuf,
    /// Leaves RocksDB's stock parallelism when omitted.
    #[serde(default)]
    db_parallelism: Option<i32>,
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

fn load_settings(cli: Cli) -> (PathBuf, u16, Option<i32>) {
    if let Some(config_path) = cli.config {
        let config = load_deployer_config(&config_path);
        return (
            resolve_data_dir(&config_path, config.data_dir),
            config.port,
            config.db_parallelism,
        );
    }

    (
        cli.data_dir
            .expect("clap should require --data-dir or --hosts"),
        cli.port,
        cli.db_parallelism,
    )
}

async fn health() -> &'static str {
    "ok"
}

/// Port the deployer scrapes for binary metrics.
const METRICS_PORT: u16 = 9090;
/// Ingest latency buckets: 1ms to 60s.
const INGEST_DURATION_BUCKETS: [f64; 12] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 15.0, 60.0,
];

/// Observability for store Put requests (the upload ingest path).
#[derive(Clone)]
struct IngestMetrics {
    in_flight: Gauge,
    requests: Counter,
    duration: Histogram,
}

fn ingest_metrics() -> (Arc<Registry>, IngestMetrics) {
    let mut registry = Registry::default();
    let metrics = IngestMetrics {
        in_flight: Gauge::default(),
        requests: Counter::default(),
        duration: Histogram::new(INGEST_DURATION_BUCKETS),
    };
    registry.register(
        "ingest_in_flight",
        "Store Put requests in flight",
        metrics.in_flight.clone(),
    );
    registry.register(
        "ingest_requests",
        "Store Put requests served",
        metrics.requests.clone(),
    );
    registry.register(
        "ingest_duration",
        "Store Put request latency (s)",
        metrics.duration.clone(),
    );
    (Arc::new(registry), metrics)
}

/// Decrements in-flight on drop so a client disconnect cannot leak the gauge.
struct InFlight(Gauge);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.dec();
    }
}

async fn track_ingest(
    State(metrics): State<IngestMetrics>,
    request: Request,
    next: Next,
) -> Response {
    if !request.uri().path().ends_with("/Put") {
        return next.run(request).await;
    }
    metrics.in_flight.inc();
    let in_flight = InFlight(metrics.in_flight.clone());
    let start = Instant::now();
    let response = next.run(request).await;
    drop(in_flight);
    metrics.requests.inc();
    metrics.duration.observe(start.elapsed().as_secs_f64());
    response
}

async fn serve_metrics(State(registry): State<Arc<Registry>>) -> String {
    let mut out = String::new();
    encode(&mut out, &registry).expect("metrics encoding cannot fail");
    out
}

/// DB-scoped RocksDB options for the chain-indexer store.
///
/// Only DB-scoped options apply here: the store owns its column-family
/// options (tuned to its write path), and its ingest path writes SSTs
/// directly (no WAL or memtables), so write-path tuning has no effect.
fn chain_indexer_db_options(db_parallelism: Option<i32>) -> Options {
    let mut opts = Options::default();
    if let Some(jobs) = db_parallelism {
        opts.increase_parallelism(jobs);
        opts.set_max_background_jobs(jobs);
    }
    opts.set_max_subcompactions(ROCKS_MAX_SUBCOMPACTIONS);
    opts.set_bytes_per_sync(ROCKS_SYNC_BYTES);
    opts.set_compaction_readahead_size(ROCKS_COMPACTION_READAHEAD_SIZE);
    opts
}

fn chain_indexer_rocks_config(db_parallelism: Option<i32>) -> RocksConfig {
    RocksConfig {
        db_options: chain_indexer_db_options(db_parallelism),
        write_pipeline: RocksWritePipelineConfig {
            max_commit_batch_bytes: NonZeroUsize::new(ROCKS_MAX_COMMIT_BATCH_BYTES)
                .expect("rocks write commit batch byte limit must be nonzero"),
            stage_workers: NonZeroUsize::new(ROCKS_STAGE_WORKERS)
                .expect("rocks stage worker count must be nonzero"),
            max_queued_waves: NonZeroUsize::new(ROCKS_MAX_QUEUED_WAVES)
                .expect("rocks queued wave limit must be nonzero"),
        },
    }
}

async fn run(
    data_dir: &Path,
    port: u16,
    db_parallelism: Option<i32>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let engine = Arc::new(RocksStore::open(
        data_dir,
        Some(chain_indexer_rocks_config(db_parallelism)),
    )?);
    let (registry, metrics) = ingest_metrics();
    let connect = connect_stack(AppState::new(engine));
    let app = Router::new()
        .route("/health", get(health))
        .fallback_service(connect)
        .layer(middleware::from_fn_with_state(metrics, track_ingest))
        .layer(CorsLayer::very_permissive());

    let metrics_addr = std::net::SocketAddr::from(([0, 0, 0, 0], METRICS_PORT));
    let metrics_app = Router::new()
        .route("/metrics", get(serve_metrics))
        .with_state(registry);
    let metrics_listener = tokio::net::TcpListener::bind(metrics_addr).await?;
    tokio::spawn(async move {
        if let Err(error) = axum::serve(metrics_listener, metrics_app).await {
            tracing::warn!(?error, "metrics server exited");
        }
    });

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    info!(%addr, directory = %data_dir.display(), "chain indexer listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let (data_dir, port, db_parallelism) = load_settings(cli);
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
        if let Err(error) = run(&data_dir, port, db_parallelism).await {
            eprintln!("chain-indexer exited with error: {error}");
            std::process::exit(1);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{Cli, load_settings};
    use clap::Parser;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_path(prefix: &str, suffix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{unique}{suffix}"))
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

        let (data_dir, port, db_parallelism) = load_settings(cli);

        assert_eq!(port, 18_090);
        assert_eq!(db_parallelism, None);
        assert_eq!(
            data_dir,
            config_path.parent().unwrap().join("chain-indexer")
        );

        let _ = fs::remove_file(config_path);
    }
}
