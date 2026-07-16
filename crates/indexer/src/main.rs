//! Shared backing-store binary for the indexer stack.
//!
//! `chain-indexer` serves the exoware simulator store. It supports both
//! direct local invocations (`--port`, `--data-dir`) and commonware-deployer's
//! `--hosts ... --config ...` convention for remote bundles.

use axum::{Router, routing::get};
use clap::{ArgGroup, Parser};
use exoware_simulator::{
    AppState, RocksConfig, RocksStore, RocksWritePipelineConfig, connect_stack, rocksdb::Options,
};
use serde::Deserialize;
use std::{
    fs,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
};
use tower_http::cors::CorsLayer;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

const ROCKS_MAX_SUBCOMPACTIONS: u32 = 8;
const ROCKS_SYNC_BYTES: u64 = 8 * 1024 * 1024;
const ROCKS_COMPACTION_READAHEAD_SIZE: usize = 8 * 1024 * 1024;
const ROCKS_MAX_COMMIT_BATCH_BYTES: usize = 1024 * 1024 * 1024;

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

/// DB-scoped RocksDB options for the chain-indexer store.
///
/// Only DB-scoped options apply here: the store opens every column family
/// with stock options, and its ingest path writes SSTs directly (no WAL or
/// memtables), so CF-scoped and write-path tuning has no effect.
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
