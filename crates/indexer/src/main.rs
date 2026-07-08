//! Shared backing-store binary for the indexer stack.
//!
//! `chain-indexer` serves the exoware simulator store. It supports both
//! direct local invocations (`--port`, `--data-dir`) and commonware-deployer's
//! `--hosts ... --config ...` convention for remote bundles.

use axum::{Router, routing::get};
use clap::{ArgGroup, Parser};
use exoware_simulator::{
    AppState, RocksConfig, RocksStore, RocksWritePipelineConfig, connect_stack,
    rocksdb::{BlockBasedOptions, Cache, DBCompressionType, Options, UniversalCompactOptions},
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

const ROCKS_BACKGROUND_JOBS: i32 = 16;
const ROCKS_MAX_SUBCOMPACTIONS: u32 = 8;
const ROCKS_WRITE_BUFFER_SIZE: usize = 256 * 1024 * 1024;
const ROCKS_DB_WRITE_BUFFER_SIZE: usize = 4 * 1024 * 1024 * 1024;
const ROCKS_MEMTABLE_MEMORY_BUDGET: usize = ROCKS_DB_WRITE_BUFFER_SIZE;
const ROCKS_TARGET_FILE_SIZE_BASE: u64 = 512 * 1024 * 1024;
const ROCKS_MAX_BYTES_FOR_LEVEL_BASE: u64 = 16 * 1024 * 1024 * 1024;
const ROCKS_LEVEL_ZERO_COMPACTION_TRIGGER: i32 = 64;
const ROCKS_LEVEL_ZERO_SLOWDOWN_WRITES_TRIGGER: i32 = 1024;
const ROCKS_LEVEL_ZERO_STOP_WRITES_TRIGGER: i32 = 2048;
const ROCKS_UNIVERSAL_COMPACTION_SIZE_RATIO: i32 = 10;
const ROCKS_UNIVERSAL_COMPACTION_MIN_MERGE_WIDTH: i32 = 4;
const ROCKS_SYNC_BYTES: u64 = 8 * 1024 * 1024;
const ROCKS_COMPACTION_READAHEAD_SIZE: usize = 8 * 1024 * 1024;
const ROCKS_MIN_BLOB_SIZE: u64 = 16 * 1024;
const ROCKS_BLOB_FILE_SIZE: u64 = 512 * 1024 * 1024;
const ROCKS_BLOCK_CACHE_SIZE: usize = 1024 * 1024 * 1024;
const ROCKS_BLOB_CACHE_SIZE: usize = 4 * 1024 * 1024 * 1024;
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

async fn health() -> &'static str {
    "ok"
}

fn block_based_options(block_cache: &Cache) -> BlockBasedOptions {
    let mut opts = BlockBasedOptions::default();
    opts.set_block_cache(block_cache);
    opts.set_cache_index_and_filter_blocks(true);
    opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
    opts.set_pin_top_level_index_and_filter(true);
    opts
}

fn write_heavy_options(block_cache: &Cache, blob_cache: &Cache) -> Options {
    let mut opts = Options::default();
    let block_opts = block_based_options(block_cache);
    opts.increase_parallelism(ROCKS_BACKGROUND_JOBS);
    opts.set_max_background_jobs(ROCKS_BACKGROUND_JOBS);
    opts.set_max_subcompactions(ROCKS_MAX_SUBCOMPACTIONS);
    opts.set_block_based_table_factory(&block_opts);
    opts.optimize_universal_style_compaction(ROCKS_MEMTABLE_MEMORY_BUDGET);
    let mut universal = UniversalCompactOptions::default();
    universal.set_size_ratio(ROCKS_UNIVERSAL_COMPACTION_SIZE_RATIO);
    universal.set_min_merge_width(ROCKS_UNIVERSAL_COMPACTION_MIN_MERGE_WIDTH);
    opts.set_universal_compaction_options(&universal);
    opts.set_compression_type(DBCompressionType::None);
    opts.set_bottommost_compression_type(DBCompressionType::None);
    opts.set_wal_compression_type(DBCompressionType::None);
    opts.set_write_buffer_size(ROCKS_WRITE_BUFFER_SIZE);
    opts.set_db_write_buffer_size(ROCKS_DB_WRITE_BUFFER_SIZE);
    opts.set_max_write_buffer_number(8);
    opts.set_target_file_size_base(ROCKS_TARGET_FILE_SIZE_BASE);
    opts.set_max_bytes_for_level_base(ROCKS_MAX_BYTES_FOR_LEVEL_BASE);
    opts.set_level_zero_file_num_compaction_trigger(ROCKS_LEVEL_ZERO_COMPACTION_TRIGGER);
    opts.set_level_zero_slowdown_writes_trigger(ROCKS_LEVEL_ZERO_SLOWDOWN_WRITES_TRIGGER);
    opts.set_level_zero_stop_writes_trigger(ROCKS_LEVEL_ZERO_STOP_WRITES_TRIGGER);
    opts.set_bytes_per_sync(ROCKS_SYNC_BYTES);
    opts.set_wal_bytes_per_sync(ROCKS_SYNC_BYTES);
    opts.set_compaction_readahead_size(ROCKS_COMPACTION_READAHEAD_SIZE);
    opts.set_enable_blob_files(true);
    opts.set_min_blob_size(ROCKS_MIN_BLOB_SIZE);
    opts.set_blob_file_size(ROCKS_BLOB_FILE_SIZE);
    opts.set_blob_compression_type(DBCompressionType::None);
    opts.set_blob_compaction_readahead_size(ROCKS_COMPACTION_READAHEAD_SIZE as u64);
    opts.set_blob_cache(blob_cache);
    opts
}

fn chain_indexer_rocks_config() -> RocksConfig {
    let block_cache = Cache::new_lru_cache(ROCKS_BLOCK_CACHE_SIZE);
    let blob_cache = Cache::new_lru_cache(ROCKS_BLOB_CACHE_SIZE);

    RocksConfig {
        db_options: write_heavy_options(&block_cache, &blob_cache),
        default_cf_options: write_heavy_options(&block_cache, &blob_cache),
        meta_cf_options: Options::default(),
        log_cf_options: write_heavy_options(&block_cache, &blob_cache),
        write_pipeline: RocksWritePipelineConfig {
            max_commit_batch_bytes: NonZeroUsize::new(ROCKS_MAX_COMMIT_BATCH_BYTES)
                .expect("rocks write commit batch byte limit must be nonzero"),
        },
    }
}

async fn run(data_dir: &Path, port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let engine = Arc::new(RocksStore::open(
        data_dir,
        Some(chain_indexer_rocks_config()),
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

        let (data_dir, port) = load_settings(cli);

        assert_eq!(port, 18_090);
        assert_eq!(
            data_dir,
            config_path.parent().unwrap().join("chain-indexer")
        );

        let _ = fs::remove_file(config_path);
    }
}
