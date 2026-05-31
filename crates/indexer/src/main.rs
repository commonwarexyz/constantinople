//! Shared backing-store binary for the indexer stack.
//!
//! `chain-indexer` serves the exoware simulator store. It supports both
//! direct local invocations (`--port`, `--data-dir`) and commonware-deployer's
//! `--hosts ... --config ...` convention for remote bundles.

use axum::{Router, routing::get};
use clap::{ArgGroup, Parser};
use exoware_simulator::{AppState, RocksStore, connect_stack};
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
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

async fn health() -> &'static str {
    "ok"
}

async fn run(data_dir: &Path, port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let engine = Arc::new(RocksStore::open(data_dir)?);
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
