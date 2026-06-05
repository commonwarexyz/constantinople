//! Metadata query/stream service for the shared indexer store.
//!
//! `metadata-indexer` exposes Constantinople's SQL metadata schema
//! (`block_meta`, `tx_meta`, `tx_activity`, and `account_meta`) over
//! `store.sql.v1.Service`. It supports both
//! direct local invocations (`--store-url`, `--port`) and commonware-deployer's
//! `--hosts ... --config ...` convention for remote bundles.

use axum::{Router, routing::get};
use clap::{ArgGroup, Parser};
use commonware_deployer::aws::Hosts;
use constantinople_indexer::sql_schema::build_meta_schema;
use exoware_sdk::StoreClient;
use exoware_sql::{SqlServer, sql_connect_stack};
use serde::Deserialize;
use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};
use tracing::info;

#[derive(Parser, Debug)]
#[command(
    name = "metadata-indexer",
    version,
    about = "SQL service over Constantinople metadata tables"
)]
#[command(group(
    ArgGroup::new("mode")
        .required(true)
        .args(["store_url", "hosts"])
))]
struct Cli {
    /// URL of the exoware Store the SQL writer publishes to.
    #[arg(long, conflicts_with_all = ["hosts", "config"])]
    store_url: Option<String>,
    /// Bind address (default `0.0.0.0`).
    #[arg(long, default_value = "0.0.0.0")]
    host: IpAddr,
    /// Listen port.
    #[arg(long, default_value_t = 8091)]
    port: u16,
    /// Path to the deployer-generated hosts file.
    #[arg(long, requires = "config", conflicts_with = "store_url")]
    hosts: Option<PathBuf>,
    /// Path to the deployer-provided metadata-indexer config YAML.
    #[arg(long, requires = "hosts", conflicts_with = "store_url")]
    config: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct DeployerConfig {
    port: u16,
    chain_indexer_url: String,
}

async fn health() -> &'static str {
    "ok"
}

fn load_deployer_config(path: &Path) -> DeployerConfig {
    let raw = fs::read_to_string(path).expect("failed to read metadata-indexer config");
    serde_yaml::from_str(&raw).expect("failed to parse metadata-indexer config")
}

fn resolve_named_http_url(url: &str, hosts_by_name: &HashMap<&str, std::net::IpAddr>) -> String {
    let Some(rest) = url.strip_prefix("http://") else {
        return url.to_string();
    };
    let (authority, suffix) = match rest.split_once('/') {
        Some((authority, suffix)) => (authority, format!("/{suffix}")),
        None => (rest, String::new()),
    };
    let Some((host, port)) = authority.rsplit_once(':') else {
        return url.to_string();
    };
    let Some(ip) = hosts_by_name.get(host) else {
        return url.to_string();
    };

    format!("http://{ip}:{port}{suffix}")
}

fn load_settings(cli: Cli) -> (String, IpAddr, u16) {
    if let Some(config_path) = cli.config {
        let config = load_deployer_config(&config_path);
        let hosts_path = cli
            .hosts
            .expect("clap should require --hosts with --config");
        let raw_hosts = fs::read_to_string(hosts_path).expect("failed to read hosts file");
        let hosts: Hosts = serde_yaml::from_str(&raw_hosts).expect("failed to parse hosts file");
        let hosts_by_name = hosts
            .hosts
            .iter()
            .map(|host| (host.name.as_str(), host.ip))
            .collect::<HashMap<_, _>>();
        let store_url = resolve_named_http_url(&config.chain_indexer_url, &hosts_by_name);
        return (store_url, cli.host, config.port);
    }

    (
        cli.store_url
            .expect("clap should require --store-url or --hosts"),
        cli.host,
        cli.port,
    )
}

fn build_server(
    store_url: &str,
) -> Result<Arc<SqlServer>, Box<dyn std::error::Error + Send + Sync>> {
    let client = StoreClient::new(store_url);
    let schema = build_meta_schema(client).map_err(|e| format!("configure schema: {e}"))?;
    let server = SqlServer::new(schema)?;
    Ok(Arc::new(server))
}

async fn run(
    store_url: &str,
    host: IpAddr,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = build_server(store_url)?;
    // The explorer hits this server from a browser; allow any origin so
    // local dev (Vite on a different port) can connect without a proxy.
    let app = Router::new()
        .route("/health", get(health))
        .fallback_service(sql_connect_stack(server))
        .layer(tower_http::cors::CorsLayer::very_permissive());

    let addr = SocketAddr::from((host, port));
    info!(%addr, store_url, "constantinople sql server listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    init_tracing();
    let cli = Cli::parse();
    let (store_url, host, port) = load_settings(cli);

    let result = run(&store_url, host, port).await;

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("metadata-indexer failed: {err}");
            std::process::ExitCode::FAILURE
        }
    }
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
            "metadata-indexer",
            "--store-url",
            "http://127.0.0.1:8090",
            "--port",
            "8091",
        ])
        .expect("local invocation should parse");

        assert_eq!(cli.store_url, Some("http://127.0.0.1:8090".to_string()));
        assert_eq!(cli.port, 8091);
        assert!(cli.hosts.is_none());
        assert!(cli.config.is_none());
    }

    #[test]
    fn parses_deployer_invocation() {
        let cli = Cli::try_parse_from([
            "metadata-indexer",
            "--hosts",
            "hosts.yaml",
            "--config",
            "config.conf",
        ])
        .expect("deployer invocation should parse");

        assert_eq!(cli.hosts, Some(PathBuf::from("hosts.yaml")));
        assert_eq!(cli.config, Some(PathBuf::from("config.conf")));
        assert!(cli.store_url.is_none());
    }

    #[test]
    fn deployer_mode_resolves_chain_indexer_host_from_hosts_file() {
        let config_path = temp_path("metadata-indexer", ".yaml");
        let hosts_path = temp_path("metadata-indexer-hosts", ".yaml");
        fs::write(
            &config_path,
            "port: 18091\nchain_indexer_url: http://chain-indexer:8090\n",
        )
        .expect("config should write");
        fs::write(
            &hosts_path,
            "monitoring:\n  public: 10.0.0.1\n  private: 10.0.0.2\nhosts:\n  - name: \"chain-indexer\"\n    region: us-east-1\n    ip: 203.0.113.9\n",
        )
        .expect("hosts should write");

        let cli = Cli::try_parse_from([
            "metadata-indexer",
            "--hosts",
            hosts_path.to_str().expect("utf-8 path"),
            "--config",
            config_path.to_str().expect("utf-8 path"),
        ])
        .expect("deployer invocation should parse");

        let (store_url, _host, port) = load_settings(cli);

        assert_eq!(store_url, "http://203.0.113.9:8090");
        assert_eq!(port, 18_091);

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(hosts_path);
    }
}
