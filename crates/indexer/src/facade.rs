//! Shared command-line and server bootstrap support for the indexer facades.

use axum::Router;
use commonware_deployer::aws::Hosts;
use constantinople_primitives::resolve_named_http_url;
use serde::Deserialize;
use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};
use tracing::info;

/// Errors returned while building or serving an indexer facade.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Command-line arguments common to all Store-backed indexer facades.
#[derive(clap::Args, Debug)]
pub struct Args {
    /// URL of the exoware Store the index writers publish to.
    #[arg(long, conflicts_with_all = ["hosts", "config"])]
    pub store_url: Option<String>,
    /// Bind address (default `0.0.0.0`).
    #[arg(long, default_value = "0.0.0.0")]
    pub host: IpAddr,
    /// Path to the deployer-generated hosts file.
    #[arg(long, requires = "config", conflicts_with = "store_url")]
    pub hosts: Option<PathBuf>,
    /// Path to the deployer-provided facade config YAML.
    #[arg(long, requires = "hosts", conflicts_with = "store_url")]
    pub config: Option<PathBuf>,
}

/// Resolved settings used to serve an indexer facade.
pub struct Settings {
    /// Resolved exoware Store URL.
    pub store_url: String,
    /// Interface on which the facade listens.
    pub host: IpAddr,
    /// Port on which the facade listens.
    pub port: u16,
}

#[derive(Debug, Deserialize)]
struct DeployerConfig {
    port: u16,
    chain_indexer_url: String,
}

/// Resolve local or deployer command-line arguments into server settings.
pub fn load_settings(args: Args, local_port: u16) -> Settings {
    if let Some(config_path) = args.config {
        let raw = fs::read_to_string(config_path).expect("failed to read indexer facade config");
        let config: DeployerConfig =
            serde_yaml::from_str(&raw).expect("failed to parse indexer facade config");
        let hosts_path = args
            .hosts
            .expect("clap should require --hosts with --config");
        let raw_hosts = fs::read_to_string(hosts_path).expect("failed to read hosts file");
        let hosts: Hosts = serde_yaml::from_str(&raw_hosts).expect("failed to parse hosts file");
        let store_url = resolve_named_http_url(&config.chain_indexer_url, |name| {
            hosts
                .hosts
                .iter()
                .find(|host| host.name.as_str() == name)
                .map(|host| host.ip)
        });
        return Settings {
            store_url,
            host: args.host,
            port: config.port,
        };
    }

    Settings {
        store_url: args
            .store_url
            .expect("clap should require --store-url or --hosts"),
        host: args.host,
        port: local_port,
    }
}

/// Serve a facade router using the resolved settings.
pub async fn serve(app: Router, settings: &Settings, service: &str) -> Result<(), Error> {
    let addr = SocketAddr::from((settings.host, settings.port));
    info!(%addr, store_url = settings.store_url, service, "indexer facade listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Initialize the standard facade tracing subscriber.
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();
}

/// Convert a facade result into the process exit status used by the binaries.
pub fn exit(result: Result<(), Error>, service: &str) -> std::process::ExitCode {
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{service} failed: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Health-check handler shared by the facade routers.
pub async fn health() -> &'static str {
    "ok"
}

#[cfg(test)]
mod tests {
    use super::{Args, load_settings};
    use clap::{ArgGroup, Parser};
    use std::fs;
    use tempfile::TempDir;

    #[derive(Debug, Parser)]
    #[command(group(
        ArgGroup::new("mode")
            .required(true)
            .args(["store_url", "hosts"])
    ))]
    struct TestCli {
        #[command(flatten)]
        facade: Args,
    }

    #[test]
    fn parses_local_invocation() {
        let cli = TestCli::try_parse_from(["facade", "--store-url", "http://127.0.0.1:8090"])
            .expect("local invocation should parse");
        let settings = load_settings(cli.facade, 8_091);

        assert_eq!(settings.store_url, "http://127.0.0.1:8090");
        assert_eq!(settings.port, 8_091);
        assert_eq!(settings.host.to_string(), "0.0.0.0");
    }

    #[test]
    fn parses_deployer_invocation_and_resolves_host() {
        let temp = TempDir::new().expect("temp directory");
        let config_path = temp.path().join("config.yaml");
        let hosts_path = temp.path().join("hosts.yaml");
        fs::write(
            &config_path,
            "port: 18092\nchain_indexer_url: http://chain-indexer:8090\n",
        )
        .expect("config should write");
        fs::write(
            &hosts_path,
            "monitoring:\n  public: 10.0.0.1\n  private: 10.0.0.2\nhosts:\n  - name: \"chain-indexer\"\n    region: us-east-1\n    ip: 203.0.113.9\n",
        )
        .expect("hosts should write");

        let cli = TestCli::try_parse_from([
            "facade",
            "--hosts",
            hosts_path.to_str().expect("utf-8 path"),
            "--config",
            config_path.to_str().expect("utf-8 path"),
        ])
        .expect("deployer invocation should parse");
        let settings = load_settings(cli.facade, 8_091);

        assert_eq!(settings.store_url, "http://203.0.113.9:8090");
        assert_eq!(settings.port, 18_092);
    }

    #[test]
    fn rejects_incomplete_or_ambiguous_modes() {
        assert!(TestCli::try_parse_from(["facade"]).is_err());
        assert!(
            TestCli::try_parse_from([
                "facade",
                "--store-url",
                "http://127.0.0.1:8090",
                "--hosts",
                "hosts.yaml",
                "--config",
                "config.yaml",
            ])
            .is_err()
        );
        assert!(
            TestCli::try_parse_from(["facade", "--hosts", "hosts.yaml"]).is_err(),
            "--hosts should require --config"
        );
    }
}
