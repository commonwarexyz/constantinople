//! CLI definition.

use clap::ArgGroup;
use std::path::PathBuf;

#[derive(Debug, clap::Parser)]
#[command(name = "constantinople-spammer")]
#[command(group(
    ArgGroup::new("network_source")
        .required(true)
        .args(["peers", "hosts"])
))]
pub struct Cli {
    /// Path to the spammer config YAML (required for deployer mode, optional for local).
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Path to the local peer topology YAML file.
    #[arg(long, conflicts_with = "hosts")]
    pub peers: Option<PathBuf>,

    /// Path to the deployer-generated hosts file.
    #[arg(long, conflicts_with = "peers")]
    pub hosts: Option<PathBuf>,

    /// Number of spam accounts per validator in the ring transfer.
    #[arg(long, default_value_t = 10)]
    pub accounts: u32,

    /// Value to transfer per transaction (must be > 0 and <= 100).
    #[arg(long, default_value_t = 1)]
    pub value: u64,

    /// Seed offset for spam account keys (avoids collision with validator keys).
    #[arg(long, default_value_t = 1000)]
    pub seed_offset: u64,

    /// HTTP port for validators (only used in --hosts mode).
    #[arg(long, default_value_t = 8080)]
    pub http_port: u16,

    /// Number of rayon threads for parallel signing.
    #[arg(long, default_value_t = 2)]
    pub rayon_threads: usize,
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn parses_local_invocation() {
        let cli = Cli::try_parse_from([
            "constantinople-spammer",
            "--peers",
            "peers.yaml",
            "--accounts",
            "20",
        ])
        .expect("local invocation should parse");

        assert_eq!(cli.peers, Some(PathBuf::from("peers.yaml")));
        assert!(cli.hosts.is_none());
        assert!(cli.config.is_none());
        assert_eq!(cli.accounts, 20);
    }

    #[test]
    fn parses_deployer_invocation() {
        let cli = Cli::try_parse_from([
            "constantinople-spammer",
            "--config",
            "spammer.yaml",
            "--hosts",
            "hosts.yaml",
        ])
        .expect("deployer invocation should parse");

        assert_eq!(cli.config, Some(PathBuf::from("spammer.yaml")));
        assert_eq!(cli.hosts, Some(PathBuf::from("hosts.yaml")));
        assert!(cli.peers.is_none());
    }

    #[test]
    fn rejects_both_peers_and_hosts() {
        let result = Cli::try_parse_from([
            "constantinople-spammer",
            "--peers",
            "peers.yaml",
            "--hosts",
            "hosts.yaml",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_neither_peers_nor_hosts() {
        let result = Cli::try_parse_from(["constantinople-spammer"]);
        assert!(result.is_err());
    }
}
