//! CLI definition.

use clap::ArgGroup;
use std::path::PathBuf;

#[derive(Debug, clap::Parser)]
#[command(name = "constantinople")]
#[command(group(
    ArgGroup::new("network_source")
        .required(true)
        .args(["peers", "hosts"])
))]
pub struct Cli {
    /// Path to the validator TOML config.
    #[arg(long)]
    pub config: PathBuf,
    /// Path to the local peer topology TOML file.
    #[arg(long, conflicts_with = "hosts")]
    pub peers: Option<PathBuf>,
    /// Path to the deployer-generated hosts file.
    #[arg(long, conflicts_with = "peers")]
    pub hosts: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn parses_local_invocation() {
        let cli = Cli::try_parse_from([
            "constantinople",
            "--config",
            "validator.toml",
            "--peers",
            "peers.toml",
        ])
        .expect("local invocation should parse");

        assert_eq!(cli.config, PathBuf::from("validator.toml"));
        assert_eq!(cli.peers, Some(PathBuf::from("peers.toml")));
        assert!(cli.hosts.is_none());
    }

    #[test]
    fn parses_deployer_style_invocation() {
        let cli = Cli::try_parse_from([
            "constantinople",
            "--hosts",
            "hosts.yaml",
            "--config",
            "validator.toml",
        ])
        .expect("deployer invocation should parse");

        assert_eq!(cli.config, PathBuf::from("validator.toml"));
        assert_eq!(cli.hosts, Some(PathBuf::from("hosts.yaml")));
        assert!(cli.peers.is_none());
    }
}
