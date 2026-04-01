//! Transaction spammer for Constantinople.

mod remote;
mod shared;
mod spam;

use clap::Parser;
use std::{
    num::{NonZeroU32, NonZeroUsize},
    path::PathBuf,
};

#[derive(Debug, Parser)]
#[command(name = "constantinople-tx")]
struct Cli {
    /// Number of accounts to create.
    #[arg(long)]
    count: Option<NonZeroUsize>,
    /// Validator HTTP endpoints (repeat to target multiple mempools).
    #[arg(long = "endpoint")]
    endpoints: Vec<String>,
    /// Starting seed for deterministic key generation.
    #[arg(long, default_value_t = 0)]
    seed_start: u64,
    /// Starting nonce for every sender.
    #[arg(long, default_value_t = 0)]
    nonce: u64,
    /// Fixed submission rate in transactions per second.
    #[arg(long)]
    tps: Option<NonZeroU32>,
    #[arg(long, hide = true)]
    hosts: Option<PathBuf>,
    #[arg(long, hide = true)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.hosts {
        Some(hosts) => {
            let Some(config) = cli.config else {
                eprintln!("missing --config");
                std::process::exit(2);
            };

            let args = match remote::load_args(hosts, config) {
                Ok(args) => args,
                Err(err) => {
                    eprintln!("{err}");
                    std::process::exit(1);
                }
            };
            spam::run(args).await
        }
        None => {
            let Some(count) = cli.count else {
                eprintln!("missing --count");
                std::process::exit(2);
            };
            let Some(tps) = cli.tps else {
                eprintln!("missing --tps");
                std::process::exit(2);
            };

            let args = match spam::Args::new(
                count.get(),
                cli.endpoints,
                cli.seed_start,
                cli.nonce,
                tps.get(),
            ) {
                Ok(args) => args,
                Err(err) => {
                    eprintln!("{err}");
                    std::process::exit(1);
                }
            };
            spam::run(args).await
        }
    };

    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::Parser;
    use std::{
        num::{NonZeroU32, NonZeroUsize},
        path::PathBuf,
    };

    #[test]
    fn parses_local_spam_invocation() {
        let cli = Cli::try_parse_from([
            "constantinople-tx",
            "--count",
            "8",
            "--endpoint",
            "http://127.0.0.1:8080",
            "--tps",
            "100",
        ])
        .expect("local spam invocation should parse");

        assert_eq!(cli.count, NonZeroUsize::new(8));
        assert_eq!(cli.endpoints, vec!["http://127.0.0.1:8080"]);
        assert_eq!(cli.tps, NonZeroU32::new(100));
        assert!(cli.hosts.is_none());
    }

    #[test]
    fn parses_deployer_style_invocation() {
        let cli = Cli::try_parse_from([
            "constantinople-tx",
            "--hosts",
            "hosts.yaml",
            "--config",
            "tx-spammer.toml",
        ])
        .expect("deployer invocation should parse");

        assert_eq!(cli.hosts, Some(PathBuf::from("hosts.yaml")));
        assert_eq!(cli.config, Some(PathBuf::from("tx-spammer.toml")));
    }
}
