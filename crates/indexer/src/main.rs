//! Local exoware store binary for the indexer.
//!
//! This binary is a thin wrapper around [`exoware_simulator::server::run`].
//! It is intended for local development and integration testing only — point
//! the validator's `indexer.exoware_url` at it to capture and inspect uploads
//! without standing up the full hosted exoware service.

use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Parser)]
#[command(name = "indexer", about = "Run a local exoware store backing the constantinople indexer")]
struct Cli {
    /// TCP port to bind on `0.0.0.0`.
    #[arg(long, default_value_t = 8080)]
    port: u16,

    /// Directory used by the simulator's RocksDB engine.
    #[arg(long)]
    data_dir: PathBuf,
}

fn main() {
    let cli = Cli::parse();
    fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    runtime.block_on(async move {
        if let Err(error) = exoware_simulator::server::run(&cli.data_dir, cli.port).await {
            eprintln!("indexer simulator exited with error: {error}");
            std::process::exit(1);
        }
    });
}
