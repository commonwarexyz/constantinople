//! Constantinople validator binary.

mod cli;
mod config;
mod indexer;
mod relayer;
mod run;
mod state_reader;

use clap::Parser;
use commonware_allocator::mimalloc::{Config, MiMalloc, Purge, Reserve};
use std::time::Duration;

/// Pins enough memory for the default page caches plus the working set, so steady-state
/// allocations reuse it instead of arenas that purge memory and fault it back in. Memory beyond
/// it is kept for a minute, longer than recurring work such as metrics scrapes.
#[global_allocator]
static ALLOC: MiMalloc = MiMalloc::new(Config {
    purge: Purge::After(Duration::from_secs(60)),
    reserve: Some(Reserve::pinned(12 << 30)),
    ..Config::DEFAULT
});

fn main() {
    let cli = cli::Cli::parse();
    if let Some(hosts) = cli.hosts {
        run::run_deployer(hosts, cli.config);
        return;
    }

    run::run_local(
        cli.peers.expect("clap should require --peers or --hosts"),
        cli.config,
    );
}
