//! Constantinople validator binary.

mod cli;
mod config;
mod relayer;
mod run;
mod state_reader;

use clap::Parser;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

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
