//! Store simulator CLI (RocksDB).

use clap::{Arg, ArgAction, Command};
use std::path::PathBuf;
use tracing::error;

use exoware_simulator::rocks::WRITER_THREAD_PREFIX;
use exoware_simulator::server;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

const DIRECTORY_FLAG: &str = "directory";
const PORT_FLAG: &str = "port";
const VERBOSE_FLAG: &str = "verbose";

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let home_directory = std::env::var("HOME").expect("$HOME is not configured");
    let default_directory = PathBuf::from(format!("{home_directory}/.exoware_store_simulator"));
    let default_directory: &'static str = default_directory.to_str().unwrap().to_string().leak();

    let matches = Command::new("simulator")
        .version(crate_version())
        .about("Store API simulator (RocksDB).")
        .arg_required_else_help(true)
        .arg(
            Arg::new(VERBOSE_FLAG)
                .short('v')
                .long(VERBOSE_FLAG)
                .help("Enable verbose logging.")
                .action(ArgAction::SetTrue),
        )
        .subcommand(
            Command::new(server::CMD)
                .about("Simulator server commands.")
                .arg_required_else_help(true)
                .subcommand(
                    Command::new(server::RUN_CMD)
                        .about("Run the simulator.")
                        .arg(
                            Arg::new(DIRECTORY_FLAG)
                                .long(DIRECTORY_FLAG)
                                .help("RocksDB directory.")
                                .default_value(default_directory)
                                .value_parser(clap::value_parser!(PathBuf))
                                .action(ArgAction::Set),
                        )
                        .arg(
                            Arg::new(PORT_FLAG)
                                .long(PORT_FLAG)
                                .help("Listen port.")
                                .default_value("8080")
                                .value_parser(clap::value_parser!(u16))
                                .action(ArgAction::Set),
                        ),
                ),
        )
        .get_matches();

    let level = if matches.get_flag(VERBOSE_FLAG) {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(level).init();

    // Store write errors are fatal by design: a panicked writer thread can never accept writes
    // again, so kill the process instead of serving reads from a store that silently fails
    // every put. A restart rolls the store forward from its log. `abort` rather than `exit`:
    // exit-time teardown runs while tokio workers and RocksDB background threads are still
    // live and can hang. The kill must stay scoped to the writer threads (not fire on every
    // panic): a panic on a request-serving thread is contained by tokio and fails only that
    // request, so an unconditional abort would let a single bad request kill the process.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        if std::thread::current()
            .name()
            .is_some_and(|name| name.starts_with(WRITER_THREAD_PREFIX))
        {
            std::process::abort();
        }
    }));

    if let Some(server_matches) = matches.subcommand_matches(server::CMD) {
        match server_matches.subcommand() {
            Some((server::RUN_CMD, m)) => {
                let directory = m.get_one::<PathBuf>(DIRECTORY_FLAG).unwrap();
                let port = m.get_one::<u16>(PORT_FLAG).unwrap();
                match server::run(directory, *port).await {
                    Ok(()) => return std::process::ExitCode::SUCCESS,
                    Err(e) => {
                        error!(error = ?e, "server failed");
                    }
                }
            }
            _ => error!("invalid subcommand"),
        }
    }

    std::process::ExitCode::FAILURE
}
