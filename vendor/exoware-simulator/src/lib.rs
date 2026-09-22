//! In-process store API simulator (naive RocksDB).

pub mod rocks;
pub mod server;

pub use exoware_server::{connect_stack, AppState, Ingest, Log, Prune, Query, Retention, Sequence};
pub use rocks::{RocksConfig, RocksStore, RocksWritePipelineConfig};
pub use rocksdb;
pub use server::{open_temp, run, CMD, RUN_CMD};
