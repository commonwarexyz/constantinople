#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod client;
pub mod codec;
pub mod publisher;
mod simplex_block;
pub mod sql_schema;

pub use client::{IndexerClient, ReadError};
pub use publisher::{CertificateReporter, Publisher};

/// Route the qmdb-indexer facade serves the account-state operation log under.
/// Clients append this to the facade's base URL.
pub const QMDB_STATE_ROUTE: &str = "/state";
/// Route the qmdb-indexer facade serves the transaction operation log under.
/// Clients append this to the facade's base URL.
pub const QMDB_TRANSACTIONS_ROUTE: &str = "/transactions";
