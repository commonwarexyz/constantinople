#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod adapter_metrics;
pub mod client;
pub mod codec;
pub mod namespaces;
pub mod publisher;
mod simplex_block;
pub mod sql_schema;
mod store;
#[cfg(test)]
mod test_store;

pub use client::{IndexerClient, ReadError, TransactionMetadata};
pub use publisher::{CertificateReporter, Publisher};
pub use store::{StoreClientBuildError, StoreReadinessError, require_store_ready, store_client};
