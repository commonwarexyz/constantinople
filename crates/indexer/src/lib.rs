#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod adapter;
pub mod adapter_metrics;
pub mod client;
pub mod codec;
pub mod explorer;
pub mod namespaces;
pub mod publisher;
/// Generated explorer application protocol.
#[allow(missing_docs, elided_lifetimes_in_paths, clippy::all)]
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/constantinople.explorer.v1.rs"));
}
mod simplex_block;
pub mod sql_schema;
mod store;
mod submission;
#[cfg(test)]
mod test_store;

pub use client::{FinalizedPublicationTarget, IndexerClient, ReadError, TransactionMetadata};
pub use publisher::{CertificateReporter, Publisher};
pub use store::{
    StoreClient, StoreClientBuildError, store_client, wait_for_store_ready, writer_store_client,
};
