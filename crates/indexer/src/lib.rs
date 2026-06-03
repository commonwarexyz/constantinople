#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod client;
pub mod codec;
pub mod publisher;
mod simplex_block;
pub mod sql_schema;

pub use client::{IndexerClient, ReadError};
pub use publisher::{CertificateReporter, Publisher};
