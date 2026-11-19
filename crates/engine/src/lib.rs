#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

//! Constantinople consensus engine wiring.
//!
//! This crate assembles the full validator stack around
//! [`constantinople_application`]:
//!
//! - stateful QMDB management
//! - erasure-coded marshal
//! - fixed-epoch simplex consensus whose votes carry reports on
//!   transactions authenticated by tags
//!
//! The public API stays narrow. [`Engine`] owns the assembled actors and
//! [`Config`] describes the validator-specific inputs needed to initialize
//! them. Tests can drive the same engine under the deterministic runtime and
//! simulated networking.

pub mod types;

mod application;
mod block;
mod engine;
mod shard_filter;
mod tags;

#[doc(inline)]
pub use engine::{
    CERTIFICATE_CHANNEL, CHANNELS, COLUMN_CHANNEL, Channels, Config, Engine, MARSHAL_CHANNEL,
    MARSHAL_RESOLVER_CHANNEL, MAX_PENDING_ACKS, PROBE_CHANNEL, RESOLVER_CHANNEL,
    STATE_RESOLVER_CHANNEL, Scheme, StartupMode, TRANSACTION_RESOLVER_CHANNEL, VOTE_CHANNEL,
};
pub use tags::EngineChain;

#[cfg(all(test, feature = "test-utils"))]
mod tests;
