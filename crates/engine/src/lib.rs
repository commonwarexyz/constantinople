#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

//! Constantinople consensus engine wiring.
//!
//! This crate assembles the full validator stack around
//! [`constantinople_application`]:
//!
//! - stateful QMDB management
//! - erasure-coded marshal
//! - fixed-epoch threshold simplex consensus
//!
//! The public API stays narrow. [`Engine`] owns the assembled actors and
//! [`Config`] describes the validator-specific inputs needed to initialize
//! them. Tests can drive the same engine under the deterministic runtime and
//! simulated networking.

pub mod bootstrapper;
pub mod types;

mod engine;

#[doc(inline)]
pub use engine::{
    BOOTSTRAPPER_CHANNEL, CERTIFICATE_CHANNEL, CHANNELS, Channels, Config, Engine, MARSHAL_CHANNEL,
    MARSHAL_RESOLVER_CHANNEL, RESOLVER_CHANNEL, STATE_RESOLVER_CHANNEL,
    TRANSACTION_RESOLVER_CHANNEL, ThresholdScheme, VOTE_CHANNEL,
};

#[cfg(all(test, feature = "test-utils"))]
mod tests;
