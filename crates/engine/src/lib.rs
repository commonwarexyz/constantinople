#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

//! Constantinople consensus engine wiring.
//!
//! This crate assembles the full validator stack around
//! [`constantinople_application`]:
//!
//! - stateful QMDB management
//! - erasure-coded marshal
//! - epoch-scoped threshold simplex consensus
//! - continuous DKG reshare and state-sync recovery
//!
//! The public API stays narrow. [`Engine`] owns the assembled actors and
//! [`Config`] describes the validator-specific inputs needed to initialize
//! them. Tests can drive the same engine under the deterministic runtime and
//! simulated networking.

pub mod secret_store;
pub mod types;

mod dkg;

pub use dkg::{CommitteeParticipants, DynamicProvider, Registrar};

mod engine;

#[doc(inline)]
pub use engine::{
    CERTIFICATE_CHANNEL, CHANNELS, COMMITTEE_RESOLVER_CHANNEL, Channels, Config, DKG_CHANNEL,
    DKG_PROBE_CHANNEL, EPOCH_LENGTH, Engine, MARSHAL_CHANNEL, MARSHAL_RESOLVER_CHANNEL,
    MAX_PENDING_ACKS, PROBE_CHANNEL, RESOLVER_CHANNEL, STATE_RESOLVER_CHANNEL, SimplexTimeouts,
    StartupMode, TRANSACTION_RESOLVER_CHANNEL, ThresholdScheme, VOTE_CHANNEL,
};

#[cfg(all(test, feature = "test-utils"))]
mod tests;
