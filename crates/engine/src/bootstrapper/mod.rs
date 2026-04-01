//! Bootstrap late validators over a dedicated engine-owned p2p channel.
//!
//! The bootstrapper has two jobs:
//! - serve the local finalized tip, including its finalization certificate
//! - help a fresh validator choose an initial state-sync target
//!
//! Target selection is intentionally small and conservative:
//! 1. ask peers for their latest finalized tip
//! 2. verify every certificate and block/certificate match
//! 3. resolve subscriptions as soon as `f+1` peers return the same finalized tip
//! 4. retry on a fixed cadence if the round does not reach the threshold
//!
//! The retry cadence is part of the protocol. Callers subscribe once and wait.
//! They do not poll the actor aggressively, which keeps outbound fanout low and
//! avoids peer rate limits.
//!
//! Reliability relies on an `f+1` assumption for peer set `0`:
//! the finalization certificate is verified independently, so the quorum
//! only ensures we have a reliable sync target rather than trusting a
//! single peer. Because at most `f` peers can be Byzantine, `f+1` matching
//! responses guarantee at least one honest peer agrees on the tip.
//! The actor only counts one response per peer and rejects malformed messages,
//! invalid certificates, and block/finalization mismatches before they can
//! influence the vote count.

use crate::types::{EngineBlock, EngineFinalization, EngineMarshalMailbox, EngineVariant};

mod actor;
pub use actor::{Actor, Config};

mod mailbox;
pub use mailbox::Mailbox;
