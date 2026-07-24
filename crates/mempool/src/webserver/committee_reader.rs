//! Read-only committee state for the mempool HTTP server.

use futures::future::BoxFuture;

/// Number of blocks in a committee epoch.
pub const EPOCH_LENGTH: u64 = 1024;

/// An immutable peer eligible for committee membership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EligiblePeer {
    /// Hex-encoded Ed25519 public key.
    pub peer: String,
    /// Immutable network address.
    pub address: String,
    /// Advisory local connection state.
    pub connected: bool,
}

/// Committee state at the latest finalized height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitteeSnapshot {
    /// Latest finalized block height.
    pub height: u64,
    /// Committee active in the current epoch.
    pub current: Vec<String>,
    /// Committee scheduled for the target epoch.
    pub scheduled: Vec<String>,
    /// Complete immutable catalog of eligible peers.
    pub available: Vec<EligiblePeer>,
}

/// Reads committed committee state and advisory peer connectivity.
pub trait CommitteeReader: Send + Sync + 'static {
    /// Returns the latest committee snapshot.
    fn get<'a>(&'a self) -> BoxFuture<'a, CommitteeSnapshot>;
}
