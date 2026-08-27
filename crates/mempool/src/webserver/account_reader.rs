//! Read-only account lookup for the mempool HTTP server.

use constantinople_primitives::{Account, TransactionPublicKey};
use futures::future::BoxFuture;

/// The account backend could not answer the lookup.
///
/// Distinct from a missing account: readers return this when the state
/// database (or the bridge to the runtime that owns it) is unavailable, so
/// HTTP handlers can answer 503 instead of asserting the account does not
/// exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountsUnavailable;

/// Reads committed account state. Backed by the validator's state database.
pub trait AccountReader: Send + Sync + 'static {
    /// Returns the account for `public_key`, `Ok(None)` if it has not been
    /// written, or [`AccountsUnavailable`] if the backend cannot answer.
    fn get<'a>(
        &'a self,
        public_key: TransactionPublicKey,
    ) -> BoxFuture<'a, Result<Option<Account>, AccountsUnavailable>>;
}
