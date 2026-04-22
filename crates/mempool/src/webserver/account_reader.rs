//! Read-only account lookup for the mempool HTTP server.

use constantinople_primitives::{Account, Address};
use futures::future::BoxFuture;

/// Reads committed account state. Backed by the validator's state database.
pub trait AccountReader: Send + Sync + 'static {
    /// Returns the account at `address`, or `None` if the account has not been
    /// written.
    fn get<'a>(&'a self, address: Address) -> BoxFuture<'a, Option<Account>>;
}
