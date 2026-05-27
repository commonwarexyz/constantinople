//! Read-only account lookup for the mempool HTTP server.

use constantinople_primitives::{Account, TransactionPublicKey};
use futures::future::BoxFuture;

/// Reads committed account state. Backed by the validator's state database.
pub trait AccountReader: Send + Sync + 'static {
    /// Returns the account for `public_key`, or `None` if it has not been written.
    fn get<'a>(&'a self, public_key: TransactionPublicKey) -> BoxFuture<'a, Option<Account>>;
}
