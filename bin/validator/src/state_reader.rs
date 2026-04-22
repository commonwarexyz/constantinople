//! [`AccountReader`] adapter that forwards lookups to the validator's state
//! database.

use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use constantinople_engine::types::StateSyncDb;
use constantinople_mempool::webserver::AccountReader;
use constantinople_primitives::{Account, Address};
use futures::future::{BoxFuture, FutureExt};

/// Forwards [`AccountReader::get`] to the attached state database.
pub struct StateDbReader<E, H>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
    H: Hasher,
{
    db: StateSyncDb<E, H>,
}

impl<E, H> StateDbReader<E, H>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
    H: Hasher,
{
    pub const fn new(db: StateSyncDb<E, H>) -> Self {
        Self { db }
    }
}

impl<E, H> AccountReader for StateDbReader<E, H>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
    H: Hasher,
{
    fn get<'a>(&'a self, address: Address) -> BoxFuture<'a, Option<Account>> {
        async move {
            let db = self.db.read().await;
            db.get(&address).await.ok().flatten()
        }
        .boxed()
    }
}
