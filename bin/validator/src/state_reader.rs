//! [`AccountReader`] adapter that forwards lookups to the validator's state
//! database.

use commonware_cryptography::{Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Storage};
use constantinople_engine::types::StateSyncDb;
use constantinople_mempool::webserver::AccountReader;
use constantinople_primitives::{Account, AccountKey};
use futures::future::{BoxFuture, FutureExt};

/// Forwards [`AccountReader::get`] to the attached state database.
pub struct StateDbReader<E, H, P, T>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
    H: Hasher,
    P: PublicKey,
    T: Strategy,
{
    db: StateSyncDb<E, H, P, T>,
}

impl<E, H, P, T> StateDbReader<E, H, P, T>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
    H: Hasher,
    P: PublicKey,
    T: Strategy,
{
    pub const fn new(db: StateSyncDb<E, H, P, T>) -> Self {
        Self { db }
    }
}

impl<E, H, P, T> AccountReader<P> for StateDbReader<E, H, P, T>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
    H: Hasher,
    P: PublicKey,
    T: Strategy,
{
    fn get<'a>(&'a self, public_key: P) -> BoxFuture<'a, Option<Account>> {
        async move {
            let db = self.db.read().await;
            db.get(&AccountKey::from_public_key(&public_key))
                .await
                .ok()
                .flatten()
        }
        .boxed()
    }
}
