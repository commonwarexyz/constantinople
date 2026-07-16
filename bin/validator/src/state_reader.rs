//! [`AccountReader`] adapter that forwards lookups to the validator's state
//! database.

use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::{BufferPooler, Clock, Metrics, Storage};
use constantinople_engine::types::StateSyncDb;
use constantinople_mempool::webserver::AccountReader;
use constantinople_primitives::{Account, AccountKey, TransactionPublicKey};
use futures::future::{BoxFuture, FutureExt};

/// Forwards [`AccountReader::get`] to the attached state database.
pub struct StateDbReader<E, H, T>
where
    E: BufferPooler + Storage + Clock + Metrics + Send + Sync + 'static,
    H: Hasher,
    T: Strategy,
{
    db: StateSyncDb<E, H, T>,
}

impl<E, H, T> StateDbReader<E, H, T>
where
    E: BufferPooler + Storage + Clock + Metrics + Send + Sync + 'static,
    H: Hasher,
    T: Strategy,
{
    pub const fn new(db: StateSyncDb<E, H, T>) -> Self {
        Self { db }
    }
}

impl<E, H, T> AccountReader for StateDbReader<E, H, T>
where
    E: BufferPooler + Storage + Clock + Metrics + Send + Sync + 'static,
    H: Hasher,
    T: Strategy,
{
    fn get<'a>(&'a self, public_key: TransactionPublicKey) -> BoxFuture<'a, Option<Account>> {
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
