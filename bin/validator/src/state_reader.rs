//! [`AccountReader`] adapter that forwards lookups to the validator's state
//! database.
//!
//! HTTP handlers run on the sidecar tokio runtime, but the state database's
//! storage futures must be created and polled on the consensus runtime thread
//! (a hard requirement on the io_uring runtime). [`BridgedAccountReader`]
//! carries lookups across that boundary over channels.
//! [`serve_account_reads`] answers them from the consensus runtime.

use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage, Supervisor};
use constantinople_engine::types::StateSyncDb;
use constantinople_mempool::webserver::{AccountReader, AccountsUnavailable};
use constantinople_primitives::{Account, AccountKey, TransactionPublicKey};
use futures::future::{BoxFuture, FutureExt};
use std::sync::Arc;
use tokio::sync::{Semaphore, mpsc, oneshot};

/// Concurrent account lookups allowed on the consensus runtime.
///
/// Lookups run interleaved with consensus on the single runtime thread, so
/// in-flight reads are capped. Excess requests queue in the bridge channel
/// and overflow surfaces to submitters as 503.
const ACCOUNT_READ_MAX_IN_FLIGHT: usize = 32;

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
    fn get<'a>(
        &'a self,
        public_key: TransactionPublicKey,
    ) -> BoxFuture<'a, Result<Option<Account>, AccountsUnavailable>> {
        async move {
            let db = self.db.read().await;
            db.get(&AccountKey::from_public_key(&public_key))
                .await
                .map_err(|_| AccountsUnavailable)
        }
        .boxed()
    }
}

/// An account lookup in flight between the HTTP runtime and the consensus
/// runtime.
type AccountRequest = (
    TransactionPublicKey,
    oneshot::Sender<Result<Option<Account>, AccountsUnavailable>>,
);

/// [`AccountReader`] whose lookups are answered by [`serve_account_reads`] on
/// the consensus runtime.
///
/// Safe to call from any runtime: `get` only awaits channels.
pub struct BridgedAccountReader {
    requests: mpsc::Sender<AccountRequest>,
}

impl BridgedAccountReader {
    /// Create a reader and the request stream to hand to
    /// [`serve_account_reads`].
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<AccountRequest>) {
        let (requests, rx) = mpsc::channel(capacity);
        (Self { requests }, rx)
    }
}

impl AccountReader for BridgedAccountReader {
    fn get<'a>(
        &'a self,
        public_key: TransactionPublicKey,
    ) -> BoxFuture<'a, Result<Option<Account>, AccountsUnavailable>> {
        async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            // A closed channel or dropped reply means the consensus-side
            // service is gone: unavailable, not "account does not exist".
            self.requests
                .try_send((public_key, reply_tx))
                .map_err(|_| AccountsUnavailable)?;
            reply_rx.await.map_err(|_| AccountsUnavailable)?
        }
        .boxed()
    }
}

/// Answer bridged account lookups from the runtime that owns the state
/// database.
///
/// Must run on the consensus runtime thread: each lookup polls state-database
/// storage futures. Lookups are served concurrently, one spawned task per
/// request, with in-flight reads capped at [`ACCOUNT_READ_MAX_IN_FLIGHT`] so
/// lookup bursts cannot crowd out consensus work.
pub async fn serve_account_reads<E, H, T>(
    context: E,
    db: StateSyncDb<E, H, T>,
    mut requests: mpsc::Receiver<AccountRequest>,
) where
    E: Spawner + Supervisor + BufferPooler + Storage + Clock + Metrics + Send + Sync + 'static,
    H: Hasher,
    T: Strategy + Send + Sync + 'static,
{
    let reader = Arc::new(StateDbReader::new(db));
    let permits = Arc::new(Semaphore::new(ACCOUNT_READ_MAX_IN_FLIGHT));
    while let Some((public_key, reply)) = requests.recv().await {
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .expect("account read semaphore is never closed");
        let reader = reader.clone();
        context.child("get").spawn(move |_| async move {
            let _permit = permit;
            let _ = reply.send(reader.get(public_key).await);
        });
    }
}
