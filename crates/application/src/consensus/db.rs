//! Database aliases and batch helpers for consensus execution.

use commonware_cryptography::Hasher;
use commonware_glue::stateful::db::{
    DatabaseSet, Unmerkleized,
    any::{AnyStaged, AnyUnmerkleized},
};
use commonware_parallel::Strategy;
use commonware_runtime::{BufferPooler, Clock, Metrics, Storage};
use commonware_storage::{
    index::unordered::Index as UnorderedIndex,
    journal::contiguous::fixed::Journal as FixedJournal,
    mmr,
    qmdb::{
        any::{
            operation::Operation as AnyOperation,
            unordered::{Update as UnorderedUpdate, fixed},
            value::FixedEncoding,
        },
        keyless::fixed as keyless_fixed,
        sync::{Target as AnyTarget, compact::Target as CompactTarget},
    },
    translator::EightCap,
};
use commonware_utils::sync::TracedAsyncRwLock;
use constantinople_primitives::{Account, AccountKey};
use std::{future::Future, sync::Arc};

/// Shared QMDB handle for the application state database.
pub type StateDatabase<E, H, T, S> =
    Arc<TracedAsyncRwLock<fixed::Db<mmr::Family, E, AccountKey, Account, H, T, S>>>;

pub type TransactionHistoryDb<E, H, S> =
    keyless_fixed::CompactDb<mmr::Family, E, <H as Hasher>::Digest, H, S>;

pub type TransactionHistoryOperation<H> =
    keyless_fixed::Operation<mmr::Family, <H as Hasher>::Digest>;

pub type StateSyncTarget<D> = AnyTarget<mmr::Family, D>;
pub type TransactionHistoryTarget<D> = CompactTarget<mmr::Family, D>;

/// Shared QMDB handle for the append-only transaction history database.
pub type TransactionDatabase<E, H, S> = Arc<TracedAsyncRwLock<TransactionHistoryDb<E, H, S>>>;

/// The backing databases owned by the application.
pub type Databases<E, H, T, S> = (StateDatabase<E, H, T, S>, TransactionDatabase<E, H, S>);

/// Unmerkleized application state batch, staged by the executor before writes.
pub type StateBatch<E, H, T, S> = AnyUnmerkleized<
    mmr::Family,
    E,
    FixedJournal<E, AnyOperation<mmr::Family, UnorderedUpdate<AccountKey, FixedEncoding<Account>>>>,
    UnorderedIndex<T, mmr::Location>,
    H,
    UnorderedUpdate<AccountKey, FixedEncoding<Account>>,
    S,
>;

/// Staged application state batch: touched keys are read and their resolved
/// locations retained, so indexed updates skip key re-resolution at merkleize.
pub type StateStaged<E, H, T, S> = AnyStaged<
    mmr::Family,
    E,
    FixedJournal<E, AnyOperation<mmr::Family, UnorderedUpdate<AccountKey, FixedEncoding<Account>>>>,
    UnorderedIndex<T, mmr::Location>,
    H,
    UnorderedUpdate<AccountKey, FixedEncoding<Account>>,
    S,
>;

/// Final account values for staged reads, keyed by staged read index.
///
/// The state root depends only on the final key->value set each index resolves
/// to, so entry order is not consensus relevant.
pub type StateUpdates = Vec<(usize, Option<Account>)>;

pub(super) type TransactionBatch<E, H, S> =
    <TransactionDatabase<E, H, S> as DatabaseSet<E>>::Unmerkleized;

pub(super) type StateMerkleized<E, H, T, S> = <StateBatch<E, H, T, S> as Unmerkleized>::Merkleized;

pub(super) type TransactionMerkleized<E, H, S> =
    <TransactionBatch<E, H, S> as Unmerkleized>::Merkleized;

pub(super) type MerkleizedDatabases<E, H, S> = (
    StateMerkleized<E, H, EightCap, S>,
    TransactionMerkleized<E, H, S>,
);

pub(super) fn apply_transaction_digests<E, H, S>(
    batch: TransactionBatch<E, H, S>,
    digests: &[H::Digest],
) -> TransactionBatch<E, H, S>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    digests
        .iter()
        .fold(batch, |batch, digest| batch.append(*digest))
}

/// Merkleizes the staged state batch and the transaction-history batch
/// concurrently. `transaction_batch` is a future so a caller can keep
/// appending to the history batch on the strategy's pool while the state
/// merkleize runs; callers holding a finished batch pass it via
/// [`core::future::ready`].
pub(super) async fn finalize_execution<E, H, S>(
    state_staged: StateStaged<E, H, EightCap, S>,
    state_updates: StateUpdates,
    transaction_batch: impl Future<Output = TransactionBatch<E, H, S>>,
) -> Result<MerkleizedDatabases<E, H, S>, commonware_storage::qmdb::Error<mmr::Family>>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    // The two batches own separate databases and locks, and each merkleize
    // dispatches its CPU to the strategy's pool internally, so joining the
    // futures runs the state and transaction-history merkleizes
    // concurrently.
    let (state_merkleized, transaction_merkleized) = futures::join!(
        state_staged.merkleize(state_updates, Vec::new()),
        async move { transaction_batch.await.merkleize().await },
    );
    Ok((state_merkleized?, transaction_merkleized?))
}

#[cfg(test)]
mod tests {
    use super::{StateDatabase, StateUpdates};
    use commonware_codec::FixedSize as _;
    use commonware_cryptography::Sha256;
    use commonware_glue::stateful::db::{DatabaseSet, Merkleized as _, Unmerkleized as _};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, buffer::paged::CacheRef, deterministic};
    use commonware_storage::{
        journal::contiguous::fixed::Config as FixedJournalConfig,
        merkle::full::Config as MmrConfig, qmdb::any::FixedConfig, translator::EightCap,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};
    use constantinople_primitives::{Account, AccountKey, Nonce};

    type Db = StateDatabase<deterministic::Context, Sha256, EightCap, Sequential>;

    fn config(cache: CacheRef) -> FixedConfig<EightCap, Sequential> {
        FixedConfig {
            merkle_config: MmrConfig {
                journal_partition: "state-order-test-merkle-journal".into(),
                metadata_partition: "state-order-test-merkle-metadata".into(),
                items_per_blob: NZU64!(1024),
                write_buffer: NZUsize!(4096),
                strategy: Sequential,
                page_cache: cache.clone(),
            },
            journal_config: FixedJournalConfig {
                partition: "state-order-test-log".into(),
                items_per_blob: NZU64!(1024),
                page_cache: cache,
                write_buffer: NZUsize!(4096),
            },
            translator: EightCap,
            init_cache_size: Some(NZUsize!(1024)),
        }
    }

    #[test]
    fn state_root_ignores_update_order() {
        deterministic::Runner::default().start(|context| async move {
            let cache = CacheRef::from_pooler(&context, NZU16!(16), NZUsize!(4096));
            let db =
                <Db as DatabaseSet<deterministic::Context>>::init(context, config(cache)).await;
            let key = |byte| AccountKey::from([byte; AccountKey::SIZE]);
            let account = |balance| Account {
                balance,
                nonce: Nonce::default(),
            };
            let a = key(1);
            let b = key(2);
            let c = key(3);
            let d = key(4);

            let mut seed = db.new_batches().await;
            seed = seed.write(c, Some(account(300)));
            seed = seed.write(a, Some(account(100)));
            let seed = seed.merkleize().await.expect("seed state");
            db.finalize(seed).await;

            // The same final key->value set must produce the same root
            // regardless of staged read order or update-entry order.
            let (_, staged) = db
                .new_batches()
                .await
                .stage(&[&a, &b, &c, &d])
                .await
                .expect("first stage");
            let first: StateUpdates = vec![
                (2, Some(account(301))),
                (0, Some(account(101))),
                (3, Some(account(401))),
                (1, Some(account(201))),
            ];
            let x = staged
                .merkleize(first, Vec::new())
                .await
                .expect("first order")
                .root();

            let (_, staged) = db
                .new_batches()
                .await
                .stage(&[&d, &c, &b, &a])
                .await
                .expect("second stage");
            let second: StateUpdates = vec![
                (3, Some(account(101))),
                (1, Some(account(301))),
                (2, Some(account(201))),
                (0, Some(account(401))),
            ];
            let y = staged
                .merkleize(second, Vec::new())
                .await
                .expect("second order")
                .root();

            assert_eq!(x, y);
        });
    }
}
