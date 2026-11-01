//! Database aliases and batch helpers for consensus execution.

use commonware_cryptography::Hasher;
use commonware_glue::stateful::db::{
    DatabaseSet, Reader, Shared, Unmerkleized,
    any::{AnyStaged, AnyUnmerkleized},
};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    index::unordered::Index as UnorderedIndex,
    journal::contiguous::fixed::Journal as FixedJournal,
    mmr,
    qmdb::{
        any::{
            batch::Slot,
            operation::Operation as AnyOperation,
            unordered::{Update as UnorderedUpdate, fixed},
            value::FixedEncoding,
        },
        keyless::fixed as keyless_fixed,
        sync::{CompactTarget, Target as AnyTarget},
    },
    translator::EightCap,
};
use constantinople_primitives::{Account, AccountKey};
use std::future::Future;

/// Shared QMDB handle for the application state database.
pub type StateDatabase<E, H, T, S> =
    Shared<fixed::Db<mmr::Family, E, AccountKey, Account, H, T, S>>;

pub type TransactionHistoryDb<E, H, S> =
    keyless_fixed::CompactDb<mmr::Family, E, <H as Hasher>::Digest, H, S>;

pub type TransactionHistoryOperation<H> =
    keyless_fixed::Operation<mmr::Family, <H as Hasher>::Digest>;

pub type StateOperation =
    AnyOperation<mmr::Family, UnorderedUpdate<AccountKey, FixedEncoding<Account>>>;

pub type StateSyncTarget<D> = AnyTarget<mmr::Family, D>;
pub type TransactionHistoryTarget<D> = CompactTarget<mmr::Family, D>;

/// Shared QMDB handle for the append-only transaction history database.
pub type TransactionDatabase<E, H, S> = Shared<TransactionHistoryDb<E, H, S>>;

/// The backing databases owned by the application.
pub type Databases<E, H, T, S> = (StateDatabase<E, H, T, S>, TransactionDatabase<E, H, S>);

pub type DatabaseReaders<E, H, T, S> = (
    Reader<fixed::Db<mmr::Family, E, AccountKey, Account, H, T, S>>,
    Reader<TransactionHistoryDb<E, H, S>>,
);

/// Unmerkleized application state batch, staged by the executor before writes.
pub type StateBatch<E, H, T, S> = AnyUnmerkleized<
    mmr::Family,
    E,
    FixedJournal<E, StateOperation>,
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
    FixedJournal<E, StateOperation>,
    UnorderedIndex<T, mmr::Location>,
    H,
    UnorderedUpdate<AccountKey, FixedEncoding<Account>>,
    S,
>;

/// Final account values for a staged state batch: one slot per staged read, in
/// staged read order.
///
/// The state root depends only on the final value each key resolves to, so the
/// order of the staged reads is not consensus relevant.
pub type StateSlots = Vec<Slot<Account>>;

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
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    digests
        .iter()
        .fold(batch, |batch, digest| batch.append(*digest))
}

/// Merkleizes the staged state batch, with one slot per staged read, and the
/// transaction-history batch concurrently. `transaction_batch` is a future so
/// a caller can keep appending to the history batch on the strategy's pool
/// while the state merkleize runs; callers holding a finished batch pass it via
/// [`core::future::ready`].
pub(super) async fn finalize_execution<E, H, S>(
    state_staged: StateStaged<E, H, EightCap, S>,
    slots: StateSlots,
    transaction_batch: impl Future<Output = TransactionBatch<E, H, S>>,
) -> Result<MerkleizedDatabases<E, H, S>, commonware_storage::qmdb::Error<mmr::Family>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    // The two batches own separate databases and locks, and each merkleize
    // dispatches its CPU to the strategy's pool internally, so joining the
    // futures runs the state and transaction-history merkleizes
    // concurrently.
    let (state_merkleized, transaction_merkleized) =
        futures::join!(state_staged.merkleize(slots, Vec::new()), async move {
            transaction_batch.await.merkleize().await
        });
    Ok((state_merkleized?, transaction_merkleized?))
}

#[cfg(test)]
mod tests {
    use super::{StateBatch, StateDatabase};
    use crate::{
        consensus::compute,
        executor::{PreparedTransfer, account_slots, starting_accounts},
    };
    use commonware_codec::FixedSize as _;
    use commonware_cryptography::Sha256;
    use commonware_glue::{
        stateful::db::{DatabaseSet, Merkleized as _, Unmerkleized as _},
        transfers::Plan,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, buffer::paged::CacheRef, deterministic};
    use commonware_storage::{
        journal::contiguous::fixed::Config as FixedJournalConfig,
        merkle::full::Config as MmrConfig,
        qmdb::any::{FixedConfig, batch::Slot},
        translator::EightCap,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};
    use constantinople_primitives::{Account, AccountKey, Nonce};
    use std::sync::Arc;

    type Db = StateDatabase<deterministic::Context, Sha256, EightCap, Sequential>;
    type Batch = StateBatch<deterministic::Context, Sha256, EightCap, Sequential>;

    fn config(cache: CacheRef) -> FixedConfig<EightCap, Sequential> {
        FixedConfig {
            merkle_config: MmrConfig {
                journal_partition: "state-order-test-merkle-journal".into(),
                metadata_partition: "state-order-test-merkle-metadata".into(),
                items_per_blob: NZU64!(1024),
                write_buffer: NZUsize!(4096),
                replay_buffer: NZUsize!(4096),
                strategy: Sequential,
                page_cache: cache.clone(),
            },
            journal_config: FixedJournalConfig {
                partition: "state-order-test-log".into(),
                items_per_blob: NZU64!(1024),
                page_cache: cache,
                write_buffer: NZUsize!(4096),
                replay_buffer: NZUsize!(4096),
            },
            translator: EightCap,
            init_cache: Some(NZUsize!(1024)),
            init_buffer: NZUsize!(1 << 21),
            init_concurrency: (),
        }
    }

    fn key(byte: u8) -> AccountKey {
        AccountKey::from([byte; AccountKey::SIZE])
    }

    fn account(balance: u64) -> Account {
        Account {
            balance,
            nonce: Nonce::default(),
        }
    }

    /// Opens a state database holding `accounts`, finalized.
    async fn seeded(context: deterministic::Context, accounts: &[(AccountKey, Account)]) -> Db {
        let cache = CacheRef::new(NZU16!(16), NZUsize!(4096));
        let db =
            <Db as DatabaseSet<deterministic::Context>>::init(context, config(cache), None).await;
        let mut seed = db.new_batches().await;
        for (key, account) in accounts {
            seed = seed.write(*key, Some(*account));
        }
        let seed = seed.merkleize().await.expect("seed state");
        db.apply(seed).await;
        assert!(db.finalize().await.durable().await);
        db
    }

    #[test]
    fn state_root_ignores_slot_order() {
        deterministic::Runner::default().start(|context| async move {
            let [a, b, c, d] = [1, 2, 3, 4].map(key);
            let db = seeded(context, &[(c, account(300)), (a, account(100))]).await;

            // The same final key->value set must produce the same root
            // regardless of staged read order.
            let (_, staged) = db
                .new_batches()
                .await
                .stage(&[&a, &b, &c, &d])
                .await
                .expect("first stage");
            let first = [101, 201, 301, 401].map(|balance| Slot::Put(account(balance)));
            let x = staged
                .merkleize(first.to_vec(), Vec::new())
                .await
                .expect("first order")
                .root();

            let (_, staged) = db
                .new_batches()
                .await
                .stage(&[&d, &c, &b, &a])
                .await
                .expect("second stage");
            let second = [401, 301, 201, 101].map(|balance| Slot::Put(account(balance)));
            let y = staged
                .merkleize(second.to_vec(), Vec::new())
                .await
                .expect("second order")
                .root();

            assert_eq!(x, y);
        });
    }

    #[test]
    fn state_root_ignores_plan_key_order() {
        deterministic::Runner::default().start(|context| async move {
            // Plans of this many transfers place keys by their hash, so plans
            // keyed differently order the same keys differently.
            let keys: Vec<AccountKey> = (0..3_000u32)
                .map(|index| {
                    let mut raw = [0u8; AccountKey::SIZE];
                    raw[..4].copy_from_slice(&index.to_le_bytes());
                    AccountKey::from(raw)
                })
                .collect();
            let held: Vec<(AccountKey, Account)> = keys
                .iter()
                .step_by(2)
                .map(|key| (*key, account(1_000)))
                .collect();
            let db = seeded(context, &held).await;

            // A ring over held and absent accounts, with every sender
            // contended and a self-transfer from every third.
            let mut body = Vec::new();
            for nonce in 0..3 {
                body.extend((0..keys.len()).map(|index| PreparedTransfer {
                    sender: keys[index],
                    recipient: keys[(index + 1) % keys.len()],
                    value: 1 + index as u64 % 7,
                    nonce,
                }));
            }
            body.extend((0..keys.len()).step_by(3).map(|index| PreparedTransfer {
                sender: keys[index],
                recipient: keys[index],
                value: 50,
                nonce: 3,
            }));

            // Each plan's key order is the staged read order and the slot
            // order.
            let settle = |batch: Batch, plan: Plan<AccountKey, _>| async move {
                let keys: Vec<&AccountKey> = plan.keys().iter().collect();
                let (reads, staged) = batch.stage(&keys).await.expect("stage");
                let slots = plan
                    .settle(&starting_accounts(reads), &Sequential)
                    .expect("body settles");
                staged
                    .merkleize(account_slots(slots), Vec::new())
                    .await
                    .expect("merkleize")
                    .root()
            };
            let mut roots = Vec::new();
            let mut orders = Vec::new();
            for seed in 0..3 {
                let plan = Plan::with_seed(&body, seed, &Sequential).expect("plan");
                orders.push(plan.keys().to_vec());
                roots.push(settle(db.new_batches().await, plan).await);
            }
            let (staged, slots) =
                compute(db.new_batches().await, Arc::new(body), &Sequential).await;
            roots.push(
                staged
                    .merkleize(slots.expect("body settles"), Vec::new())
                    .await
                    .expect("merkleize")
                    .root(),
            );

            assert!(
                orders.windows(2).all(|pair| pair[0] != pair[1]),
                "seeds must order the keys differently"
            );
            assert!(roots.windows(2).all(|pair| pair[0] == pair[1]));
        });
    }
}
