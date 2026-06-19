//! Database aliases and batch helpers for consensus execution.

use crate::executor::ShardWrites;
use commonware_cryptography::Hasher;
use commonware_glue::stateful::db::{DatabaseSet, Unmerkleized, any::AnyUnmerkleized};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Storage};
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
use std::sync::Arc;

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

/// Unmerkleized application state batch used for executor read-through.
pub type StateBatch<E, H, T, S> = AnyUnmerkleized<
    mmr::Family,
    E,
    FixedJournal<E, AnyOperation<mmr::Family, UnorderedUpdate<AccountKey, FixedEncoding<Account>>>>,
    UnorderedIndex<T, mmr::Location>,
    H,
    UnorderedUpdate<AccountKey, FixedEncoding<Account>>,
    S,
>;

pub(super) type TransactionBatch<E, H, S> =
    <TransactionDatabase<E, H, S> as DatabaseSet<E>>::Unmerkleized;

pub(super) type StateMerkleized<E, H, T, S> = <StateBatch<E, H, T, S> as Unmerkleized>::Merkleized;

pub(super) type TransactionMerkleized<E, H, S> =
    <TransactionBatch<E, H, S> as Unmerkleized>::Merkleized;

pub(super) type MerkleizedDatabases<E, H, S> = (
    StateMerkleized<E, H, EightCap, S>,
    TransactionMerkleized<E, H, S>,
);

/// Per-shard account writes produced by compute.
///
/// This is a state diff, not an ordered log: shard order is not consensus
/// relevant, and each account should be emitted by at most one shard.
pub struct StateWrites {
    pub(super) shards: Vec<ShardWrites>,
}

impl StateWrites {
    pub(super) const fn new(shards: Vec<ShardWrites>) -> Self {
        Self { shards }
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.shards.iter().all(Vec::is_empty)
    }
}

/// Writes each shard's mutated accounts to a state batch.
///
/// The resulting `state_root` depends only on the final key->value set, so the
/// shards (and accounts within them) may be folded in any order.
pub(super) fn apply_shard_maps<E, H, S>(
    batch: StateBatch<E, H, EightCap, S>,
    state_writes: StateWrites,
) -> StateBatch<E, H, EightCap, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let StateWrites { shards } = state_writes;
    shards.into_iter().fold(batch, |batch, shard_map| {
        shard_map
            .into_iter()
            .fold(batch, |batch, (account_key, account)| {
                batch.write(account_key, Some(account))
            })
    })
}

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

pub(super) async fn finalize_execution<E, H, S>(
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
) -> Result<MerkleizedDatabases<E, H, S>, commonware_storage::qmdb::Error<mmr::Family>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let (state_merkleized, transaction_merkleized) =
        futures::join!(state_batch.merkleize(), transaction_batch.merkleize());
    Ok((state_merkleized?, transaction_merkleized?))
}

#[cfg(test)]
mod tests {
    use super::{StateDatabase, StateWrites, apply_shard_maps};
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
        }
    }

    #[test]
    fn state_root_ignores_write_order() {
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

            let x = apply_shard_maps(
                db.new_batches().await,
                StateWrites::new(vec![
                    vec![(c, account(301)), (a, account(101))],
                    vec![(d, account(401)), (b, account(201))],
                ]),
            )
            .merkleize()
            .await
            .expect("first order")
            .root();

            let y = apply_shard_maps(
                db.new_batches().await,
                StateWrites::new(vec![
                    vec![(b, account(201)), (d, account(401))],
                    vec![(a, account(101)), (c, account(301))],
                ]),
            )
            .merkleize()
            .await
            .expect("second order")
            .root();

            assert_eq!(x, y);
        });
    }
}
