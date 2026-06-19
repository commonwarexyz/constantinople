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
            batch::{DeferredResolvedRead, DeferredResolvedReadIndex},
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
pub(super) type StateBatch<E, H, T, S> = AnyUnmerkleized<
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

pub(super) type StateResolvedRead =
    DeferredResolvedRead<mmr::Family, UnorderedUpdate<AccountKey, FixedEncoding<Account>>>;
pub(super) type StateResolvedReadIndex =
    DeferredResolvedReadIndex<mmr::Family, UnorderedUpdate<AccountKey, FixedEncoding<Account>>>;

pub(super) struct StateIndexedResolvedRead {
    pub(super) shard: usize,
    pub(super) resolved: StateResolvedReadIndex,
}

pub(super) struct StateWrites {
    pub(super) shards: Vec<ShardWrites>,
    pub(super) resolved: Vec<StateResolvedRead>,
    pub(super) indexed_resolved: Vec<StateIndexedResolvedRead>,
}

impl StateWrites {
    pub(super) const fn new(shards: Vec<ShardWrites>) -> Self {
        Self {
            shards,
            resolved: Vec::new(),
            indexed_resolved: Vec::new(),
        }
    }

    pub(super) const fn with_indexed_resolved(
        shards: Vec<ShardWrites>,
        indexed_resolved: Vec<StateIndexedResolvedRead>,
    ) -> Self {
        Self {
            shards,
            resolved: Vec::new(),
            indexed_resolved,
        }
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
    let StateWrites {
        shards,
        resolved,
        indexed_resolved,
    } = state_writes;
    let indexed_resolved = indexed_resolved
        .into_iter()
        .map(|entry| {
            let (index, loc, cached) = entry.resolved;
            let key = shards[entry.shard][index].0;
            (key, loc, cached)
        })
        .collect::<Vec<_>>();
    batch.extend_resolved(resolved.into_iter().chain(indexed_resolved));
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
