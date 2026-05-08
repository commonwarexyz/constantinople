//! Database aliases and batch helpers for consensus execution.

use crate::processor::executor::Changeset;
use commonware_cryptography::{Hasher, PublicKey};
use commonware_glue::stateful::db::{DatabaseSet, Unmerkleized, current::CurrentUnmerkleized};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    index::unordered::Index as UnorderedIndex,
    journal::contiguous::fixed::Journal as FixedJournal,
    mmr,
    qmdb::{
        any::{
            operation::Operation as AnyOperation, unordered::Update as UnorderedUpdate,
            value::FixedEncoding,
        },
        current::unordered::fixed,
        keyless::fixed as keyless_fixed,
        sync::compact::Target as CompactTarget,
    },
    translator::EightCap,
};
use commonware_utils::sync::AsyncRwLock;
use constantinople_primitives::{Account, AccountKey, SignedTransaction};
use std::sync::Arc;

pub const STATE_BITMAP_CHUNK_BYTES: usize = 64;

/// Shared QMDB handle for the application state database.
pub(super) type StateDatabase<E, H, P, T, S> = Arc<
    AsyncRwLock<
        fixed::Db<mmr::Family, E, AccountKey<P>, Account, H, T, STATE_BITMAP_CHUNK_BYTES, S>,
    >,
>;

pub type TransactionHistoryDb<E, H, S> =
    keyless_fixed::CompactDb<mmr::Family, E, <H as Hasher>::Digest, H, S>;

pub type TransactionHistoryOperation<H> =
    keyless_fixed::Operation<mmr::Family, <H as Hasher>::Digest>;

pub type TransactionHistoryTarget<D> = CompactTarget<mmr::Family, D>;

/// Shared QMDB handle for the append-only transaction history database.
pub(super) type TransactionDatabase<E, H, S> = Arc<AsyncRwLock<TransactionHistoryDb<E, H, S>>>;

/// The backing databases owned by the application.
pub(super) type Databases<E, H, P, T, S> =
    (StateDatabase<E, H, P, T, S>, TransactionDatabase<E, H, S>);

/// Unmerkleized application state batch used for processor read-through.
pub(super) type StateBatch<E, H, P, T, S> = CurrentUnmerkleized<
    mmr::Family,
    E,
    FixedJournal<
        E,
        AnyOperation<mmr::Family, UnorderedUpdate<AccountKey<P>, FixedEncoding<Account>>>,
    >,
    UnorderedIndex<T, mmr::Location>,
    H,
    UnorderedUpdate<AccountKey<P>, FixedEncoding<Account>>,
    STATE_BITMAP_CHUNK_BYTES,
    S,
>;

pub(super) type TransactionBatch<E, H, S> =
    <TransactionDatabase<E, H, S> as DatabaseSet<E>>::Unmerkleized;

pub(super) type StateMerkleized<E, H, P, T, S> =
    <StateBatch<E, H, P, T, S> as Unmerkleized>::Merkleized;

pub(super) type TransactionMerkleized<E, H, S> =
    <TransactionBatch<E, H, S> as Unmerkleized>::Merkleized;

pub(super) type MerkleizedDatabases<E, H, P, S> = (
    StateMerkleized<E, H, P, EightCap, S>,
    TransactionMerkleized<E, H, S>,
);

/// Writes a changeset of account updates to a state batch.
pub(super) fn apply_changeset<E, H, P, S>(
    batch: StateBatch<E, H, P, EightCap, S>,
    changeset: &Changeset<P>,
) -> StateBatch<E, H, P, EightCap, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    changeset
        .iter()
        .fold(batch, |batch, (account_key, account)| {
            batch.write(account_key.clone(), Some(*account))
        })
}

pub(super) fn apply_transaction_digests<E, H, P, S>(
    batch: TransactionBatch<E, H, S>,
    transactions: &[SignedTransaction<P, H>],
) -> TransactionBatch<E, H, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    transactions.iter().fold(batch, |batch, transaction| {
        batch.append(*transaction.message_digest())
    })
}

pub(super) async fn finalize_execution<E, H, P, S>(
    state_batch: StateBatch<E, H, P, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
) -> Result<MerkleizedDatabases<E, H, P, S>, commonware_storage::qmdb::Error<mmr::Family>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    let (state_merkleized, transaction_merkleized) =
        futures::join!(state_batch.merkleize(), transaction_batch.merkleize());
    Ok((state_merkleized?, transaction_merkleized?))
}
