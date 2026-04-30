//! Database aliases and batch helpers for consensus execution.

use crate::processor::executor::Changeset;
use commonware_cryptography::{Hasher, PublicKey};
use commonware_glue::stateful::db::{DatabaseSet, Unmerkleized, any::AnyUnmerkleized};
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
        sync::compact::Target as CompactTarget,
    },
    translator::EightCap,
};
use commonware_utils::sync::AsyncRwLock;
use constantinople_primitives::{Account, AccountKey, SignedTransaction};
use std::sync::Arc;

/// Shared QMDB handle for the application state database.
pub(super) type StateDatabase<E, H, P, T> =
    Arc<AsyncRwLock<fixed::Db<mmr::Family, E, AccountKey<P>, Account, H, T>>>;

pub type TransactionHistoryDb<E, H> =
    keyless_fixed::CompactDb<mmr::Family, E, <H as Hasher>::Digest, H>;

pub type TransactionHistoryOperation<H> =
    keyless_fixed::Operation<mmr::Family, <H as Hasher>::Digest>;

pub type TransactionHistoryTarget<D> = CompactTarget<mmr::Family, D>;

/// Shared QMDB handle for the append-only transaction history database.
pub(super) type TransactionDatabase<E, H> = Arc<AsyncRwLock<TransactionHistoryDb<E, H>>>;

/// The backing databases owned by the application.
pub(super) type Databases<E, H, P, T> = (StateDatabase<E, H, P, T>, TransactionDatabase<E, H>);

/// Unmerkleized application state batch used for processor read-through.
pub(super) type StateBatch<E, H, P, T> = AnyUnmerkleized<
    mmr::Family,
    E,
    FixedJournal<
        E,
        AnyOperation<mmr::Family, UnorderedUpdate<AccountKey<P>, FixedEncoding<Account>>>,
    >,
    UnorderedIndex<T, mmr::Location>,
    H,
    UnorderedUpdate<AccountKey<P>, FixedEncoding<Account>>,
>;

pub(super) type TransactionBatch<E, H> =
    <TransactionDatabase<E, H> as DatabaseSet<E>>::Unmerkleized;

pub(super) type StateMerkleized<E, H, P, T> = <StateBatch<E, H, P, T> as Unmerkleized>::Merkleized;

pub(super) type TransactionMerkleized<E, H> = <TransactionBatch<E, H> as Unmerkleized>::Merkleized;

/// Writes a changeset of account updates to a state batch.
pub(super) fn apply_changeset<E, H, P>(
    batch: StateBatch<E, H, P, EightCap>,
    changeset: &Changeset<P>,
) -> StateBatch<E, H, P, EightCap>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
{
    changeset
        .iter()
        .fold(batch, |batch, (account_key, account)| {
            batch.write(account_key.clone(), Some(*account))
        })
}

pub(super) fn apply_transaction_digests<E, H, P>(
    batch: TransactionBatch<E, H>,
    transactions: &[SignedTransaction<P, H>],
) -> TransactionBatch<E, H>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
{
    transactions.iter().fold(batch, |batch, transaction| {
        batch.append(*transaction.message_digest())
    })
}

pub(super) async fn finalize_execution<E, H, P>(
    state_batch: StateBatch<E, H, P, EightCap>,
    transaction_batch: TransactionBatch<E, H>,
) -> Result<
    (
        StateMerkleized<E, H, P, EightCap>,
        TransactionMerkleized<E, H>,
    ),
    commonware_storage::qmdb::Error<mmr::Family>,
>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
{
    let (state_merkleized, transaction_merkleized) =
        futures::join!(state_batch.merkleize(), transaction_batch.merkleize());
    Ok((state_merkleized?, transaction_merkleized?))
}
