//! Transaction-history range helpers.

use super::db::TransactionHistoryTarget;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_storage::mmr;
use commonware_utils::non_empty_range;
use constantinople_primitives::SealedBlock;

pub(super) const fn header_range_to_target<D>(
    root: D,
    range: commonware_utils::range::NonEmptyRange<u64>,
) -> TransactionHistoryTarget<D>
where
    D: Digest,
{
    TransactionHistoryTarget {
        root,
        leaf_count: mmr::Location::new(range.end()),
    }
}

pub(super) fn parent_transactions_inactivity_floor<C, P, H>(
    parent: &SealedBlock<C, P, H>,
) -> mmr::Location
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let parent_body_len = u64::try_from(parent.body.len()).expect("transaction count exceeded u64");
    let floor = parent
        .header
        .transactions_range
        .end()
        .checked_sub(parent_body_len)
        .and_then(|end| end.checked_sub(1))
        .expect("parent transaction range must include the parent commit");
    mmr::Location::new(floor)
}

pub(super) fn child_transactions_range<C, P, H>(
    parent: &SealedBlock<C, P, H>,
    transaction_count: usize,
) -> commonware_utils::range::NonEmptyRange<u64>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let transaction_count =
        u64::try_from(transaction_count).expect("transaction count exceeded u64");
    let end = parent
        .header
        .transactions_range
        .end()
        .checked_add(transaction_count)
        .and_then(|end| end.checked_add(1))
        .expect("transaction history size exceeded u64");
    non_empty_range!(*parent_transactions_inactivity_floor(parent), end)
}
