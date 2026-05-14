//! Transaction-history range helpers.

use super::db::TransactionHistoryTarget;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_storage::mmr;
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
