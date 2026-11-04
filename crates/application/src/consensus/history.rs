//! Transaction-history entries and range helpers.

use super::db::TransactionHistoryTarget;
use crate::executor::PreparedTransfer;
use ahash::AHashMap;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_storage::{mmr, qmdb::any::batch::Slot};
use constantinople_primitives::{Account, AccountKey, SealedBlock, TransactionHistoryEntry};

/// Derives block-order indices from the settled counts of an accepted body.
///
/// Every accepted participant has a `Put` slot because its count increased.
/// Walking backward consumes exactly those increments, independent of staged
/// key order or proposal candidates that were dropped.
pub(super) fn entries<D: Digest>(
    accepted: impl DoubleEndedIterator<Item = (PreparedTransfer, D)> + ExactSizeIterator,
    keys: &[AccountKey],
    slots: &[Slot<Account>],
) -> Vec<TransactionHistoryEntry<D>> {
    assert_eq!(keys.len(), slots.len());
    let mut counts: AHashMap<_, _> = keys
        .iter()
        .zip(slots)
        .filter_map(|(key, slot)| match slot {
            Slot::Put(account) => Some((*key, account.tx_count)),
            Slot::Keep | Slot::Delete => None,
        })
        .collect();
    let mut result = Vec::with_capacity(accepted.len());
    for (transfer, digest) in accepted.rev() {
        let sender = counts
            .get_mut(&transfer.sender)
            .expect("accepted sender has a settled account");
        *sender = sender
            .checked_sub(1)
            .expect("accepted sender count increased");
        let sender_index = *sender;
        let recipient_index = if transfer.sender == transfer.recipient {
            sender_index
        } else {
            let recipient = counts
                .get_mut(&transfer.recipient)
                .expect("accepted recipient has a settled account");
            *recipient = recipient
                .checked_sub(1)
                .expect("accepted recipient count increased");
            *recipient
        };
        result.push(TransactionHistoryEntry {
            digest,
            sender_index,
            recipient_index,
        });
    }
    result.reverse();
    result
}

pub(super) const fn header_range_to_target<D>(
    root: D,
    range: commonware_utils::range::NonEmptyRange<u64>,
) -> TransactionHistoryTarget<D>
where
    D: Digest,
{
    TransactionHistoryTarget {
        root,
        size: mmr::Location::new(range.end()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::{TransferAccount, account_slots, starting_accounts};
    use commonware_codec::FixedSize as _;
    use commonware_cryptography::sha256;
    use commonware_glue::transfers::{Plan, Selection};
    use commonware_parallel::Sequential;
    use commonware_utils::TestRng;
    use rand::RngExt as _;
    use std::collections::HashMap;

    fn key(index: u8) -> AccountKey {
        AccountKey::from([index; AccountKey::SIZE])
    }

    fn transfer(sender: u8, recipient: u8, nonce: u64) -> PreparedTransfer {
        PreparedTransfer {
            sender: key(sender),
            recipient: key(recipient),
            value: 1,
            nonce,
        }
    }

    /// Compares the reverse pass with an independent forward count over selection's survivors.
    fn check_rounds(start: &HashMap<AccountKey, Account>, rounds: &[Vec<PreparedTransfer>]) {
        let mut selection: Selection<AccountKey, TransferAccount> = Selection::with_seed(9);
        let mut accepted = Vec::new();
        let mut expected = Vec::new();
        let mut counts: HashMap<_, _> = start.iter().map(|(k, a)| (*k, a.tx_count)).collect();
        let mut position = 0u8;
        for round in rounds {
            let touched = selection.touch(round);
            let reads = selection.keys()[touched]
                .iter()
                .map(|key| start.get(key).copied())
                .collect();
            selection.register(starting_accounts(reads));
            for (transfer, keep) in round.iter().zip(selection.apply(round)) {
                let digest = sha256::Digest::from([position; 32]);
                position += 1;
                if !keep {
                    continue;
                }
                let sender_index = *counts.entry(transfer.sender).or_default();
                let recipient_index = *counts.entry(transfer.recipient).or_default();
                *counts.get_mut(&transfer.sender).unwrap() += 1;
                if transfer.sender != transfer.recipient {
                    *counts.get_mut(&transfer.recipient).unwrap() += 1;
                }
                expected.push(TransactionHistoryEntry {
                    digest,
                    sender_index,
                    recipient_index,
                });
                accepted.push((*transfer, digest));
            }
        }
        let mut keys = selection.keys().to_vec();
        let mut slots = account_slots(selection.settle(&Sequential));
        assert_eq!(entries(accepted.iter().copied(), &keys, &slots), expected);
        for (key, slot) in keys.iter().zip(&slots) {
            if let Slot::Put(account) = slot {
                assert_eq!(account.tx_count, counts[key]);
            }
        }

        keys.reverse();
        slots.reverse();
        assert_eq!(entries(accepted.iter().copied(), &keys, &slots), expected);

        let body: Vec<_> = accepted.iter().map(|(transfer, _)| *transfer).collect();
        for seed in [0, 1, 2] {
            let plan = Plan::with_seed(&body, seed, &Sequential).unwrap();
            let reads = plan
                .keys()
                .iter()
                .map(|key| start.get(key).copied())
                .collect();
            let slots = account_slots(plan.settle(&starting_accounts(reads), &Sequential).unwrap());
            assert_eq!(
                entries(accepted.iter().copied(), plan.keys(), &slots),
                expected
            );
        }
    }

    #[test]
    fn first_repeated_mixed_and_self_touches_across_refills() {
        check_rounds(
            &HashMap::new(),
            &[
                vec![transfer(1, 2, 0), transfer(1, 2, 0), transfer(2, 3, 0)],
                vec![transfer(1, 1, 1), transfer(3, 1, 0), transfer(1, 2, 2)],
            ],
        );
    }

    #[test]
    fn empty_and_exhausted_histories() {
        check_rounds(&HashMap::new(), &[Vec::new()]);
        let start = HashMap::from([
            (
                key(1),
                Account {
                    tx_count: u64::MAX - 1,
                    ..Account::default()
                },
            ),
            (
                key(2),
                Account {
                    tx_count: u64::MAX,
                    ..Account::default()
                },
            ),
        ]);
        check_rounds(
            &start,
            &[vec![
                transfer(1, 2, 0),
                transfer(1, 1, 0),
                transfer(1, 3, 1),
            ]],
        );
    }

    #[test]
    fn selected_histories_are_contiguous_and_independent_of_slot_order() {
        let mut rng = TestRng::new(91);
        for _ in 0..1_000 {
            let start: HashMap<_, _> = (0..8)
                .map(|i| {
                    (
                        key(i),
                        Account {
                            tx_count: rng.random_range(0..100),
                            ..Account::default()
                        },
                    )
                })
                .collect();
            let rounds: Vec<Vec<_>> = (0..4)
                .map(|_| {
                    (0..10)
                        .map(|_| {
                            transfer(
                                rng.random_range(0..8),
                                rng.random_range(0..8),
                                rng.random_range(0..8),
                            )
                        })
                        .collect()
                })
                .collect();
            check_rounds(&start, &rounds);
        }
    }
}
