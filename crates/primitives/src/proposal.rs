//! Proposal budgets for the canonical SHA-256 and Ed25519 validator stack.

use crate::{Outcomes, ParentNotarization, Transaction, TransactionSignature};
use commonware_codec::{EncodeSize, FixedSize, varint::UInt};
use commonware_consensus::types::coding::COMMITMENT_SIZE;
use commonware_cryptography::{Digest, ed25519, sha256};
use constantinople_auth::MAX_ENTRIES;

/// Maximum encoded block size accepted by consensus, including its header and body framing.
pub const MAXIMUM_BLOCK_SIZE: usize = 16 * 1024 * 1024;

/// Maximum encoded application message accepted by the validator network.
pub const MAXIMUM_MESSAGE_SIZE: u32 = 32 * 1024 * 1024;

/// Transaction-byte budget after reserving space for block framing and for
/// what a block carries about its parent.
///
/// A block carries a notarization of its parent and one outcome bit for each of
/// the parent's transactions. Their size depends on the parent, so the budget
/// reserves the most they take ([`parent_bytes_bound`]) when the parent is as
/// full as this budget allows and `validators` validators vote.
///
/// Returns `None` if the block budget exceeds the consensus limit or cannot
/// accommodate the largest header, the reservation and an empty body.
pub fn max_transaction_bytes(block_bytes: usize, validators: u32) -> Option<usize> {
    if block_bytes > MAXIMUM_BLOCK_SIZE {
        return None;
    }
    let body_bytes = block_bytes
        .checked_sub(maximum_header_size())?
        .checked_sub(parent_bytes_bound(validators, 0))?;

    // A transaction's length prefix takes one byte below 128 bytes and two bytes
    // above. With the smallest transaction at 82 bytes, `a` short and `b` long
    // transactions that fit in the body have `a + 2b <= body / 64` prefix bytes.
    let minimum_transaction = Transaction::<sha256::Digest>::SIZE + TransactionSignature::MIN_SIZE;
    let max_transaction_count = body_bytes / minimum_transaction;
    let framing = max_transaction_count.encode_size() + body_bytes / 64;
    let available = body_bytes.checked_sub(framing)?;

    // Each transaction of the parent costs this block one bit in every vote's
    // report and one outcome bit. `t` transactions take at least
    // `t * minimum_transaction` bytes of the parent's budget, and at most
    // `(t / 8 + 1) * share` bytes here.
    let share = validators as usize + 1;
    let bits = minimum_transaction * 8;
    Some(available.saturating_sub(share) * bits / (bits + share))
}

/// Encoded size of what a block carries about its parent: the notarization and
/// the outcome bits.
pub fn parent_bytes<C: Digest>(
    notarization: Option<&ParentNotarization<C>>,
    outcomes: &Outcomes,
) -> usize {
    notarization.map_or(false.encode_size(), |notarization| {
        true.encode_size() + notarization.encode_size()
    }) + outcomes.encode_size()
}

/// The most [`parent_bytes`] can be for a parent with `transactions`
/// transactions, if every one of `validators` votes in the notarization
/// carries a report no longer than one bit for each transaction.
///
/// A validator that follows the protocol sends such a report. A faulty one may
/// send a longer report, which a proposer counts against its transactions.
pub fn parent_bytes_bound(validators: u32, transactions: usize) -> usize {
    let validators = validators as usize;
    let bits = transactions.div_ceil(8);
    let proposal = 3 * UInt(u64::MAX).encode_size() + COMMITMENT_SIZE;
    let signers = u64::SIZE + validators.div_ceil(8);
    let report = UInt(2 * MAX_ENTRIES as u64 + 1).encode_size() + bits;
    let votes = validators.encode_size() + validators * (report + ed25519::Signature::SIZE);
    let outcomes = u64::SIZE + bits;
    true.encode_size() + proposal + signers + votes + outcomes
}

fn maximum_header_size() -> usize {
    // Epoch and the two views use varints. The remaining header counters are fixed width.
    3 * UInt(u64::MAX).encode_size()
        + ed25519::PublicKey::SIZE
        + COMMITMENT_SIZE
        + 5 * sha256::Digest::SIZE
        + 6 * u64::SIZE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Block, Header, Sealable, SealedBlock, SignedTransaction, TRANSACTION_NAMESPACE,
        TransactionPublicKey,
    };
    use commonware_codec::Encode;
    use commonware_coding::ReedSolomon;
    use commonware_consensus::{
        simplex::types::{Context, Notarization, Notarize, Proposal},
        types::{Epoch, Round, View, coding::Commitment as CodingCommitment},
    };
    use commonware_cryptography::{Digest, Signer, secp256r1::standard as secp256r1};
    use commonware_math::algebra::Random;
    use commonware_parallel::Sequential;
    use commonware_utils::{non_empty, non_empty_range};
    use constantinople_auth::Report;
    use std::num::NonZeroU64;

    type Commitment = CodingCommitment<
        SealedBlock<sha256::Digest, ed25519::PublicKey, sha256::Sha256>,
        ReedSolomon<sha256::Sha256>,
        sha256::Sha256,
    >;

    fn maximum_header() -> Header<Commitment, sha256::Digest, ed25519::PublicKey> {
        Header {
            context: Context {
                round: Round::new(Epoch::new(u64::MAX), View::new(u64::MAX)),
                leader: ed25519::PrivateKey::from_seed(0).public_key(),
                parent: (View::new(u64::MAX), Commitment::default()),
            },
            parent: sha256::Digest::EMPTY,
            height: u64::MAX,
            timestamp: u64::MAX,
            parent_notarization: sha256::Digest::EMPTY,
            parent_outcomes: sha256::Digest::EMPTY,
            state_root: sha256::Digest::EMPTY,
            state_range: non_empty_range!(u64::MAX - 1, u64::MAX),
            transactions_root: sha256::Digest::EMPTY,
            transactions_range: non_empty_range!(u64::MAX - 1, u64::MAX),
        }
    }

    fn signature_size_extremes() -> [SignedTransaction<sha256::Sha256>; 3] {
        let key = TransactionPublicKey::x25519([9; 32].into());
        let unsigned = Transaction::new(key.clone(), key, NonZeroU64::MIN, 0)
            .seal_for_mac(&mut sha256::Sha256::default());
        assert_eq!(
            unsigned.signature().encode_size(),
            TransactionSignature::MIN_SIZE
        );

        let signer = ed25519::PrivateKey::from_seed(1);
        let key = TransactionPublicKey::ed25519(signer.public_key());
        let transaction = Transaction::new(key.clone(), key, NonZeroU64::MIN, 0);
        let minimum = transaction.seal_and_sign(
            &signer,
            TRANSACTION_NAMESPACE,
            &mut sha256::Sha256::default(),
        );
        assert_eq!(
            minimum.signature().encode_size(),
            TransactionSignature::MIN_SIGNED_SIZE
        );

        let signer = secp256r1::PrivateKey::random(commonware_utils::test_rng());
        let key = TransactionPublicKey::secp256r1(signer.public_key());
        let transaction = Transaction::new(key.clone(), key, NonZeroU64::MIN, 0)
            .seal(&mut sha256::Sha256::default());
        let mut client_data_json = br#"{"type":"webauthn.get","challenge":"test"}"#.to_vec();
        client_data_json.resize(512, b' ');
        let signature = TransactionSignature::secp256r1(
            signer.sign(TRANSACTION_NAMESPACE, transaction.seal().as_ref()),
            vec![0; 256],
            client_data_json,
        )
        .expect("maximum WebAuthn fields should encode");
        assert_eq!(signature.encode_size(), TransactionSignature::MAX_SIZE);
        let maximum = SignedTransaction::new_unchecked(transaction, signature);
        [unsigned, minimum, maximum]
    }

    const VALIDATORS: [u32; 2] = [6, 16];

    /// A notarization by every one of `validators` validators, each reporting
    /// on `entries` transactions with a report as long as an honest one gets.
    fn notarization(validators: u32, entries: usize) -> ParentNotarization<Commitment> {
        let fixture = constantinople_auth::fixture(
            &mut commonware_utils::test_rng(),
            b"proposal-test",
            validators,
        );
        let proposal = Proposal::new(
            Round::new(Epoch::new(u64::MAX), View::new(u64::MAX)),
            View::new(u64::MAX - 1),
            Commitment::default(),
        );
        let verdicts: Vec<bool> = (0..entries).map(|position| position % 2 == 0).collect();
        let votes: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| {
                scheme.reports().insert(
                    proposal.round,
                    proposal.payload.as_ref(),
                    Report::new(&verdicts),
                );
                Notarize::sign(scheme, proposal.clone()).expect("report was recorded")
            })
            .collect();
        Notarization::from_notarizes(&fixture.schemes[0], non_empty![@votes.iter()], &Sequential)
            .expect("every validator voted")
    }

    /// The smallest block budget that leaves a transaction budget.
    fn minimum_block_budget(validators: u32) -> usize {
        (0..MAXIMUM_BLOCK_SIZE)
            .find(|&budget| max_transaction_bytes(budget, validators).is_some())
            .expect("some budget is large enough")
    }

    #[test]
    fn bound_covers_what_a_block_carries_about_its_parent() {
        for validators in VALIDATORS {
            for entries in [0, 1, 7, 8, 9, 64, 1_000, 10_001] {
                let notarization = notarization(validators, entries);
                let outcomes = Outcomes::zeroes(entries as u64);
                let bound = parent_bytes_bound(validators, entries);
                assert!(parent_bytes(Some(&notarization), &outcomes) <= bound);
                assert!(parent_bytes::<Commitment>(None, &outcomes) <= bound);
            }
        }
    }

    #[test]
    fn smallest_budget_holds_an_empty_block() {
        for validators in VALIDATORS {
            let budget = minimum_block_budget(validators);
            assert_eq!(max_transaction_bytes(budget, validators), Some(0));
            let block = Block::<_, _, sha256::Sha256>::with_parent(
                maximum_header(),
                Some(notarization(validators, 0)),
                Outcomes::new(),
                Vec::new(),
            );
            assert!(block.encode().len() <= budget);
        }
    }

    #[test]
    fn selection_budget_fits_encoded_blocks() {
        let transactions = signature_size_extremes();
        let sizes = transactions
            .each_ref()
            .map(|t| t.encode_size().encode_size());
        assert_eq!(sizes, [1, 2, 2]);

        // A transaction of 127 bytes is the largest with a one-byte prefix, and one
        // of 128 bytes pays the most for its two-byte prefix. No transaction has
        // these sizes, so the bound has room to spare.
        let patterns = [
            &transactions[..1],
            &transactions[1..2],
            &transactions[2..],
            &transactions[..2],
            &transactions[..],
        ];
        for validators in VALIDATORS {
            let minimum = minimum_block_budget(validators);
            for block_budget in [
                minimum,
                minimum + 83,
                minimum + 1_000,
                19_232,
                19_381,
                MAXIMUM_BLOCK_SIZE,
            ] {
                let budget = max_transaction_bytes(block_budget, validators).unwrap();

                // The parent holds as many transactions as the budget allows, and
                // every vote for it reports on all of them.
                let parent = budget / transactions[0].encode_size();
                let notarization = notarization(validators, parent);
                let outcomes = Outcomes::zeroes(parent as u64);

                for pattern in patterns {
                    let mut filled = 0;
                    let mut body = Vec::new();
                    for transaction in pattern.iter().cycle() {
                        let size = transaction.encode_size();
                        if filled + size > budget {
                            break;
                        }
                        filled += size;
                        body.push(transaction.clone());
                    }
                    let block = Block::with_parent(
                        maximum_header(),
                        Some(notarization.clone()),
                        outcomes.clone(),
                        body,
                    );
                    assert!(
                        block.encode().len() <= block_budget,
                        "transaction budget {budget} exceeded block budget {block_budget}",
                    );
                }
            }
        }
    }

    #[test]
    fn rejects_invalid_block_budgets() {
        for budget in [0, MAXIMUM_BLOCK_SIZE + 1, usize::MAX] {
            assert_eq!(max_transaction_bytes(budget, 6), None);
        }
    }
}
