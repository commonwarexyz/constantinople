//! Ring-pattern transaction signing and batch sizing.

use crate::accounts::SpamAccount;
use commonware_cryptography::{Sha256, ed25519};
use commonware_parallel::Strategy;
use constantinople_primitives::{Signable, SignedTransaction, TRANSACTION_NAMESPACE, Transaction};
use core::num::NonZeroU64;

/// Concrete signed transaction type.
///
/// Uses [`Sha256`] as the hasher to match the validator's Engine instantiation.
pub type Tx = SignedTransaction<ed25519::PublicKey, Sha256>;

/// Signs one transaction for a single sender in the ring.
fn sign_one(
    sender: &SpamAccount,
    recipient_address: &constantinople_primitives::Address,
    value: NonZeroU64,
    nonce: u64,
) -> Tx {
    let tx = Transaction::new(sender.public_key.clone(), *recipient_address, value, nonce);
    tx.seal_and_sign(
        &sender.private_key,
        TRANSACTION_NAMESPACE,
        &mut Sha256::default(),
    )
}

/// Signs a range of rounds for a set of accounts using the given parallel
/// [`Strategy`].
///
/// Account `i` sends `value` to account `(i + 1) % N`. The nonce for every
/// account in round `r` equals `r` (accounts start at nonce 0 and send
/// exactly once per round).
///
/// Rounds `start_round..start_round + num_rounds` are signed.
/// Returns a flat `Vec` of all signed transactions across those rounds.
pub fn sign_rounds<St: Strategy>(
    strategy: &St,
    accounts: &[SpamAccount],
    value: NonZeroU64,
    start_round: u64,
    num_rounds: u64,
) -> Vec<Tx> {
    let n = accounts.len();

    // Build work items: (sender_index, round) pairs.
    let work: Vec<(usize, u64)> = (start_round..start_round + num_rounds)
        .flat_map(|round| (0..n).map(move |i| (i, round)))
        .collect();

    // Sign in parallel across the rayon pool.
    strategy.map_collect_vec(work, |(i, round)| {
        let sender = &accounts[i];
        let recipient_address = &accounts[(i + 1) % n].address;
        sign_one(sender, recipient_address, value, round)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::generate_accounts;
    use commonware_parallel::Sequential;

    #[test]
    fn sign_produces_correct_count() {
        let accounts = generate_accounts(5, 1000);
        let value = NonZeroU64::new(1).unwrap();
        let txs = sign_rounds(&Sequential, &accounts, value, 0, 3);
        assert_eq!(txs.len(), 5 * 3);
    }

    #[test]
    fn single_round_produces_one_tx_per_account() {
        let accounts = generate_accounts(10, 1000);
        let value = NonZeroU64::new(1).unwrap();
        let txs = sign_rounds(&Sequential, &accounts, value, 42, 1);
        assert_eq!(txs.len(), 10);
        for tx in &txs {
            assert_eq!(tx.value().nonce, 42);
        }
    }

    #[test]
    fn nonces_are_correct() {
        let accounts = generate_accounts(3, 1000);
        let value = NonZeroU64::new(1).unwrap();
        let txs = sign_rounds(&Sequential, &accounts, value, 0, 4);
        for (idx, tx) in txs.iter().enumerate() {
            let round = (idx / 3) as u64;
            assert_eq!(tx.value().nonce, round);
        }
    }

    #[test]
    fn signed_transactions_survive_encode_decode_roundtrip() {
        use commonware_codec::{Decode, Encode, RangeCfg};
        use commonware_cryptography::{Sha256, ed25519};
        use constantinople_primitives::{TRANSACTION_NAMESPACE, verify_transaction_batch};

        let accounts = generate_accounts(5, 1000);
        let value = NonZeroU64::new(1).unwrap();
        let txs = sign_rounds(&Sequential, &accounts, value, 0, 2);

        // Encode as the client would.
        let body = txs.as_slice().encode();

        // Decode as the server would.
        let max_transactions = body.len() / 118; // conservative min tx size
        let cfg = (RangeCfg::new(1..=max_transactions), ());
        let decoded = Vec::<Tx>::decode_cfg(&mut &body[..], &cfg).expect("decode should succeed");
        assert_eq!(decoded.len(), txs.len());

        // Verify signatures as the server would (using Sha256, same as the validator).
        let mut rng = commonware_utils::test_rng();
        assert!(
            verify_transaction_batch::<ed25519::PublicKey, Sha256, ed25519::Batch>(
                TRANSACTION_NAMESPACE,
                &mut rng,
                &decoded,
            ),
            "batch signature verification should pass"
        );
    }
}
