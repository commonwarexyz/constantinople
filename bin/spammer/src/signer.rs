//! Ring-pattern transaction signing and batch sizing.

use crate::accounts::SpamAccount;
use commonware_cryptography::{Sha256, ed25519};
use commonware_parallel::Strategy;
use constantinople_primitives::{
    SignedTransaction, TRANSACTION_NAMESPACE, Transaction, TransactionPublicKey,
};
use core::num::NonZeroU64;

/// Concrete signed transaction type.
pub type Tx = SignedTransaction<Sha256>;

/// Signs one transaction for a single sender in the ring.
fn sign_one(
    sender: &SpamAccount,
    recipient: &ed25519::PublicKey,
    value: NonZeroU64,
    nonce: u64,
) -> Tx {
    let tx = Transaction::new(
        TransactionPublicKey::ed25519(sender.public_key.clone()),
        TransactionPublicKey::ed25519(recipient.clone()),
        value,
        nonce,
    );
    tx.seal_and_sign(
        &sender.private_key,
        TRANSACTION_NAMESPACE,
        &mut Sha256::default(),
    )
}

/// Signs a variable-size batch while preserving per-account nonce order.
///
/// Senders are selected by walking the account ring from `cursor`. Each
/// selected account uses and increments its own nonce, so callers can vary
/// `count` per submission without creating nonce gaps.
pub fn sign_batch<St: Strategy>(
    strategy: &St,
    accounts: &[SpamAccount],
    value: NonZeroU64,
    nonces: &mut [u64],
    cursor: &mut usize,
    count: usize,
) -> Vec<Tx> {
    assert_eq!(accounts.len(), nonces.len(), "nonces must match accounts");
    assert!(!accounts.is_empty(), "need at least one account");
    assert!(count > 0, "need at least one transaction");

    let n = accounts.len();
    let mut work = Vec::with_capacity(count);
    for _ in 0..count {
        let sender_index = *cursor;
        let nonce = nonces[sender_index];
        nonces[sender_index] = nonce + 1;
        *cursor = (*cursor + 1) % n;
        work.push((sender_index, nonce));
    }

    strategy.map_collect_vec(work, |(i, nonce)| {
        let sender = &accounts[i];
        let recipient = &accounts[(i + 1) % n].public_key;
        sign_one(sender, recipient, value, nonce)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::generate_accounts;
    use commonware_codec::{Decode, Encode, RangeCfg};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::NZUsize;
    use constantinople_primitives::{PublicKeyCache, verify_transaction_batch};

    #[test]
    fn sign_produces_correct_count() {
        let accounts = generate_accounts(5, 1000);
        let value = NonZeroU64::new(1).unwrap();
        let mut nonces = vec![0; accounts.len()];
        let mut cursor = 0;
        let txs = sign_batch(&Sequential, &accounts, value, &mut nonces, &mut cursor, 15);
        assert_eq!(txs.len(), 5 * 3);
    }

    #[test]
    fn single_round_produces_one_tx_per_account() {
        let accounts = generate_accounts(10, 1000);
        let value = NonZeroU64::new(1).unwrap();
        let mut nonces = vec![0; accounts.len()];
        let mut cursor = 0;
        let txs = sign_batch(&Sequential, &accounts, value, &mut nonces, &mut cursor, 10);
        assert_eq!(txs.len(), 10);
        for tx in &txs {
            assert_eq!(tx.value().nonce, 0);
        }
    }

    #[test]
    fn nonces_are_correct() {
        let accounts = generate_accounts(3, 1000);
        let value = NonZeroU64::new(1).unwrap();
        let mut nonces = vec![0; accounts.len()];
        let mut cursor = 0;
        let txs = sign_batch(&Sequential, &accounts, value, &mut nonces, &mut cursor, 12);
        for (idx, tx) in txs.iter().enumerate() {
            let round = (idx / 3) as u64;
            assert_eq!(tx.value().nonce, round);
        }
    }

    #[test]
    fn signed_transactions_survive_encode_decode_roundtrip() {
        deterministic::Runner::default().start(|context| async move {
            let cache = PublicKeyCache::new(context, NZUsize!(16));

            let accounts = generate_accounts(5, 1000);
            let value = NonZeroU64::new(1).unwrap();
            let mut nonces = vec![0; accounts.len()];
            let mut cursor = 0;
            let txs = sign_batch(&Sequential, &accounts, value, &mut nonces, &mut cursor, 10);

            // Encode as the client would.
            let body = txs.as_slice().encode();

            // Decode as the server would.
            let max_transactions = body.len() / 118; // conservative min tx size
            let cfg = (RangeCfg::new(1..=max_transactions), ());
            let decoded =
                Vec::<Tx>::decode_cfg(&mut &body[..], &cfg).expect("decode should succeed");
            assert_eq!(decoded.len(), txs.len());

            // Verify signatures as the server would (using Sha256, same as the validator).
            let lazy_decoded: Vec<_> = decoded
                .into_iter()
                .map(constantinople_primitives::LazySignedTransaction::new)
                .collect();
            assert!(
                verify_transaction_batch::<Sha256, _>(
                    TRANSACTION_NAMESPACE,
                    &mut commonware_utils::test_rng(),
                    &cache,
                    &lazy_decoded,
                    &Sequential,
                ),
                "batch signature verification should pass"
            );
        });
    }

    #[test]
    fn variable_batch_preserves_per_account_nonces() {
        let accounts = generate_accounts(4, 1000);
        let value = NonZeroU64::new(1).unwrap();
        let mut nonces = vec![0; accounts.len()];
        let mut cursor = 0;

        let first = sign_batch(&Sequential, &accounts, value, &mut nonces, &mut cursor, 6);
        let second = sign_batch(&Sequential, &accounts, value, &mut nonces, &mut cursor, 3);

        assert_eq!(first.len(), 6);
        assert_eq!(second.len(), 3);
        assert_eq!(cursor, 1);
        assert_eq!(nonces, vec![3, 2, 2, 2]);

        let observed: Vec<_> = first
            .iter()
            .chain(second.iter())
            .map(|tx| tx.value().nonce)
            .collect();
        assert_eq!(observed, vec![0, 0, 0, 0, 1, 1, 1, 1, 2]);
    }
}
