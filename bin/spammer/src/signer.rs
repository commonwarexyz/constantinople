//! Ring-pattern transaction signing, tagging and batch sizing.

use crate::accounts::{SpamAccount, TaggedAccount};
use bytes::Bytes;
use commonware_codec::Encode as _;
use commonware_cryptography::{Sha256, ed25519};
use commonware_parallel::Strategy;
use commonware_utils::Participant;
use constantinople_auth::Submission;
use constantinople_primitives::{
    SignedTransaction, TRANSACTION_NAMESPACE, Transaction, TransactionPublicKey,
};
use core::num::NonZeroU64;

/// Concrete transaction type, with a signature or without one.
pub type Tx = SignedTransaction<Sha256>;

/// A transaction without a signature, with the tags its proposer needs.
pub type TaggedTx = Submission<Tx>;

/// The accounts of one submitter.
pub enum Accounts {
    /// Accounts that sign their transactions.
    Signed(Vec<SpamAccount>),
    /// Accounts that tag their transactions for the validator `proposer`.
    Tagged {
        accounts: Vec<TaggedAccount>,
        proposer: Participant,
    },
}

impl Accounts {
    pub const fn len(&self) -> usize {
        match self {
            Self::Signed(accounts) => accounts.len(),
            Self::Tagged { accounts, .. } => accounts.len(),
        }
    }

    /// Builds the next batch of `count` transactions. See [`sign_batch`].
    pub fn batch<St: Strategy>(
        &self,
        strategy: &St,
        value: NonZeroU64,
        nonces: &mut [u64],
        cursor: &mut usize,
        count: usize,
    ) -> Batch {
        match self {
            Self::Signed(accounts) => {
                Batch::Signed(sign_batch(strategy, accounts, value, nonces, cursor, count))
            }
            Self::Tagged { accounts, proposer } => Batch::Tagged(tag_batch(
                strategy, accounts, *proposer, value, nonces, cursor, count,
            )),
        }
    }
}

/// A batch ready for submission.
pub enum Batch {
    Signed(Vec<Tx>),
    Tagged(Vec<TaggedTx>),
}

impl Batch {
    pub const fn len(&self) -> usize {
        match self {
            Self::Signed(batch) => batch.len(),
            Self::Tagged(batch) => batch.len(),
        }
    }

    /// The request body that carries the batch.
    pub fn encode(&self) -> Bytes {
        match self {
            Self::Signed(batch) => batch.encode(),
            Self::Tagged(batch) => batch.encode(),
        }
    }

    /// The relayer endpoint that takes the batch.
    pub const fn path(&self) -> &'static str {
        match self {
            Self::Signed(_) => "/transactions",
            Self::Tagged(_) => "/submissions",
        }
    }
}

impl From<Vec<Tx>> for Batch {
    fn from(batch: Vec<Tx>) -> Self {
        Self::Signed(batch)
    }
}

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
    let n = accounts.len();
    let work = select(n, nonces, cursor, count);
    strategy.map_collect_vec(work, |(i, nonce)| {
        let sender = &accounts[i];
        let recipient = &accounts[(i + 1) % n].public_key;
        sign_one(sender, recipient, value, nonce)
    })
}

/// Builds a variable-size batch of submissions to `proposer`, selecting
/// senders and nonces as [`sign_batch`] does.
///
/// A submission carries one tag per validator, each a keyed hash under the
/// key the sender shares with that validator, and no signature.
pub fn tag_batch<St: Strategy>(
    strategy: &St,
    accounts: &[TaggedAccount],
    proposer: Participant,
    value: NonZeroU64,
    nonces: &mut [u64],
    cursor: &mut usize,
    count: usize,
) -> Vec<TaggedTx> {
    let n = accounts.len();
    let work = select(n, nonces, cursor, count);
    strategy.map_collect_vec(work, |(i, nonce)| {
        let sender = &accounts[i];
        let recipient = &accounts[(i + 1) % n].public_key;
        let transaction = Transaction::new(
            TransactionPublicKey::x25519(sender.public_key),
            TransactionPublicKey::x25519(*recipient),
            value,
            nonce,
        )
        .seal_for_mac(&mut Sha256::default());
        let digest = *transaction.message_digest();
        Submission::new(&sender.keys, proposer, transaction, digest.as_ref())
    })
}

/// Walks the ring of `accounts` accounts from `cursor`, taking the next nonce
/// of each of `count` senders.
fn select(
    accounts: usize,
    nonces: &mut [u64],
    cursor: &mut usize,
    count: usize,
) -> Vec<(usize, u64)> {
    assert_eq!(accounts, nonces.len(), "nonces must match accounts");
    assert!(accounts > 0, "need at least one account");
    assert!(count > 0, "need at least one transaction");

    let mut work = Vec::with_capacity(count);
    for _ in 0..count {
        let sender_index = *cursor;
        let nonce = nonces[sender_index];
        nonces[sender_index] = nonce + 1;
        *cursor = (*cursor + 1) % accounts;
        work.push((sender_index, nonce));
    }
    work
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
            let decoded = Vec::<Tx>::decode_cfg(body, &cfg).expect("decode should succeed");
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
    fn tagged_batch_is_what_its_proposer_admits() {
        use crate::accounts::generate_tagged_accounts;
        use constantinople_auth::PrivateKey;

        let validators: Vec<_> = (0..6u8).map(|i| PrivateKey::from([50 + i; 32])).collect();
        let keys: Vec<_> = validators.iter().map(PrivateKey::public_key).collect();
        let accounts = generate_tagged_accounts(&Sequential, 3, 1000, &keys);
        let proposer = Participant::new(4);
        let value = NonZeroU64::new(1).unwrap();
        let mut nonces = vec![0; accounts.len()];
        let mut cursor = 0;
        let batch = tag_batch(
            &Sequential,
            &accounts,
            proposer,
            value,
            &mut nonces,
            &mut cursor,
            7,
        );
        assert_eq!(nonces, vec![3, 2, 2]);

        // Decode as the proposer would, and check each submission as it does.
        let body = Batch::Tagged(batch.clone()).encode();
        let cfg = (RangeCfg::new(1..=batch.len()), ((), validators.len()));
        let decoded = Vec::<TaggedTx>::decode_cfg(body, &cfg).expect("decode should succeed");
        assert_eq!(decoded, batch);
        for (position, submission) in decoded.iter().enumerate() {
            assert!(submission.transaction.is_mac());
            let sender = &accounts[position % accounts.len()];
            let digest = *submission.transaction.message_digest();
            for (index, validator) in validators.iter().enumerate() {
                let key = validator
                    .with_user(TRANSACTION_NAMESPACE, &sender.public_key)
                    .expect("account key is not low order");
                let admitted = submission.admit(
                    Participant::new(index as u32),
                    &key,
                    digest.as_ref(),
                    validators.len(),
                );
                assert_eq!(admitted.is_ok(), index == 4);
            }
        }
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
