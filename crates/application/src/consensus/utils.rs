//! Utility functions for the application.

use super::StateBatch;
use crate::processor::state::State;
use commonware_cryptography::{Hasher, PublicKey};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{mmr, qmdb::Error as StorageError, translator::Translator};
use constantinople_primitives::VerifiedTransaction;
use std::collections::{HashMap, HashSet};

/// Loads the accounts needed by `transactions` from `batch`.
///
/// The loader gathers every unique sender and recipient across the block body,
/// reads each account at most once, and builds an in-memory [`State`] snapshot
/// for verification.
pub async fn load_state<E, H, P, T>(
    batch: &StateBatch<E, H, T>,
    transactions: &[VerifiedTransaction<P, H>],
) -> Result<State, StorageError<mmr::Family>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    T: Translator,
{
    let addresses = transactions.iter().fold(
        HashSet::with_capacity(transactions.len().saturating_mul(2)),
        |mut acc, tx| {
            acc.insert(tx.signer());
            acc.insert(tx.value().to);
            acc
        },
    );
    if addresses.is_empty() {
        return Ok(HashMap::new());
    }

    let addresses: Vec<_> = addresses.into_iter().collect();
    let keys: Vec<_> = addresses.iter().collect();
    let db = batch.lock().await;
    let values = batch.batch().get_many(&keys, &*db).await?;

    let accounts = addresses
        .into_iter()
        .zip(values)
        .map(|(addr, account)| (addr, account.unwrap_or_default()))
        .collect();

    Ok(accounts)
}

#[cfg(test)]
mod tests {
    use commonware_codec::{DecodeExt, Encode, FixedSize, types::lazy::Lazy};
    use commonware_cryptography::{Signer as _, ed25519, sha256};
    use commonware_parallel::Rayon;
    use constantinople_primitives::{
        Address, Signable, SignedTransaction, Transaction, verify_transaction_chunks,
    };
    use core::num::{NonZeroU64, NonZeroUsize};
    use rand::{SeedableRng, rngs::StdRng};

    const NAMESPACE: &[u8] = b"consensus-test";

    #[derive(Debug, Clone)]
    struct TestSigner {
        key: ed25519::PrivateKey,
        address: Address,
    }

    impl TestSigner {
        fn from_seed(seed: u64) -> Self {
            let key = ed25519::PrivateKey::from_seed(seed);
            let address =
                Address::from_public_key(&mut sha256::Sha256::default(), &key.public_key());
            Self { key, address }
        }
    }

    fn signed_transaction(
        signer: &TestSigner,
        to: Address,
        nonce: u64,
    ) -> SignedTransaction<ed25519::PublicKey, sha256::Sha256> {
        Transaction::new(
            signer.key.public_key(),
            to,
            NonZeroU64::new(nonce + 1).expect("test value should be non-zero"),
            nonce,
        )
        .seal_and_sign(&signer.key, NAMESPACE, &mut sha256::Sha256::default())
    }

    fn invalid_transaction(
        claimed_signer: &TestSigner,
        actual_signer: &TestSigner,
        to: Address,
        nonce: u64,
    ) -> SignedTransaction<ed25519::PublicKey, sha256::Sha256> {
        Transaction::new(
            claimed_signer.key.public_key(),
            to,
            NonZeroU64::new(nonce + 1).expect("test value should be non-zero"),
            nonce,
        )
        .seal_and_sign(
            &actual_signer.key,
            NAMESPACE,
            &mut sha256::Sha256::default(),
        )
    }

    #[test]
    fn chunked_verification_preserves_transaction_order() {
        let strategy =
            Rayon::new(NonZeroUsize::new(4).expect("test thread count should be non-zero"))
                .expect("rayon strategy should construct");
        let sender = TestSigner::from_seed(7);
        let recipient = TestSigner::from_seed(9);
        let transactions = (0..64)
            .map(|nonce| signed_transaction(&sender, recipient.address, nonce))
            .collect::<Vec<_>>();
        let expected_digests = transactions
            .iter()
            .map(|transaction| *transaction.message_digest())
            .collect::<Vec<_>>();
        let mut rng = StdRng::seed_from_u64(11);
        let lazy_txs = transactions.into_iter().map(Lazy::new).collect();

        let verified =
            verify_transaction_chunks::<ed25519::PublicKey, sha256::Sha256, ed25519::Batch, _>(
                &strategy, NAMESPACE, &mut rng, lazy_txs,
            )
            .expect("valid chunked verification should succeed");
        let verified_digests = verified
            .iter()
            .map(|transaction| *transaction.message_digest())
            .collect::<Vec<_>>();

        assert_eq!(verified_digests, expected_digests);
    }

    #[test]
    fn chunked_verification_rejects_invalid_signature() {
        let strategy =
            Rayon::new(NonZeroUsize::new(4).expect("test thread count should be non-zero"))
                .expect("rayon strategy should construct");
        let sender = TestSigner::from_seed(13);
        let attacker = TestSigner::from_seed(17);
        let recipient = TestSigner::from_seed(19);
        let mut transactions = (0..64)
            .map(|nonce| signed_transaction(&sender, recipient.address, nonce))
            .collect::<Vec<_>>();
        transactions[31] = invalid_transaction(&sender, &attacker, recipient.address, 31);
        let mut rng = StdRng::seed_from_u64(23);
        let lazy_txs = transactions.into_iter().map(Lazy::new).collect();

        let verified =
            verify_transaction_chunks::<ed25519::PublicKey, sha256::Sha256, ed25519::Batch, _>(
                &strategy, NAMESPACE, &mut rng, lazy_txs,
            );

        assert!(verified.is_none());
    }

    #[test]
    fn chunked_verification_rejects_malformed_sender() {
        let strategy =
            Rayon::new(NonZeroUsize::new(4).expect("test thread count should be non-zero"))
                .expect("rayon strategy should construct");
        let sender = TestSigner::from_seed(29);
        let recipient = TestSigner::from_seed(31);
        let transaction = signed_transaction(&sender, recipient.address, 0);
        let mut encoded = transaction.encode().to_vec();

        let invalid_sender = (0u8..=u8::MAX)
            .flat_map(|first| (0u8..=u8::MAX).map(move |last| (first, last)))
            .find_map(|(first, last)| {
                let mut candidate = [0; ed25519::PublicKey::SIZE];
                candidate[0] = first;
                candidate[ed25519::PublicKey::SIZE - 1] = last;

                ed25519::PublicKey::decode(&mut &candidate[..])
                    .is_err()
                    .then_some(candidate)
            })
            .expect("test should find invalid sender bytes");
        encoded[..invalid_sender.len()].copy_from_slice(&invalid_sender);

        let malformed =
            SignedTransaction::<ed25519::PublicKey, sha256::Sha256>::decode(&mut &encoded[..])
                .expect("decode should defer sender validation");
        let mut rng = StdRng::seed_from_u64(37);

        let verified = verify_transaction_chunks::<
            ed25519::PublicKey,
            sha256::Sha256,
            ed25519::Batch,
            _,
        >(&strategy, NAMESPACE, &mut rng, vec![Lazy::new(malformed)]);

        assert!(verified.is_none());
    }
}
