//! Utility functions for the application.

use crate::processor::state::State;
use commonware_cryptography::{BatchVerifier, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    mmr,
    qmdb::Error as StorageError,
    translator::Translator,
};
use constantinople_primitives::{SignedTransaction, VerifiedTransaction};
use futures::{StreamExt, stream::FuturesUnordered};
use rand::{SeedableRng, rngs::StdRng};
use rand_core::CryptoRngCore;
use std::collections::BTreeMap;

use super::StateBatch;

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
    let mut addresses = Vec::with_capacity(transactions.len().saturating_mul(2));
    for transaction in transactions {
        addresses.push(transaction.signer());
        addresses.push(transaction.value().to);
    }

    addresses.sort_unstable();
    addresses.dedup();

    if addresses.is_empty() {
        return Ok(BTreeMap::new());
    }

    let db = batch.lock().await;
    let db = &*db;
    let state_batch = batch.inner();
    let pending_reads: FuturesUnordered<_> = addresses
        .into_iter()
        .map(|address| async move {
            let account = state_batch.get(&address, db).await?;
            Ok::<_, StorageError<mmr::Family>>((address, account.unwrap_or_default()))
        })
        .collect();

    let accounts = pending_reads
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    Ok(accounts)
}

/// Verifies a batch of signed transactions.
pub(super) fn verify_transaction_batch<P, H, B>(
    namespace: &[u8],
    rng: &mut impl CryptoRngCore,
    transactions: &[SignedTransaction<P, H>],
) -> bool
where
    P: PublicKey,
    H: Hasher,
    B: BatchVerifier<PublicKey = P>,
{
    let mut batch_verifier = B::new();
    for transaction in transactions {
        // Decode the sender and signature inside the worker so decompression
        // happens on the rayon pool instead of the runtime thread.
        let Some(sender) = transaction.value().sender() else {
            return false;
        };
        let Some(signature) = transaction.signature() else {
            return false;
        };

        if !batch_verifier.add(
            namespace,
            transaction.message_digest().as_ref(),
            sender,
            signature,
        ) {
            return false;
        }
    }

    batch_verifier.verify(rng)
}

/// Verifies transactions across strategy partitions and preserves block order.
pub(super) fn verify_transaction_chunks<P, H, B, St>(
    strategy: &St,
    namespace: &'static [u8],
    rng: &mut impl CryptoRngCore,
    transactions: Vec<SignedTransaction<P, H>>,
) -> Option<Vec<VerifiedTransaction<P, H>>>
where
    P: PublicKey,
    H: Hasher,
    B: BatchVerifier<PublicKey = P>,
    St: Strategy,
{
    if transactions.is_empty() {
        return Some(Vec::new());
    }

    let chunk_count = strategy.parallelism_hint().min(transactions.len());
    let chunk_size = transactions.len().div_ceil(chunk_count);

    let mut remaining = transactions;
    let mut chunks = Vec::with_capacity(chunk_count);
    while !remaining.is_empty() {
        let split_at = chunk_size.min(remaining.len());
        let rest = remaining.split_off(split_at);
        let mut rng_seed = [0; 32];
        rng.fill_bytes(&mut rng_seed);
        chunks.push((rng_seed, remaining));
        remaining = rest;
    }

    let verified_chunks = strategy.map_collect_vec(chunks, |(rng_seed, chunk)| {
        let mut chunk_rng = StdRng::from_seed(rng_seed);
        verify_transaction_batch::<P, H, B>(namespace, &mut chunk_rng, &chunk)
            .then(|| chunk.into_iter().map(Into::into).collect::<Vec<_>>())
    });

    let mut verified = Vec::new();
    for chunk in verified_chunks {
        verified.extend(chunk?);
    }
    Some(verified)
}

#[cfg(test)]
mod tests {
    use super::verify_transaction_chunks;
    use commonware_codec::{DecodeExt, Encode, FixedSize};
    use commonware_cryptography::{Digest, Signer as _, blake3, ed25519};
    use commonware_parallel::Rayon;
    use constantinople_primitives::{Address, Signable, SignedTransaction, Transaction};
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
                Address::from_public_key(&mut blake3::Blake3::default(), &key.public_key());
            Self { key, address }
        }
    }

    fn signed_transaction(
        signer: &TestSigner,
        to: Address,
        nonce: u64,
    ) -> SignedTransaction<ed25519::PublicKey, blake3::Blake3> {
        Transaction::new(
            signer.key.public_key(),
            to,
            NonZeroU64::new(nonce + 1).expect("test value should be non-zero"),
            nonce,
        )
        .seal_and_sign(&signer.key, NAMESPACE, &mut blake3::Blake3::default())
    }

    fn invalid_transaction(
        claimed_signer: &TestSigner,
        actual_signer: &TestSigner,
        to: Address,
        nonce: u64,
    ) -> SignedTransaction<ed25519::PublicKey, blake3::Blake3> {
        Transaction::new(
            claimed_signer.key.public_key(),
            to,
            NonZeroU64::new(nonce + 1).expect("test value should be non-zero"),
            nonce,
        )
        .seal_and_sign(
            &actual_signer.key,
            NAMESPACE,
            &mut blake3::Blake3::default(),
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

        let verified = verify_transaction_chunks::<
            ed25519::PublicKey,
            blake3::Blake3,
            ed25519::Batch,
            _,
        >(&strategy, NAMESPACE, &mut rng, transactions)
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

        let verified = verify_transaction_chunks::<
            ed25519::PublicKey,
            blake3::Blake3,
            ed25519::Batch,
            _,
        >(&strategy, NAMESPACE, &mut rng, transactions);

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
            SignedTransaction::<ed25519::PublicKey, blake3::Blake3>::decode(&mut &encoded[..])
                .expect("decode should defer sender validation");
        let mut rng = StdRng::seed_from_u64(37);

        let verified = verify_transaction_chunks::<
            ed25519::PublicKey,
            blake3::Blake3,
            ed25519::Batch,
            _,
        >(&strategy, NAMESPACE, &mut rng, vec![malformed]);

        assert!(verified.is_none());
    }

}
