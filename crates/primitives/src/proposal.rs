//! Proposal budgets for the canonical SHA-256 and Ed25519 validator stack.

use crate::{Transaction, TransactionSignature};
use commonware_codec::{EncodeSize, FixedSize, varint::UInt};
use commonware_consensus::{
    marshal::coding::types::coding_config_for_participants, types::coding::Commitment,
};
use commonware_cryptography::{ed25519, sha256};

/// Maximum encoded block size accepted by consensus, including its header and body framing.
pub const MAXIMUM_BLOCK_SIZE: usize = 16 * 1024 * 1024;

/// Maximum encoded application message accepted by the validator network.
pub const MAXIMUM_MESSAGE_SIZE: u32 = 32 * 1024 * 1024;

/// Transaction-byte budget after reserving space for block framing.
///
/// Returns `None` if the block budget exceeds the consensus limit or cannot
/// accommodate the largest header and an empty body.
pub fn max_transaction_bytes(block_bytes: usize) -> Option<usize> {
    if block_bytes > MAXIMUM_BLOCK_SIZE {
        return None;
    }
    let body_bytes = block_bytes.checked_sub(maximum_header_size())?;

    // Counting minimum-size transactions reserves enough two-byte prefixes for any signature mix.
    let minimum_transaction = Transaction::<sha256::Digest>::SIZE + TransactionSignature::MIN_SIZE;
    let max_transaction_count = body_bytes / minimum_transaction;
    let framing = max_transaction_count.encode_size()
        + max_transaction_count * minimum_transaction.encode_size();
    body_bytes.checked_sub(framing)
}

/// Maximum raw shard size for blocks admitted by consensus.
///
/// Panics if fewer than four validators are supplied.
pub fn maximum_shard_size(num_validators: u16) -> usize {
    let config = coding_config_for_participants(num_validators);

    // Coding metadata and Reed-Solomon's length prefix precede the split into even-width shards.
    let payload_bytes = MAXIMUM_BLOCK_SIZE + config.encode_size() + u32::SIZE;
    let shards = usize::from(config.minimum_shards.get());
    payload_bytes.div_ceil(2 * shards) * 2
}

fn maximum_header_size() -> usize {
    // Epoch and the two views use varints. The remaining header counters are fixed width.
    3 * UInt(u64::MAX).encode_size()
        + ed25519::PublicKey::SIZE
        + Commitment::SIZE
        + 3 * sha256::Digest::SIZE
        + 6 * u64::SIZE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Block, Header, Sealable, SignedTransaction, TRANSACTION_NAMESPACE, TransactionPublicKey,
    };
    use commonware_codec::Encode;
    use commonware_consensus::{
        simplex::types::Context,
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{Digest, Signer, secp256r1::standard as secp256r1};
    use commonware_math::algebra::Random;
    use commonware_utils::non_empty_range;
    use std::num::NonZeroU64;

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
            state_root: sha256::Digest::EMPTY,
            state_range: non_empty_range!(u64::MAX - 1, u64::MAX),
            transactions_root: sha256::Digest::EMPTY,
            transactions_range: non_empty_range!(u64::MAX - 1, u64::MAX),
        }
    }

    fn signature_size_extremes() -> [SignedTransaction<sha256::Sha256>; 2] {
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
            TransactionSignature::MIN_SIZE
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
        [minimum, maximum]
    }

    #[test]
    fn empty_block_bound_matches_maximum_header_codec() {
        let block = Block::<_, _, sha256::Sha256>::new(maximum_header(), Vec::new());
        assert_eq!(
            maximum_header_size() + 0usize.encode_size(),
            block.encode().len()
        );
        assert_eq!(max_transaction_bytes(block.encode().len()), Some(0));
        assert_eq!(max_transaction_bytes(block.encode().len() - 1), None);
    }

    #[test]
    fn selection_budget_fits_encoded_blocks() {
        let transactions = signature_size_extremes();
        let minimum_size = transactions[0].encode_size();
        let maximum_size = transactions[1].encode_size();
        assert_eq!(minimum_size.encode_size(), 2);
        assert_eq!(maximum_size.encode_size(), 2);

        for pattern in [&transactions[..1], &transactions[1..], &transactions[..]] {
            for block_budget in [307, 512, 8192, 19232, 19381, MAXIMUM_BLOCK_SIZE] {
                let budget = max_transaction_bytes(block_budget).unwrap();
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
                let block = Block::new(maximum_header(), body);
                assert!(
                    block.encode().len() <= block_budget,
                    "transaction budget {budget} exceeded block budget {block_budget}",
                );
            }
        }
    }

    #[test]
    fn rejects_invalid_block_budgets() {
        for budget in [0, MAXIMUM_BLOCK_SIZE + 1, usize::MAX] {
            assert_eq!(max_transaction_bytes(budget), None);
        }
    }

    #[test]
    fn shard_limit_scales_with_original_shards() {
        assert_eq!(maximum_shard_size(4), 8 * 1024 * 1024 + 4);
        assert!(maximum_shard_size(7) < maximum_shard_size(4));
        assert!(maximum_shard_size(50) < maximum_shard_size(7));
        assert!(maximum_shard_size(u16::MAX) > 0);
    }
}
