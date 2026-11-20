//! Spammer account generation and seed selection.

use commonware_cryptography::{Hasher as _, Sha256, Signer, ed25519};
use commonware_parallel::Strategy;
use constantinople_auth::SharedKey;
use constantinople_primitives::TRANSACTION_NAMESPACE;
use rand::{Rng, RngExt};

/// A spam account with its signing key.
pub struct SpamAccount {
    pub private_key: ed25519::PrivateKey,
    pub public_key: ed25519::PublicKey,
}

/// Generates `count` deterministic spam accounts from sequential seeds
/// starting at `seed_offset`.
pub fn generate_accounts(count: u32, seed_offset: u64) -> Vec<SpamAccount> {
    (0..count)
        .map(|i| {
            let private_key = ed25519::PrivateKey::from_seed(seed_offset + u64::from(i));
            let public_key = private_key.public_key();
            SpamAccount {
                private_key,
                public_key,
            }
        })
        .collect()
}

/// A spam account whose transactions are authenticated by tags.
pub struct TaggedAccount {
    pub public_key: constantinople_auth::PublicKey,
    /// The key the account shares with each validator, in participant order.
    pub keys: Vec<SharedKey>,
}

/// Generates `count` deterministic X25519 spam accounts from sequential seeds
/// starting at `seed_offset`, and derives the key each one shares with every
/// validator. `validators` holds the validators' X25519 keys in participant
/// order.
///
/// The keys are derived once: every later transaction of an account costs a
/// keyed hash per validator.
pub fn generate_tagged_accounts<St: Strategy>(
    strategy: &St,
    count: u32,
    seed_offset: u64,
    validators: &[constantinople_auth::PublicKey],
) -> Vec<TaggedAccount> {
    strategy.map_collect_vec(0..count, |i| {
        let seed = seed_offset + u64::from(i);
        let secret: [u8; 32] = Sha256::hash(&[&seed.to_be_bytes()])
            .as_ref()
            .try_into()
            .expect("SHA-256 digests are 32 bytes");
        let secret = constantinople_auth::PrivateKey::from(secret);
        let keys = validators
            .iter()
            .map(|validator| {
                secret
                    .with_validator(TRANSACTION_NAMESPACE, validator)
                    .expect("validator tag key must not be a low-order point")
            })
            .collect();
        TaggedAccount {
            public_key: secret.public_key(),
            keys,
        }
    })
}

/// Selects a seed range large enough for every submitter account.
pub fn resolve_seed_offset(
    configured: Option<u64>,
    accounts_per_submitter: u32,
    submitters: usize,
    rng: &mut impl Rng,
) -> u64 {
    let submitters = u64::try_from(submitters).expect("submitter count must fit in u64");
    let total_accounts = u64::from(accounts_per_submitter)
        .checked_mul(submitters)
        .expect("total account count overflow");
    assert!(total_accounts > 0, "need at least one spam account");

    let max_seed_offset = u64::MAX - (total_accounts - 1);
    configured.map_or_else(
        || rng.random_range(0..=max_seed_offset),
        |seed_offset| {
            assert!(
                seed_offset <= max_seed_offset,
                "seed offset does not leave room for every spam account"
            );
            seed_offset
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts_are_deterministic() {
        let a = generate_accounts(3, 1000);
        let b = generate_accounts(3, 1000);
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.public_key, y.public_key);
        }
    }

    #[test]
    fn different_seeds_produce_different_accounts() {
        let a = generate_accounts(1, 1000);
        let b = generate_accounts(1, 1001);
        assert_ne!(a[0].public_key, b[0].public_key);
    }

    #[test]
    fn public_keys_are_unique() {
        let accounts = generate_accounts(10, 1000);
        for (i, a) in accounts.iter().enumerate() {
            for (j, b) in accounts.iter().enumerate() {
                if i != j {
                    assert_ne!(a.public_key, b.public_key);
                }
            }
        }
    }

    #[test]
    fn explicit_seed_offset_is_deterministic() {
        let mut rng = commonware_utils::test_rng();
        let seed_offset = resolve_seed_offset(Some(42), 10, 4, &mut rng);

        assert_eq!(seed_offset, 42);
    }

    #[test]
    fn fresh_seed_offsets_change_between_starts() {
        let mut rng = commonware_utils::test_rng();
        let first = resolve_seed_offset(None, 10, 4, &mut rng);
        let second = resolve_seed_offset(None, 10, 4, &mut rng);

        assert_ne!(first, second);
    }

    #[test]
    fn explicit_seed_offset_can_use_the_last_seed() {
        let mut rng = commonware_utils::test_rng();
        let seed_offset = resolve_seed_offset(Some(u64::MAX - 5), 2, 3, &mut rng);
        let last_submitter = generate_accounts(2, seed_offset + 4);

        assert_eq!(
            last_submitter[1].public_key,
            ed25519::PrivateKey::from_seed(u64::MAX).public_key()
        );
    }

    #[test]
    fn random_seed_offset_leaves_room_for_every_account() {
        let mut rng = commonware_utils::test_rng();
        let accounts_per_submitter = 10;
        let submitters = 4;
        let seed_offset = resolve_seed_offset(None, accounts_per_submitter, submitters, &mut rng);
        let total_accounts = u64::from(accounts_per_submitter)
            * u64::try_from(submitters).expect("submitter count must fit");
        let max_seed_offset = u64::MAX - (total_accounts - 1);
        let last_seed = seed_offset
            .checked_add(total_accounts - 1)
            .expect("selected range must fit");

        assert!(seed_offset <= max_seed_offset);
        assert_eq!(last_seed - seed_offset, total_accounts - 1);
    }

    #[test]
    #[should_panic(expected = "seed offset does not leave room for every spam account")]
    fn explicit_seed_offset_rejects_account_range_overflow() {
        let mut rng = commonware_utils::test_rng();
        resolve_seed_offset(Some(u64::MAX - 4), 2, 3, &mut rng);
    }
}
