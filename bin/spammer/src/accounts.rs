//! Deterministic spam account generation.

use commonware_cryptography::{Signer, ed25519};
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
        resolve_seed_offset(Some(u64::MAX), 2, 1, &mut rng);
    }
}
