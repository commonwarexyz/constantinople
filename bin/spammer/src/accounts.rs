//! Deterministic spam account generation.

use commonware_cryptography::{Signer, blake3, ed25519};
use constantinople_primitives::Address;

/// A spam account with its signing key and derived address.
pub struct SpamAccount {
    pub private_key: ed25519::PrivateKey,
    pub public_key: ed25519::PublicKey,
    pub address: Address,
}

/// Generates `count` deterministic spam accounts from sequential seeds
/// starting at `seed_offset`.
pub fn generate_accounts(count: u32, seed_offset: u64) -> Vec<SpamAccount> {
    (0..count)
        .map(|i| {
            let private_key = ed25519::PrivateKey::from_seed(seed_offset + u64::from(i));
            let public_key = private_key.public_key();
            let address = Address::from_public_key(&mut blake3::Blake3::default(), &public_key);
            SpamAccount {
                private_key,
                public_key,
                address,
            }
        })
        .collect()
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
            assert_eq!(x.address, y.address);
        }
    }

    #[test]
    fn different_seeds_produce_different_accounts() {
        let a = generate_accounts(1, 1000);
        let b = generate_accounts(1, 1001);
        assert_ne!(a[0].public_key, b[0].public_key);
    }

    #[test]
    fn addresses_are_unique() {
        let accounts = generate_accounts(10, 1000);
        for (i, a) in accounts.iter().enumerate() {
            for (j, b) in accounts.iter().enumerate() {
                if i != j {
                    assert_ne!(a.address, b.address);
                }
            }
        }
    }
}
