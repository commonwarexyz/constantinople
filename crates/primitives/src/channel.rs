//! Payment-channel primitives shared by the chain and the off-chain operator.
//!
//! A payment channel is unidirectional: a payer escrows funds into a channel
//! account once, then streams off-chain *vouchers* to a receiver. Each voucher
//! is the payer's signature over a monotonically increasing cumulative amount.
//! The receiver verifies vouchers locally (no on-chain transaction per payment)
//! and periodically settles the latest voucher on-chain.
//!
//! The two halves of the system — the on-chain settlement logic and the
//! off-chain operator — must agree exactly on which vouchers are valid, or the
//! operator could accept a voucher the chain later rejects (and never get
//! paid). This module is that shared verification core:
//!
//! - [`channel_address`] derives the channel account address from
//!   `(payer, receiver, open_nonce)`. Because the address binds the parties, the
//!   payer/receiver identities never need to be stored on-chain.
//! - [`voucher_message`] builds the exact bytes a voucher signs.
//! - [`verify_voucher`] checks a voucher signature against the payer's key.
//! - [`VOUCHER_NAMESPACE`] domain-separates voucher signatures from
//!   transaction signatures.

use crate::{AccountKey, TransactionPublicKey};
use commonware_codec::FixedSize as _;
use commonware_cryptography::{Hasher, Sha256, Verifier as _, ed25519};

/// Signing namespace for channel vouchers.
///
/// Distinct from [`crate::TRANSACTION_NAMESPACE`] so a voucher signature can
/// never be replayed as a transaction signature (or vice versa).
pub const VOUCHER_NAMESPACE: &[u8] = b"constantinople-voucher";

/// Domain separator mixed into channel-address derivation.
const CHANNEL_ADDRESS_DOMAIN: &[u8] = b"constantinople-channel";

/// Derives the channel account address for a `(payer, receiver, open_nonce)`
/// triple.
///
/// The address is `H(DOMAIN || payer || receiver || open_nonce)`, where
/// `open_nonce` is the nonce of the `OpenChannel` transaction. It lives in the
/// same key space as a regular account, but no private key produces it, so no
/// ordinary transfer can move funds out of the channel — only the channel
/// settlement logic can. Because account nonces are monotonic and never reused,
/// each open yields a unique address that no later `OpenChannel` can recreate:
/// neither party's identity needs to be persisted, a settled channel can be
/// deleted, and an old voucher can never be replayed against a *different*
/// channel.
///
/// Note this address is publicly derivable, so an ordinary transfer *can*
/// credit it again after settlement; the on-chain lane documents the resulting
/// replay caveat (see `constantinople-application`'s channel module).
pub fn channel_address(payer: &AccountKey, receiver: &AccountKey, open_nonce: u64) -> AccountKey {
    let mut hasher = Sha256::default();
    hasher.update(CHANNEL_ADDRESS_DOMAIN);
    hasher.update(payer.as_ref());
    hasher.update(receiver.as_ref());
    hasher.update(&open_nonce.to_be_bytes());
    AccountKey::try_from(hasher.finalize().as_ref()).expect("sha256 digest has account-key length")
}

/// Builds the message a voucher signs: the channel address followed by the
/// big-endian cumulative amount.
pub fn voucher_message(channel: &AccountKey, cumulative: u64) -> [u8; AccountKey::SIZE + 8] {
    let mut message = [0u8; AccountKey::SIZE + 8];
    message[..AccountKey::SIZE].copy_from_slice(channel.as_ref());
    message[AccountKey::SIZE..].copy_from_slice(&cumulative.to_be_bytes());
    message
}

/// Verifies a payer's voucher signature over `(channel, cumulative)`.
///
/// Returns `false` for non-Ed25519 payers; the demo signs vouchers with the
/// native Ed25519 scheme.
pub fn verify_voucher(
    payer: &TransactionPublicKey,
    channel: &AccountKey,
    cumulative: u64,
    signature: &ed25519::Signature,
) -> bool {
    let Some(key) = payer.as_ed25519() else {
        return false;
    };
    let message = voucher_message(channel, cumulative);
    key.verify(VOUCHER_NAMESPACE, &message, signature)
}

/// A signed, off-chain voucher.
///
/// The receiver accumulates these as payments stream in and submits the latest
/// one on-chain to settle. `cumulative` is monotonic across a channel's life.
#[derive(Debug, Clone)]
pub struct Voucher {
    /// The channel account address this voucher draws against.
    pub channel: AccountKey,
    /// The cumulative amount authorized by the payer.
    pub cumulative: u64,
    /// The payer's signature over [`voucher_message`].
    pub signature: ed25519::Signature,
}

impl Voucher {
    /// Signs a voucher for `channel` authorizing `cumulative` with the payer's
    /// key.
    pub fn sign(payer: &ed25519::PrivateKey, channel: AccountKey, cumulative: u64) -> Self {
        use commonware_cryptography::Signer as _;
        let message = voucher_message(&channel, cumulative);
        let signature = payer.sign(VOUCHER_NAMESPACE, &message);
        Self {
            channel,
            cumulative,
            signature,
        }
    }

    /// Verifies this voucher against the payer's public key.
    pub fn verify(&self, payer: &TransactionPublicKey) -> bool {
        verify_voucher(payer, &self.channel, self.cumulative, &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Signer as _, ed25519};

    fn payer_key(seed: u64) -> ed25519::PrivateKey {
        ed25519::PrivateKey::from_seed(seed)
    }

    #[test]
    fn channel_address_is_deterministic_and_binds_parties() {
        let payer = AccountKey::from([1u8; AccountKey::SIZE]);
        let receiver = AccountKey::from([2u8; AccountKey::SIZE]);

        let a = channel_address(&payer, &receiver, 3);
        let b = channel_address(&payer, &receiver, 3);
        assert_eq!(a, b, "derivation must be deterministic");

        // Swapping the parties (a payer->receiver channel is not a
        // receiver->payer channel) yields a different address.
        assert_ne!(a, channel_address(&receiver, &payer, 3));
        // A different open nonce yields a different address.
        assert_ne!(a, channel_address(&payer, &receiver, 4));
    }

    #[test]
    fn voucher_verifies_against_payer_key() {
        let payer = payer_key(7);
        let payer_pk = TransactionPublicKey::ed25519(payer.public_key());
        let channel = AccountKey::from([9u8; AccountKey::SIZE]);

        let voucher = Voucher::sign(&payer, channel, 25);
        assert!(voucher.verify(&payer_pk));
    }

    #[test]
    fn voucher_rejects_tampered_amount() {
        let payer = payer_key(8);
        let payer_pk = TransactionPublicKey::ed25519(payer.public_key());
        let channel = AccountKey::from([9u8; AccountKey::SIZE]);

        let voucher = Voucher::sign(&payer, channel, 25);
        // A receiver cannot inflate the claim without invalidating the
        // signature.
        assert!(!verify_voucher(&payer_pk, &channel, 26, &voucher.signature));
    }

    #[test]
    fn voucher_rejects_wrong_payer() {
        let payer = payer_key(8);
        let other = TransactionPublicKey::ed25519(payer_key(9).public_key());
        let channel = AccountKey::from([9u8; AccountKey::SIZE]);

        let voucher = Voucher::sign(&payer, channel, 25);
        assert!(!voucher.verify(&other));
    }
}
