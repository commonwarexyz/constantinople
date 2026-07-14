//! Payment-channel primitives shared by the chain and the off-chain operator.
//!
//! A payment channel is unidirectional: a payer escrows funds into a channel
//! account once, then streams off-chain *vouchers* to a receiver. Each voucher
//! is signed by the channel's delegated *voucher key* — an Ed25519 key the
//! payer names in the `OpenChannel` — over a monotonically increasing
//! cumulative amount. The receiver verifies vouchers locally (no on-chain
//! transaction per payment) and periodically settles the latest voucher
//! on-chain.
//!
//! Delegation is what lets any account be a payer: the payer's own key (which
//! may be a WebAuthn passkey that demands a user ceremony per signature) signs
//! exactly one transaction — the open — and the named voucher key signs the
//! high-frequency payments silently. The voucher key is an authority, not an
//! account: it cannot transfer funds or open channels, and compromising it
//! authorizes at most the deposits of the channels that name it, payable only
//! to their fixed receivers.
//!
//! The two halves of the system — the on-chain settlement logic and the
//! off-chain operator — must agree exactly on which vouchers are valid, or the
//! operator could accept a voucher the chain later rejects (and never get
//! paid). This module is that shared verification core:
//!
//! - [`channel_address`] derives the channel account address from
//!   `(payer, receiver, operator, voucher_key, open_nonce)`. Because the
//!   address binds the parties and the delegated key, none of them need to be
//!   stored on-chain.
//! - [`voucher_message`] builds the exact bytes a voucher signs.
//! - [`verify_voucher`] checks a voucher signature against the voucher key.
//! - [`VOUCHER_NAMESPACE`] domain-separates voucher signatures from
//!   transaction signatures.

use crate::AccountKey;
use commonware_codec::FixedSize as _;
use commonware_cryptography::{Hasher, Sha256, Verifier as _, ed25519};

/// Signing namespace for channel vouchers.
///
/// Distinct from [`crate::TRANSACTION_NAMESPACE`] so a voucher signature can
/// never be replayed as a transaction signature (or vice versa).
pub const VOUCHER_NAMESPACE: &[u8] = b"constantinople-voucher";

/// Domain separator mixed into channel-address derivation. The `-v2` suffix
/// marks the delegated-voucher-key derivation (the key joined the preimage).
const CHANNEL_ADDRESS_DOMAIN: &[u8] = b"constantinople-channel-v2";

/// Derives the channel account address for a
/// `(payer, receiver, operator, voucher_key, open_nonce)` tuple.
///
/// The address is `H(DOMAIN || payer || receiver || operator || voucher_key
/// || open_nonce)`, where `open_nonce` is the nonce of the `OpenChannel`
/// transaction. It lives in the same key space as a regular account, but no
/// private key produces it, so no ordinary transfer can move funds out of the
/// channel — only the channel settlement logic can. Because account nonces are
/// monotonic and never reused, each open yields a unique address that no later
/// `OpenChannel` can recreate: no party's identity needs to be persisted, a
/// settled channel can be deleted, and an old voucher can never be replayed
/// against a *different* channel.
///
/// The `operator` is the account whose key may settle the channel with a
/// [`crate::Operation::CloseChannel`]; the settled cumulative is paid to
/// `receiver`; `voucher_key` is the delegated Ed25519 key whose signatures the
/// settlement accepts. A channel run by its own payee simply names itself
/// (`operator == receiver`). Because all the participants and the delegated
/// key are inside the hash, a voucher's signature over the address commits to
/// the full tuple: redirecting a voucher to a different payee or settler — or
/// substituting a voucher key the closer controls — would need a second
/// preimage.
///
/// Note this address is publicly derivable, so an ordinary transfer *can*
/// credit it again after settlement; the on-chain lane documents the resulting
/// replay caveat (see `constantinople-application`'s channel module).
pub fn channel_address(
    payer: &AccountKey,
    receiver: &AccountKey,
    operator: &AccountKey,
    voucher_key: &ed25519::PublicKey,
    open_nonce: u64,
) -> AccountKey {
    let mut hasher = Sha256::default();
    hasher.update(CHANNEL_ADDRESS_DOMAIN);
    hasher.update(payer.as_ref());
    hasher.update(receiver.as_ref());
    hasher.update(operator.as_ref());
    hasher.update(voucher_key.as_ref());
    hasher.update(&open_nonce.to_be_bytes());
    AccountKey::from_digest(&hasher.finalize())
}

/// Builds the message a voucher signs: the channel address followed by the
/// big-endian cumulative amount.
pub fn voucher_message(channel: &AccountKey, cumulative: u64) -> [u8; AccountKey::SIZE + 8] {
    let mut message = [0u8; AccountKey::SIZE + 8];
    message[..AccountKey::SIZE].copy_from_slice(channel.as_ref());
    message[AccountKey::SIZE..].copy_from_slice(&cumulative.to_be_bytes());
    message
}

/// Verifies a voucher signature over `(channel, cumulative)` against the
/// channel's delegated voucher key.
///
/// The address the message embeds commits to the voucher key, so a valid
/// signature also proves the key is the one the channel was opened with.
pub fn verify_voucher(
    voucher_key: &ed25519::PublicKey,
    channel: &AccountKey,
    cumulative: u64,
    signature: &ed25519::Signature,
) -> bool {
    let message = voucher_message(channel, cumulative);
    voucher_key.verify(VOUCHER_NAMESPACE, &message, signature)
}

/// A signed, off-chain voucher.
///
/// The receiver accumulates these as payments stream in and submits the latest
/// one on-chain to settle. `cumulative` is monotonic across a channel's life.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Voucher {
    /// The channel account address this voucher draws against.
    pub channel: AccountKey,
    /// The cumulative amount authorized by the voucher key.
    pub cumulative: u64,
    /// The voucher key's signature over [`voucher_message`].
    pub signature: ed25519::Signature,
}

impl Voucher {
    /// Signs a voucher for `channel` authorizing `cumulative` with the
    /// channel's delegated voucher key.
    pub fn sign(voucher_key: &ed25519::PrivateKey, channel: AccountKey, cumulative: u64) -> Self {
        use commonware_cryptography::Signer as _;
        let message = voucher_message(&channel, cumulative);
        let signature = voucher_key.sign(VOUCHER_NAMESPACE, &message);
        Self {
            channel,
            cumulative,
            signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Signer as _, ed25519};

    fn voucher_key(seed: u64) -> ed25519::PrivateKey {
        ed25519::PrivateKey::from_seed(seed)
    }

    #[test]
    fn channel_address_is_deterministic_and_binds_parties() {
        let payer = AccountKey::from([1u8; AccountKey::SIZE]);
        let receiver = AccountKey::from([2u8; AccountKey::SIZE]);
        let operator = AccountKey::from([3u8; AccountKey::SIZE]);
        let key = voucher_key(1).public_key();
        let other_key = voucher_key(2).public_key();

        let a = channel_address(&payer, &receiver, &operator, &key, 3);
        let b = channel_address(&payer, &receiver, &operator, &key, 3);
        assert_eq!(a, b, "derivation must be deterministic");

        // Swapping the parties (a payer->receiver channel is not a
        // receiver->payer channel) yields a different address.
        assert_ne!(a, channel_address(&receiver, &payer, &operator, &key, 3));
        // A different operator yields a different address: the settling key
        // is a participant, not an afterthought.
        assert_ne!(a, channel_address(&payer, &operator, &receiver, &key, 3));
        assert_ne!(a, channel_address(&payer, &receiver, &payer, &key, 3));
        // A different voucher key yields a different address: a closer
        // cannot substitute a key it controls.
        assert_ne!(
            a,
            channel_address(&payer, &receiver, &operator, &other_key, 3)
        );
        // A different open nonce yields a different address.
        assert_ne!(a, channel_address(&payer, &receiver, &operator, &key, 4));
    }

    #[test]
    fn voucher_verifies_against_voucher_key() {
        let key = voucher_key(7);
        let channel = AccountKey::from([9u8; AccountKey::SIZE]);

        let voucher = Voucher::sign(&key, channel, 25);
        assert!(verify_voucher(
            &key.public_key(),
            &channel,
            voucher.cumulative,
            &voucher.signature
        ));
    }

    #[test]
    fn voucher_rejects_tampered_amount() {
        let key = voucher_key(8);
        let channel = AccountKey::from([9u8; AccountKey::SIZE]);

        let voucher = Voucher::sign(&key, channel, 25);
        // A receiver cannot inflate the claim without invalidating the
        // signature.
        assert!(!verify_voucher(
            &key.public_key(),
            &channel,
            26,
            &voucher.signature
        ));
    }

    #[test]
    fn voucher_rejects_wrong_key() {
        let key = voucher_key(8);
        let other = voucher_key(9).public_key();
        let channel = AccountKey::from([9u8; AccountKey::SIZE]);

        let voucher = Voucher::sign(&key, channel, 25);
        assert!(!verify_voucher(
            &other,
            &channel,
            voucher.cumulative,
            &voucher.signature
        ));
    }
}
