//! Account model for the Constantinople chain.

use crate::{
    TransactionPublicKey,
    auth::{ED25519_SCHEME, SECP256R1_SCHEME},
};
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedArray, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{Hasher, ed25519, sha256};
use commonware_formatting::hex;
use commonware_utils::{Array, Span};
use core::ops::Deref;
use derive_more::{Debug, Display};

/// Default starting balance for accounts that have not been written yet.
pub const DEFAULT_ACCOUNT_BALANCE: u64 = 100;

/// Number of future nonce uses tracked on each account.
pub const NONCE_BITMAP_CAPACITY: u64 = u64::BITS as u64;

// Account keys keep the legacy Ed25519 public-key width. Secp256r1 accounts
// are hashed into this same fixed-width state key.
const ACCOUNT_KEY_SIZE: usize = ed25519::PublicKey::SIZE;

/// Fixed-width account identifier derived from a transaction public key.
///
/// Unlike [`commonware_cryptography::PublicKey`] implementations, decoding an
/// [`AccountKey`] does not validate or decompress the curve point. This keeps
/// state-database replay, indexing, and lookup on cheap byte comparisons while
/// preserving the legacy Ed25519 account format.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, FixedArray)]
#[fixed_array(infallible)]
pub struct AccountKey {
    bytes: [u8; ACCOUNT_KEY_SIZE],
}

impl AccountKey {
    /// Creates an account key from a decoded public key.
    pub fn from_public_key(public_key: &TransactionPublicKey) -> Self {
        match public_key {
            TransactionPublicKey::Ed25519 { encoded } => {
                Self::try_from(&encoded[1..1 + Self::SIZE])
                    .expect("ed25519 account-key slice has account-key length")
            }
            TransactionPublicKey::Secp256r1 { encoded } => {
                Self::try_from(sha256::Sha256::hash(encoded).as_ref())
                    .expect("sha256 digest has account-key length")
            }
        }
    }

    /// Creates an account key from encoded transaction public-key bytes.
    pub fn from_public_key_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != TransactionPublicKey::SIZE {
            return None;
        }

        match bytes[0] {
            ED25519_SCHEME => Self::try_from(&bytes[1..1 + Self::SIZE]).ok(),
            SECP256R1_SCHEME => Self::try_from(sha256::Sha256::hash(bytes).as_ref()).ok(),
            _ => None,
        }
    }

    /// First eight account-key bytes as a little-endian routing prefix.
    #[inline]
    pub fn prefix(&self) -> u64 {
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&self.bytes[..8]);
        u64::from_le_bytes(prefix)
    }
}

impl FixedSize for AccountKey {
    const SIZE: usize = ACCOUNT_KEY_SIZE;
}

impl Write for AccountKey {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.bytes);
    }
}

impl Read for AccountKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        if buf.remaining() < Self::SIZE {
            return Err(CodecError::EndOfBuffer);
        }

        let mut bytes = [0u8; ACCOUNT_KEY_SIZE];
        buf.copy_to_slice(&mut bytes);
        Ok(Self { bytes })
    }
}

impl AsRef<[u8]> for AccountKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Deref for AccountKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl core::fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.bytes))
    }
}

impl core::fmt::Display for AccountKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.bytes))
    }
}

impl Span for AccountKey {}
impl Array for AccountKey {}

/// Account nonce state.
#[derive(Debug, Display, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(any(feature = "arbitrary", test), derive(arbitrary::Arbitrary))]
#[display("Nonce {{ base: {}, bitmap: {} }}", base, bitmap)]
pub struct Nonce {
    /// The next nonce that has not been consumed by this account.
    pub base: u64,
    /// Used future nonces relative to [`Self::base`].
    ///
    /// Bit 0 records `base + 1`, and bit 63 records `base + 64`.
    pub bitmap: u64,
}

impl Nonce {
    /// Creates account nonce state from raw parts.
    pub const fn new(base: u64, bitmap: u64) -> Self {
        Self { base, bitmap }
    }

    /// Records a transaction nonce if it has not already been consumed.
    ///
    /// Nonces below [`Self::base`] are stale. Nonces inside the run-ahead
    /// window set a bitmap bit. Nonces beyond the window clear the bitmap and
    /// advance [`Self::base`] beyond the consumed transaction.
    pub fn consume(&mut self, nonce: u64) -> bool {
        let Some(next) = next_nonce_state(self.base, self.bitmap, nonce) else {
            return false;
        };

        *self = next;
        true
    }
}

impl FixedSize for Nonce {
    const SIZE: usize = u64::SIZE + u64::SIZE;
}

impl Write for Nonce {
    fn write(&self, buf: &mut impl BufMut) {
        self.base.write(buf);
        self.bitmap.write(buf);
    }
}

impl Read for Nonce {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            base: u64::read(buf)?,
            bitmap: u64::read(buf)?,
        })
    }
}

/// An account, as represented in the state of the chain.
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(any(feature = "arbitrary", test), derive(arbitrary::Arbitrary))]
#[display("Account {{ balance: {}, nonce: {} }}", balance, nonce)]
pub struct Account {
    /// The balance of the account, which is the amount of tokens that the
    /// account holds.
    pub balance: u64,
    /// Consumed and run-ahead transaction nonce state.
    pub nonce: Nonce,
}

impl Default for Account {
    fn default() -> Self {
        Self {
            balance: DEFAULT_ACCOUNT_BALANCE,
            nonce: Nonce::default(),
        }
    }
}

impl FixedSize for Account {
    const SIZE: usize = u64::SIZE + Nonce::SIZE;
}

impl Write for Account {
    fn write(&self, buf: &mut impl BufMut) {
        self.balance.write(buf);
        self.nonce.write(buf);
    }
}

impl Read for Account {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            balance: u64::read(buf)?,
            nonce: Nonce::read(buf)?,
        })
    }
}

fn next_nonce_state(base: u64, bitmap: u64, nonce: u64) -> Option<Nonce> {
    let next_used_nonce = nonce.checked_add(1)?;

    if nonce < base {
        return None;
    }

    let delta = nonce - base;
    if delta == 0 {
        return consume_current_nonce(base, bitmap);
    }

    if delta > NONCE_BITMAP_CAPACITY {
        return Some(Nonce::new(next_used_nonce, 0));
    }

    let bit = 1u64 << (delta - 1);
    if bitmap & bit != 0 {
        return None;
    }

    Some(Nonce::new(base, bitmap | bit))
}

fn consume_current_nonce(base: u64, bitmap: u64) -> Option<Nonce> {
    let mut advance = 1;
    while advance <= NONCE_BITMAP_CAPACITY {
        let bit = 1u64 << (advance - 1);
        if bitmap & bit == 0 {
            break;
        }
        advance += 1;
    }

    let nonce = base.checked_add(advance)?;
    let bitmap = if advance >= NONCE_BITMAP_CAPACITY {
        0
    } else {
        bitmap >> advance
    };
    Some(Nonce::new(nonce, bitmap))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, FixedSize};
    use commonware_cryptography::{
        Hasher, Signer, ed25519, secp256r1::standard as secp256r1, sha256,
    };

    #[test]
    fn account_key_roundtrip_does_not_validate_public_key() {
        let mut raw = vec![0u8; AccountKey::SIZE];
        raw[0] = 1;

        let key = AccountKey::decode(&mut &raw[..]).expect("account keys are raw bytes");

        assert_eq!(key.as_ref(), raw.as_slice());
    }

    #[test]
    fn account_key_from_ed25519_public_key_uses_legacy_key_bytes() {
        let private_key = ed25519::PrivateKey::from_seed(1);
        let public_key = TransactionPublicKey::ed25519(private_key.public_key());

        let key = AccountKey::from_public_key(&public_key);

        assert_eq!(key.as_ref(), &public_key.as_ref()[1..1 + AccountKey::SIZE]);
    }

    #[test]
    fn account_key_from_secp256r1_public_key_uses_hash() {
        let private_key = secp256r1::PrivateKey::from_seed(1);
        let public_key = TransactionPublicKey::secp256r1(private_key.public_key());

        let key = AccountKey::from_public_key(&public_key);

        assert_eq!(
            key.as_ref(),
            sha256::Sha256::hash(public_key.as_ref()).as_ref()
        );
    }

    #[test]
    fn account_codec_roundtrip() {
        let account = Account {
            balance: 42,
            nonce: Nonce::new(7, 3),
        };

        let mut buf = Vec::with_capacity(Account::SIZE);
        account.write(&mut buf);
        assert_eq!(buf.len(), Account::SIZE);

        let decoded = Account::decode(&mut &buf[..]).expect("decoding should succeed");
        assert_eq!(decoded, account);
    }

    #[test]
    fn account_default_starts_funded() {
        assert_eq!(
            Account::default(),
            Account {
                balance: DEFAULT_ACCOUNT_BALANCE,
                nonce: Nonce::default(),
            }
        );
    }

    #[test]
    fn nonce_records_run_ahead_value() {
        let mut nonce = Nonce::default();

        assert!(nonce.consume(2));
        assert_eq!(nonce, Nonce::new(0, 0b10));
    }

    #[test]
    fn nonce_compacts_contiguous_run_ahead() {
        let mut nonce = Nonce::default();

        assert!(nonce.consume(2));
        assert!(nonce.consume(0));
        assert_eq!(nonce, Nonce::new(1, 0b1));

        assert!(nonce.consume(1));
        assert_eq!(nonce, Nonce::new(3, 0));
    }

    #[test]
    fn nonce_rejects_duplicate_run_ahead() {
        let mut nonce = Nonce::default();

        assert!(nonce.consume(2));
        assert!(!nonce.consume(2));
        assert_eq!(nonce, Nonce::new(0, 0b10));
    }

    #[test]
    fn nonce_rejects_run_ahead_value_that_cannot_advance() {
        let mut nonce = Nonce::new(u64::MAX - 1, 0);

        assert!(!nonce.consume(u64::MAX));
        assert_eq!(nonce, Nonce::new(u64::MAX - 1, 0));
    }

    #[test]
    fn nonce_clears_bitmap_after_far_jump() {
        let mut nonce = Nonce::default();

        assert!(nonce.consume(2));
        assert!(nonce.consume(NONCE_BITMAP_CAPACITY + 1));
        assert_eq!(nonce, Nonce::new(NONCE_BITMAP_CAPACITY + 2, 0));
        assert!(!nonce.consume(NONCE_BITMAP_CAPACITY + 1));
    }
}
