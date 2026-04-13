//! Account model for the Constantinople chain.
//!
//! This module defines the core account-related types:
//!
//! - [`Address`] — A 20-byte identifier derived by hashing a public key.
//! - [`Account`] — The on-chain state of an account, tracking its balance and nonce.

use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_math::algebra::Random;
use commonware_utils::{Array, Span, hex};
use core::ops::Deref;
use derive_more::{AsRef, Debug, Display};
use rand_core::CryptoRngCore;

/// Default starting balance for accounts that have not been written yet.
pub const DEFAULT_ACCOUNT_BALANCE: u64 = 100;

/// A 20-byte account address, derived by hashing a [`PublicKey`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, AsRef)]
#[display("{}", hex(self.0.as_ref()))]
#[debug("{}", hex(self.0.as_ref()))]
#[as_ref(forward)]
#[cfg_attr(any(feature = "arbitrary", test), derive(arbitrary::Arbitrary))]
pub struct Address([u8; Self::SIZE]);

impl Address {
    /// Hashes the given public key to produce an address.
    ///
    /// ## Panics
    ///
    /// Panics if the hasher's output size is smaller than [`Self::SIZE`].
    pub fn from_public_key<H, P>(hasher: &mut H, public_key: &P) -> Self
    where
        H: Hasher,
        P: PublicKey,
    {
        hasher.update(public_key.as_ref());
        let mut address = [0u8; Self::SIZE];
        address.copy_from_slice(&hasher.finalize().as_ref()[..Self::SIZE]);
        Self(address)
    }
}

impl FixedSize for Address {
    const SIZE: usize = 20;
}

impl Write for Address {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(self.0.as_ref());
    }
}

impl Read for Address {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        if buf.remaining() < Self::SIZE {
            return Err(CodecError::EndOfBuffer);
        }

        let mut address = [0u8; Self::SIZE];
        buf.copy_to_slice(&mut address);
        Ok(Self(address))
    }
}

impl Deref for Address {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Span for Address {}
impl Array for Address {}

impl Random for Address {
    fn random(mut rng: impl CryptoRngCore) -> Self {
        let mut address = [0u8; Self::SIZE];
        rng.fill_bytes(&mut address);
        Self(address)
    }
}

impl Digest for Address {
    const EMPTY: Self = Self([0u8; Self::SIZE]);
}

/// Macro for converting sequence of string literals containing hex-encoded data
/// into an [`Address`] type.
#[macro_export]
macro_rules! address {
    ($s:tt) => {
        const { $crate::Address::new(::commonware_utils::hex!($s)) }
    };
}

/// An account, as represented in the state of the chain.
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(any(feature = "arbitrary", test), derive(arbitrary::Arbitrary))]
#[display("Account {{ balance: {}, nonce: {} }}", balance, nonce)]
pub struct Account {
    /// The balance of the account, which is the amount of tokens that the
    /// account holds.
    pub balance: u64,
    /// The nonce of the account, which is incremented every time a
    /// transaction is sent from the account.
    pub nonce: u64,
}

impl Default for Account {
    fn default() -> Self {
        Self {
            balance: DEFAULT_ACCOUNT_BALANCE,
            nonce: 0,
        }
    }
}

impl FixedSize for Account {
    const SIZE: usize = u64::SIZE + u64::SIZE;
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
            nonce: u64::read(buf)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, FixedSize};
    use commonware_cryptography::{Signer, blake3, secp256r1::recoverable};
    use commonware_math::algebra::Random;
    use commonware_utils::test_rng;

    #[test]
    fn address_display() {
        let address = Address([0xAB; Address::SIZE]);
        assert_eq!(format!("{}", address), "ab".repeat(Address::SIZE));
        assert_eq!(format!("{:?}", address), "ab".repeat(Address::SIZE));
    }

    #[test]
    fn address_codec_roundtrip() {
        let address = Address::random(&mut test_rng());

        let mut buf = Vec::with_capacity(Address::SIZE);
        address.write(&mut buf);
        assert_eq!(buf.len(), Address::SIZE);

        let decoded = Address::decode(&mut &buf[..]).expect("decoding should succeed");
        assert_eq!(decoded, address);
    }

    #[test]
    fn address_codec_short_buffer() {
        let buf = [0u8; Address::SIZE - 1];
        let result = Address::decode(&mut &buf[..]);
        assert!(result.is_err(), "should fail with a short buffer");
    }

    #[test]
    fn address_from_public_key_deterministic() {
        let hasher = &mut blake3::Blake3::default();
        let key = recoverable::PrivateKey::random(test_rng());
        let pk = key.public_key();

        let a1 = Address::from_public_key(hasher, &pk);
        let a2 = Address::from_public_key(hasher, &pk);
        assert_eq!(a1, a2, "same public key should produce the same address");
    }

    #[test]
    fn account_codec_roundtrip() {
        let account = Account {
            balance: 42,
            nonce: 7,
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
                nonce: 0,
            }
        );
    }
}
