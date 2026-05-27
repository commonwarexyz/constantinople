//! Account model for the Constantinople chain.

use crate::TransactionPublicKey;
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_formatting::hex;
use commonware_utils::{Array, Span};
use core::ops::Deref;
use derive_more::{Debug, Display};

/// Default starting balance for accounts that have not been written yet.
pub const DEFAULT_ACCOUNT_BALANCE: u64 = 100;

/// Raw public-key bytes used as an account key.
///
/// Unlike [`PublicKey`] implementations, decoding an [`AccountKey`] does not
/// validate or decompress the curve point. This keeps state-database replay,
/// indexing, and lookup on cheap byte comparisons while preserving the public
/// key's canonical wire representation as the account identifier.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountKey {
    bytes: Bytes,
}

impl AccountKey {
    /// Creates an account key from a decoded public key.
    pub fn from_public_key(public_key: &TransactionPublicKey) -> Self {
        Self {
            bytes: Bytes::copy_from_slice(public_key.as_ref()),
        }
    }

    /// Creates an account key from canonical public-key bytes.
    pub fn from_bytes(bytes: Bytes) -> Option<Self> {
        if bytes.len() != TransactionPublicKey::SIZE {
            return None;
        }

        Some(Self { bytes })
    }
}

impl FixedSize for AccountKey {
    const SIZE: usize = TransactionPublicKey::SIZE;
}

impl Write for AccountKey {
    fn write(&self, buf: &mut impl BufMut) {
        debug_assert_eq!(self.bytes.len(), Self::SIZE);
        buf.put_slice(&self.bytes);
    }
}

impl Read for AccountKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        if buf.remaining() < Self::SIZE {
            return Err(CodecError::EndOfBuffer);
        }

        Ok(Self {
            bytes: buf.copy_to_bytes(Self::SIZE),
        })
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
    use commonware_cryptography::{Signer, ed25519};

    #[test]
    fn account_key_roundtrip_does_not_validate_public_key() {
        let mut raw = vec![0u8; TransactionPublicKey::SIZE];
        raw[0] = 1;

        let key = AccountKey::decode(&mut &raw[..]).expect("account keys are raw public-key bytes");

        assert_eq!(key.as_ref(), raw.as_slice());
    }

    #[test]
    fn account_key_from_public_key_uses_public_key_bytes() {
        let private_key = ed25519::PrivateKey::from_seed(1);
        let public_key = TransactionPublicKey::ed25519(private_key.public_key());

        let key = AccountKey::from_public_key(&public_key);

        assert_eq!(key.as_ref(), public_key.as_ref());
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
