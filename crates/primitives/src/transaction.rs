//! Constantinople transaction type.

use crate::{Address, Sealable, Sealed, Slot};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{Encode, EncodeSize, Error, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher, PublicKey};

/// Declares whether state will be read or written by a transaction.
///
/// This distinction enables finer-grained parallel scheduling: two transactions
/// that both *read* the same slot can execute concurrently, while any write
/// to a slot conflicts with all other accesses to that slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(any(feature = "arbitrary", test), derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum AccessMode {
    /// The transaction will only read state.
    Read = 0,
    /// The transaction will write (and possibly read) state.
    Write = 1,
}

impl Write for AccessMode {
    fn write(&self, buf: &mut impl BufMut) {
        (*self as u8).write(buf);
    }
}

impl FixedSize for AccessMode {
    const SIZE: usize = 1;
}

impl Read for AccessMode {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Read),
            1 => Ok(Self::Write),
            other => Err(Error::InvalidEnum(other)),
        }
    }
}

/// A declared state access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(any(feature = "arbitrary", test), derive(arbitrary::Arbitrary))]
pub enum Access {
    /// Declares account-level access.
    Account(Address, AccessMode),
    /// Declares storage-level access.
    Storage(Address, Slot, AccessMode),
}

impl Write for Access {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Account(address, access) => {
                0u8.write(buf);
                address.write(buf);
                access.write(buf);
            }
            Self::Storage(address, slot, access) => {
                1u8.write(buf);
                address.write(buf);
                slot.write(buf);
                access.write(buf);
            }
        }
    }
}

impl EncodeSize for Access {
    fn encode_size(&self) -> usize {
        match self {
            Self::Account(address, access) => {
                u8::SIZE + address.encode_size() + access.encode_size()
            }
            Self::Storage(address, slot, access) => {
                u8::SIZE + address.encode_size() + slot.encode_size() + access.encode_size()
            }
        }
    }
}

impl Read for Access {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Account(Address::read(buf)?, AccessMode::read(buf)?)),
            1 => Ok(Self::Storage(
                Address::read(buf)?,
                Slot::read(buf)?,
                AccessMode::read(buf)?,
            )),
            other => Err(Error::InvalidEnum(other)),
        }
    }
}

/// A list of accesses declared by a transaction.
///
/// Empty means no explicit accesses were declared.
pub type AccessList = Vec<Access>;

/// Codec configuration for decoding a [`Transaction`].
#[derive(Clone, Debug)]
pub struct TransactionCfg {
    /// Maximum size of the transaction input bytes.
    pub max_input_size: RangeCfg<usize>,
}

impl Default for TransactionCfg {
    fn default() -> Self {
        Self {
            max_input_size: RangeCfg::new(0..=usize::MAX),
        }
    }
}

/// A transaction on the Constantinople blockchain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Transaction<D: Digest, P: PublicKey> {
    /// The sender public key.
    pub sender: P,
    /// The recipient address.
    pub to: Address,
    /// The input data for the transaction.
    pub input: Bytes,
    /// The value to send with the transaction.
    pub value: u64,
    /// The sender nonce.
    pub nonce: u64,
    /// The digest type.
    pub _digest: core::marker::PhantomData<D>,
}

impl<D: Digest, P: PublicKey> Transaction<D, P> {
    /// Hashes the consensus-encoded transaction to produce a [`Digest`].
    ///
    /// If you want to cache the hash, consider using the [`Sealable`] trait.
    ///
    /// [`Digest`]: Digest
    pub fn hash_slow<H: Hasher>(&self, hasher: &mut H) -> H::Digest {
        // Ensure the hasher is reset before use.
        hasher.reset();

        let encoded = self.encode();
        hasher.update(&encoded);

        hasher.finalize()
    }
}

impl<D: Digest, P: PublicKey> Write for Transaction<D, P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.sender.write(buf);
        self.to.write(buf);
        self.input.write(buf);
        self.value.write(buf);
        self.nonce.write(buf);
    }
}

impl<D: Digest, P: PublicKey> EncodeSize for Transaction<D, P> {
    fn encode_size(&self) -> usize {
        self.sender.encode_size()
            + self.to.encode_size()
            + self.input.encode_size()
            + self.value.encode_size()
            + self.nonce.encode_size()
    }
}

impl<D: Digest, P: PublicKey> Read for Transaction<D, P> {
    type Cfg = TransactionCfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            sender: P::read(buf)?,
            to: Address::read(buf)?,
            input: Bytes::read_cfg(buf, &cfg.max_input_size)?,
            value: u64::read(buf)?,
            nonce: u64::read(buf)?,
            _digest: core::marker::PhantomData,
        })
    }
}

impl<D: Digest, P: PublicKey> Sealable for Transaction<D, P> {
    type SealDigest = D;

    fn seal<H: Hasher<Digest = Self::SealDigest>>(self, hasher: &mut H) -> Sealed<Self, H> {
        let seal = self.hash_slow(hasher);

        Sealed::new_unchecked(self, seal)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<D: Digest, P> arbitrary::Arbitrary<'_> for Transaction<D, P>
where
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            sender: u.arbitrary()?,
            to: u.arbitrary()?,
            input: Bytes::from(<Vec<u8> as arbitrary::Arbitrary>::arbitrary(u)?),
            value: u.arbitrary()?,
            nonce: u.arbitrary()?,
            _digest: core::marker::PhantomData,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use arbitrary::{Arbitrary, unstructured::Unstructured};
    use commonware_codec::Decode;
    use commonware_cryptography::{Signer, blake3, ed25519};
    use commonware_math::algebra::Random;
    use rand::{SeedableRng, rngs::StdRng};

    fn test_sender() -> ed25519::PublicKey {
        let mut rng = StdRng::from_seed([7u8; 32]);
        ed25519::PrivateKey::random(&mut rng).public_key()
    }

    #[test]
    fn test_roundtrip_transaction_consensus() {
        let reference_tx: Transaction<blake3::Digest, ed25519::PublicKey> =
            Transaction::arbitrary(&mut Unstructured::new(&[])).unwrap();

        let mut encoded = Vec::with_capacity(reference_tx.encode_size());
        reference_tx.write(&mut encoded);

        let decoded = Transaction::<blake3::Digest, ed25519::PublicKey>::decode_cfg(
            &mut &encoded[..],
            &TransactionCfg::default(),
        )
        .expect("decoding should succeed");

        assert_eq!(
            decoded, reference_tx,
            "Decoded transaction should match the original"
        );
    }

    #[test]
    fn transaction_hash_slow_deterministic() {
        let tx: Transaction<blake3::Digest, ed25519::PublicKey> =
            Transaction::arbitrary(&mut Unstructured::new(&[])).unwrap();
        let hasher = &mut blake3::Blake3::default();

        let h1 = tx.hash_slow(hasher);
        let h2 = tx.hash_slow(hasher);
        assert_eq!(h1, h2, "hash_slow should be deterministic");
    }

    #[test]
    fn transaction_seal_matches_hash_slow() {
        use crate::Sealable;

        let tx: Transaction<blake3::Digest, ed25519::PublicKey> =
            Transaction::arbitrary(&mut Unstructured::new(&[])).unwrap();
        let hasher = &mut blake3::Blake3::default();

        let expected = tx.hash_slow(hasher);
        let sealed = tx.seal(hasher);
        assert_eq!(*sealed.seal(), expected);
    }

    #[test]
    fn transaction_with_input_data_roundtrip() {
        let tx = Transaction::<blake3::Digest, ed25519::PublicKey> {
            sender: test_sender(),
            to: Address::EMPTY,
            input: Bytes::from_static(b"hello world"),
            value: 12345,
            nonce: 1,
            _digest: core::marker::PhantomData,
        };

        let mut buf = Vec::with_capacity(tx.encode_size());
        tx.write(&mut buf);

        let decoded = Transaction::<blake3::Digest, ed25519::PublicKey>::decode_cfg(
            &mut &buf[..],
            &TransactionCfg::default(),
        )
        .expect("decoding should succeed");
        assert_eq!(decoded, tx);
    }

    #[test]
    fn transaction_encode_size_matches_written() {
        let tx = Transaction::<blake3::Digest, ed25519::PublicKey> {
            sender: test_sender(),
            to: Address::arbitrary(&mut Unstructured::new(&[0xCC; 64])).unwrap(),
            input: Bytes::from_static(b"some payload"),
            value: u64::MAX,
            nonce: u64::MAX,
            _digest: core::marker::PhantomData,
        };

        let expected = tx.encode_size();
        let mut buf = Vec::new();
        tx.write(&mut buf);
        assert_eq!(buf.len(), expected);
    }
}
