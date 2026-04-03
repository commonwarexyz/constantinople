//! Constantinople transaction type and transaction wrappers.

use crate::{Address, Sealable, Sealed, Signed, Verified};
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error, FixedSize, Read, ReadExt, Write, types::lazy::Lazy,
};
use commonware_cryptography::{Digest, Hasher, PublicKey, Verifier};
use core::num::NonZeroU64;

/// A signed transaction accepted by the canonical block format.
pub type SignedTransaction<P, H> =
    Signed<Transaction<<H as Hasher>::Digest, P>, H, <P as Verifier>::Signature>;

/// A verified transaction paired with its cached sender address.
pub type VerifiedTransaction<P, H> =
    Verified<Transaction<<H as Hasher>::Digest, P>, H, <P as Verifier>::Signature>;

/// A transaction on the Constantinople blockchain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Transaction<D: Digest, P: PublicKey> {
    /// The sender public key, decoded lazily on demand.
    pub sender: Lazy<P>,
    /// The recipient address.
    pub to: Address,
    /// The value to send with the transaction.
    pub value: NonZeroU64,
    /// The sender nonce.
    pub nonce: u64,
    /// The digest type.
    pub _digest: core::marker::PhantomData<D>,
}

impl<D: Digest, P: PublicKey> Transaction<D, P> {
    /// Creates a new transaction.
    pub fn new(sender: P, to: Address, value: NonZeroU64, nonce: u64) -> Self {
        Self {
            sender: Lazy::new(sender),
            to,
            value,
            nonce,
            _digest: core::marker::PhantomData,
        }
    }

    /// Returns the decoded sender public key.
    pub fn sender(&self) -> Option<&P> {
        self.sender.get()
    }

    /// Returns the lazily decoded sender public key.
    pub const fn sender_lazy(&self) -> &Lazy<P> {
        &self.sender
    }

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
        self.value.get().write(buf);
        self.nonce.write(buf);
    }
}

impl<D: Digest, P: PublicKey> EncodeSize for Transaction<D, P> {
    fn encode_size(&self) -> usize {
        self.sender.encode_size() + self.to.encode_size() + u64::SIZE + self.nonce.encode_size()
    }
}

impl<D: Digest, P: PublicKey> Read for Transaction<D, P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let _ = cfg;
        let sender = Lazy::<P>::read(buf)?;
        let to = Address::read(buf)?;
        let value = u64::read(buf)?;
        let value = NonZeroU64::new(value)
            .ok_or(Error::Invalid("Transaction", "value must be non-zero"))?;

        Ok(Self {
            sender,
            to,
            value,
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
            sender: Lazy::new(u.arbitrary()?),
            to: u.arbitrary()?,
            value: NonZeroU64::new(u.int_in_range(1..=u64::MAX)?)
                .expect("arbitrary non-zero value should construct"),
            nonce: u.arbitrary()?,
            _digest: core::marker::PhantomData,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use arbitrary::{Arbitrary, unstructured::Unstructured};
    use commonware_codec::DecodeExt;
    use commonware_cryptography::{Signer, blake3, ed25519};
    use commonware_math::algebra::Random;
    use core::num::NonZeroU64;
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

        let decoded = Transaction::<blake3::Digest, ed25519::PublicKey>::decode(&mut &encoded[..])
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
    fn transaction_roundtrip() {
        let tx = Transaction::<blake3::Digest, ed25519::PublicKey>::new(
            test_sender(),
            Address::EMPTY,
            NonZeroU64::new(12_345).expect("test value should be non-zero"),
            1,
        );

        let mut buf = Vec::with_capacity(tx.encode_size());
        tx.write(&mut buf);

        let decoded = Transaction::<blake3::Digest, ed25519::PublicKey>::decode(&mut &buf[..])
            .expect("decoding should succeed");
        assert_eq!(decoded, tx);
    }

    #[test]
    fn transaction_encode_size_matches_written() {
        let tx = Transaction::<blake3::Digest, ed25519::PublicKey>::new(
            test_sender(),
            Address::arbitrary(&mut Unstructured::new(&[0xCC; 64])).unwrap(),
            NonZeroU64::new(u64::MAX).expect("max value should be non-zero"),
            u64::MAX,
        );

        let expected = tx.encode_size();
        let mut buf = Vec::new();
        tx.write(&mut buf);
        assert_eq!(buf.len(), expected);
    }

    #[test]
    fn transaction_zero_value_decode_is_rejected() {
        let sender = test_sender();
        let tx = Transaction::<blake3::Digest, ed25519::PublicKey>::new(
            sender.clone(),
            Address::EMPTY,
            NonZeroU64::new(1).expect("test value should be non-zero"),
            7,
        );

        let mut buf = Vec::new();
        sender.write(&mut buf);
        tx.to.write(&mut buf);
        0u64.write(&mut buf);
        tx.nonce.write(&mut buf);

        let result = Transaction::<blake3::Digest, ed25519::PublicKey>::decode(&mut &buf[..]);
        assert!(result.is_err(), "zero-value transactions must be rejected");
    }

    #[test]
    fn transaction_decode_defers_sender_validation() {
        let invalid_sender = (0u8..=u8::MAX)
            .flat_map(|first| (0u8..=u8::MAX).map(move |last| (first, last)))
            .find_map(|(first, last)| {
                let mut candidate = [0; ed25519::PublicKey::SIZE];
                candidate[0] = first;
                candidate[ed25519::PublicKey::SIZE - 1] = last;

                ed25519::PublicKey::decode(&mut &candidate[..])
                    .is_err()
                    .then_some(candidate)
            })
            .expect("test should find invalid sender bytes");

        let mut buf = Vec::new();
        invalid_sender.write(&mut buf);
        Address::EMPTY.write(&mut buf);
        1u64.write(&mut buf);
        9u64.write(&mut buf);

        let decoded = Transaction::<blake3::Digest, ed25519::PublicKey>::decode(&mut &buf[..])
            .expect("decoding should defer sender validation");

        assert!(decoded.sender().is_none());
    }
}
