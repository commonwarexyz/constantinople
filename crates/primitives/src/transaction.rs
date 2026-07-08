//! Constantinople transaction type and transaction wrappers.

use crate::{AccountKey, Sealable, Sealed, TransactionPublicKey, TransactionSignature};
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error, FixedSize, Read, ReadExt, Write, types::lazy::Lazy,
};
use commonware_cryptography::{Digest, Hasher, Signer};
use core::num::NonZeroU64;

/// A signed transaction accepted by the canonical block format.
#[derive(Debug, Clone)]
pub struct SignedTransaction<H>
where
    H: Hasher,
{
    inner: Sealed<Transaction<H::Digest>, H>,
    signature: TransactionSignature,
}

impl<H> PartialEq for SignedTransaction<H>
where
    H: Hasher,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.signature == other.signature
    }
}

impl<H> Eq for SignedTransaction<H> where H: Hasher {}

/// A signed transaction whose signature has been accepted by the caller.
pub type VerifiedTransaction<H> = SignedTransaction<H>;

impl<H> SignedTransaction<H>
where
    H: Hasher,
{
    /// Creates a signed transaction without checking the signature.
    pub const fn new_unchecked(
        inner: Sealed<Transaction<H::Digest>, H>,
        signature: TransactionSignature,
    ) -> Self {
        Self { inner, signature }
    }

    /// Returns the inner sealed transaction.
    pub fn into_inner(self) -> Sealed<Transaction<H::Digest>, H> {
        self.inner
    }

    /// Returns a reference to the inner sealed transaction.
    pub const fn inner(&self) -> &Sealed<Transaction<H::Digest>, H> {
        &self.inner
    }

    /// Returns a reference to the transaction.
    pub fn value(&self) -> &Transaction<H::Digest> {
        self.inner()
    }

    /// Returns the transaction digest that was signed.
    pub const fn message_digest(&self) -> &H::Digest {
        self.inner.seal()
    }

    /// Returns the decoded transaction signature.
    pub const fn signature(&self) -> &TransactionSignature {
        &self.signature
    }
}

impl<H> Write for SignedTransaction<H>
where
    H: Hasher,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.inner.write(buf);
        self.signature.write(buf);
    }
}

impl<H> EncodeSize for SignedTransaction<H>
where
    H: Hasher,
{
    fn encode_size(&self) -> usize {
        self.inner.encode_size() + self.signature.encode_size()
    }
}

// Encoding borrowed transactions lets collections like `Vec<&SignedTransaction>`
// encode without cloning each transaction first.
impl<H> Write for &SignedTransaction<H>
where
    H: Hasher,
{
    fn write(&self, buf: &mut impl BufMut) {
        (**self).write(buf);
    }
}

impl<H> EncodeSize for &SignedTransaction<H>
where
    H: Hasher,
{
    fn encode_size(&self) -> usize {
        (**self).encode_size()
    }
}

impl<H> Read for SignedTransaction<H>
where
    H: Hasher,
{
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let inner = Sealed::<Transaction<H::Digest>, H>::read(buf)?;
        let signature = TransactionSignature::read(buf)?;
        Ok(Self { inner, signature })
    }
}

/// A transaction on the Constantinople blockchain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Transaction<D: Digest> {
    /// The sender public key, decoded lazily on demand.
    pub sender: Lazy<TransactionPublicKey>,
    /// The recipient account key.
    pub to: AccountKey,
    /// The value to send with the transaction.
    pub value: NonZeroU64,
    /// The sender nonce.
    pub nonce: u64,
    /// The digest type.
    pub _digest: core::marker::PhantomData<D>,
}

impl<D: Digest> Transaction<D> {
    /// Creates a new transaction.
    pub fn new(
        sender: TransactionPublicKey,
        to: TransactionPublicKey,
        value: NonZeroU64,
        nonce: u64,
    ) -> Self {
        Self {
            sender: Lazy::new(sender),
            to: AccountKey::from_public_key(&to),
            value,
            nonce,
            _digest: core::marker::PhantomData,
        }
    }

    /// Returns the decoded sender public key.
    pub fn sender(&self) -> Option<&TransactionPublicKey> {
        self.sender.get()
    }

    /// Returns the lazily decoded sender public key.
    pub const fn sender_lazy(&self) -> &Lazy<TransactionPublicKey> {
        &self.sender
    }

    /// Hashes the consensus-encoded transaction to produce a [`Digest`].
    ///
    /// If you want to cache the hash, consider using the [`Sealable`] trait.
    ///
    /// [`Digest`]: Digest
    pub fn hash_slow<H: Hasher>(&self, hasher: &mut H) -> H::Digest {
        hasher.update(&self.encode());
        hasher.finalize()
    }

    /// Seals and signs this transaction with a supported transaction signer.
    pub fn seal_and_sign<H, S>(
        self,
        signer: &S,
        namespace: &[u8],
        hasher: &mut H,
    ) -> SignedTransaction<H>
    where
        H: Hasher<Digest = D>,
        S: Signer,
        TransactionSignature: From<S::Signature>,
    {
        let sealed = self.seal(hasher);
        let signature = TransactionSignature::from(signer.sign(namespace, sealed.seal().as_ref()));
        SignedTransaction::new_unchecked(sealed, signature)
    }
}

impl<D: Digest> Write for Transaction<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.sender.write(buf);
        self.to.write(buf);
        self.value.get().write(buf);
        self.nonce.write(buf);
    }
}

impl<D: Digest> FixedSize for Transaction<D> {
    const SIZE: usize = TransactionPublicKey::SIZE + AccountKey::SIZE + u64::SIZE + u64::SIZE;
}

impl<D: Digest> Read for Transaction<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let sender = Lazy::<TransactionPublicKey>::read(buf)?;
        let to = AccountKey::read(buf)?;
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

impl<D: Digest> Sealable for Transaction<D> {
    type SealDigest = D;

    fn seal<H: Hasher<Digest = Self::SealDigest>>(self, hasher: &mut H) -> Sealed<Self, H> {
        let seal = self.hash_slow(hasher);
        Sealed::new_unchecked(self, seal)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<D: Digest> arbitrary::Arbitrary<'_> for Transaction<D> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let sender = commonware_cryptography::ed25519::PublicKey::arbitrary(u)?;
        let to = commonware_cryptography::ed25519::PublicKey::arbitrary(u)?;
        Ok(Self {
            sender: Lazy::new(TransactionPublicKey::ed25519(sender)),
            to: AccountKey::from_public_key(&TransactionPublicKey::ed25519(to)),
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
    use crate::Sealable;
    use arbitrary::{Arbitrary, unstructured::Unstructured};
    use commonware_codec::{DecodeExt, EncodeSize};
    use commonware_cryptography::{Signer, ed25519, sha256};
    use commonware_math::algebra::Random;
    use core::num::NonZeroU64;
    use rand::{SeedableRng, rngs::StdRng};

    fn test_sender() -> TransactionPublicKey {
        let mut rng = StdRng::from_seed([7u8; 32]);
        TransactionPublicKey::ed25519(ed25519::PrivateKey::random(&mut rng).public_key())
    }

    #[test]
    fn test_roundtrip_transaction_consensus() {
        let reference_tx: Transaction<sha256::Digest> =
            Transaction::arbitrary(&mut Unstructured::new(&[])).unwrap();

        let mut encoded = Vec::with_capacity(reference_tx.encode_size());
        reference_tx.write(&mut encoded);

        let decoded = Transaction::<sha256::Digest>::decode(&mut &encoded[..])
            .expect("decoding should succeed");

        assert_eq!(
            decoded, reference_tx,
            "Decoded transaction should match the original"
        );
    }

    #[test]
    fn transaction_hash_slow_deterministic() {
        let tx: Transaction<sha256::Digest> =
            Transaction::arbitrary(&mut Unstructured::new(&[])).unwrap();
        let hasher = &mut sha256::Sha256::default();

        let h1 = tx.hash_slow(hasher);
        let h2 = tx.hash_slow(hasher);
        assert_eq!(h1, h2, "hash_slow should be deterministic");
    }

    #[test]
    fn transaction_seal_matches_hash_slow() {
        let tx: Transaction<sha256::Digest> =
            Transaction::arbitrary(&mut Unstructured::new(&[])).unwrap();
        let hasher = &mut sha256::Sha256::default();

        let expected = tx.hash_slow(hasher);
        let sealed = tx.seal(hasher);
        assert_eq!(*sealed.seal(), expected);
    }

    #[test]
    fn transaction_roundtrip() {
        let tx = Transaction::<sha256::Digest>::new(
            test_sender(),
            test_sender(),
            NonZeroU64::new(12_345).expect("test value should be non-zero"),
            1,
        );

        let mut buf = Vec::with_capacity(tx.encode_size());
        tx.write(&mut buf);

        let decoded =
            Transaction::<sha256::Digest>::decode(&mut &buf[..]).expect("decoding should succeed");
        assert_eq!(decoded, tx);
    }

    #[test]
    fn transaction_encode_size_matches_written() {
        let tx = Transaction::<sha256::Digest>::new(
            test_sender(),
            test_sender(),
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
        let tx = Transaction::<sha256::Digest>::new(
            sender.clone(),
            test_sender(),
            NonZeroU64::new(1).expect("test value should be non-zero"),
            7,
        );

        let mut buf = Vec::new();
        sender.write(&mut buf);
        tx.to.write(&mut buf);
        0u64.write(&mut buf);
        tx.nonce.write(&mut buf);

        let result = Transaction::<sha256::Digest>::decode(&mut &buf[..]);
        assert!(result.is_err(), "zero-value transactions must be rejected");
    }

    #[test]
    fn transaction_decode_defers_sender_validation() {
        let invalid_sender = (0u8..=u8::MAX)
            .flat_map(|first| (0u8..=u8::MAX).map(move |last| (first, last)))
            .find_map(|(first, last)| {
                let mut candidate = [0; TransactionPublicKey::SIZE];
                candidate[0] = 0;
                candidate[1] = first;
                candidate[TransactionPublicKey::SIZE - 1] = last;

                TransactionPublicKey::decode(&mut &candidate[..])
                    .is_err()
                    .then_some(candidate)
            })
            .expect("test should find invalid sender bytes");

        let mut buf = Vec::new();
        invalid_sender.write(&mut buf);
        AccountKey::from_public_key(&test_sender()).write(&mut buf);
        1u64.write(&mut buf);
        9u64.write(&mut buf);

        let decoded = Transaction::<sha256::Digest>::decode(&mut &buf[..])
            .expect("decoding should defer sender validation");

        assert!(decoded.sender().is_none());
    }
}
