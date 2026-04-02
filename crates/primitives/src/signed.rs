//! Signed value containers.
//!
//! This module builds on the [`Sealed`] wrapper to add cryptographic
//! signatures:
//!
//! - [`Signed`] — A [`Sealed`] value with an attached signature over its seal.
//! - [`Verified`] — A [`Signed`] value whose signature has already been verified.
//! - [`Signable`] — A convenience trait for types that are [`Sealable`],
//!   providing a one-step `seal_and_sign` method.

use crate::{Address, Sealable, Sealed, Transaction};
use commonware_codec::{EncodeSize, Error, Read, Write};
use commonware_cryptography::{Digest, Hasher, PublicKey, Signature, Signer, Verifier};

/// A [`Sealed`] object with an attached signature over its seal.
#[derive(Debug, Clone)]
pub struct Signed<T, H, Sig>
where
    H: Hasher,
    Sig: Signature,
{
    inner: Sealed<T, H>,
    signature: Sig,
}

impl<T, H, Sig> PartialEq for Signed<T, H, Sig>
where
    T: PartialEq,
    H: Hasher,
    Sig: Signature,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.signature == other.signature
    }
}

impl<T, H, Sig> Eq for Signed<T, H, Sig>
where
    T: Eq,
    H: Hasher,
    Sig: Signature,
{
}

impl<T, H, Sig> Signed<T, H, Sig>
where
    H: Hasher,
    Sig: Signature,
{
    /// Creates a new [`Signed`] instance by signing the seal of `inner`.
    pub fn new(
        inner: Sealed<T, H>,
        namespace: &[u8],
        signer: &impl Signer<Signature = Sig>,
    ) -> Self {
        let signature = signer.sign(namespace, inner.seal().as_ref());
        Self { inner, signature }
    }

    /// Creates a new [`Signed`] instance with the given sealed value and signature.
    ///
    /// The caller must ensure `signature` is a valid signature over `inner.seal()`.
    pub const fn new_unchecked(inner: Sealed<T, H>, signature: Sig) -> Self {
        Self { inner, signature }
    }

    /// Returns the inner sealed value.
    pub fn into_inner(self) -> Sealed<T, H> {
        self.inner
    }

    /// Returns a reference to the inner sealed value.
    pub const fn inner(&self) -> &Sealed<T, H> {
        &self.inner
    }

    /// Returns a reference to the innermost value.
    pub fn value(&self) -> &T {
        self.inner()
    }

    /// Returns the message digest of the inner value.
    pub const fn message_digest(&self) -> &H::Digest {
        self.inner.seal()
    }

    /// Returns a reference to the signature.
    pub const fn signature(&self) -> &Sig {
        &self.signature
    }

    /// Verifies the signature against `public_key`.
    pub fn verify<P>(&self, namespace: &[u8], public_key: &P) -> bool
    where
        P: PublicKey + Verifier<Signature = Sig>,
    {
        public_key.verify(namespace, self.message_digest().as_ref(), self.signature())
    }
}

/// A [`Signed`] value whose signature has been verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified<T, H, Sig>
where
    H: Hasher,
    Sig: Signature,
{
    inner: Signed<T, H, Sig>,
    signer: Address,
}

type VerifiedSignedTransaction<D, P, H> =
    Verified<Transaction<D, P>, H, <P as Verifier>::Signature>;

impl<D, P, H> Signed<Transaction<D, P>, H, <P as Verifier>::Signature>
where
    D: Digest,
    P: PublicKey,
    H: Hasher,
{
    /// Consumes the signed transaction and returns an owned verified wrapper.
    pub fn into_verified(
        self,
        namespace: &[u8],
    ) -> Result<VerifiedSignedTransaction<D, P, H>, Self> {
        if !self.verify(namespace, &self.value().sender) {
            return Err(self);
        }

        Ok(self.into())
    }
}

impl<D, P> Transaction<D, P>
where
    D: Digest,
    P: PublicKey,
{
    /// Seals and signs a locally constructed transaction and returns it as verified.
    ///
    /// This is intended for trusted local construction paths. It asserts that the
    /// embedded sender matches the provided signer's public key, signs the
    /// transaction once, and caches the sender address without re-verifying the
    /// signature that was just produced.
    pub fn seal_and_sign_verified<H, S>(
        self,
        signer: &S,
        namespace: &[u8],
        hasher: &mut H,
    ) -> Verified<Self, H, P::Signature>
    where
        H: Hasher<Digest = D>,
        S: Signer<PublicKey = P, Signature = <P as Verifier>::Signature>,
    {
        let signer_public_key = signer.public_key();
        assert!(
            self.sender == signer_public_key,
            "transaction sender must match signer public key",
        );

        let signed = Signed::new(self.seal(hasher), namespace, signer);
        signed.into()
    }
}

impl<T, H, Sig> Verified<T, H, Sig>
where
    H: Hasher,
    Sig: Signature,
{
    /// Returns the underlying signed value.
    pub const fn inner(&self) -> &Signed<T, H, Sig> {
        &self.inner
    }

    /// Consumes the wrapper and returns the signed value.
    pub fn into_inner(self) -> Signed<T, H, Sig> {
        self.inner
    }

    /// Returns the verified signer's cached address.
    pub const fn signer(&self) -> Address {
        self.signer
    }

    /// Returns a reference to the innermost value.
    pub fn value(&self) -> &T {
        self.inner.value()
    }

    /// Returns the message digest of the inner value.
    pub const fn message_digest(&self) -> &H::Digest {
        self.inner.message_digest()
    }

    /// Returns a reference to the signature.
    pub const fn signature(&self) -> &Sig {
        self.inner.signature()
    }
}

impl<T, H, Sig> Write for Verified<T, H, Sig>
where
    T: Write,
    H: Hasher,
    Sig: Signature,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.inner.write(buf);
    }
}

impl<T, H, Sig> EncodeSize for Verified<T, H, Sig>
where
    T: EncodeSize,
    H: Hasher,
    Sig: Signature,
{
    fn encode_size(&self) -> usize {
        self.inner.encode_size()
    }
}

impl<T, H, Sig> Write for Signed<T, H, Sig>
where
    T: Write,
    H: Hasher,
    Sig: Signature,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.inner.write(buf);
        self.signature.write(buf);
    }
}

impl<T, H, Sig> EncodeSize for Signed<T, H, Sig>
where
    T: EncodeSize,
    H: Hasher,
    Sig: Signature,
{
    fn encode_size(&self) -> usize {
        self.inner.encode_size() + self.signature.encode_size()
    }
}

impl<T, H, Sig> Read for Signed<T, H, Sig>
where
    T: Read + Sealable<SealDigest = H::Digest>,
    H: Hasher,
    Sig: Signature,
{
    type Cfg = <T as Read>::Cfg;

    fn read_cfg(buf: &mut impl bytes::Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let inner = Sealed::<T, H>::read_cfg(buf, cfg)?;
        let signature = Sig::read(buf)?;
        Ok(Self::new_unchecked(inner, signature))
    }
}

#[cfg(any(feature = "arbitrary", test))]
impl<'a, T, H, Sig> arbitrary::Arbitrary<'a> for Signed<T, H, Sig>
where
    T: arbitrary::Arbitrary<'a> + Sealable<SealDigest = H::Digest>,
    H: Hasher,
    Sig: Signature + arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            inner: u.arbitrary::<T>()?.seal(&mut H::new()),
            signature: u.arbitrary()?,
        })
    }
}

/// A type that can be sealed and signed.
pub trait Signable: Sealable {
    /// Seals and signs the value.
    fn seal_and_sign<H, S>(
        self,
        signer: &S,
        namespace: &[u8],
        hasher: &mut H,
    ) -> Signed<Self, H, S::Signature>
    where
        H: Hasher<Digest = Self::SealDigest>,
        S: Signer,
        Self: Sized,
    {
        let sealed = self.seal(hasher);
        Signed::new(sealed, namespace, signer)
    }
}

impl<T: Sealable> Signable for T {}

impl<D, P, H> From<Signed<Transaction<D, P>, H, P::Signature>>
    for Verified<Transaction<D, P>, H, P::Signature>
where
    D: Digest,
    P: PublicKey,
    H: Hasher,
{
    fn from(signed: Signed<Transaction<D, P>, H, P::Signature>) -> Self {
        let mut hasher = H::default();
        let signer = Address::from_public_key(&mut hasher, &signed.value().sender);
        Self {
            inner: signed,
            signer,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{Address, Sealable, Sealed, Transaction, signed::Signable};
    use commonware_cryptography::{
        Digest, Hasher, Signer, Verifier, blake3, ed25519, secp256r1::recoverable,
    };
    use commonware_math::algebra::Random;
    use core::num::NonZeroU64;
    use rand::rngs::OsRng;

    const NAMESPACE: &[u8] = b"test namespace";

    #[derive(Debug)]
    struct MockValue([u8; 4]);

    impl Sealable for MockValue {
        type SealDigest = blake3::Digest;

        fn seal<H: Hasher<Digest = Self::SealDigest>>(
            self,
            hasher: &mut H,
        ) -> crate::Sealed<Self, H> {
            hasher.update(&self.0);
            Sealed::new_unchecked(self, hasher.finalize())
        }
    }

    #[test]
    fn signed_verify_works_for_ed25519() {
        let hasher = &mut blake3::Blake3::default();
        let private_key = ed25519::PrivateKey::random(&mut OsRng);
        let signed = MockValue([1, 2, 3, 4]).seal_and_sign(&private_key, NAMESPACE, hasher);

        assert!(signed.verify(NAMESPACE, &private_key.public_key()));
    }

    #[test]
    fn signed_verify_works_for_secp256r1() {
        let hasher = &mut blake3::Blake3::default();
        let private_key = recoverable::PrivateKey::random(&mut OsRng);
        let signed = MockValue([5, 6, 7, 8]).seal_and_sign(&private_key, NAMESPACE, hasher);

        assert!(signed.verify(NAMESPACE, &private_key.public_key()));
    }

    #[test]
    fn signed_into_inner_returns_sealed() {
        let hasher = &mut blake3::Blake3::default();
        let private_key = ed25519::PrivateKey::random(&mut OsRng);
        let signed = MockValue([9, 10, 11, 12]).seal_and_sign(&private_key, NAMESPACE, hasher);

        let seal = *signed.message_digest();
        let sealed = signed.into_inner();

        assert_eq!(*sealed.seal(), seal);
        assert_eq!(sealed.0, [9, 10, 11, 12]);
    }

    #[test]
    fn wrong_namespace_fails_verification() {
        let hasher = &mut blake3::Blake3::default();
        let private_key = ed25519::PrivateKey::random(&mut OsRng);
        let signed = MockValue([1, 2, 3, 4]).seal_and_sign(&private_key, NAMESPACE, hasher);

        assert!(!signed.verify(b"wrong namespace", &private_key.public_key()));
        assert!(private_key.public_key().verify(
            NAMESPACE,
            signed.message_digest().as_ref(),
            signed.signature()
        ));
    }

    #[test]
    fn verified_caches_signer_address() {
        let hasher = &mut blake3::Blake3::default();
        let private_key = ed25519::PrivateKey::random(&mut OsRng);
        let public_key = private_key.public_key();
        let verified = Transaction {
            sender: public_key.clone(),
            to: Address::EMPTY,
            value: NonZeroU64::new(1).expect("test value should be non-zero"),
            nonce: 0,
            _digest: core::marker::PhantomData::<blake3::Digest>,
        }
        .seal_and_sign_verified(&private_key, NAMESPACE, hasher);

        let expected = Address::from_public_key(&mut blake3::Blake3::default(), &public_key);
        assert_eq!(verified.signer(), expected);
        assert!(verified.inner().verify(NAMESPACE, &verified.value().sender));
    }

    #[test]
    #[should_panic(expected = "transaction sender must match signer public key")]
    fn seal_and_sign_verified_rejects_mismatched_sender() {
        let hasher = &mut blake3::Blake3::default();
        let private_key = ed25519::PrivateKey::random(&mut OsRng);
        let wrong_key = ed25519::PrivateKey::random(&mut OsRng);

        let _ = Transaction {
            sender: wrong_key.public_key(),
            to: Address::EMPTY,
            value: NonZeroU64::new(1).expect("test value should be non-zero"),
            nonce: 0,
            _digest: core::marker::PhantomData::<blake3::Digest>,
        }
        .seal_and_sign_verified(&private_key, NAMESPACE, hasher);
    }
}
