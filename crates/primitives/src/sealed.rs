//! Hashed value container with a cached seal (digest).
//!
//! This module provides the [`Sealable`] trait for types that can be hashed into
//! a [`Sealed`] wrapper, which caches the computed digest alongside the original value.

use commonware_codec::{EncodeSize, Error, Read, Write};
use commonware_cryptography::{Digest, Digestible, Hasher};
use derive_more::{Debug, Deref};

/// A type that can be hashed and sealed.
pub trait Sealable {
    /// The type of digest used for sealing the value.
    type SealDigest: Digest;

    /// Hashes the value and returns a sealed version of it.
    fn seal<H: Hasher<Digest = Self::SealDigest>>(self, hasher: &mut H) -> Sealed<Self, H>
    where
        Self: Sized;
}

/// A type that has been hashed with a cached digest.
#[derive(Debug, Deref)]
pub struct Sealed<T, H: Hasher> {
    #[deref]
    inner: T,
    seal: H::Digest,
}

impl<T: Clone, H: Hasher> Clone for Sealed<T, H> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            seal: self.seal,
        }
    }
}

/// Finalize a borrowed hasher and install the reset state it returns.
pub(crate) fn finalize_reset<H: Hasher>(hasher: &mut H) -> H::Digest {
    let (reset, digest) = core::mem::take(hasher).finalize();
    *hasher = reset;
    digest
}

impl<T, H> PartialEq for Sealed<T, H>
where
    T: PartialEq,
    H: Hasher,
    H::Digest: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.seal == other.seal
    }
}

impl<T, H> Eq for Sealed<T, H>
where
    T: Eq,
    H: Hasher,
    H::Digest: Eq,
{
}

impl<T, H: Hasher> Sealed<T, H> {
    /// Creates a new `Sealed` instance with the given inner value and seal. Does not
    /// require `T` to be [`Sealable`].
    ///
    /// The caller must ensure `seal` is the correct seal for `inner`. This function
    /// does not check whether the seal matches the inner value's true hash.
    pub const fn new_unchecked(inner: T, seal: H::Digest) -> Self {
        Self { inner, seal }
    }

    /// Returns the inner value.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Returns a reference to the cached seal.
    pub const fn seal(&self) -> &H::Digest {
        &self.seal
    }
}

impl<T, H> Digestible for Sealed<T, H>
where
    T: Clone + Send + Sync + 'static,
    H: Hasher,
{
    type Digest = H::Digest;

    fn digest(&self) -> Self::Digest {
        self.seal
    }
}

impl<T, H> Write for Sealed<T, H>
where
    T: Write,
    H: Hasher,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.inner.write(buf);
    }
}

impl<T, H> EncodeSize for Sealed<T, H>
where
    T: EncodeSize,
    H: Hasher,
{
    fn encode_size(&self) -> usize {
        self.inner.encode_size()
    }
}

impl<T, H> Read for Sealed<T, H>
where
    T: Read + Sealable<SealDigest = H::Digest>,
    H: Hasher,
{
    type Cfg = <T as Read>::Cfg;

    fn read_cfg(buf: &mut impl bytes::Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let inner = T::read_cfg(buf, cfg)?;
        Ok(inner.seal(&mut H::default()))
    }
}

#[cfg(any(feature = "arbitrary", test))]
impl<'a, T, H> arbitrary::Arbitrary<'a> for Sealed<T, H>
where
    T: arbitrary::Arbitrary<'a> + Sealable<SealDigest = H::Digest>,
    H: Hasher,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(u.arbitrary::<T>()?.seal(&mut H::default()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use commonware_cryptography::{Hasher, sha256};
    use commonware_formatting::hex;

    #[derive(core::fmt::Debug, Clone, PartialEq, Eq)]
    #[repr(transparent)]
    struct MockSeal([u8; 8]);

    impl Sealable for MockSeal {
        type SealDigest = sha256::Digest;

        fn seal<H: Hasher<Digest = Self::SealDigest>>(self, hasher: &mut H) -> Sealed<Self, H> {
            hasher.update(&self.0);
            Sealed::new_unchecked(self, finalize_reset(hasher))
        }
    }

    #[test]
    fn test_seal() {
        const EXPECTED: [u8; 32] =
            hex!("5eb36b538cf44d53a2a091d3ef6b4d719e9ee0d3805505e2aaa12803d78babe1");

        let mock = MockSeal(hex!("beefbabe0badc0de"));
        let sealed = mock.seal(&mut sha256::Sha256::default());

        assert_eq!(sealed.seal().as_ref(), EXPECTED);
    }

    #[test]
    fn sealed_deref() {
        let mock = MockSeal([1, 2, 3, 4, 5, 6, 7, 8]);
        let sealed = mock.seal(&mut sha256::Sha256::default());
        assert_eq!(sealed.0, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn sealed_into_inner() {
        let mock = MockSeal([10; 8]);
        let sealed = mock.seal(&mut sha256::Sha256::default());
        let inner = sealed.into_inner();
        assert_eq!(inner.0, [10; 8]);
    }

    #[test]
    fn sealed_clone_eq() {
        let mock = MockSeal([0xAB; 8]);
        let sealed = mock.seal(&mut sha256::Sha256::default());
        let cloned = sealed.clone();
        assert_eq!(sealed, cloned);
    }

    #[test]
    fn different_inputs_produce_different_seals() {
        let a = MockSeal([0x00; 8]).seal(&mut sha256::Sha256::default());
        let b = MockSeal([0xFF; 8]).seal(&mut sha256::Sha256::default());
        assert_ne!(a.seal(), b.seal());
    }
}
