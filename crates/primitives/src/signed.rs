//! Signed value containers.
//!
//! This module builds on the [`Sealed`] wrapper to add cryptographic
//! signatures:
//!
//! - [`Signed`] — A [`Sealed`] value with an attached signature over its seal.
//! - [`Signable`] — A convenience trait for types that are [`Sealable`],
//!   providing a one-step `seal_and_sign` method.

use crate::{Sealable, Sealed, SignedTransaction};
use commonware_codec::{Error, FixedSize, Read, ReadExt, Write, types::lazy::Lazy};
use commonware_cryptography::{BatchVerifier, Hasher, PublicKey, Signature, Signer, Verifier};
use commonware_parallel::Strategy;
use rand::{SeedableRng, rngs::StdRng};
use rand_core::CryptoRngCore;

/// A [`Sealed`] object with an attached signature over its seal.
#[derive(Debug, Clone)]
pub struct Signed<T, H, Sig>
where
    H: Hasher,
    Sig: Signature,
{
    inner: Sealed<T, H>,
    signature: Lazy<Sig>,
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
        Self {
            inner,
            signature: Lazy::new(signature),
        }
    }

    /// Creates a new [`Signed`] instance with the given sealed value and signature.
    ///
    /// The caller must ensure `signature` is a valid signature over `inner.seal()`.
    pub fn new_unchecked(inner: Sealed<T, H>, signature: Sig) -> Self {
        Self {
            inner,
            signature: Lazy::new(signature),
        }
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

    /// Returns the lazily decoded signature.
    pub const fn signature_lazy(&self) -> &Lazy<Sig> {
        &self.signature
    }

    /// Returns the decoded signature.
    pub fn signature(&self) -> Option<&Sig> {
        self.signature.get()
    }

    /// Verifies the signature against `public_key`.
    pub fn verify<P>(&self, namespace: &[u8], public_key: &P) -> bool
    where
        P: PublicKey + Verifier<Signature = Sig>,
    {
        let Some(signature) = self.signature() else {
            return false;
        };

        public_key.verify(namespace, self.message_digest().as_ref(), signature)
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

impl<T, H, Sig> FixedSize for Signed<T, H, Sig>
where
    T: FixedSize,
    H: Hasher,
    Sig: Signature,
{
    const SIZE: usize = T::SIZE + Sig::SIZE;
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
        let signature = Lazy::<Sig>::read(buf)?;
        Ok(Self { inner, signature })
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
            signature: Lazy::new(u.arbitrary()?),
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

/// Materializes lazily-encoded signed transactions in parallel.
///
/// Returns `None` if any transaction fails to decode.
pub fn materialize_transaction_chunks<P, H, St>(
    strategy: &St,
    transactions: Vec<Lazy<SignedTransaction<P, H>>>,
) -> Option<Vec<SignedTransaction<P, H>>>
where
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    if transactions.is_empty() {
        return Some(Vec::new());
    }

    let parallelism = strategy.parallelism_hint();
    if parallelism <= 1 || transactions.len() <= parallelism {
        return transactions
            .into_iter()
            .map(|lazy| lazy.get().cloned())
            .collect();
    }

    strategy
        .map_collect_vec(transactions, |lazy| lazy.get().cloned())
        .into_iter()
        .collect()
}

/// Forces lazily encoded signed transactions to decode in parallel.
///
/// Returns the original lazy transactions after warming their cached decoded
/// values, or `None` if any transaction fails to decode.
pub fn preload_transaction_chunks<P, H, St>(
    strategy: &St,
    transactions: Vec<Lazy<SignedTransaction<P, H>>>,
) -> Option<Vec<Lazy<SignedTransaction<P, H>>>>
where
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    if transactions.is_empty() {
        return Some(Vec::new());
    }

    let parallelism = strategy.parallelism_hint();
    if parallelism <= 1 || transactions.len() <= parallelism {
        return transactions
            .iter()
            .all(|lazy| lazy.get().is_some())
            .then_some(transactions);
    }

    strategy
        .fold(
            &transactions,
            || true,
            |decoded, lazy| decoded && lazy.get().is_some(),
            |left, right| left && right,
        )
        .then_some(transactions)
}

/// Verifies a slice of lazily-encoded signed transactions using batch
/// verification.
///
/// Calling `.get()` on each [`Lazy`] forces the underlying
/// [`SignedTransaction`] to be decoded and its seal digest computed. When this
/// function runs inside a worker thread (via [`verify_transaction_chunks`])
/// that per-transaction cost is paid on the worker rather than the runtime
/// thread.
///
/// Returns `true` if every transaction decodes and all signatures verify,
/// `false` otherwise.
pub fn verify_transaction_batch<P, H, BV>(
    namespace: &[u8],
    rng: &mut impl CryptoRngCore,
    transactions: &[Lazy<SignedTransaction<P, H>>],
) -> bool
where
    P: PublicKey,
    H: Hasher,
    BV: BatchVerifier<PublicKey = P>,
{
    let mut verifier = BV::new();
    for lazy in transactions {
        // Force materialization on this thread (the chunked caller runs this
        // inside a parallel worker, so decoding + seal hashing is spread
        // across cores).
        let Some(transaction) = lazy.get() else {
            return false;
        };
        let Some(sender) = transaction.value().sender() else {
            return false;
        };
        let Some(signature) = transaction.signature() else {
            return false;
        };
        if !verifier.add(
            namespace,
            transaction.message_digest().as_ref(),
            sender,
            signature,
        ) {
            return false;
        }
    }
    verifier.verify(rng)
}

/// Splits lazily-encoded transactions into chunks, verifies each chunk in
/// parallel using batch signature verification, and returns the decoded
/// transactions in their original order.
///
/// Forcing each [`Lazy`] happens inside the worker, so transaction decoding
/// and seal hashing are performed on the strategy's threads. Returns `None`
/// if any chunk contains an invalid or undecodable transaction.
pub fn verify_transaction_chunks<P, H, BV, St>(
    strategy: &St,
    namespace: &'static [u8],
    rng: &mut impl CryptoRngCore,
    transactions: Vec<Lazy<SignedTransaction<P, H>>>,
) -> Option<Vec<SignedTransaction<P, H>>>
where
    P: PublicKey,
    H: Hasher,
    BV: BatchVerifier<PublicKey = P>,
    St: Strategy,
{
    if transactions.is_empty() {
        return Some(Vec::new());
    }

    let chunk_count = strategy.parallelism_hint().min(transactions.len());
    let chunk_size = transactions.len().div_ceil(chunk_count);

    let mut remaining = transactions;
    let mut chunks = Vec::with_capacity(chunk_count);
    while !remaining.is_empty() {
        let split_at = chunk_size.min(remaining.len());
        let rest = remaining.split_off(split_at);
        let mut rng_seed = [0u8; 32];
        rng.fill_bytes(&mut rng_seed);
        chunks.push((rng_seed, remaining));
        remaining = rest;
    }

    let verified_chunks = strategy.map_collect_vec(chunks, |(rng_seed, chunk)| {
        let mut chunk_rng = StdRng::from_seed(rng_seed);
        if !verify_transaction_batch::<P, H, BV>(namespace, &mut chunk_rng, &chunk) {
            return None;
        }
        // Each lazy was forced during verification above, so unwrapping the
        // materialized value is infallible here.
        let verified: Option<Vec<_>> = chunk.into_iter().map(|lazy| lazy.get().cloned()).collect();
        verified
    });

    let mut verified = Vec::new();
    for chunk in verified_chunks {
        verified.extend(chunk?);
    }
    Some(verified)
}

#[cfg(test)]
mod test {
    use crate::{Sealable, Sealed, Transaction, signed::Signable};
    use commonware_cryptography::{
        Hasher, Signer, Verifier, ed25519, secp256r1::recoverable, sha256,
    };
    use commonware_math::algebra::Random;
    use commonware_utils::test_rng;
    use core::num::NonZeroU64;

    const NAMESPACE: &[u8] = b"test namespace";

    #[derive(Debug)]
    struct MockValue([u8; 4]);

    impl Sealable for MockValue {
        type SealDigest = sha256::Digest;

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
        let hasher = &mut sha256::Sha256::default();
        let private_key = ed25519::PrivateKey::random(&mut test_rng());
        let signed = MockValue([1, 2, 3, 4]).seal_and_sign(&private_key, NAMESPACE, hasher);

        assert!(signed.verify(NAMESPACE, &private_key.public_key()));
    }

    #[test]
    fn signed_verify_works_for_secp256r1() {
        let hasher = &mut sha256::Sha256::default();
        let private_key = recoverable::PrivateKey::random(&mut test_rng());
        let signed = MockValue([5, 6, 7, 8]).seal_and_sign(&private_key, NAMESPACE, hasher);

        assert!(signed.verify(NAMESPACE, &private_key.public_key()));
    }

    #[test]
    fn signed_into_inner_returns_sealed() {
        let hasher = &mut sha256::Sha256::default();
        let private_key = ed25519::PrivateKey::random(&mut test_rng());
        let signed = MockValue([9, 10, 11, 12]).seal_and_sign(&private_key, NAMESPACE, hasher);

        let seal = *signed.message_digest();
        let sealed = signed.into_inner();

        assert_eq!(*sealed.seal(), seal);
        assert_eq!(sealed.0, [9, 10, 11, 12]);
    }

    #[test]
    fn wrong_namespace_fails_verification() {
        let hasher = &mut sha256::Sha256::default();
        let private_key = ed25519::PrivateKey::random(&mut test_rng());
        let signed = MockValue([1, 2, 3, 4]).seal_and_sign(&private_key, NAMESPACE, hasher);

        assert!(!signed.verify(b"wrong namespace", &private_key.public_key()));
        assert!(
            private_key.public_key().verify(
                NAMESPACE,
                signed.message_digest().as_ref(),
                signed
                    .signature()
                    .expect("locally created signatures must decode")
            )
        );
    }

    #[test]
    fn signed_transaction_exposes_sender_public_key() {
        let hasher = &mut sha256::Sha256::default();
        let private_key = ed25519::PrivateKey::random(&mut test_rng());
        let public_key = private_key.public_key();
        let signed = Transaction::new(
            public_key.clone(),
            public_key.clone(),
            NonZeroU64::new(1).expect("test value should be non-zero"),
            0,
        )
        .seal_and_sign(&private_key, NAMESPACE, hasher);

        assert_eq!(signed.value().sender(), Some(&public_key));
        assert!(
            signed.verify(
                NAMESPACE,
                signed
                    .value()
                    .sender()
                    .expect("signed sender should decode"),
            )
        );
    }
}
