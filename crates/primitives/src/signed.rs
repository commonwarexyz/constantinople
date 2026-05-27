//! Signed value containers.
//!
//! This module builds on the [`Sealed`] wrapper to add cryptographic
//! signatures:
//!
//! - [`Signed`] — A [`Sealed`] value with an attached signature over its seal.
//! - [`Signable`] — A convenience trait for types that are [`Sealable`],
//!   providing a one-step `seal_and_sign` method.

use crate::{Sealable, Sealed, SignedTransaction, TransactionBatchVerifier};
use commonware_codec::{Error, FixedSize, Read, ReadExt, Write, types::lazy::Lazy};
use commonware_cryptography::{BatchVerifier, Hasher, PublicKey, Signature, Signer, Verifier};
use commonware_parallel::Strategy;
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
pub fn materialize_transaction_chunks<H, St>(
    strategy: &St,
    transactions: Vec<Lazy<SignedTransaction<H>>>,
) -> Option<Vec<SignedTransaction<H>>>
where
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
pub fn preload_transaction_chunks<H, St>(
    strategy: &St,
    transactions: Vec<Lazy<SignedTransaction<H>>>,
) -> Option<Vec<Lazy<SignedTransaction<H>>>>
where
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
            .all(signature_inputs_decode)
            .then_some(transactions);
    }

    strategy
        .fold(
            &transactions,
            || true,
            |decoded, lazy| decoded && signature_inputs_decode(lazy),
            |left, right| left && right,
        )
        .then_some(transactions)
}

fn signature_inputs_decode<H>(lazy: &Lazy<SignedTransaction<H>>) -> bool
where
    H: Hasher,
{
    let Some(transaction) = lazy.get() else {
        return false;
    };
    transaction.value().sender().is_some() && transaction.signature().is_some()
}

/// Verifies a slice of lazily-encoded signed transactions using batch
/// verification.
///
/// Calling `.get()` on each [`Lazy`] forces the underlying
/// [`SignedTransaction`] to be decoded and its seal digest computed.
///
/// Returns `true` if every transaction decodes and all signatures verify,
/// `false` otherwise.
pub fn verify_transaction_batch<H, St>(
    signature_strategy: &St,
    namespace: &[u8],
    rng: &mut impl CryptoRngCore,
    transactions: &[Lazy<SignedTransaction<H>>],
) -> bool
where
    H: Hasher,
    St: Strategy,
{
    let mut verifier = TransactionBatchVerifier::new();
    for lazy in transactions {
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
    verifier.verify(rng, signature_strategy)
}

/// Verifies lazily-encoded transactions.
///
/// The hash strategy first forces each [`Lazy`] to decode and compute its seal
/// digest. The signature strategy then runs batch signature verification over
/// the warmed transactions. Returns `None` if any transaction contains an invalid or
/// undecodable transaction.
pub fn verify_transaction_chunks<H, SigSt, HashSt>(
    signature_strategy: &SigSt,
    hash_strategy: &HashSt,
    namespace: &'static [u8],
    rng: &mut impl CryptoRngCore,
    transactions: Vec<Lazy<SignedTransaction<H>>>,
) -> Option<Vec<SignedTransaction<H>>>
where
    H: Hasher,
    SigSt: Strategy,
    HashSt: Strategy,
{
    if transactions.is_empty() {
        return Some(Vec::new());
    }

    let transactions = preload_transaction_chunks(hash_strategy, transactions)?;

    if !verify_transaction_batch::<H, _>(signature_strategy, namespace, rng, &transactions) {
        return None;
    }

    // Each lazy was forced during verification above, so materialization cannot fail here.
    transactions
        .into_iter()
        .map(|lazy| lazy.get().cloned())
        .collect()
}

#[cfg(test)]
mod test {
    use crate::{
        Sealable, Sealed, SignedTransaction, Transaction, TransactionPublicKey, signed::Signable,
    };
    use commonware_codec::{
        DecodeExt as _, EncodeSize as _, FixedSize as _, ReadExt as _, Write as _,
        types::lazy::Lazy,
    };
    use commonware_cryptography::{
        Hasher, Signer, Verifier, ed25519, secp256r1::recoverable, sha256,
    };
    use commonware_math::algebra::Random;
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use core::num::NonZeroU64;

    const NAMESPACE: &[u8] = b"test namespace";

    #[derive(Debug)]
    struct MockValue([u8; 4]);

    type Ed25519SignedTransaction = SignedTransaction<sha256::Sha256>;

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
        let public_key = TransactionPublicKey::ed25519(private_key.public_key());
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

    #[test]
    fn preload_transaction_chunks_forces_nested_signature_inputs() {
        let hasher = &mut sha256::Sha256::default();
        let private_key = ed25519::PrivateKey::random(&mut test_rng());
        let public_key = TransactionPublicKey::ed25519(private_key.public_key());
        let signed = Transaction::new(
            public_key.clone(),
            public_key,
            NonZeroU64::new(1).expect("test value should be non-zero"),
            0,
        )
        .seal_and_sign(&private_key, NAMESPACE, hasher);

        let mut encoded = Vec::with_capacity(signed.encode_size());
        signed.write(&mut encoded);
        encoded[..TransactionPublicKey::SIZE].copy_from_slice(&invalid_public_key_bytes());

        let lazy = Lazy::<Ed25519SignedTransaction>::read(&mut &encoded[..])
            .expect("outer transaction should decode");
        assert!(
            lazy.get().is_some(),
            "outer transaction decode should defer sender validation"
        );

        assert!(
            super::preload_transaction_chunks(&Sequential, vec![lazy]).is_none(),
            "preload must force the nested sender public key"
        );
    }

    fn invalid_public_key_bytes() -> [u8; TransactionPublicKey::SIZE] {
        (0u8..=u8::MAX)
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
            .expect("test should find invalid public key bytes")
    }
}
