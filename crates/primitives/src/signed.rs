//! Signed value containers.
//!
//! This module builds on the [`Sealed`] wrapper to add cryptographic
//! signatures:
//!
//! - [`Signed`] — A [`Sealed`] value with an attached signature over its seal.
//! - [`Signable`] — A convenience trait for types that are [`Sealable`],
//!   providing a one-step `seal_and_sign` method.

use crate::{
    PublicKeyCache, Sealable, Sealed, SignedTransaction, Transaction, TransactionBatchVerifier,
    TransactionSignature,
};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{
    DecodeExt, Encode, EncodeSize, Error, FixedSize, RangeCfg, Read, ReadExt, Write,
    types::lazy::Lazy,
};
use commonware_cryptography::{Hasher, PublicKey, Signature, Signer, Verifier};
use commonware_parallel::{Sequential, Strategy};
use rand::{SeedableRng, rngs::StdRng};
use rand_core::CryptoRngCore;
use std::sync::{Arc, OnceLock};

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

/// A lazily decoded signed transaction.
#[derive(Clone)]
pub struct LazySignedTransaction<H>
where
    H: Hasher,
{
    pending: Option<Bytes>,
    value: Arc<OnceLock<Option<SignedTransaction<H>>>>,
}

impl<H> LazySignedTransaction<H>
where
    H: Hasher,
{
    const MAX_ENCODED_SIZE: usize = Transaction::<H::Digest>::SIZE + TransactionSignature::MAX_SIZE;

    /// Creates a lazy transaction from an already decoded value.
    pub fn new(value: SignedTransaction<H>) -> Self {
        Self {
            pending: None,
            value: Arc::new(Some(value).into()),
        }
    }

    /// Returns the decoded transaction, if decoding succeeds.
    pub fn get(&self) -> Option<&SignedTransaction<H>> {
        self.value
            .get_or_init(|| {
                let bytes = self
                    .pending
                    .as_ref()
                    .expect("pending bytes must exist when value is absent");
                SignedTransaction::decode(bytes.clone()).ok()
            })
            .as_ref()
    }

    /// Consumes the lazy transaction, returning the decoded value if decoding
    /// succeeds.
    ///
    /// Moves the cached value out when this handle is its only owner; clones
    /// only when the decoded value is still shared with another handle.
    pub fn into_value(self) -> Option<SignedTransaction<H>> {
        self.get()?;
        match Arc::try_unwrap(self.value) {
            Ok(value) => value.into_inner().flatten(),
            Err(shared) => shared.get().expect("value was forced above").clone(),
        }
    }

    /// Returns the encoded signed transaction bytes without the lazy length prefix.
    ///
    /// If this value came from block decoding, this clones the deferred bytes and
    /// does not materialize the transaction.
    pub fn encoded_signed_transaction(&self) -> Bytes {
        if let Some(bytes) = &self.pending {
            return bytes.clone();
        }

        self.get()
            .expect("lazy signed transaction must have a value")
            .encode()
    }

    fn deferred(bytes: Bytes) -> Self {
        Self {
            pending: Some(bytes),
            value: Default::default(),
        }
    }
}

impl<H> Read for LazySignedTransaction<H>
where
    H: Hasher,
{
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let len = usize::read_cfg(buf, &RangeCfg::new(0..=Self::MAX_ENCODED_SIZE))?;
        if len < Transaction::<H::Digest>::SIZE + TransactionSignature::MIN_SIZE {
            return Err(Error::EndOfBuffer);
        }
        if buf.remaining() < len {
            return Err(Error::EndOfBuffer);
        }

        Ok(Self::deferred(buf.copy_to_bytes(len)))
    }
}

impl<H> Write for LazySignedTransaction<H>
where
    H: Hasher,
{
    fn write(&self, buf: &mut impl BufMut) {
        if let Some(pending) = &self.pending {
            pending.len().write(buf);
            buf.put_slice(pending);
            return;
        }
        let transaction = self
            .get()
            .expect("lazy signed transaction must have a value");
        transaction.encode_size().write(buf);
        transaction.write(buf);
    }
}

impl<H> EncodeSize for LazySignedTransaction<H>
where
    H: Hasher,
{
    fn encode_size(&self) -> usize {
        if let Some(pending) = &self.pending {
            return pending.len().encode_size() + pending.len();
        }
        let len = self
            .get()
            .expect("lazy signed transaction must have a value")
            .encode_size();
        len.encode_size() + len
    }
}

impl<H> PartialEq for LazySignedTransaction<H>
where
    H: Hasher,
    SignedTransaction<H>: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

impl<H> Eq for LazySignedTransaction<H> where H: Hasher {}

impl<H> core::fmt::Debug for LazySignedTransaction<H>
where
    H: Hasher,
    SignedTransaction<H>: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.get().fmt(f)
    }
}

/// Materializes lazily-encoded signed transactions in parallel.
///
/// Returns `None` if any transaction fails to decode.
pub fn materialize_transaction_chunks<H, St>(
    strategy: &St,
    transactions: Vec<LazySignedTransaction<H>>,
) -> Option<Vec<SignedTransaction<H>>>
where
    H: Hasher,
    St: Strategy,
{
    strategy
        .map_collect_vec(transactions, LazySignedTransaction::into_value)
        .into_iter()
        .collect()
}

/// Forces a borrowed slice of lazily encoded signed transactions to decode in
/// parallel.
///
/// Returns `false` if any transaction fails to decode.
pub fn preload_transaction_slice<H, St>(
    transactions: &[LazySignedTransaction<H>],
    strategy: &St,
) -> bool
where
    H: Hasher,
    St: Strategy,
{
    strategy.fold(
        transactions,
        || true,
        |decoded, lazy| decoded && signature_inputs_decode(lazy),
        |left, right| left && right,
    )
}

/// Forces lazily encoded signed transactions to decode in parallel.
///
/// Returns the original lazy transactions after warming their cached decoded
/// values, or `None` if any transaction fails to decode.
pub fn preload_transaction_chunks<H, St>(
    transactions: Vec<LazySignedTransaction<H>>,
    strategy: &St,
) -> Option<Vec<LazySignedTransaction<H>>>
where
    H: Hasher,
    St: Strategy,
{
    preload_transaction_slice(&transactions, strategy).then_some(transactions)
}

/// Forces the lazy transaction to decode and its sender public key to parse, in
/// parallel with its caller. Returns `false` if decode fails or the sender is
/// not present. Decompression is deferred to the batch build, which looks each
/// sender up in the shared cache exactly once.
fn signature_inputs_decode<H>(lazy: &LazySignedTransaction<H>) -> bool
where
    H: Hasher,
{
    let Some(transaction) = lazy.get() else {
        return false;
    };
    transaction.value().sender().is_some()
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
    namespace: &[u8],
    rng: &mut impl CryptoRngCore,
    cache: &PublicKeyCache,
    transactions: &[LazySignedTransaction<H>],
    signature_strategy: &St,
) -> bool
where
    H: Hasher,
    St: Strategy,
{
    if transactions.is_empty() {
        return true;
    }

    // Build and verify independent sub-batches in parallel. The serial per
    // signature work (cache decompression, the SHA-512 challenge hash, and the
    // coalescing map) runs inside each shard rather than ahead of a single
    // batch, so it scales with the strategy instead of bottlenecking on one
    // thread. Each shard draws its batch-verification randomness from a seed
    // generated here, since the source rng cannot be shared across threads.
    let parallelism = signature_strategy.parallelism_hint().max(1);
    let shard_size = transactions.len().div_ceil(parallelism).max(1);
    let shards: Vec<(&[LazySignedTransaction<H>], [u8; 32])> = transactions
        .chunks(shard_size)
        .map(|shard| {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            (shard, seed)
        })
        .collect();

    signature_strategy.fold(
        shards,
        || true,
        |valid, (shard, seed)| valid && verify_shard(namespace, cache, shard, seed),
        |left, right| left && right,
    )
}

/// Builds and verifies a single sub-batch sequentially.
fn verify_shard<H>(
    namespace: &[u8],
    cache: &PublicKeyCache,
    shard: &[LazySignedTransaction<H>],
    seed: [u8; 32],
) -> bool
where
    H: Hasher,
{
    let mut verifier = TransactionBatchVerifier::new();
    for lazy in shard {
        let Some(transaction) = lazy.get() else {
            return false;
        };
        let Some(sender) = transaction.value().sender() else {
            return false;
        };
        if !verifier.add(
            namespace,
            transaction.message_digest().as_ref(),
            sender,
            transaction.signature(),
            cache,
        ) {
            return false;
        }
    }
    verifier.verify(&mut StdRng::from_seed(seed), &Sequential)
}

/// Verifies lazily-encoded transactions.
///
/// First forces each [`Lazy`] to decode and compute its seal digest, then runs
/// batch signature verification over the warmed transactions, both on
/// `strategy`. Returns `None` if any transaction is invalid or undecodable.
pub fn verify_transaction_chunks<H, St>(
    namespace: &'static [u8],
    rng: &mut impl CryptoRngCore,
    cache: &PublicKeyCache,
    transactions: Vec<LazySignedTransaction<H>>,
    strategy: &St,
) -> Option<Vec<SignedTransaction<H>>>
where
    H: Hasher,
    St: Strategy,
{
    if transactions.is_empty() {
        return Some(Vec::new());
    }

    let transactions = preload_transaction_chunks(transactions, strategy)?;

    if !verify_transaction_batch::<H, _>(namespace, rng, cache, &transactions, strategy) {
        return None;
    }

    // Each lazy was forced during verification above, so materialization cannot fail here.
    transactions
        .into_iter()
        .map(LazySignedTransaction::into_value)
        .collect()
}

#[cfg(test)]
mod test {
    use crate::{
        LazySignedTransaction, PublicKeyCache, Sealable, Sealed, Transaction,
        TransactionBatchVerifier, TransactionPublicKey, signed::Signable,
    };
    use commonware_codec::{
        DecodeExt as _, EncodeSize as _, FixedSize as _, ReadExt as _, Write as _,
    };
    use commonware_cryptography::{
        Hasher, Signer, Verifier, ed25519, secp256r1::standard as secp256r1, sha256,
    };
    use commonware_math::algebra::Random;
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::{NZUsize, test_rng};
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
        let private_key = secp256r1::PrivateKey::random(&mut test_rng());
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
        deterministic::Runner::default().start(|context| async move {
            let cache = PublicKeyCache::new(context, NZUsize!(16));
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

            let mut verifier = TransactionBatchVerifier::new();
            assert!(
                verifier.add(
                    NAMESPACE,
                    signed.message_digest().as_ref(),
                    signed
                        .value()
                        .sender()
                        .expect("signed sender should decode"),
                    signed.signature(),
                    &cache,
                )
            );
            assert!(verifier.verify(&mut test_rng(), &Sequential));
        });
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

        let mut transaction = Vec::with_capacity(signed.encode_size());
        signed.write(&mut transaction);
        transaction[..TransactionPublicKey::SIZE].copy_from_slice(&invalid_public_key_bytes());

        let mut encoded = Vec::with_capacity(transaction.len().encode_size() + transaction.len());
        transaction.len().write(&mut encoded);
        encoded.extend_from_slice(&transaction);

        let lazy = LazySignedTransaction::<sha256::Sha256>::read(&mut &encoded[..])
            .expect("outer transaction should decode");
        assert!(
            lazy.get().is_some(),
            "outer transaction decode should defer sender validation"
        );

        assert!(
            super::preload_transaction_chunks(vec![lazy], &Sequential).is_none(),
            "preload must force the nested sender public key"
        );
    }

    #[test]
    fn lazy_signed_transaction_exposes_pending_bytes_without_materializing() {
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

        let mut transaction = Vec::with_capacity(signed.encode_size());
        signed.write(&mut transaction);
        transaction[0] = u8::MAX;

        let mut encoded = Vec::with_capacity(transaction.len().encode_size() + transaction.len());
        transaction.len().write(&mut encoded);
        encoded.extend_from_slice(&transaction);

        let lazy = LazySignedTransaction::<sha256::Sha256>::read(&mut &encoded[..])
            .expect("outer transaction should decode");

        assert_eq!(lazy.encoded_signed_transaction().as_ref(), transaction);
        assert!(
            lazy.get()
                .expect("signed transaction should decode while sender stays lazy")
                .value()
                .sender()
                .is_none(),
            "nested sender decode should still fail after reading pending bytes"
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
