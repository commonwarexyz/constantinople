//! Ed25519 signing keys, signatures, and verification.
//!
//! # Validation criteria (ZIP215)
//!
//! Signature validation follows [ZIP215], the criteria that make Ed25519 safe for consensus:
//!
//! - The point encodings of the verifying key `A` and the signature component `R` are accepted
//!   even when non-canonical (a `y` coordinate at or above `p`, or a negative-zero `x`), as long
//!   as they decode to a curve point.
//! - The scalar component `s` must be canonical (`s < L`), ruling out signature malleability.
//! - The verification equation is cofactored: `[8](s·B - R - H(R || A || M)·A) == identity`.
//!
//! [`VerifyingKey::verify`] and [`BatchVerifier::verify`] apply exactly the same criteria, so
//! batch and individual verification agree on every signature: a batch is valid precisely when
//! each of its signatures verifies individually. See [this
//! post](https://hdevalence.ca/blog/2020-10-04-its-25519am) for why these criteria matter.
//!
//! [ZIP215]: https://zips.z.cash/zip-0215

mod core;

use self::core::Scalar;
use crate::curve::GAffine;
use ::core::{
    fmt::{self, Debug, Display},
    hash::{Hash, Hasher},
};
#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{FixedSize, Read, Write};
use commonware_formatting::Hex;
use commonware_math::algebra::Random;
use commonware_parallel::Strategy;
use commonware_utils::union_unique;
use rand_core::CryptoRng;
use sha2::{
    Digest,
    digest::{FixedOutput, Update},
};
#[cfg(feature = "std")]
use std::sync::Arc;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// An Ed25519 signing key.
///
/// Secret material is zeroized when the key is dropped.
#[derive(ZeroizeOnDrop)]
pub struct SigningKey {
    /// When serializing, we want to just write the seed, so we keep it around.
    seed: [u8; 32],
    /// The private prefix we use to derive a deterministic nonce for each message.
    prefix: [u8; 32],
    /// The pruned secret scalar, reduced modulo the basepoint order.
    scalar: Scalar,
    /// The verifying key derived from the secret scalar.
    #[zeroize(skip)]
    verifying_key: VerifyingKey,
}

// Private methods.
impl SigningKey {
    fn from_seed(seed: [u8; 32]) -> Self {
        let seed = Zeroizing::new(seed);
        // Following: https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.5.
        // The first half becomes our secret scalar material, while the second half
        // is the private prefix we use to derive deterministic nonces.
        let h: Zeroizing<[u8; 64]> =
            Zeroizing::new(sha2::Sha512::new().chain(&seed[..]).finalize_fixed().into());
        let mut scalar_le_bytes: Zeroizing<[u8; 32]> =
            Zeroizing::new(h[..32].try_into().expect("h is 64 bytes"));
        let prefix: Zeroizing<[u8; 32]> =
            Zeroizing::new(h[32..].try_into().expect("h is 64 bytes"));
        // We want the integer represented by these little-endian bytes to be a
        // multiple of the curve's cofactor, 8, so we "clamp" it by zeroing its
        // three least-significant bits. This is part of Ed25519 key derivation too,
        // not just key exchange.
        scalar_le_bytes[0] &= 0b1111_1000;
        // We also want the scalar to fit in 255 bits, so we unset bit 255. This
        // doesn't put it below L; scalar-field arithmetic still has to reduce it
        // modulo L.
        scalar_le_bytes[31] &= 0b0111_1111;
        // The RFC also requires us to set bit 254, giving the scalar a fixed 255-bit
        // length. Among other things, this forces scalar-multiplication implementations
        // that start at the highest set bit to use the same number of iterations. It
        // doesn't make a variable-time implementation safe by itself.
        scalar_le_bytes[31] |= 0b0100_0000;
        let mut wide_scalar = Zeroizing::new([0u8; 64]);
        wide_scalar[..32].copy_from_slice(&scalar_le_bytes[..]);
        let scalar = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&wide_scalar));
        let point = GAffine::BASEPOINT
            .to_extended()
            .scalar_mul_secret(&scalar_le_bytes);
        let verifying_key = VerifyingKey {
            bytes: point.to_bytes(),
            point: Some(Arc::new(point.to_affine())),
        };

        Self {
            seed: *seed,
            prefix: *prefix,
            scalar: *scalar,
            verifying_key,
        }
    }
}

impl Random for SigningKey {
    fn random(mut rng: impl rand_core::CryptoRng) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut seed[..]);
        Self::from_seed(*seed)
    }
}

impl Write for SigningKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.seed.write(buf);
    }
}

impl FixedSize for SigningKey {
    const SIZE: usize = 32;
}

impl Read for SigningKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let seed = Zeroizing::new(<[u8; Self::SIZE]>::read_cfg(buf, cfg)?);
        Ok(Self::from_seed(*seed))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for SigningKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let seed: Zeroizing<[u8; Self::SIZE]> = Zeroizing::new(u.arbitrary()?);
        Ok(Self::from_seed(*seed))
    }
}

// Public methods.
impl SigningKey {
    /// The verifying key associated with this signing key.
    ///
    /// Signatures produced by this signing key can be verified using this public key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key.clone()
    }

    /// Signs a namespaced message using deterministic Ed25519.
    ///
    /// The namespace is committed to the signature to prevent its reuse in another context.
    /// Signing is deterministic per [RFC 8032]: the nonce is derived from the key and the
    /// message, so signing the same message twice yields the same signature and no randomness
    /// is consumed.
    ///
    /// [RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032
    pub fn sign(&self, namespace: &[u8], msg: &[u8]) -> Signature {
        let msg = union_unique(namespace, msg);

        let nonce_digest: Zeroizing<[u8; 64]> = Zeroizing::new(
            sha2::Sha512::new()
                .chain(self.prefix.as_slice())
                .chain(&msg)
                .finalize_fixed()
                .into(),
        );
        let nonce = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&nonce_digest));
        let nonce_bytes = Zeroizing::new(nonce.to_bytes());
        let r_bytes = GAffine::BASEPOINT
            .to_extended()
            .scalar_mul_secret(&nonce_bytes)
            .to_bytes();

        let challenge_digest: [u8; 64] = sha2::Sha512::new()
            .chain(r_bytes)
            .chain(self.verifying_key.bytes)
            .chain(&msg)
            .finalize_fixed()
            .into();
        let challenge = Scalar::from_bytes_mod_order_wide(&challenge_digest);
        let challenge_scalar = Zeroizing::new(challenge.mul_mod_l(&self.scalar));
        let s_bytes = nonce.add_mod_l(&challenge_scalar).to_bytes();

        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&r_bytes);
        bytes[32..].copy_from_slice(&s_bytes);
        Signature { bytes }
    }
}

/// A public key used to check signatures.
#[derive(Clone)]
pub struct VerifyingKey {
    /// The encoded point.
    ///
    /// When deserializing, we just have the bytes, deferring parsing of them until
    /// signature verification, so that we can more efficiently parse them in batch.
    bytes: [u8; 32],
    /// If available, the point associated with these bytes.
    point: Option<Arc<GAffine>>,
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for VerifyingKey {}

impl PartialOrd for VerifyingKey {
    fn partial_cmp(&self, other: &Self) -> Option<::core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VerifyingKey {
    fn cmp(&self, other: &Self) -> ::core::cmp::Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl Hash for VerifyingKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Hex(&self.bytes))
    }
}

impl Display for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Hex(&self.bytes))
    }
}

impl AsRef<[u8]> for VerifyingKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Write for VerifyingKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.bytes.write(buf);
    }
}

impl FixedSize for VerifyingKey {
    const SIZE: usize = 32;
}

impl Read for VerifyingKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            bytes: <[u8; Self::SIZE]>::read_cfg(buf, cfg)?,
            point: None,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for VerifyingKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            bytes: u.arbitrary()?,
            point: None,
        })
    }
}

// Public methods.
impl VerifyingKey {
    /// Decompresses a collection of keys with the selected SIMD backend.
    ///
    /// Prepared keys retain their affine points so later batch verification can
    /// skip repeated public-key decompression while still batch-decompressing
    /// each signature's `R` component.
    pub fn prepare_batch(mut keys: Vec<Self>, strategy: &impl Strategy) -> Option<Vec<Self>> {
        let encodings: Vec<_> = keys.iter().map(|key| key.bytes).collect();
        let points = core::decompress_verifying_keys(&encodings, strategy)?;
        for (key, point) in keys.iter_mut().zip(points) {
            key.point = Some(Arc::new(point));
        }
        Some(keys)
    }

    /// Verifies `sig` over the namespaced message, per the [module's validation
    /// criteria](self).
    #[must_use]
    pub fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Signature) -> bool {
        let r_bytes: [u8; 32] = sig.bytes[..32].try_into().expect("signature is 64 bytes");
        let s_bytes: [u8; 32] = sig.bytes[32..].try_into().expect("signature is 64 bytes");
        let Some(s) = Scalar::from_canonical_bytes(&s_bytes) else {
            return false;
        };
        let Some(r) = GAffine::decompress(&r_bytes) else {
            return false;
        };
        let a = match &self.point {
            Some(point) => point.to_extended(),
            None => {
                let Some(point) = GAffine::decompress(&self.bytes) else {
                    return false;
                };
                point.to_extended()
            }
        };

        let msg = union_unique(namespace, msg);
        let digest: [u8; 64] = sha2::Sha512::new()
            .chain(r_bytes)
            .chain(self.bytes)
            .chain(&msg)
            .finalize_fixed()
            .into();
        let k = Scalar::from_bytes_mod_order_wide(&digest);

        let sb = GAffine::BASEPOINT.to_extended().scalar_mul(s.bits_be());
        let ka = a.scalar_mul(k.bits_be());
        sb.add(ka.add_mixed(r).negate())
            .mul_by_cofactor()
            .is_identity()
    }
}

/// An object demonstrating that the owner of a [`VerifyingKey`] approved a message.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Signature {
    bytes: [u8; 64],
}

impl Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Hex(&self.bytes))
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Hex(&self.bytes))
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Write for Signature {
    fn write(&self, buf: &mut impl BufMut) {
        self.bytes.write(buf);
    }
}

impl FixedSize for Signature {
    const SIZE: usize = 64;
}

impl Read for Signature {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            bytes: <[u8; Self::SIZE]>::read_cfg(buf, cfg)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Signature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            bytes: u.arbitrary()?,
        })
    }
}

/// A batch verification context.
pub struct BatchVerifier<'a> {
    items: Vec<(&'a [u8], &'a [u8], VerifyingKey, core::Signature)>,
}

impl<'a> BatchVerifier<'a> {
    /// Creates a verifier with space for `capacity` signatures.
    pub fn new(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
        }
    }

    /// Queues a signature for verification over the namespaced message.
    pub fn add(
        &mut self,
        namespace: &'a [u8],
        message: &'a [u8],
        public_key: &VerifyingKey,
        signature: &Signature,
    ) {
        self.add_owned(namespace, message, public_key.clone(), signature);
    }

    /// Queues a signature while transferring ownership of a prepared key.
    pub fn add_owned(
        &mut self,
        namespace: &'a [u8],
        message: &'a [u8],
        public_key: VerifyingKey,
        signature: &Signature,
    ) {
        self.items.push((
            namespace,
            message,
            public_key,
            core::Signature::from_bytes(signature.bytes),
        ));
    }

    /// Check all the signatures in the batch.
    ///
    /// This returns true precisely when all the signatures in the batch are valid under the
    /// [module's validation criteria](self), matching [`VerifyingKey::verify`] on every
    /// signature: an invalid batch is only ever accepted if the random coefficients drawn from
    /// `rng` collide, an event of negligible probability (about `2^-128`).
    #[must_use]
    pub fn verify(self, rng: &mut impl CryptoRng, strategy: &impl Strategy) -> bool {
        let items = self
            .items
            .iter()
            .map(|(namespace, message, public_key, signature)| {
                (
                    &public_key.bytes,
                    public_key.point.as_deref(),
                    signature,
                    *namespace,
                    *message,
                )
            });
        core::verify_namespaced_batch(rng, items, strategy)
    }
}

#[cfg(test)]
mod tests {
    use super::{BatchVerifier, Signature, SigningKey, VerifyingKey};
    use commonware_math::algebra::Random;
    use commonware_parallel::{Rayon, Sequential, Strategy};
    use commonware_utils::{NZUsize, test_rng, union_unique};
    use ed25519_consensus::{
        Signature as RefSignature, SigningKey as RefSigningKey, VerificationKey as RefVerifyingKey,
    };
    use rand_core::Rng;

    const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_CURVE25519_SIGNING_TEST";
    const WRONG_NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_CURVE25519_SIGNING_TEST_WRONG";

    #[test]
    fn sign_matches_reference_implementation() {
        let mut rng = test_rng();
        for i in 0..16 {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let signing_key = SigningKey::from_seed(seed);
            let reference_key = RefSigningKey::from(seed);
            let message = format!("message {i}").into_bytes();

            let verifying_key = signing_key.verifying_key();
            assert_eq!(
                verifying_key.as_ref(),
                reference_key.verification_key().to_bytes()
            );

            let signature = signing_key.sign(NAMESPACE, &message);
            let reference_signature = reference_key.sign(&union_unique(NAMESPACE, &message));
            assert_eq!(signature.bytes, reference_signature.to_bytes());
            assert!(verifying_key.verify(NAMESPACE, &message, &signature));
            assert!(!verifying_key.verify(WRONG_NAMESPACE, &message, &signature));
        }
    }

    #[test]
    fn batch_verifier_accepts_own_signatures() {
        let mut rng = test_rng();
        let fixtures = (0..16)
            .map(|i| {
                let signing_key = SigningKey::random(&mut rng);
                let message = format!("message {i}").into_bytes();
                let signature = signing_key.sign(NAMESPACE, &message);
                (message, signing_key.verifying_key(), signature)
            })
            .collect::<Vec<_>>();
        let mut verifier = BatchVerifier::new(16);
        for (message, verifying_key, signature) in &fixtures {
            verifier.add(NAMESPACE, message, verifying_key, signature);
        }
        assert!(verifier.verify(&mut rng, &Sequential));
    }

    #[test]
    fn signing_key_zeroizes_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<SigningKey>();
        assert!(core::mem::needs_drop::<SigningKey>());
    }

    #[test]
    fn zip215_accepts_negative_zero_encodings_with_prepared_keys() {
        let mut positive_identity = [0u8; 32];
        positive_identity[0] = 1;
        positive_identity[31] = 0x80;

        let mut negative_identity = [0xff; 32];
        negative_identity[0] = 0xec;

        let mut non_canonical_positive_identity = [0xff; 32];
        non_canonical_positive_identity[0] = 0xee;

        let encodings = [
            positive_identity,
            negative_identity,
            non_canonical_positive_identity,
        ];
        let message = b"negative-zero encoding";
        let namespaced_message = union_unique(NAMESPACE, message);
        let mut rng = test_rng();
        let raw_keys: Vec<_> = encodings
            .iter()
            .map(|encoding| VerifyingKey {
                bytes: *encoding,
                point: None,
            })
            .collect();
        let prepared_keys = VerifyingKey::prepare_batch(raw_keys.clone(), &Sequential)
            .expect("ZIP-215 encodings must decompress");
        let mut raw_batch = BatchVerifier::new(encodings.len());
        let mut prepared_batch = BatchVerifier::new(encodings.len());

        for ((encoding, raw_key), prepared_key) in
            encodings.into_iter().zip(&raw_keys).zip(&prepared_keys)
        {
            let mut signature_bytes = [0u8; 64];
            signature_bytes[..32].copy_from_slice(&encoding);
            let signature = Signature {
                bytes: signature_bytes,
            };

            let reference_key = RefVerifyingKey::try_from(encoding).unwrap();
            let reference_signature = RefSignature::from(signature_bytes);
            assert!(
                reference_key
                    .verify(&reference_signature, &namespaced_message)
                    .is_ok()
            );
            assert!(raw_key.verify(NAMESPACE, message, &signature));
            assert!(prepared_key.verify(NAMESPACE, message, &signature));
            raw_batch.add(NAMESPACE, message, raw_key, &signature);
            prepared_batch.add(NAMESPACE, message, prepared_key, &signature);
        }

        assert!(raw_batch.verify(&mut rng, &Sequential));
        assert!(prepared_batch.verify(&mut rng, &Sequential));
    }

    #[test]
    fn batch_verifier_accepts_mixed_prepared_and_raw_copies_of_one_key() {
        let mut rng = test_rng();
        let signing_key = SigningKey::random(&mut rng);
        let prepared_key = signing_key.verifying_key();
        let raw_key = VerifyingKey {
            bytes: prepared_key.bytes,
            point: None,
        };
        let first_message = b"raw key first";
        let second_message = b"prepared key second";
        let first_signature = signing_key.sign(NAMESPACE, first_message);
        let second_signature = signing_key.sign(NAMESPACE, second_message);

        let mut batch = BatchVerifier::new(2);
        batch.add(NAMESPACE, first_message, &raw_key, &first_signature);
        batch.add(NAMESPACE, second_message, &prepared_key, &second_signature);
        assert!(batch.verify(&mut rng, &Sequential));
    }

    #[test]
    fn prepared_batches_agree_across_strategies() {
        fn verify(
            fixtures: &[(Vec<u8>, VerifyingKey, Signature)],
            strategy: &impl Strategy,
        ) -> bool {
            let mut batch = BatchVerifier::new(fixtures.len());
            for (message, key, signature) in fixtures {
                batch.add(NAMESPACE, message, key, signature);
            }
            batch.verify(&mut test_rng(), strategy)
        }

        let strategy = Rayon::new(NZUsize!(4)).expect("Rayon pool must start");
        let mut rng = test_rng();
        let signing_keys: Vec<_> = (0..256).map(|_| SigningKey::random(&mut rng)).collect();
        let raw_keys = signing_keys
            .iter()
            .map(|key| {
                let key = key.verifying_key();
                VerifyingKey {
                    bytes: key.bytes,
                    point: None,
                }
            })
            .collect();
        let prepared_keys = VerifyingKey::prepare_batch(raw_keys, &strategy)
            .expect("generated keys must decompress");
        let mut fixtures: Vec<_> = signing_keys
            .iter()
            .zip(prepared_keys)
            .enumerate()
            .map(|(index, (signing_key, verifying_key))| {
                let message = format!("prepared message {index}").into_bytes();
                let signature = signing_key.sign(NAMESPACE, &message);
                (message, verifying_key, signature)
            })
            .collect();

        assert!(verify(&fixtures, &Sequential));
        assert!(verify(&fixtures, &strategy));

        fixtures[123].2.bytes[32..].fill(0xff);
        assert!(!verify(&fixtures, &Sequential));
        assert!(!verify(&fixtures, &strategy));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::super::{Signature, SigningKey, VerifyingKey};
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<SigningKey> => 1024,
            CodecConformance<VerifyingKey>,
            CodecConformance<Signature>,
        }
    }
}
