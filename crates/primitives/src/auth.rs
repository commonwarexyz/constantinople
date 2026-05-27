//! Transaction account keys and signatures.

use bytes::{Buf, BufMut};
use commonware_codec::{Error, FixedSize, Read, ReadExt as _, Write};
use commonware_cryptography::{
    BatchVerifier, PublicKey, Signature as SignatureTrait, Verifier, ed25519,
    secp256r1::standard as secp256r1,
};
use commonware_parallel::Strategy;
use commonware_utils::{Array, Span};
use core::{
    fmt::{Debug, Display},
    hash::Hash,
    ops::Deref,
};
use rand_core::CryptoRngCore;

const ED25519_SCHEME: u8 = 0;
const SECP256R1_SCHEME: u8 = 1;
const KEY_BYTES: usize = secp256r1::PublicKey::SIZE;
const SIGNATURE_BYTES: usize = ed25519::Signature::SIZE;

/// A transaction account public key.
///
/// The first byte is the signature scheme. The remaining bytes hold the
/// scheme's canonical public key bytes. Ed25519 keys are padded with one
/// trailing zero byte to keep this type compatible with Commonware's fixed-size
/// public-key traits.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TransactionPublicKey {
    /// Commonware Ed25519.
    Ed25519 {
        /// Parsed public key.
        key: ed25519::PublicKey,
        /// Fixed transaction encoding.
        encoded: [u8; Self::SIZE],
    },
    /// Commonware secp256r1 standard.
    Secp256r1 {
        /// Parsed public key.
        key: secp256r1::PublicKey,
        /// Fixed transaction encoding.
        encoded: [u8; Self::SIZE],
    },
}

impl TransactionPublicKey {
    /// Creates an Ed25519 transaction public key.
    pub fn ed25519(key: ed25519::PublicKey) -> Self {
        let mut encoded = [0; Self::SIZE];
        encoded[0] = ED25519_SCHEME;
        encoded[1..1 + ed25519::PublicKey::SIZE].copy_from_slice(key.as_ref());
        Self::Ed25519 { key, encoded }
    }

    /// Creates a secp256r1 transaction public key.
    pub fn secp256r1(key: secp256r1::PublicKey) -> Self {
        let mut encoded = [0; Self::SIZE];
        encoded[0] = SECP256R1_SCHEME;
        encoded[1..].copy_from_slice(key.as_ref());
        Self::Secp256r1 { key, encoded }
    }
}

impl Verifier for TransactionPublicKey {
    type Signature = TransactionSignature;

    fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Self::Signature) -> bool {
        match (self, sig) {
            (Self::Ed25519 { key, .. }, TransactionSignature::Ed25519 { signature, .. }) => {
                key.verify(namespace, msg, signature)
            }
            (Self::Secp256r1 { key, .. }, TransactionSignature::Secp256r1 { signature, .. }) => {
                key.verify(namespace, msg, signature)
            }
            _ => false,
        }
    }
}

impl PublicKey for TransactionPublicKey {}

impl Write for TransactionPublicKey {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(self.as_ref());
    }
}

impl Read for TransactionPublicKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        if buf.remaining() < Self::SIZE {
            return Err(Error::EndOfBuffer);
        }

        let mut encoded = [0; Self::SIZE];
        buf.copy_to_slice(&mut encoded);
        match encoded[0] {
            ED25519_SCHEME => {
                if encoded[1 + ed25519::PublicKey::SIZE..]
                    .iter()
                    .any(|byte| *byte != 0)
                {
                    return Err(Error::Invalid("TransactionPublicKey", "non-zero padding"));
                }
                let key = ed25519::PublicKey::read(&mut &encoded[1..1 + ed25519::PublicKey::SIZE])?;
                Ok(Self::Ed25519 { key, encoded })
            }
            SECP256R1_SCHEME => {
                let key = secp256r1::PublicKey::read(&mut &encoded[1..])?;
                Ok(Self::Secp256r1 { key, encoded })
            }
            _ => Err(Error::Invalid("TransactionPublicKey", "unknown scheme")),
        }
    }
}

impl FixedSize for TransactionPublicKey {
    const SIZE: usize = 1 + KEY_BYTES;
}

impl Span for TransactionPublicKey {}
impl Array for TransactionPublicKey {}

impl AsRef<[u8]> for TransactionPublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Ed25519 { encoded, .. } | Self::Secp256r1 { encoded, .. } => encoded,
        }
    }
}

impl Deref for TransactionPublicKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl Debug for TransactionPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Display::fmt(self, f)
    }
}

impl Display for TransactionPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl From<ed25519::PublicKey> for TransactionPublicKey {
    fn from(key: ed25519::PublicKey) -> Self {
        Self::ed25519(key)
    }
}

impl From<secp256r1::PublicKey> for TransactionPublicKey {
    fn from(key: secp256r1::PublicKey) -> Self {
        Self::secp256r1(key)
    }
}

/// A transaction signature.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TransactionSignature {
    /// Commonware Ed25519.
    Ed25519 {
        /// Parsed signature.
        signature: ed25519::Signature,
        /// Fixed transaction encoding.
        encoded: [u8; Self::SIZE],
    },
    /// Commonware secp256r1 standard.
    Secp256r1 {
        /// Parsed signature.
        signature: secp256r1::Signature,
        /// Fixed transaction encoding.
        encoded: [u8; Self::SIZE],
    },
}

impl TransactionSignature {
    /// Creates an Ed25519 transaction signature.
    pub fn ed25519(signature: ed25519::Signature) -> Self {
        let mut encoded = [0; Self::SIZE];
        encoded[0] = ED25519_SCHEME;
        encoded[1..].copy_from_slice(signature.as_ref());
        Self::Ed25519 { signature, encoded }
    }

    /// Creates a secp256r1 transaction signature.
    pub fn secp256r1(signature: secp256r1::Signature) -> Self {
        let mut encoded = [0; Self::SIZE];
        encoded[0] = SECP256R1_SCHEME;
        encoded[1..].copy_from_slice(signature.as_ref());
        Self::Secp256r1 { signature, encoded }
    }
}

impl SignatureTrait for TransactionSignature {}

impl Write for TransactionSignature {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(self.as_ref());
    }
}

impl Read for TransactionSignature {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        if buf.remaining() < Self::SIZE {
            return Err(Error::EndOfBuffer);
        }

        let mut encoded = [0; Self::SIZE];
        buf.copy_to_slice(&mut encoded);
        match encoded[0] {
            ED25519_SCHEME => {
                let signature = ed25519::Signature::read(&mut &encoded[1..])?;
                Ok(Self::Ed25519 { signature, encoded })
            }
            SECP256R1_SCHEME => {
                let signature = secp256r1::Signature::read(&mut &encoded[1..])?;
                Ok(Self::Secp256r1 { signature, encoded })
            }
            _ => Err(Error::Invalid("TransactionSignature", "unknown scheme")),
        }
    }
}

impl FixedSize for TransactionSignature {
    const SIZE: usize = 1 + SIGNATURE_BYTES;
}

impl Span for TransactionSignature {}
impl Array for TransactionSignature {}

impl AsRef<[u8]> for TransactionSignature {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Ed25519 { encoded, .. } | Self::Secp256r1 { encoded, .. } => encoded,
        }
    }
}

impl Deref for TransactionSignature {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl Debug for TransactionSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Display::fmt(self, f)
    }
}

impl Display for TransactionSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl From<ed25519::Signature> for TransactionSignature {
    fn from(signature: ed25519::Signature) -> Self {
        Self::ed25519(signature)
    }
}

impl From<secp256r1::Signature> for TransactionSignature {
    fn from(signature: secp256r1::Signature) -> Self {
        Self::secp256r1(signature)
    }
}

/// Verifies mixed transaction signatures with separate scheme groups.
pub struct TransactionBatchVerifier {
    ed25519: ed25519::Batch,
    secp256r1: Vec<Secp256r1Item>,
}

struct Secp256r1Item {
    namespace: Vec<u8>,
    message: Vec<u8>,
    public_key: secp256r1::PublicKey,
    signature: secp256r1::Signature,
}

impl BatchVerifier for TransactionBatchVerifier {
    type PublicKey = TransactionPublicKey;

    fn new() -> Self {
        Self {
            ed25519: ed25519::Batch::new(),
            secp256r1: Vec::new(),
        }
    }

    fn add(
        &mut self,
        namespace: &[u8],
        message: &[u8],
        public_key: &Self::PublicKey,
        signature: &TransactionSignature,
    ) -> bool {
        match (public_key, signature) {
            (
                TransactionPublicKey::Ed25519 { key, .. },
                TransactionSignature::Ed25519 { signature, .. },
            ) => self.ed25519.add(namespace, message, key, signature),
            (
                TransactionPublicKey::Secp256r1 { key, .. },
                TransactionSignature::Secp256r1 { signature, .. },
            ) => {
                self.secp256r1.push(Secp256r1Item {
                    namespace: namespace.to_vec(),
                    message: message.to_vec(),
                    public_key: key.clone(),
                    signature: signature.clone(),
                });
                true
            }
            _ => false,
        }
    }

    fn verify<R: CryptoRngCore>(self, rng: &mut R, strategy: &impl Strategy) -> bool {
        if !self.ed25519.verify(rng, strategy) {
            return false;
        }

        verify_secp256r1(strategy, self.secp256r1)
    }
}

fn verify_secp256r1(strategy: &impl Strategy, items: Vec<Secp256r1Item>) -> bool {
    if items.is_empty() {
        return true;
    }

    strategy.fold(
        items,
        || true,
        |valid, item| {
            valid
                && item
                    .public_key
                    .verify(&item.namespace, &item.message, &item.signature)
        },
        |left, right| left && right,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::{Hasher, Signer as _, sha256};
    use commonware_math::algebra::Random as _;
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;

    const NAMESPACE: &[u8] = b"constantinople-tx";

    #[test]
    fn public_key_codec_carries_scheme_byte() {
        let signer = secp256r1::PrivateKey::random(&mut test_rng());
        let key = TransactionPublicKey::secp256r1(signer.public_key());
        let encoded = key.encode();

        assert_eq!(encoded[0], SECP256R1_SCHEME);
        assert_eq!(TransactionPublicKey::decode(encoded.as_ref()).unwrap(), key);
    }

    #[test]
    fn signature_codec_carries_scheme_byte() {
        let signer = ed25519::PrivateKey::random(&mut test_rng());
        let signature = TransactionSignature::ed25519(signer.sign(NAMESPACE, b"hello"));
        let encoded = signature.encode();

        assert_eq!(encoded[0], ED25519_SCHEME);
        assert_eq!(
            TransactionSignature::decode(encoded.as_ref()).unwrap(),
            signature
        );
    }

    #[test]
    fn mixed_batch_verifier_accepts_both_schemes() {
        let ed25519 = ed25519::PrivateKey::random(&mut test_rng());
        let secp256r1 = secp256r1::PrivateKey::random(&mut test_rng());
        let ed_message = sha256::Sha256::hash(b"ed25519").to_vec();
        let r1_message = sha256::Sha256::hash(b"secp256r1").to_vec();

        let mut verifier = TransactionBatchVerifier::new();
        assert!(verifier.add(
            NAMESPACE,
            &ed_message,
            &TransactionPublicKey::ed25519(ed25519.public_key()),
            &TransactionSignature::ed25519(ed25519.sign(NAMESPACE, &ed_message)),
        ));
        assert!(verifier.add(
            NAMESPACE,
            &r1_message,
            &TransactionPublicKey::secp256r1(secp256r1.public_key()),
            &TransactionSignature::secp256r1(secp256r1.sign(NAMESPACE, &r1_message)),
        ));

        assert!(verifier.verify(&mut test_rng(), &Sequential));
    }

    #[test]
    fn mixed_batch_verifier_rejects_scheme_mismatch() {
        let ed25519 = ed25519::PrivateKey::random(&mut test_rng());
        let secp256r1 = secp256r1::PrivateKey::random(&mut test_rng());
        let message = sha256::Sha256::hash(b"message").to_vec();

        let mut verifier = TransactionBatchVerifier::new();
        assert!(!verifier.add(
            NAMESPACE,
            &message,
            &TransactionPublicKey::ed25519(ed25519.public_key()),
            &TransactionSignature::secp256r1(secp256r1.sign(NAMESPACE, &message)),
        ));
    }
}
