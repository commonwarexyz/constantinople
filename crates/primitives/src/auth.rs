//! Transaction account keys and signatures.

use crate::DecompressedPublicKey;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, FixedSize, Read, ReadExt as _, Write};
use commonware_cryptography::{
    BatchVerifier, Hasher as _, ed25519, secp256r1::standard as secp256r1, sha256,
};
use commonware_parallel::Strategy;
use commonware_utils::{Array, Span};
use core::{
    fmt::{Debug, Display},
    hash::Hash,
    ops::Deref,
};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey, signature::Verifier as _};
use rand::CryptoRng;

pub(crate) const ED25519_SCHEME: u8 = 0;
pub(crate) const SECP256R1_SCHEME: u8 = 1;
const KEY_BYTES: usize = secp256r1::PublicKey::SIZE;
const SIGNATURE_BYTES: usize = ed25519::Signature::SIZE;
const ED25519_SIGNATURE_BYTES: usize = 1 + SIGNATURE_BYTES;
const WEBAUTHN_AUTHENTICATOR_DATA_BYTES: usize = 256;
const WEBAUTHN_CLIENT_DATA_JSON_BYTES: usize = 512;
const WEBAUTHN_USER_VERIFIED_FLAG: u8 = 0x04;

/// A transaction account public key.
///
/// The first byte is the signature scheme. The remaining bytes hold the
/// scheme's canonical compressed public key bytes. Ed25519 keys are padded with
/// one trailing zero byte to keep this type compatible with Commonware's
/// fixed-size public-key traits.
///
/// Decoding is intentionally cheap: it validates only the scheme byte and (for
/// Ed25519) the trailing padding. The expensive compressed-to-decompressed
/// point conversion is deferred to signature verification, where it is served
/// from a shared [`PublicKeyCache`](crate::PublicKeyCache) so a recurring sender's key is decompressed
/// at most once.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TransactionPublicKey {
    /// Commonware Ed25519.
    Ed25519 {
        /// Fixed transaction encoding.
        encoded: [u8; Self::SIZE],
    },
    /// Commonware secp256r1 standard.
    Secp256r1 {
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
        Self::Ed25519 { encoded }
    }

    /// Creates a secp256r1 transaction public key.
    pub fn secp256r1(key: secp256r1::PublicKey) -> Self {
        let mut encoded = [0; Self::SIZE];
        encoded[0] = SECP256R1_SCHEME;
        encoded[1..].copy_from_slice(key.as_ref());
        Self::Secp256r1 { encoded }
    }
}

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
                Ok(Self::Ed25519 { encoded })
            }
            SECP256R1_SCHEME => Ok(Self::Secp256r1 { encoded }),
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
            Self::Ed25519 { encoded } => encoded,
            Self::Secp256r1 { encoded } => encoded,
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
        /// Transaction encoding.
        encoded: [u8; ED25519_SIGNATURE_BYTES],
    },
    /// WebAuthn secp256r1 assertion.
    Secp256r1 {
        /// Parsed assertion signature.
        signature: secp256r1::Signature,
        /// Authenticator data from the assertion response.
        authenticator_data: Vec<u8>,
        /// Client data JSON from the assertion response.
        client_data_json: Vec<u8>,
        /// Transaction encoding.
        encoded: Vec<u8>,
    },
}

impl TransactionSignature {
    /// Minimum encoded transaction signature size.
    pub const MIN_SIZE: usize = 1 + SIGNATURE_BYTES;
    /// Maximum encoded transaction signature size.
    pub const MAX_SIZE: usize = 1
        + SIGNATURE_BYTES
        + u16::SIZE
        + WEBAUTHN_AUTHENTICATOR_DATA_BYTES
        + u16::SIZE
        + WEBAUTHN_CLIENT_DATA_JSON_BYTES;

    /// Creates an Ed25519 transaction signature.
    pub fn ed25519(signature: ed25519::Signature) -> Self {
        let mut encoded = [0; ED25519_SIGNATURE_BYTES];
        encoded[0] = ED25519_SCHEME;
        encoded[1..].copy_from_slice(signature.as_ref());
        Self::Ed25519 { signature, encoded }
    }

    /// Creates a WebAuthn secp256r1 transaction signature.
    pub fn secp256r1(
        signature: secp256r1::Signature,
        authenticator_data: Vec<u8>,
        client_data_json: Vec<u8>,
    ) -> Result<Self, Error> {
        if authenticator_data.len() > WEBAUTHN_AUTHENTICATOR_DATA_BYTES {
            return Err(Error::Invalid(
                "TransactionSignature",
                "authenticator data too large",
            ));
        }
        if client_data_json.len() > WEBAUTHN_CLIENT_DATA_JSON_BYTES {
            return Err(Error::Invalid(
                "TransactionSignature",
                "client data JSON too large",
            ));
        }

        let mut encoded = Vec::with_capacity(
            1 + SIGNATURE_BYTES
                + u16::SIZE
                + authenticator_data.len()
                + u16::SIZE
                + client_data_json.len(),
        );
        encoded.push(SECP256R1_SCHEME);
        encoded.extend_from_slice(signature.as_ref());
        (authenticator_data.len() as u16).write(&mut encoded);
        encoded.extend_from_slice(&authenticator_data);
        (client_data_json.len() as u16).write(&mut encoded);
        encoded.extend_from_slice(&client_data_json);

        Ok(Self::Secp256r1 {
            signature,
            authenticator_data,
            client_data_json,
            encoded,
        })
    }
}

impl Write for TransactionSignature {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(self.as_ref());
    }
}

impl Read for TransactionSignature {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        if buf.remaining() < 1 + SIGNATURE_BYTES {
            return Err(Error::EndOfBuffer);
        }

        let scheme = u8::read(buf)?;
        match scheme {
            ED25519_SCHEME => {
                let signature = ed25519::Signature::read(buf)?;
                let mut encoded = [0; ED25519_SIGNATURE_BYTES];
                encoded[0] = ED25519_SCHEME;
                encoded[1..].copy_from_slice(signature.as_ref());
                Ok(Self::Ed25519 { signature, encoded })
            }
            SECP256R1_SCHEME => {
                let signature = secp256r1::Signature::read(buf)?;
                let authenticator_data_len = u16::read(buf)? as usize;
                if authenticator_data_len > WEBAUTHN_AUTHENTICATOR_DATA_BYTES {
                    return Err(Error::Invalid(
                        "TransactionSignature",
                        "authenticator data too large",
                    ));
                }
                if buf.remaining() < authenticator_data_len + u16::SIZE {
                    return Err(Error::EndOfBuffer);
                }
                let authenticator_data = buf.copy_to_bytes(authenticator_data_len).to_vec();

                let client_data_json_len = u16::read(buf)? as usize;
                if client_data_json_len > WEBAUTHN_CLIENT_DATA_JSON_BYTES {
                    return Err(Error::Invalid(
                        "TransactionSignature",
                        "client data JSON too large",
                    ));
                }
                if buf.remaining() < client_data_json_len {
                    return Err(Error::EndOfBuffer);
                }
                let client_data_json = buf.copy_to_bytes(client_data_json_len).to_vec();

                let mut encoded = Vec::with_capacity(
                    1 + SIGNATURE_BYTES
                        + u16::SIZE
                        + authenticator_data.len()
                        + u16::SIZE
                        + client_data_json.len(),
                );
                encoded.push(SECP256R1_SCHEME);
                encoded.extend_from_slice(signature.as_ref());
                (authenticator_data.len() as u16).write(&mut encoded);
                encoded.extend_from_slice(&authenticator_data);
                (client_data_json.len() as u16).write(&mut encoded);
                encoded.extend_from_slice(&client_data_json);

                Ok(Self::Secp256r1 {
                    signature,
                    authenticator_data,
                    client_data_json,
                    encoded,
                })
            }
            _ => Err(Error::Invalid("TransactionSignature", "unknown scheme")),
        }
    }
}

impl EncodeSize for TransactionSignature {
    fn encode_size(&self) -> usize {
        self.as_ref().len()
    }
}

impl AsRef<[u8]> for TransactionSignature {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Ed25519 { encoded, .. } => encoded,
            Self::Secp256r1 { encoded, .. } => encoded,
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

/// Verifies mixed transaction signatures with separate scheme groups.
pub struct TransactionBatchVerifier {
    ed25519: ed25519::Batch,
    secp256r1: Vec<Secp256r1Item>,
}

struct Secp256r1Item {
    message: Vec<u8>,
    verifying_key: VerifyingKey,
    signature: secp256r1::Signature,
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
}

impl TransactionBatchVerifier {
    /// Creates an empty transaction batch verifier with capacity for at least
    /// `capacity` signatures.
    pub fn new(capacity: usize) -> Self {
        Self {
            ed25519: ed25519::Batch::new(capacity),
            secp256r1: Vec::new(),
        }
    }

    /// Adds a transaction signature to the appropriate verification group.
    ///
    /// The sender public key must already be decompressed (see
    /// [`PublicKeyCache::decompress`](crate::PublicKeyCache::decompress)),
    /// which lets batch callers resolve keys in parallel before queueing.
    /// Returns `false` if the key and signature schemes do not match.
    pub fn add(
        &mut self,
        namespace: &[u8],
        message: &[u8],
        key: &DecompressedPublicKey,
        signature: &TransactionSignature,
    ) -> bool {
        match (key, signature) {
            (
                DecompressedPublicKey::Ed25519(key),
                TransactionSignature::Ed25519 { signature, .. },
            ) => self.ed25519.add(namespace, message, key, signature),
            (
                DecompressedPublicKey::Secp256r1(verifying_key),
                TransactionSignature::Secp256r1 {
                    signature,
                    authenticator_data,
                    client_data_json,
                    ..
                },
            ) => {
                self.secp256r1.push(Secp256r1Item {
                    message: message.to_vec(),
                    verifying_key: *verifying_key,
                    signature: signature.clone(),
                    authenticator_data: authenticator_data.clone(),
                    client_data_json: client_data_json.clone(),
                });
                true
            }
            _ => false,
        }
    }

    /// Verifies every queued signature.
    pub fn verify<R: CryptoRng>(self, rng: &mut R, strategy: &impl Strategy) -> bool {
        if !self.ed25519.verify(rng, strategy) {
            return false;
        }

        verify_secp256r1(strategy, self.secp256r1)
    }
}

impl Default for TransactionBatchVerifier {
    fn default() -> Self {
        Self::new(0)
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
                && verify_webauthn_assertion(
                    &item.verifying_key,
                    &item.message,
                    &item.signature,
                    &item.authenticator_data,
                    &item.client_data_json,
                )
        },
        |left, right| left && right,
    )
}

fn verify_webauthn_assertion(
    verifying_key: &VerifyingKey,
    challenge: &[u8],
    signature: &secp256r1::Signature,
    authenticator_data: &[u8],
    client_data_json: &[u8],
) -> bool {
    if authenticator_data.len() < 37 {
        return false;
    }
    if authenticator_data[32] & WEBAUTHN_USER_VERIFIED_FLAG == 0 {
        return false;
    }

    let Ok(client_data) = serde_json::from_slice::<serde_json::Value>(client_data_json) else {
        return false;
    };
    if client_data.get("type").and_then(serde_json::Value::as_str) != Some("webauthn.get") {
        return false;
    }
    if client_data
        .get("challenge")
        .and_then(serde_json::Value::as_str)
        != Some(base64_url_no_pad(challenge).as_str())
    {
        return false;
    }

    let client_data_hash = sha256::Sha256::hash(client_data_json);
    let mut payload =
        Vec::with_capacity(authenticator_data.len() + client_data_hash.as_ref().len());
    payload.extend_from_slice(authenticator_data);
    payload.extend_from_slice(client_data_hash.as_ref());
    verify_raw_secp256r1(verifying_key, &payload, signature)
}

fn verify_raw_secp256r1(
    verifying_key: &VerifyingKey,
    payload: &[u8],
    signature: &secp256r1::Signature,
) -> bool {
    let Ok(signature) = P256Signature::from_slice(signature.as_ref()) else {
        return false;
    };
    verifying_key.verify(payload, &signature).is_ok()
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);

        out.push(ALPHABET[(first >> 2) as usize] as char);
        out.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(third & 0x3f) as usize] as char);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PublicKeyCache;
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::{Hasher, Signer as _, sha256};
    use commonware_formatting::from_hex;
    use commonware_math::algebra::Random as _;
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::{NZUsize, test_rng};
    use p256::{
        ecdsa::{SigningKey, signature::Signer as _},
        elliptic_curve::Generate as _,
    };

    const NAMESPACE: &[u8] = b"constantinople-tx";

    #[test]
    fn public_key_codec_carries_scheme_byte() {
        let signer = secp256r1::PrivateKey::random(test_rng());
        let key = TransactionPublicKey::secp256r1(signer.public_key());
        let encoded = key.encode();

        assert_eq!(encoded[0], SECP256R1_SCHEME);
        assert_eq!(TransactionPublicKey::decode(encoded.as_ref()).unwrap(), key);
    }

    #[test]
    fn signature_codec_carries_scheme_byte() {
        let signer = ed25519::PrivateKey::random(test_rng());
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
        deterministic::Runner::default().start(|context| async move {
            let cache = PublicKeyCache::new(context, NZUsize!(16));
            let ed25519 = ed25519::PrivateKey::random(test_rng());
            let ed_message = sha256::Sha256::hash(b"ed25519").to_vec();
            let r1_message = sha256::Sha256::hash(b"secp256r1").to_vec();
            let (r1_public_key, r1_signature) = webauthn_signature(&r1_message);

            let ed_public_key = TransactionPublicKey::ed25519(ed25519.public_key());
            let keys = cache
                .decompress(&[&ed_public_key, &r1_public_key], &Sequential)
                .expect("valid keys");

            let mut verifier = TransactionBatchVerifier::new(1);
            assert!(verifier.add(
                NAMESPACE,
                &ed_message,
                &keys[0],
                &TransactionSignature::ed25519(ed25519.sign(NAMESPACE, &ed_message)),
            ));
            assert!(verifier.add(NAMESPACE, &r1_message, &keys[1], &r1_signature));

            assert!(verifier.verify(&mut test_rng(), &Sequential));

            // Both keys were decompressed through the shared cache.
            assert_eq!(cache.len(), 2);
        });
    }

    #[test]
    fn mixed_batch_verifier_rejects_scheme_mismatch() {
        deterministic::Runner::default().start(|context| async move {
            let cache = PublicKeyCache::new(context, NZUsize!(16));
            let ed25519 = ed25519::PrivateKey::random(test_rng());
            let message = sha256::Sha256::hash(b"message").to_vec();
            let (_, signature) = webauthn_signature(&message);

            let public_key = TransactionPublicKey::ed25519(ed25519.public_key());
            let key = &cache
                .decompress(&[&public_key], &Sequential)
                .expect("valid ed25519 key")[0];

            let mut verifier = TransactionBatchVerifier::new(1);
            assert!(!verifier.add(NAMESPACE, &message, key, &signature));
        });
    }

    #[test]
    fn webauthn_signature_rejects_wrong_challenge() {
        deterministic::Runner::default().start(|context| async move {
            let cache = PublicKeyCache::new(context, NZUsize!(16));
            let message = sha256::Sha256::hash(b"message").to_vec();
            let wrong_message = sha256::Sha256::hash(b"wrong").to_vec();
            let (public_key, signature) = webauthn_signature(&wrong_message);
            let key = &cache
                .decompress(&[&public_key], &Sequential)
                .expect("valid r1 key")[0];

            let mut verifier = TransactionBatchVerifier::new(1);
            assert!(verifier.add(NAMESPACE, &message, key, &signature));
            assert!(!verifier.verify(&mut test_rng(), &Sequential));
        });
    }

    #[test]
    fn webauthn_signature_rejects_missing_user_verification() {
        deterministic::Runner::default().start(|context| async move {
            let cache = PublicKeyCache::new(context, NZUsize!(16));
            let message = sha256::Sha256::hash(b"message").to_vec();
            let (public_key, mut signature) = webauthn_signature(&message);
            let TransactionSignature::Secp256r1 {
                signature: inner,
                mut authenticator_data,
                client_data_json,
                ..
            } = signature
            else {
                unreachable!("helper should create r1 signature");
            };
            authenticator_data[32] = 0;
            signature =
                TransactionSignature::secp256r1(inner, authenticator_data, client_data_json)
                    .unwrap();
            let key = &cache
                .decompress(&[&public_key], &Sequential)
                .expect("valid r1 key")[0];

            let mut verifier = TransactionBatchVerifier::new(1);
            assert!(verifier.add(NAMESPACE, &message, key, &signature));
            assert!(!verifier.verify(&mut test_rng(), &Sequential));
        });
    }

    #[test]
    fn webauthn_verifier_checks_raw_browser_signature_payload() {
        let public_key = secp256r1::PublicKey::decode(
            from_hex("03e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let verifying_key = VerifyingKey::from_sec1_bytes(public_key.as_ref()).unwrap();
        let signature = secp256r1::Signature::decode(
            from_hex(
                "bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f\
                 17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c",
            )
            .unwrap()
            .as_slice(),
        )
        .unwrap();
        let message = from_hex(
            "e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45f\
             d75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217\
             ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce\
             470a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3",
        )
        .unwrap();

        assert!(verify_raw_secp256r1(&verifying_key, &message, &signature));
    }

    #[test]
    fn webauthn_verification_populates_and_reuses_cache() {
        deterministic::Runner::default().start(|context| async move {
            let cache = PublicKeyCache::new(context, NZUsize!(16));
            let message = sha256::Sha256::hash(b"secp256r1").to_vec();
            let (public_key, signature) = webauthn_signature(&message);

            let key = &cache
                .decompress(&[&public_key], &Sequential)
                .expect("valid r1 key")[0];
            let mut verifier = TransactionBatchVerifier::new(1);
            assert!(verifier.add(NAMESPACE, &message, key, &signature));
            assert!(verifier.verify(&mut test_rng(), &Sequential));
            assert_eq!(cache.len(), 1);
            assert!(cache.contains(&public_key));

            // A second verification of the same key reuses the cached decompression.
            let key = &cache
                .decompress(&[&public_key], &Sequential)
                .expect("valid r1 key")[0];
            let mut verifier = TransactionBatchVerifier::new(1);
            assert!(verifier.add(NAMESPACE, &message, key, &signature));
            assert!(verifier.verify(&mut test_rng(), &Sequential));
            assert_eq!(cache.len(), 1);
        });
    }

    fn webauthn_signature(challenge: &[u8]) -> (TransactionPublicKey, TransactionSignature) {
        let mut authenticator_data = vec![0; 37];
        authenticator_data[32] = WEBAUTHN_USER_VERIFIED_FLAG;
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}"}}"#,
            base64_url_no_pad(challenge)
        )
        .into_bytes();
        let client_data_hash = sha256::Sha256::hash(&client_data_json);
        let mut payload =
            Vec::with_capacity(authenticator_data.len() + client_data_hash.as_ref().len());
        payload.extend_from_slice(&authenticator_data);
        payload.extend_from_slice(client_data_hash.as_ref());

        let signer = SigningKey::generate_from_rng(&mut test_rng());
        let public_key = TransactionPublicKey::secp256r1(
            secp256r1::PublicKey::decode(signer.verifying_key().to_sec1_point(true).as_bytes())
                .unwrap(),
        );
        let raw_signature: p256::ecdsa::Signature = signer.sign(&payload);
        let raw_signature = raw_signature.normalize_s();
        let signature = secp256r1::Signature::decode(raw_signature.to_bytes().as_slice()).unwrap();
        let signature =
            TransactionSignature::secp256r1(signature, authenticator_data, client_data_json)
                .unwrap();

        (public_key, signature)
    }
}
