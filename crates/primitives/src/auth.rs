//! Transaction account keys and signatures.

use crate::{PublicKeyCache, SignedTransaction};
use bytes::BufMut;
use commonware_codec::{Buf, Copying, EncodeSize, Error, FixedSize, Read, ReadExt as _, Write};
use commonware_cryptography::{
    BatchEntry, BatchVerifier, Hasher, secp256r1::standard as secp256r1, sha256,
};
use commonware_cryptography_curve25519::signing as ed25519;
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
/// scheme's compressed public key bytes. Ed25519 keys are padded with
/// one trailing zero byte to keep this type compatible with Commonware's
/// fixed-size public-key traits.
///
/// Decoding is intentionally cheap: it validates only the scheme byte and (for
/// Ed25519) the trailing padding. Point decompression is deferred to signature
/// verification. Ed25519 batch verification decompresses each distinct key
/// once per batch, and secp256r1 keys are served from a shared
/// [`PublicKeyCache`] so a recurring sender's key is decompressed at most once
/// while it stays cached. A key that is not a curve point fails verification.
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
    pub fn ed25519(key: ed25519::VerifyingKey) -> Self {
        let mut encoded = [0; Self::SIZE];
        encoded[0] = ED25519_SCHEME;
        encoded[1..1 + ed25519::VerifyingKey::SIZE].copy_from_slice(key.as_ref());
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
                if encoded[1 + ed25519::VerifyingKey::SIZE..]
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

impl From<ed25519::VerifyingKey> for TransactionPublicKey {
    fn from(key: ed25519::VerifyingKey) -> Self {
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

/// Verifies the signatures of every transaction yielded by `transaction`.
///
/// Every Ed25519 signature is checked in one randomized batch on `strategy`.
/// The batch verifier groups signers by their raw key encoding and
/// decompresses each distinct key once, so Ed25519 keys are passed through
/// as encoded rather than resolved through `cache`. Secp256r1 (WebAuthn)
/// signatures are checked individually against keys resolved through
/// `cache`.
///
/// `rng` seeds the batch's random coefficients and must be unpredictable to
/// whoever assembled `items`.
///
/// Returns `false` if any item fails to decode, pairs a key with a signature
/// of another scheme, or carries an invalid signature.
pub(crate) fn verify_signatures<T, H>(
    namespace: &[u8],
    rng: &mut impl CryptoRng,
    cache: &PublicKeyCache,
    items: &[T],
    transaction: impl Fn(&T) -> Option<&SignedTransaction<H>> + Sync,
    strategy: &impl Strategy,
) -> bool
where
    T: Sync,
    H: Hasher,
{
    // Batch entries borrow a verifying key, which the transaction encoding
    // does not hold, so the Ed25519 keys are copied out in item order.
    let mut ed25519_keys = Vec::with_capacity(items.len());
    let mut secp256r1 = Vec::new();
    for item in items {
        let Some(transaction) = transaction(item) else {
            return false;
        };
        let Some(sender) = transaction.value().sender() else {
            return false;
        };
        match (sender, transaction.signature()) {
            (TransactionPublicKey::Ed25519 { encoded }, TransactionSignature::Ed25519 { .. }) => {
                ed25519_keys.push(ed25519_key(encoded));
            }
            (TransactionPublicKey::Secp256r1 { .. }, TransactionSignature::Secp256r1 { .. }) => {
                secp256r1.push(transaction);
            }
            _ => return false,
        }
    }

    // Batch verification rejects empty input, so a batch without Ed25519
    // signatures skips it. When every item is Ed25519, entries are projected
    // straight from `items`.
    let ed25519_valid = if ed25519_keys.is_empty() {
        true
    } else if secp256r1.is_empty() {
        ed25519::VerifyingKey::verify_batch(
            rng,
            items,
            |index, item| {
                let transaction = transaction(item).expect("every item decoded above");
                ed25519_entry(namespace, transaction, &ed25519_keys[index])
            },
            strategy,
        )
    } else {
        let transactions: Vec<_> = items
            .iter()
            .filter_map(&transaction)
            .filter(|transaction| {
                matches!(
                    transaction.signature(),
                    TransactionSignature::Ed25519 { .. }
                )
            })
            .collect();
        ed25519::VerifyingKey::verify_batch(
            rng,
            &transactions,
            |index, transaction| ed25519_entry(namespace, transaction, &ed25519_keys[index]),
            strategy,
        )
    };
    ed25519_valid && verify_secp256r1(cache, &secp256r1, strategy)
}

/// Returns the Ed25519 key held by an Ed25519 transaction public key encoding.
///
/// Every 32-byte string decodes; an encoding that is not a curve point fails
/// signature verification instead.
fn ed25519_key(encoded: &[u8; TransactionPublicKey::SIZE]) -> ed25519::VerifyingKey {
    ed25519::VerifyingKey::read(&mut Copying(&encoded[1..1 + ed25519::VerifyingKey::SIZE]))
        .expect("Ed25519 verifying keys decode from any 32 bytes")
}

fn ed25519_entry<'a, H: Hasher>(
    namespace: &'a [u8],
    transaction: &'a SignedTransaction<H>,
    key: &'a ed25519::VerifyingKey,
) -> BatchEntry<'a, ed25519::VerifyingKey> {
    let TransactionSignature::Ed25519 { signature, .. } = transaction.signature() else {
        unreachable!("only Ed25519 signatures are batched");
    };
    BatchEntry {
        namespace,
        message: transaction.message_digest().as_ref(),
        public_key: key,
        signature,
    }
}

/// Verifies secp256r1 WebAuthn assertions, whose challenge is the signed
/// transaction digest.
fn verify_secp256r1<H: Hasher>(
    cache: &PublicKeyCache,
    transactions: &[&SignedTransaction<H>],
    strategy: &impl Strategy,
) -> bool {
    if transactions.is_empty() {
        return true;
    }

    let senders: Vec<_> = transactions
        .iter()
        .map(|transaction| transaction.value().sender().expect("sender decoded"))
        .collect();
    let Some(keys) = cache.decompress(&senders, strategy) else {
        return false;
    };
    strategy.fold(
        transactions.iter().zip(&keys),
        || true,
        |valid, (transaction, key)| {
            let TransactionSignature::Secp256r1 {
                signature,
                authenticator_data,
                client_data_json,
                ..
            } = transaction.signature()
            else {
                unreachable!("only secp256r1 signatures are queued");
            };
            valid
                && verify_webauthn_assertion(
                    key,
                    transaction.message_digest().as_ref(),
                    signature,
                    authenticator_data,
                    client_data_json,
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

    let client_data_hash = sha256::Sha256::hash(&[client_data_json]);
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
pub(crate) mod tests {
    use super::*;
    use crate::{Sealable as _, Transaction, verify_transactions};
    use commonware_codec::{Copying, DecodeExt as _, Encode as _};
    use commonware_cryptography::{Signer as _, sha256::Sha256};
    use commonware_formatting::from_hex;
    use commonware_math::algebra::Random as _;
    use commonware_parallel::{Rayon, Sequential};
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::{NZUsize, test_rng};
    use core::num::NonZeroU64;
    use p256::{
        ecdsa::{SigningKey, signature::Signer as _},
        elliptic_curve::Generate as _,
    };

    const NAMESPACE: &[u8] = b"constantinople-tx";

    /// The Ed25519 encoding of `y = 2`, which is not the `y` coordinate of
    /// any curve point.
    const NOT_A_POINT: [u8; 32] = {
        let mut bytes = [0; 32];
        bytes[0] = 2;
        bytes
    };

    pub(crate) fn ed25519_signer(seed: u64) -> ed25519::SigningKey {
        <ed25519::SigningKey as commonware_cryptography::Signer>::from_seed(seed)
    }

    fn unsigned(
        sender: TransactionPublicKey,
        nonce: u64,
    ) -> Transaction<<Sha256 as Hasher>::Digest> {
        Transaction::new(
            sender.clone(),
            sender,
            NonZeroU64::new(1).expect("non-zero"),
            nonce,
        )
    }

    pub(crate) fn ed25519_transaction(
        signer: &ed25519::SigningKey,
        nonce: u64,
    ) -> SignedTransaction<Sha256> {
        unsigned(TransactionPublicKey::ed25519(signer.public_key()), nonce).seal_and_sign(
            signer,
            NAMESPACE,
            &mut Sha256::default(),
        )
    }

    /// Replaces the transaction's signature with `signature`.
    fn resign(
        transaction: &SignedTransaction<Sha256>,
        signature: TransactionSignature,
    ) -> SignedTransaction<Sha256> {
        SignedTransaction::new_unchecked(transaction.inner().clone(), signature)
    }

    /// Re-signs the transaction with `signer` over a different message.
    fn forge(
        transaction: &SignedTransaction<Sha256>,
        signer: &ed25519::SigningKey,
    ) -> SignedTransaction<Sha256> {
        resign(
            transaction,
            TransactionSignature::ed25519(signer.sign(NAMESPACE, b"another message")),
        )
    }

    pub(crate) fn webauthn_signer(seed: u8) -> SigningKey {
        let mut rng = test_rng();
        for _ in 0..seed {
            let _ = SigningKey::generate_from_rng(&mut rng);
        }
        SigningKey::generate_from_rng(&mut rng)
    }

    fn webauthn_public_key(signer: &SigningKey) -> TransactionPublicKey {
        TransactionPublicKey::secp256r1(
            secp256r1::PublicKey::decode(Copying(
                signer.verifying_key().to_sec1_point(true).as_bytes(),
            ))
            .unwrap(),
        )
    }

    fn webauthn_signature_with(
        signer: &SigningKey,
        challenge: &[u8],
        mut authenticator_data: Vec<u8>,
    ) -> TransactionSignature {
        if authenticator_data.is_empty() {
            authenticator_data = vec![0; 37];
            authenticator_data[32] = WEBAUTHN_USER_VERIFIED_FLAG;
        }
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}"}}"#,
            base64_url_no_pad(challenge)
        )
        .into_bytes();
        let client_data_hash = sha256::Sha256::hash(&[client_data_json.as_ref()]);
        let mut payload = authenticator_data.clone();
        payload.extend_from_slice(client_data_hash.as_ref());

        let raw_signature: p256::ecdsa::Signature = signer.sign(&payload);
        let raw_signature = raw_signature.normalize_s();
        let signature =
            secp256r1::Signature::decode(Copying(raw_signature.to_bytes().as_slice())).unwrap();
        TransactionSignature::secp256r1(signature, authenticator_data, client_data_json).unwrap()
    }

    pub(crate) fn webauthn_transaction(
        signer: &SigningKey,
        nonce: u64,
    ) -> SignedTransaction<Sha256> {
        let sealed = unsigned(webauthn_public_key(signer), nonce).seal(&mut Sha256::default());
        let signature = webauthn_signature_with(signer, sealed.seal().as_ref(), Vec::new());
        SignedTransaction::new_unchecked(sealed, signature)
    }

    /// Verifies `transactions` on a fresh cache, sequentially and on a
    /// multi-worker pool, and checks that both agree.
    fn verify(transactions: &[SignedTransaction<Sha256>]) -> bool {
        deterministic::Runner::default().start(|context| async move {
            let cache = PublicKeyCache::new(context, NZUsize!(16));
            let rayon = Rayon::new(NZUsize!(4)).unwrap();
            let sequential = verify_transactions(
                NAMESPACE,
                &mut test_rng(),
                &cache,
                transactions,
                &Sequential,
            );
            let parallel =
                verify_transactions(NAMESPACE, &mut test_rng(), &cache, transactions, &rayon);
            assert_eq!(sequential, parallel);
            sequential
        })
    }

    #[test]
    fn public_key_codec_carries_scheme_byte() {
        let signer = secp256r1::PrivateKey::random(test_rng());
        let key = TransactionPublicKey::secp256r1(signer.public_key());
        let encoded = key.encode();

        assert_eq!(encoded[0], SECP256R1_SCHEME);
        assert_eq!(TransactionPublicKey::decode(encoded).unwrap(), key);
    }

    #[test]
    fn signature_codec_carries_scheme_byte() {
        let signer = ed25519::SigningKey::random(test_rng());
        let signature = TransactionSignature::ed25519(signer.sign(NAMESPACE, b"hello"));
        let encoded = signature.encode();

        assert_eq!(encoded[0], ED25519_SCHEME);
        assert_eq!(TransactionSignature::decode(encoded).unwrap(), signature);
    }

    #[test]
    fn empty_batch_is_valid() {
        assert!(verify(&[]));
    }

    #[test]
    fn ed25519_batch_with_distinct_and_repeated_signers() {
        let signers: Vec<_> = (0..3).map(ed25519_signer).collect();
        let transactions: Vec<_> = (0..12)
            .map(|nonce| ed25519_transaction(&signers[nonce as usize % 3], nonce))
            .collect();
        assert!(verify(&transactions));
        assert!(verify(&transactions[..1]));

        // One signer for every transaction.
        let repeated: Vec<_> = (0..8)
            .map(|nonce| ed25519_transaction(&signers[0], nonce))
            .collect();
        assert!(verify(&repeated));
    }

    #[test]
    fn ed25519_batch_rejects_invalid_signature_at_any_position() {
        let signers: Vec<_> = (0..3).map(ed25519_signer).collect();
        let transactions: Vec<_> = (0..9)
            .map(|nonce| ed25519_transaction(&signers[nonce as usize % 3], nonce))
            .collect();
        for position in [0, 4, 8] {
            let mut batch = transactions.clone();
            batch[position] = forge(&batch[position], &signers[position % 3]);
            assert!(!verify(&batch), "invalid signature at {position}");
        }
    }

    #[test]
    fn mixed_batch_accepts_both_schemes() {
        let ed25519 = ed25519_signer(0);
        let webauthn = webauthn_signer(0);
        let transactions = vec![
            ed25519_transaction(&ed25519, 0),
            webauthn_transaction(&webauthn, 1),
            ed25519_transaction(&ed25519, 2),
            ed25519_transaction(&ed25519_signer(1), 3),
            webauthn_transaction(&webauthn_signer(1), 4),
            ed25519_transaction(&ed25519, 5),
        ];
        assert!(verify(&transactions));
    }

    #[test]
    fn mixed_batch_rejects_invalid_signature_at_any_position() {
        let ed25519 = ed25519_signer(0);
        let webauthn = webauthn_signer(0);
        let transactions = vec![
            ed25519_transaction(&ed25519, 0),
            webauthn_transaction(&webauthn, 1),
            ed25519_transaction(&ed25519, 2),
            webauthn_transaction(&webauthn, 3),
            ed25519_transaction(&ed25519, 4),
        ];
        for position in [0, 2, 4] {
            let mut batch = transactions.clone();
            batch[position] = forge(&batch[position], &ed25519);
            assert!(!verify(&batch), "invalid Ed25519 signature at {position}");
        }

        // A WebAuthn assertion over another transaction's digest.
        let mut batch = transactions;
        batch[3] = resign(&batch[3], batch[1].signature().clone());
        assert!(!verify(&batch));
    }

    #[test]
    fn secp256r1_only_batch_skips_ed25519_verification() {
        let transactions = vec![
            webauthn_transaction(&webauthn_signer(0), 0),
            webauthn_transaction(&webauthn_signer(1), 1),
        ];
        assert!(verify(&transactions));
    }

    #[test]
    fn undecodable_ed25519_key_fails_verification() {
        let mut encoded = [0; TransactionPublicKey::SIZE];
        encoded[1..1 + ed25519::VerifyingKey::SIZE].copy_from_slice(&NOT_A_POINT);
        let sender = TransactionPublicKey::decode(Copying(&encoded[..]))
            .expect("Ed25519 key decoding does not validate the point");

        let signer = ed25519_signer(0);
        let sealed = unsigned(sender, 0).seal(&mut Sha256::default());
        let signature =
            TransactionSignature::ed25519(signer.sign(NAMESPACE, sealed.seal().as_ref()));
        let invalid = SignedTransaction::new_unchecked(sealed, signature);
        assert!(!verify(core::slice::from_ref(&invalid)));

        let valid = ed25519_transaction(&signer, 1);
        assert!(!verify(&[valid.clone(), invalid.clone(), valid]));
        assert!(!verify(&[
            invalid,
            webauthn_transaction(&webauthn_signer(0), 2)
        ]));
    }

    #[test]
    fn non_canonical_ed25519_scalar_is_rejected() {
        // The group order L, little-endian.
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let signer = ed25519_signer(0);
        let valid = ed25519_transaction(&signer, 0);
        let TransactionSignature::Ed25519 { signature, .. } = valid.signature() else {
            unreachable!("Ed25519 transaction");
        };

        // Encode the same scalar as `s + L`, which still fits in 32 bytes.
        let mut bytes: [u8; 64] = signature.as_ref().try_into().unwrap();
        let mut carry = 0u16;
        for (byte, l) in bytes[32..].iter_mut().zip(L) {
            let sum = u16::from(*byte) + u16::from(l) + carry;
            *byte = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0);
        let malleated = TransactionSignature::decode(Copying(
            &[&[ED25519_SCHEME][..], &bytes[..]].concat()[..],
        ))
        .expect("signatures decode from any 64 bytes");

        let other = ed25519_transaction(&ed25519_signer(1), 1);
        assert!(verify(&[valid.clone(), other.clone()]));
        assert!(!verify(&[resign(&valid, malleated), other]));
    }

    #[test]
    fn ed25519_batch_rejects_wrong_namespace() {
        let signer = ed25519_signer(0);
        let valid = ed25519_transaction(&signer, 0);
        let wrong_namespace = resign(
            &valid,
            TransactionSignature::ed25519(
                signer.sign(b"other-namespace", valid.message_digest().as_ref()),
            ),
        );
        assert!(!verify(core::slice::from_ref(&wrong_namespace)));
        assert!(!verify(&[ed25519_transaction(&signer, 1), wrong_namespace]));
    }

    #[test]
    fn batch_rejects_scheme_mismatch() {
        let ed25519 = ed25519_transaction(&ed25519_signer(0), 0);
        let webauthn = webauthn_transaction(&webauthn_signer(0), 1);
        assert!(!verify(&[resign(&ed25519, webauthn.signature().clone())]));
        assert!(!verify(&[resign(&webauthn, ed25519.signature().clone())]));
    }

    #[test]
    fn webauthn_signature_rejects_wrong_challenge() {
        let signer = webauthn_signer(0);
        let transaction = webauthn_transaction(&signer, 0);
        let signature = webauthn_signature_with(&signer, b"wrong challenge", Vec::new());
        assert!(!verify(&[resign(&transaction, signature)]));
    }

    #[test]
    fn webauthn_signature_rejects_missing_user_verification() {
        let signer = webauthn_signer(0);
        let transaction = webauthn_transaction(&signer, 0);
        let signature =
            webauthn_signature_with(&signer, transaction.message_digest().as_ref(), vec![0; 37]);
        assert!(!verify(&[resign(&transaction, signature)]));
    }

    // The challenge and flags are valid, so only the P-256 signature check
    // rejects the assertion.
    #[test]
    fn webauthn_signature_rejects_wrong_signer() {
        let transaction = webauthn_transaction(&webauthn_signer(0), 0);
        let signature = webauthn_signature_with(
            &webauthn_signer(1),
            transaction.message_digest().as_ref(),
            Vec::new(),
        );
        let forged = resign(&transaction, signature);
        assert!(!verify(core::slice::from_ref(&forged)));
        assert!(!verify(&[
            ed25519_transaction(&ed25519_signer(0), 1),
            forged
        ]));
    }

    #[test]
    fn webauthn_verifier_checks_raw_browser_signature_payload() {
        let public_key = secp256r1::PublicKey::decode(
            from_hex("03e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c").unwrap(),
        )
        .unwrap();
        let verifying_key = VerifyingKey::from_sec1_bytes(public_key.as_ref()).unwrap();
        let signature = secp256r1::Signature::decode(
            from_hex(
                "bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f\
                 17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c",
            )
            .unwrap(),
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

    /// Only secp256r1 senders populate the cache; Ed25519 senders are batch
    /// verified from their raw encodings.
    #[test]
    fn verification_caches_only_secp256r1_keys() {
        deterministic::Runner::default().start(|context| async move {
            let cache = PublicKeyCache::new(context, NZUsize!(16));
            let webauthn = webauthn_signer(0);
            let transactions = vec![
                ed25519_transaction(&ed25519_signer(0), 0),
                webauthn_transaction(&webauthn, 1),
            ];
            for _ in 0..2 {
                assert!(verify_transactions(
                    NAMESPACE,
                    &mut test_rng(),
                    &cache,
                    &transactions,
                    &Sequential
                ));
                assert_eq!(cache.len(), 1);
                assert!(cache.contains(&webauthn_public_key(&webauthn)));
            }
        });
    }
}
