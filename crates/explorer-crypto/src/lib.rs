//! Browser crypto bindings for the explorer.

use commonware_codec::{DecodeExt as _, Read as _, ReadExt as _};
use commonware_consensus::{
    simplex::{scheme::bls12381_threshold::standard as threshold_standard, types::Finalization},
    types::coding::Commitment,
};
use commonware_cryptography::{
    Sha256, Signer as _,
    bls12381::primitives::{
        sharing::{ModeVersion, Sharing},
        variant::{MinSig, Variant},
    },
    certificate::Scheme as _,
    ed25519, sha256,
};
use commonware_parallel::Sequential;
use constantinople_primitives::{Block, BlockCfg, Sealed};
use core::num::NonZeroU32;
use js_sys::{BigInt, Object, Reflect, Uint8Array};
use rand::{SeedableRng as _, rngs::StdRng};
use wasm_bindgen::prelude::*;

const ED25519_PRIVATE_KEY_BYTES: usize = 32;
const CONSENSUS_NAMESPACE: &[u8] = b"constantinople_CONSENSUS";
const MAX_SIMPLEX_PARTICIPANTS: u32 = 10_000;

type ConsensusScheme = threshold_standard::Scheme<ed25519::PublicKey, MinSig>;
type ChainBlock = Sealed<Block<Commitment, ed25519::PublicKey, Sha256>, Sha256>;

/// A Constantinople Ed25519 account key.
#[wasm_bindgen]
pub struct ChainKey {
    private_key: ed25519::PrivateKey,
}

#[wasm_bindgen]
impl ChainKey {
    /// Builds an account key from 32 private-key bytes.
    #[wasm_bindgen(js_name = fromSeed)]
    pub fn from_seed(seed: &[u8]) -> Result<Self, JsError> {
        if seed.len() != ED25519_PRIVATE_KEY_BYTES {
            return Err(JsError::new("Ed25519 seed must be 32 bytes"));
        }

        let private_key = ed25519::PrivateKey::decode(seed)
            .map_err(|error| JsError::new(&format!("invalid Ed25519 seed: {error}")))?;
        Ok(Self { private_key })
    }

    /// Returns the public key bytes for this account.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.private_key.public_key().as_ref().to_vec()
    }

    /// Signs `message` with Commonware's namespaced Ed25519 signer.
    pub fn sign(&self, namespace: &[u8], message: &[u8]) -> Vec<u8> {
        self.private_key.sign(namespace, message).as_ref().to_vec()
    }
}

/// Verifies a Simplex finalization and returns its certified transaction root.
#[wasm_bindgen(js_name = verifyFinalization)]
pub fn verify_finalization(
    verification_material: &[u8],
    finalized_artifact: &[u8],
) -> Result<JsValue, JsError> {
    let identity = simplex_identity(verification_material)?;

    let scheme = ConsensusScheme::certificate_verifier(CONSENSUS_NAMESPACE, identity);
    let mut reader = finalized_artifact;
    let proof = Finalization::<ConsensusScheme, Commitment>::read_cfg(
        &mut reader,
        &scheme.certificate_codec_config(),
    )
    .map_err(|error| JsError::new(&format!("failed to decode finalization proof: {error}")))?;
    let mut rng = StdRng::seed_from_u64(0);
    if !proof.verify(&mut rng, &scheme, &Sequential) {
        return Err(JsError::new("finalization certificate verification failed"));
    }

    let commitment = Commitment::read(&mut reader).map_err(|error| {
        JsError::new(&format!("failed to decode certified commitment: {error}"))
    })?;
    if proof.proposal.payload != commitment {
        return Err(JsError::new(
            "finalization payload does not match certified commitment",
        ));
    }

    let block = ChainBlock::read_cfg(&mut reader, &BlockCfg::default())
        .map_err(|error| JsError::new(&format!("failed to decode finalized block: {error}")))?;
    if !reader.is_empty() {
        return Err(JsError::new("finalized artifact contains trailing bytes"));
    }
    if commitment.block::<sha256::Digest>() != *block.seal() {
        return Err(JsError::new(
            "certified commitment does not match finalized block digest",
        ));
    }

    let result = Object::new();
    set(&result, "height", BigInt::from(block.header.height).into())?;
    set(
        &result,
        "view",
        BigInt::from(proof.proposal.round.view().get()).into(),
    )?;
    set(
        &result,
        "transactionsRoot",
        Uint8Array::from(block.header.transactions_root.as_ref()).into(),
    )?;
    set(
        &result,
        "transactionsStart",
        BigInt::from(block.header.transactions_range.start()).into(),
    )?;
    set(
        &result,
        "transactionsTip",
        BigInt::from(block.header.transactions_range.end()).into(),
    )?;
    set(
        &result,
        "stateRoot",
        Uint8Array::from(block.header.state_root.as_ref()).into(),
    )?;
    set(
        &result,
        "stateStart",
        BigInt::from(block.header.state_range.start()).into(),
    )?;
    set(
        &result,
        "stateTip",
        BigInt::from(block.header.state_range.end()).into(),
    )?;
    set(
        &result,
        "blockDigest",
        Uint8Array::from(block.seal().as_ref()).into(),
    )?;
    Ok(result.into())
}

/// Verifies a Simplex finalization certificate against an expected block digest.
///
/// This intentionally does not decode the finalized block body appended after
/// the certified commitment. The live explorer already has the block digest in
/// `block_meta`, and decoding thousands of transactions per block just to draw
/// a certificate checkmark would put certificate work back on the hot path.
#[wasm_bindgen(js_name = verifyBlockCertificate)]
pub fn verify_block_certificate(
    verification_material: &[u8],
    finalized_artifact: &[u8],
    expected_block_digest: &[u8],
) -> Result<JsValue, JsError> {
    let identity = simplex_identity(verification_material)?;
    let expected_block_digest = decode_digest(expected_block_digest, "expected block digest")?;

    let scheme = ConsensusScheme::certificate_verifier(CONSENSUS_NAMESPACE, identity);
    let mut reader = finalized_artifact;
    let proof = Finalization::<ConsensusScheme, Commitment>::read_cfg(
        &mut reader,
        &scheme.certificate_codec_config(),
    )
    .map_err(|error| JsError::new(&format!("failed to decode finalization proof: {error}")))?;
    let mut rng = StdRng::seed_from_u64(0);
    if !proof.verify(&mut rng, &scheme, &Sequential) {
        return Err(JsError::new("finalization certificate verification failed"));
    }

    let commitment = Commitment::read(&mut reader).map_err(|error| {
        JsError::new(&format!("failed to decode certified commitment: {error}"))
    })?;
    if proof.proposal.payload != commitment {
        return Err(JsError::new(
            "finalization payload does not match certified commitment",
        ));
    }
    if commitment.block::<sha256::Digest>() != expected_block_digest {
        return Err(JsError::new(
            "certified commitment does not match block metadata digest",
        ));
    }

    let result = Object::new();
    set(
        &result,
        "view",
        BigInt::from(proof.proposal.round.view().get()).into(),
    )?;
    Ok(result.into())
}

fn simplex_identity(verification_material: &[u8]) -> Result<<MinSig as Variant>::Public, JsError> {
    let mut identity_bytes = verification_material;
    match <MinSig as Variant>::Public::read(&mut identity_bytes) {
        Ok(identity) if identity_bytes.is_empty() => return Ok(identity),
        _ => {}
    }

    let mut sharing_bytes = verification_material;
    let max_participants =
        NonZeroU32::new(MAX_SIMPLEX_PARTICIPANTS).expect("MAX_SIMPLEX_PARTICIPANTS is non-zero");
    let sharing =
        Sharing::<MinSig>::read_cfg(&mut sharing_bytes, &(max_participants, ModeVersion::v0()))
            .map_err(|error| {
                JsError::new(&format!(
                    "failed to decode Simplex verification material: {error}"
                ))
            })?;
    if !sharing_bytes.is_empty() {
        return Err(JsError::new(
            "Simplex verification material contains trailing bytes",
        ));
    }
    Ok(*sharing.public())
}

fn decode_digest(bytes: &[u8], label: &str) -> Result<sha256::Digest, JsError> {
    sha256::Digest::decode(bytes)
        .map_err(|error| JsError::new(&format!("failed to decode {label}: {error}")))
}

fn set(target: &Object, key: &str, value: JsValue) -> Result<(), JsError> {
    Reflect::set(target, &JsValue::from_str(key), &value)
        .map(|_| ())
        .map_err(|_| JsError::new("failed to build verification result"))
}
