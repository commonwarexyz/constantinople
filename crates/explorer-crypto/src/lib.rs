//! Browser crypto bindings for the explorer.

use commonware_codec::{
    Decode, DecodeExt as _, Encode as _, FixedSize as _, Read as _, ReadExt as _,
};
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
use commonware_storage::{
    merkle::{self, Location, mmr},
    qmdb::{
        any::{
            operation::Operation as AnyOperation,
            unordered::{Operation as UnorderedOperation, Update as UnorderedUpdate},
            value::FixedEncoding,
        },
        current::proof::OpsRootWitness,
        keyless,
        verify::verify_proof,
    },
};
use constantinople_primitives::{Account, AccountKey, Block, BlockCfg, Sealed};
use core::num::NonZeroU32;
use js_sys::{Array, BigInt, Object, Reflect, Uint8Array};
use rand::{SeedableRng as _, rngs::StdRng};
use wasm_bindgen::prelude::*;

const ED25519_PRIVATE_KEY_BYTES: usize = 32;
const CONSENSUS_NAMESPACE: &[u8] = b"constantinople_CONSENSUS";
const MAX_SIMPLEX_PARTICIPANTS: u32 = 10_000;

type TransactionOperation = keyless::Operation<mmr::Family, FixedEncoding<sha256::Digest>>;
type AccountOperation =
    UnorderedOperation<mmr::Family, AccountKey<ed25519::PublicKey>, FixedEncoding<Account>>;
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

/// Verifies a transaction-hash QMDB range proof.
#[expect(
    clippy::too_many_arguments,
    reason = "wasm-bindgen exports flat parameters"
)]
#[wasm_bindgen(js_name = verifyTransactionProof)]
pub fn verify_transaction_proof(
    expected_root: &[u8],
    proof: &[u8],
    ops_root: &[u8],
    ops_root_witness: &[u8],
    start_location: u64,
    encoded_operations: Array,
    expected_location: u64,
    expected_digest: &[u8],
) -> Result<JsValue, JsError> {
    let expected_root = decode_digest(expected_root, "expected transactions root")?;
    let expected_digest = decode_digest(expected_digest, "expected transaction digest")?;
    let target_root = historical_target_root(ops_root, ops_root_witness, &expected_root)?;
    let operations = decode_operations(&encoded_operations)?;
    if operations.is_empty() {
        return Err(JsError::new("transaction proof has no operations"));
    }

    let max_digests = proof.len() / sha256::Digest::SIZE + 1;
    let proof = merkle::Proof::<mmr::Family, sha256::Digest>::decode_cfg(proof, &max_digests)
        .map_err(|error| JsError::new(&format!("failed to decode transaction proof: {error}")))?;
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    if !verify_proof(
        &hasher,
        &proof,
        Location::new(start_location),
        &operations,
        &target_root,
    ) {
        return Err(JsError::new("transaction proof failed MMR verification"));
    }

    let Some(offset) = expected_location.checked_sub(start_location) else {
        return Err(JsError::new(
            "expected transaction location is before proof range",
        ));
    };
    let offset = usize::try_from(offset)
        .map_err(|_| JsError::new("expected transaction location does not fit usize"))?;
    let Some(operation) = operations.get(offset) else {
        return Err(JsError::new(
            "expected transaction location is outside proof range",
        ));
    };
    let TransactionOperation::Append(digest) = operation else {
        return Err(JsError::new(
            "expected transaction location is not an append",
        ));
    };
    if digest != &expected_digest {
        return Err(JsError::new(
            "transaction proof append digest does not match submitted digest",
        ));
    }

    let result = Object::new();
    set(&result, "location", BigInt::from(expected_location).into())?;
    set(
        &result,
        "root",
        Uint8Array::from(expected_root.as_ref()).into(),
    )?;
    set(
        &result,
        "proofSizeBytes",
        JsValue::from_f64(proof.encode().len() as f64),
    )?;
    set(
        &result,
        "operationCount",
        JsValue::from_f64(operations.len() as f64),
    )?;
    Ok(result.into())
}

/// Verifies an account-state QMDB range proof.
#[expect(
    clippy::too_many_arguments,
    reason = "wasm-bindgen exports flat parameters"
)]
#[wasm_bindgen(js_name = verifyAccountProof)]
pub fn verify_account_proof(
    expected_root: &[u8],
    proof: &[u8],
    ops_root: &[u8],
    ops_root_witness: &[u8],
    start_location: u64,
    encoded_operations: Array,
    expected_location: u64,
    expected_key: &[u8],
) -> Result<JsValue, JsError> {
    let expected_root = decode_digest(expected_root, "expected state root")?;
    let expected_key =
        AccountKey::<ed25519::PublicKey>::from_bytes(bytes::Bytes::copy_from_slice(expected_key))
            .ok_or_else(|| JsError::new("expected account key must be 32 bytes"))?;
    let target_root = historical_target_root(ops_root, ops_root_witness, &expected_root)?;
    let operations = decode_account_operations(&encoded_operations)?;
    if operations.is_empty() {
        return Err(JsError::new("account proof has no operations"));
    }

    let max_digests = proof.len() / sha256::Digest::SIZE + 1;
    let proof = merkle::Proof::<mmr::Family, sha256::Digest>::decode_cfg(proof, &max_digests)
        .map_err(|error| JsError::new(&format!("failed to decode account proof: {error}")))?;
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    if !verify_proof(
        &hasher,
        &proof,
        Location::new(start_location),
        &operations,
        &target_root,
    ) {
        return Err(JsError::new("account proof failed MMR verification"));
    }

    let Some(offset) = expected_location.checked_sub(start_location) else {
        return Err(JsError::new(
            "expected account location is before proof range",
        ));
    };
    let offset = usize::try_from(offset)
        .map_err(|_| JsError::new("expected account location does not fit usize"))?;
    let Some(operation) = operations.get(offset) else {
        return Err(JsError::new(
            "expected account location is outside proof range",
        ));
    };
    let AnyOperation::Update(UnorderedUpdate(key, account)) = operation else {
        return Err(JsError::new("expected account location is not an update"));
    };
    if key != &expected_key {
        return Err(JsError::new("account proof update key does not match"));
    }

    let result = Object::new();
    set(&result, "location", BigInt::from(expected_location).into())?;
    set(&result, "balance", BigInt::from(account.balance).into())?;
    set(&result, "nonce", BigInt::from(account.nonce).into())?;
    set(
        &result,
        "root",
        Uint8Array::from(expected_root.as_ref()).into(),
    )?;
    set(
        &result,
        "proofSizeBytes",
        JsValue::from_f64(proof.encode().len() as f64),
    )?;
    Ok(result.into())
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

fn historical_target_root(
    ops_root: &[u8],
    ops_root_witness: &[u8],
    expected_root: &sha256::Digest,
) -> Result<sha256::Digest, JsError> {
    match (ops_root.is_empty(), ops_root_witness.is_empty()) {
        (true, true) => Ok(*expected_root),
        (false, true) => {
            let ops_root = decode_digest(ops_root, "transaction ops root")?;
            if &ops_root != expected_root {
                return Err(JsError::new(
                    "transaction proof ops root does not match block root",
                ));
            }
            Ok(ops_root)
        }
        (false, false) => {
            let ops_root = decode_digest(ops_root, "transaction ops root")?;
            let witness =
                OpsRootWitness::<mmr::Family, sha256::Digest>::decode_cfg(ops_root_witness, &())
                    .map_err(|error| {
                        JsError::new(&format!(
                            "failed to decode transaction ops-root witness: {error}"
                        ))
                    })?;
            let hasher = commonware_storage::qmdb::hasher::<Sha256>();
            if !witness.verify(&hasher, &ops_root, expected_root) {
                return Err(JsError::new(
                    "transaction proof ops-root witness failed verification",
                ));
            }
            Ok(ops_root)
        }
        (true, false) => Err(JsError::new(
            "transaction proof has an ops-root witness but no ops root",
        )),
    }
}

fn decode_operations(encoded_operations: &Array) -> Result<Vec<TransactionOperation>, JsError> {
    encoded_operations
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let bytes = Uint8Array::new(&value).to_vec();
            TransactionOperation::decode_cfg(bytes.as_slice(), &()).map_err(|error| {
                JsError::new(&format!(
                    "failed to decode transaction proof operation {index}: {error}"
                ))
            })
        })
        .collect()
}

fn decode_account_operations(encoded_operations: &Array) -> Result<Vec<AccountOperation>, JsError> {
    encoded_operations
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let bytes = Uint8Array::new(&value).to_vec();
            AccountOperation::decode_cfg(bytes.as_slice(), &()).map_err(|error| {
                JsError::new(&format!(
                    "failed to decode account proof operation {index}: {error}"
                ))
            })
        })
        .collect()
}

fn set(target: &Object, key: &str, value: JsValue) -> Result<(), JsError> {
    Reflect::set(target, &JsValue::from_str(key), &value)
        .map(|_| ())
        .map_err(|_| JsError::new("failed to build verification result"))
}
