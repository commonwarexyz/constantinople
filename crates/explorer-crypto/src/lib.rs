//! Browser crypto bindings for the explorer.

use commonware_codec::{Decode, DecodeExt as _, Encode as _, FixedSize as _};
use commonware_cryptography::{Sha256, Signer as _, ed25519, sha256};
use commonware_storage::{
    merkle::{self, Family as _, Location, Position, mmr},
    qmdb::{
        any::value::FixedEncoding, current::proof::OpsRootWitness, keyless,
        verify::verify_proof_and_extract_digests,
    },
};
use js_sys::{Array, BigInt, Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;

const ED25519_PRIVATE_KEY_BYTES: usize = 32;

type TransactionOperation = keyless::Operation<mmr::Family, FixedEncoding<sha256::Digest>>;

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
    let nodes = verify_proof_and_extract_digests(
        &hasher,
        &proof,
        Location::new(start_location),
        &operations,
        &target_root,
    )
    .map_err(|error| {
        JsError::new(&format!(
            "transaction proof failed MMR verification: {error}"
        ))
    })?;

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
    set(
        &result,
        "mmr",
        mmr_visualization(&proof, &nodes, expected_location)?,
    )?;
    Ok(result.into())
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

fn set(target: &Object, key: &str, value: JsValue) -> Result<(), JsError> {
    Reflect::set(target, &JsValue::from_str(key), &value)
        .map(|_| ())
        .map_err(|_| JsError::new("failed to build verification result"))
}

fn mmr_visualization(
    proof: &merkle::Proof<mmr::Family, sha256::Digest>,
    nodes: &[(Position<mmr::Family>, sha256::Digest)],
    expected_location: u64,
) -> Result<JsValue, JsError> {
    let object = Object::new();
    let size = Position::<mmr::Family>::try_from(proof.leaves)
        .map_err(|error| JsError::new(&format!("failed to compute MMR size: {error}")))?;
    let target_position = mmr::Family::location_to_position(Location::new(expected_location));

    set(
        &object,
        "leaves",
        BigInt::from(proof.leaves.as_u64()).into(),
    )?;
    set(
        &object,
        "inactivePeaks",
        JsValue::from_f64(proof.inactive_peaks as f64),
    )?;
    set(&object, "targetPosition", position_value(target_position))?;

    let peak_array = Array::new();
    for (position, height) in mmr::Family::peaks(size) {
        let peak = Object::new();
        set(&peak, "position", position_value(position))?;
        set(&peak, "height", JsValue::from_f64(height as f64))?;
        peak_array.push(&peak);
    }
    set(&object, "peaks", peak_array.into())?;

    let node_array = Array::new();
    for (position, digest) in nodes {
        let node = Object::new();
        set(&node, "position", position_value(*position))?;
        set(
            &node,
            "height",
            JsValue::from_f64(mmr::Family::pos_to_height(*position) as f64),
        )?;
        set(&node, "digest", Uint8Array::from(digest.as_ref()).into())?;
        set(
            &node,
            "kind",
            JsValue::from_str(if *position == target_position {
                "target"
            } else {
                "proof"
            }),
        )?;
        node_array.push(&node);
    }
    set(&object, "nodes", node_array.into())?;

    Ok(object.into())
}

fn position_value(position: Position<mmr::Family>) -> JsValue {
    BigInt::from(position.as_u64()).into()
}
