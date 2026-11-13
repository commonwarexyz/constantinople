//! Authenticate fixed account lookups against a certified current-state root.

use commonware_codec::{Copying, Decode, DecodeExt, FixedSize};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_storage::{
    merkle::{MAX_PROOF_DIGESTS_PER_ELEMENT, mmr},
    qmdb::{any::unordered::fixed::Operation, current::proof::constant::OperationProof},
};
use constantinople_primitives::{Account, AccountKey};

/// Bitmap chunk width used by the account database.
pub const ACCOUNT_CHUNK_BYTES: usize = 32;

// A single-leaf proof needs at most 122 digests; this also covers its fixed metadata and account.
const MAX_PROOF_BYTES: usize = 16 * 1024;

type AccountOperation = Operation<mmr::Family, AccountKey, Account>;
type AccountOperationProof = OperationProof<mmr::Family, Digest, ACCOUNT_CHUNK_BYTES>;

/// An active account update authenticated against the caller's root and exact operation count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAccountLookup {
    /// Location of the account's active update.
    pub location: u64,
    /// The requested account key.
    pub key: AccountKey,
    /// The authenticated account value.
    pub account: Account,
}

/// Why a lookup could not be authenticated.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// The caller supplied an invalid root, key, proof, or operation encoding.
    #[error("invalid account proof encoding")]
    InvalidEncoding,
    /// The proof exceeds the bounded size for one account lookup.
    #[error("account proof exceeds the size limit")]
    ProofTooLarge,
    /// The proof covers a different certified boundary.
    #[error("account proof does not match the certified operation count")]
    WrongBoundary,
    /// The operation names another account or is not an update.
    #[error("account proof does not contain the requested account update")]
    WrongAccount,
    /// The proof does not authenticate its claim against the supplied root.
    #[error("account proof failed verification")]
    VerificationFailed,
}

/// Verify one native Commonware account proof.
///
/// `encoded_operation` is the claimed active update of `key`, and `expected_tip` is the inclusive
/// last operation location from the certified header. The caller obtains `root` and
/// `expected_tip` from the same verified certificate. Proofs use MMR, SHA-256, fixed account
/// encodings, and 32-byte bitmap chunks. The account database authenticates only present
/// accounts. It has no proof that an account is absent.
pub fn verify_current_account_lookup(
    proof: &[u8],
    root: &[u8],
    key: &[u8],
    expected_tip: u64,
    encoded_operation: &[u8],
) -> Result<VerifiedAccountLookup, Error> {
    if proof.len() > MAX_PROOF_BYTES {
        return Err(Error::ProofTooLarge);
    }
    let root = Digest::decode(Copying(root)).map_err(|_| Error::InvalidEncoding)?;
    let key = AccountKey::decode(Copying(key)).map_err(|_| Error::InvalidEncoding)?;
    let leaves = expected_tip.checked_add(1).ok_or(Error::WrongBoundary)?;

    if encoded_operation.len() != AccountOperation::SIZE {
        return Err(Error::InvalidEncoding);
    }
    let operation =
        AccountOperation::decode(Copying(encoded_operation)).map_err(|_| Error::InvalidEncoding)?;
    let AccountOperation::Update(update) = &operation else {
        return Err(Error::WrongAccount);
    };
    if update.0 != key {
        return Err(Error::WrongAccount);
    }
    let account = update.1;
    let proof = AccountOperationProof::decode_cfg(Copying(proof), &MAX_PROOF_DIGESTS_PER_ELEMENT)
        .map_err(|_| Error::InvalidEncoding)?;
    if proof.range_proof.proof.leaves.as_u64() != leaves {
        return Err(Error::WrongBoundary);
    }
    if !proof.verify::<Sha256, _>(operation, &root) {
        return Err(Error::VerificationFailed);
    }
    Ok(VerifiedAccountLookup {
        location: proof.loc.as_u64(),
        key,
        account,
    })
}

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
mod wasm;

#[cfg(test)]
mod tests;
