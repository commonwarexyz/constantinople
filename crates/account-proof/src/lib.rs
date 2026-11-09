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

/// A lookup authenticated against the caller's root and exact operation count.
///
/// Only inclusion is authenticated: the unordered account database carries no key spans, so an
/// account without an active update is simply not found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedAccountLookup {
    /// The account has this value at the certified boundary.
    Present {
        /// Location of the account's active update.
        location: u64,
        /// The requested account key.
        key: AccountKey,
        /// The authenticated account value.
        account: Account,
    },
}

/// Why a lookup could not be authenticated.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// The response must contain an inclusion claim, since exclusion is not authenticated.
    #[error("account lookup must contain an inclusion claim")]
    InvalidClaim,
    /// The caller supplied an invalid root, key, proof, or operation encoding.
    #[error("invalid account proof encoding")]
    InvalidEncoding,
    /// The proof exceeds the bounded size for one account lookup.
    #[error("account proof exceeds the size limit")]
    ProofTooLarge,
    /// The proof covers a different certified boundary.
    #[error("account proof does not match the certified operation count")]
    WrongBoundary,
    /// An inclusion operation names another account or is not an update.
    #[error("account proof does not contain the requested account update")]
    WrongAccount,
    /// The proof does not authenticate its claim against the supplied root.
    #[error("account proof failed verification")]
    VerificationFailed,
}

/// Verify one native Commonware account proof.
///
/// `expected_tip` is the inclusive last operation location from the certified header. The lookup
/// must carry `encoded_operation` with `exclusion == false`, and exclusion claims are rejected. The
/// caller obtains `root` and `expected_tip` from the same verified certificate. Proofs use MMR,
/// SHA-256, fixed account encodings, and 32-byte bitmap chunks.
pub fn verify_current_account_lookup(
    proof: &[u8],
    root: &[u8],
    key: &[u8],
    expected_tip: u64,
    encoded_operation: Option<Vec<u8>>,
    exclusion: bool,
) -> Result<VerifiedAccountLookup, Error> {
    let Some(encoded_operation) = encoded_operation.filter(|_| !exclusion) else {
        return Err(Error::InvalidClaim);
    };
    if proof.len() > MAX_PROOF_BYTES {
        return Err(Error::ProofTooLarge);
    }
    let root = Digest::decode(Copying(root)).map_err(|_| Error::InvalidEncoding)?;
    let key = AccountKey::decode(Copying(key)).map_err(|_| Error::InvalidEncoding)?;
    let leaves = expected_tip.checked_add(1).ok_or(Error::WrongBoundary)?;

    if encoded_operation.len() != AccountOperation::SIZE {
        return Err(Error::InvalidEncoding);
    }
    let operation = AccountOperation::decode(Copying(encoded_operation.as_slice()))
        .map_err(|_| Error::InvalidEncoding)?;
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
    Ok(VerifiedAccountLookup::Present {
        location: proof.loc.as_u64(),
        key,
        account,
    })
}

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
mod wasm;

#[cfg(test)]
mod tests;
