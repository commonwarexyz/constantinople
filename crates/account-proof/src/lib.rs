//! Authenticate fixed account lookups against a certified current-state root.

use commonware_codec::{Copying, Decode, DecodeExt, FixedSize};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_storage::{
    merkle::{MAX_PROOF_DIGESTS_PER_ELEMENT, mmr},
    qmdb::{
        any::{ordered::fixed::Operation, value::FixedEncoding},
        current::{ordered::proof::constant::ExclusionProof, proof::constant::OperationProof},
    },
};
use constantinople_primitives::{Account, AccountKey};

/// Bitmap chunk width used by the account database.
pub const ACCOUNT_CHUNK_BYTES: usize = 32;

// A single-leaf proof needs at most 122 digests; this also covers its fixed metadata and account.
const MAX_PROOF_BYTES: usize = 16 * 1024;

type AccountOperation = Operation<mmr::Family, AccountKey, Account>;
type AccountOperationProof = OperationProof<mmr::Family, Digest, ACCOUNT_CHUNK_BYTES>;
type AccountExclusionProof =
    ExclusionProof<mmr::Family, AccountKey, FixedEncoding<Account>, Digest, ACCOUNT_CHUNK_BYTES>;

/// A lookup authenticated against the caller's root and exact operation count.
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
    /// The account has no assigned value at the certified boundary.
    Absent {
        /// The requested account key.
        key: AccountKey,
        /// Location of the operation whose key span excludes the requested key: the active
        /// update of the preceding account, or the commit of an empty database.
        location: u64,
        /// The adjacent active keys bracketing the requested key, when the database is not empty.
        span: Option<(AccountKey, AccountKey)>,
    },
}

/// Why a lookup could not be authenticated.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// The response must contain exactly one inclusion or exclusion claim.
    #[error("account lookup must contain exactly one inclusion or exclusion claim")]
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
/// `expected_tip` is the inclusive last operation location from the certified header. Inclusion
/// requires `encoded_operation` and `exclusion == false`; exclusion requires no operation and
/// `exclusion == true`. The caller obtains `root` and `expected_tip` from the same verified
/// certificate. Proofs use MMR, SHA-256, fixed account encodings, and 32-byte bitmap chunks.
pub fn verify_current_account_lookup(
    proof: &[u8],
    root: &[u8],
    key: &[u8],
    expected_tip: u64,
    encoded_operation: Option<Vec<u8>>,
    exclusion: bool,
) -> Result<VerifiedAccountLookup, Error> {
    if exclusion == encoded_operation.is_some() {
        return Err(Error::InvalidClaim);
    }
    if proof.len() > MAX_PROOF_BYTES {
        return Err(Error::ProofTooLarge);
    }
    let root = Digest::decode(Copying(root)).map_err(|_| Error::InvalidEncoding)?;
    let key = AccountKey::decode(Copying(key)).map_err(|_| Error::InvalidEncoding)?;
    let leaves = expected_tip.checked_add(1).ok_or(Error::WrongBoundary)?;

    if let Some(encoded_operation) = encoded_operation {
        if encoded_operation.len() != AccountOperation::SIZE {
            return Err(Error::InvalidEncoding);
        }
        let operation = AccountOperation::decode(Copying(encoded_operation.as_slice()))
            .map_err(|_| Error::InvalidEncoding)?;
        let AccountOperation::Update(update) = &operation else {
            return Err(Error::WrongAccount);
        };
        if update.key != key {
            return Err(Error::WrongAccount);
        }
        let account = update.value;
        let proof =
            AccountOperationProof::decode_cfg(Copying(proof), &MAX_PROOF_DIGESTS_PER_ELEMENT)
                .map_err(|_| Error::InvalidEncoding)?;
        if proof.range_proof.proof.leaves.as_u64() != leaves {
            return Err(Error::WrongBoundary);
        }
        if !proof.verify::<Sha256, _>(operation, &root) {
            return Err(Error::VerificationFailed);
        }
        return Ok(VerifiedAccountLookup::Present {
            location: proof.loc.as_u64(),
            key,
            account,
        });
    }

    let proof =
        AccountExclusionProof::decode_cfg(Copying(proof), &(MAX_PROOF_DIGESTS_PER_ELEMENT, (), ()))
            .map_err(|_| Error::InvalidEncoding)?;
    let (operation_proof, span) = match &proof {
        AccountExclusionProof::KeyValue(proof, update) => {
            (proof, Some((update.key, update.next_key)))
        }
        AccountExclusionProof::Commit(proof, _) => (proof, None),
    };
    if operation_proof.range_proof.proof.leaves.as_u64() != leaves {
        return Err(Error::WrongBoundary);
    }
    if !proof.verify::<Sha256>(&key, &root) {
        return Err(Error::VerificationFailed);
    }
    Ok(VerifiedAccountLookup::Absent {
        key,
        location: operation_proof.loc.as_u64(),
        span,
    })
}

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
mod wasm;

#[cfg(test)]
mod tests;
