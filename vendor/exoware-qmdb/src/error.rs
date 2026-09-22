use commonware_storage::{merkle, qmdb};
use exoware_sdk::{ClientError, ConnectError};

// Native Merkle errors cannot carry RPC codes. Reserve this tag to preserve Store retryability.
const STORE_READ_ABORTED: &str = "exoware-qmdb Store read aborted";

pub(crate) fn store_read_error<F: merkle::Family>(
    error: ClientError,
    message: &'static str,
) -> merkle::Error<F> {
    if error.rpc_code() == Some(connectrpc::ErrorCode::Aborted) {
        merkle::Error::DataCorrupted(STORE_READ_ABORTED)
    } else {
        merkle::Error::DataCorrupted(message)
    }
}

pub(crate) fn merkle_error<F: merkle::Family>(error: merkle::Error<F>) -> QmdbError {
    match error {
        merkle::Error::DataCorrupted(STORE_READ_ABORTED) => {
            ClientError::Rpc(Box::new(ConnectError::aborted(STORE_READ_ABORTED))).into()
        }
        error => QmdbError::CommonwareMerkle(error.to_string()),
    }
}

pub(crate) fn current_proof_error<F: merkle::Family>(error: qmdb::Error<F>) -> QmdbError {
    match error {
        qmdb::Error::Merkle(merkle::Error::DataCorrupted(STORE_READ_ABORTED)) => {
            ClientError::Rpc(Box::new(ConnectError::aborted(STORE_READ_ABORTED))).into()
        }
        error => QmdbError::CommonwareMerkle(error.to_string()),
    }
}

pub(crate) fn error_key<K: AsRef<[u8]> + ?Sized>(key: &K) -> Vec<u8> {
    key.as_ref().to_vec()
}

/// Which proof shape failed verification. Carried on
/// [`QmdbError::ProofVerification`] so callers and tests can discriminate
/// without string matching on the error message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofKind {
    /// Single-key current-state proof (`KeyLookupService.Get`).
    CurrentKeyValue,
    /// Current ordered proof that a key is inactive.
    CurrentKeyExclusion,
    /// Historical multi-proof over subscribed operations.
    HistoricalMultiKey,
    /// Subscribe-time multi-proof covering matched operations in one batch
    /// (`OperationLogService.Subscribe`).
    BatchMulti,
    /// Contiguous historical range proof (sync checkpoint).
    RangeCheckpoint,
    /// Contiguous current-state range proof.
    CurrentRange,
}

impl std::fmt::Display for ProofKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::CurrentKeyValue => "current key-value",
            Self::CurrentKeyExclusion => "current key-exclusion",
            Self::HistoricalMultiKey => "historical many-key",
            Self::BatchMulti => "batch multi",
            Self::RangeCheckpoint => "range checkpoint",
            Self::CurrentRange => "current range",
        };
        f.write_str(s)
    }
}

impl From<crate::request::InvalidWindow> for QmdbError {
    fn from(err: crate::request::InvalidWindow) -> Self {
        use crate::request::InvalidWindow;
        match err {
            InvalidWindow::TipOverflow => Self::CorruptData(err.to_string()),
            InvalidWindow::StartOutOfBounds { start, count } => {
                Self::RangeStartOutOfBounds { start, count }
            }
            InvalidWindow::ZeroMaximum => Self::InvalidRangeLength,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QmdbError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("batch must contain at least one operation")]
    EmptyBatch,
    #[error("proof request must contain at least one key")]
    EmptyProofRequest,
    #[error("range proof max_locations must be > 0")]
    InvalidRangeLength,
    #[error("invalid key range: start_key {start_key:?} must be less than end_key {end_key:?}")]
    InvalidKeyRange {
        start_key: Vec<u8>,
        end_key: Vec<u8>,
    },
    #[error("duplicate key in proof request: {key:?}")]
    DuplicateRequestedKey { key: Vec<u8> },
    #[error("requested location {requested} is above published watermark {available}")]
    WatermarkTooLow { requested: u64, available: u64 },
    #[error("proof key not found at watermark {watermark}: {key:?}")]
    ProofKeyNotFound { watermark: u64, key: Vec<u8> },
    #[error("requested key is not active at watermark {watermark}: {key:?}")]
    KeyNotActive { watermark: u64, key: Vec<u8> },
    #[error("current proofs are only available at uploaded batch locations; no batch ends at {location}")]
    CurrentProofRequiresBatchBoundary { location: u64 },
    #[error("current boundary state has not been uploaded for batch location {location}")]
    CurrentBoundaryStateMissing { location: u64 },
    #[error("range proof start {start} is out of bounds for watermark with {count} leaves")]
    RangeStartOutOfBounds { start: u64, count: u64 },
    #[error("encoded value exceeds store value limit ({len} > {max})")]
    EncodedValueTooLarge { len: usize, max: usize },
    #[error(
        "sortable key encoding for raw key length {raw_len} expands to {encoded_len} bytes, exceeding max {max}"
    )]
    SortableKeyTooLarge {
        raw_len: usize,
        encoded_len: usize,
        max: usize,
    },
    #[error("{kind} proof failed verification")]
    ProofVerification { kind: ProofKind },
    #[error("range proof does not satisfy the request: {0}")]
    RangeMismatch(&'static str),
    #[error("corrupt qmdb data: {0}")]
    CorruptData(String),
    #[error("commonware merkle error: {0}")]
    CommonwareMerkle(String),
    #[error("qmdb stream transport error: {0}")]
    Stream(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_storage::merkle::mmr;
    use connectrpc::ErrorCode;

    #[test]
    fn proof_boundaries_preserve_only_structured_store_aborts() {
        for code in [
            ErrorCode::Aborted,
            ErrorCode::Internal,
            ErrorCode::Unavailable,
        ] {
            let failure = || {
                store_read_error::<mmr::Family>(
                    ClientError::Rpc(Box::new(ConnectError::new(code, STORE_READ_ABORTED))),
                    "node fetch failed",
                )
            };
            for error in [
                merkle_error(failure()),
                current_proof_error(qmdb::Error::Merkle(failure())),
            ] {
                if code == ErrorCode::Aborted {
                    assert!(
                        matches!(error, QmdbError::Client(error) if error.rpc_code() == Some(code))
                    );
                } else {
                    assert!(matches!(error, QmdbError::CommonwareMerkle(_)));
                }
            }
        }
        for error in [
            merkle_error(merkle::Error::<mmr::Family>::DataCorrupted("invalid node")),
            current_proof_error(qmdb::Error::Merkle(
                merkle::Error::<mmr::Family>::ElementPruned(merkle::Position::new(0)),
            )),
        ] {
            assert!(matches!(error, QmdbError::CommonwareMerkle(_)));
        }
    }
}
