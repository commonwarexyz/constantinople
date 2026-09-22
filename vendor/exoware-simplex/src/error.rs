use exoware_sdk::ClientError;

#[derive(Debug, thiserror::Error)]
pub enum SimplexError {
    #[error("store client error: {0}")]
    Client(#[from] ClientError),
    #[error("codec error: {0}")]
    Codec(#[from] commonware_codec::Error),
    #[error("simplex proof payload does not match header digest")]
    ProofBlockMismatch,
    #[error("simplex artifact does not match requested index")]
    RecordKeyMismatch,
    #[error("simplex upload contains no rows")]
    EmptyUpload,
}
