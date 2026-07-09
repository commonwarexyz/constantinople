//! Shared error type for HTTP submissions to the mempool webserver.

use derive_more::Display;

/// Error returned by mempool submission calls.
#[derive(Debug, Display)]
pub enum SubmitError {
    /// One or more transactions failed to decode or had an invalid signature.
    #[display("bad request")]
    BadRequest,
    /// The batch exceeds the server's `max_propose_bytes` limit.
    #[display("payload too large")]
    PayloadTooLarge,
    /// The server's pool is full.
    #[display("service unavailable")]
    ServiceUnavailable,
    /// The server encountered an internal error.
    #[display("internal server error")]
    InternalServerError,
    /// HTTP transport error.
    #[display("http error: {_0}")]
    Http(reqwest::Error),
    /// Failed to parse the response body.
    #[display("invalid response: {_0}")]
    InvalidResponse(serde_json::Error),
    /// The server returned an unexpected status code.
    #[display("unexpected status {_0}")]
    Unexpected(u16),
}

impl From<reqwest::Error> for SubmitError {
    fn from(error: reqwest::Error) -> Self {
        Self::Http(error)
    }
}
