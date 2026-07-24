//! Mempool webserver actor.
//!
//! Accepts signed transactions over HTTP, verifies them, and serves
//! batches to the consensus layer via [`TransactionSource`](crate::TransactionSource).
//!
//! # Architecture
//!
//! - **HTTP handlers** (axum) run on tokio worker threads, decoding and
//!   verifying transactions in parallel.
//! - **Actor** owns a byte-bounded FIFO pool and processes submit,
//!   propose, and report messages from a single channel.
//! - **Mailbox** is the cloneable handle that implements
//!   [`TransactionSource`](crate::TransactionSource) and
//!   [`Reporter`](commonware_consensus::Reporter).

use derive_more::Display;

mod account_reader;
pub use account_reader::AccountReader;

mod actor;
pub use actor::{Actor, Config, TxStatus};

mod mailbox;
pub use mailbox::{ActorReceiver, Mailbox};

mod http;

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
