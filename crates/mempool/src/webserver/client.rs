//! HTTP client for submitting transaction batches to the mempool webserver.

use super::TxStatus;
use commonware_codec::Encode;
use commonware_cryptography::Hasher;
use constantinople_primitives::{SignedTransaction, TransactionPublicKey};
use derive_more::Display;
use serde::Deserialize;

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

/// HTTP client for the mempool webserver.
///
/// Submits codec-encoded transaction batches to `POST /transactions` and
/// blocks until the server responds with a [`TxStatus`].
pub struct Client {
    url: String,
    http: reqwest::Client,
}

impl Client {
    /// Creates a new client targeting the given base URL (e.g. `http://127.0.0.1:8080`).
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            http: reqwest::Client::new(),
        }
    }

    /// Submits a batch of signed transactions and waits for the result.
    ///
    /// The batch is encoded as a commonware-codec length-prefixed vector.
    /// The call blocks until the server reports full finalization, partial
    /// finalization, or drop.
    pub async fn submit<H>(
        &self,
        transactions: &[SignedTransaction<H>],
    ) -> Result<TxStatus, SubmitError>
    where
        H: Hasher,
    {
        let body = transactions.encode();
        let response = self
            .http
            .post(format!("{}/transactions", self.url))
            .header("content-type", "application/octet-stream")
            .body(body)
            .send()
            .await?;

        match response.status().as_u16() {
            200 => {
                let bytes = response.bytes().await?;
                serde_json::from_slice(&bytes).map_err(SubmitError::InvalidResponse)
            }
            400 => Err(SubmitError::BadRequest),
            413 => Err(SubmitError::PayloadTooLarge),
            500 => Err(SubmitError::InternalServerError),
            503 => Err(SubmitError::ServiceUnavailable),
            other => Err(SubmitError::Unexpected(other)),
        }
    }

    /// Submits a batch and returns after validator verification plus enqueue.
    ///
    /// The batch is encoded as a commonware-codec length-prefixed vector and
    /// sent to `POST /transactions/ingest`.
    pub async fn ingest<H>(
        &self,
        transactions: &[SignedTransaction<H>],
    ) -> Result<IngestView, SubmitError>
    where
        H: Hasher,
    {
        self.ingest_encoded(transactions.encode()).await
    }

    /// Submits an already codec-encoded batch to the fast ingest endpoint.
    pub async fn ingest_encoded(&self, body: bytes::Bytes) -> Result<IngestView, SubmitError> {
        let response = self
            .http
            .post(format!("{}/transactions/ingest", self.url))
            .header("content-type", "application/octet-stream")
            .body(body)
            .send()
            .await?;

        match response.status().as_u16() {
            202 => {
                let bytes = response.bytes().await?;
                serde_json::from_slice(&bytes).map_err(SubmitError::InvalidResponse)
            }
            400 => Err(SubmitError::BadRequest),
            413 => Err(SubmitError::PayloadTooLarge),
            500 => Err(SubmitError::InternalServerError),
            503 => Err(SubmitError::ServiceUnavailable),
            other => Err(SubmitError::Unexpected(other)),
        }
    }

    /// Fetches the committed account for `public_key`.
    ///
    /// Returns `Ok(Some(account))` when the account has been written, `Ok(None)`
    /// when no record exists yet, and [`SubmitError::ServiceUnavailable`]
    /// while the validator's state database is still attaching.
    pub async fn fetch_account(
        &self,
        public_key: &TransactionPublicKey,
    ) -> Result<Option<AccountView>, SubmitError> {
        let response = self
            .http
            .get(format!("{}/account/{}", self.url, public_key))
            .send()
            .await?;

        match response.status().as_u16() {
            200 => {
                let bytes = response.bytes().await?;
                serde_json::from_slice(&bytes)
                    .map(Some)
                    .map_err(SubmitError::InvalidResponse)
            }
            404 => Ok(None),
            400 => Err(SubmitError::BadRequest),
            500 => Err(SubmitError::InternalServerError),
            503 => Err(SubmitError::ServiceUnavailable),
            other => Err(SubmitError::Unexpected(other)),
        }
    }
}

/// Committed account snapshot returned by [`Client::fetch_account`].
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct AccountView {
    pub balance: u64,
    pub nonce: u64,
    pub nonce_bitmap: u64,
}

/// Fast-ingest acknowledgement returned by validators.
#[derive(Debug, Clone, Deserialize)]
pub struct IngestView {
    pub digests: Vec<String>,
}
