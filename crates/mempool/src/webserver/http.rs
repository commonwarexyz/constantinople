//! HTTP handlers for the mempool webserver.

use super::Mailbox;
use axum::{Router, body::Bytes, extract::State, http::StatusCode, routing::post};
use commonware_codec::{DecodeExt, EncodeSize};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use constantinople_primitives::SignedTransaction;
use std::sync::Arc;

/// Shared state for HTTP handlers.
pub(super) struct AppState<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    /// Mailbox handle to the mempool actor.
    pub mailbox: Mailbox<C, P, H>,
    /// Transaction signing namespace used for signature verification.
    pub namespace: &'static [u8],
}

/// Builds the axum [`Router`] for the mempool HTTP API.
pub(super) fn router<C, P, H>(state: Arc<AppState<C, P, H>>) -> Router
where
    C: Digest + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Send + Sync,
    P::Signature: Send + Sync,
{
    Router::new()
        .route("/transactions", post(submit_transaction::<C, P, H>))
        .with_state(state)
}

/// Accepts a single signed transaction as raw commonware-codec bytes.
///
/// Returns:
/// - `200 OK` if the transaction was accepted into the pool.
/// - `400 Bad Request` if the body cannot be decoded or the signature is invalid.
/// - `503 Service Unavailable` if the pool is full.
async fn submit_transaction<C, P, H>(
    State(state): State<Arc<AppState<C, P, H>>>,
    body: Bytes,
) -> StatusCode
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let signed: SignedTransaction<P, H> = match SignedTransaction::decode(&mut body.as_ref()) {
        Ok(tx) => tx,
        Err(_) => return StatusCode::BAD_REQUEST,
    };

    let Some(sender_key) = signed.value().sender() else {
        return StatusCode::BAD_REQUEST;
    };
    if !signed.verify(state.namespace, sender_key) {
        return StatusCode::BAD_REQUEST;
    }

    let size = signed.encode_size();
    let verified = signed.into();

    if state.mailbox.try_submit(verified, size) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
