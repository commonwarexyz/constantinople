//! HTTP handlers for the mempool webserver.

use super::Mailbox;
use axum::{Router, body::Bytes, extract::State, http::StatusCode, routing::post};
use bytes::Buf;
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
    pub mailbox: Mailbox<C, P, H>,
    pub namespace: &'static [u8],
    pub max_batch_bytes: usize,
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
        .route("/transactions", post(submit_batch::<C, P, H>))
        .with_state(state)
}

/// Accepts a batch of signed transactions as concatenated commonware-codec bytes.
///
/// Blocks until the batch is finalized in a block or dropped.
///
/// Returns:
/// - `200 OK` with JSON status on finalization or drop.
/// - `400 Bad Request` if the body is empty, any transaction fails to decode,
///   or any signature is invalid.
/// - `413 Payload Too Large` if the batch exceeds `max_propose_bytes`.
/// - `503 Service Unavailable` if the pool is full.
async fn submit_batch<C, P, H>(
    State(state): State<Arc<AppState<C, P, H>>>,
    body: Bytes,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, String::new());
    }

    let mut buf = body.as_ref();
    let mut verified = Vec::new();
    let mut total_bytes = 0;

    while buf.has_remaining() {
        let signed: SignedTransaction<P, H> = match SignedTransaction::decode(&mut buf) {
            Ok(tx) => tx,
            Err(_) => return (StatusCode::BAD_REQUEST, String::new()),
        };

        let Some(sender_key) = signed.value().sender() else {
            return (StatusCode::BAD_REQUEST, String::new());
        };
        if !signed.verify(state.namespace, sender_key) {
            return (StatusCode::BAD_REQUEST, String::new());
        }

        total_bytes += signed.encode_size();
        let tx = signed.into();
        verified.push(tx);
    }

    if total_bytes > state.max_batch_bytes {
        return (StatusCode::PAYLOAD_TOO_LARGE, String::new());
    }

    let Some(result_rx) = state.mailbox.try_submit(verified, total_bytes) else {
        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
    };

    result_rx.await.map_or_else(
        |_| (StatusCode::INTERNAL_SERVER_ERROR, String::new()),
        |status| {
            (
                StatusCode::OK,
                serde_json::to_string(&status).expect("TxStatus serialization cannot fail"),
            )
        },
    )
}
