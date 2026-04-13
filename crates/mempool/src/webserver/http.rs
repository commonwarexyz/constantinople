//! HTTP handlers for the mempool webserver.

use super::Mailbox;
use axum::{Router, body::Bytes, extract::State, http::StatusCode, routing::post};
use commonware_codec::{Decode, EncodeSize, RangeCfg};
use commonware_cryptography::{BatchVerifier, Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use constantinople_primitives::{SignedTransaction, verify_transaction_chunks};
use rand_core::OsRng;
use std::sync::Arc;

/// Shared state for HTTP handlers.
pub(super) struct AppState<C, P, H, St>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    pub mailbox: Mailbox<C, P, H>,
    pub namespace: &'static [u8],
    pub max_batch_bytes: usize,
    pub strategy: St,
}

/// Builds the axum [`Router`] for the mempool HTTP API.
pub(super) fn router<C, P, H, BV, St>(state: Arc<AppState<C, P, H, St>>) -> Router
where
    C: Digest + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Send + Sync,
    P::Signature: Send + Sync,
    BV: BatchVerifier<PublicKey = P> + Send + Sync + 'static,
    St: Strategy + Send + Sync + 'static,
{
    Router::new()
        .route("/transactions", post(submit_batch::<C, P, H, BV, St>))
        .with_state(state)
}

/// Accepts a batch of signed transactions as a commonware-codec length-prefixed
/// vector.
///
/// Signatures are verified in parallel using the configured [`Strategy`] and
/// [`BatchVerifier`]. Blocks until the batch is finalized in a block or dropped.
///
/// Returns:
/// - `200 OK` with JSON status on finalization or drop.
/// - `400 Bad Request` if the body is empty, any transaction fails to decode,
///   or any signature is invalid.
/// - `413 Payload Too Large` if the batch exceeds `max_propose_bytes`.
/// - `503 Service Unavailable` if the pool is full.
async fn submit_batch<C, P, H, BV, St>(
    State(state): State<Arc<AppState<C, P, H, St>>>,
    body: Bytes,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    BV: BatchVerifier<PublicKey = P> + Send + 'static,
    St: Strategy,
{
    // Phase 1: Decode the length-prefixed transaction vector (sequential, fast).
    let cfg = (RangeCfg::new(1..=usize::MAX), ());
    let signed = match Vec::<SignedTransaction<P, H>>::decode_cfg(body.as_ref(), &cfg) {
        Ok(txs) => txs,
        Err(_) => return (StatusCode::BAD_REQUEST, String::new()),
    };
    let total_bytes: usize = signed.iter().map(EncodeSize::encode_size).sum();

    if total_bytes > state.max_batch_bytes {
        return (StatusCode::PAYLOAD_TOO_LARGE, String::new());
    }

    // Phase 2: Verify signatures in parallel on the rayon pool.
    let strategy = state.strategy.clone();
    let namespace = state.namespace;
    let verified = match tokio::task::spawn_blocking(move || {
        verify_transaction_chunks::<P, H, BV, _>(&strategy, namespace, &mut OsRng, signed)
    })
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => return (StatusCode::BAD_REQUEST, String::new()),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, String::new()),
    };

    // Phase 3: Submit to actor and await result.
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
