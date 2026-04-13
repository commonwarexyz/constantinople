//! HTTP handlers for the mempool webserver.

use super::Mailbox;
use axum::{Router, body::Bytes, extract::State, http::StatusCode, routing::post};
use commonware_codec::{Decode, EncodeSize, RangeCfg};
use commonware_cryptography::{BatchVerifier, Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use constantinople_primitives::{SignedTransaction, VerifiedTransaction};
use rand::{SeedableRng, rngs::StdRng};
use rand_core::{OsRng, RngCore};
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

/// Accepts a batch of signed transactions as concatenated commonware-codec bytes.
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
        verify_batch::<P, H, BV, St>(&strategy, namespace, signed)
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

/// Splits transactions into chunks, verifies each chunk in parallel using
/// batch signature verification, and returns the verified transactions in
/// their original order.
fn verify_batch<P, H, BV, St>(
    strategy: &St,
    namespace: &'static [u8],
    transactions: Vec<SignedTransaction<P, H>>,
) -> Option<Vec<VerifiedTransaction<P, H>>>
where
    P: PublicKey,
    H: Hasher,
    BV: BatchVerifier<PublicKey = P>,
    St: Strategy,
{
    if transactions.is_empty() {
        return Some(Vec::new());
    }

    let chunk_count = strategy.parallelism_hint().min(transactions.len());
    let chunk_size = transactions.len().div_ceil(chunk_count);

    let mut remaining = transactions;
    let mut chunks = Vec::with_capacity(chunk_count);
    while !remaining.is_empty() {
        let split_at = chunk_size.min(remaining.len());
        let rest = remaining.split_off(split_at);
        let mut rng_seed = [0u8; 32];
        OsRng.fill_bytes(&mut rng_seed);
        chunks.push((rng_seed, remaining));
        remaining = rest;
    }

    let verified_chunks = strategy.map_collect_vec(chunks, |(rng_seed, chunk)| {
        let mut rng = StdRng::from_seed(rng_seed);
        verify_chunk::<P, H, BV>(namespace, &mut rng, &chunk)
            .then(|| chunk.into_iter().map(Into::into).collect::<Vec<_>>())
    });

    let mut verified = Vec::new();
    for chunk in verified_chunks {
        verified.extend(chunk?);
    }
    Some(verified)
}

/// Verifies all signatures in a chunk using batch verification.
fn verify_chunk<P, H, BV>(
    namespace: &[u8],
    rng: &mut impl rand_core::CryptoRngCore,
    transactions: &[SignedTransaction<P, H>],
) -> bool
where
    P: PublicKey,
    H: Hasher,
    BV: BatchVerifier<PublicKey = P>,
{
    let mut verifier = BV::new();
    for transaction in transactions {
        let Some(sender) = transaction.value().sender() else {
            return false;
        };
        let Some(signature) = transaction.signature() else {
            return false;
        };
        if !verifier.add(
            namespace,
            transaction.message_digest().as_ref(),
            sender,
            signature,
        ) {
            return false;
        }
    }
    verifier.verify(rng)
}
