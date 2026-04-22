//! HTTP handlers for the mempool webserver.

use super::{Mailbox, actor::AccountReaderCell};
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::{get, post},
};
use commonware_codec::{Decode, DecodeExt, EncodeSize, FixedSize, RangeCfg, types::lazy::Lazy};
use commonware_cryptography::{BatchVerifier, Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_utils::from_hex;
use constantinople_primitives::{Account, Address, SignedTransaction, verify_transaction_chunks};
use rand_core::OsRng;
use std::sync::Arc;

/// Maximum bytes needed to encode the batch-length prefix.
///
/// `commonware-codec` encodes `Vec` lengths as `u32` varints, which fit in at
/// most 5 bytes.
const MAX_BATCH_LENGTH_PREFIX_BYTES: usize = 5;

/// Minimum bytes needed to encode the batch-length prefix.
const MIN_BATCH_LENGTH_PREFIX_BYTES: usize = 1;

/// Minimum bytes needed to encode a `u64` varint.
const MIN_U64_VARINT_BYTES: usize = 1;

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
    pub account_reader: AccountReaderCell,
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
    let max_request_bytes = max_request_bytes(state.max_batch_bytes);

    Router::new()
        .route("/transactions", post(submit_batch::<C, P, H, BV, St>))
        .route("/account/{address}", get(fetch_account::<C, P, H, St>))
        .layer(DefaultBodyLimit::max(max_request_bytes))
        .with_state(state)
}

const fn max_request_bytes(max_batch_bytes: usize) -> usize {
    max_batch_bytes.saturating_add(MAX_BATCH_LENGTH_PREFIX_BYTES)
}

const fn min_signed_transaction_bytes<P>() -> usize
where
    P: PublicKey,
{
    P::SIZE + Address::SIZE + MIN_U64_VARINT_BYTES + MIN_U64_VARINT_BYTES + P::Signature::SIZE
}

fn max_transaction_count<P>(body_len: usize) -> Option<usize>
where
    P: PublicKey,
{
    let payload_len = body_len.saturating_sub(MIN_BATCH_LENGTH_PREFIX_BYTES);
    let max_transactions = payload_len / min_signed_transaction_bytes::<P>();
    (max_transactions > 0).then_some(max_transactions)
}

/// Accepts a batch of signed transactions as a commonware-codec length-prefixed
/// vector.
///
/// Signatures are verified in parallel using the configured [`Strategy`] and
/// [`BatchVerifier`]. Blocks until the batch is fully finalized, partially
/// finalized, or dropped.
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
    if body.len() > max_request_bytes(state.max_batch_bytes) {
        return (StatusCode::PAYLOAD_TOO_LARGE, String::new());
    }

    // Phase 1: Decode the length-prefixed transaction vector (sequential, fast).
    let Some(max_transactions) = max_transaction_count::<P>(body.len()) else {
        return (StatusCode::BAD_REQUEST, String::new());
    };
    let cfg = (RangeCfg::new(1..=max_transactions), ());
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
    let signed_lazy = signed.into_iter().map(Lazy::new).collect::<Vec<_>>();
    let verified = match tokio::task::spawn_blocking(move || {
        verify_transaction_chunks::<P, H, BV, _>(&strategy, namespace, &mut OsRng, signed_lazy)
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

/// Returns the committed account at the hex-encoded address.
///
/// Responds with:
/// - `200 OK` and `{"balance": u64, "nonce": u64}` if the account exists.
/// - `404 Not Found` if the account has not been written.
/// - `400 Bad Request` if the path is not a 20-byte hex string.
/// - `503 Service Unavailable` if the state database has not been attached yet.
async fn fetch_account<C, P, H, St>(
    State(state): State<Arc<AppState<C, P, H, St>>>,
    Path(address): Path<String>,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    let Some(bytes) = from_hex(&address) else {
        return (StatusCode::BAD_REQUEST, String::new());
    };
    if bytes.len() != Address::SIZE {
        return (StatusCode::BAD_REQUEST, String::new());
    }
    let address = match Address::decode(bytes.as_slice()) {
        Ok(address) => address,
        Err(_) => return (StatusCode::BAD_REQUEST, String::new()),
    };

    let Some(reader) = state.account_reader.get() else {
        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
    };

    reader.get(address).await.map_or_else(
        || (StatusCode::NOT_FOUND, String::new()),
        |account| {
            (
                StatusCode::OK,
                serde_json::to_string(&AccountResponse::from(account))
                    .expect("account serialization cannot fail"),
            )
        },
    )
}

#[derive(serde::Serialize)]
struct AccountResponse {
    balance: u64,
    nonce: u64,
}

impl From<Account> for AccountResponse {
    fn from(account: Account) -> Self {
        Self {
            balance: account.balance,
            nonce: account.nonce,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AppState, router};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{ed25519, sha256};
    use commonware_parallel::Sequential;
    use futures::executor::block_on;
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::Arc,
    };
    use tokio::sync::mpsc;
    use tower::ServiceExt;

    fn test_router(max_batch_bytes: usize) -> axum::Router {
        let (sender, _receiver) = mpsc::channel(1);
        let state = Arc::new(AppState {
            mailbox: super::super::mailbox::Mailbox::new(sender),
            namespace: b"mempool-http-test",
            max_batch_bytes,
            strategy: Sequential,
            account_reader: std::sync::Arc::new(std::sync::OnceLock::new()),
        });

        router::<sha256::Digest, ed25519::PublicKey, sha256::Sha256, ed25519::Batch, Sequential>(
            state,
        )
    }

    #[test]
    fn router_accepts_requests_above_axum_default_limit() {
        let app = test_router(4 * 1024 * 1024);
        let request = Request::builder()
            .method("POST")
            .uri("/transactions")
            .body(Body::from(vec![0u8; 2 * 1024 * 1024 + 1]))
            .expect("request should build");

        let response = block_on(app.oneshot(request)).expect("router should return a response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn router_rejects_malformed_length_prefix_without_panicking() {
        let app = test_router(4 * 1024 * 1024);
        let request = Request::builder()
            .method("POST")
            .uri("/transactions")
            .body(Body::from(u32::MAX.encode()))
            .expect("request should build");

        let result = catch_unwind(AssertUnwindSafe(|| block_on(app.oneshot(request))));

        let response = result.expect("malformed prefixes must not panic");
        let response = response.expect("router should return a response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
