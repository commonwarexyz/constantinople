//! HTTP handlers for the mempool webserver.

use super::{
    Mailbox,
    actor::{AccountReaderCell, IngestStatus},
};
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{Method, StatusCode, header::CONTENT_TYPE},
    routing::{get, post},
};
use commonware_codec::{Decode, DecodeExt, EncodeSize, FixedSize, RangeCfg};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_formatting::from_hex;
use commonware_parallel::Strategy;
use constantinople_primitives::{
    Account, LazySignedTransaction, Nonce, Operation, PublicKeyCache, SignedTransaction,
    TransactionPublicKey, TransactionSignature, VerifiedTransaction, verify_transaction_chunks,
};
use rand_core::OsRng;
use std::{fmt::Display, sync::Arc};
use tower_http::cors::{Any, CorsLayer};

/// Maximum bytes needed to encode the batch-length prefix.
///
/// `commonware-codec` encodes `Vec` lengths as `u32` varints, which fit in at
/// most 5 bytes.
const MAX_BATCH_LENGTH_PREFIX_BYTES: usize = 5;

/// Minimum bytes needed to encode the batch-length prefix.
const MIN_BATCH_LENGTH_PREFIX_BYTES: usize = 1;

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
    pub public_key_cache: PublicKeyCache,
    pub account_reader: AccountReaderCell,
}

type SharedState<C, P, H, St> = Arc<AppState<C, P, H, St>>;

/// Builds the axum [`Router`] for the mempool HTTP API.
pub(super) fn router<C, P, H, St>(state: SharedState<C, P, H, St>) -> Router
where
    C: Digest + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Display + Send + Sync,
    St: Strategy + Send + Sync + 'static,
{
    let max_request_bytes = max_request_bytes(state.max_batch_bytes);
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE]);

    Router::new()
        .route("/transactions", post(submit_batch::<C, P, H, St>))
        .route("/transactions/ingest", post(ingest_batch::<C, P, H, St>))
        .route("/transactions/{batch_id}", get(fetch_status::<C, P, H, St>))
        .route("/account/{public_key}", get(fetch_account::<C, P, H, St>))
        .route(
            "/consensus/round",
            get(fetch_consensus_round::<C, P, H, St>),
        )
        .layer(DefaultBodyLimit::max(max_request_bytes))
        .layer(cors)
        .with_state(state)
}

const fn max_request_bytes(max_batch_bytes: usize) -> usize {
    max_batch_bytes.saturating_add(MAX_BATCH_LENGTH_PREFIX_BYTES)
}

const fn min_signed_transaction_bytes() -> usize {
    // Smallest signed transaction: the common sender + nonce, the smallest
    // operation (a transfer), and the smallest signature.
    u64::SIZE + TransactionPublicKey::SIZE + Operation::MIN_SIZE + TransactionSignature::MIN_SIZE
}

fn max_transaction_count(body_len: usize) -> Option<usize> {
    let payload_len = body_len.saturating_sub(MIN_BATCH_LENGTH_PREFIX_BYTES);
    let max_transactions = payload_len / min_signed_transaction_bytes();
    (max_transactions > 0).then_some(max_transactions)
}

/// Accepts a batch of signed transactions as a commonware-codec length-prefixed
/// vector.
///
/// Signatures are verified in parallel using the configured [`Strategy`].
/// Blocks until the batch is fully finalized, partially finalized, or dropped.
///
/// Returns:
/// - `200 OK` with JSON status on finalization or drop.
/// - `400 Bad Request` if the body is empty, any transaction fails to decode,
///   or any signature is invalid.
/// - `413 Payload Too Large` if the batch exceeds `max_propose_bytes`.
/// - `503 Service Unavailable` if the pool is full.
async fn submit_batch<C, P, H, St>(
    State(state): State<SharedState<C, P, H, St>>,
    body: Bytes,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    let batch_id = H::hash(&body).to_string();
    let batch = match verify_body::<P, H, _>(&state, body).await {
        Ok(batch) => batch,
        Err(status) => return (status, String::new()),
    };

    // Phase 3: Submit to actor and await result.
    let Some(result_rx) = state.mailbox.try_submit(
        batch_id,
        batch.digests,
        batch.transactions,
        batch.total_bytes,
    ) else {
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

/// Accepts a verified transaction batch without waiting for finalization.
///
/// This endpoint is intended for relayers. It uses the same body format and
/// validation path as [`submit_batch`], but returns as soon as the actor has
/// accepted the batch for proposal.
async fn ingest_batch<C, P, H, St>(
    State(state): State<SharedState<C, P, H, St>>,
    body: Bytes,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    let batch_id = H::hash(&body).to_string();
    let batch = match verify_body::<P, H, _>(&state, body).await {
        Ok(batch) => batch,
        Err(status) => return (status, String::new()),
    };
    let digests = batch.digests.iter().map(ToString::to_string).collect();

    let Some(result_rx) = state.mailbox.try_ingest(
        batch_id,
        batch.digests,
        batch.transactions,
        batch.total_bytes,
    ) else {
        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
    };

    match result_rx.await {
        Ok(IngestStatus::Accepted) => {}
        Ok(IngestStatus::Dropped) => return (StatusCode::SERVICE_UNAVAILABLE, String::new()),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, String::new()),
    }

    let response = IngestResponse { digests };
    (
        StatusCode::ACCEPTED,
        serde_json::to_string(&response).expect("ingest response serialization cannot fail"),
    )
}

struct VerifiedBatch<H>
where
    H: Hasher,
{
    transactions: Vec<VerifiedTransaction<H>>,
    digests: Vec<H::Digest>,
    total_bytes: usize,
}

async fn verify_body<P, H, St>(
    state: &AppState<impl Digest, P, H, St>,
    body: Bytes,
) -> Result<VerifiedBatch<H>, StatusCode>
where
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    if body.len() > max_request_bytes(state.max_batch_bytes) {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let Some(max_transactions) = max_transaction_count(body.len()) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let cfg = (RangeCfg::new(1..=max_transactions), ());
    let signed = Vec::<SignedTransaction<H>>::decode_cfg(body.as_ref(), &cfg)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let total_bytes: usize = signed.iter().map(EncodeSize::encode_size).sum();

    if total_bytes > state.max_batch_bytes {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let strategy = state.strategy.clone();
    let namespace = state.namespace;
    let public_key_cache = state.public_key_cache.clone();
    let signed_lazy = signed
        .into_iter()
        .map(LazySignedTransaction::new)
        .collect::<Vec<_>>();
    let transactions = tokio::task::spawn_blocking(move || {
        verify_transaction_chunks::<H, _>(
            namespace,
            &mut OsRng,
            &public_key_cache,
            signed_lazy,
            &strategy,
        )
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::BAD_REQUEST)?;
    let digests = transactions
        .iter()
        .map(|transaction| *transaction.message_digest())
        .collect();

    Ok(VerifiedBatch {
        transactions,
        digests,
        total_bytes,
    })
}

#[derive(serde::Serialize)]
struct IngestResponse {
    digests: Vec<String>,
}

#[derive(serde::Serialize)]
struct ConsensusRoundResponse {
    round: u64,
}

/// Returns the latest known status for a submitted batch.
async fn fetch_status<C, P, H, St>(
    State(state): State<SharedState<C, P, H, St>>,
    Path(batch_id): Path<String>,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    state.mailbox.query_status(batch_id).await.map_or_else(
        || (StatusCode::NOT_FOUND, String::new()),
        |status| {
            (
                StatusCode::OK,
                serde_json::to_string(&status).expect("batch status serialization cannot fail"),
            )
        },
    )
}

/// Returns the highest consensus round observed by this validator.
async fn fetch_consensus_round<C, P, H, St>(
    State(state): State<SharedState<C, P, H, St>>,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    state.mailbox.query_consensus_round().await.map_or_else(
        || (StatusCode::SERVICE_UNAVAILABLE, String::new()),
        |round| {
            (
                StatusCode::OK,
                serde_json::to_string(&ConsensusRoundResponse { round })
                    .expect("consensus round serialization cannot fail"),
            )
        },
    )
}

/// Returns the committed account for the hex-encoded public key.
///
/// Responds with:
/// - `200 OK` and account JSON if the account exists.
/// - `404 Not Found` if the account has not been written.
/// - `400 Bad Request` if the path is not a valid public key hex string.
/// - `503 Service Unavailable` if the state database has not been attached yet.
async fn fetch_account<C, P, H, St>(
    State(state): State<SharedState<C, P, H, St>>,
    Path(public_key): Path<String>,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    let Some(bytes) = from_hex(&public_key) else {
        return (StatusCode::BAD_REQUEST, String::new());
    };
    if bytes.len() != TransactionPublicKey::SIZE {
        return (StatusCode::BAD_REQUEST, String::new());
    }
    let public_key = match TransactionPublicKey::decode(bytes.as_slice()) {
        Ok(public_key) => public_key,
        Err(_) => return (StatusCode::BAD_REQUEST, String::new()),
    };

    let Some(reader) = state.account_reader.get() else {
        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
    };

    reader.get(public_key).await.map_or_else(
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
    nonce: NonceResponse,
}

#[derive(serde::Serialize)]
struct NonceResponse {
    base: u64,
    bitmap: u64,
}

impl From<Account> for AccountResponse {
    fn from(account: Account) -> Self {
        Self {
            balance: account.balance,
            nonce: NonceResponse::from(account.nonce),
        }
    }
}

impl From<Nonce> for NonceResponse {
    fn from(nonce: Nonce) -> Self {
        Self {
            base: nonce.base,
            bitmap: nonce.bitmap,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AppState, PublicKeyCache, router};
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode, header},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{ed25519, sha256};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Metrics, Runner as _};
    use commonware_utils::NZUsize;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tower::ServiceExt;

    fn test_router(context: impl Metrics, max_batch_bytes: usize) -> axum::Router {
        let (sender, _receiver) = mpsc::channel(1);
        let state = Arc::new(AppState {
            mailbox: super::super::mailbox::Mailbox::new(sender),
            namespace: b"mempool-http-test",
            max_batch_bytes,
            strategy: Sequential,
            public_key_cache: PublicKeyCache::new(context, NZUsize!(16)),
            account_reader: std::sync::Arc::new(std::sync::OnceLock::new()),
        });

        router::<sha256::Digest, ed25519::PublicKey, sha256::Sha256, Sequential>(state)
    }

    #[test]
    fn router_accepts_requests_above_axum_default_limit() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let app = test_router(context, 4 * 1024 * 1024);
            let request = Request::builder()
                .method("POST")
                .uri("/transactions")
                .body(Body::from(vec![0u8; 2 * 1024 * 1024 + 1]))
                .expect("request should build");

            let response = app.oneshot(request).await.expect("router should respond");

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        });
    }

    #[test]
    fn router_rejects_malformed_length_prefix_without_panicking() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let app = test_router(context, 4 * 1024 * 1024);
            let request = Request::builder()
                .method("POST")
                .uri("/transactions")
                .body(Body::from(u32::MAX.encode()))
                .expect("request should build");

            // A panic here (rather than a clean rejection) would fail the test.
            let response = app.oneshot(request).await.expect("router should respond");

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        });
    }

    #[test]
    fn router_allows_explorer_account_preflight() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let app = test_router(context, 4 * 1024 * 1024);
            let request = Request::builder()
                .method(Method::OPTIONS)
                .uri("/account/00")
                .header(header::ORIGIN, "http://127.0.0.1:5173")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .body(Body::empty())
                .expect("request should build");

            let response = app.oneshot(request).await.expect("router should respond");

            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
                Some(&header::HeaderValue::from_static("*")),
            );
        });
    }
}
