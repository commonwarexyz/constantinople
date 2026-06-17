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
    Account, LazySignedTransaction, Nonce, SignedTransaction, TransactionPublicKey,
    TransactionSignature, VerifiedTransaction, verify_transaction_chunks,
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

/// Minimum bytes needed to encode a `u64` varint.
const MIN_U64_VARINT_BYTES: usize = 1;

/// Shared state for HTTP handlers.
pub(super) struct AppState<C, P, H, SigSt, HashSt>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    SigSt: Strategy,
    HashSt: Strategy,
{
    pub mailbox: Mailbox<C, P, H>,
    pub namespace: &'static [u8],
    pub max_batch_bytes: usize,
    pub signature_strategy: SigSt,
    pub hash_strategy: HashSt,
    pub account_reader: AccountReaderCell,
}

type SharedState<C, P, H, SigSt, HashSt> = Arc<AppState<C, P, H, SigSt, HashSt>>;

/// Builds the axum [`Router`] for the mempool HTTP API.
pub(super) fn router<C, P, H, SigSt, HashSt>(state: SharedState<C, P, H, SigSt, HashSt>) -> Router
where
    C: Digest + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Display + Send + Sync,
    SigSt: Strategy + Send + Sync + 'static,
    HashSt: Strategy + Send + Sync + 'static,
{
    let max_request_bytes = max_request_bytes(state.max_batch_bytes);
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE]);

    Router::new()
        .route(
            "/transactions",
            post(submit_batch::<C, P, H, SigSt, HashSt>),
        )
        .route(
            "/transactions/ingest",
            post(ingest_batch::<C, P, H, SigSt, HashSt>),
        )
        .route(
            "/transactions/{batch_id}",
            get(fetch_status::<C, P, H, SigSt, HashSt>),
        )
        .route(
            "/account/{public_key}",
            get(fetch_account::<C, P, H, SigSt, HashSt>),
        )
        .route(
            "/consensus/round",
            get(fetch_consensus_round::<C, P, H, SigSt, HashSt>),
        )
        .layer(DefaultBodyLimit::max(max_request_bytes))
        .layer(cors)
        .with_state(state)
}

const fn max_request_bytes(max_batch_bytes: usize) -> usize {
    max_batch_bytes.saturating_add(MAX_BATCH_LENGTH_PREFIX_BYTES)
}

const fn min_signed_transaction_bytes() -> usize {
    TransactionPublicKey::SIZE
        + TransactionPublicKey::SIZE
        + MIN_U64_VARINT_BYTES
        + MIN_U64_VARINT_BYTES
        + TransactionSignature::MIN_SIZE
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
async fn submit_batch<C, P, H, SigSt, HashSt>(
    State(state): State<SharedState<C, P, H, SigSt, HashSt>>,
    body: Bytes,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    SigSt: Strategy,
    HashSt: Strategy,
{
    let batch_id = H::hash(&body).to_string();
    let batch = match verify_body::<P, H, _, _>(&state, body).await {
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
async fn ingest_batch<C, P, H, SigSt, HashSt>(
    State(state): State<SharedState<C, P, H, SigSt, HashSt>>,
    body: Bytes,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    SigSt: Strategy,
    HashSt: Strategy,
{
    let batch_id = H::hash(&body).to_string();
    let batch = match verify_body::<P, H, _, _>(&state, body).await {
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

async fn verify_body<P, H, SigSt, HashSt>(
    state: &AppState<impl Digest, P, H, SigSt, HashSt>,
    body: Bytes,
) -> Result<VerifiedBatch<H>, StatusCode>
where
    P: PublicKey,
    H: Hasher,
    SigSt: Strategy,
    HashSt: Strategy,
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

    let signature_strategy = state.signature_strategy.clone();
    let hash_strategy = state.hash_strategy.clone();
    let namespace = state.namespace;
    let signed_lazy = signed
        .into_iter()
        .map(LazySignedTransaction::new)
        .collect::<Vec<_>>();
    let transactions = tokio::task::spawn_blocking(move || {
        verify_transaction_chunks::<H, _, _>(
            &signature_strategy,
            &hash_strategy,
            namespace,
            &mut OsRng,
            signed_lazy,
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
async fn fetch_status<C, P, H, SigSt, HashSt>(
    State(state): State<SharedState<C, P, H, SigSt, HashSt>>,
    Path(batch_id): Path<String>,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    SigSt: Strategy,
    HashSt: Strategy,
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
async fn fetch_consensus_round<C, P, H, SigSt, HashSt>(
    State(state): State<SharedState<C, P, H, SigSt, HashSt>>,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    SigSt: Strategy,
    HashSt: Strategy,
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
async fn fetch_account<C, P, H, SigSt, HashSt>(
    State(state): State<SharedState<C, P, H, SigSt, HashSt>>,
    Path(public_key): Path<String>,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    SigSt: Strategy,
    HashSt: Strategy,
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
    use super::{
        super::{
            AccountReader, Actor, Config, Mailbox,
            actor::{AccountReaderCell, BatchStatus},
        },
        AppState, router, verify_body,
    };
    use crate::TransactionSource;
    use axum::{
        body::{Body, Bytes, to_bytes},
        http::{Method, Request, StatusCode, header},
        response::Response,
    };
    use commonware_actor::Feedback;
    use commonware_codec::{Encode, EncodeSize};
    use commonware_consensus::{
        Reporter,
        marshal::Update,
        simplex::types::Context,
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{Digest, Hasher, Signer, ed25519, sha256};
    use commonware_formatting::hex;
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner, Supervisor};
    use commonware_utils::{Acknowledgement, acknowledgement::Exact, non_empty_range};
    use constantinople_primitives::{
        Account, Block, Header, Nonce, Sealable, SealedBlock, SignedTransaction,
        TRANSACTION_NAMESPACE, Transaction, TransactionPublicKey, VerifiedTransaction,
    };
    use futures::{executor::block_on, future::BoxFuture};
    use serde_json::json;
    use std::{
        collections::HashMap,
        num::NonZeroU64,
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{Arc, OnceLock},
        time::Duration,
    };
    use tokio::sync::mpsc;
    use tower::ServiceExt;

    type TestDigest = sha256::Digest;
    type TestHasher = sha256::Sha256;
    type TestPublicKey = ed25519::PublicKey;
    type TestMailbox = Mailbox<TestDigest, TestPublicKey, TestHasher>;
    type TestTransaction = SignedTransaction<TestHasher>;
    type TestBlock = SealedBlock<TestDigest, TestPublicKey, TestHasher>;

    struct StaticAccountReader {
        accounts: HashMap<TransactionPublicKey, Account>,
    }

    impl AccountReader for StaticAccountReader {
        fn get<'a>(&'a self, public_key: TransactionPublicKey) -> BoxFuture<'a, Option<Account>> {
            Box::pin(async move { self.accounts.get(&public_key).copied() })
        }
    }

    fn account_reader_cell() -> AccountReaderCell {
        Arc::new(OnceLock::new())
    }

    fn install_account_reader(
        cell: &AccountReaderCell,
        accounts: HashMap<TransactionPublicKey, Account>,
    ) {
        let reader: Arc<dyn AccountReader> = Arc::new(StaticAccountReader { accounts });
        assert!(cell.set(reader).is_ok());
    }

    fn test_state(
        mailbox: TestMailbox,
        max_batch_bytes: usize,
        account_reader: AccountReaderCell,
    ) -> Arc<AppState<TestDigest, TestPublicKey, TestHasher, Sequential, Sequential>> {
        Arc::new(AppState {
            mailbox,
            namespace: TRANSACTION_NAMESPACE,
            max_batch_bytes,
            signature_strategy: Sequential,
            hash_strategy: Sequential,
            account_reader,
        })
    }

    fn test_app(
        mailbox: TestMailbox,
        max_batch_bytes: usize,
        account_reader: AccountReaderCell,
    ) -> axum::Router {
        router::<TestDigest, TestPublicKey, TestHasher, Sequential, Sequential>(test_state(
            mailbox,
            max_batch_bytes,
            account_reader,
        ))
    }

    fn closed_mailbox() -> TestMailbox {
        let (mailbox, receiver) = Mailbox::channel(1);
        drop(receiver);
        mailbox
    }

    fn test_router(max_batch_bytes: usize) -> axum::Router {
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        let mailbox = super::super::mailbox::Mailbox::new(sender);

        test_app(mailbox, max_batch_bytes, account_reader_cell())
    }

    fn signed_transaction(seed: u64, nonce: u64) -> TestTransaction {
        let signer = ed25519::PrivateKey::from_seed(seed);
        let recipient = ed25519::PrivateKey::from_seed(seed + 1_000).public_key();
        Transaction::new(
            TransactionPublicKey::ed25519(signer.public_key()),
            TransactionPublicKey::ed25519(recipient),
            NonZeroU64::new(1).expect("non-zero value"),
            nonce,
        )
        .seal_and_sign(
            &signer,
            TRANSACTION_NAMESPACE,
            &mut sha256::Sha256::default(),
        )
    }

    fn encoded_batch(transactions: &[TestTransaction]) -> Bytes {
        transactions.to_vec().encode()
    }

    fn test_context(view: u64) -> Context<TestDigest, TestPublicKey> {
        let leader = ed25519::PrivateKey::from_seed(42).public_key();
        Context {
            round: Round::new(Epoch::zero(), View::new(view)),
            leader,
            parent: (View::zero(), TestDigest::EMPTY),
        }
    }

    fn test_header(height: u64) -> Header<TestDigest, TestDigest, TestPublicKey> {
        Header {
            context: test_context(height),
            parent: TestDigest::EMPTY,
            height,
            timestamp: height,
            state_root: TestDigest::EMPTY,
            state_range: non_empty_range!(0, 1),
            transactions_root: TestDigest::EMPTY,
            transactions_range: non_empty_range!(0, 1),
        }
    }

    fn sealed_block(height: u64, transactions: Vec<VerifiedTransaction<TestHasher>>) -> TestBlock {
        Block::new(test_header(height), transactions).seal(&mut TestHasher::default())
    }

    fn report_block(mailbox: &TestMailbox, block: TestBlock) {
        let mut reporter = mailbox.clone();
        let (acknowledgement, _acknowledged) = Exact::handle();
        assert!(matches!(
            reporter.report(Update::Block(block, acknowledgement)),
            Feedback::Ok
        ));
    }

    async fn start_actor(
        context: commonware_runtime::tokio::Context,
        max_pool_bytes: usize,
        max_propose_bytes: usize,
    ) -> TestMailbox {
        let (mailbox, receiver) = Mailbox::channel(8);
        let actor = Actor::new(
            context.child("mempool"),
            Config {
                max_pool_bytes,
                max_propose_bytes,
                namespace: TRANSACTION_NAMESPACE,
                drop_grace_blocks: 2,
                signature_strategy: Sequential,
                hash_strategy: Sequential,
            },
            mailbox.clone(),
            receiver,
            account_reader_cell(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener binds");
        let _handle = actor.start(listener);
        mailbox
    }

    fn post(uri: &str, body: Bytes) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .body(Body::from(body))
            .expect("request should build")
    }

    fn get(uri: impl AsRef<str>) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(uri.as_ref())
            .body(Body::empty())
            .expect("request should build")
    }

    async fn send(app: axum::Router, request: Request<Body>) -> Response {
        app.oneshot(request)
            .await
            .expect("router should return a response")
    }

    async fn response_json(response: Response) -> serde_json::Value {
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should collect");
        serde_json::from_slice(&body).expect("response body should be JSON")
    }

    async fn response_text(response: Response) -> String {
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should collect");
        String::from_utf8(body.to_vec()).expect("response body should be UTF-8")
    }

    async fn wait_for_batch_status(mailbox: &TestMailbox, batch_id: &str) -> BatchStatus {
        for _ in 0..100 {
            if let Some(status) = mailbox.query_status(batch_id.to_string()).await {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("batch status was not recorded");
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

    #[test]
    fn router_allows_explorer_account_preflight() {
        let app = test_router(4 * 1024 * 1024);
        let request = Request::builder()
            .method(Method::OPTIONS)
            .uri("/account/00")
            .header(header::ORIGIN, "http://127.0.0.1:5173")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .body(Body::empty())
            .expect("request should build");

        let response = block_on(app.oneshot(request)).expect("router should return a response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&header::HeaderValue::from_static("*")),
        );
    }

    #[test]
    fn verify_body_accepts_valid_signed_batch_and_returns_digests() {
        commonware_runtime::tokio::Runner::default().start(|_| async move {
            let transaction = signed_transaction(1, 0);
            let body = encoded_batch(std::slice::from_ref(&transaction));
            let state = test_state(closed_mailbox(), 1024 * 1024, account_reader_cell());

            let batch = verify_body::<TestPublicKey, TestHasher, _, _>(state.as_ref(), body)
                .await
                .expect("valid signed transaction batch verifies");

            assert_eq!(batch.transactions.len(), 1);
            assert_eq!(
                batch.transactions[0].message_digest(),
                transaction.message_digest()
            );
            assert_eq!(batch.digests, vec![*transaction.message_digest()]);
            assert_eq!(batch.total_bytes, transaction.encode_size());
        });
    }

    #[test]
    fn verify_body_rejects_decoded_batch_over_max_bytes() {
        commonware_runtime::tokio::Runner::default().start(|_| async move {
            let transaction = signed_transaction(2, 0);
            let body = encoded_batch(std::slice::from_ref(&transaction));
            let state = test_state(
                closed_mailbox(),
                transaction.encode_size() - 1,
                account_reader_cell(),
            );

            let Err(status) =
                verify_body::<TestPublicKey, TestHasher, _, _>(state.as_ref(), body).await
            else {
                panic!("decoded transaction bytes should exceed the batch limit");
            };

            assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        });
    }

    #[test]
    fn submit_batch_returns_finalized_status_after_actor_report() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let transaction = signed_transaction(3, 0);
            let digest = *transaction.message_digest();
            let body = encoded_batch(std::slice::from_ref(&transaction));
            let batch_id = TestHasher::hash(&body).to_string();
            let mailbox = start_actor(context, 1024 * 1024, 1024 * 1024).await;
            let app = test_app(mailbox.clone(), 1024 * 1024, account_reader_cell());

            let response_task =
                tokio::spawn(async move { send(app, post("/transactions", body)).await });

            assert_eq!(
                wait_for_batch_status(&mailbox, &batch_id).await,
                BatchStatus::Accepted {
                    digests: vec![digest.to_string()],
                },
            );

            let mut source = mailbox.clone();
            let proposed = source.propose(&test_header(0), &test_context(1)).await;
            assert_eq!(proposed.len(), 1);
            assert_eq!(proposed[0].message_digest(), &digest);

            report_block(&mailbox, sealed_block(1, proposed));

            let response = tokio::time::timeout(Duration::from_secs(1), response_task)
                .await
                .expect("submit response should resolve after finalization")
                .expect("submit task should not panic");
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response_json(response).await,
                json!({
                    "status": "finalized",
                    "height": 1,
                }),
            );
        });
    }

    #[test]
    fn submit_batch_returns_service_unavailable_when_mailbox_is_closed() {
        commonware_runtime::tokio::Runner::default().start(|_| async move {
            let transaction = signed_transaction(4, 0);
            let app = test_app(closed_mailbox(), 1024 * 1024, account_reader_cell());

            let response = send(
                app,
                post(
                    "/transactions",
                    encoded_batch(std::slice::from_ref(&transaction)),
                ),
            )
            .await;

            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(response_text(response).await.is_empty());
        });
    }

    #[test]
    fn ingest_batch_returns_digests_and_fetch_status_returns_accepted() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let transaction = signed_transaction(5, 0);
            let digest = *transaction.message_digest();
            let body = encoded_batch(std::slice::from_ref(&transaction));
            let batch_id = TestHasher::hash(&body).to_string();
            let mailbox = start_actor(context, 1024 * 1024, 1024 * 1024).await;
            let app = test_app(mailbox, 1024 * 1024, account_reader_cell());

            let response = send(app.clone(), post("/transactions/ingest", body)).await;
            assert_eq!(response.status(), StatusCode::ACCEPTED);
            assert_eq!(
                response_json(response).await,
                json!({
                    "digests": [digest.to_string()],
                }),
            );

            let response = send(app.clone(), get(format!("/transactions/{batch_id}"))).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response_json(response).await,
                json!({
                    "status": "accepted",
                    "digests": [digest.to_string()],
                }),
            );

            let response = send(app, get("/transactions/unknown-batch")).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert!(response_text(response).await.is_empty());
        });
    }

    #[test]
    fn ingest_batch_returns_service_unavailable_when_pool_is_full() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let transaction = signed_transaction(6, 0);
            let mailbox = start_actor(context, transaction.encode_size() - 1, 1024 * 1024).await;
            let app = test_app(mailbox, 1024 * 1024, account_reader_cell());

            let response = send(
                app,
                post(
                    "/transactions/ingest",
                    encoded_batch(std::slice::from_ref(&transaction)),
                ),
            )
            .await;

            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(response_text(response).await.is_empty());
        });
    }

    #[test]
    fn fetch_consensus_round_returns_observed_round_and_503_when_unavailable() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let mailbox = start_actor(context, 1024 * 1024, 1024 * 1024).await;
            let app = test_app(mailbox.clone(), 1024 * 1024, account_reader_cell());

            report_block(&mailbox, sealed_block(7, Vec::new()));

            let response = send(app, get("/consensus/round")).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response_json(response).await,
                json!({
                    "round": 7,
                }),
            );

            let unavailable = test_app(closed_mailbox(), 1024 * 1024, account_reader_cell());
            let response = send(unavailable, get("/consensus/round")).await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(response_text(response).await.is_empty());
        });
    }

    #[test]
    fn fetch_account_maps_reader_results_to_http() {
        commonware_runtime::tokio::Runner::default().start(|_| async move {
            let public_key =
                TransactionPublicKey::ed25519(ed25519::PrivateKey::from_seed(7).public_key());
            let public_key_path = format!("/account/{}", hex(public_key.as_ref()));

            let app = test_app(closed_mailbox(), 1024 * 1024, account_reader_cell());
            let response = send(app.clone(), get("/account/not-hex")).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let response = send(app.clone(), get("/account/00")).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);

            let response = send(app, get(&public_key_path)).await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

            let missing_reader = account_reader_cell();
            install_account_reader(&missing_reader, HashMap::new());
            let app = test_app(closed_mailbox(), 1024 * 1024, missing_reader);
            let response = send(app, get(&public_key_path)).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);

            let account = Account {
                balance: 55,
                nonce: Nonce::new(8, 3),
            };
            let reader = account_reader_cell();
            install_account_reader(&reader, HashMap::from([(public_key, account)]));
            let app = test_app(closed_mailbox(), 1024 * 1024, reader);
            let response = send(app, get(&public_key_path)).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response_json(response).await,
                json!({
                    "balance": 55,
                    "nonce": {
                        "base": 8,
                        "bitmap": 3,
                    },
                }),
            );
        });
    }
}
