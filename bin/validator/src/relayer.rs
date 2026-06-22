//! Consensus-following transaction relayer.

use crate::config::{RelayerConfig, RelayerLeaderConfig};
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, Method, StatusCode, header::CONTENT_TYPE},
    routing::{get, post},
};
use commonware_actor::Feedback;
use commonware_codec::{Decode, DecodeExt, Encode, EncodeSize, FixedSize, RangeCfg};
use commonware_consensus::{Reporter, Viewable};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::MinSig, ed25519, sha256};
use commonware_formatting::from_hex;
use constantinople_engine::types::EngineActivity;
use constantinople_mempool::webserver::{AccountReader, TxStatus};
use constantinople_primitives::{Account, Nonce, SignedTransaction, TransactionPublicKey};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{Arc, OnceLock},
};
use tokio::sync::watch;
use tower_http::cors::{Any, CorsLayer};
use tracing::debug;

const DEFAULT_MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
const MAX_BATCH_LENGTH_PREFIX_BYTES: usize = 5;
const MIN_BATCH_LENGTH_PREFIX_BYTES: usize = 1;
const TARGET_LEADER_HEADER: &str = "x-constantinople-relayer-target-leader";
const LEADER_FANOUT_HEADER: &str = "x-constantinople-relayer-leader-fanout";
const PINNED_SUBMIT_RETRIES: usize = 3;

type Activity = EngineActivity<ed25519::PublicKey, MinSig>;

#[derive(Clone)]
pub struct Observer {
    current_view: watch::Sender<u64>,
}

#[derive(Clone)]
pub struct ViewClock {
    current_view: watch::Sender<u64>,
}

impl Observer {
    pub fn new() -> (Self, ViewClock) {
        let (current_view, _) = watch::channel(0);
        (
            Self {
                current_view: current_view.clone(),
            },
            ViewClock { current_view },
        )
    }
}

impl Reporter for Observer {
    type Activity = Activity;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let view = activity_view(&activity);
        self.current_view.send_if_modified(|current| {
            if view <= *current {
                return false;
            }
            *current = view;
            true
        });
        Feedback::Ok
    }
}

fn activity_view(activity: &Activity) -> u64 {
    match activity {
        Activity::Notarize(activity) => activity.view().get(),
        Activity::Notarization(activity) | Activity::Certification(activity) => {
            activity.view().get()
        }
        Activity::Nullify(activity) => activity.view().get(),
        Activity::Nullification(activity) => activity.view().get(),
        Activity::Finalize(activity) => activity.view().get(),
        Activity::Finalization(activity) => activity.view().get(),
        Activity::ConflictingNotarize(activity) => activity.view().get(),
        Activity::ConflictingFinalize(activity) => activity.view().get(),
        Activity::NullifyFinalize(activity) => activity.view().get(),
    }
}

#[derive(Clone)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub relayer: RelayerConfig,
    pub account_reader: Arc<OnceLock<Arc<dyn AccountReader>>>,
    pub view_clock: ViewClock,
}

#[derive(Clone)]
struct AppState {
    leaders: Arc<Vec<Leader>>,
    max_retry_views: u64,
    max_batch_bytes: usize,
    account_reader: Arc<OnceLock<Arc<dyn AccountReader>>>,
    view_clock: ViewClock,
    http: reqwest::Client,
}

#[derive(Debug, Clone)]
struct Leader {
    public_key: String,
    sort_key: Vec<u8>,
    url: String,
}

#[derive(Debug)]
struct DecodedBatch {
    transactions: Vec<SignedTransaction<sha256::Sha256>>,
    digests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "status")]
enum BatchStatus {
    Accepted {
        digests: Vec<String>,
    },
    Finalized {
        height: u64,
        included: Vec<String>,
    },
    PartiallyFinalized {
        height: u64,
        included: Vec<String>,
        filtered: Vec<String>,
    },
    Dropped {
        filtered: Vec<String>,
    },
}

#[derive(Debug)]
enum ForwardResult {
    Accepted { leader: Leader },
    Deterministic(StatusCode),
    Transient { leader: Leader },
}

#[derive(Debug, Deserialize)]
struct IngestResponse {
    digests: Vec<String>,
}

pub async fn serve(config: ServerConfig) {
    let state = AppState {
        leaders: Arc::new(normalize_leaders(config.relayer.leaders)),
        max_retry_views: config.relayer.max_retry_views,
        max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
        account_reader: config.account_reader,
        view_clock: config.view_clock,
        http: reqwest::Client::new(),
    };
    let listen = config.listen;
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .expect("failed to bind relayer listener");
    axum::serve(listener, app)
        .await
        .expect("relayer HTTP server exited");
}

fn router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE]);

    Router::new()
        .route("/transactions", post(submit_transactions))
        .route("/transactions/{batch_id}", get(transaction_status))
        .route("/account/{public_key}", get(account))
        .route("/health", get(health))
        .route("/ready", get(ready))
        .layer(DefaultBodyLimit::max(max_request_bytes(
            state.max_batch_bytes,
        )))
        .layer(cors)
        .with_state(state)
}

async fn submit_transactions(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, String) {
    if let Some(target) = requested_target_leader(&headers) {
        if body.len() > max_request_bytes(state.max_batch_bytes) {
            return (StatusCode::PAYLOAD_TOO_LARGE, String::new());
        }
        if requested_leader_fanout(&headers).is_some_and(|fanout| fanout != 1) {
            return (StatusCode::BAD_REQUEST, String::new());
        }
        return submit_to_pinned_leader(&state, body, &target).await;
    }

    let batch = match decode_batch(&body, state.max_batch_bytes) {
        Ok(batch) => batch,
        Err(status) => return (status, String::new()),
    };

    submit_with_retries(&state, batch).await
}

async fn submit_to_pinned_leader(
    state: &AppState,
    body: Bytes,
    target: &str,
) -> (StatusCode, String) {
    let Some(leader) = leader_by_id(&state.leaders, target).cloned() else {
        return (StatusCode::BAD_REQUEST, String::new());
    };
    submit_blocking_to_leader(&state.http, &leader, body).await
}

async fn submit_with_retries(state: &AppState, batch: DecodedBatch) -> (StatusCode, String) {
    if state.leaders.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
    }

    let mut pending = batch.digests.iter().cloned().collect::<HashSet<_>>();
    let mut included = HashSet::new();
    let mut height = 0;
    let mut accepted_any = false;
    let mut attempts = Vec::<(String, Leader)>::new();
    let mut views = state.view_clock.current_view.subscribe();
    let mut view = *views.borrow();

    for retry in 0..=state.max_retry_views {
        let body = encode_pending(&batch, &pending);
        let sent_batch_id = batch_id(&body);

        for target in next_two_leaders(&state.leaders, view) {
            attempts.push((sent_batch_id.clone(), target));
        }

        let targets = attempts
            .iter()
            .filter(|(batch_id, _)| batch_id == &sent_batch_id)
            .map(|(_, leader)| leader.clone())
            .collect::<Vec<_>>();
        let result = forward_to_targets(&state.http, &targets, body).await;
        if let Some(status) = result.deterministic {
            return (status, String::new());
        }
        accepted_any |= result.accepted;

        merge_statuses(state, &attempts, &mut included, &mut height).await;
        pending.retain(|digest| !included.contains(digest));
        if pending.is_empty() {
            return json_response(TxStatus::Finalized { height });
        }

        if retry == state.max_retry_views {
            if !accepted_any {
                return (StatusCode::SERVICE_UNAVAILABLE, String::new());
            }
            return json_response(best_effort_status(&batch.digests, &included, height));
        }

        wait_for_view_advance(&mut views, &mut view).await;
    }

    json_response(best_effort_status(&batch.digests, &included, height))
}

struct ForwardSummary {
    accepted: bool,
    deterministic: Option<StatusCode>,
}

async fn forward_to_targets(
    http: &reqwest::Client,
    targets: &[Leader],
    body: Bytes,
) -> ForwardSummary {
    let sends = targets.iter().map(|leader| {
        let leader = leader.clone();
        let http = http.clone();
        let body = body.clone();
        async move { forward_to_leader(&http, leader, body).await }
    });

    let mut accepted = false;
    let mut deterministic = None;
    for result in join_all(sends).await {
        match result {
            ForwardResult::Accepted { leader } => {
                accepted = true;
                debug!(leader = %leader.public_key, "relayer forward accepted");
            }
            ForwardResult::Deterministic(status) => deterministic = Some(status),
            ForwardResult::Transient { leader } => {
                debug!(leader = %leader.public_key, "relayer forward transient failure");
            }
        }
    }

    ForwardSummary {
        accepted,
        deterministic,
    }
}

async fn merge_statuses(
    state: &AppState,
    attempts: &[(String, Leader)],
    included: &mut HashSet<String>,
    height: &mut u64,
) {
    for (batch_id, leader) in attempts {
        let Some(status) = fetch_status_from_leader(&state.http, leader, batch_id).await else {
            continue;
        };
        match status {
            BatchStatus::Accepted { .. } => {}
            BatchStatus::Finalized {
                height: finalized_height,
                included: leader_included,
            }
            | BatchStatus::PartiallyFinalized {
                height: finalized_height,
                included: leader_included,
                ..
            } => {
                *height = (*height).max(finalized_height);
                included.extend(leader_included);
            }
            BatchStatus::Dropped { .. } => {}
        }
    }
}

async fn wait_for_view_advance(views: &mut watch::Receiver<u64>, current: &mut u64) {
    loop {
        if views.changed().await.is_err() {
            return;
        }
        let next = *views.borrow();
        if next > *current {
            *current = next;
            return;
        }
    }
}

fn best_effort_status(digests: &[String], included: &HashSet<String>, height: u64) -> TxStatus {
    if included.is_empty() {
        return TxStatus::Dropped;
    }
    let filtered = digests
        .iter()
        .filter(|digest| !included.contains(*digest))
        .cloned()
        .collect::<Vec<_>>();
    if filtered.is_empty() {
        return TxStatus::Finalized { height };
    }
    let included = digests
        .iter()
        .filter(|digest| included.contains(*digest))
        .cloned()
        .collect();
    TxStatus::PartiallyFinalized {
        height,
        included,
        filtered,
    }
}

fn json_response(status: TxStatus) -> (StatusCode, String) {
    (
        StatusCode::OK,
        serde_json::to_string(&status).expect("transaction status serialization cannot fail"),
    )
}

async fn transaction_status() -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, String::new())
}

async fn account(
    State(state): State<AppState>,
    Path(public_key): Path<String>,
) -> (StatusCode, String) {
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
    let Some(account) = reader.get(public_key).await else {
        return (StatusCode::NOT_FOUND, String::new());
    };

    (
        StatusCode::OK,
        serde_json::to_string(&AccountResponse::from(account))
            .expect("account serialization cannot fail"),
    )
}

#[derive(Serialize)]
struct AccountResponse {
    balance: u64,
    nonce: NonceResponse,
}

#[derive(Serialize)]
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

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn ready(State(state): State<AppState>) -> StatusCode {
    if state.leaders.is_empty() {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    StatusCode::OK
}

async fn forward_to_leader(http: &reqwest::Client, leader: Leader, body: Bytes) -> ForwardResult {
    match http
        .post(format!("{}/transactions/ingest", leader.url))
        .header("content-type", "application/octet-stream")
        .body(body)
        .send()
        .await
    {
        Ok(response) if response.status() == StatusCode::ACCEPTED => {
            let Ok(bytes) = response.bytes().await else {
                return ForwardResult::Transient { leader };
            };
            let Ok(ack) = serde_json::from_slice::<IngestResponse>(&bytes) else {
                return ForwardResult::Transient { leader };
            };
            if ack.digests.is_empty() {
                return ForwardResult::Transient { leader };
            }
            ForwardResult::Accepted { leader }
        }
        Ok(response)
            if response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::PAYLOAD_TOO_LARGE =>
        {
            ForwardResult::Deterministic(response.status())
        }
        Ok(_) | Err(_) => ForwardResult::Transient { leader },
    }
}

async fn submit_blocking_to_leader(
    http: &reqwest::Client,
    leader: &Leader,
    body: Bytes,
) -> (StatusCode, String) {
    let mut backoff = std::time::Duration::from_millis(50);
    for attempt in 0..PINNED_SUBMIT_RETRIES {
        match http
            .post(format!("{}/transactions", leader.url))
            .header("content-type", "application/octet-stream")
            .body(body.clone())
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                if should_retry_pinned_submit(status) && attempt + 1 < PINNED_SUBMIT_RETRIES {
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                    continue;
                }
                return (status, body);
            }
            Err(_) if attempt + 1 < PINNED_SUBMIT_RETRIES => {
                tokio::time::sleep(backoff).await;
                backoff *= 2;
            }
            Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, String::new()),
        }
    }

    (StatusCode::SERVICE_UNAVAILABLE, String::new())
}

fn should_retry_pinned_submit(status: StatusCode) -> bool {
    status == StatusCode::SERVICE_UNAVAILABLE || status.is_server_error()
}

async fn fetch_status_from_leader(
    http: &reqwest::Client,
    leader: &Leader,
    batch_id: &str,
) -> Option<BatchStatus> {
    let response = http
        .get(format!("{}/transactions/{batch_id}", leader.url))
        .send()
        .await
        .ok()?;
    if response.status() != StatusCode::OK {
        return None;
    }
    let bytes = response.bytes().await.ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn decode_batch(body: &Bytes, max_batch_bytes: usize) -> Result<DecodedBatch, StatusCode> {
    if body.len() > max_request_bytes(max_batch_bytes) {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let Some(max_transactions) = max_transaction_count(body.len()) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let cfg = (RangeCfg::new(1..=max_transactions), ());
    let transactions = Vec::<SignedTransaction<sha256::Sha256>>::decode_cfg(body.as_ref(), &cfg)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let total_bytes = transactions
        .iter()
        .map(EncodeSize::encode_size)
        .sum::<usize>();
    if total_bytes > max_batch_bytes {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let digests = transactions
        .iter()
        .map(|transaction| transaction.message_digest().to_string())
        .collect();

    Ok(DecodedBatch {
        transactions,
        digests,
    })
}

fn encode_pending(batch: &DecodedBatch, pending: &HashSet<String>) -> Bytes {
    batch
        .transactions
        .iter()
        .filter(|transaction| pending.contains(&transaction.message_digest().to_string()))
        .cloned()
        .collect::<Vec<_>>()
        .encode()
}

const fn max_request_bytes(max_batch_bytes: usize) -> usize {
    max_batch_bytes.saturating_add(MAX_BATCH_LENGTH_PREFIX_BYTES)
}

fn max_transaction_count(body_len: usize) -> Option<usize> {
    let payload_len = body_len.saturating_sub(MIN_BATCH_LENGTH_PREFIX_BYTES);
    let max_transactions = payload_len / min_signed_transaction_bytes();
    (max_transactions > 0).then_some(max_transactions)
}

const fn min_signed_transaction_bytes() -> usize {
    constantinople_primitives::TransactionPublicKey::SIZE
        + constantinople_primitives::TransactionPublicKey::SIZE
        + 1
        + 1
        + constantinople_primitives::TransactionSignature::MIN_SIZE
}

fn batch_id(body: &Bytes) -> String {
    sha256::Sha256::hash(body).to_string()
}

fn requested_target_leader(headers: &HeaderMap) -> Option<String> {
    Some(
        headers
            .get(TARGET_LEADER_HEADER)?
            .to_str()
            .ok()?
            .to_lowercase(),
    )
}

fn requested_leader_fanout(headers: &HeaderMap) -> Option<usize> {
    headers
        .get(LEADER_FANOUT_HEADER)?
        .to_str()
        .ok()?
        .parse::<usize>()
        .ok()
}

fn normalize_leaders(leaders: Vec<RelayerLeaderConfig>) -> Vec<Leader> {
    let mut leaders = leaders
        .into_iter()
        .map(|leader| {
            let public_key = leader.public_key.to_lowercase();
            Leader {
                sort_key: from_hex(&public_key)
                    .unwrap_or_else(|| panic!("leader public_key must be hex: {public_key}")),
                public_key,
                url: leader.url.trim_end_matches('/').to_string(),
            }
        })
        .collect::<Vec<_>>();
    leaders.sort_by(|left, right| {
        left.sort_key
            .cmp(&right.sort_key)
            .then_with(|| left.public_key.cmp(&right.public_key))
    });
    leaders
}

fn next_two_leaders(leaders: &[Leader], observed_view: u64) -> Vec<Leader> {
    if leaders.is_empty() {
        return Vec::new();
    }
    let first = ((observed_view + 1) as usize) % leaders.len();
    let second = ((observed_view + 2) as usize) % leaders.len();
    if first == second {
        return vec![leaders[first].clone()];
    }
    vec![leaders[first].clone(), leaders[second].clone()]
}

fn leader_by_id<'a>(leaders: &'a [Leader], public_key: &str) -> Option<&'a Leader> {
    leaders
        .iter()
        .find(|leader| leader.public_key == public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        extract::Path,
        http::HeaderValue,
        response::Response,
    };
    use commonware_cryptography::Signer as _;
    use constantinople_primitives::{TRANSACTION_NAMESPACE, Transaction};
    use futures::future::BoxFuture;
    use std::{
        collections::HashMap,
        num::NonZeroU64,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use tower::ServiceExt;

    struct StaticAccountReader {
        accounts: HashMap<TransactionPublicKey, Account>,
    }

    impl AccountReader for StaticAccountReader {
        fn get<'a>(&'a self, public_key: TransactionPublicKey) -> BoxFuture<'a, Option<Account>> {
            Box::pin(async move { self.accounts.get(&public_key).copied() })
        }
    }

    fn leader(key: &str) -> Leader {
        Leader {
            public_key: key.to_string(),
            sort_key: from_hex(key).expect("hex key"),
            url: format!("http://{key}"),
        }
    }

    fn leader_with_url(key: &str, url: String) -> Leader {
        Leader {
            public_key: key.to_string(),
            sort_key: from_hex(key).expect("hex key"),
            url,
        }
    }

    async fn spawn_mock_leader(mock: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock leader");
        let leader_url = format!("http://{}", listener.local_addr().expect("mock addr"));
        tokio::spawn(async move {
            axum::serve(listener, mock)
                .await
                .expect("mock leader serve");
        });
        leader_url
    }

    fn pinned_state(leader_url: String) -> AppState {
        let (_, view_clock) = Observer::new();
        AppState {
            leaders: Arc::new(vec![Leader {
                public_key: "00".to_string(),
                sort_key: vec![0],
                url: leader_url,
            }]),
            max_retry_views: 1,
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            account_reader: Arc::new(OnceLock::new()),
            view_clock,
            http: reqwest::Client::new(),
        }
    }

    fn test_state(
        leaders: Vec<Leader>,
        account_reader: Arc<OnceLock<Arc<dyn AccountReader>>>,
    ) -> AppState {
        let (_, view_clock) = Observer::new();
        AppState {
            leaders: Arc::new(leaders),
            max_retry_views: 0,
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            account_reader,
            view_clock,
            http: reqwest::Client::new(),
        }
    }

    fn empty_account_reader() -> Arc<OnceLock<Arc<dyn AccountReader>>> {
        Arc::new(OnceLock::new())
    }

    fn account_reader_with(
        accounts: HashMap<TransactionPublicKey, Account>,
    ) -> Arc<OnceLock<Arc<dyn AccountReader>>> {
        let cell = empty_account_reader();
        let reader: Arc<dyn AccountReader> = Arc::new(StaticAccountReader { accounts });
        assert!(cell.set(reader).is_ok());
        cell
    }

    fn pinned_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(TARGET_LEADER_HEADER, HeaderValue::from_static("00"));
        headers.insert(LEADER_FANOUT_HEADER, HeaderValue::from_static("1"));
        headers
    }

    fn signed_transaction(seed: u64, nonce: u64) -> SignedTransaction<sha256::Sha256> {
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

    fn encoded_batch(transactions: &[SignedTransaction<sha256::Sha256>]) -> Bytes {
        transactions.to_vec().encode()
    }

    async fn response_json(response: Response) -> serde_json::Value {
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should collect");
        serde_json::from_slice(&body).expect("response body should be JSON")
    }

    async fn router_get(app: Router, uri: &str) -> Response {
        app.oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should respond")
    }

    async fn spawn_accepting_status_leader(status: BatchStatus) -> String {
        let status = Arc::new(status);
        let mock = Router::new()
            .route(
                "/transactions/ingest",
                post(|| async {
                    (
                        StatusCode::ACCEPTED,
                        r#"{"digests":["accepted"]}"#.to_string(),
                    )
                }),
            )
            .route(
                "/transactions/{batch_id}",
                get(move || {
                    let status = status.clone();
                    async move {
                        (
                            StatusCode::OK,
                            serde_json::to_string(status.as_ref()).expect("status serializes"),
                        )
                    }
                }),
            );
        spawn_mock_leader(mock).await
    }

    #[tokio::test]
    async fn router_serves_health_ready_and_unknown_transaction_status() {
        let app = router(test_state(Vec::new(), empty_account_reader()));

        let response = router_get(app.clone(), "/health").await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = router_get(app.clone(), "/ready").await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let response = router_get(app, "/transactions/some-batch").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let ready_app = router(test_state(vec![leader("00")], empty_account_reader()));
        let response = router_get(ready_app, "/ready").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn account_endpoint_maps_reader_results_to_http() {
        let public_key =
            TransactionPublicKey::ed25519(ed25519::PrivateKey::from_seed(7).public_key());
        let public_key_path = format!("/account/{public_key}");

        let app = router(test_state(Vec::new(), empty_account_reader()));
        let response = router_get(app.clone(), "/account/not-hex").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = router_get(app.clone(), "/account/00").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = router_get(app, &public_key_path).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let missing_app = router(test_state(Vec::new(), account_reader_with(HashMap::new())));
        let response = router_get(missing_app, &public_key_path).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let account = Account {
            balance: 55,
            nonce: Nonce::new(8, 3),
        };
        let present_app = router(test_state(
            Vec::new(),
            account_reader_with(HashMap::from([(public_key, account)])),
        ));
        let response = router_get(present_app, &public_key_path).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_json(response).await,
            serde_json::json!({
                "balance": 55,
                "nonce": {
                    "base": 8,
                    "bitmap": 3,
                },
            }),
        );
    }

    #[test]
    fn decode_batch_validates_encoded_transaction_batches() {
        let transaction = signed_transaction(1, 0);
        let body = encoded_batch(std::slice::from_ref(&transaction));

        let batch = decode_batch(&body, DEFAULT_MAX_BATCH_BYTES).expect("batch decodes");
        assert_eq!(batch.transactions.len(), 1);
        assert_eq!(
            batch.digests,
            vec![transaction.message_digest().to_string()]
        );

        assert_eq!(
            decode_batch(&Bytes::from_static(b"bad"), DEFAULT_MAX_BATCH_BYTES)
                .expect_err("malformed body rejected"),
            StatusCode::BAD_REQUEST,
        );

        assert_eq!(
            decode_batch(&Bytes::from(vec![0; max_request_bytes(0) + 1]), 0)
                .expect_err("oversized raw body rejected"),
            StatusCode::PAYLOAD_TOO_LARGE,
        );

        assert_eq!(
            decode_batch(&body, transaction.encode_size() - 1)
                .expect_err("oversized decoded batch rejected"),
            StatusCode::PAYLOAD_TOO_LARGE,
        );
    }

    #[test]
    fn encode_pending_only_resubmits_unresolved_transactions() {
        let first = signed_transaction(2, 0);
        let second = signed_transaction(3, 0);
        let second_digest = second.message_digest().to_string();
        let body = encoded_batch(&[first, second]);
        let batch = decode_batch(&body, DEFAULT_MAX_BATCH_BYTES).expect("batch decodes");
        let pending = HashSet::from([second_digest.clone()]);

        let retried = decode_batch(&encode_pending(&batch, &pending), DEFAULT_MAX_BATCH_BYTES)
            .expect("pending batch decodes");

        assert_eq!(retried.transactions.len(), 1);
        assert_eq!(retried.digests, vec![second_digest]);
    }

    #[tokio::test]
    async fn forward_to_leader_classifies_responses() {
        let accepted_url = spawn_mock_leader(Router::new().route(
            "/transactions/ingest",
            post(|| async { (StatusCode::ACCEPTED, r#"{"digests":["aa"]}"#.to_string()) }),
        ))
        .await;
        match forward_to_leader(
            &reqwest::Client::new(),
            leader_with_url("00", accepted_url),
            Bytes::from_static(b"body"),
        )
        .await
        {
            ForwardResult::Accepted { leader } => assert_eq!(leader.public_key, "00"),
            result => panic!("expected accepted result, got {result:?}"),
        }

        let invalid_json_url = spawn_mock_leader(Router::new().route(
            "/transactions/ingest",
            post(|| async { (StatusCode::ACCEPTED, "not-json") }),
        ))
        .await;
        assert!(matches!(
            forward_to_leader(
                &reqwest::Client::new(),
                leader_with_url("01", invalid_json_url),
                Bytes::from_static(b"body"),
            )
            .await,
            ForwardResult::Transient { .. }
        ));

        let empty_digests_url = spawn_mock_leader(Router::new().route(
            "/transactions/ingest",
            post(|| async { (StatusCode::ACCEPTED, r#"{"digests":[]}"#.to_string()) }),
        ))
        .await;
        assert!(matches!(
            forward_to_leader(
                &reqwest::Client::new(),
                leader_with_url("02", empty_digests_url),
                Bytes::from_static(b"body"),
            )
            .await,
            ForwardResult::Transient { .. }
        ));

        for (key, status) in [
            ("03", StatusCode::BAD_REQUEST),
            ("04", StatusCode::PAYLOAD_TOO_LARGE),
        ] {
            let url = spawn_mock_leader(
                Router::new().route("/transactions/ingest", post(move || async move { status })),
            )
            .await;
            assert!(matches!(
                forward_to_leader(
                    &reqwest::Client::new(),
                    leader_with_url(key, url),
                    Bytes::from_static(b"body"),
                )
                .await,
                ForwardResult::Deterministic(actual) if actual == status
            ));
        }

        let unavailable_url = spawn_mock_leader(Router::new().route(
            "/transactions/ingest",
            post(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        ))
        .await;
        assert!(matches!(
            forward_to_leader(
                &reqwest::Client::new(),
                leader_with_url("05", unavailable_url),
                Bytes::from_static(b"body"),
            )
            .await,
            ForwardResult::Transient { .. }
        ));
    }

    #[tokio::test]
    async fn forward_to_targets_summarizes_acceptance_and_deterministic_errors() {
        let accepted_url = spawn_mock_leader(Router::new().route(
            "/transactions/ingest",
            post(|| async { (StatusCode::ACCEPTED, r#"{"digests":["aa"]}"#.to_string()) }),
        ))
        .await;
        let deterministic_url = spawn_mock_leader(Router::new().route(
            "/transactions/ingest",
            post(|| async { StatusCode::PAYLOAD_TOO_LARGE }),
        ))
        .await;
        let targets = vec![
            leader_with_url("00", accepted_url),
            leader_with_url("01", deterministic_url),
        ];

        let summary = forward_to_targets(
            &reqwest::Client::new(),
            &targets,
            Bytes::from_static(b"body"),
        )
        .await;

        assert!(summary.accepted);
        assert_eq!(summary.deterministic, Some(StatusCode::PAYLOAD_TOO_LARGE));
    }

    #[tokio::test]
    async fn fetch_and_merge_statuses_collect_only_included_digests() {
        let statuses = Arc::new(HashMap::from([
            (
                "accepted".to_string(),
                BatchStatus::Accepted {
                    digests: vec!["aa".to_string()],
                },
            ),
            (
                "finalized".to_string(),
                BatchStatus::Finalized {
                    height: 4,
                    included: vec!["aa".to_string()],
                },
            ),
            (
                "partial".to_string(),
                BatchStatus::PartiallyFinalized {
                    height: 7,
                    included: vec!["bb".to_string()],
                    filtered: vec!["cc".to_string()],
                },
            ),
            (
                "dropped".to_string(),
                BatchStatus::Dropped {
                    filtered: vec!["dd".to_string()],
                },
            ),
        ]));
        let mock = Router::new().route(
            "/transactions/{batch_id}",
            get(move |Path(batch_id): Path<String>| {
                let statuses = statuses.clone();
                async move {
                    let Some(status) = statuses.get(&batch_id) else {
                        return (StatusCode::NOT_FOUND, String::new());
                    };
                    (
                        StatusCode::OK,
                        serde_json::to_string(status).expect("status serializes"),
                    )
                }
            }),
        );
        let url = spawn_mock_leader(mock).await;
        let leader = leader_with_url("00", url);
        let state = test_state(vec![leader.clone()], empty_account_reader());

        assert!(matches!(
            fetch_status_from_leader(&state.http, &leader, "finalized").await,
            Some(BatchStatus::Finalized { height: 4, .. })
        ));
        assert!(
            fetch_status_from_leader(&state.http, &leader, "missing")
                .await
                .is_none()
        );

        let mut included = HashSet::new();
        let mut height = 0;
        let attempts = vec![
            ("accepted".to_string(), leader.clone()),
            ("finalized".to_string(), leader.clone()),
            ("partial".to_string(), leader.clone()),
            ("dropped".to_string(), leader),
        ];

        merge_statuses(&state, &attempts, &mut included, &mut height).await;

        assert_eq!(
            included,
            HashSet::from(["aa".to_string(), "bb".to_string()])
        );
        assert_eq!(height, 7);
    }

    #[tokio::test]
    async fn wait_for_view_advance_ignores_same_view_until_newer_view_arrives() {
        let (sender, mut receiver) = tokio::sync::watch::channel(1);
        let mut current = 1;

        let waiter = tokio::spawn(async move {
            wait_for_view_advance(&mut receiver, &mut current).await;
            current
        });
        sender.send_replace(1);
        sender.send_replace(2);

        assert_eq!(waiter.await.expect("waiter task completes"), 2);
    }

    #[tokio::test]
    async fn submit_with_retries_handles_core_outcomes() {
        let first = signed_transaction(10, 0);
        let second = signed_transaction(11, 0);
        let first_digest = first.message_digest().to_string();
        let second_digest = second.message_digest().to_string();
        let one_tx_batch = decode_batch(
            &encoded_batch(std::slice::from_ref(&first)),
            DEFAULT_MAX_BATCH_BYTES,
        )
        .expect("single transaction batch decodes");
        let two_tx_batch = decode_batch(&encoded_batch(&[first, second]), DEFAULT_MAX_BATCH_BYTES)
            .expect("two transaction batch decodes");

        let empty_state = test_state(Vec::new(), empty_account_reader());
        let (status, body) = submit_with_retries(&empty_state, one_tx_batch).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.is_empty());

        let deterministic_url = spawn_mock_leader(Router::new().route(
            "/transactions/ingest",
            post(|| async { StatusCode::BAD_REQUEST }),
        ))
        .await;
        let deterministic_state = test_state(
            vec![leader_with_url("00", deterministic_url)],
            empty_account_reader(),
        );
        let (status, body) = submit_with_retries(&deterministic_state, two_tx_batch).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.is_empty());

        let finalized_tx = signed_transaction(12, 0);
        let finalized_digest = finalized_tx.message_digest().to_string();
        let finalized_batch = decode_batch(
            &encoded_batch(std::slice::from_ref(&finalized_tx)),
            DEFAULT_MAX_BATCH_BYTES,
        )
        .expect("finalized batch decodes");
        let finalized_url = spawn_accepting_status_leader(BatchStatus::Finalized {
            height: 5,
            included: vec![finalized_digest],
        })
        .await;
        let finalized_state = test_state(
            vec![leader_with_url("00", finalized_url)],
            empty_account_reader(),
        );

        let (status, body) = submit_with_retries(&finalized_state, finalized_batch).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<TxStatus>(&body).expect("status json"),
            TxStatus::Finalized { height: 5 },
        );

        let partial_first = signed_transaction(13, 0);
        let partial_second = signed_transaction(14, 0);
        let partial_first_digest = partial_first.message_digest().to_string();
        let partial_second_digest = partial_second.message_digest().to_string();
        let partial_batch = decode_batch(
            &encoded_batch(&[partial_first, partial_second]),
            DEFAULT_MAX_BATCH_BYTES,
        )
        .expect("partial batch decodes");
        let partial_url = spawn_accepting_status_leader(BatchStatus::PartiallyFinalized {
            height: 8,
            included: vec![partial_first_digest.clone()],
            filtered: vec![partial_second_digest.clone()],
        })
        .await;
        let partial_state = test_state(
            vec![leader_with_url("00", partial_url)],
            empty_account_reader(),
        );

        let (status, body) = submit_with_retries(&partial_state, partial_batch).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<TxStatus>(&body).expect("status json"),
            TxStatus::PartiallyFinalized {
                height: 8,
                included: vec![partial_first_digest],
                filtered: vec![partial_second_digest],
            },
        );

        let unavailable_tx = signed_transaction(15, 0);
        let unavailable_batch = decode_batch(
            &encoded_batch(std::slice::from_ref(&unavailable_tx)),
            DEFAULT_MAX_BATCH_BYTES,
        )
        .expect("unavailable batch decodes");
        let unavailable_url = spawn_mock_leader(Router::new().route(
            "/transactions/ingest",
            post(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        ))
        .await;
        let unavailable_state = test_state(
            vec![leader_with_url("00", unavailable_url)],
            empty_account_reader(),
        );

        let (status, body) = submit_with_retries(&unavailable_state, unavailable_batch).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.is_empty());

        assert_ne!(first_digest, second_digest);
    }

    #[tokio::test]
    async fn pinned_submission_rejects_bad_target_fanout_and_oversized_body() {
        let state = pinned_state("http://127.0.0.1:9".to_string());

        let mut unknown_target = HeaderMap::new();
        unknown_target.insert(TARGET_LEADER_HEADER, HeaderValue::from_static("ff"));
        unknown_target.insert(LEADER_FANOUT_HEADER, HeaderValue::from_static("1"));
        let (status, body) = submit_transactions(
            State(state.clone()),
            unknown_target,
            Bytes::from_static(b"body"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.is_empty());

        let mut bad_fanout = HeaderMap::new();
        bad_fanout.insert(TARGET_LEADER_HEADER, HeaderValue::from_static("00"));
        bad_fanout.insert(LEADER_FANOUT_HEADER, HeaderValue::from_static("2"));
        let (status, body) = submit_transactions(
            State(state.clone()),
            bad_fanout,
            Bytes::from_static(b"body"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.is_empty());

        let mut tiny_limit_state = state;
        tiny_limit_state.max_batch_bytes = 0;
        let (status, body) = submit_transactions(
            State(tiny_limit_state),
            pinned_headers(),
            Bytes::from(vec![0; max_request_bytes(0) + 1]),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(body.is_empty());
    }

    #[test]
    fn normalize_leaders_sorts_lowercases_and_trims_urls() {
        let leaders = normalize_leaders(vec![
            RelayerLeaderConfig {
                public_key: "0B".to_string(),
                url: "http://second/".to_string(),
            },
            RelayerLeaderConfig {
                public_key: "0a".to_string(),
                url: "http://first///".to_string(),
            },
        ]);

        assert_eq!(
            leaders
                .iter()
                .map(|leader| (leader.public_key.as_str(), leader.url.as_str()))
                .collect::<Vec<_>>(),
            vec![("0a", "http://first"), ("0b", "http://second")],
        );
    }

    #[test]
    fn targets_next_two_views() {
        let leaders = vec![leader("00"), leader("01"), leader("02"), leader("03")];

        let targets = next_two_leaders(&leaders, 0)
            .into_iter()
            .map(|leader| leader.public_key)
            .collect::<Vec<_>>();

        assert_eq!(targets, vec!["01", "02"]);
    }

    #[test]
    fn targets_deduplicate_single_leader_network() {
        let leaders = vec![leader("00")];

        let targets = next_two_leaders(&leaders, 12)
            .into_iter()
            .map(|leader| leader.public_key)
            .collect::<Vec<_>>();

        assert_eq!(targets, vec!["00"]);
    }

    #[test]
    fn retry_budget_returns_partial_status() {
        let digests = vec!["aa".to_string(), "bb".to_string()];
        let included = HashSet::from(["aa".to_string()]);

        let status = best_effort_status(&digests, &included, 7);

        assert_eq!(
            status,
            TxStatus::PartiallyFinalized {
                height: 7,
                included: vec!["aa".to_string()],
                filtered: vec!["bb".to_string()]
            }
        );
    }

    #[tokio::test]
    async fn pinned_target_proxies_blocking_submit_without_decoding() {
        let submit_count = Arc::new(AtomicUsize::new(0));
        let ingest_count = Arc::new(AtomicUsize::new(0));
        let submit_count_for_handler = submit_count.clone();
        let ingest_count_for_handler = ingest_count.clone();
        let mock = Router::new()
            .route(
                "/transactions",
                post(move |body: Bytes| {
                    let submit_count = submit_count_for_handler.clone();
                    async move {
                        submit_count.fetch_add(1, Ordering::Relaxed);
                        assert_eq!(body, Bytes::from_static(b"not a codec batch"));
                        json_response(TxStatus::Dropped)
                    }
                }),
            )
            .route(
                "/transactions/ingest",
                post(move || {
                    let ingest_count = ingest_count_for_handler.clone();
                    async move {
                        ingest_count.fetch_add(1, Ordering::Relaxed);
                        (StatusCode::ACCEPTED, String::new())
                    }
                }),
            );
        let state = pinned_state(spawn_mock_leader(mock).await);

        let (status, body) = submit_transactions(
            State(state),
            pinned_headers(),
            Bytes::from_static(b"not a codec batch"),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<TxStatus>(&body).expect("status json"),
            TxStatus::Dropped,
        );
        assert_eq!(submit_count.load(Ordering::Relaxed), 1);
        assert_eq!(ingest_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn pinned_target_retries_transient_blocking_submit() {
        let submit_count = Arc::new(AtomicUsize::new(0));
        let submit_count_for_handler = submit_count.clone();
        let mock = Router::new().route(
            "/transactions",
            post(move |body: Bytes| {
                let submit_count = submit_count_for_handler.clone();
                async move {
                    assert_eq!(body, Bytes::from_static(b"not a codec batch"));
                    let attempt = submit_count.fetch_add(1, Ordering::Relaxed);
                    if attempt == 0 {
                        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
                    }
                    json_response(TxStatus::Dropped)
                }
            }),
        );
        let state = pinned_state(spawn_mock_leader(mock).await);

        let (status, body) = submit_transactions(
            State(state),
            pinned_headers(),
            Bytes::from_static(b"not a codec batch"),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<TxStatus>(&body).expect("status json"),
            TxStatus::Dropped,
        );
        assert_eq!(submit_count.load(Ordering::Relaxed), 2);
    }
}
