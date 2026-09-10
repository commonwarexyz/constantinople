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
use commonware_codec::{Decode, DecodeExt, EncodeSize, FixedSize, RangeCfg};
use commonware_consensus::{Reporter, Viewable};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519, sha256};
use commonware_formatting::from_hex;
use commonware_parallel::Strategy;
use constantinople_engine::types::EngineActivity;
use constantinople_mempool::webserver::{AccountReader, TxStatus};
use constantinople_primitives::{Account, Nonce, SignedTransaction, TransactionPublicKey};
use futures::{StreamExt, stream::FuturesUnordered};
use serde::Serialize;
use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::sync::{Semaphore, oneshot, watch};
use tower_http::cors::{Any, CorsLayer};
use tracing::debug;

const MAX_BATCH_LENGTH_PREFIX_BYTES: usize = 5;
const MIN_BATCH_LENGTH_PREFIX_BYTES: usize = 1;
const TARGET_LEADER_HEADER: &str = "x-constantinople-relayer-target-leader";
const LEADER_FANOUT_HEADER: &str = "x-constantinople-relayer-leader-fanout";
const SINGLE_TRANSACTION_FANOUT: usize = 4;
const BATCH_FANOUT: usize = 2;
const LEADER_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const LEADER_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum batches admitted to CPU decoding concurrently.
///
/// Batch decoding seal-hashes every transaction on the strategy's pool, which
/// the co-located validator engine also depends on; admitting one batch at a
/// time keeps client bursts from queueing CPU ahead of consensus work. The
/// owned permit moves into the pool job, so a client disconnect cannot
/// release it while the job runs.
const MAX_CONCURRENT_DECODES: usize = 1;

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
pub struct ServerConfig<St: Strategy> {
    pub listen: SocketAddr,
    pub relayer: RelayerConfig,
    pub account_reader: Arc<OnceLock<Arc<dyn AccountReader>>>,
    pub view_clock: ViewClock,
    pub strategy: St,
    /// Must match the validators' mempool `max_propose_bytes` so a batch
    /// the relayer accepts is never rejected by a leader for size.
    pub max_batch_bytes: usize,
}

#[derive(Clone)]
struct AppState<St: Strategy> {
    leaders: Arc<Vec<Leader>>,
    max_batch_bytes: usize,
    account_reader: Arc<OnceLock<Arc<dyn AccountReader>>>,
    view_clock: ViewClock,
    blocking_http: reqwest::Client,
    client_response_timeout: Duration,
    leader_response_timeout: Duration,
    strategy: St,
    decode_permits: Arc<Semaphore>,
}

#[derive(Debug, Clone)]
struct Leader {
    public_key: String,
    sort_key: Vec<u8>,
    url: String,
}

#[derive(Debug)]
enum LeaderResponse {
    Terminal(TxStatus),
    Deterministic(StatusCode),
    Ambiguous,
}

type RelayResponse = (StatusCode, String);

pub async fn serve<St: Strategy>(config: ServerConfig<St>) {
    let state = AppState {
        leaders: Arc::new(normalize_leaders(config.relayer.leaders)),
        max_batch_bytes: config.max_batch_bytes,
        account_reader: config.account_reader,
        view_clock: config.view_clock,
        blocking_http: reqwest::Client::builder()
            .connect_timeout(LEADER_REQUEST_TIMEOUT)
            .build()
            .expect("relayer blocking HTTP client configuration is valid"),
        client_response_timeout: CLIENT_RESPONSE_TIMEOUT,
        leader_response_timeout: LEADER_RESPONSE_TIMEOUT,
        strategy: config.strategy,
        decode_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_DECODES)),
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

fn router<St: Strategy>(state: AppState<St>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE]);

    Router::new()
        .route("/transactions", post(submit_transactions::<St>))
        .route("/account/{public_key}", get(account::<St>))
        .route("/health", get(health))
        .route("/ready", get(ready::<St>))
        .layer(DefaultBodyLimit::max(max_request_bytes(
            state.max_batch_bytes,
        )))
        .layer(cors)
        .with_state(state)
}

async fn submit_transactions<St: Strategy>(
    State(state): State<AppState<St>>,
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

    // Decoding seal-hashes every transaction, so it runs on the strategy's
    // pool with the owned permit riding in the job to bound concurrent
    // decode CPU. Decoding stays single-threaded because the wire format has
    // no per-transaction framing to split on.
    let Ok(permit) = state.decode_permits.clone().acquire_owned().await else {
        return (StatusCode::INTERNAL_SERVER_ERROR, String::new());
    };
    let max_batch_bytes = state.max_batch_bytes;
    let decoded = state
        .strategy
        .spawn(move |_: St| {
            let _permit = permit;
            decode_batch(&body, max_batch_bytes).map(|transactions| (body, transactions))
        })
        .await;
    let (body, transactions) = match decoded {
        Ok(decoded) => decoded,
        Err(status) => return (status, String::new()),
    };

    let fanout = if transactions == 1 {
        SINGLE_TRANSACTION_FANOUT
    } else {
        BATCH_FANOUT
    };
    submit_to_public_leaders(&state, body, fanout).await
}

async fn submit_to_pinned_leader<St: Strategy>(
    state: &AppState<St>,
    body: Bytes,
    target: &str,
) -> (StatusCode, String) {
    let Some(leader) = leader_by_id(&state.leaders, target).cloned() else {
        return (StatusCode::BAD_REQUEST, String::new());
    };
    submit_to_blocking_leader(&state.blocking_http, &leader, body).await
}

async fn submit_to_public_leaders<St: Strategy>(
    state: &AppState<St>,
    body: Bytes,
    fanout: usize,
) -> RelayResponse {
    if state.leaders.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
    }

    let views = state.view_clock.current_view.subscribe();
    let view = *views.borrow();
    let targets = next_leaders(&state.leaders, view, fanout);
    let http = state.blocking_http.clone();
    let leader_response_timeout = state.leader_response_timeout;
    let (response_tx, response_rx) = oneshot::channel();

    tokio::spawn(async move {
        forward_to_targets(http, targets, body, leader_response_timeout, response_tx).await;
    });

    match tokio::time::timeout(state.client_response_timeout, response_rx).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) | Err(_) => (StatusCode::ACCEPTED, String::new()),
    }
}

async fn forward_to_targets(
    http: reqwest::Client,
    targets: Vec<Leader>,
    body: Bytes,
    leader_response_timeout: Duration,
    response_tx: oneshot::Sender<RelayResponse>,
) {
    let target_count = targets.len();
    let mut sends = targets
        .into_iter()
        .map(|leader| {
            let http = http.clone();
            let body = body.clone();
            async move {
                tokio::time::timeout(
                    leader_response_timeout,
                    forward_to_leader(&http, &leader, body),
                )
                .await
                .unwrap_or(LeaderResponse::Ambiguous)
            }
        })
        .collect::<FuturesUnordered<_>>();
    let mut response_tx = Some(response_tx);
    let mut partial = None;
    let mut deterministic = None;
    let mut dropped = 0;

    while let Some(result) = sends.next().await {
        match result {
            LeaderResponse::Terminal(status @ TxStatus::Finalized { .. }) => {
                send_once(&mut response_tx, status_response(status));
            }
            LeaderResponse::Terminal(status @ TxStatus::PartiallyFinalized { .. }) => {
                partial = Some(preferred_partial(partial, status));
            }
            LeaderResponse::Terminal(TxStatus::Dropped) => dropped += 1,
            LeaderResponse::Deterministic(status) => {
                deterministic = Some(status);
                send_once(&mut response_tx, (status, String::new()));
            }
            LeaderResponse::Ambiguous => {}
        }
    }

    let response = partial.map_or_else(
        || {
            deterministic.map_or_else(
                || {
                    if dropped == target_count {
                        status_response(TxStatus::Dropped)
                    } else {
                        (StatusCode::ACCEPTED, String::new())
                    }
                },
                |status| (status, String::new()),
            )
        },
        status_response,
    );
    send_once(&mut response_tx, response);
}

fn send_once(sender: &mut Option<oneshot::Sender<RelayResponse>>, response: RelayResponse) {
    if let Some(sender) = sender.take() {
        let _ = sender.send(response);
    }
}

fn status_response(status: TxStatus) -> RelayResponse {
    serde_json::to_string(&status).map_or_else(
        |_| (StatusCode::INTERNAL_SERVER_ERROR, String::new()),
        |body| (StatusCode::OK, body),
    )
}

fn preferred_partial(current: Option<TxStatus>, candidate: TxStatus) -> TxStatus {
    let Some(current) = current else {
        return candidate;
    };
    let TxStatus::PartiallyFinalized {
        height: current_height,
        included: current_included,
        filtered: current_filtered,
    } = current
    else {
        unreachable!("partial aggregation stores only partial results")
    };
    let TxStatus::PartiallyFinalized {
        height: candidate_height,
        included: candidate_included,
        filtered: candidate_filtered,
    } = candidate
    else {
        unreachable!("partial aggregation receives only partial results")
    };

    if (
        candidate_included,
        std::cmp::Reverse(candidate_filtered),
        candidate_height,
    ) > (
        current_included,
        std::cmp::Reverse(current_filtered),
        current_height,
    ) {
        candidate
    } else {
        current
    }
}

async fn account<St: Strategy>(
    State(state): State<AppState<St>>,
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

async fn ready<St: Strategy>(State(state): State<AppState<St>>) -> StatusCode {
    if state.leaders.is_empty() {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    StatusCode::OK
}

async fn forward_to_leader(http: &reqwest::Client, leader: &Leader, body: Bytes) -> LeaderResponse {
    let response = match http
        .post(format!("{}/transactions", leader.url))
        .header("content-type", "application/octet-stream")
        .body(body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => {
            debug!(leader = %leader.public_key, "relayer forward transient failure");
            return LeaderResponse::Ambiguous;
        }
    };
    if response.status() == StatusCode::BAD_REQUEST
        || response.status() == StatusCode::PAYLOAD_TOO_LARGE
    {
        return LeaderResponse::Deterministic(response.status());
    }
    if response.status() != StatusCode::OK {
        debug!(leader = %leader.public_key, status = %response.status(), "relayer forward ambiguous response");
        return LeaderResponse::Ambiguous;
    }

    response.json::<TxStatus>().await.map_or_else(
        |_| {
            debug!(leader = %leader.public_key, "relayer forward invalid terminal response");
            LeaderResponse::Ambiguous
        },
        LeaderResponse::Terminal,
    )
}

async fn submit_to_blocking_leader(
    http: &reqwest::Client,
    leader: &Leader,
    body: Bytes,
) -> (StatusCode, String) {
    let response = match http
        .post(format!("{}/transactions/background", leader.url))
        .header("content-type", "application/octet-stream")
        .body(body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, String::new()),
    };
    let status = response.status();
    response.text().await.map_or_else(
        |_| (StatusCode::SERVICE_UNAVAILABLE, String::new()),
        |body| (status, body),
    )
}

fn decode_batch(body: &Bytes, max_batch_bytes: usize) -> Result<usize, StatusCode> {
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

    Ok(transactions.len())
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
    for pair in leaders.windows(2) {
        assert_ne!(
            pair[0].public_key, pair[1].public_key,
            "leader public_key must be unique: {}",
            pair[0].public_key
        );
    }
    leaders
}

fn next_leaders(leaders: &[Leader], observed_view: u64, fanout: usize) -> Vec<Leader> {
    if leaders.is_empty() {
        return Vec::new();
    }
    let observed = (observed_view % leaders.len() as u64) as usize;
    (0..fanout.min(leaders.len()))
        .map(|offset| leaders[(observed + 1 + offset) % leaders.len()].clone())
        .collect()
}

fn leader_by_id<'a>(leaders: &'a [Leader], public_key: &str) -> Option<&'a Leader> {
    leaders
        .iter()
        .find(|leader| leader.public_key == public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use commonware_codec::Encode as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    const DEFAULT_MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;

    fn leader(key: &str) -> Leader {
        Leader {
            public_key: key.to_string(),
            sort_key: from_hex(key).expect("hex key"),
            url: format!("http://{key}"),
        }
    }

    fn signed_transfer(seed: u64, nonce: u64) -> SignedTransaction<sha256::Sha256> {
        use commonware_cryptography::Signer as _;
        use constantinople_primitives::Transaction;

        let sender = ed25519::PrivateKey::from_seed(seed);
        let recipient = ed25519::PrivateKey::from_seed(seed + 1).public_key();
        Transaction::new(
            TransactionPublicKey::ed25519(sender.public_key()),
            TransactionPublicKey::ed25519(recipient),
            core::num::NonZeroU64::new(1).expect("non-zero"),
            nonce,
        )
        .seal_and_sign(&sender, b"relayer-test", &mut sha256::Sha256::default())
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

    fn mock_leader(key: &str, url: String) -> Leader {
        Leader {
            public_key: key.to_string(),
            sort_key: from_hex(key).expect("hex key"),
            url,
        }
    }

    fn test_state(
        leaders: Vec<Leader>,
        client_response_timeout: Duration,
        leader_response_timeout: Duration,
    ) -> AppState<commonware_parallel::Sequential> {
        let (_, view_clock) = Observer::new();
        AppState {
            leaders: Arc::new(leaders),
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            account_reader: Arc::new(OnceLock::new()),
            view_clock,
            blocking_http: reqwest::Client::builder()
                .build()
                .expect("test blocking HTTP client configuration is valid"),
            client_response_timeout,
            leader_response_timeout,
            strategy: commonware_parallel::Sequential,
            decode_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_DECODES)),
        }
    }

    fn pinned_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(TARGET_LEADER_HEADER, HeaderValue::from_static("00"));
        headers.insert(LEADER_FANOUT_HEADER, HeaderValue::from_static("1"));
        headers
    }

    fn terminal_router(
        status: TxStatus,
        delay: Duration,
        completion: Option<Arc<Notify>>,
    ) -> Router {
        Router::new().route(
            "/transactions",
            post(move || {
                let completion = completion.clone();
                async move {
                    tokio::time::sleep(delay).await;
                    if let Some(completion) = completion {
                        completion.notify_one();
                    }
                    status_response(status)
                }
            }),
        )
    }

    async fn counted_leaders(count: usize) -> (Vec<Leader>, Vec<Arc<AtomicUsize>>) {
        let mut leaders = Vec::with_capacity(count);
        let mut requests = Vec::with_capacity(count);
        for index in 0..count {
            let request_count = Arc::new(AtomicUsize::new(0));
            let request_count_for_handler = request_count.clone();
            let router = Router::new().route(
                "/transactions",
                post(move || {
                    let request_count = request_count_for_handler.clone();
                    async move {
                        request_count.fetch_add(1, Ordering::Relaxed);
                        status_response(TxStatus::Dropped)
                    }
                }),
            );
            let key = format!("{index:02x}");
            leaders.push(mock_leader(&key, spawn_mock_leader(router).await));
            requests.push(request_count);
        }
        (leaders, requests)
    }

    #[test]
    fn decode_batch_reports_transaction_count() {
        let body = vec![signed_transfer(1, 0), signed_transfer(2, 0)].encode();

        assert_eq!(decode_batch(&body, DEFAULT_MAX_BATCH_BYTES), Ok(2));
    }

    #[test]
    fn decode_batch_rejects_malformed_bytes() {
        assert_eq!(
            decode_batch(&Bytes::from_static(b"not a batch"), DEFAULT_MAX_BATCH_BYTES),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn targets_next_two_views() {
        let leaders = vec![leader("00"), leader("01"), leader("02"), leader("03")];

        let targets = next_leaders(&leaders, 0, 2)
            .into_iter()
            .map(|leader| leader.public_key)
            .collect::<Vec<_>>();

        assert_eq!(targets, vec!["01", "02"]);
    }

    #[test]
    fn targets_cap_fanout_at_network_size() {
        let leaders = vec![leader("00"), leader("01"), leader("02")];

        let targets = next_leaders(&leaders, 1, 4)
            .into_iter()
            .map(|leader| leader.public_key)
            .collect::<Vec<_>>();

        assert_eq!(targets, vec!["02", "00", "01"]);
    }

    #[test]
    #[should_panic(expected = "leader public_key must be unique")]
    fn duplicate_leader_ids_are_rejected() {
        normalize_leaders(vec![
            RelayerLeaderConfig {
                public_key: "00".to_string(),
                url: "http://first".to_string(),
            },
            RelayerLeaderConfig {
                public_key: "00".to_string(),
                url: "http://second".to_string(),
            },
        ]);
    }

    #[tokio::test]
    async fn pinned_target_uses_background_once_and_proxies_terminal_response() {
        let foreground_count = Arc::new(AtomicUsize::new(0));
        let background_count = Arc::new(AtomicUsize::new(0));
        let foreground_count_for_handler = foreground_count.clone();
        let background_count_for_handler = background_count.clone();
        let mock = Router::new()
            .route(
                "/transactions",
                post(move || {
                    let foreground_count = foreground_count_for_handler.clone();
                    async move {
                        foreground_count.fetch_add(1, Ordering::Relaxed);
                        status_response(TxStatus::Dropped)
                    }
                }),
            )
            .route(
                "/transactions/background",
                post(move |body: Bytes| {
                    let background_count = background_count_for_handler.clone();
                    async move {
                        background_count.fetch_add(1, Ordering::Relaxed);
                        assert_eq!(body, Bytes::from_static(b"not a codec batch"));
                        tokio::time::sleep(Duration::from_millis(30)).await;
                        (StatusCode::OK, r#"{"status":"finalized","height":7}"#)
                    }
                }),
            );
        let url = spawn_mock_leader(mock).await;
        let state = test_state(
            vec![mock_leader("00", url)],
            Duration::from_millis(5),
            Duration::from_millis(10),
        );

        let response = submit_transactions(
            State(state),
            pinned_headers(),
            Bytes::from_static(b"not a codec batch"),
        )
        .await;

        assert_eq!(
            response,
            (
                StatusCode::OK,
                r#"{"status":"finalized","height":7}"#.to_string()
            )
        );
        assert_eq!(background_count.load(Ordering::Relaxed), 1);
        assert_eq!(foreground_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn unpinned_returns_fast_finalized_response() {
        let slow = terminal_router(TxStatus::Dropped, Duration::from_millis(200), None);
        let finalized = terminal_router(TxStatus::Finalized { height: 9 }, Duration::ZERO, None);
        let slow = mock_leader("00", spawn_mock_leader(slow).await);
        let finalized = mock_leader("01", spawn_mock_leader(finalized).await);
        let state = test_state(
            vec![slow, finalized],
            Duration::from_millis(300),
            Duration::from_millis(400),
        );
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let response = tokio::time::timeout(
            Duration::from_millis(100),
            submit_transactions(State(state), HeaderMap::new(), body),
        )
        .await
        .expect("finalized response should not wait for other leaders");

        assert_eq!(response, status_response(TxStatus::Finalized { height: 9 }));
    }

    #[tokio::test]
    async fn unpinned_returns_dropped_only_after_all_leaders_drop() {
        let first = terminal_router(TxStatus::Dropped, Duration::ZERO, None);
        let second = terminal_router(TxStatus::Dropped, Duration::from_millis(20), None);
        let first = mock_leader("00", spawn_mock_leader(first).await);
        let second = mock_leader("01", spawn_mock_leader(second).await);
        let state = test_state(
            vec![first, second],
            Duration::from_millis(100),
            Duration::from_millis(200),
        );
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let response = submit_transactions(State(state), HeaderMap::new(), body).await;

        assert_eq!(response, status_response(TxStatus::Dropped));
    }

    #[tokio::test]
    async fn unpinned_dropped_waits_for_delayed_finalized() {
        let dropped = terminal_router(TxStatus::Dropped, Duration::ZERO, None);
        let finalized = terminal_router(
            TxStatus::Finalized { height: 11 },
            Duration::from_millis(30),
            None,
        );
        let dropped = mock_leader("00", spawn_mock_leader(dropped).await);
        let finalized = mock_leader("01", spawn_mock_leader(finalized).await);
        let state = test_state(
            vec![dropped, finalized],
            Duration::from_millis(100),
            Duration::from_millis(200),
        );
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let response = submit_transactions(State(state), HeaderMap::new(), body).await;

        assert_eq!(
            response,
            status_response(TxStatus::Finalized { height: 11 })
        );
    }

    #[tokio::test]
    async fn unpinned_timeout_returns_accepted_while_owned_request_completes() {
        let completion = Arc::new(Notify::new());
        let delayed = terminal_router(
            TxStatus::Dropped,
            Duration::from_millis(50),
            Some(completion.clone()),
        );
        let delayed = mock_leader("00", spawn_mock_leader(delayed).await);
        let state = test_state(
            vec![delayed],
            Duration::from_millis(5),
            Duration::from_millis(100),
        );
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let response = submit_transactions(State(state), HeaderMap::new(), body).await;

        assert_eq!(response, (StatusCode::ACCEPTED, String::new()));
        tokio::time::timeout(Duration::from_millis(200), completion.notified())
            .await
            .expect("owned request should complete after client timeout");
    }

    #[tokio::test]
    async fn unpinned_partial_waits_for_all_leaders() {
        let completion = Arc::new(Notify::new());
        let partial = terminal_router(
            TxStatus::PartiallyFinalized {
                height: 12,
                included: 1,
                filtered: 1,
            },
            Duration::ZERO,
            None,
        );
        let dropped = terminal_router(
            TxStatus::Dropped,
            Duration::from_millis(30),
            Some(completion.clone()),
        );
        let partial = mock_leader("00", spawn_mock_leader(partial).await);
        let dropped = mock_leader("01", spawn_mock_leader(dropped).await);
        let state = test_state(
            vec![partial, dropped],
            Duration::from_millis(100),
            Duration::from_millis(200),
        );
        let body: Bytes = vec![signed_transfer(1, 0), signed_transfer(2, 0)].encode();

        let response = submit_transactions(State(state), HeaderMap::new(), body).await;

        assert_eq!(
            response,
            status_response(TxStatus::PartiallyFinalized {
                height: 12,
                included: 1,
                filtered: 1,
            })
        );
        tokio::time::timeout(Duration::from_millis(10), completion.notified())
            .await
            .expect("partial result should wait for every leader");
    }

    #[tokio::test]
    async fn unpinned_single_transaction_fans_out_to_four_leaders() {
        let (leaders, requests) = counted_leaders(5).await;
        let state = test_state(
            leaders,
            Duration::from_millis(100),
            Duration::from_millis(200),
        );
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let response = submit_transactions(State(state), HeaderMap::new(), body).await;
        let requests = requests
            .iter()
            .map(|count| count.load(Ordering::Relaxed))
            .collect::<Vec<_>>();

        assert_eq!(response, status_response(TxStatus::Dropped));
        assert_eq!(requests, vec![0, 1, 1, 1, 1]);
    }

    #[tokio::test]
    async fn unpinned_multi_transaction_batch_fans_out_to_two_leaders() {
        let (leaders, requests) = counted_leaders(5).await;
        let state = test_state(
            leaders,
            Duration::from_millis(100),
            Duration::from_millis(200),
        );
        let body: Bytes = vec![signed_transfer(1, 0), signed_transfer(2, 0)].encode();

        let response = submit_transactions(State(state), HeaderMap::new(), body).await;
        let requests = requests
            .iter()
            .map(|count| count.load(Ordering::Relaxed))
            .collect::<Vec<_>>();

        assert_eq!(response, status_response(TxStatus::Dropped));
        assert_eq!(requests, vec![0, 1, 1, 0, 0]);
    }

    #[tokio::test]
    async fn unpinned_preserves_deterministic_validator_rejection() {
        let rejected = Router::new().route(
            "/transactions",
            post(|| async { (StatusCode::BAD_REQUEST, String::new()) }),
        );
        let unresponsive = Router::new().route(
            "/transactions",
            post(|| async { std::future::pending::<(StatusCode, String)>().await }),
        );
        let rejected = mock_leader("00", spawn_mock_leader(rejected).await);
        let unresponsive = mock_leader("01", spawn_mock_leader(unresponsive).await);
        let state = test_state(
            vec![rejected, unresponsive],
            Duration::from_millis(50),
            Duration::from_millis(100),
        );
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let response = submit_transactions(State(state), HeaderMap::new(), body).await;

        assert_eq!(response, (StatusCode::BAD_REQUEST, String::new()));
    }

    #[tokio::test]
    async fn unpinned_bounds_owned_leader_waits() {
        let unresponsive = Router::new().route(
            "/transactions",
            post(|| async { std::future::pending::<(StatusCode, String)>().await }),
        );
        let unresponsive = mock_leader("00", spawn_mock_leader(unresponsive).await);
        let state = test_state(
            vec![unresponsive],
            Duration::from_millis(100),
            Duration::from_millis(15),
        );
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let response = tokio::time::timeout(
            Duration::from_millis(50),
            submit_transactions(State(state), HeaderMap::new(), body),
        )
        .await
        .expect("owned leader wait should remain bounded");

        assert_eq!(response, (StatusCode::ACCEPTED, String::new()));
    }
}
