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
use constantinople_mempool::webserver::AccountReader;
use constantinople_primitives::{Account, Nonce, SignedTransaction, TransactionPublicKey};
use futures::{StreamExt, stream::FuturesUnordered};
use serde::Serialize;
use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::sync::{Semaphore, watch};
use tower_http::cors::{Any, CorsLayer};
use tracing::debug;

const MAX_BATCH_LENGTH_PREFIX_BYTES: usize = 5;
const MIN_BATCH_LENGTH_PREFIX_BYTES: usize = 1;
const TARGET_LEADER_HEADER: &str = "x-constantinople-relayer-target-leader";
const LEADER_FANOUT_HEADER: &str = "x-constantinople-relayer-leader-fanout";
const PINNED_SUBMIT_RETRIES: usize = 3;
const LEADER_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const VIEW_ADVANCE_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

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
    max_retry_views: u64,
    max_batch_bytes: usize,
    account_reader: Arc<OnceLock<Arc<dyn AccountReader>>>,
    view_clock: ViewClock,
    http: reqwest::Client,
    view_advance_wait_timeout: Duration,
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
enum ForwardResult {
    Accepted,
    Deterministic(StatusCode),
    Transient,
}

pub async fn serve<St: Strategy>(config: ServerConfig<St>) {
    let state = AppState {
        leaders: Arc::new(normalize_leaders(config.relayer.leaders)),
        max_retry_views: config.relayer.max_retry_views,
        max_batch_bytes: config.max_batch_bytes,
        account_reader: config.account_reader,
        view_clock: config.view_clock,
        http: reqwest::Client::builder()
            .timeout(LEADER_REQUEST_TIMEOUT)
            .build()
            .expect("relayer HTTP client configuration is valid"),
        view_advance_wait_timeout: VIEW_ADVANCE_WAIT_TIMEOUT,
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
) -> StatusCode {
    if let Some(target) = requested_target_leader(&headers) {
        if body.len() > max_request_bytes(state.max_batch_bytes) {
            return StatusCode::PAYLOAD_TOO_LARGE;
        }
        if requested_leader_fanout(&headers).is_some_and(|fanout| fanout != 1) {
            return StatusCode::BAD_REQUEST;
        }
        return submit_to_pinned_leader(&state, body, &target).await;
    }

    // Decoding seal-hashes every transaction, so it runs on the strategy's
    // pool with the owned permit riding in the job to bound concurrent
    // decode CPU. Single-threaded: the wire format has no per-transaction
    // framing to split on.
    let Ok(permit) = state.decode_permits.clone().acquire_owned().await else {
        return StatusCode::INTERNAL_SERVER_ERROR;
    };
    let max_batch_bytes = state.max_batch_bytes;
    let decoded = state
        .strategy
        .spawn(move |_: St| {
            let _permit = permit;
            decode_batch(&body, max_batch_bytes).map(|()| body)
        })
        .await;
    let body = match decoded {
        Ok(body) => body,
        Err(status) => return status,
    };

    submit_with_retries(&state, body).await
}

async fn submit_to_pinned_leader<St: Strategy>(
    state: &AppState<St>,
    body: Bytes,
    target: &str,
) -> StatusCode {
    let Some(leader) = leader_by_id(&state.leaders, target).cloned() else {
        return StatusCode::BAD_REQUEST;
    };
    submit_to_leader_with_retries(&state.http, &leader, body).await
}

async fn submit_with_retries<St: Strategy>(state: &AppState<St>, body: Bytes) -> StatusCode {
    if state.leaders.is_empty() {
        return StatusCode::SERVICE_UNAVAILABLE;
    }

    let mut views = state.view_clock.current_view.subscribe();
    let mut view = *views.borrow();

    for retry in 0..=state.max_retry_views {
        let targets = next_two_leaders(&state.leaders, view);
        match forward_to_targets(&state.http, &targets, body.clone()).await {
            ForwardResult::Accepted => return StatusCode::ACCEPTED,
            ForwardResult::Deterministic(status) => return status,
            ForwardResult::Transient => {}
        }

        if retry == state.max_retry_views {
            return StatusCode::SERVICE_UNAVAILABLE;
        }

        wait_for_view_advance(&mut views, &mut view, state.view_advance_wait_timeout).await;
    }

    StatusCode::SERVICE_UNAVAILABLE
}

async fn forward_to_targets(
    http: &reqwest::Client,
    targets: &[Leader],
    body: Bytes,
) -> ForwardResult {
    let mut sends = targets
        .iter()
        .map(|leader| forward_to_leader(http, leader, body.clone()))
        .collect::<FuturesUnordered<_>>();
    let mut deterministic = None;

    while let Some(result) = sends.next().await {
        match result {
            ForwardResult::Accepted => return ForwardResult::Accepted,
            ForwardResult::Deterministic(status) => {
                deterministic = Some(status);
            }
            ForwardResult::Transient => {}
        }
    }

    deterministic.map_or(ForwardResult::Transient, ForwardResult::Deterministic)
}

async fn wait_for_view_advance(
    views: &mut watch::Receiver<u64>,
    current: &mut u64,
    max_wait: Duration,
) {
    let observed = tokio::time::timeout(max_wait, async {
        loop {
            if views.changed().await.is_err() {
                return None;
            }
            let next = *views.borrow();
            if next > *current {
                return Some(next);
            }
        }
    })
    .await;

    match observed {
        Ok(Some(observed)) => *current = observed,
        Ok(None) | Err(_) => *current = (*current).saturating_add(1),
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

async fn forward_to_leader(http: &reqwest::Client, leader: &Leader, body: Bytes) -> ForwardResult {
    match http
        .post(format!("{}/transactions/ingest", leader.url))
        .header("content-type", "application/octet-stream")
        .body(body)
        .send()
        .await
    {
        Ok(response) if response.status() == StatusCode::ACCEPTED => {
            debug!(leader = %leader.public_key, "relayer forward accepted");
            ForwardResult::Accepted
        }
        Ok(response)
            if response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::PAYLOAD_TOO_LARGE =>
        {
            ForwardResult::Deterministic(response.status())
        }
        Ok(_) | Err(_) => {
            debug!(leader = %leader.public_key, "relayer forward transient failure");
            ForwardResult::Transient
        }
    }
}

async fn submit_to_leader_with_retries(
    http: &reqwest::Client,
    leader: &Leader,
    body: Bytes,
) -> StatusCode {
    let mut backoff = std::time::Duration::from_millis(50);
    for attempt in 0..PINNED_SUBMIT_RETRIES {
        match forward_to_leader(http, leader, body.clone()).await {
            ForwardResult::Accepted => return StatusCode::ACCEPTED,
            ForwardResult::Deterministic(status) => return status,
            ForwardResult::Transient if attempt + 1 < PINNED_SUBMIT_RETRIES => {
                tokio::time::sleep(backoff).await;
                backoff *= 2;
            }
            ForwardResult::Transient => {
                return StatusCode::SERVICE_UNAVAILABLE;
            }
        }
    }

    StatusCode::SERVICE_UNAVAILABLE
}

fn decode_batch(body: &Bytes, max_batch_bytes: usize) -> Result<(), StatusCode> {
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

    Ok(())
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
    use axum::http::HeaderValue;
    use commonware_codec::Encode as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    #[test]
    fn decode_batch_accepts_valid_transactions() {
        let body = vec![signed_transfer(1, 0), signed_transfer(2, 0)].encode();

        assert_eq!(decode_batch(&body, DEFAULT_MAX_BATCH_BYTES), Ok(()));
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

    fn pinned_state(leader_url: String) -> AppState<commonware_parallel::Sequential> {
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
            http: reqwest::Client::builder()
                .timeout(Duration::from_millis(100))
                .build()
                .expect("test HTTP client configuration is valid"),
            view_advance_wait_timeout: Duration::from_millis(20),
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
    fn decode_batch_rejects_malformed_bytes() {
        assert_eq!(
            decode_batch(&Bytes::from_static(b"not a batch"), DEFAULT_MAX_BATCH_BYTES),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[tokio::test]
    async fn pinned_target_forwards_to_ingest_without_decoding() {
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
                        StatusCode::INTERNAL_SERVER_ERROR
                    }
                }),
            )
            .route(
                "/transactions/ingest",
                post(move |body: Bytes| {
                    let ingest_count = ingest_count_for_handler.clone();
                    async move {
                        ingest_count.fetch_add(1, Ordering::Relaxed);
                        assert_eq!(body, Bytes::from_static(b"not a codec batch"));
                        StatusCode::ACCEPTED
                    }
                }),
            );
        let state = pinned_state(spawn_mock_leader(mock).await);

        let status = submit_transactions(
            State(state),
            pinned_headers(),
            Bytes::from_static(b"not a codec batch"),
        )
        .await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(submit_count.load(Ordering::Relaxed), 0);
        assert_eq!(ingest_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn pinned_target_retries_transient_ingest() {
        let submit_count = Arc::new(AtomicUsize::new(0));
        let submit_count_for_handler = submit_count.clone();
        let mock = Router::new().route(
            "/transactions/ingest",
            post(move |body: Bytes| {
                let submit_count = submit_count_for_handler.clone();
                async move {
                    assert_eq!(body, Bytes::from_static(b"not a codec batch"));
                    let attempt = submit_count.fetch_add(1, Ordering::Relaxed);
                    if attempt == 0 {
                        return StatusCode::SERVICE_UNAVAILABLE;
                    }
                    StatusCode::ACCEPTED
                }
            }),
        );
        let state = pinned_state(spawn_mock_leader(mock).await);

        let status = submit_transactions(
            State(state),
            pinned_headers(),
            Bytes::from_static(b"not a codec batch"),
        )
        .await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(submit_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn pinned_target_does_not_retry_deterministic_rejection() {
        let submit_count = Arc::new(AtomicUsize::new(0));
        let submit_count_for_handler = submit_count.clone();
        let mock = Router::new().route(
            "/transactions/ingest",
            post(move || {
                let submit_count = submit_count_for_handler.clone();
                async move {
                    submit_count.fetch_add(1, Ordering::Relaxed);
                    StatusCode::BAD_REQUEST
                }
            }),
        );
        let state = pinned_state(spawn_mock_leader(mock).await);

        let status = submit_transactions(
            State(state),
            pinned_headers(),
            Bytes::from_static(b"not a codec batch"),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(submit_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn pinned_target_bounds_transient_retries() {
        let submit_count = Arc::new(AtomicUsize::new(0));
        let submit_count_for_handler = submit_count.clone();
        let mock = Router::new().route(
            "/transactions/ingest",
            post(move || {
                let submit_count = submit_count_for_handler.clone();
                async move {
                    submit_count.fetch_add(1, Ordering::Relaxed);
                    StatusCode::SERVICE_UNAVAILABLE
                }
            }),
        );
        let state = pinned_state(spawn_mock_leader(mock).await);

        let status = submit_transactions(
            State(state),
            pinned_headers(),
            Bytes::from_static(b"not a codec batch"),
        )
        .await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(submit_count.load(Ordering::Relaxed), PINNED_SUBMIT_RETRIES);
    }

    /// Pops the next scripted response, repeating the last one once the
    /// script is down to a single entry; `None` for an empty script.
    fn take_scripted<T: Clone>(script: &std::sync::Mutex<Vec<T>>) -> Option<T> {
        let mut script = script.lock().expect("script lock");
        match script.len() {
            0 => None,
            1 => Some(script[0].clone()),
            _ => Some(script.remove(0)),
        }
    }

    /// A mock leader whose ingest endpoint records bodies and repeats its last
    /// scripted status once the script reaches one entry.
    fn scripted_leader(ingest: Vec<StatusCode>) -> (Router, Arc<std::sync::Mutex<Vec<Bytes>>>) {
        let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ingest = Arc::new(std::sync::Mutex::new(ingest));
        let bodies_for_handler = bodies.clone();
        let router = Router::new().route(
            "/transactions/ingest",
            post(move |body: Bytes| {
                let bodies = bodies_for_handler.clone();
                let ingest = ingest.clone();
                async move {
                    bodies.lock().expect("bodies lock").push(body);
                    take_scripted(&ingest).unwrap_or(StatusCode::ACCEPTED)
                }
            }),
        );
        (router, bodies)
    }

    fn retry_state(
        leaders: Vec<Leader>,
        max_retry_views: u64,
    ) -> AppState<commonware_parallel::Sequential> {
        let (_, view_clock) = Observer::new();
        AppState {
            leaders: Arc::new(leaders),
            max_retry_views,
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            account_reader: Arc::new(OnceLock::new()),
            view_clock,
            http: reqwest::Client::builder()
                .timeout(Duration::from_millis(100))
                .build()
                .expect("test HTTP client configuration is valid"),
            view_advance_wait_timeout: Duration::from_millis(20),
            strategy: commonware_parallel::Sequential,
            decode_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_DECODES)),
        }
    }

    fn mock_leader(key: &str, url: String) -> Leader {
        Leader {
            public_key: key.to_string(),
            sort_key: from_hex(key).expect("hex key"),
            url,
        }
    }

    /// Advances the relayer's observed view every few milliseconds so
    /// `wait_for_view_advance` never stalls a retry round.
    fn advance_views(sender: watch::Sender<u64>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut view = 0u64;
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                view += 1;
                sender.send_replace(view);
            }
        })
    }

    #[tokio::test]
    async fn unpinned_returns_empty_accepted_after_ingest() {
        let (router, bodies) = scripted_leader(vec![StatusCode::ACCEPTED]);
        let leader = mock_leader("aa", spawn_mock_leader(router).await);
        let state = retry_state(vec![leader], 3);
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let status = submit_transactions(State(state), HeaderMap::new(), body).await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(bodies.lock().expect("bodies lock").len(), 1);
    }

    #[tokio::test]
    async fn unpinned_retry_reposts_transient_leader_within_window() {
        let (router, bodies) =
            scripted_leader(vec![StatusCode::SERVICE_UNAVAILABLE, StatusCode::ACCEPTED]);
        let leader = mock_leader("aa", spawn_mock_leader(router).await);
        let state = retry_state(vec![leader], 2);
        let views = state.view_clock.current_view.clone();
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let submit = tokio::spawn(submit_transactions(State(state), HeaderMap::new(), body));
        let ticker = advance_views(views);
        let status = submit.await.expect("submit task");
        ticker.abort();

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(bodies.lock().expect("bodies lock").len(), 2);
    }

    #[tokio::test]
    async fn unpinned_retry_remains_bounded_when_view_stops() {
        let (router, bodies) =
            scripted_leader(vec![StatusCode::SERVICE_UNAVAILABLE, StatusCode::ACCEPTED]);
        let leader = mock_leader("aa", spawn_mock_leader(router).await);
        let state = retry_state(vec![leader], 1);
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let status = tokio::time::timeout(
            Duration::from_secs(1),
            submit_transactions(State(state), HeaderMap::new(), body),
        )
        .await
        .expect("view timeout should advance the retry window");

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(bodies.lock().expect("bodies lock").len(), 2);
    }

    #[tokio::test]
    async fn unpinned_does_not_retry_deterministic_rejection() {
        let (router, bodies) = scripted_leader(vec![StatusCode::BAD_REQUEST]);
        let leader = mock_leader("aa", spawn_mock_leader(router).await);
        let state = retry_state(vec![leader], 3);
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let status = submit_transactions(State(state), HeaderMap::new(), body).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(bodies.lock().expect("bodies lock").len(), 1);
    }

    #[tokio::test]
    async fn unpinned_retry_budget_returns_service_unavailable() {
        let (router, bodies) = scripted_leader(vec![StatusCode::SERVICE_UNAVAILABLE]);
        let leader = mock_leader("aa", spawn_mock_leader(router).await);
        let state = retry_state(vec![leader], 2);
        let views = state.view_clock.current_view.clone();
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let submit = tokio::spawn(submit_transactions(State(state), HeaderMap::new(), body));
        let ticker = advance_views(views);
        let status = submit.await.expect("submit task");
        ticker.abort();

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(bodies.lock().expect("bodies lock").len(), 3);
    }

    #[tokio::test]
    async fn unpinned_returns_after_first_acceptance() {
        let slow = Router::new().route(
            "/transactions/ingest",
            post(|| async { std::future::pending::<StatusCode>().await }),
        );
        let (accepted, accepted_bodies) = scripted_leader(vec![StatusCode::ACCEPTED]);
        let accepted = mock_leader("aa", spawn_mock_leader(accepted).await);
        let slow = mock_leader("bb", spawn_mock_leader(slow).await);
        let state = retry_state(vec![accepted, slow], 1);
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let status = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            submit_transactions(State(state), HeaderMap::new(), body),
        )
        .await
        .expect("accepted leader should complete the request");

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(accepted_bodies.lock().expect("bodies lock").len(), 1);
    }

    #[tokio::test]
    async fn unpinned_acceptance_wins_over_concurrent_rejection() {
        let rejected = scripted_leader(vec![StatusCode::BAD_REQUEST]).0;
        let accepted = Router::new().route(
            "/transactions/ingest",
            post(|| async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                StatusCode::ACCEPTED
            }),
        );
        let rejected = mock_leader("aa", spawn_mock_leader(rejected).await);
        let accepted = mock_leader("bb", spawn_mock_leader(accepted).await);
        let state = retry_state(vec![rejected, accepted], 0);
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let status = submit_transactions(State(state), HeaderMap::new(), body).await;

        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn unpinned_unresponsive_leader_returns_service_unavailable() {
        let slow = Router::new().route(
            "/transactions/ingest",
            post(|| async { std::future::pending::<StatusCode>().await }),
        );
        let slow = mock_leader("aa", spawn_mock_leader(slow).await);
        let state = retry_state(vec![slow], 0);
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let status = tokio::time::timeout(
            Duration::from_secs(1),
            submit_transactions(State(state), HeaderMap::new(), body),
        )
        .await
        .expect("leader request timeout should bound the admission attempt");

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }
}
