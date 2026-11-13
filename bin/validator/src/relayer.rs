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
use commonware_consensus::{
    Reporter, Viewable,
    types::{TermLength, View},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, sha256};
use commonware_cryptography_curve25519::signing as ed25519;
use commonware_formatting::from_hex;
use commonware_parallel::Strategy;
use constantinople_engine::types::EngineActivity;
use constantinople_mempool::webserver::{AccountReader, TxStatus};
use constantinople_primitives::{Account, Nonce, SignedTransaction, TransactionPublicKey};
use futures::{StreamExt, stream::FuturesUnordered};
use serde::Serialize;
use std::{
    cmp::Reverse,
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
const LEADER_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
// The Explorer allows twelve seconds including upload and decoding. Either
// deadline leaves uncertain delivery to digest reconciliation.
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

type Activity = EngineActivity<ed25519::VerifyingKey, MinSig>;

#[derive(Clone)]
pub struct Observer {
    current_view: watch::Sender<u64>,
    term_length: TermLength,
}

#[derive(Clone)]
pub struct ViewClock {
    current_view: watch::Sender<u64>,
    term_length: TermLength,
}

impl Observer {
    pub fn new(term_length: TermLength) -> (Self, ViewClock) {
        let (current_view, _) = watch::channel(0);
        (
            Self {
                current_view: current_view.clone(),
                term_length,
            },
            ViewClock {
                current_view,
                term_length,
            },
        )
    }
}

impl Reporter for Observer {
    type Activity = Activity;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let view = activity_view(&activity, self.term_length);
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

/// Returns the view the activity reports. A nullification abandons the rest of
/// its view's term, so it reports the last view of that term.
fn activity_view(activity: &Activity, term_length: TermLength) -> u64 {
    match activity {
        Activity::Notarize(activity) => activity.view().get(),
        Activity::Notarization(activity) | Activity::Certification(activity) => {
            activity.view().get()
        }
        Activity::Nullify(activity) => activity.view().get(),
        Activity::Nullification(activity) => activity.view().term_end(term_length).get(),
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
    /// Signed-transaction byte budget derived from the encoded block limit.
    /// Must match the validators' mempool budget so accepted batches fit a proposal.
    pub max_batch_bytes: usize,
}

#[derive(Clone)]
struct AppState<St: Strategy> {
    leaders: Arc<Vec<Leader>>,
    max_batch_bytes: usize,
    account_reader: Arc<OnceLock<Arc<dyn AccountReader>>>,
    view_clock: ViewClock,
    http: reqwest::Client,
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
        http: reqwest::Client::builder()
            .connect_timeout(LEADER_CONNECT_TIMEOUT)
            .build()
            .expect("relayer HTTP client configuration is valid"),
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
    let work_size = body.len();
    let decoded = state
        .strategy
        .spawn(work_size, move |_: St| {
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
    let Some(named) = leader_by_id(&state.leaders, target) else {
        return (StatusCode::BAD_REQUEST, String::new());
    };
    let term_length = state.view_clock.term_length;
    if term_length == TermLength::ONE {
        return submit_background_to_leader(&state.http, named, body).await;
    }

    // A pinned batch waits on one validator until it resolves. Under a term
    // longer than one view the named validator may not lead for a long time,
    // so the batch goes to the leader of the term containing the next view,
    // whatever validator the client named.
    //
    // If consensus leaves that term before the batch resolves, that leader may
    // never propose it. The relayer then stops waiting and answers 503, and
    // the client's retry reaches the leader of the new term.
    let mut current_view = state.view_clock.current_view.subscribe();
    let view = *current_view.borrow_and_update();
    let term = next_term(view, term_length);
    let leader = next_leaders(&state.leaders, view, term_length, 1).swap_remove(0);
    tokio::select! {
        response = submit_background_to_leader(&state.http, &leader, body) => response,
        Ok(_) = current_view.wait_for(|view| next_term(*view, term_length) != term) => {
            (StatusCode::SERVICE_UNAVAILABLE, String::new())
        }
    }
}

async fn submit_to_public_leaders<St: Strategy>(
    state: &AppState<St>,
    body: Bytes,
    fanout: usize,
) -> RelayResponse {
    if state.leaders.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
    }

    let view = *state.view_clock.current_view.borrow();
    let targets = next_leaders(&state.leaders, view, state.view_clock.term_length, fanout);
    let http = state.http.clone();
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
    let mut partial: Option<(u64, Reverse<u64>, u64)> = None;
    let mut rejection = None;
    let mut rejected = 0;
    let mut dropped = 0;

    while let Some(result) = sends.next().await {
        match result {
            LeaderResponse::Terminal(status @ TxStatus::Finalized { .. }) => {
                send_once(&mut response_tx, status_response(status));
            }
            LeaderResponse::Terminal(TxStatus::PartiallyFinalized {
                height,
                included,
                filtered,
            }) => {
                let candidate = (included, Reverse(filtered), height);
                partial = Some(partial.map_or(candidate, |current| current.max(candidate)));
            }
            LeaderResponse::Terminal(TxStatus::Dropped) => dropped += 1,
            LeaderResponse::Deterministic(status) => {
                rejection = Some(status);
                rejected += 1;
            }
            LeaderResponse::Ambiguous => {}
        }
    }

    // One leader's rejection cannot rule out acceptance by another copy.
    let response = match (partial, rejection) {
        (Some((included, Reverse(filtered), height)), _) => {
            status_response(TxStatus::PartiallyFinalized {
                height,
                included,
                filtered,
            })
        }
        (None, Some(status)) if rejected == target_count => (status, String::new()),
        _ if dropped == target_count => status_response(TxStatus::Dropped),
        _ => (StatusCode::ACCEPTED, String::new()),
    };
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
    let public_key = match TransactionPublicKey::decode(bytes) {
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

async fn submit_background_to_leader(
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
    let transactions = Vec::<SignedTransaction<sha256::Sha256>>::decode_cfg(body.clone(), &cfg)
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

/// Returns the index of the term containing the view after `observed_view`.
const fn next_term(observed_view: u64, term_length: TermLength) -> u64 {
    View::new(observed_view.saturating_add(1)).term_index(term_length)
}

/// Returns the leader of the term containing the view after `observed_view`,
/// followed by the leaders of the terms after it, as the round-robin elector
/// assigns them at epoch zero.
fn next_leaders(
    leaders: &[Leader],
    observed_view: u64,
    term_length: TermLength,
    fanout: usize,
) -> Vec<Leader> {
    if leaders.is_empty() {
        return Vec::new();
    }
    let first = (next_term(observed_view, term_length) % leaders.len() as u64) as usize;
    (0..fanout.min(leaders.len()))
        .map(|offset| leaders[(first + offset) % leaders.len()].clone())
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
    use commonware_consensus::{
        simplex::types::Nullification,
        types::{Epoch, Round},
    };
    use commonware_cryptography::bls12381::{certificate::threshold::Certificate, primitives::ops};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    const DEFAULT_MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
    const STABLE_TERM: TermLength = TermLength::new(std::num::NonZeroU32::new(1_000_000).unwrap());

    fn leader(key: &str) -> Leader {
        Leader {
            public_key: key.to_string(),
            sort_key: from_hex(key).expect("hex key"),
            url: format!("http://{key}"),
        }
    }

    fn leader_keys(leaders: Vec<Leader>) -> Vec<String> {
        leaders
            .into_iter()
            .map(|leader| leader.public_key)
            .collect()
    }

    fn signed_transfer(seed: u64, nonce: u64) -> SignedTransaction<sha256::Sha256> {
        use commonware_cryptography::Signer as _;
        use constantinople_primitives::Transaction;

        let sender = ed25519::SigningKey::from_seed(seed);
        let recipient = ed25519::SigningKey::from_seed(seed + 1).public_key();
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
        let (_, view_clock) = Observer::new(TermLength::ONE);
        AppState {
            leaders: Arc::new(leaders),
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            account_reader: Arc::new(OnceLock::new()),
            view_clock,
            http: reqwest::Client::builder()
                .build()
                .expect("test HTTP client configuration is valid"),
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

    async fn counted_leaders(
        count: usize,
        route: &'static str,
    ) -> (Vec<Leader>, Vec<Arc<AtomicUsize>>) {
        let mut leaders = Vec::with_capacity(count);
        let mut requests = Vec::with_capacity(count);
        for index in 0..count {
            let request_count = Arc::new(AtomicUsize::new(0));
            let request_count_for_handler = request_count.clone();
            let router = Router::new().route(
                route,
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

    fn request_counts(requests: &[Arc<AtomicUsize>]) -> Vec<usize> {
        requests
            .iter()
            .map(|count| count.load(Ordering::Relaxed))
            .collect()
    }

    /// Signals `received` when a background submission arrives and answers it
    /// as finalized only once `release` is notified.
    fn held_background_router(received: Arc<Notify>, release: Arc<Notify>) -> Router {
        Router::new().route(
            "/transactions/background",
            post(move || {
                let received = received.clone();
                let release = release.clone();
                async move {
                    received.notify_one();
                    release.notified().await;
                    status_response(TxStatus::Finalized { height: 3 })
                }
            }),
        )
    }

    fn nullification(view: u64) -> Activity {
        Activity::Nullification(Nullification {
            round: Round::new(Epoch::zero(), View::new(view)),
            certificate: Certificate::new(ops::hash::<MinSig>(b"relayer-test", b"nullification")),
        })
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

        let targets = leader_keys(next_leaders(&leaders, 0, TermLength::ONE, 2));

        assert_eq!(targets, vec!["01", "02"]);
    }

    #[test]
    fn targets_cap_fanout_at_network_size() {
        let leaders = vec![leader("00"), leader("01"), leader("02")];

        let targets = leader_keys(next_leaders(&leaders, 1, TermLength::ONE, 4));

        assert_eq!(targets, vec!["02", "00", "01"]);
    }

    #[test]
    fn single_view_terms_target_the_leaders_of_the_following_views() {
        let leaders = vec![leader("00"), leader("01"), leader("02"), leader("03")];

        for view in 0..12 {
            for fanout in 1..=leaders.len() {
                let expected = (0..fanout)
                    .map(|offset| {
                        leaders[(view + 1 + offset) % leaders.len()]
                            .public_key
                            .clone()
                    })
                    .collect::<Vec<_>>();
                let targets =
                    leader_keys(next_leaders(&leaders, view as u64, TermLength::ONE, fanout));
                assert_eq!(targets, expected, "view {view}, fanout {fanout}");
            }
        }
    }

    #[test]
    fn stable_term_targets_one_leader_until_the_next_term() {
        let leaders = vec![leader("00"), leader("01"), leader("02")];

        for view in [0, 1, 500_000, 999_999] {
            assert_eq!(
                leader_keys(next_leaders(&leaders, view, STABLE_TERM, 2)),
                vec!["01", "02"],
                "view {view}"
            );
        }
        assert_eq!(
            leader_keys(next_leaders(&leaders, 1_000_000, STABLE_TERM, 2)),
            vec!["02", "00"]
        );
    }

    #[test]
    fn schedule_matches_the_round_robin_elector() {
        use commonware_consensus::{
            simplex::elector::{Config as ElectorConfig, Elector as _, RoundRobin},
            types::ViewDelta,
        };
        use commonware_cryptography::Signer as _;
        use commonware_formatting::hex;
        use commonware_utils::{TryCollect as _, ordered::Set};
        type Scheme = constantinople_engine::ThresholdScheme<ed25519::VerifyingKey, MinSig>;

        let keys = (0..5)
            .map(|seed| ed25519::SigningKey::from_seed(seed).public_key())
            .collect::<Vec<_>>();
        let participants: Set<ed25519::VerifyingKey> = keys.iter().cloned().try_collect().unwrap();
        let leaders = normalize_leaders(
            keys.iter()
                .map(|key| RelayerLeaderConfig {
                    public_key: hex(&key.encode()),
                    url: "http://leader".to_string(),
                })
                .collect(),
        );
        let term_length = TermLength::new(std::num::NonZeroU32::new(3).unwrap());
        let configs = [
            (TermLength::ONE, RoundRobin::<sha256::Sha256>::default()),
            (
                term_length,
                RoundRobin::default().with_term(
                    term_length,
                    Duration::from_secs(1),
                    ViewDelta::new(0),
                ),
            ),
        ];

        for (term_length, config) in configs {
            let elector = ElectorConfig::<Scheme>::build(config, &participants);
            for view in 0..20 {
                let elected = elector.elect(Round::new(Epoch::zero(), View::new(view + 1)), ());
                assert_eq!(
                    next_leaders(&leaders, view, term_length, 1)[0].public_key,
                    hex(&participants[usize::from(elected)].encode()),
                    "term length {term_length}, view {view}"
                );
            }
        }
    }

    #[test]
    fn nullification_advances_to_the_next_term_leader() {
        let leaders = vec![leader("00"), leader("01"), leader("02")];

        for (term_length, expected) in [(TermLength::ONE, "01"), (STABLE_TERM, "02")] {
            let (mut observer, view_clock) = Observer::new(term_length);
            let _ = observer.report(nullification(3));
            let view = *view_clock.current_view.borrow();

            assert_eq!(
                leader_keys(next_leaders(&leaders, view, term_length, 1)),
                vec![expected],
                "term length {term_length}"
            );
        }
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
    async fn pinned_target_follows_the_term_leader_only_under_long_terms() {
        for (term_length, expected) in [(TermLength::ONE, [1, 0]), (STABLE_TERM, [0, 1])] {
            let (leaders, requests) = counted_leaders(2, "/transactions/background").await;
            let mut state = test_state(
                leaders,
                Duration::from_millis(100),
                Duration::from_millis(200),
            );
            state.view_clock = Observer::new(term_length).1;

            let response = submit_transactions(
                State(state),
                pinned_headers(),
                Bytes::from_static(b"not a codec batch"),
            )
            .await;

            assert_eq!(response, status_response(TxStatus::Dropped));
            assert_eq!(
                request_counts(&requests),
                expected,
                "term length {term_length}"
            );
        }
    }

    #[tokio::test]
    async fn pinned_unknown_target_is_rejected_under_long_terms() {
        let mut state = test_state(
            vec![leader("01")],
            Duration::from_millis(100),
            Duration::from_millis(200),
        );
        state.view_clock = Observer::new(STABLE_TERM).1;

        let response = submit_transactions(
            State(state),
            pinned_headers(),
            Bytes::from_static(b"not a codec batch"),
        )
        .await;

        assert_eq!(response, (StatusCode::BAD_REQUEST, String::new()));
    }

    #[tokio::test]
    async fn pinned_batch_is_released_when_its_term_ends() {
        for nullify in [true, false] {
            let (mut leaders, requests) = counted_leaders(3, "/transactions/background").await;
            let received = Arc::new(Notify::new());
            let held = held_background_router(received.clone(), Arc::new(Notify::new()));
            leaders[1] = mock_leader("01", spawn_mock_leader(held).await);
            let mut state = test_state(
                leaders,
                Duration::from_millis(100),
                Duration::from_millis(200),
            );
            let (mut observer, view_clock) = Observer::new(STABLE_TERM);
            state.view_clock = view_clock.clone();
            let body = Bytes::from_static(b"not a codec batch");

            let submission = tokio::spawn(submit_transactions(
                State(state.clone()),
                pinned_headers(),
                body.clone(),
            ));
            tokio::time::timeout(Duration::from_secs(1), received.notified())
                .await
                .expect("the first-term leader should receive the batch");
            if nullify {
                let _ = observer.report(nullification(3));
            } else {
                view_clock.current_view.send_replace(STABLE_TERM.get());
            }
            let response = tokio::time::timeout(Duration::from_secs(1), submission)
                .await
                .expect("leaving the term should release the pinned batch")
                .expect("submission task should not panic");
            assert_eq!(response, (StatusCode::SERVICE_UNAVAILABLE, String::new()));

            let response = submit_transactions(State(state), pinned_headers(), body).await;

            assert_eq!(response, status_response(TxStatus::Dropped));
            assert_eq!(
                request_counts(&requests),
                vec![0, 0, 1],
                "nullify {nullify}"
            );
        }
    }

    #[tokio::test]
    async fn single_view_terms_do_not_interrupt_a_pinned_batch() {
        let received = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let held = held_background_router(received.clone(), release.clone());
        let state = test_state(
            vec![mock_leader("00", spawn_mock_leader(held).await)],
            Duration::from_millis(100),
            Duration::from_millis(200),
        );
        let view_clock = state.view_clock.clone();

        let mut submission = tokio::spawn(submit_transactions(
            State(state),
            pinned_headers(),
            Bytes::from_static(b"not a codec batch"),
        ));
        tokio::time::timeout(Duration::from_secs(1), received.notified())
            .await
            .expect("the named leader should receive the batch");
        view_clock.current_view.send_replace(5);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut submission)
                .await
                .is_err(),
            "a view change must not release the pinned batch"
        );
        release.notify_one();
        let response = tokio::time::timeout(Duration::from_secs(1), submission)
            .await
            .expect("the pinned batch should resolve once the leader answers")
            .expect("submission task should not panic");

        assert_eq!(response, status_response(TxStatus::Finalized { height: 3 }));
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
        let (leaders, requests) = counted_leaders(5, "/transactions").await;
        let state = test_state(
            leaders,
            Duration::from_millis(100),
            Duration::from_millis(200),
        );
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let response = submit_transactions(State(state), HeaderMap::new(), body).await;

        assert_eq!(response, status_response(TxStatus::Dropped));
        assert_eq!(request_counts(&requests), vec![0, 1, 1, 1, 1]);
    }

    #[tokio::test]
    async fn unpinned_multi_transaction_batch_fans_out_to_two_leaders() {
        let (leaders, requests) = counted_leaders(5, "/transactions").await;
        let state = test_state(
            leaders,
            Duration::from_millis(100),
            Duration::from_millis(200),
        );
        let body: Bytes = vec![signed_transfer(1, 0), signed_transfer(2, 0)].encode();

        let response = submit_transactions(State(state), HeaderMap::new(), body).await;

        assert_eq!(response, status_response(TxStatus::Dropped));
        assert_eq!(request_counts(&requests), vec![0, 1, 1, 0, 0]);
    }

    #[tokio::test]
    async fn unpinned_rejection_does_not_resolve_an_uncertain_copy() {
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

        assert_eq!(response, (StatusCode::ACCEPTED, String::new()));
    }

    #[tokio::test]
    async fn unpinned_size_rejection_cannot_beat_finality() {
        let rejected = Router::new()
            .route(
                "/transactions",
                post(|_: Bytes| async { status_response(TxStatus::Dropped) }),
            )
            .layer(DefaultBodyLimit::max(1));
        let finalized = terminal_router(
            TxStatus::Finalized { height: 11 },
            Duration::from_millis(30),
            None,
        );
        let leaders = vec![
            mock_leader("00", spawn_mock_leader(rejected).await),
            mock_leader("01", spawn_mock_leader(finalized).await),
        ];
        let state = test_state(
            leaders,
            Duration::from_millis(200),
            Duration::from_millis(400),
        );
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let response = submit_transactions(State(state), HeaderMap::new(), body).await;

        assert_eq!(
            response,
            status_response(TxStatus::Finalized { height: 11 })
        );
    }

    #[tokio::test]
    async fn unpinned_unanimous_rejection_is_terminal() {
        for status in [StatusCode::BAD_REQUEST, StatusCode::PAYLOAD_TOO_LARGE] {
            let rejected = || {
                Router::new().route(
                    "/transactions",
                    post(move || async move { (status, String::new()) }),
                )
            };
            let leaders = vec![
                mock_leader("00", spawn_mock_leader(rejected()).await),
                mock_leader("01", spawn_mock_leader(rejected()).await),
            ];
            let state = test_state(
                leaders,
                Duration::from_millis(200),
                Duration::from_millis(400),
            );
            let body = vec![signed_transfer(1, 0)].encode();

            let response = submit_transactions(State(state), HeaderMap::new(), body).await;

            assert_eq!(response, (status, String::new()));
        }
    }

    #[tokio::test]
    async fn unpinned_dropped_and_uncertain_remains_pending() {
        for status in [StatusCode::OK, StatusCode::SERVICE_UNAVAILABLE] {
            let uncertain = Router::new().route(
                "/transactions",
                post(move || async move { (status, "not a terminal status") }),
            );
            let leaders = vec![
                mock_leader(
                    "00",
                    spawn_mock_leader(terminal_router(TxStatus::Dropped, Duration::ZERO, None))
                        .await,
                ),
                mock_leader("01", spawn_mock_leader(uncertain).await),
            ];
            let state = test_state(
                leaders,
                Duration::from_millis(200),
                Duration::from_millis(400),
            );
            let body = vec![signed_transfer(1, 0)].encode();

            let response = submit_transactions(State(state), HeaderMap::new(), body).await;

            assert_eq!(response, (StatusCode::ACCEPTED, String::new()));
        }
    }

    #[tokio::test]
    async fn unpinned_partial_prefers_more_included_in_either_order() {
        let preferred = TxStatus::PartiallyFinalized {
            height: 7,
            included: 3,
            filtered: 1,
        };
        let other = TxStatus::PartiallyFinalized {
            height: 9,
            included: 2,
            filtered: 2,
        };
        for outcomes in [[preferred, other], [other, preferred]] {
            let leaders = vec![
                mock_leader(
                    "00",
                    spawn_mock_leader(terminal_router(outcomes[0], Duration::ZERO, None)).await,
                ),
                mock_leader(
                    "01",
                    spawn_mock_leader(terminal_router(
                        outcomes[1],
                        Duration::from_millis(30),
                        None,
                    ))
                    .await,
                ),
            ];
            let state = test_state(
                leaders,
                Duration::from_millis(200),
                Duration::from_millis(400),
            );
            let body = (0..4)
                .map(|nonce| signed_transfer(1, nonce))
                .collect::<Vec<_>>()
                .encode();

            let response = submit_transactions(State(state), HeaderMap::new(), body).await;

            assert_eq!(response, status_response(preferred));
        }
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
