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
use commonware_parallel::Strategy;
use constantinople_engine::types::EngineActivity;
use constantinople_mempool::webserver::{AccountReader, TxStatus};
use constantinople_primitives::{Account, Nonce, SignedTransaction, TransactionPublicKey};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, OnceLock},
};
use tokio::sync::{Semaphore, watch};
use tower_http::cors::{Any, CorsLayer};
use tracing::debug;

const DEFAULT_MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
const MAX_BATCH_LENGTH_PREFIX_BYTES: usize = 5;
const MIN_BATCH_LENGTH_PREFIX_BYTES: usize = 1;
const TARGET_LEADER_HEADER: &str = "x-constantinople-relayer-target-leader";
const LEADER_FANOUT_HEADER: &str = "x-constantinople-relayer-leader-fanout";
const PINNED_SUBMIT_RETRIES: usize = 3;

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
}

#[derive(Clone)]
struct AppState<St: Strategy> {
    leaders: Arc<Vec<Leader>>,
    max_retry_views: u64,
    max_batch_bytes: usize,
    account_reader: Arc<OnceLock<Arc<dyn AccountReader>>>,
    view_clock: ViewClock,
    http: reqwest::Client,
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
struct DecodedBatch {
    transactions: Vec<SignedTransaction<sha256::Sha256>>,
    /// Hex digest -> every position in `transactions` carrying it (duplicate
    /// digests map to all copies), for matching status-API digest lists back
    /// to local transactions.
    digest_index: HashMap<String, Vec<usize>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "status")]
enum BatchStatus {
    Accepted,
    Finalized {
        height: u64,
    },
    PartiallyFinalized {
        height: u64,
        included: Vec<String>,
        filtered: Vec<String>,
    },
    Dropped,
}

#[derive(Debug)]
enum ForwardResult {
    Accepted { leader: Leader },
    Deterministic(StatusCode),
    Transient { leader: Leader },
}

pub async fn serve<St: Strategy>(config: ServerConfig<St>) {
    let state = AppState {
        leaders: Arc::new(normalize_leaders(config.relayer.leaders)),
        max_retry_views: config.relayer.max_retry_views,
        max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
        account_reader: config.account_reader,
        view_clock: config.view_clock,
        http: reqwest::Client::new(),
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
    // pool along with hashing the batch id. The owned permit rides in the
    // job to bound concurrent decode CPU (the pool is shared with the
    // co-located engine).
    let Ok(permit) = state.decode_permits.clone().acquire_owned().await else {
        return (StatusCode::INTERNAL_SERVER_ERROR, String::new());
    };
    let max_batch_bytes = state.max_batch_bytes;
    let decoded = state
        .strategy
        .spawn(move |_: St| {
            let _permit = permit;
            decode_batch(&body, max_batch_bytes).map(|batch| {
                let id = batch_id(&body);
                (batch, body, id)
            })
        })
        .await;
    let (batch, body, original_batch_id) = match decoded {
        Ok(parts) => parts,
        Err(status) => return (status, String::new()),
    };

    submit_with_retries(&state, batch, body, original_batch_id).await
}

async fn submit_to_pinned_leader<St: Strategy>(
    state: &AppState<St>,
    body: Bytes,
    target: &str,
) -> (StatusCode, String) {
    let Some(leader) = leader_by_id(&state.leaders, target).cloned() else {
        return (StatusCode::BAD_REQUEST, String::new());
    };
    submit_blocking_to_leader(&state.http, &leader, body).await
}

async fn submit_with_retries<St: Strategy>(
    state: &AppState<St>,
    batch: DecodedBatch,
    body: Bytes,
    original_batch_id: String,
) -> (StatusCode, String) {
    if state.leaders.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
    }

    let batch = Arc::new(batch);
    let total = batch.transactions.len();
    let mut pending: HashSet<usize> = (0..total).collect();
    let mut included: HashSet<usize> = HashSet::new();
    let mut sent: HashMap<String, Vec<usize>> = HashMap::new();
    let mut height = 0;
    let mut accepted_any = false;
    let mut attempts = Vec::<(String, Leader)>::new();
    let mut views = state.view_clock.current_view.subscribe();
    let mut view = *views.borrow();

    for retry in 0..=state.max_retry_views {
        // Until something resolves, resends reuse the original request bytes;
        // once the pending set shrinks, the subset is re-encoded and hashed
        // on the strategy's pool.
        let (send_body, sent_batch_id) = if pending.len() == total {
            (body.clone(), original_batch_id.clone())
        } else {
            let batch = Arc::clone(&batch);
            let pending = pending.clone();
            state
                .strategy
                .spawn(move |_: St| {
                    let body = encode_pending(&batch, &pending);
                    let id = batch_id(&body);
                    (body, id)
                })
                .await
        };
        sent.entry(sent_batch_id.clone())
            .or_insert_with(|| pending.iter().copied().collect());
        for target in next_two_leaders(&state.leaders, view) {
            attempts.push((sent_batch_id.clone(), target));
        }
        let targets = attempts
            .iter()
            .filter(|(batch_id, _)| batch_id == &sent_batch_id)
            .map(|(_, leader)| leader.clone())
            .collect::<Vec<_>>();
        let result = forward_to_targets(&state.http, &targets, send_body).await;
        if let Some(status) = result.deterministic {
            return (status, String::new());
        }
        accepted_any |= result.accepted;

        merge_statuses(state, &attempts, &sent, &batch, &mut included, &mut height).await;
        pending.retain(|index| !included.contains(index));
        if pending.is_empty() {
            return json_response(TxStatus::Finalized { height });
        }

        if retry == state.max_retry_views {
            if !accepted_any {
                return (StatusCode::SERVICE_UNAVAILABLE, String::new());
            }
            return json_response(best_effort_status(total, included.len(), height));
        }

        wait_for_view_advance(&mut views, &mut view).await;
    }

    json_response(best_effort_status(total, included.len(), height))
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

async fn merge_statuses<St: Strategy>(
    state: &AppState<St>,
    attempts: &[(String, Leader)],
    sent: &HashMap<String, Vec<usize>>,
    batch: &DecodedBatch,
    included: &mut HashSet<usize>,
    height: &mut u64,
) {
    for (batch_id, leader) in attempts {
        let Some(status) = fetch_status_from_leader(&state.http, leader, batch_id).await else {
            continue;
        };
        match status {
            BatchStatus::Accepted | BatchStatus::Dropped => {}
            // A fully finalized batch includes everything that was sent
            // under that batch id.
            BatchStatus::Finalized {
                height: finalized_height,
            } => {
                *height = (*height).max(finalized_height);
                if let Some(indices) = sent.get(batch_id) {
                    included.extend(indices.iter().copied());
                }
            }
            BatchStatus::PartiallyFinalized {
                height: finalized_height,
                included: leader_included,
                ..
            } => {
                *height = (*height).max(finalized_height);
                for digest in leader_included {
                    if let Some(indices) = batch.digest_index.get(&digest) {
                        included.extend(indices.iter().copied());
                    }
                }
            }
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

const fn best_effort_status(total: usize, included: usize, height: u64) -> TxStatus {
    if included == 0 {
        return TxStatus::Dropped;
    }
    if included == total {
        return TxStatus::Finalized { height };
    }
    TxStatus::PartiallyFinalized {
        height,
        included: included as u64,
        filtered: (total - included) as u64,
    }
}

fn json_response(status: TxStatus) -> (StatusCode, String) {
    (
        StatusCode::OK,
        serde_json::to_string(&status).expect("transaction status serialization cannot fail"),
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

async fn forward_to_leader(http: &reqwest::Client, leader: Leader, body: Bytes) -> ForwardResult {
    match http
        .post(format!("{}/transactions/ingest", leader.url))
        .header("content-type", "application/octet-stream")
        .body(body)
        .send()
        .await
    {
        Ok(response) if response.status() == StatusCode::ACCEPTED => {
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
    let mut digest_index: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, transaction) in transactions.iter().enumerate() {
        digest_index
            .entry(transaction.message_digest().to_string())
            .or_default()
            .push(index);
    }

    Ok(DecodedBatch {
        transactions,
        digest_index,
    })
}

fn encode_pending(batch: &DecodedBatch, pending: &HashSet<usize>) -> Bytes {
    batch
        .transactions
        .iter()
        .enumerate()
        .filter(|(index, _)| pending.contains(index))
        .map(|(_, transaction)| transaction)
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
    use axum::http::HeaderValue;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
    fn decode_batch_maps_duplicate_digests_to_all_positions() {
        let unique = signed_transfer(1, 0);
        let duplicate = signed_transfer(2, 0);
        let body = vec![unique.clone(), duplicate.clone(), duplicate.clone()].encode();

        let batch = decode_batch(&body, DEFAULT_MAX_BATCH_BYTES).expect("decode");

        let unique_positions = &batch.digest_index[&unique.message_digest().to_string()];
        let duplicate_positions = &batch.digest_index[&duplicate.message_digest().to_string()];
        assert_eq!(unique_positions, &vec![0]);
        assert_eq!(duplicate_positions, &vec![1, 2]);

        // Re-encoding the remaining subset preserves original order.
        let pending: HashSet<usize> = [0].into_iter().collect();
        assert_eq!(encode_pending(&batch, &pending), vec![unique].encode());
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
            http: reqwest::Client::new(),
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
    fn retry_budget_returns_partial_status() {
        let status = best_effort_status(2, 1, 7);

        assert_eq!(
            status,
            TxStatus::PartiallyFinalized {
                height: 7,
                included: 1,
                filtered: 1
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
