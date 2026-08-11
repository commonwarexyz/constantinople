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
use commonware_consensus::{
    Reporter, Viewable,
    types::{TermLength, View},
};
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
const LEADER_HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const PINNED_SUBMIT_TIMEOUT: Duration = Duration::from_secs(30);

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

fn activity_view(activity: &Activity, term_length: TermLength) -> u64 {
    match activity {
        Activity::Notarize(activity) => activity.view().get(),
        Activity::Notarization(activity) | Activity::Certification(activity) => {
            activity.view().get()
        }
        Activity::Nullify(activity) => activity.view().get(),
        Activity::Nullification(activity) => activity
            .view()
            .next_term_start(term_length)
            .get()
            .saturating_sub(1),
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
    strategy: St,
    decode_permits: Arc<Semaphore>,
    leader_http_timeout: Duration,
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
}

/// Hex digest -> every position in `transactions` carrying it (duplicate
/// digests map to all copies), for matching status-API digest lists back to
/// local transactions.
///
/// Only the partial-finalization status arm consumes this, so it is built on
/// demand (on the strategy's pool) instead of eagerly hex-formatting tens of
/// thousands of digests on every submission.
type DigestIndex = HashMap<String, Vec<usize>>;

fn build_digest_index(batch: &DecodedBatch) -> DigestIndex {
    let mut digest_index = DigestIndex::new();
    for (index, transaction) in batch.transactions.iter().enumerate() {
        digest_index
            .entry(transaction.message_digest().to_string())
            .or_default()
            .push(index);
    }
    digest_index
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
        max_batch_bytes: config.max_batch_bytes,
        account_reader: config.account_reader,
        view_clock: config.view_clock,
        http: reqwest::Client::new(),
        strategy: config.strategy,
        decode_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_DECODES)),
        leader_http_timeout: LEADER_HTTP_TIMEOUT,
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
    // decode CPU. Single-threaded: the wire format has no per-transaction
    // framing to split on.
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
    let mut filtered: HashSet<usize> = HashSet::new();
    let mut sent: HashMap<String, Vec<usize>> = HashMap::new();
    let mut digest_index: Option<DigestIndex> = None;
    let mut height = 0;

    // Every (batch id, leader) pair POSTed at least once; polled every
    // round, which recovers accepts lost in transit.
    let mut posted = Vec::<(String, Leader)>::new();

    // Accepted and terminal pairs are never re-POSTed. Repeat POSTs for an
    // unresolved attempt are safe because leaders key status by batch id.
    let mut accepted: HashSet<(String, String)> = HashSet::new();
    let mut terminal_attempts: HashSet<(String, String)> = HashSet::new();
    let mut views = state.view_clock.current_view.subscribe();
    let mut view = *views.borrow();
    let mut unaccepted_retries = 0;

    loop {
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

        // POST only to the leader for the next view. A resend to an accepting
        // leader only re-burns its ingress decode and verification.
        let target = next_leader(&state.leaders, view, state.view_clock.term_length)
            .expect("non-empty leader set");
        let accepted_key = (sent_batch_id.clone(), target.public_key.clone());
        if !accepted.contains(&accepted_key) && !terminal_attempts.contains(&accepted_key) {
            let has_prior_attempt = !posted.is_empty();
            if !posted.iter().any(|(batch_id, leader)| {
                batch_id == &sent_batch_id && leader.public_key == target.public_key
            }) {
                posted.push((sent_batch_id.clone(), target.clone()));
            }
            match forward_to_leader(&state.http, target, send_body, state.leader_http_timeout).await
            {
                ForwardResult::Accepted { leader } => {
                    debug!(leader = %leader.public_key, "relayer forward accepted");
                    accepted.insert((sent_batch_id.clone(), leader.public_key));
                }
                ForwardResult::Deterministic(status) => {
                    // A prior POST may have been admitted even when its
                    // response was lost. A later target's rejection is not a
                    // terminal outcome for that unresolved attempt.
                    if accepted.is_empty() && !has_prior_attempt {
                        return (status, String::new());
                    }
                }
                ForwardResult::Transient { leader } => {
                    debug!(leader = %leader.public_key, "relayer forward transient failure");
                }
            }
        }

        merge_statuses(
            state,
            &posted,
            &sent,
            &batch,
            &mut accepted,
            &mut terminal_attempts,
            &mut digest_index,
            &mut included,
            &mut filtered,
            &mut height,
        )
        .await;
        pending.retain(|index| !included.contains(index));
        if pending.is_empty() {
            return json_response(TxStatus::Finalized { height });
        }

        if accepted.is_empty() {
            if unaccepted_retries == state.max_retry_views {
                if let Some(status) = terminal_status(total, &included, &filtered, height) {
                    return json_response(status);
                }
                return (StatusCode::SERVICE_UNAVAILABLE, String::new());
            }
            unaccepted_retries += 1;
        } else {
            // The routing budget bounds attempts to find an accepting leader,
            // not the lifetime of work a leader has already admitted.
            unaccepted_retries = 0;
        }

        wait_for_view_advance(&mut views, &mut view).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn merge_statuses<St: Strategy>(
    state: &AppState<St>,
    posted: &[(String, Leader)],
    sent: &HashMap<String, Vec<usize>>,
    batch: &Arc<DecodedBatch>,
    accepted: &mut HashSet<(String, String)>,
    terminal_attempts: &mut HashSet<(String, String)>,
    digest_index: &mut Option<DigestIndex>,
    included: &mut HashSet<usize>,
    filtered: &mut HashSet<usize>,
    height: &mut u64,
) {
    let fetches = posted
        .iter()
        .filter(|(batch_id, leader)| {
            !terminal_attempts.contains(&(batch_id.clone(), leader.public_key.clone()))
        })
        .map(|(batch_id, leader)| {
            let http = state.http.clone();
            async move {
                (
                    batch_id,
                    leader,
                    fetch_status_from_leader(&http, leader, batch_id, state.leader_http_timeout)
                        .await,
                )
            }
        });
    for (batch_id, leader, status) in join_all(fetches).await {
        let Some(status) = status else {
            continue;
        };
        let accepted_key = (batch_id.clone(), leader.public_key.clone());
        match status {
            BatchStatus::Accepted => {
                accepted.insert(accepted_key);
            }
            BatchStatus::Dropped => {
                accepted.remove(&accepted_key);
                terminal_attempts.insert(accepted_key);
                if let Some(indices) = sent.get(batch_id) {
                    filtered.extend(indices.iter().copied());
                }
            }

            // A fully finalized batch includes everything that was sent
            // under that batch id.
            BatchStatus::Finalized {
                height: finalized_height,
            } => {
                accepted.remove(&accepted_key);
                terminal_attempts.insert(accepted_key);
                *height = (*height).max(finalized_height);
                if let Some(indices) = sent.get(batch_id) {
                    included.extend(indices.iter().copied());
                }
            }
            BatchStatus::PartiallyFinalized {
                height: finalized_height,
                included: leader_included,
                filtered: leader_filtered,
            } => {
                accepted.remove(&accepted_key);
                terminal_attempts.insert(accepted_key);
                *height = (*height).max(finalized_height);
                if digest_index.is_none() {
                    let batch = Arc::clone(batch);
                    *digest_index = Some(
                        state
                            .strategy
                            .spawn(move |_: St| build_digest_index(&batch))
                            .await,
                    );
                }
                let index = digest_index.as_ref().expect("digest index built above");
                for digest in leader_included {
                    if let Some(indices) = index.get(&digest) {
                        included.extend(indices.iter().copied());
                    }
                }
                for digest in leader_filtered {
                    if let Some(indices) = index.get(&digest) {
                        filtered.extend(indices.iter().copied());
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

/// Builds a terminal response only after every original transaction has a
/// leader-reported outcome. Inclusion wins if different attempts report the
/// same transaction both included and filtered.
fn terminal_status(
    total: usize,
    included: &HashSet<usize>,
    filtered: &HashSet<usize>,
    height: u64,
) -> Option<TxStatus> {
    let filtered = filtered.difference(included).count();
    if included.len() + filtered != total {
        return None;
    }
    if included.is_empty() {
        return Some(TxStatus::Dropped);
    }
    Some(TxStatus::PartiallyFinalized {
        height,
        included: included.len() as u64,
        filtered: filtered as u64,
    })
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

async fn forward_to_leader(
    http: &reqwest::Client,
    leader: Leader,
    body: Bytes,
    timeout: Duration,
) -> ForwardResult {
    match http
        .post(format!("{}/transactions/ingest", leader.url))
        .header("content-type", "application/octet-stream")
        .body(body)
        .timeout(timeout)
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
            .timeout(PINNED_SUBMIT_TIMEOUT)
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
    timeout: Duration,
) -> Option<BatchStatus> {
    let response = http
        .get(format!("{}/transactions/{batch_id}", leader.url))
        .timeout(timeout)
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

    Ok(DecodedBatch { transactions })
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
    sha256::Sha256::hash(&[body.as_ref()]).to_string()
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

fn next_leader(leaders: &[Leader], observed_view: u64, term_length: TermLength) -> Option<Leader> {
    if leaders.is_empty() {
        return None;
    }
    let next_view = View::new(observed_view.saturating_add(1));
    let term = next_view.term_index(term_length);
    let index = usize::try_from(term % leaders.len() as u64).ok()?;
    leaders.get(index).cloned()
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
    fn digest_index_maps_duplicate_digests_to_all_positions() {
        let unique = signed_transfer(1, 0);
        let duplicate = signed_transfer(2, 0);
        let body = vec![unique.clone(), duplicate.clone(), duplicate.clone()].encode();

        let batch = decode_batch(&body, DEFAULT_MAX_BATCH_BYTES).expect("decode");
        let digest_index = build_digest_index(&batch);

        let unique_positions = &digest_index[&unique.message_digest().to_string()];
        let duplicate_positions = &digest_index[&duplicate.message_digest().to_string()];
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
        let (_, view_clock) = Observer::new(TermLength::ONE);
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
            leader_http_timeout: Duration::from_millis(50),
        }
    }

    fn pinned_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(TARGET_LEADER_HEADER, HeaderValue::from_static("00"));
        headers.insert(LEADER_FANOUT_HEADER, HeaderValue::from_static("1"));
        headers
    }

    #[test]
    fn targets_only_the_next_view_leader() {
        let leaders = vec![leader("00"), leader("01"), leader("02"), leader("03")];

        let target = next_leader(&leaders, 0, TermLength::ONE).expect("leader");

        assert_eq!(target.public_key, "01");
    }

    #[test]
    fn targets_one_leader_for_an_entire_stable_term() {
        let leaders = vec![leader("00"), leader("01"), leader("02")];
        let term_length = TermLength::new(std::num::NonZeroU32::new(1_000_000).unwrap());

        assert_eq!(
            next_leader(&leaders, 0, term_length)
                .expect("first-term leader")
                .public_key,
            "01"
        );
        assert_eq!(
            next_leader(&leaders, 999_999, term_length)
                .expect("first-term leader")
                .public_key,
            "01"
        );
        assert_eq!(
            next_leader(&leaders, 1_000_000, term_length)
                .expect("second-term leader")
                .public_key,
            "02"
        );
    }

    #[test]
    fn targets_single_leader_network() {
        let leaders = vec![leader("00")];

        assert_eq!(
            next_leader(&leaders, 12, TermLength::ONE)
                .expect("leader")
                .public_key,
            "00"
        );
    }

    #[test]
    fn terminal_status_requires_an_outcome_for_every_transaction() {
        let included: HashSet<usize> = [0].into_iter().collect();
        let observed: HashSet<usize> = [0, 1].into_iter().collect();

        // An index reported both included and filtered counts as included.
        assert_eq!(
            terminal_status(2, &included, &observed, 7),
            Some(TxStatus::PartiallyFinalized {
                height: 7,
                included: 1,
                filtered: 1
            })
        );
        assert_eq!(terminal_status(2, &included, &HashSet::new(), 7), None);
        assert_eq!(
            terminal_status(2, &HashSet::new(), &observed, 0),
            Some(TxStatus::Dropped)
        );
        assert_eq!(
            terminal_status(2, &HashSet::new(), &HashSet::new(), 0),
            None
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

    /// A mock leader whose ingest endpoint answers with scripted status codes
    /// (default 202) while recording POST bodies, and whose status endpoint
    /// serves scripted [`BatchStatus`] responses (`None` -> 404).
    fn scripted_leader(
        ingest: Vec<StatusCode>,
        statuses: Vec<Option<BatchStatus>>,
    ) -> (Router, Arc<std::sync::Mutex<Vec<Bytes>>>) {
        let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ingest = Arc::new(std::sync::Mutex::new(ingest));
        let statuses = Arc::new(std::sync::Mutex::new(statuses));
        let bodies_for_handler = bodies.clone();
        let router = Router::new()
            .route(
                "/transactions/ingest",
                post(move |body: Bytes| {
                    let bodies = bodies_for_handler.clone();
                    let ingest = ingest.clone();
                    async move {
                        bodies.lock().expect("bodies lock").push(body);
                        let status = take_scripted(&ingest).unwrap_or(StatusCode::ACCEPTED);
                        (status, String::new())
                    }
                }),
            )
            .route(
                "/transactions/{batch_id}",
                get(move |Path(_): Path<String>| {
                    let statuses = statuses.clone();
                    async move {
                        take_scripted(&statuses).flatten().map_or_else(
                            || (StatusCode::NOT_FOUND, String::new()),
                            |status| {
                                (
                                    StatusCode::OK,
                                    serde_json::to_string(&status).expect("status json"),
                                )
                            },
                        )
                    }
                }),
            );
        (router, bodies)
    }

    fn retry_state(
        leaders: Vec<Leader>,
        max_retry_views: u64,
    ) -> AppState<commonware_parallel::Sequential> {
        retry_state_with_term(leaders, max_retry_views, TermLength::ONE)
    }

    fn retry_state_with_term(
        leaders: Vec<Leader>,
        max_retry_views: u64,
        term_length: TermLength,
    ) -> AppState<commonware_parallel::Sequential> {
        let (_, view_clock) = Observer::new(term_length);
        AppState {
            leaders: Arc::new(leaders),
            max_retry_views,
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            account_reader: Arc::new(OnceLock::new()),
            view_clock,
            http: reqwest::Client::new(),
            strategy: commonware_parallel::Sequential,
            decode_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_DECODES)),
            leader_http_timeout: Duration::from_millis(50),
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
    async fn unpinned_retry_tracks_each_rotating_leader_without_fanout() {
        let (router_a, bodies_a) = scripted_leader(
            Vec::new(),
            vec![
                Some(BatchStatus::Accepted),
                Some(BatchStatus::Finalized { height: 7 }),
            ],
        );
        let (router_b, bodies_b) = scripted_leader(Vec::new(), vec![Some(BatchStatus::Accepted)]);
        let leader_a = mock_leader("aa", spawn_mock_leader(router_a).await);
        let leader_b = mock_leader("bb", spawn_mock_leader(router_b).await);
        let state = retry_state(vec![leader_a, leader_b], 3);
        let views = state.view_clock.current_view.clone();
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let submit = tokio::spawn(submit_transactions(State(state), HeaderMap::new(), body));
        let ticker = advance_views(views);
        let (status, response) = submit.await.expect("submit task");
        ticker.abort();

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<TxStatus>(&response).expect("status json"),
            TxStatus::Finalized { height: 7 },
        );

        // Each retry posts to only that view's leader. Accepted batches are
        // polled and are not re-posted when their leader rotates back in.
        assert_eq!(bodies_a.lock().expect("bodies lock").len(), 1);
        assert_eq!(bodies_b.lock().expect("bodies lock").len(), 1);
    }

    #[tokio::test]
    async fn stalled_historical_status_does_not_block_a_terminal_result() {
        let bodies_a = Arc::new(std::sync::Mutex::new(Vec::new()));
        let bodies_a_for_handler = bodies_a.clone();
        let router_a = Router::new()
            .route(
                "/transactions/ingest",
                post(move |body: Bytes| {
                    let bodies = bodies_a_for_handler.clone();
                    async move {
                        bodies.lock().expect("bodies lock").push(body);
                        (StatusCode::ACCEPTED, String::new())
                    }
                }),
            )
            .route(
                "/transactions/{batch_id}",
                get(|| async { std::future::pending::<(StatusCode, String)>().await }),
            );
        let (router_b, bodies_b) = scripted_leader(
            Vec::new(),
            vec![
                Some(BatchStatus::Accepted),
                Some(BatchStatus::Finalized { height: 7 }),
            ],
        );
        let leader_a = mock_leader("aa", spawn_mock_leader(router_a).await);
        let leader_b = mock_leader("bb", spawn_mock_leader(router_b).await);
        let state = retry_state(vec![leader_a, leader_b], 3);
        let views = state.view_clock.current_view.clone();
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let submit = tokio::spawn(submit_transactions(State(state), HeaderMap::new(), body));
        let ticker = advance_views(views);
        let (status, response) =
            tokio::time::timeout(std::time::Duration::from_millis(250), submit)
                .await
                .expect("a stalled historical leader should be bounded")
                .expect("submit task");
        ticker.abort();

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<TxStatus>(&response).expect("status json"),
            TxStatus::Finalized { height: 7 },
        );
        assert_eq!(bodies_a.lock().expect("bodies lock").len(), 1);
        assert_eq!(bodies_b.lock().expect("bodies lock").len(), 1);
    }

    #[tokio::test]
    async fn unpinned_stable_term_posts_only_to_its_leader() {
        let (router_a, bodies_a) = scripted_leader(Vec::new(), Vec::new());
        let (router_b, bodies_b) =
            scripted_leader(Vec::new(), vec![Some(BatchStatus::Finalized { height: 7 })]);
        let leader_a = mock_leader("aa", spawn_mock_leader(router_a).await);
        let leader_b = mock_leader("bb", spawn_mock_leader(router_b).await);
        let term_length = TermLength::new(std::num::NonZeroU32::new(1_000_000).unwrap());
        let state = retry_state_with_term(vec![leader_a, leader_b], 3, term_length);
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let (status, response) = submit_transactions(State(state), HeaderMap::new(), body).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<TxStatus>(&response).expect("status json"),
            TxStatus::Finalized { height: 7 },
        );
        assert!(bodies_a.lock().expect("bodies lock").is_empty());
        assert_eq!(bodies_b.lock().expect("bodies lock").len(), 1);
    }

    #[tokio::test]
    async fn unpinned_retry_reposts_transient_leader_within_window() {
        let (router, bodies) = scripted_leader(
            vec![StatusCode::SERVICE_UNAVAILABLE, StatusCode::ACCEPTED],
            vec![None, Some(BatchStatus::Finalized { height: 3 })],
        );
        let leader = mock_leader("aa", spawn_mock_leader(router).await);
        let state = retry_state(vec![leader], 2);
        let views = state.view_clock.current_view.clone();
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let submit = tokio::spawn(submit_transactions(State(state), HeaderMap::new(), body));
        let ticker = advance_views(views);
        let (status, response) = submit.await.expect("submit task");
        ticker.abort();

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<TxStatus>(&response).expect("status json"),
            TxStatus::Finalized { height: 3 },
        );

        // The transient round-0 failure is retried in round 1 because the
        // single leader stays in the targeting window; the accepted POST is
        // never repeated.
        assert_eq!(bodies.lock().expect("bodies lock").len(), 2);
    }

    #[tokio::test]
    async fn accepted_batch_outlives_routing_retry_budget() {
        let (router, bodies) = scripted_leader(
            Vec::new(),
            vec![
                Some(BatchStatus::Accepted),
                Some(BatchStatus::Accepted),
                Some(BatchStatus::Finalized { height: 3 }),
            ],
        );
        let leader = mock_leader("aa", spawn_mock_leader(router).await);
        let state = retry_state(vec![leader], 1);
        let views = state.view_clock.current_view.clone();
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let submit = tokio::spawn(submit_transactions(State(state), HeaderMap::new(), body));
        let ticker = advance_views(views);
        let (status, response) = submit.await.expect("submit task");
        ticker.abort();

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<TxStatus>(&response).expect("status json"),
            TxStatus::Finalized { height: 3 },
        );
        assert_eq!(bodies.lock().expect("bodies lock").len(), 1);
    }

    #[tokio::test]
    async fn accepted_status_recovers_lost_ingest_response() {
        let (router, bodies) = scripted_leader(
            vec![StatusCode::INTERNAL_SERVER_ERROR],
            vec![
                Some(BatchStatus::Accepted),
                Some(BatchStatus::Accepted),
                Some(BatchStatus::Finalized { height: 3 }),
            ],
        );
        let leader = mock_leader("aa", spawn_mock_leader(router).await);
        let state = retry_state(vec![leader], 1);
        let views = state.view_clock.current_view.clone();
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let submit = tokio::spawn(submit_transactions(State(state), HeaderMap::new(), body));
        let ticker = advance_views(views);
        let (status, response) = submit.await.expect("submit task");
        ticker.abort();

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<TxStatus>(&response).expect("status json"),
            TxStatus::Finalized { height: 3 },
        );
        assert_eq!(bodies.lock().expect("bodies lock").len(), 1);
    }

    #[tokio::test]
    async fn later_leader_rejection_does_not_override_an_accepted_attempt() {
        let (router_a, bodies_a) = scripted_leader(vec![StatusCode::BAD_REQUEST], vec![None]);
        let (router_b, bodies_b) = scripted_leader(
            Vec::new(),
            vec![
                Some(BatchStatus::Accepted),
                Some(BatchStatus::Finalized { height: 3 }),
            ],
        );
        let leader_a = mock_leader("aa", spawn_mock_leader(router_a).await);
        let leader_b = mock_leader("bb", spawn_mock_leader(router_b).await);
        let state = retry_state(vec![leader_a, leader_b], 2);
        let views = state.view_clock.current_view.clone();
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let submit = tokio::spawn(submit_transactions(State(state), HeaderMap::new(), body));
        let ticker = advance_views(views);
        let (status, response) = submit.await.expect("submit task");
        ticker.abort();

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<TxStatus>(&response).expect("status json"),
            TxStatus::Finalized { height: 3 },
        );
        assert_eq!(bodies_a.lock().expect("bodies lock").len(), 1);
        assert_eq!(bodies_b.lock().expect("bodies lock").len(), 1);
    }

    #[tokio::test]
    async fn initial_leader_deterministic_rejection_is_returned() {
        let (router, bodies) = scripted_leader(vec![StatusCode::BAD_REQUEST], vec![None]);
        let leader = mock_leader("aa", spawn_mock_leader(router).await);
        let state = retry_state(vec![leader], 2);
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let (status, response) = submit_transactions(State(state), HeaderMap::new(), body).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(response.is_empty());
        assert_eq!(bodies.lock().expect("bodies lock").len(), 1);
    }

    #[tokio::test]
    async fn admitted_batch_is_not_reposted_after_leader_reports_drop() {
        let (router, bodies) = scripted_leader(
            Vec::new(),
            vec![Some(BatchStatus::Accepted), Some(BatchStatus::Dropped)],
        );
        let leader = mock_leader("aa", spawn_mock_leader(router).await);
        let state = retry_state(vec![leader], 2);
        let views = state.view_clock.current_view.clone();
        let body: Bytes = vec![signed_transfer(1, 0)].encode();

        let submit = tokio::spawn(submit_transactions(State(state), HeaderMap::new(), body));
        let ticker = advance_views(views);
        let (status, response) = submit.await.expect("submit task");
        ticker.abort();

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<TxStatus>(&response).expect("status json"),
            TxStatus::Dropped,
        );
        assert_eq!(bodies.lock().expect("bodies lock").len(), 1);
    }

    #[tokio::test]
    async fn unpinned_retry_resends_pending_subset_after_partial_finalization() {
        let first = signed_transfer(1, 0);
        let second = signed_transfer(2, 0);
        let partial = BatchStatus::PartiallyFinalized {
            height: 5,
            included: vec![first.message_digest().to_string()],
            filtered: vec![second.message_digest().to_string()],
        };
        let (router, bodies) = scripted_leader(Vec::new(), vec![Some(partial)]);
        let leader = mock_leader("aa", spawn_mock_leader(router).await);
        let state = retry_state(vec![leader], 1);
        let views = state.view_clock.current_view.clone();
        let body: Bytes = vec![first, second.clone()].encode();

        let submit = tokio::spawn(submit_transactions(State(state), HeaderMap::new(), body));
        let ticker = advance_views(views);
        let (status, response) = submit.await.expect("submit task");
        ticker.abort();

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<TxStatus>(&response).expect("status json"),
            TxStatus::PartiallyFinalized {
                height: 5,
                included: 1,
                filtered: 1,
            },
        );

        // The partial finalization builds the on-demand digest index, shrinks
        // the pending set, and round 1 re-POSTs only the pending subset under
        // a fresh batch id.
        let bodies = bodies.lock().expect("bodies lock");
        assert_eq!(bodies.len(), 2);
        assert_eq!(bodies[1], vec![second].encode());
    }

    /// A transaction the leader never reported filtered is still pending when
    /// the retry budget ends; it must not be counted as filtered.
    #[tokio::test]
    async fn unpinned_retry_budget_does_not_report_a_terminal_status_for_pending_work() {
        let first = signed_transfer(1, 0);
        let second = signed_transfer(2, 0);
        let partial = BatchStatus::PartiallyFinalized {
            height: 5,
            included: vec![first.message_digest().to_string()],
            filtered: Vec::new(),
        };
        let (router, _) = scripted_leader(Vec::new(), vec![Some(partial)]);
        let leader = mock_leader("aa", spawn_mock_leader(router).await);
        let state = retry_state(vec![leader], 1);
        let views = state.view_clock.current_view.clone();
        let body: Bytes = vec![first, second].encode();

        let submit = tokio::spawn(submit_transactions(State(state), HeaderMap::new(), body));
        let ticker = advance_views(views);
        let (status, response) = submit.await.expect("submit task");
        ticker.abort();

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.is_empty());
    }

    /// A leader that admits a batch but whose accept responses are all lost
    /// (transient POST failures) is still polled for status; a complete
    /// terminal outcome recovered there must surface instead of a 503.
    #[tokio::test]
    async fn unpinned_final_round_reports_polled_progress_when_accepts_lost() {
        let first = signed_transfer(1, 0);
        let second = signed_transfer(2, 0);
        let partial = BatchStatus::PartiallyFinalized {
            height: 5,
            included: vec![first.message_digest().to_string()],
            filtered: vec![second.message_digest().to_string()],
        };

        // Every POST "loses" its response (500 -> transient), while the
        // round-0 status poll reports the batch partially finalized.
        let (router, bodies) = scripted_leader(
            vec![
                StatusCode::INTERNAL_SERVER_ERROR,
                StatusCode::INTERNAL_SERVER_ERROR,
            ],
            vec![Some(partial)],
        );
        let leader = mock_leader("aa", spawn_mock_leader(router).await);
        let state = retry_state(vec![leader], 1);
        let views = state.view_clock.current_view.clone();
        let body: Bytes = vec![first, second].encode();

        let submit = tokio::spawn(submit_transactions(State(state), HeaderMap::new(), body));
        let ticker = advance_views(views);
        let (status, response) = submit.await.expect("submit task");
        ticker.abort();

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<TxStatus>(&response).expect("status json"),
            TxStatus::PartiallyFinalized {
                height: 5,
                included: 1,
                filtered: 1,
            },
        );
        assert_eq!(bodies.lock().expect("bodies lock").len(), 2);
    }
}
