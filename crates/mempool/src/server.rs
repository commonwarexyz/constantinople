//! HTTP mempool server and `TransactionSource` implementation.
//!
//! The HTTP layer stays intentionally small. The hot path is handled by a
//! synchronous FIFO core that supports binary batch ingestion, lease-based block
//! proposals, recent terminal status caching, and waiter registration for
//! long-poll style clients.

use crate::{
    PendingTransaction, SignedTransaction, TransactionSource,
    core::{AcceptError, FifoCore, ResolveNotification},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::post,
};
use commonware_codec::ReadExt;
use commonware_consensus::{Reporter, marshal::Update, simplex::types::Context};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_utils::{Acknowledgement, from_hex, hex};
use constantinople_primitives::Header;
use std::{
    marker::PhantomData,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::oneshot, time::Instant};

const MAX_HTTP_BODY_BYTES: usize = 64 * 1024 * 1024;
const WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_WAIT_BATCH_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_WAIT_BATCH_TIMEOUT: Duration = Duration::from_secs(25);

fn decode_body_hex(body: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    from_hex(body.trim()).ok_or((StatusCode::BAD_REQUEST, "bad hex".to_string()))
}

/// Inclusion confirmation for a submitted transaction.
///
/// This is returned by the legacy `/tx` route after the transaction reaches a
/// terminal outcome.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct InclusionReceipt {
    pub tx_hash: String,
    pub included: bool,
    pub height: u64,
}

/// Immediate confirmation for a submitted transaction.
///
/// This is returned by the single-transaction accept route as soon as the
/// transaction is known to the mempool.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SubmissionReceipt {
    pub tx_hash: String,
}

/// Immediate confirmation for a submitted transaction batch.
///
/// The hashes stay aligned with the request order, including duplicates.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SubmissionBatchReceipt {
    pub tx_hashes: Vec<String>,
}

/// Transaction states returned to HTTP clients.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    Pending,
    Included,
    Rejected,
    Unknown,
}

/// Status for a transaction hash.
///
/// Pending statuses represent transactions that are still queued or leased by a
/// proposal. Included and rejected statuses are terminal and come from recent
/// finalized history.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransactionStatus {
    pub tx_hash: String,
    pub state: TransactionState,
    pub height: u64,
}

/// Batch transaction status request body.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransactionStatusRequest {
    pub tx_hashes: Vec<String>,
}

/// Long-poll wait request body.
///
/// The server waits until every pending hash becomes terminal or the timeout is
/// reached. Unknown hashes return immediately.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct WaitBatchRequest {
    pub tx_hashes: Vec<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

/// Batch transaction status response body.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransactionStatusResponse {
    pub statuses: Vec<TransactionStatus>,
}

/// Mempool size limits.
#[derive(Debug, Clone, Copy)]
pub struct MempoolConfig {
    /// Maximum bytes of transactions to return in a single `propose()` call.
    pub max_propose_bytes: usize,
    /// Maximum bytes of pending transactions before rejecting new submissions.
    pub max_pool_bytes: usize,
    /// Reserved for future proposal pacing configuration.
    ///
    /// Proposed transactions currently remain in-flight until they are
    /// explicitly included or rejected.
    pub proposal_lease_duration: Duration,
}

/// FIFO HTTP mempool.
///
/// The mempool exposes a narrow consensus-facing `TransactionSource` interface
/// while serving both legacy single-transaction routes and high-throughput batch
/// HTTP endpoints.
pub struct Mempool<C, P, H>
where
    H: Hasher,
    P: PublicKey,
{
    inner: Arc<Mutex<FifoCore<H, P>>>,
    config: MempoolConfig,
    transaction_namespace: &'static [u8],
    _marker: PhantomData<C>,
}

impl<C, P, H> Clone for Mempool<C, P, H>
where
    H: Hasher,
    P: PublicKey,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            config: self.config,
            transaction_namespace: self.transaction_namespace,
            _marker: PhantomData,
        }
    }
}

impl<C, P, H> Mempool<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    /// Creates a mempool.
    ///
    /// The returned mempool shares a single FIFO core between HTTP handlers and
    /// consensus proposal/finalize callbacks.
    pub fn new(transaction_namespace: &'static [u8], config: MempoolConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(FifoCore::new())),
            config,
            transaction_namespace,
            _marker: PhantomData,
        }
    }

    /// Records included transactions and wakes any waiters.
    pub fn notify_included(&self, height: u64, transaction_hashes: &[H::Digest]) {
        let notifications = {
            let mut core = lock_core(&self.inner);
            let now = Instant::now();
            transaction_hashes
                .iter()
                .map(|hash| {
                    core.resolve_included(
                        hash.as_ref().to_vec(),
                        InclusionReceipt {
                            tx_hash: hex(hash.as_ref()),
                            included: true,
                            height,
                        },
                        now,
                    )
                })
                .collect::<Vec<_>>()
        };
        send_notifications(notifications);
    }

    /// Records rejected transactions and wakes any waiters.
    pub fn notify_rejected(&self, rejected_hashes: &[H::Digest]) {
        let notifications = {
            let mut core = lock_core(&self.inner);
            let now = Instant::now();
            rejected_hashes
                .iter()
                .map(|hash| {
                    let hash_bytes = hash.as_ref().to_vec();
                    core.resolve_rejected(
                        hash_bytes.clone(),
                        InclusionReceipt {
                            tx_hash: hex(&hash_bytes),
                            included: false,
                            height: 0,
                        },
                        now,
                    )
                })
                .collect::<Vec<_>>()
        };
        send_notifications(notifications);
    }
}

impl<C, P, H> TransactionSource<C, P, H> for Mempool<C, P, H>
where
    C: Digest + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    H: Hasher + Send + Sync + 'static,
{
    fn propose(
        &mut self,
        _parent: &Header<C, H::Digest, P>,
        _context: &Context<C, P>,
    ) -> impl std::future::Future<Output = Vec<PendingTransaction<P, H>>> + Send {
        let inner = self.inner.clone();
        let max_bytes = self.config.max_propose_bytes;
        let proposal_lease_duration = self.config.proposal_lease_duration;

        async move {
            let mut core = lock_core(&inner);
            core.propose(max_bytes, proposal_lease_duration, Instant::now())
        }
    }
}

impl<C, P, H> Reporter for Mempool<C, P, H>
where
    C: Digest + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    H: Hasher + Send + Sync + 'static,
{
    type Activity = Update<crate::SealedBlock<C, P, H>>;

    async fn report(&mut self, activity: Self::Activity) {
        if let Update::Block(block, acknowledgement) = activity {
            let height = block.header.height;
            let transaction_hashes = block
                .body
                .iter()
                .map(|transaction| *transaction.message_digest())
                .collect::<Vec<_>>();
            self.notify_included(height, &transaction_hashes);
            acknowledgement.acknowledge();
        }
    }
}

async fn submit_tx<C, P, H>(
    State(state): State<Arc<RouterState<C, P, H>>>,
    body: String,
) -> Result<Json<InclusionReceipt>, (StatusCode, String)>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let tx = decode_transaction(&state, &body)?;
    let hash = tx.message_digest().as_ref().to_vec();
    let tx_hash = hex(&hash);
    let receiver = accept_single(&state, tx, true)?;

    if let Some(receiver) = receiver {
        return wait_for_receipt(receiver).await.map(Json);
    }

    terminal_receipt(&state, hash, tx_hash)
        .map(Json)
        .ok_or((StatusCode::REQUEST_TIMEOUT, "inclusion timeout".to_string()))
}

async fn accept_tx<C, P, H>(
    State(state): State<Arc<RouterState<C, P, H>>>,
    body: String,
) -> Result<(StatusCode, Json<SubmissionReceipt>), (StatusCode, String)>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let tx = decode_transaction(&state, &body)?;
    let tx_hash = accept_single_hash(&state, tx)?;
    Ok((StatusCode::ACCEPTED, Json(SubmissionReceipt { tx_hash })))
}

async fn accept_tx_batch<C, P, H>(
    State(state): State<Arc<RouterState<C, P, H>>>,
    body: Bytes,
) -> Result<(StatusCode, Json<SubmissionBatchReceipt>), (StatusCode, String)>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let transactions = decode_transaction_batch(&state, &body)?;
    let tx_hashes = accept_transactions(&state, transactions)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(SubmissionBatchReceipt { tx_hashes }),
    ))
}

fn decode_transaction<C, P, H>(
    state: &RouterState<C, P, H>,
    body: &str,
) -> Result<PendingTransaction<P, H>, (StatusCode, String)>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let bytes = decode_body_hex(body)?;
    let mut remaining = bytes.as_slice();
    let transaction = read_transaction(state, &mut remaining)?;
    if !remaining.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "expected exactly one transaction".to_string(),
        ));
    }

    Ok(transaction)
}

#[cfg(test)]
fn decode_transaction_bytes<C, P, H>(
    state: &RouterState<C, P, H>,
    bytes: &[u8],
) -> Result<PendingTransaction<P, H>, (StatusCode, String)>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let mut remaining = bytes;
    read_transaction(state, &mut remaining)
}

fn read_transaction<C, P, H>(
    state: &RouterState<C, P, H>,
    remaining: &mut &[u8],
) -> Result<PendingTransaction<P, H>, (StatusCode, String)>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let tx = SignedTransaction::<P, H>::read(remaining)
        .map_err(|err| (StatusCode::BAD_REQUEST, format!("bad transaction: {err}")))?;

    tx.into_verified(state.namespace)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid signature".to_string()))
}

fn decode_transaction_batch<C, P, H>(
    state: &RouterState<C, P, H>,
    body: &[u8],
) -> Result<Vec<PendingTransaction<P, H>>, (StatusCode, String)>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let mut remaining = body;
    let mut transactions = Vec::new();

    while !remaining.is_empty() {
        transactions.push(read_transaction(state, &mut remaining)?);
    }

    Ok(transactions)
}

fn decode_transaction_hash(hash: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    decode_body_hex(hash).map_err(|_| (StatusCode::BAD_REQUEST, "bad tx_hash".to_string()))
}

fn accept_single<C, P, H>(
    state: &RouterState<C, P, H>,
    tx: PendingTransaction<P, H>,
    wait_for_terminal: bool,
) -> Result<Option<oneshot::Receiver<InclusionReceipt>>, (StatusCode, String)>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let hash = tx.message_digest().as_ref().to_vec();
    let mut core = lock_core(&state.inner);
    map_accept_error(core.accept_many(vec![tx], state.max_pool_bytes, Instant::now()))?;
    Ok(wait_for_terminal
        .then(|| core.register_waiter(&hash))
        .flatten())
}

fn accept_single_hash<C, P, H>(
    state: &RouterState<C, P, H>,
    tx: PendingTransaction<P, H>,
) -> Result<String, (StatusCode, String)>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let tx_hashes = accept_transactions(state, vec![tx])?;
    Ok(tx_hashes
        .into_iter()
        .next()
        .expect("single transaction accept should return one hash"))
}

fn accept_transactions<C, P, H>(
    state: &RouterState<C, P, H>,
    transactions: Vec<PendingTransaction<P, H>>,
) -> Result<Vec<String>, (StatusCode, String)>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let mut core = lock_core(&state.inner);
    map_accept_error(core.accept_many(transactions, state.max_pool_bytes, Instant::now()))
}

async fn transaction_status<C, P, H>(
    State(state): State<Arc<RouterState<C, P, H>>>,
    Json(request): Json<TransactionStatusRequest>,
) -> Result<Json<TransactionStatusResponse>, (StatusCode, String)>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let requested_hashes = decode_requested_hashes(&request.tx_hashes)?;
    let statuses = {
        let mut core = lock_core(&state.inner);
        core.status_many(&requested_hashes, &request.tx_hashes, Instant::now())
    };

    Ok(Json(TransactionStatusResponse { statuses }))
}

async fn wait_batch<C, P, H>(
    State(state): State<Arc<RouterState<C, P, H>>>,
    Json(request): Json<WaitBatchRequest>,
) -> Result<Json<TransactionStatusResponse>, (StatusCode, String)>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let requested_hashes = decode_requested_hashes(&request.tx_hashes)?;
    if request.tx_hashes.is_empty() {
        return Ok(Json(TransactionStatusResponse {
            statuses: Vec::new(),
        }));
    }

    let timeout = wait_batch_timeout(request.timeout_ms);
    let initial = {
        let mut core = lock_core(&state.inner);
        let statuses = core.status_many(&requested_hashes, &request.tx_hashes, Instant::now());
        if should_return_wait_statuses(&statuses, timeout) {
            return Ok(Json(TransactionStatusResponse { statuses }));
        }

        core.register_waiters(&requested_hashes)
    };

    let _ = tokio::time::timeout(timeout, wait_for_receivers(initial)).await;
    let statuses = {
        let mut core = lock_core(&state.inner);
        core.status_many(&requested_hashes, &request.tx_hashes, Instant::now())
    };

    Ok(Json(TransactionStatusResponse { statuses }))
}

fn decode_requested_hashes(tx_hashes: &[String]) -> Result<Vec<Vec<u8>>, (StatusCode, String)> {
    tx_hashes
        .iter()
        .map(|hash| decode_transaction_hash(hash))
        .collect()
}

fn terminal_receipt<C, P, H>(
    state: &RouterState<C, P, H>,
    hash: Vec<u8>,
    tx_hash: String,
) -> Option<InclusionReceipt>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let mut core = lock_core(&state.inner);
    let statuses = core.status_many(&[hash], &[tx_hash], Instant::now());
    status_to_receipt(statuses.into_iter().next()?)
}

fn status_to_receipt(status: TransactionStatus) -> Option<InclusionReceipt> {
    match status.state {
        TransactionState::Included => Some(InclusionReceipt {
            tx_hash: status.tx_hash,
            included: true,
            height: status.height,
        }),
        TransactionState::Rejected => Some(InclusionReceipt {
            tx_hash: status.tx_hash,
            included: false,
            height: status.height,
        }),
        TransactionState::Pending | TransactionState::Unknown => None,
    }
}

fn should_return_wait_statuses(statuses: &[TransactionStatus], timeout: Duration) -> bool {
    timeout.is_zero()
        || statuses.iter().all(is_terminal_status)
        || statuses.iter().any(is_unknown_status)
}

const fn is_terminal_status(status: &TransactionStatus) -> bool {
    matches!(
        status.state,
        TransactionState::Included | TransactionState::Rejected
    )
}

fn is_unknown_status(status: &TransactionStatus) -> bool {
    status.state == TransactionState::Unknown
}

fn wait_batch_timeout(timeout_ms: Option<u64>) -> Duration {
    timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_WAIT_BATCH_TIMEOUT)
        .min(MAX_WAIT_BATCH_TIMEOUT)
}

async fn wait_for_receipt(
    receiver: oneshot::Receiver<InclusionReceipt>,
) -> Result<InclusionReceipt, (StatusCode, String)> {
    match tokio::time::timeout(WAIT_TIMEOUT, receiver).await {
        Ok(Ok(receipt)) => Ok(receipt),
        Ok(Err(_)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "waiter dropped".to_string(),
        )),
        Err(_) => Err((StatusCode::REQUEST_TIMEOUT, "inclusion timeout".to_string())),
    }
}

async fn wait_for_receivers(receivers: Vec<oneshot::Receiver<InclusionReceipt>>) {
    for receiver in receivers {
        let _ = receiver.await;
    }
}

fn map_accept_error<T>(result: Result<T, AcceptError>) -> Result<T, (StatusCode, String)> {
    result.map_err(|err| match err {
        AcceptError::MempoolFull => (StatusCode::SERVICE_UNAVAILABLE, "mempool full".to_string()),
    })
}

fn send_notifications(notifications: Vec<ResolveNotification>) {
    for notification in notifications {
        for waiter in notification.waiters {
            let _ = waiter.send(notification.receipt.clone());
        }
    }
}

fn lock_core<H: Hasher, P: PublicKey>(
    inner: &Arc<Mutex<FifoCore<H, P>>>,
) -> std::sync::MutexGuard<'_, FifoCore<H, P>> {
    inner.lock().expect("mempool core mutex poisoned")
}

struct RouterState<C, P, H>
where
    H: Hasher,
    P: PublicKey,
{
    inner: Arc<Mutex<FifoCore<H, P>>>,
    namespace: &'static [u8],
    max_pool_bytes: usize,
    _marker: PhantomData<C>,
}

/// Creates the axum router for the mempool HTTP API.
///
/// The router exposes legacy single-transaction routes along with the high
/// throughput `/tx/accept_batch` and `/tx/wait_batch` endpoints.
pub fn router<C, P, H>(mempool: &Mempool<C, P, H>) -> Router
where
    C: Digest + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    H: Hasher + Send + Sync + 'static,
{
    let state = Arc::new(RouterState {
        inner: mempool.inner.clone(),
        namespace: mempool.transaction_namespace,
        max_pool_bytes: mempool.config.max_pool_bytes,
        _marker: PhantomData::<C>,
    });

    Router::new()
        .route("/tx", post(submit_tx::<C, P, H>))
        .route("/tx/accept", post(accept_tx::<C, P, H>))
        .route("/tx/accept_batch", post(accept_tx_batch::<C, P, H>))
        .route("/tx/status", post(transaction_status::<C, P, H>))
        .route("/tx/wait_batch", post(wait_batch::<C, P, H>))
        .layer(DefaultBodyLimit::max(MAX_HTTP_BODY_BYTES))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::{
        Mempool, MempoolConfig, RouterState, SubmissionBatchReceipt, SubmissionReceipt,
        TransactionState, TransactionStatusRequest, TransactionStatusResponse, WaitBatchRequest,
        accept_tx, router,
    };
    use crate::{
        TransactionSource,
        core::{AcceptError, FifoCore},
    };
    use axum::{
        Json,
        body::Body,
        extract::State,
        http::{Request, StatusCode},
    };
    use commonware_codec::{Encode, EncodeSize};
    use commonware_consensus::{
        simplex::types::Context,
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{Digest, Signer, blake3, ed25519};
    use commonware_utils::hex;
    use constantinople_primitives::{Address, Header, Transaction};
    use core::{marker::PhantomData, num::NonZeroU64};
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tokio::time::Instant;

    const NAMESPACE: &[u8] = b"mempool-test";

    fn test_context() -> Context<blake3::Digest, ed25519::PublicKey> {
        Context {
            round: Round::new(Epoch::zero(), View::zero()),
            leader: ed25519::PrivateKey::from_seed(13).public_key(),
            parent: (View::zero(), blake3::Digest::EMPTY),
        }
    }

    fn test_parent() -> Header<blake3::Digest, blake3::Digest, ed25519::PublicKey> {
        Header {
            context: test_context(),
            parent: blake3::Digest::EMPTY,
            height: 0,
            timestamp: 0,
            state_root: blake3::Digest::EMPTY,
            state_range: commonware_utils::non_empty_range!(0, 1),
            transactions_root: blake3::Digest::EMPTY,
            transactions_range: commonware_utils::non_empty_range!(0, 1),
        }
    }

    fn test_state(
        max_pool_bytes: usize,
    ) -> Arc<RouterState<blake3::Digest, ed25519::PublicKey, blake3::Blake3>> {
        Arc::new(RouterState {
            inner: Arc::new(Mutex::new(FifoCore::new())),
            namespace: NAMESPACE,
            max_pool_bytes,
            _marker: PhantomData,
        })
    }

    fn signed_bytes(nonce: u64) -> Vec<u8> {
        let key = ed25519::PrivateKey::from_seed(7);
        Transaction {
            sender: key.public_key(),
            to: Address::EMPTY,
            value: NonZeroU64::new(1).expect("test value should be non-zero"),
            nonce,
            _digest: PhantomData::<blake3::Digest>,
        }
        .seal_and_sign_verified(&key, NAMESPACE, &mut blake3::Blake3::default())
        .encode()
        .to_vec()
    }

    fn decode_transaction(
        bytes: &[u8],
    ) -> crate::PendingTransaction<ed25519::PublicKey, blake3::Blake3> {
        super::decode_transaction_bytes(
            &RouterState {
                inner: Arc::new(Mutex::new(FifoCore::new())),
                namespace: NAMESPACE,
                max_pool_bytes: usize::MAX,
                _marker: PhantomData::<blake3::Digest>,
            },
            bytes,
        )
        .expect("transaction should decode")
    }

    fn encode_batch(batches: &[Vec<u8>]) -> Vec<u8> {
        let total = batches.iter().map(Vec::len).sum();
        let mut encoded = Vec::with_capacity(total);
        for batch in batches {
            encoded.extend_from_slice(batch);
        }
        encoded
    }

    #[tokio::test]
    async fn accept_tx_enqueues_without_registering_waiter() {
        let state = test_state(1024 * 1024);
        let body = hex(&signed_bytes(0));

        let result = accept_tx::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>(
            State(state.clone()),
            body,
        )
        .await;

        let (status, Json(SubmissionReceipt { tx_hash })) = result.expect("accept should succeed");
        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(!tx_hash.is_empty());

        let statuses = {
            let mut core = state.inner.lock().expect("mempool lock should succeed");
            core.status_many(
                &[decode_transaction_hash(&tx_hash).unwrap()],
                &[tx_hash],
                Instant::now(),
            )
        };
        assert_eq!(statuses[0].state, TransactionState::Pending);
    }

    #[test]
    fn duplicate_accept_is_idempotent_even_when_pool_is_full() {
        let mut core = FifoCore::<blake3::Blake3, ed25519::PublicKey>::new();
        let tx0 = decode_transaction(&signed_bytes(0));
        let tx1 = decode_transaction(&signed_bytes(1));
        let max_pool_bytes = tx0.encode_size();

        let first = core.accept_many(vec![tx0.clone()], max_pool_bytes, Instant::now());
        let duplicate = core.accept_many(vec![tx0], max_pool_bytes, Instant::now());
        let different = core.accept_many(vec![tx1], max_pool_bytes, Instant::now());

        assert!(first.is_ok());
        assert!(duplicate.is_ok());
        assert_eq!(different, Err(AcceptError::MempoolFull));
    }

    #[test]
    fn expired_inflight_batch_is_reproposed_before_new_ready_transactions() {
        let mut core = FifoCore::<blake3::Blake3, ed25519::PublicKey>::new();
        let tx0 = decode_transaction(&signed_bytes(0));
        let tx1 = decode_transaction(&signed_bytes(1));
        let tx2 = decode_transaction(&signed_bytes(2));
        let tx_bytes = tx0.encode_size();
        let now = Instant::now();

        core.accept_many(vec![tx0, tx1, tx2], usize::MAX, now)
            .expect("accept should succeed");
        let first = core.propose(tx_bytes * 2, Duration::from_millis(10), now);
        let second = core.propose(tx_bytes * 2, Duration::from_millis(10), now);
        let reproposed = core.propose(
            tx_bytes * 2,
            Duration::from_millis(10),
            now + Duration::from_millis(11),
        );

        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 1);
        assert_eq!(reproposed.len(), 2);
        assert_eq!(first[0].message_digest(), reproposed[0].message_digest());
        assert_eq!(first[1].message_digest(), reproposed[1].message_digest());
    }

    #[tokio::test]
    async fn accept_batch_route_accepts_raw_bytes() {
        let mempool = Mempool::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>::new(
            NAMESPACE,
            MempoolConfig {
                max_propose_bytes: 1024 * 1024,
                max_pool_bytes: 1024 * 1024,
                proposal_lease_duration: Duration::from_secs(1),
            },
        );
        let app = router(&mempool);
        let request = Request::post("/tx/accept_batch")
            .body(Body::from(encode_batch(&[
                signed_bytes(0),
                signed_bytes(1),
            ])))
            .expect("request should build");

        use tower::ServiceExt;

        let response = app
            .oneshot(request)
            .await
            .expect("accept batch route should respond");

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should decode");
        let SubmissionBatchReceipt { tx_hashes } =
            serde_json::from_slice(&body).expect("batch receipt should deserialize");
        assert_eq!(tx_hashes.len(), 2);
    }

    #[tokio::test]
    async fn wait_batch_route_blocks_until_transactions_become_terminal() {
        let mempool = Mempool::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>::new(
            NAMESPACE,
            MempoolConfig {
                max_propose_bytes: 1024 * 1024,
                max_pool_bytes: 1024 * 1024,
                proposal_lease_duration: Duration::from_secs(1),
            },
        );
        let digest = *decode_transaction(&signed_bytes(0)).message_digest();
        let tx_hashes = {
            let mut core = mempool.inner.lock().expect("mempool lock should succeed");
            core.accept_many(
                vec![decode_transaction(&signed_bytes(0))],
                1024 * 1024,
                Instant::now(),
            )
            .expect("accept should succeed")
        };

        let app = router(&mempool);
        let request = Request::post("/tx/wait_batch")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&WaitBatchRequest {
                    tx_hashes: tx_hashes.clone(),
                    timeout_ms: Some(1_000),
                })
                .expect("wait request should serialize"),
            ))
            .expect("wait request should build");

        use tower::ServiceExt;

        let wait_task = tokio::spawn(app.clone().oneshot(request));
        tokio::time::sleep(Duration::from_millis(20)).await;
        mempool.notify_included(7, &[digest]);

        let response = wait_task
            .await
            .expect("wait task should join")
            .expect("wait route should respond");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should decode");
        let TransactionStatusResponse { statuses } =
            serde_json::from_slice(&body).expect("wait response should deserialize");

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].tx_hash, tx_hashes[0]);
        assert_eq!(statuses[0].state, TransactionState::Included);
        assert_eq!(statuses[0].height, 7);
    }

    #[tokio::test]
    async fn status_route_reports_pending_and_included_transactions() {
        let mempool = Mempool::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>::new(
            NAMESPACE,
            MempoolConfig {
                max_propose_bytes: 1024 * 1024,
                max_pool_bytes: 1024 * 1024,
                proposal_lease_duration: Duration::from_secs(1),
            },
        );
        let pending_digest = *decode_transaction(&signed_bytes(0)).message_digest();
        let included_digest = *decode_transaction(&signed_bytes(1)).message_digest();
        let pending_hash = hex(pending_digest.as_ref());
        let included_hash = hex(included_digest.as_ref());

        {
            let mut core = mempool.inner.lock().expect("mempool lock should succeed");
            core.accept_many(
                vec![decode_transaction(&signed_bytes(0))],
                1024 * 1024,
                Instant::now(),
            )
            .expect("accept should succeed");
        }
        mempool.notify_included(7, &[included_digest]);

        let app = router(&mempool);
        let request = Request::post("/tx/status")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&TransactionStatusRequest {
                    tx_hashes: vec![pending_hash.clone(), included_hash.clone()],
                })
                .expect("request should serialize"),
            ))
            .expect("request should build");

        use tower::ServiceExt;

        let response = app
            .oneshot(request)
            .await
            .expect("status route should respond");
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should decode");
        let TransactionStatusResponse { statuses } =
            serde_json::from_slice(&body).expect("response should deserialize");

        assert_eq!(statuses.len(), 2);
        assert_eq!(statuses[0].tx_hash, pending_hash);
        assert_eq!(statuses[0].state, TransactionState::Pending);
        assert_eq!(statuses[1].tx_hash, included_hash);
        assert_eq!(statuses[1].state, TransactionState::Included);
        assert_eq!(statuses[1].height, 7);
    }

    #[test]
    fn stale_rejected_callback_does_not_override_included_status() {
        let mempool = Mempool::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>::new(
            NAMESPACE,
            MempoolConfig {
                max_propose_bytes: 1024 * 1024,
                max_pool_bytes: 1024 * 1024,
                proposal_lease_duration: Duration::from_secs(1),
            },
        );
        let transaction = decode_transaction(&signed_bytes(0));
        let digest = *transaction.message_digest();
        let tx_hash = hex(digest.as_ref());

        {
            let mut core = mempool.inner.lock().expect("mempool lock should succeed");
            core.accept_many(vec![transaction], 1024 * 1024, Instant::now())
                .expect("accept should succeed");
        }

        mempool.notify_included(7, &[digest]);
        mempool.notify_rejected(&[digest]);

        let statuses = {
            let mut core = mempool.inner.lock().expect("mempool lock should succeed");
            core.status_many(
                &[decode_transaction_hash(&tx_hash).expect("tx hash should decode")],
                &[tx_hash],
                Instant::now(),
            )
        };

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, TransactionState::Included);
        assert_eq!(statuses[0].height, 7);
    }

    #[tokio::test]
    async fn propose_retries_the_same_inflight_batch_after_expiry() {
        let mut mempool = Mempool::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>::new(
            NAMESPACE,
            MempoolConfig {
                max_propose_bytes: 1024 * 1024,
                max_pool_bytes: 1024 * 1024,
                proposal_lease_duration: Duration::from_millis(10),
            },
        );
        {
            let mut core = mempool.inner.lock().expect("mempool lock should succeed");
            core.accept_many(
                vec![decode_transaction(&signed_bytes(0))],
                1024 * 1024,
                Instant::now(),
            )
            .expect("accept should succeed");
        }

        let first = mempool.propose(&test_parent(), &test_context()).await;
        let second = mempool.propose(&test_parent(), &test_context()).await;
        tokio::time::sleep(Duration::from_millis(15)).await;
        let third = mempool.propose(&test_parent(), &test_context()).await;

        assert_eq!(first.len(), 1);
        assert!(second.is_empty());
        assert_eq!(third.len(), 1);
        assert_eq!(first[0].message_digest(), third[0].message_digest());
    }

    #[tokio::test]
    async fn large_finalize_and_reject_batches_leave_recent_terminal_statuses() {
        let mut mempool = Mempool::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>::new(
            NAMESPACE,
            MempoolConfig {
                max_propose_bytes: usize::MAX,
                max_pool_bytes: usize::MAX,
                proposal_lease_duration: Duration::from_secs(1),
            },
        );
        let transactions = (0..2048)
            .map(|nonce| decode_transaction(&signed_bytes(nonce)))
            .collect::<Vec<_>>();
        let digests = transactions
            .iter()
            .map(|tx| *tx.message_digest())
            .collect::<Vec<_>>();
        {
            let mut core = mempool.inner.lock().expect("mempool lock should succeed");
            core.accept_many(transactions, usize::MAX, Instant::now())
                .expect("accept should succeed");
        }

        let proposed = mempool.propose(&test_parent(), &test_context()).await;
        assert_eq!(proposed.len(), 2048);

        mempool.notify_included(9, &digests[..1024]);
        mempool.notify_rejected(&digests[1024..]);

        let tx_hashes = digests
            .iter()
            .map(|digest| hex(digest.as_ref()))
            .collect::<Vec<_>>();
        let requested = tx_hashes
            .iter()
            .map(|tx_hash| super::decode_transaction_hash(tx_hash).unwrap())
            .collect::<Vec<_>>();
        let statuses = {
            let mut core = mempool.inner.lock().expect("mempool lock should succeed");
            core.status_many(&requested, &tx_hashes, Instant::now())
        };
        let included = statuses
            .iter()
            .filter(|status| status.state == TransactionState::Included)
            .count();
        let rejected = statuses
            .iter()
            .filter(|status| status.state == TransactionState::Rejected)
            .count();
        let next = mempool.propose(&test_parent(), &test_context()).await;

        assert_eq!(included, 1024);
        assert_eq!(rejected, 1024);
        assert!(next.is_empty());
    }

    fn decode_transaction_hash(hash: &str) -> Result<Vec<u8>, (StatusCode, String)> {
        super::decode_transaction_hash(hash)
    }
}
