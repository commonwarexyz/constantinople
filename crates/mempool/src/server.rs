//! HTTP mempool server and `TransactionSource` implementation.

use crate::{Finalized, PendingTransaction, SignedTransaction, TransactionSource};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::post,
};
use commonware_codec::{EncodeSize, ReadExt};
use commonware_consensus::{Reporter, simplex::types::Context};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_utils::{from_hex, hex};
use constantinople_primitives::Header;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Mutex, oneshot};
use tracing::warn;

fn decode_body_hex(body: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    from_hex(body.trim()).ok_or((StatusCode::BAD_REQUEST, "bad hex".to_string()))
}

/// Inclusion confirmation returned to HTTP callers.
#[derive(Debug, serde::Serialize)]
pub struct InclusionReceipt {
    pub tx_hash: String,
    pub included: bool,
    pub height: u64,
}

/// Immediate submission confirmation returned to HTTP callers.
#[derive(Debug, serde::Serialize)]
pub struct SubmissionReceipt {
    pub tx_hash: String,
}

/// Mempool size limits.
#[derive(Debug, Clone, Copy)]
pub struct MempoolConfig {
    /// Maximum bytes of transactions to return in a single `propose()` call.
    pub max_propose_bytes: usize,
    /// Maximum bytes of pending transactions before rejecting new submissions.
    pub max_pool_bytes: usize,
}

/// Shared mempool state between HTTP handlers and the TransactionSource.
struct MempoolInner<H: Hasher, P: PublicKey> {
    pending: VecDeque<PendingTransaction<P, H>>,
    pending_bytes: usize,
    waiters: HashMap<Vec<u8>, oneshot::Sender<InclusionReceipt>>,
}

/// HTTP mempool that implements `TransactionSource`.
pub struct Mempool<C, P, H>
where
    H: Hasher,
    P: PublicKey,
{
    inner: Arc<Mutex<MempoolInner<H, P>>>,
    config: MempoolConfig,
    transaction_namespace: &'static [u8],
    _marker: std::marker::PhantomData<C>,
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
            _marker: std::marker::PhantomData,
        }
    }
}

impl<C, P, H> Mempool<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    pub fn new(transaction_namespace: &'static [u8], config: MempoolConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MempoolInner {
                pending: VecDeque::new(),
                pending_bytes: 0,
                waiters: HashMap::new(),
            })),
            config,
            transaction_namespace,
            _marker: std::marker::PhantomData,
        }
    }

    /// Notifies waiters that their transactions were included in a block.
    pub async fn notify_included(&self, height: u64, transaction_hashes: &[H::Digest]) {
        let mut inner = self.inner.lock().await;
        for hash in transaction_hashes {
            let hash = hash.as_ref().to_vec();
            if let Some(sender) = inner.waiters.remove(&hash) {
                let _ = sender.send(InclusionReceipt {
                    tx_hash: hex(&hash),
                    included: true,
                    height,
                });
            }
        }
    }

    /// Notifies waiters that their transactions were rejected.
    pub async fn notify_rejected(&self, rejected_hashes: &[H::Digest]) {
        let mut inner = self.inner.lock().await;
        for hash in rejected_hashes {
            let hash_bytes = hash.as_ref().to_vec();
            if let Some(sender) = inner.waiters.remove(&hash_bytes) {
                let _ = sender.send(InclusionReceipt {
                    tx_hash: hex(&hash_bytes),
                    included: false,
                    height: 0,
                });
            }
        }
    }
}

impl<C, P, H> Reporter for Mempool<C, P, H>
where
    C: Digest + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    H: Hasher + Send + Sync + 'static,
{
    type Activity = Finalized<C, P, H>;

    async fn report(&mut self, finalized: Self::Activity) {
        let height = finalized.block.header.height;
        let mut inner = self.inner.lock().await;

        for tx in &finalized.block.body {
            let hash = tx.message_digest().as_ref().to_vec();
            if let Some(sender) = inner.waiters.remove(&hash) {
                let _ = sender.send(InclusionReceipt {
                    tx_hash: hex(&hash),
                    included: true,
                    height,
                });
            }
        }
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
        async move {
            let mut guard = inner.lock().await;
            let mut batch = Vec::new();
            let mut batch_bytes = 0;
            while let Some(tx) = guard.pending.front() {
                let tx_bytes = tx.encode_size();
                if batch_bytes + tx_bytes > max_bytes && !batch.is_empty() {
                    break;
                }
                let tx = guard.pending.pop_front().unwrap();
                guard.pending_bytes -= tx.encode_size();
                batch_bytes += tx_bytes;
                batch.push(tx);
            }
            batch
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
    let (hash, _tx_hash_hex, receiver) = enqueue_transaction(&state, tx, true).await?;

    match tokio::time::timeout(Duration::from_secs(30), receiver).await {
        Ok(Ok(receipt)) => Ok(Json(receipt)),
        Ok(Err(_)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "waiter dropped".to_string(),
        )),
        Err(_) => {
            let mut inner = state.inner.lock().await;
            inner.waiters.remove(&hash);
            Err((StatusCode::REQUEST_TIMEOUT, "inclusion timeout".to_string()))
        }
    }
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
    let (_hash, tx_hash_hex, _) = enqueue_transaction(&state, tx, false).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(SubmissionReceipt {
            tx_hash: tx_hash_hex,
        }),
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
    let tx = SignedTransaction::<P, H>::read(&mut &bytes[..])
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad transaction: {e}")))?;

    tx.into_verified(state.namespace)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid signature".to_string()))
}

async fn enqueue_transaction<C, P, H>(
    state: &RouterState<C, P, H>,
    tx: PendingTransaction<P, H>,
    wait_for_inclusion: bool,
) -> Result<(Vec<u8>, String, oneshot::Receiver<InclusionReceipt>), (StatusCode, String)>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let tx_bytes = tx.encode_size();
    let hash = tx.message_digest().as_ref().to_vec();
    let tx_hash_hex = hex(&hash);
    let (sender, receiver) = oneshot::channel();

    {
        let mut inner = state.inner.lock().await;
        if inner.pending_bytes + tx_bytes > state.max_pool_bytes {
            warn!(tx_hash = %tx_hash_hex, "mempool full, rejecting transaction");
            return Err((StatusCode::SERVICE_UNAVAILABLE, "mempool full".to_string()));
        }

        inner.pending_bytes += tx_bytes;
        if wait_for_inclusion {
            inner.waiters.insert(hash.clone(), sender);
        }
        inner.pending.push_back(tx);
    }
    Ok((hash, tx_hash_hex, receiver))
}

struct RouterState<C, P, H>
where
    H: Hasher,
    P: PublicKey,
{
    inner: Arc<Mutex<MempoolInner<H, P>>>,
    namespace: &'static [u8],
    max_pool_bytes: usize,
    _marker: std::marker::PhantomData<C>,
}

/// Creates the axum router for the mempool HTTP API.
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
        _marker: std::marker::PhantomData::<C>,
    });

    Router::new()
        .route("/tx", post(submit_tx::<C, P, H>))
        .route("/tx/accept", post(accept_tx::<C, P, H>))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::{MempoolConfig, MempoolInner, RouterState, SubmissionReceipt, accept_tx, router};
    use axum::{
        Json,
        body::Body,
        extract::State,
        http::{Request, StatusCode},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{Digest, Signer, blake3, ed25519};
    use commonware_utils::hex;
    use constantinople_primitives::{Address, Transaction};
    use core::{marker::PhantomData, num::NonZeroU64};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    const NAMESPACE: &[u8] = b"mempool-test";

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

    #[tokio::test]
    async fn accept_tx_enqueues_without_registering_waiter() {
        let state = Arc::new(
            RouterState::<blake3::Digest, ed25519::PublicKey, blake3::Blake3> {
                inner: Arc::new(Mutex::new(MempoolInner {
                    pending: Default::default(),
                    pending_bytes: 0,
                    waiters: Default::default(),
                })),
                namespace: NAMESPACE,
                max_pool_bytes: 1024 * 1024,
                _marker: PhantomData,
            },
        );
        let body = hex(&signed_bytes(0));

        let result = accept_tx::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>(
            State(state.clone()),
            body,
        )
        .await;

        let (status, Json(SubmissionReceipt { tx_hash })) = result.expect("accept should succeed");
        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(!tx_hash.is_empty());

        let inner = state.inner.lock().await;
        assert_eq!(inner.pending.len(), 1);
        assert!(inner.waiters.is_empty());
    }

    #[tokio::test]
    async fn accept_route_returns_immediately() {
        let mempool = super::Mempool::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>::new(
            NAMESPACE,
            MempoolConfig {
                max_propose_bytes: 1024 * 1024,
                max_pool_bytes: 1024 * 1024,
            },
        );
        let app = router(&mempool);
        let request = Request::post("/tx/accept")
            .body(Body::from(hex(&signed_bytes(0))))
            .expect("request should build");

        use tower::ServiceExt;

        let response = app
            .oneshot(request)
            .await
            .expect("accept route should respond");

        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }
}
