//! HTTP mempool server and `TransactionSource` implementation.

use crate::{Finalized, PendingTransaction, SignedTransaction, TransactionSource};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::post,
};
use commonware_codec::{EncodeSize, Read};
use commonware_consensus::{Reporter, simplex::types::Context};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_utils::{from_hex, hex};
use constantinople_primitives::{Header, Receipt, TransactionCfg};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Mutex, oneshot};
use tracing::{info, warn};

fn decode_body_hex(body: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    from_hex(body.trim()).ok_or((StatusCode::BAD_REQUEST, "bad hex".to_string()))
}

/// Inclusion confirmation returned to HTTP callers.
#[derive(Debug, serde::Serialize)]
pub struct InclusionReceipt {
    pub tx_hash: String,
    pub included: bool,
    pub height: u64,
    pub status: String,
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

    /// Notifies waiters that their transactions were included in a finalized block.
    pub async fn notify_included(&self, height: u64, receipts: &[Receipt<H::Digest>]) {
        let mut inner = self.inner.lock().await;
        for receipt in receipts {
            let hash = receipt.transaction_hash.as_ref().to_vec();
            if let Some(sender) = inner.waiters.remove(&hash) {
                let _ = sender.send(InclusionReceipt {
                    tx_hash: hex(&hash),
                    included: true,
                    height,
                    status: format!("{:?}", receipt.status),
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
                    status: "Rejected".to_string(),
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

        for (tx, receipt) in finalized.block.body.iter().zip(&finalized.receipts) {
            let hash = tx.message_digest().as_ref().to_vec();
            if let Some(sender) = inner.waiters.remove(&hash) {
                let _ = sender.send(InclusionReceipt {
                    tx_hash: hex(&hash),
                    included: true,
                    height,
                    status: format!("{:?}", receipt.status),
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
    let bytes = decode_body_hex(&body)?;

    let tx = SignedTransaction::<P, H>::read_cfg(&mut &bytes[..], &TransactionCfg::default())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad transaction: {e}")))?;
    let tx = tx
        .into_verified(state.namespace)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid signature".to_string()))?;

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
        inner.waiters.insert(hash.clone(), sender);
        inner.pending.push_back(tx);
    }

    info!(tx_hash = %tx_hash_hex, "accepted transaction");

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
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(state)
}
