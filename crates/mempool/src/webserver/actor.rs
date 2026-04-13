//! Mempool webserver actor.
//!
//! Owns a byte-bounded FIFO pool of verified transactions. Receives
//! batch submissions from HTTP handlers and serves proposals to the
//! consensus layer via the [`Mailbox`](super::Mailbox).

use super::{Mailbox, http, mailbox::Message};
use commonware_consensus::marshal::Update;
use commonware_cryptography::{BatchVerifier, Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::{ContextCell, Handle, Metrics, Spawner, spawn_cell};
use commonware_utils::{Acknowledgement, channel::fallible::OneshotExt};
use constantinople_primitives::VerifiedTransaction;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashSet, VecDeque},
    hash::Hash,
    sync::Arc,
};
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

/// Outcome of a submitted batch, delivered when the result is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TxStatus {
    /// The batch's block was finalized.
    Finalized { height: u64 },
    /// The batch was proposed but its block was not finalized.
    Dropped,
}

/// Mempool actor configuration.
pub struct Config<St: Strategy> {
    /// Maximum total bytes the pool will hold.
    pub max_pool_bytes: usize,
    /// Maximum bytes returned in a single `propose` call, and the
    /// maximum accepted batch size for submissions.
    pub max_propose_bytes: usize,
    /// Bounded channel capacity for the actor mailbox.
    pub mailbox_size: usize,
    /// Transaction signing namespace used for signature verification.
    pub namespace: &'static [u8],
    /// Number of finalized blocks to wait before marking a proposed
    /// batch as [`TxStatus::Dropped`].
    pub drop_grace_blocks: u64,
    /// Parallel execution strategy for batch signature verification.
    pub strategy: St,
}

/// A batch of transactions waiting in the pool.
struct PoolEntry<P: PublicKey, H: Hasher> {
    transactions: Vec<VerifiedTransaction<P, H>>,
    total_bytes: usize,
    waiter: oneshot::Sender<TxStatus>,
}

/// A set of batches that were proposed together at a given height.
struct Proposed<H: Hasher> {
    height: u64,
    digests: HashSet<H::Digest>,
    waiters: Vec<oneshot::Sender<TxStatus>>,
}

/// The mempool actor.
///
/// Create via [`Actor::new`], which returns `(Actor, Mailbox)`. Call
/// [`Actor::start`] to spawn the event loop and HTTP server on the runtime.
pub struct Actor<E, C, P, H, St>
where
    E: Spawner,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    context: ContextCell<E>,
    mailbox: Mailbox<C, P, H>,
    rx: mpsc::Receiver<Message<C, P, H>>,
    pool: VecDeque<PoolEntry<P, H>>,
    pool_bytes: usize,
    max_pool_bytes: usize,
    max_propose_bytes: usize,
    namespace: &'static [u8],
    drop_grace_blocks: u64,
    strategy: St,
}

impl<E, C, P, H, St> Actor<E, C, P, H, St>
where
    E: Spawner + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    H::Digest: Hash,
    St: Strategy,
{
    /// Creates a new mempool actor and its control [`Mailbox`].
    pub fn new(context: E, config: Config<St>) -> (Self, Mailbox<C, P, H>) {
        let (tx, rx) = mpsc::channel(config.mailbox_size);
        let mailbox = Mailbox::new(tx);
        (
            Self {
                context: ContextCell::new(context),
                mailbox: mailbox.clone(),
                rx,
                pool: VecDeque::new(),
                pool_bytes: 0,
                max_pool_bytes: config.max_pool_bytes,
                max_propose_bytes: config.max_propose_bytes,
                namespace: config.namespace,
                drop_grace_blocks: config.drop_grace_blocks,
                strategy: config.strategy,
            },
            mailbox,
        )
    }

    /// Spawns the actor event loop and HTTP server on the runtime.
    ///
    /// The `BV` type parameter selects the batch signature verifier used
    /// by the HTTP handlers (e.g., `ed25519::Batch`).
    pub fn start<BV>(mut self, listener: tokio::net::TcpListener) -> Handle<()>
    where
        BV: BatchVerifier<PublicKey = P> + Send + Sync + 'static,
    {
        spawn_cell!(self.context, self.run::<BV>(listener).await)
    }

    async fn run<BV>(self, listener: tokio::net::TcpListener)
    where
        BV: BatchVerifier<PublicKey = P> + Send + Sync + 'static,
    {
        let Self {
            context,
            mailbox,
            mut rx,
            mut pool,
            mut pool_bytes,
            max_pool_bytes,
            max_propose_bytes,
            namespace,
            drop_grace_blocks,
            strategy,
        } = self;

        let app_state = Arc::new(http::AppState {
            mailbox,
            namespace,
            max_batch_bytes: max_propose_bytes,
            strategy,
        });
        let app = http::router::<C, P, H, BV, St>(app_state);
        let _http_handle = context.as_present().with_label("http").spawn(|_| async {
            let _ = axum::serve(listener, app).await;
        });

        let mut proposed: VecDeque<Proposed<H>> = VecDeque::new();

        while let Some(message) = rx.recv().await {
            match message {
                Message::Submit {
                    transactions,
                    total_bytes,
                    result,
                } => {
                    if pool_bytes + total_bytes <= max_pool_bytes {
                        pool_bytes += total_bytes;
                        pool.push_back(PoolEntry {
                            transactions,
                            total_bytes,
                            waiter: result,
                        });
                    } else {
                        let _ = result.send(TxStatus::Dropped);
                    }
                }
                Message::Propose { height, response } => {
                    let mut batch_txs = Vec::new();
                    let mut batch_bytes = 0;
                    let mut batch_digests = HashSet::new();
                    let mut batch_waiters = Vec::new();

                    while let Some(entry) = pool.front() {
                        if batch_bytes + entry.total_bytes > max_propose_bytes
                            && !batch_txs.is_empty()
                        {
                            break;
                        }
                        let entry = pool.pop_front().expect("front was Some");
                        pool_bytes -= entry.total_bytes;
                        batch_bytes += entry.total_bytes;
                        for tx in &entry.transactions {
                            batch_digests.insert(*tx.message_digest());
                        }
                        batch_txs.extend(entry.transactions);
                        batch_waiters.push(entry.waiter);
                    }

                    if !batch_waiters.is_empty() {
                        proposed.push_back(Proposed {
                            height,
                            digests: batch_digests,
                            waiters: batch_waiters,
                        });
                    }
                    response.send_lossy(batch_txs);
                }
                Message::Report(Update::Block(block, acknowledgement)) => {
                    let height = block.header.height;
                    let finalized: HashSet<H::Digest> =
                        block.body.iter().map(|tx| *tx.message_digest()).collect();

                    let mut remaining = VecDeque::new();
                    for mut batch in proposed.drain(..) {
                        if batch.digests.iter().any(|d| finalized.contains(d)) {
                            for waiter in batch.waiters.drain(..) {
                                let _ = waiter.send(TxStatus::Finalized { height });
                            }
                        } else if height >= batch.height + drop_grace_blocks {
                            for waiter in batch.waiters.drain(..) {
                                let _ = waiter.send(TxStatus::Dropped);
                            }
                        } else {
                            remaining.push_back(batch);
                        }
                    }
                    proposed = remaining;

                    acknowledgement.acknowledge();
                }
                Message::Report(Update::Tip(..)) => {}
            }
        }
        warn!("mempool actor stopped: all senders dropped");
    }
}
