//! Mempool webserver actor.
//!
//! Owns a byte-bounded FIFO pool of verified transactions. Receives
//! submissions from HTTP handlers and serves batches to the consensus
//! layer via the [`Mailbox`](super::Mailbox).

use super::{Mailbox, http, mailbox::Message};
use commonware_consensus::marshal::Update;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_runtime::{ContextCell, Handle, Metrics, Spawner, spawn_cell};
use commonware_utils::{Acknowledgement, channel::fallible::OneshotExt};
use constantinople_primitives::VerifiedTransaction;
use std::{collections::VecDeque, sync::Arc};
use tokio::sync::mpsc;
use tracing::warn;

/// Mempool actor configuration.
pub struct Config {
    /// Maximum total bytes the pool will hold.
    pub max_pool_bytes: usize,
    /// Maximum bytes returned in a single `propose` call.
    pub max_propose_bytes: usize,
    /// Bounded channel capacity for the actor mailbox.
    pub mailbox_size: usize,
    /// Transaction signing namespace used for signature verification.
    pub namespace: &'static [u8],
}

/// The mempool actor.
///
/// Create via [`Actor::new`], which returns `(Actor, Mailbox)`. Call
/// [`Actor::start`] to spawn the event loop and HTTP server on the runtime.
pub struct Actor<E, C, P, H>
where
    E: Spawner,
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    context: ContextCell<E>,
    mailbox: Mailbox<C, P, H>,
    rx: mpsc::Receiver<Message<C, P, H>>,
    pool: VecDeque<(VerifiedTransaction<P, H>, usize)>,
    pool_bytes: usize,
    max_pool_bytes: usize,
    max_propose_bytes: usize,
    namespace: &'static [u8],
}

impl<E, C, P, H> Actor<E, C, P, H>
where
    E: Spawner + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    /// Creates a new mempool actor and its control [`Mailbox`].
    pub fn new(context: E, config: Config) -> (Self, Mailbox<C, P, H>) {
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
            },
            mailbox,
        )
    }

    /// Spawns the actor event loop and HTTP server on the runtime.
    pub fn start(mut self, listener: tokio::net::TcpListener) -> Handle<()> {
        spawn_cell!(self.context, self.run(listener).await)
    }

    async fn run(self, listener: tokio::net::TcpListener) {
        let Self {
            context,
            mailbox,
            mut rx,
            mut pool,
            mut pool_bytes,
            max_pool_bytes,
            max_propose_bytes,
            namespace,
        } = self;

        let app_state = Arc::new(http::AppState {
            mailbox,
            namespace,
        });
        let app = http::router(app_state);
        let _http_handle = context.as_present().with_label("http").spawn(|_| async {
            let _ = axum::serve(listener, app).await;
        });

        while let Some(message) = rx.recv().await {
            match message {
                Message::Submit { transaction, size } => {
                    if pool_bytes + size <= max_pool_bytes {
                        pool_bytes += size;
                        pool.push_back((transaction, size));
                    }
                }
                Message::Propose { response } => {
                    let mut batch = Vec::new();
                    let mut batch_bytes = 0;
                    while let Some((_, size)) = pool.front() {
                        if batch_bytes + size > max_propose_bytes && !batch.is_empty() {
                            break;
                        }
                        let (tx, size) = pool.pop_front().expect("front was Some");
                        batch_bytes += size;
                        pool_bytes -= size;
                        batch.push(tx);
                    }
                    response.send_lossy(batch);
                }
                Message::Report(Update::Tip(..)) => {}
                Message::Report(Update::Block(_, acknowledgement)) => {
                    acknowledgement.acknowledge();
                }
            }
        }
        warn!("mempool actor stopped: all senders dropped");
    }
}
