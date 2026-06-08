//! Mailbox for the mempool webserver actor.

use super::actor::{BatchStatus, IngestStatus, TxStatus};
use crate::TransactionSource;
use commonware_actor::Feedback;
use commonware_consensus::{Reporter, marshal::Update, simplex::types::Context};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_utils::channel::fallible::AsyncFallibleExt;
use constantinople_primitives::{Header, SealedBlock, VerifiedTransaction};
use std::time::Instant;
use tokio::sync::{
    mpsc::{self, error::TrySendError},
    oneshot,
};

/// Opaque receiver handle produced by [`Mailbox::channel`] and consumed by
/// [`Actor::new`](super::Actor::new).
pub struct ActorReceiver<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    pub(super) rx: mpsc::Receiver<Message<C, P, H>>,
}

pub(super) enum Message<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    /// A batch of verified transactions submitted by an HTTP handler.
    Submit {
        enqueued_at: Instant,
        batch_id: String,
        digests: Vec<H::Digest>,
        transactions: Vec<VerifiedTransaction<H>>,
        total_bytes: usize,
        result: Option<oneshot::Sender<TxStatus>>,
        ingest_result: Option<oneshot::Sender<IngestStatus>>,
    },
    /// HTTP asks for the latest known batch status.
    QueryStatus {
        batch_id: String,
        response: oneshot::Sender<Option<BatchStatus>>,
    },
    /// HTTP asks for the highest locally observed consensus round.
    QueryConsensusRound { response: oneshot::Sender<u64> },
    /// Consensus requests transactions for the next proposal.
    Propose {
        enqueued_at: Instant,
        height: u64,
        response: oneshot::Sender<Vec<VerifiedTransaction<H>>>,
    },
    /// Consensus reports a finalized or tip block.
    Report {
        enqueued_at: Instant,
        update: Update<SealedBlock<C, P, H>>,
    },
}

/// Handle to the mempool actor, used by HTTP handlers and the consensus layer.
pub struct Mailbox<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    sender: mpsc::Sender<Message<C, P, H>>,
}

impl<C, P, H> Clone for Mailbox<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<C, P, H> Mailbox<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    pub(super) const fn new(sender: mpsc::Sender<Message<C, P, H>>) -> Self {
        Self { sender }
    }

    /// Creates a new mailbox backed by a bounded channel of the given
    /// capacity, returning the mailbox handle and the receiver half.
    ///
    /// Use this when the mailbox needs to exist before the [`Actor`](super::Actor)
    /// is constructed (e.g. to hand it to consensus as a transaction source).
    pub fn channel(capacity: usize) -> (Self, ActorReceiver<C, P, H>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self::new(tx), ActorReceiver { rx })
    }

    /// Non-blocking batch submission for HTTP handlers.
    ///
    /// On success, returns a receiver that resolves with the batch outcome
    /// once its block is fully finalized, partially finalized, or dropped.
    /// Returns `None` if the channel is full.
    pub fn try_submit(
        &self,
        batch_id: String,
        digests: Vec<H::Digest>,
        transactions: Vec<VerifiedTransaction<H>>,
        total_bytes: usize,
    ) -> Option<oneshot::Receiver<TxStatus>> {
        let (result_tx, result_rx) = oneshot::channel();
        self.sender
            .try_send(Message::Submit {
                enqueued_at: Instant::now(),
                batch_id,
                digests,
                transactions,
                total_bytes,
                result: Some(result_tx),
                ingest_result: None,
            })
            .ok()
            .map(|()| result_rx)
    }

    /// Fast batch ingestion for relayers.
    ///
    /// Returns a receiver that resolves once the actor accepts or rejects the
    /// batch for proposal. Returns `None` if the channel is full.
    pub(super) fn try_ingest(
        &self,
        batch_id: String,
        digests: Vec<H::Digest>,
        transactions: Vec<VerifiedTransaction<H>>,
        total_bytes: usize,
    ) -> Option<oneshot::Receiver<IngestStatus>> {
        let (result_tx, result_rx) = oneshot::channel();
        self.sender
            .try_send(Message::Submit {
                enqueued_at: Instant::now(),
                batch_id,
                digests,
                transactions,
                total_bytes,
                result: None,
                ingest_result: Some(result_tx),
            })
            .ok()
            .map(|()| result_rx)
    }

    /// Returns the latest known status for a submitted batch.
    pub async fn query_status(&self, batch_id: String) -> Option<BatchStatus> {
        self.sender
            .request(|response| Message::QueryStatus { batch_id, response })
            .await
            .flatten()
    }

    /// Returns the highest finalized consensus round observed by this mempool.
    pub async fn query_consensus_round(&self) -> Option<u64> {
        self.sender
            .request(|response| Message::QueryConsensusRound { response })
            .await
    }
}

impl<C, P, H> TransactionSource<C, P, H> for Mailbox<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    async fn propose(
        &mut self,
        parent: &Header<C, H::Digest, P>,
        _context: &Context<C, P>,
    ) -> Vec<VerifiedTransaction<H>> {
        let height = parent.height + 1;
        self.sender
            .request(|response| Message::Propose {
                enqueued_at: Instant::now(),
                height,
                response,
            })
            .await
            .expect("mempool actor mailbox closed")
    }
}

impl<C, P, H> Reporter for Mailbox<C, P, H>
where
    C: Digest + Send + 'static,
    P: PublicKey + Send + 'static,
    H: Hasher + Send + 'static,
    H::Digest: Send,
{
    type Activity = Update<SealedBlock<C, P, H>>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let message = Message::Report {
            enqueued_at: Instant::now(),
            update: activity,
        };
        match self.sender.try_send(message) {
            Ok(()) => Feedback::Ok,
            Err(TrySendError::Full(message)) => {
                let sender = self.sender.clone();
                tokio::spawn(async move {
                    let _ = sender.send(message).await;
                });
                Feedback::Backoff
            }
            Err(TrySendError::Closed(_)) => Feedback::Closed,
        }
    }
}
