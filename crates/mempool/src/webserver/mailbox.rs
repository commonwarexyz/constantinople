//! Mailbox for the mempool webserver actor.

use super::actor::TxStatus;
use crate::TransactionSource;
use commonware_consensus::{Reporter, marshal::Update, simplex::types::Context};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_utils::channel::fallible::AsyncFallibleExt;
use constantinople_primitives::{Header, SealedBlock, VerifiedTransaction};
use tokio::sync::{mpsc, oneshot};

pub(super) enum Message<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    /// A batch of verified transactions submitted by an HTTP handler.
    Submit {
        transactions: Vec<VerifiedTransaction<P, H>>,
        total_bytes: usize,
        result: oneshot::Sender<TxStatus>,
    },
    /// Consensus requests transactions for the next proposal.
    Propose {
        height: u64,
        response: oneshot::Sender<Vec<VerifiedTransaction<P, H>>>,
    },
    /// Consensus reports a finalized or tip block.
    Report(Update<SealedBlock<C, P, H>>),
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

    /// Non-blocking batch submission for HTTP handlers.
    ///
    /// On success, returns a receiver that resolves with the batch outcome
    /// once its block is finalized or dropped. Returns `None` if the channel
    /// is full.
    pub fn try_submit(
        &self,
        transactions: Vec<VerifiedTransaction<P, H>>,
        total_bytes: usize,
    ) -> Option<oneshot::Receiver<TxStatus>> {
        let (result_tx, result_rx) = oneshot::channel();
        self.sender
            .try_send(Message::Submit {
                transactions,
                total_bytes,
                result: result_tx,
            })
            .ok()
            .map(|()| result_rx)
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
    ) -> Vec<VerifiedTransaction<P, H>> {
        let height = parent.height + 1;
        self.sender
            .request(|response| Message::Propose { height, response })
            .await
            .expect("mempool actor mailbox closed")
    }
}

impl<C, P, H> Reporter for Mailbox<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    type Activity = Update<SealedBlock<C, P, H>>;

    async fn report(&mut self, activity: Self::Activity) {
        self.sender.send_lossy(Message::Report(activity)).await;
    }
}
