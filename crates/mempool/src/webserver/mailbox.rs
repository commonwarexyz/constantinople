//! Mailbox for the mempool webserver actor.

use super::actor::{IngestStatus, PreparedSelection, SelectionState, StoredBatchStatus, TxStatus};
use crate::TransactionSource;
use commonware_actor::Feedback;
use commonware_consensus::{Reporter, marshal::Update, types::Round};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_utils::channel::fallible::AsyncFallibleExt;
use constantinople_primitives::{Header, SealedBlock, VerifiedTransaction};
use std::sync::Arc;
use tokio::sync::{
    Mutex,
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
    pub(super) selection: Arc<Mutex<SelectionState<H>>>,
}

pub(super) enum Message<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    /// A batch of verified transactions submitted by an HTTP handler.
    Submit {
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
        response: oneshot::Sender<Option<StoredBatchStatus<H::Digest>>>,
    },
    /// Consensus reports a finalized or tip block.
    Report(Update<SealedBlock<C, P, H>>),
}

/// Handle to the mempool actor, used by HTTP handlers and the consensus layer.
pub struct Mailbox<C, P, H, St>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    sender: mpsc::Sender<Message<C, P, H>>,
    selection: Arc<Mutex<SelectionState<H>>>,
    strategy: St,
}

impl<C, P, H, St> Clone for Mailbox<C, P, H, St>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            selection: Arc::clone(&self.selection),
            strategy: self.strategy.clone(),
        }
    }
}

impl<C, P, H, St> Mailbox<C, P, H, St>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    pub(super) const fn new(
        sender: mpsc::Sender<Message<C, P, H>>,
        selection: Arc<Mutex<SelectionState<H>>>,
        strategy: St,
    ) -> Self {
        Self {
            sender,
            selection,
            strategy,
        }
    }

    /// Creates a new mailbox backed by a bounded channel of the given
    /// capacity, returning the mailbox handle and the receiver half.
    ///
    /// Use this when the mailbox needs to exist before the [`Actor`](super::Actor)
    /// is constructed (e.g. to hand it to consensus as a transaction source).
    pub fn channel(
        capacity: usize,
        max_propose_bytes: usize,
        strategy: St,
    ) -> (Self, ActorReceiver<C, P, H>) {
        let (tx, rx) = mpsc::channel(capacity);
        let selection = Arc::new(Mutex::new(SelectionState::new(max_propose_bytes)));
        (
            Self::new(tx, Arc::clone(&selection), strategy),
            ActorReceiver { rx, selection },
        )
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
    pub(super) async fn query_status(
        &self,
        batch_id: String,
    ) -> Option<StoredBatchStatus<H::Digest>> {
        self.sender
            .request(|response| Message::QueryStatus { batch_id, response })
            .await
            .flatten()
    }
}

impl<C, P, H, St> TransactionSource<C, P, H> for Mailbox<C, P, H, St>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    H::Digest: Eq + std::hash::Hash,
    St: Strategy,
{
    async fn propose(
        &mut self,
        parent: &Header<C, H::Digest, P>,
        round: Round,
        filled: usize,
    ) -> Vec<VerifiedTransaction<H>> {
        assert!(!self.sender.is_closed(), "mempool actor mailbox closed");
        let height = parent.height + 1;
        let selection = Arc::clone(&self.selection).lock_owned().await;
        let prepared = self
            .strategy
            .spawn(move |_: St| PreparedSelection::new(selection, height, round, filled))
            .await;
        prepared.commit()
    }
}

impl<C, P, H, St> Reporter for Mailbox<C, P, H, St>
where
    C: Digest + Send + 'static,
    P: PublicKey + Send + 'static,
    H: Hasher + Send + 'static,
    H::Digest: Send,
    St: Strategy,
{
    type Activity = Update<SealedBlock<C, P, H>>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match self.sender.try_send(Message::Report(activity)) {
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

#[cfg(test)]
mod tests {
    use super::Mailbox;
    use crate::TransactionSource;
    use commonware_codec::EncodeSize as _;
    use commonware_consensus::{
        simplex::types::Context,
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{Digest as _, Signer as _, ed25519, sha256};
    use commonware_math::algebra::Random as _;
    use commonware_parallel::{Rayon, Sequential};
    use commonware_runtime::{Runner as _, tokio as runtime};
    use commonware_utils::{NZUsize, non_empty_range};
    use constantinople_primitives::{
        Header, TRANSACTION_NAMESPACE, Transaction, TransactionPublicKey,
    };
    use futures::FutureExt as _;
    use rand::{SeedableRng as _, rngs::StdRng};
    use std::{
        num::NonZeroU64,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        thread,
        time::Duration,
    };

    fn parent() -> Header<sha256::Digest, sha256::Digest, ed25519::PublicKey> {
        let mut rng = StdRng::from_seed([7; 32]);
        let leader = ed25519::PrivateKey::random(&mut rng).public_key();
        Header {
            context: Context {
                round: Round::new(Epoch::zero(), View::zero()),
                leader,
                parent: (View::zero(), sha256::Digest::EMPTY),
            },
            parent: sha256::Digest::EMPTY,
            height: 0,
            timestamp: 0,
            state_root: sha256::Digest::EMPTY,
            state_range: non_empty_range!(0, 1),
            transactions_root: sha256::Digest::EMPTY,
            transactions_range: non_empty_range!(0, 1),
        }
    }

    #[test]
    fn proposal_selection_does_not_wait_for_actor_work() {
        let (mut mailbox, _receiver) =
            Mailbox::<sha256::Digest, ed25519::PublicKey, sha256::Sha256, Sequential>::channel(
                1, 1, Sequential,
            );
        let parent = parent();
        let selected = mailbox
            .propose(&parent, parent.context.round, 0)
            .now_or_never();
        assert!(
            selected.is_some(),
            "proposal selection must not wait for status/report actor work"
        );
        assert!(selected.expect("proposal should be ready").is_empty());
    }

    #[test]
    fn full_budget_proposal_selection_does_not_block_runtime_worker() {
        const MAX_PROPOSE_BYTES: usize = 24 * 1024 * 1024;
        let (mut mailbox, receiver) =
            Mailbox::<sha256::Digest, ed25519::PublicKey, sha256::Sha256, Rayon>::channel(
                1,
                MAX_PROPOSE_BYTES,
                Rayon::new(NZUsize!(2)).expect("rayon pool"),
            );
        let signer = ed25519::PrivateKey::from_seed(11);
        let recipient = ed25519::PrivateKey::from_seed(12).public_key();
        let transaction = Transaction::new(
            TransactionPublicKey::ed25519(signer.public_key()),
            TransactionPublicKey::ed25519(recipient),
            NonZeroU64::new(1).expect("non-zero amount"),
            0,
        )
        .seal_and_sign(
            &signer,
            TRANSACTION_NAMESPACE,
            &mut sha256::Sha256::default(),
        );
        let transaction_bytes = transaction.encode_size();
        let transaction_count = MAX_PROPOSE_BYTES / transaction_bytes;
        let total_bytes = transaction_count * transaction_bytes;

        let (started_tx, started_rx) = mpsc::sync_channel(0);
        let (progress_tx, progress_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let runtime_progressed = Arc::new(AtomicBool::new(false));
        {
            let mut selection = receiver
                .selection
                .try_lock()
                .expect("mempool selection state should be idle");
            selection.push_for_test(vec![transaction; transaction_count], total_bytes);
            selection.set_proposal_hook(Box::new(move || {
                started_tx
                    .send(())
                    .expect("proposal start observer dropped");
                release_rx
                    .recv()
                    .expect("proposal release observer dropped");
            }));
        }

        let observed = Arc::clone(&runtime_progressed);
        let release = thread::spawn(move || {
            started_rx.recv().expect("proposal hook did not start");
            if progress_rx.recv_timeout(Duration::from_secs(1)).is_ok() {
                observed.store(true, Ordering::SeqCst);
            }
            release_tx.send(()).expect("proposal hook dropped");
        });

        let selection_for_report = Arc::clone(&receiver.selection);
        let parent = parent();
        runtime::Runner::new(runtime::Config::default().with_worker_threads(1)).start(
            move |_| async move {
                let proposal =
                    tokio::spawn(
                        async move { mailbox.propose(&parent, parent.context.round, 0).await },
                    );
                tokio::task::yield_now().await;
                let report = tokio::spawn(async move {
                    selection_for_report
                        .lock()
                        .await
                        .drain_pending_transactions_for_test()
                });
                tokio::spawn(async move {
                    progress_tx.send(()).expect("progress observer dropped");
                });
                let selected = proposal.await.expect("proposal task panicked");
                assert_eq!(selected.len(), transaction_count);
                assert_eq!(
                    report.await.expect("report task panicked"),
                    transaction_count,
                    "report acknowledgement must observe the complete selection journal",
                );
            },
        );
        release.join().expect("proposal release thread panicked");
        assert!(
            runtime_progressed.load(Ordering::SeqCst),
            "full-budget selection blocked the sole runtime worker"
        );
    }

    #[test]
    fn cancelled_proposal_selection_returns_transactions_to_pool() {
        const TRANSACTIONS: usize = 3;
        let (mut mailbox, receiver) =
            Mailbox::<sha256::Digest, ed25519::PublicKey, sha256::Sha256, Rayon>::channel(
                1,
                1024,
                Rayon::new(NZUsize!(2)).expect("rayon pool"),
            );
        let signer = ed25519::PrivateKey::from_seed(21);
        let recipient = ed25519::PrivateKey::from_seed(22).public_key();
        let transaction = Transaction::new(
            TransactionPublicKey::ed25519(signer.public_key()),
            TransactionPublicKey::ed25519(recipient),
            NonZeroU64::new(1).expect("non-zero amount"),
            0,
        )
        .seal_and_sign(
            &signer,
            TRANSACTION_NAMESPACE,
            &mut sha256::Sha256::default(),
        );
        let total_bytes = TRANSACTIONS * transaction.encode_size();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        {
            let mut started_tx = Some(started_tx);
            let mut selection = receiver
                .selection
                .try_lock()
                .expect("mempool selection state should be idle");
            selection.push_for_test(vec![transaction; TRANSACTIONS], total_bytes);
            selection.set_proposal_hook(Box::new(move || {
                started_tx
                    .take()
                    .expect("proposal hook ran twice")
                    .send(())
                    .expect("proposal start observer dropped");
                release_rx
                    .recv()
                    .expect("proposal release observer dropped");
            }));
        }

        let selection = Arc::clone(&receiver.selection);
        let parent = parent();
        runtime::Runner::new(runtime::Config::default().with_worker_threads(1)).start(
            move |_| async move {
                let proposal =
                    tokio::spawn(
                        async move { mailbox.propose(&parent, parent.context.round, 0).await },
                    );
                started_rx.await.expect("proposal hook did not start");
                proposal.abort();
                release_tx.send(()).expect("proposal hook dropped");
                assert!(
                    proposal
                        .await
                        .expect_err("cancelled proposal completed")
                        .is_cancelled()
                );

                let selection = selection.lock().await;
                assert_eq!(selection.queued_transactions_for_test(), TRANSACTIONS);
                assert_eq!(selection.pending_transactions_for_test(), 0);
            },
        );
    }
}
