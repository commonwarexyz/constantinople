//! Speculative pre-building of the next proposal.
//!
//! After this node verifies a block it may be asked to propose a child of
//! that block in the next round. Verification completes well before the
//! notarization certificate arrives, so the leader of the next round has an
//! idle window in which the expensive half of proposing — transaction
//! selection and execution — can run off the critical path. When consensus
//! then requests a proposal with the expected parent, the pre-built execution
//! is reused and only the header (real context, fresh timestamp) remains.
//!
//! Selection consumes transactions from the mempool (the mempool never
//! re-queues served transactions), so a pre-build whose parent guess turns
//! out wrong must not be discarded: its transaction selection seeds the
//! actual proposal instead. No structural relationship between the guessed
//! and actual parent can be assumed — a view can produce both a notarization
//! and a nullification, so certified blocks at the same height on divergent
//! histories are possible — which is why reuse relies on execution alone:
//! the selection re-executes best effort against the actual parent's state,
//! any transaction that no longer applies (typically one that already landed
//! on that chain) is dropped by its nonce or balance check, and the block
//! tops up from the live mempool toward the proposal budget. Execution
//! output depends only on the
//! parent and the transaction set — not on the consensus context or the
//! block timestamp — so a pre-built execution is valid for whichever round
//! ends up proposing on the parent it was built on.

use super::{
    db::{Databases, MerkleizedDatabases},
    execution::{ProposalExecution, execute_proposal},
    history::transactions_inactivity_floor,
};
use commonware_consensus::types::{Round, View};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_glue::stateful::db::DatabaseSet;
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Spawner, Storage,
    telemetry::{
        metrics::{Counter, MetricsExt as _},
        traces::TracedExt as _,
    },
};
use commonware_storage::translator::EightCap;
use commonware_utils::sync::{AsyncMutex, Mutex};
use constantinople_mempool::TransactionSource;
use constantinople_primitives::Header;
use futures::channel::oneshot;
use std::sync::Arc;
use tracing::{Instrument as _, info_span};

/// A finished pre-build: the execution of a speculative child proposal and
/// the digest of the parent it was built on.
pub(super) struct PreBuilt<E, H, St>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    St: Strategy,
{
    /// Digest of the parent block the execution extends.
    pub(super) parent: H::Digest,
    /// The completed execution (merkleized databases plus the block body).
    pub(super) execution: ProposalExecution<E, H, St>,
}

/// In-flight or completed pre-build. The sender half lives on the spawned
/// pre-build task; a completed value waits buffered in the channel until
/// consumed, restored, or replaced.
type Slot<E, H, St> = Option<oneshot::Receiver<Option<PreBuilt<E, H, St>>>>;

/// Awaits an in-flight pre-build, restoring it to the slot if the caller is
/// cancelled first. The glue actor drops the propose future whenever the
/// consensus view moves on; without the restore, that cancellation would
/// destroy a pre-build (and strand its consumed transactions) that the next
/// proposal could still use.
struct RestoreOnCancel<'a, E, H, St>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    St: Strategy,
{
    slot: &'a Mutex<Slot<E, H, St>>,
    receiver: Option<oneshot::Receiver<Option<PreBuilt<E, H, St>>>>,
}

impl<E, H, St> RestoreOnCancel<'_, E, H, St>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    St: Strategy,
{
    async fn recv(mut self) -> Option<PreBuilt<E, H, St>> {
        let receiver = self.receiver.as_mut().expect("armed until resolution");
        let result = receiver.await;
        // Resolved (or the task died): nothing worth restoring on drop.
        self.receiver = None;
        result.ok().flatten()
    }
}

impl<E, H, St> Drop for RestoreOnCancel<'_, E, H, St>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    St: Strategy,
{
    fn drop(&mut self) {
        let Some(receiver) = self.receiver.take() else {
            return;
        };
        let mut slot = self.slot.lock();
        // A concurrent verify may have armed a fresher pre-build; it wins.
        if slot.is_none() {
            *slot = Some(receiver);
        }
    }
}

/// Decides when to pre-build and hands finished pre-builds to `propose`.
pub(super) struct Speculator<E, H, I, St>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    St: Strategy,
{
    /// Mempool handle shared with each pre-build task. A replaced task can
    /// briefly contend with its successor's seed selection, so tasks hold the
    /// lock only for that selection, never across execution.
    input: Arc<AsyncMutex<I>>,
    /// Returns whether the local signer leads `round`.
    is_leader: Arc<dyn Fn(Round) -> bool + Send + Sync>,
    slot: Mutex<Slot<E, H, St>>,
    prebuilds: Counter,
    hits: Counter,
    reuses: Counter,
    discards: Counter,
}

impl<E, H, I, St> Speculator<E, H, I, St>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    St: Strategy,
{
    pub(super) fn new(
        context: impl Metrics,
        input: I,
        is_leader: Arc<dyn Fn(Round) -> bool + Send + Sync>,
    ) -> Self {
        Self {
            input: Arc::new(AsyncMutex::new(input)),
            is_leader,
            slot: Mutex::new(None),
            prebuilds: context.counter("prebuilds", "Speculative proposal pre-builds started"),
            hits: context.counter(
                "hits",
                "Proposals served entirely from a speculative pre-build",
            ),
            reuses: context.counter(
                "reuses",
                "Proposals that re-executed pre-built transactions on a different parent",
            ),
            discards: context.counter(
                "discards",
                "Speculative pre-builds replaced before any proposal consumed them",
            ),
        }
    }

    /// Starts a pre-build of the next proposal on top of `parent` (a block
    /// this node just verified) when the local signer leads the next view.
    /// The next round is assumed to stay in the parent's epoch; near an epoch
    /// boundary the guess can only waste one pre-build, never corrupt one
    /// (consumption ignores rounds entirely).
    ///
    /// The heavy work (mempool selection, execution, merkleization) runs on a
    /// spawned task and the strategy's pool; this call only forks batches and
    /// swaps the slot.
    ///
    /// The forked batches read through `merkleized`, which the stateful actor
    /// keeps alive in its pending map. If a conflicting finalization prunes
    /// that entry mid-build, the task's merkleize panics; the runtime handle
    /// catches it, the slot then yields `None`, and the proposal falls back
    /// to the fresh path — a lost pre-build, never a lost proposal.
    pub(super) fn maybe_prebuild<C, P>(
        &self,
        runtime: &E,
        strategy: &St,
        parent_header: &Header<C, H::Digest, P>,
        parent_digest: H::Digest,
        parent_body_len: u64,
        merkleized: &MerkleizedDatabases<E, H, St>,
    ) where
        E: Spawner,
        C: Digest,
        P: PublicKey,
        I: TransactionSource<C, P, H> + Sync,
    {
        let round = parent_header.context.round;
        let next = Round::new(round.epoch(), View::new(round.view().get() + 1));
        if !(self.is_leader)(next) {
            return;
        }

        let (result, receiver) = oneshot::channel();
        let displaced = self.slot.lock().replace(receiver);
        if let Some(displaced) = displaced {
            // The previous pre-build was never consumed. Its transactions are
            // dropped with it (the mempool ages them out the same way it ages
            // out transactions from a proposal that never finalized), and the
            // possibly block-sized buffered execution is released on the
            // pool, off the verify path.
            self.discards.inc();
            let drop_span = info_span!("application.speculate.drop_replaced");
            drop(strategy.spawn(move |_: St| drop_span.in_scope(|| drop(displaced))));
        }
        self.prebuilds.inc();

        let (state_batch, transaction_batch) =
            <Databases<E, H, EightCap, St> as DatabaseSet<E>>::fork_batches(merkleized);
        let parent_floor =
            transactions_inactivity_floor(parent_header.transactions_range.end(), parent_body_len);
        let parent_header = parent_header.clone();
        let input = Arc::clone(&self.input);
        let strategy = strategy.clone();
        let span = info_span!(
            "application.speculate",
            height = (parent_header.height + 1).traced()
        );
        drop(runtime.child("speculation").spawn(move |clock| {
            async move {
                // Consume from the mempool only while someone can still use
                // the result: a replaced task stops before selecting. The
                // lock covers just the selection so a successor's seed pop
                // (and nothing heavier) can ever wait on this task.
                let seed = {
                    let mut input = input.lock().await;
                    if result.is_canceled() {
                        return;
                    }
                    input
                        .propose(&parent_header, next, 0)
                        .instrument(info_span!("application.speculate.input"))
                        .await
                };
                if seed.is_empty() {
                    // Nothing was consumed from the mempool; leave the slot
                    // empty so propose takes the fresh path (and picks up any
                    // transactions that arrive in the meantime).
                    let _ = result.send(None);
                    return;
                }
                // No refill source: dropped candidates are rare on the newest
                // block, and a miss re-executes with live refills at propose
                // time anyway. This also caps what a replaced task can strand
                // at its seed selection.
                let execution = execute_proposal::<E, C, P, H, St, I>(
                    strategy,
                    &clock,
                    state_batch,
                    transaction_batch,
                    parent_floor,
                    &parent_header,
                    next,
                    seed,
                    None,
                )
                .await;
                if execution.body.is_empty() {
                    // Every seed transaction dropped against the guessed
                    // parent: an empty pre-build would later propose an empty
                    // block without ever consulting the mempool, so leave the
                    // slot empty and let propose take the fresh path.
                    let _ = result.send(None);
                    return;
                }
                let _ = result.send(Some(PreBuilt {
                    parent: parent_digest,
                    execution,
                }));
            }
            .instrument(span)
        }));
    }

    /// Takes the current pre-build, waiting for an in-flight one to finish.
    /// A pre-build has no expiry: it waits here until the next proposal
    /// attempt consumes it (or a fresher verify replaces it), and execution
    /// against the actual parent decides what still applies.
    ///
    /// Returns `None` when no pre-build was started, when selection came back
    /// empty, or when the pre-build task failed. If the caller is cancelled
    /// while waiting, the pre-build is restored for the next proposal.
    pub(super) async fn take(&self) -> Option<PreBuilt<E, H, St>> {
        let receiver = self.slot.lock().take()?;
        RestoreOnCancel {
            slot: &self.slot,
            receiver: Some(receiver),
        }
        .recv()
        .await
    }

    pub(super) fn record_hit(&self) {
        self.hits.inc();
    }

    pub(super) fn record_reuse(&self) {
        self.reuses.inc();
    }
}
