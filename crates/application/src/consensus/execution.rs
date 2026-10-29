//! Execution and commitment checks for consensus blocks.
//!
//! This module drives the transfer settlement in [`crate::executor`] against the state database.
//! It prepares block bodies, stages the accounts a body touches, settles the body's transfers with
//! [`commonware_glue::transfers`], appends transaction-history entries, and returns the merkleized
//! commitments that consensus proposes, verifies, or applies.
//!
//! A body settles against block-start state. Nonces and spends are sender-local, and credits from
//! the block cannot fund its spends, so which accounts a body changes, and how, follows from its
//! transfers before any account is read. Verification therefore plans the body, reads every
//! account it touches once, and settles the whole body or rejects it.
//!
//! ```text
//! body transactions
//!        |
//!        v
//! prepare
//!        |
//!        +--> sealed message digests ----------------------------+
//!        |                                                       |
//!        v                                                       |
//! prepared transfers                                             |
//!        |                                                       |
//!        v                                                       |
//! Plan::new: each touched account once, with its debit and       |
//! credit sums and its nonce effects in block order               |
//!        |                                                       |
//!        v                                                       v
//! stage the plan's accounts in one read            transaction-history append
//!        |                                                       |
//!        v                                                       |
//! Plan::settle: one slot per staged account                      |
//!        |                                                       |
//!        v                                                       v
//! staged state merkleize          +           transaction-history merkleize
//!        |
//!        v
//! merkleized commitments
//! ```
//!
//! Account state is read with one awaited QMDB `stage` call, which returns the starting accounts
//! plus a staged batch that retains each key's resolved location, so merkleizing the settled slots
//! skips key re-resolution. A plan's key order is unspecified and can differ between plans of the
//! same body, and the state root does not depend on it: the staged merkleize resolves each slot to
//! its key, so the root depends only on each key's final value. A body that cannot settle (a
//! refused nonce, a debit beyond a starting balance, or a final balance past `u64::MAX`) is
//! rejected whole, with no partial state to reconcile. Which offending account and reason a plan
//! reports may differ between plans, so a rejection only marks the body invalid. Transaction
//! history is append-only: transaction digests are appended in block order, so the
//! transaction-history commitment still reflects block order.
//!
//! Proposing, verifying, and applying certified blocks all use this same transition.
//! `execute_proposal` builds a proposal best effort with a [`Selection`]: malformed candidates are
//! dropped, the rest apply one at a time in block order against block-start state, a candidate that
//! cannot settle with those accepted before it is dropped, the block tops up from the mempool
//! toward the proposal budget, and an empty selection proposes an empty block so an idle chain
//! keeps making progress — a proposal is always produced. The accepted body settles to the same
//! slots under the verifier's plan.
//! `execute_body` prepares a proposed body, recomputes execution, and compares
//! the resulting commitments to the header. Certified apply shallow-clones the
//! block's lazy body (per-transaction handles whose decode cache stays shared)
//! to move it into the prepare job, without building an intermediate
//! materialized transaction vector. Preparing a transfer does
//! not invent a second transaction identifier: it reads the transaction's sealed
//! message digest. For lazily encoded block bodies, whichever consumer first
//! materializes the transaction computes that seal once and caches the decoded
//! transaction for the other consumers.
//!
//! Parallel fan-out comes from the supplied `Strategy`, which decides per
//! operation whether fanning out beats staying serial. The strategy drives
//! preparation, planning, settlement, and QMDB merkleization beneath the batch
//! APIs. QMDB reads stay on the async path and are not run inside `Strategy`
//! workers.

use super::{
    INVALID_TRANSACTION_FLOOR, MALFORMED_TRANSACTION, Result, STATIC_INVALID_TRANSACTION,
    body::PreparedBody,
    db::{self, StateBatch, StateSlots, StateStaged, TransactionBatch, apply_transaction_digests},
    reject_verify,
};
use crate::executor::{self, PreparedTransfer, TransferAccount};
use commonware_codec::EncodeSize as _;
use commonware_consensus::types::Round;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_glue::{
    stateful::db::Merkleized as _,
    transfers::{Plan, Selection},
};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Storage, telemetry::traces::TracedExt as _};
use commonware_storage::{
    merkle::Family,
    mmr,
    qmdb::{Error as QmdbError, chain::Bounds},
    translator::EightCap,
};
use commonware_utils::non_empty_range;
use constantinople_mempool::TransactionSource;
use constantinople_primitives::{AccountKey, Header, LazySignedTransaction, SignedTransaction};
use std::{
    future::{Future, ready},
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tracing::{Instrument as _, info_span};

pub(super) struct ProposalExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    pub(super) block: BlockExecution<E, H, S>,
    pub(super) body: Vec<SignedTransaction<H>>,
}

pub(super) struct BlockExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    pub(super) state: db::StateMerkleized<E, H, EightCap, S>,
    pub(super) transactions: db::TransactionMerkleized<E, H, S>,
    pub(super) state_sync_range: commonware_utils::range::NonEmptyRange<u64>,
    pub(super) transactions_range: commonware_utils::range::NonEmptyRange<u64>,
    pub(super) transaction_count: usize,
}

impl<E, H, S> BlockExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    pub(super) fn into_merkleized(self) -> db::MerkleizedDatabases<E, H, S> {
        (self.state, self.transactions)
    }
}

/// Settles a body's transfers against the batch's block-start state.
///
/// Plans the transfers, consumes the batch to stage every account the plan touches, and settles the
/// plan into one slot per staged account. Returns the staged batch alongside `None` if the body
/// cannot settle (the whole body is rejected).
#[tracing::instrument(name = "application.execute.compute", level = "info", skip_all)]
pub async fn compute<E, H, S>(
    batch: StateBatch<E, H, EightCap, S>,
    transfers: Arc<Vec<PreparedTransfer>>,
    strategy: &S,
) -> (StateStaged<E, H, EightCap, S>, Option<StateSlots>)
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let plan_span = info_span!("application.execute.plan", txs = transfers.len().traced());
    let work_size = transfers.len();
    let plan = strategy
        .spawn(work_size, move |s: S| {
            plan_span.in_scope(|| Plan::new(transfers.as_slice(), &s))
        })
        .await;
    let Ok(plan) = plan else {
        return (stage_empty(batch).await, None);
    };

    // One staged QMDB read lets the storage layer sort and batch journal
    // positions, and each key's resolved location is reused when the staged
    // batch merkleizes.
    let (reads, staged) = {
        let keys: Vec<&AccountKey> = plan.keys().iter().collect();
        batch
            .stage(&keys)
            .await
            .expect("account state loading must succeed")
    };
    let settle_span = info_span!("application.execute.settle", accounts = plan.len().traced());
    let work_size = plan.len();
    let slots = strategy
        .spawn(work_size, move |s: S| {
            settle_span.in_scope(|| {
                plan.settle(&executor::starting_accounts(reads), &s)
                    .ok()
                    .map(executor::account_slots)
            })
        })
        .await;
    (staged, slots)
}

/// Stages a batch with no reads, for paths that reject or skip execution.
pub(super) async fn stage_empty<E, H, S>(
    batch: StateBatch<E, H, EightCap, S>,
) -> StateStaged<E, H, EightCap, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let (_, staged) = batch
        .stage(&[])
        .await
        .expect("staging no reads must succeed");
    staged
}

pub fn prepare_signed<H, S>(
    strategy: &S,
    txs: &[SignedTransaction<H>],
) -> Option<(Vec<PreparedTransfer>, Vec<H::Digest>)>
where
    H: Hasher,
    S: Strategy,
{
    strategy
        .try_map_collect_vec(txs, |tx| {
            executor::prepare_transfer(tx)
                .map(|transfer| (transfer, *tx.message_digest()))
                .ok_or(())
        })
        .ok()
        .map(|prepared| prepared.into_iter().unzip())
}

pub(super) fn prepare_lazy<H, S>(
    strategy: &S,
    body: &[LazySignedTransaction<H>],
) -> Result<(Vec<PreparedTransfer>, Vec<H::Digest>)>
where
    H: Hasher,
    S: Strategy,
{
    strategy
        .try_map_collect_vec(body, |lazy| {
            let tx = lazy.get().ok_or(MALFORMED_TRANSACTION)?;
            let transfer = executor::prepare_transfer(tx).ok_or(MALFORMED_TRANSACTION)?;
            Ok((transfer, *tx.message_digest()))
        })
        .map(|prepared| prepared.into_iter().unzip())
}

/// An in-flight transaction-history append chained across refill rounds.
type PendingAppend<E, H, S> = Pin<Box<dyn Future<Output = TransactionBatch<E, H, S>> + Send>>;

/// Wall-clock budget for building one proposal. Refill rounds keep running
/// while block headroom remains and this deadline has not passed; a round in
/// flight always completes (popped transactions must be executed or they
/// would strand), so the deadline gates starting another refill, not
/// finishing one. Transactions dropped in the final round age out of the
/// mempool like any unfinalized proposal.
const BUILD_TIMEOUT: Duration = Duration::from_millis(50);

/// Executes a proposal's candidate transactions best effort.
///
/// Verification is all or nothing, but a proposer chooses the block body:
/// each candidate (the supplied selection first, then mempool refills)
/// applies against block-start account state in block order, and any
/// transaction that does not apply — malformed encoding, stale nonce
/// (typically a transaction that already landed in an ancestor block),
/// unaffordable value, or credit overflow — is dropped instead of dooming the
/// proposal. Each refill asks the mempool for the block's remaining headroom
/// (it knows the proposal budget; we report the bytes already included), so
/// the block fills toward the budget even when the seed was small. Each round
/// reads only the accounts it touches for the first time, through `stage` for
/// the first round and `expand` after, in the selection's key order, so the
/// staged slots line up with the selection's keys. The loop ends when the
/// mempool has nothing left that fits or the build deadline passes. The
/// surviving body settles under all-or-nothing verification to the same
/// slots.
///
/// Each round starts appending its accepted digests before the next refill.
/// When offloaded, the append can overlap later rounds and the final state
/// merkleize. The strategy may instead complete an append inline. Chained
/// appends preserve the accepted digests' block order. An empty selection
/// proposes an empty block so an idle chain keeps making progress.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(name = "application.execute", level = "info", skip_all)]
pub(super) async fn execute_proposal<E, C, P, H, S, I>(
    strategy: S,
    clock: &impl Clock,
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent_floor: mmr::Location,
    parent_header: &Header<C, H::Digest, P>,
    round: Round,
    candidates: Vec<SignedTransaction<H>>,
    input: &mut I,
) -> ProposalExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
    I: TransactionSource<C, P, H> + Sync,
{
    let mut unstaged = Some(state_batch);
    let mut staged: Option<StateStaged<E, H, EightCap, S>> = None;
    let mut selection: Selection<AccountKey, TransferAccount> = Selection::new();
    let mut body: Vec<SignedTransaction<H>> = Vec::new();
    let mut included_bytes = 0usize;
    let mut candidates = candidates;

    // Rounds share one history batch, so each append is joined before the
    // next starts. Offloaded appends can overlap the next round's work.
    let mut transaction_batch = Some(transaction_batch);
    let mut pending_append: Option<PendingAppend<E, H, S>> = None;
    let deadline = clock.current() + BUILD_TIMEOUT;

    loop {
        if candidates.is_empty() {
            break;
        }

        // A proposer chooses its body, so candidates that fail preparation
        // can be excluded. Keep results aligned with the candidate vector
        // while compacting valid transfers and recording first-touched accounts.
        let prepare_span = info_span!(
            "application.execute.prepare",
            txs = candidates.len().traced()
        );
        let accounts_span =
            info_span!("application.execute.accounts", keys = tracing::field::Empty);
        let work_size = candidates.len();
        let (candidates_back, prepared, transfers, selection_back, touched) = strategy
            .spawn(work_size, {
                let accounts_span = accounts_span.clone();
                let mut selection = selection;
                move |s: S| {
                    let (prepared, transfers) = prepare_span.in_scope(|| {
                        let prepared: Vec<Option<(PreparedTransfer, H::Digest)>> = s
                            .map_collect_vec(&candidates, |tx| {
                                executor::prepare_transfer(tx)
                                    .map(|transfer| (transfer, *tx.message_digest()))
                            });
                        let transfers: Vec<PreparedTransfer> = prepared
                            .iter()
                            .flatten()
                            .map(|(transfer, _)| *transfer)
                            .collect();
                        (prepared, transfers)
                    });
                    let touched = accounts_span.in_scope(|| selection.touch(&transfers));
                    (candidates, prepared, transfers, selection, touched)
                }
            })
            .await;
        candidates = candidates_back;
        selection = selection_back;
        accounts_span.record("keys", touched.len().traced());

        // Load block-start values for accounts this round touches for the
        // first time; later rounds expand the same staged read space, whose
        // slots continue exactly where the selection's keys do.
        if !touched.is_empty() {
            let stage_span = info_span!("application.execute.stage", keys = touched.len().traced());
            async {
                let keys: Vec<&AccountKey> = selection.keys()[touched.clone()].iter().collect();
                let reads = if let Some(batch) = unstaged.take() {
                    let (reads, next) = batch
                        .stage(&keys)
                        .await
                        .expect("account state loading must succeed");
                    staged = Some(next);
                    reads
                } else {
                    let (range, reads, next) = staged
                        .take()
                        .expect("staged batch exists after the first round")
                        .expand(&keys)
                        .await
                        .expect("account state loading must succeed");
                    debug_assert_eq!(range, touched);
                    staged = Some(next);
                    reads
                };
                selection.register(executor::starting_accounts(reads));
            }
            .instrument(stage_span)
            .await;
        }

        // Apply in block order and fold the survivors into the body, all in
        // one job so the split is attributed and the candidates move
        // straight into the body.
        let select_span = info_span!(
            "application.execute.select",
            txs = transfers.len().traced(),
            dropped = tracing::field::Empty,
        );
        let work_size = transfers.len();
        let (selection_back, body_back, chunk, included_delta, dropped_bytes) = strategy
            .spawn(work_size, {
                let span = select_span.clone();
                let mut selection = selection;
                let mut body = body;
                move |_: S| {
                    span.in_scope(|| {
                        let applied = selection.apply(&transfers);
                        let mut flags = applied.into_iter();
                        let mut chunk: Vec<H::Digest> = Vec::with_capacity(transfers.len());
                        let mut included = 0usize;
                        let mut dropped = 0usize;
                        for (transaction, prepared) in candidates.into_iter().zip(prepared) {
                            let Some((_, digest)) = prepared else {
                                continue;
                            };
                            if flags.next().expect("one flag per prepared transfer") {
                                included += transaction.encode_size();
                                chunk.push(digest);
                                body.push(transaction);
                            } else {
                                dropped += transaction.encode_size();
                            }
                        }
                        (selection, body, chunk, included, dropped)
                    })
                }
            })
            .await;
        selection = selection_back;
        body = body_back;
        included_bytes += included_delta;
        select_span.record("dropped", dropped_bytes.traced());

        // Start this round's history append before refilling so it can
        // overlap the next round when the strategy offloads it.
        if !chunk.is_empty() {
            let batch = match pending_append.take() {
                Some(append) => {
                    append
                        .instrument(info_span!("application.execute.apply_wait"))
                        .await
                }
                None => transaction_batch
                    .take()
                    .expect("transaction batch is owned until the first append"),
            };
            let apply_span = info_span!("application.execute.apply", txs = chunk.len().traced());
            let work_size = chunk.len();
            pending_append = Some(Box::pin(strategy.spawn(work_size, move |_: S| {
                apply_span.in_scope(|| apply_transaction_digests(batch, &chunk))
            })));
        }

        if clock.current() >= deadline {
            break;
        }

        // Top the block up toward the mempool's proposal budget; an empty
        // response means nothing fits in the remaining headroom (or the pool
        // is dry) and ends the loop.
        candidates = input
            .propose(parent_header, round, included_bytes)
            .instrument(info_span!("application.execute.refill"))
            .await;
    }

    let staged = match staged {
        Some(staged) => staged,
        None => stage_empty(unstaged.take().expect("nothing was staged")).await,
    };

    // Settle the accepted transfers while any offloaded history append drains.
    let settle_span = info_span!(
        "application.execute.settle",
        accounts = selection.keys().len().traced()
    );
    let work_size = selection.keys().len();
    let slots = strategy
        .spawn(work_size, move |s: S| {
            settle_span.in_scope(|| executor::account_slots(selection.settle(&s)))
        })
        .await;

    // Pass the append future into `finalize_child` so any remaining work can
    // overlap state merkleization. Empty selections need no append job.
    let drained = transaction_batch.take();
    let append = pending_append.take();
    let transaction_batch = async move {
        match append {
            Some(append) => append.await,
            None => drained.expect("transaction batch is owned until the first append"),
        }
    }
    .instrument(info_span!("application.execute.apply_wait"));

    ProposalExecution {
        block: finalize_child(
            staged,
            slots,
            transaction_batch,
            parent_floor,
            body.len(),
            "database merkleization must succeed",
        )
        .await,
        body,
    }
}

#[tracing::instrument(name = "application.execute", level = "info", skip_all)]
pub(super) async fn execute_body<E, H, S>(
    strategy: S,
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent_floor: mmr::Location,
    body: PreparedBody<H>,
) -> Result<BlockExecution<E, H, S>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let prepare_span = info_span!("application.execute.prepare", txs = body.len().traced());
    let work_size = body.len();
    let (transfers, digests) = strategy
        .spawn(work_size, move |s| {
            prepare_span.in_scope(|| prepare_lazy(&s, body.as_ref().as_slice()))
        })
        .await?;

    let transaction_count = transfers.len();
    let transfers = Arc::new(transfers);

    // The history append is independent of state execution, so start it before
    // compute. The strategy may run it inline or offload it to overlap compute.
    let apply_span = info_span!("application.execute.apply", txs = digests.len().traced());
    let work_size = digests.len();
    let apply = strategy.spawn(work_size, move |_: S| {
        apply_span.in_scope(|| apply_transaction_digests(transaction_batch, &digests))
    });
    let (staged, slots) = compute(state_batch, transfers, &strategy).await;

    // Join the append before surfacing a rejection so its panics propagate
    // and no job outlives this call.
    let transaction_batch = apply.await;
    let slots = slots.ok_or(STATIC_INVALID_TRANSACTION)?;

    Ok(finalize_child(
        staged,
        slots,
        ready(transaction_batch),
        parent_floor,
        transaction_count,
        "database merkleization during verification must succeed",
    )
    .await)
}

#[tracing::instrument(name = "application.apply.body", level = "info", skip_all)]
pub(super) async fn apply_prepared_body<E, H, S>(
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    transaction_floor: mmr::Location,
    transfers: Vec<PreparedTransfer>,
    digests: Vec<H::Digest>,
    strategy: S,
) -> Result<db::MerkleizedDatabases<E, H, S>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let transfers = Arc::new(transfers);

    // The history append is independent of state execution, so start it before
    // compute. The strategy may run it inline or offload it to overlap compute.
    let apply_span = info_span!("application.execute.apply", txs = digests.len().traced());
    let work_size = digests.len();
    let apply = strategy.spawn(work_size, move |_: S| {
        apply_span.in_scope(|| {
            apply_transaction_digests(transaction_batch, &digests)
                .with_inactivity_floor(transaction_floor)
        })
    });
    let (staged, slots) = compute(state_batch, transfers, &strategy).await;

    // Join the append before surfacing a rejection so its panics propagate
    // and no job outlives this call.
    let transaction_batch = apply.await;
    let slots = slots.ok_or(STATIC_INVALID_TRANSACTION)?;

    // The replayed header supplies the transaction-history floor, and merkleize
    // rejects a floor below the parent's or past this block's commit. Any other
    // merkleize failure is a storage failure.
    match db::finalize_execution(staged, slots, ready(transaction_batch)).await {
        Ok(merkleized) => Ok(merkleized),
        Err(QmdbError::FloorRegressed(..) | QmdbError::FloorBeyondSize(..)) => {
            Err(INVALID_TRANSACTION_FLOOR)
        }
        Err(error) => panic!("database merkleization during replay must succeed: {error:?}"),
    }
}

pub(super) fn commitments_match<E, C, P, H, S>(
    header: &Header<C, H::Digest, P>,
    execution: &BlockExecution<E, H, S>,
) -> bool
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    if execution.state.root() != header.state_root {
        reject_verify(header.height, "state_root_mismatch");
        return false;
    }
    if execution.state_sync_range != header.state_range {
        reject_verify(header.height, "state_range_mismatch");
        return false;
    }
    if execution.transactions.root() != header.transactions_root {
        reject_verify(header.height, "transaction_root_mismatch");
        return false;
    }
    if execution.transactions_range != header.transactions_range {
        reject_verify(header.height, "transaction_range_mismatch");
        return false;
    }

    true
}

/// Merkleizes the staged state and transaction batches into a child block
/// execution. `transaction_batch` is a future so a still-draining history
/// append can overlap the state merkleize; callers holding a finished batch
/// pass it via [`ready`].
#[tracing::instrument(name = "application.execute.finalize", level = "info", skip_all)]
async fn finalize_child<E, H, S>(
    state_staged: StateStaged<E, H, EightCap, S>,
    state_slots: StateSlots,
    transaction_batch: impl Future<Output = TransactionBatch<E, H, S>>,
    parent_floor: mmr::Location,
    transaction_count: usize,
    expect_message: &'static str,
) -> BlockExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let transaction_batch =
        async move { transaction_batch.await.with_inactivity_floor(parent_floor) };
    let (state, transactions) =
        db::finalize_execution(state_staged, state_slots, transaction_batch)
            .await
            .expect(expect_message);
    let state_sync_range = range_from_bounds(state.bounds());
    let transactions_range = range_from_bounds(transactions.bounds());

    BlockExecution {
        state,
        transactions,
        state_sync_range,
        transactions_range,
        transaction_count,
    }
}

fn range_from_bounds<F, D>(bounds: &Bounds<F, D>) -> commonware_utils::range::NonEmptyRange<u64>
where
    F: Family,
    D: Digest,
{
    non_empty_range!(*bounds.inactivity_floor, *bounds.tip.size)
}

#[cfg(test)]
mod tests {
    use super::range_from_bounds;
    use commonware_cryptography::{Digest as _, sha256};
    use commonware_storage::{
        mmr,
        qmdb::chain::{Bounds, Commitment},
    };
    use commonware_utils::non_empty_range;

    #[test]
    fn range_comes_from_qmdb_bounds() {
        let bounds = Bounds {
            base: Commitment {
                size: mmr::Location::new(7),
                root: sha256::Digest::EMPTY,
            },
            db: Commitment {
                size: mmr::Location::new(9),
                root: sha256::Digest::EMPTY,
            },
            tip: Commitment {
                size: mmr::Location::new(15),
                root: sha256::Digest::EMPTY,
            },
            ancestors: Vec::new(),
            inactivity_floor: mmr::Location::new(11),
        };

        assert_eq!(range_from_bounds(&bounds), non_empty_range!(11, 15));
    }
}
