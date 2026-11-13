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
//! After settlement, a reverse walk of the accepted body assigns each transaction its sender
//! and recipient indices from the final account counts. History append and state merkleization
//! then run concurrently. Indexing uses the settled accounts without further database access.
//!
//! Account state is read with one awaited QMDB `stage` call. It returns the starting accounts and
//! a staged batch that retains each key's resolved location, so merkleizing the settled slots skips
//! key re-resolution. A plan's key order is unspecified and can differ between plans of the same
//! body. The staged merkleize resolves each slot to its key, so the state root depends only on each
//! key's final value and not on that order.
//!
//! A body that cannot settle (a refused nonce, a debit beyond a starting balance, or a final
//! balance or history count past `u64::MAX`) is rejected whole, with no partial state to reconcile.
//! Different plans may report a different offending account and reason, so a rejection only
//! marks the body invalid. Transaction-history entries append in block order, so their commitment
//! reflects that order.
//!
//! Proposing, verifying, and applying certified blocks all use this same transition.
//! `execute_proposal` builds a proposal best effort with a [`Selection`]. Malformed candidates are
//! dropped, and the rest apply one at a time in block order against block-start state, dropping
//! each candidate that cannot settle with those accepted before it. The block tops up from the
//! mempool toward the proposal budget, and an empty selection still proposes an empty block so an
//! idle chain keeps making progress. The accepted body settles to the same slots under the
//! verifier's plan.
//!
//! `execute_body` prepares a proposed body, recomputes execution, and compares the resulting
//! commitments to the header. Certified apply shares ownership of the block's immutable lazy body
//! with the prepare job. Preparing a transfer reads the transaction's sealed message digest as its
//! identifier. For lazily encoded block bodies, whichever consumer first materializes the
//! transaction computes that seal once and caches the decoded transaction for the other consumers.
//!
//! Parallel fan-out comes from the supplied `Strategy`, which decides per
//! operation whether fanning out beats staying serial. The strategy drives
//! preparation, planning, settlement, and QMDB merkleization beneath the batch
//! APIs. QMDB reads stay on the async path and are not run inside `Strategy`
//! workers.

use super::{
    INVALID_TRANSACTION_FLOOR, MALFORMED_TRANSACTION, Result, STATIC_INVALID_TRANSACTION,
    body::PreparedBody,
    db::{self, StateBatch, StateSlots, StateStaged, TransactionBatch, apply_transaction_entries},
    history, reject_verify,
};
use crate::executor::{self, PreparedTransfer, TransferAccount};
use commonware_codec::EncodeSize;
use commonware_consensus::types::Round;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_glue::{
    stateful::db::Merkleized as _,
    transfers::{Account, Change, Plan, Selection, Transfer},
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
use std::{future::Future, sync::Arc, time::Duration};
use tracing::{Instrument as _, info_span};

pub(super) struct ProposalExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    pub(super) block: BlockExecution<E, H, S>,
    pub(super) body: Arc<Vec<LazySignedTransaction<H>>>,
    /// The encoded size of `body`.
    pub(super) body_size: usize,
}

/// A proposal candidate's transfer, message digest and encoded size, or `None` if it does not
/// decode or prepare.
///
/// A candidate that does not prepare changes no account, so selection applies it without effect
/// and the proposer leaves it out of the body.
struct Candidate<D>(Option<(PreparedTransfer, D, usize)>);

impl<D> Transfer for Candidate<D> {
    type Key = AccountKey;
    type Account = TransferAccount;

    fn changes(
        &self,
    ) -> impl Iterator<Item = (&AccountKey, Change<<TransferAccount as Account>::Effect>)> {
        self.0
            .iter()
            .flat_map(|(transfer, _, _)| transfer.changes())
    }
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
    compute_with(batch, transfers, strategy, |_, slots| slots).await
}

// The finish callback runs inside the settlement job, while the plan still owns its key
// order, so callers can keep what they need from the keys without a second job.
async fn compute_with<E, H, S, R>(
    batch: StateBatch<E, H, EightCap, S>,
    transfers: Arc<Vec<PreparedTransfer>>,
    strategy: &S,
    finish: impl FnOnce(&[AccountKey], StateSlots) -> R + Send + 'static,
) -> (StateStaged<E, H, EightCap, S>, Option<R>)
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
    R: Send + 'static,
{
    // A body whose debit or credit sums overflow cannot settle, so it stages
    // no reads and settles to `None`.
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

    // The starting accounts arrive in the plan's key order, so each settled
    // slot lines up with its staged read.
    let settle_span = info_span!("application.execute.settle", accounts = plan.len().traced());
    let work_size = plan.len();
    let slots = strategy
        .spawn(work_size, move |s: S| {
            settle_span.in_scope(|| {
                plan.settle(&executor::starting_accounts(reads), &s)
                    .ok()
                    .map(|slots| finish(plan.keys(), executor::account_slots(slots)))
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

/// Wall-clock budget for building one proposal. Refill rounds keep running
/// while block headroom remains and this deadline has not passed; a round in
/// flight always completes (popped transactions must be executed or they
/// would strand), so the deadline gates starting another refill, not
/// finishing one. Transactions dropped in the final round age out of the
/// mempool like any unfinalized proposal.
const BUILD_TIMEOUT: Duration = Duration::from_millis(50);

/// Executes a proposal's candidate transactions best effort.
///
/// Verification is all or nothing, but a proposer chooses the block body. Each
/// candidate (the supplied selection first, then mempool refills) applies
/// against block-start account state in block order, and a transaction that
/// does not apply is dropped without dooming the proposal. A transaction fails
/// to apply on a malformed encoding, a stale nonce (typically one that already
/// landed in an ancestor block), an unaffordable value, or a credit overflow.
/// The surviving body settles under all-or-nothing verification to the same
/// slots.
///
/// Each refill reports the bytes already included, and the mempool returns
/// candidates for the headroom left under the proposal budget, so the block
/// fills toward the budget even when the seed was small. The loop ends when
/// the mempool has nothing left that fits or the build deadline passes. With
/// `skip_final_refill`, it also ends after a round that drops nothing.
///
/// Each round reads only the accounts it touches for the first time, through
/// `stage` for the first round and `expand` after, in the selection's key
/// order, so the staged slots line up with the selection's keys.
///
/// After settlement, history entries take their indices from the final account
/// counts and append in block order while state merkleization runs. An empty
/// selection proposes an empty block so an idle chain keeps making progress.
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
    candidates: Vec<LazySignedTransaction<H>>,
    input: &mut I,
    skip_final_refill: bool,
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
    let mut body: Vec<LazySignedTransaction<H>> = Vec::new();
    let mut accepted: Vec<(PreparedTransfer, H::Digest)> = Vec::new();
    let mut included_bytes = 0usize;

    // Each accepted transaction adds its length-prefixed encoding to the body's encoded size, so
    // the block's size needs no pass over the body.
    let mut framed_bytes = 0usize;
    let mut candidates = candidates;

    let deadline = clock.current() + BUILD_TIMEOUT;

    loop {
        if candidates.is_empty() {
            break;
        }

        // A proposer chooses its body, so candidates that fail to decode or
        // prepare can be excluded. Keep one prepared candidate per transaction
        // while recording first-touched accounts.
        let prepare_span = info_span!(
            "application.execute.prepare",
            txs = candidates.len().traced()
        );
        let accounts_span =
            info_span!("application.execute.accounts", keys = tracing::field::Empty);
        let work_size = candidates.len();
        let (candidates_back, prepared, selection_back, touched) = strategy
            .spawn(work_size, {
                let accounts_span = accounts_span.clone();
                let mut selection = selection;
                move |s: S| {
                    let prepared: Vec<Candidate<H::Digest>> = prepare_span.in_scope(|| {
                        s.map_collect_vec(&candidates, |lazy| {
                            Candidate(lazy.get().and_then(|tx| {
                                executor::prepare_transfer(tx).map(|transfer| {
                                    (transfer, *tx.message_digest(), tx.encode_size())
                                })
                            }))
                        })
                    });
                    let touched = accounts_span.in_scope(|| selection.touch(&prepared));
                    (candidates, prepared, selection, touched)
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
            txs = prepared.len().traced(),
            dropped = tracing::field::Empty,
        );
        let work_size = prepared.len();
        let (selection_back, body_back, accepted_back, included_delta, framed_delta, dropped_bytes) =
            strategy
                .spawn(work_size, {
                    let span = select_span.clone();
                    let mut selection = selection;
                    let mut body = body;
                    let mut accepted = accepted;
                    move |_: S| {
                        span.in_scope(|| {
                            let applied = selection.apply(&prepared);
                            let mut included = 0usize;
                            let mut framed = 0usize;
                            let mut dropped = 0usize;
                            let mut candidates = candidates.into_iter();
                            for (prepared, &kept) in prepared.iter().zip(&applied) {
                                let transaction =
                                    candidates.next().expect("one candidate per transaction");
                                let Candidate(Some((transfer, digest, size))) = prepared else {
                                    continue;
                                };
                                if kept {
                                    included += size;
                                    framed += size.encode_size() + size;
                                    accepted.push((*transfer, *digest));
                                    body.push(transaction);
                                } else {
                                    dropped += size;
                                }
                            }
                            (selection, body, accepted, included, framed, dropped)
                        })
                    }
                })
                .await;
        selection = selection_back;
        body = body_back;
        accepted = accepted_back;
        included_bytes += included_delta;
        framed_bytes += framed_delta;
        select_span.record("dropped", dropped_bytes.traced());

        if clock.current() >= deadline {
            break;
        }

        // The mempool serves whole batches while they fit the headroom it is told about, so a
        // non-empty round that kept every candidate left less headroom than its next batch and
        // another request would come back empty unless the pool was dry and refilled meanwhile.
        if skip_final_refill && dropped_bytes == 0 {
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

    // A proposal that touched no account still merkleizes through a staged
    // batch, so stage one with no reads.
    let staged = match staged {
        Some(staged) => staged,
        None => stage_empty(unstaged.take().expect("nothing was staged")).await,
    };

    let settle_span = info_span!(
        "application.execute.settle",
        accounts = selection.keys().len().traced()
    );
    let work_size = selection.keys().len();
    let (slots, keys) = strategy
        .spawn(work_size, move |s: S| {
            settle_span.in_scope(|| {
                let keys = selection.keys().to_vec();
                let slots = executor::account_slots(selection.settle(&s));
                (slots, keys)
            })
        })
        .await;

    // History entries derive from the settled counts but are not needed by the state
    // merkleize, so their derivation and append run beside it instead of ahead of it.
    let apply_span = info_span!("application.execute.apply", txs = accepted.len().traced());
    let counts = history::tx_counts(&slots);
    let transaction_batch = strategy.spawn(accepted.len(), move |_: S| {
        apply_span.in_scope(|| {
            let entries = history::entries(accepted.into_iter(), &keys, &counts);
            apply_transaction_entries(transaction_batch, &entries)
        })
    });

    let body_size = body.len().encode_size() + framed_bytes;
    let block = finalize_child(
        staged,
        slots,
        transaction_batch,
        parent_floor,
        body.len(),
        "database merkleization must succeed",
    )
    .await;
    ProposalExecution {
        block,
        body: Arc::new(body),
        body_size,
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
    // A transaction that fails to decode or prepare rejects the whole body.
    let prepare_span = info_span!("application.execute.prepare", txs = body.len().traced());
    let work_size = body.len();
    let (transfers, digests) = strategy
        .spawn(work_size, move |s| {
            prepare_span.in_scope(|| prepare_lazy(&s, body.as_ref().as_slice()))
        })
        .await?;

    let transaction_count = transfers.len();
    let transfers = Arc::new(transfers);

    let accepted = Arc::clone(&transfers);
    let (staged, settled) = compute_with(state_batch, transfers, &strategy, move |keys, slots| {
        (slots, keys.to_vec())
    })
    .await;
    let (slots, keys) = settled.ok_or(STATIC_INVALID_TRANSACTION)?;

    // History entries derive from the settled counts but are not needed by the state
    // merkleize, so their derivation and append run beside it instead of ahead of it.
    let apply_span = info_span!("application.execute.apply", txs = accepted.len().traced());
    let counts = history::tx_counts(&slots);
    let transaction_batch = strategy.spawn(accepted.len(), move |_: S| {
        apply_span.in_scope(|| {
            let entries = history::entries(accepted.iter().copied().zip(digests), &keys, &counts);
            apply_transaction_entries(transaction_batch, &entries)
        })
    });

    Ok(finalize_child(
        staged,
        slots,
        transaction_batch,
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

    let accepted = Arc::clone(&transfers);
    let (staged, settled) = compute_with(state_batch, transfers, &strategy, move |keys, slots| {
        (slots, keys.to_vec())
    })
    .await;
    let (slots, keys) = settled.ok_or(STATIC_INVALID_TRANSACTION)?;
    let apply_span = info_span!("application.execute.apply", txs = accepted.len().traced());
    let counts = history::tx_counts(&slots);
    let transaction_batch = strategy.spawn(accepted.len(), move |_: S| {
        apply_span.in_scope(|| {
            let entries = history::entries(accepted.iter().copied().zip(digests), &keys, &counts);
            apply_transaction_entries(transaction_batch, &entries)
                .with_inactivity_floor(transaction_floor)
        })
    });

    // The replayed header supplies the transaction-history floor, and merkleize
    // rejects a floor below the parent's or past this block's commit. Any other
    // merkleize failure is a storage failure.
    match db::finalize_execution(staged, slots, transaction_batch).await {
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
/// pass it via [`core::future::ready`].
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
    let state_sync_range = non_empty_range!(*state.sync_boundary(), *state.bounds().tip.size);
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
