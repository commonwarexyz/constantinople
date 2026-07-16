//! Execution and commitment checks for consensus blocks.
//!
//! This module is the consensus-facing wrapper around the account executor. It
//! prepares block bodies, stages the state needed for account execution,
//! computes final account values and transaction-history updates, and returns
//! the merkleized commitments that consensus proposes, verifies, or applies.
//!
//! The important invariant is that account execution is based on block-start
//! state. Nonces and spends are sender-local, and credits from this block are
//! not available for spending until the block has finished executing. Because of
//! that rule, execution can build deterministic account effects from the
//! transfer list before looking at account state, then apply those effects to
//! loaded accounts all or nothing.
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
//! build account-touch execution plan                             |
//!        |                                                       |
//!        v                                                       |
//! stage unique senders/recipients/general accounts               |
//!        |                                                       |
//!        +--> discrete lane -- check nonce/debit, apply credits  |
//!        |                                                       |
//!        +--> general lane -- check/apply each account once      |
//!        |                                                       |
//!        v                                                       |
//! indexed StateUpdates ------------------------------------------+
//!        |
//!        v
//! staged state batch + transaction-history batch
//!        |
//!        v
//! merkleized commitments
//! ```
//!
//! The account-touch plan has two lanes. The discrete lane contains only
//! transfers whose non-self sender and recipient accounts are unique in the
//! block, so each loaded account produces exactly one final write. The general
//! lane contains every transfer that touches a contended account. It aggregates
//! one effect per affected account: sent nonces, non-self debit total,
//! self-transfer affordability floor, and recipient credit total. The account is
//! loaded once, checked once, and written once. Credits are added after debit
//! affordability is checked, so an in-block credit cannot fund an in-block
//! spend. If any debit check or credit addition fails in either lane, the whole
//! batch is rejected; there is no partial execution state to reconcile.
//!
//! Account state is loaded with one awaited QMDB `stage` call, which returns
//! the loaded values plus a staged batch that retains each key's resolved
//! location. Every staged account produces exactly one final value, so the
//! writes are `(staged read index, account)` updates that skip key
//! re-resolution when the staged batch merkleizes. Transaction history is
//! append-only: transaction digests are appended in block order, so the
//! transaction-history commitment still reflects block order.
//!
//! Proposing, verifying, and applying certified blocks all use this same
//! transition. `execute_proposal` builds a proposal best effort: malformed or
//! inapplicable candidates are dropped individually, the block tops up from
//! the mempool toward the proposal budget, and an empty selection proposes an
//! empty block so an idle chain keeps making progress — a proposal is always
//! produced.
//! `execute_body` prepares a proposed body, recomputes execution, and compares
//! the resulting commitments to the header. Certified apply shallow-clones the
//! block's lazy body (per-transaction handles whose decode cache stays shared)
//! to move it into the pool's prepare job, without building an intermediate
//! materialized transaction vector. Preparing a transfer does
//! not invent a second transaction identifier: it reads the transaction's sealed
//! message digest. For lazily encoded block bodies, whichever consumer first
//! materializes the transaction computes that seal once and caches the decoded
//! transaction for the other consumers.
//!
//! Parallel fan-out comes from the supplied `Strategy`, which decides per
//! operation whether fanning out beats staying serial. The strategy drives
//! preparation and QMDB merkleization beneath the batch APIs; per-account
//! mutation is a few instructions per account, so it runs as one serial pass.
//! QMDB reads stay on the async path and are not run inside `Strategy`
//! workers.

use super::{
    MALFORMED_TRANSACTION, Result, STATIC_INVALID_TRANSACTION,
    body::PreparedBody,
    db::{
        self, StateBatch, StateStaged, StateUpdates, TransactionBatch, apply_transaction_digests,
    },
    reject_verify,
};
use crate::executor::{self, PreparedTransfer};
use commonware_codec::EncodeSize as _;
use commonware_consensus::types::Round;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_glue::stateful::db::Merkleized as _;
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Storage, telemetry::traces::TracedExt as _,
};
use commonware_storage::{merkle::Family, mmr, qmdb::batch_chain::Bounds, translator::EightCap};
use commonware_utils::non_empty_range;
use constantinople_mempool::TransactionSource;
use constantinople_primitives::{Account, Header, LazySignedTransaction, SignedTransaction};
use std::{
    future::{Future, ready},
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tracing::{Instrument as _, info_span};

pub(super) struct ProposalExecution<E, H, S>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    pub(super) block: BlockExecution<E, H, S>,
    pub(super) body: Vec<SignedTransaction<H>>,
}

pub(super) struct BlockExecution<E, H, S>
where
    E: BufferPooler + Storage + Clock + Metrics,
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
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    pub(super) fn into_merkleized(self) -> db::MerkleizedDatabases<E, H, S> {
        (self.state, self.transactions)
    }
}

/// Stages and executes a batch from a deterministic account-touch plan.
///
/// Consumes the batch to stage every account the plan touches, then computes
/// each staged account's final value. Unique transfers use the discrete lane.
/// Transfers touching contended accounts use the general lane, which loads each
/// affected account once and applies its accumulated effect. Returns the staged
/// batch alongside `None` if any transfer fails its nonce or balance check or
/// overflows a recipient (the whole batch is rejected).
#[tracing::instrument(name = "application.execute.compute", level = "info", skip_all)]
pub async fn compute<E, H, S>(
    batch: StateBatch<E, H, EightCap, S>,
    transfers: Arc<Vec<PreparedTransfer>>,
    strategy: &S,
) -> (StateStaged<E, H, EightCap, S>, Option<StateUpdates>)
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let plan_span = info_span!("application.execute.plan", txs = transfers.len().traced());
    let plan = {
        let transfers = Arc::clone(&transfers);
        strategy.spawn(move |_: S| plan_span.in_scope(|| executor::execution_plan(&transfers)))
    }
    .await;
    let Some(plan) = plan else {
        return (stage_empty(batch).await, None);
    };
    let (staged, values) = load_accounts(batch, &plan.discrete, &plan.general).await;
    let build_span = info_span!(
        "application.execute.build",
        accounts = values.len().traced()
    );
    let updates = strategy
        .spawn(move |_: S| build_span.in_scope(|| build_updates(plan, transfers, values)))
        .await;
    (staged, updates)
}

/// Stages a batch with no reads, for paths that reject or skip execution.
pub(super) async fn stage_empty<E, H, S>(
    batch: StateBatch<E, H, EightCap, S>,
) -> StateStaged<E, H, EightCap, S>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let (_, staged) = batch
        .stage(&[])
        .await
        .expect("staging no reads must succeed");
    staged
}

struct LoadedAccounts {
    /// Staged values in read order: senders, then recipients, then general.
    values: Vec<Option<Account>>,
    sender_len: usize,
    recipient_len: usize,
}

impl LoadedAccounts {
    const fn len(&self) -> usize {
        self.values.len()
    }

    fn senders(&self) -> &[Option<Account>] {
        &self.values[..self.sender_len]
    }

    fn recipients(&self) -> &[Option<Account>] {
        &self.values[self.sender_len..self.sender_len + self.recipient_len]
    }

    fn general(&self) -> &[Option<Account>] {
        &self.values[self.sender_len + self.recipient_len..]
    }
}

async fn load_accounts<E, H, S>(
    batch: StateBatch<E, H, EightCap, S>,
    discrete: &executor::DiscreteWorkload,
    general: &executor::GeneralWorkload,
) -> (StateStaged<E, H, EightCap, S>, LoadedAccounts)
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let sender_len = discrete.sender_keys.len();
    let recipient_len = discrete.recipient_keys.len();
    let general_len = general.account_keys().len();
    let keys = discrete
        .sender_keys
        .iter()
        .chain(&discrete.recipient_keys)
        .chain(general.account_keys())
        .collect::<Vec<_>>();

    // One staged QMDB read lets the storage layer sort and batch journal
    // positions across all lanes, and each key's resolved location is reused
    // when the staged batch merkleizes.
    let (values, staged) = batch
        .stage(keys.as_slice())
        .await
        .expect("account state loading must succeed");
    assert_eq!(values.len(), sender_len + recipient_len + general_len);
    (
        staged,
        LoadedAccounts {
            values,
            sender_len,
            recipient_len,
        },
    )
}

/// Computes the final value of every staged account.
///
/// Update indices follow the staged read order (discrete senders, discrete
/// recipients, then general accounts), and every staged account produces
/// exactly one final value, so the writes enumerate directly into indexed
/// updates. The per-account arithmetic is a few instructions, so one serial
/// pass into the updates vector beats parallel fan-out and its intermediate
/// buffers.
fn build_updates(
    plan: executor::ExecutionPlan,
    transfers: Arc<Vec<PreparedTransfer>>,
    values: LoadedAccounts,
) -> Option<StateUpdates> {
    let executor::ExecutionPlan { discrete, general } = &plan;
    let mut updates = StateUpdates::with_capacity(values.len());

    // Discrete senders: one write per transfer, in transfer order.
    for (transfer_index, value) in discrete.transfers.iter().zip(values.senders()) {
        let transfer = &transfers[*transfer_index];
        let mut account = value.unwrap_or_default();
        if account.balance < transfer.value || !account.nonce.consume(transfer.nonce) {
            return None;
        }
        if transfer.sender != transfer.recipient {
            account.balance -= transfer.value;
        }
        updates.push((updates.len(), Some(account)));
    }

    // Discrete recipients: one write per non-self transfer, in transfer
    // order. The zip is exhaustive because recipient_keys was built from
    // exactly the non-self transfers (asserted against the staged read count
    // in load_accounts).
    let non_self = discrete.transfers.iter().filter(|&&transfer_index| {
        transfers[transfer_index].sender != transfers[transfer_index].recipient
    });
    for (transfer_index, value) in non_self.zip(values.recipients()) {
        let transfer = &transfers[*transfer_index];
        let mut account = value.unwrap_or_default();
        executor::apply_credit(&mut account, transfer.value)?;
        updates.push((updates.len(), Some(account)));
    }

    // General lane: one write per affected account, in account order.
    if !general.is_empty() {
        let written = executor::apply_general_accounts(values.general(), general, &transfers)?;
        for account in written {
            updates.push((updates.len(), Some(account)));
        }
    }

    assert_eq!(updates.len(), values.len());
    Some(updates)
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
/// executes against block-start account state in block order, and any
/// transaction that does not apply — malformed encoding, stale nonce
/// (typically a transaction that already landed in an ancestor block),
/// unaffordable value, or credit overflow — is dropped instead of dooming the
/// proposal. Each refill asks the mempool for the block's remaining headroom
/// (it knows the proposal budget; we report the bytes already included), so
/// the block fills toward the budget even when the seed was small. `stage` +
/// `expand` load each round's new accounts incrementally. The loop ends when
/// the mempool has nothing left that fits or the build deadline passes. The
/// surviving body re-executes cleanly under all-or-nothing verification with
/// identical account writes.
///
/// The transaction-history append is pipelined per round: a round's accepted
/// digests append on the strategy's pool while the next round refills,
/// prepares, stages, and selects, and the final round's append drains
/// concurrently with the state merkleize inside `finalize_child` (chunked
/// appends fold to exactly the accepted digests in block order). An empty
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
    candidates: Vec<SignedTransaction<H>>,
    input: &mut I,
) -> ProposalExecution<E, H, S>
where
    E: BufferPooler + Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
    I: TransactionSource<C, P, H> + Sync,
{
    let mut unstaged = Some(state_batch);
    let mut staged: Option<StateStaged<E, H, EightCap, S>> = None;
    let mut selector = executor::SelectiveExecutor::new();
    let mut body: Vec<SignedTransaction<H>> = Vec::new();
    let mut included_bytes = 0usize;
    let mut candidates = candidates;

    // The history append for a round's accepted digests runs on the pool
    // while later rounds refill, prepare, stage, and select; rounds chain on
    // the batch, so the previous append is joined before the next is spawned.
    let mut transaction_batch = Some(transaction_batch);
    let mut pending_append: Option<PendingAppend<E, H, S>> = None;
    let deadline = clock.current() + BUILD_TIMEOUT;

    loop {
        if candidates.is_empty() {
            break;
        }

        // Prepare the candidates on the pool: a proposer chooses its body,
        // so a candidate that fails preparation is simply excluded (unlike
        // verification's all-or-nothing preparation). Results stay
        // index-aligned with the candidate vector; the same job compacts the
        // well-formed transfers and records first-touched accounts.
        let prepare_span = info_span!(
            "application.execute.prepare",
            txs = candidates.len().traced()
        );
        let accounts_span =
            info_span!("application.execute.accounts", keys = tracing::field::Empty);
        let (candidates_back, prepared, transfers, selector_back, missing) = strategy
            .spawn({
                let accounts_span = accounts_span.clone();
                let mut selector = selector;
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
                    let missing = accounts_span.in_scope(|| selector.begin_round(&transfers));
                    (candidates, prepared, transfers, selector, missing)
                }
            })
            .await;
        candidates = candidates_back;
        selector = selector_back;
        accounts_span.record("keys", missing.len().traced());

        // Load block-start values for accounts this round touches for the
        // first time; later rounds expand the same staged read space, whose
        // indices continue exactly where the selector's dense table does.
        if !missing.is_empty() {
            let stage_span = info_span!("application.execute.stage", keys = missing.len().traced());
            async {
                let keys: Vec<&_> = missing.iter().collect();
                if let Some(batch) = unstaged.take() {
                    let (values, next) = batch
                        .stage(&keys)
                        .await
                        .expect("account state loading must succeed");
                    selector.register(&values);
                    staged = Some(next);
                } else {
                    let (_, values, next) = staged
                        .take()
                        .expect("staged batch exists after the first round")
                        .expand(&keys)
                        .await
                        .expect("account state loading must succeed");
                    selector.register(&values);
                    staged = Some(next);
                }
            }
            .instrument(stage_span)
            .await;
        }

        // Apply in block order and fold the survivors into the body, all in
        // one pool job so the split is attributed and the candidates move
        // straight into the body.
        let select_span = info_span!(
            "application.execute.select",
            txs = transfers.len().traced(),
            dropped = tracing::field::Empty,
        );
        let (selector_back, body_back, chunk, included_delta, dropped_bytes) = strategy
            .spawn({
                let span = select_span.clone();
                let mut selector = selector;
                let mut body = body;
                move |_: S| {
                    span.in_scope(|| {
                        let applied = selector.apply(&transfers);
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
                        (selector, body, chunk, included, dropped)
                    })
                }
            })
            .await;
        selector = selector_back;
        body = body_back;
        included_bytes += included_delta;
        select_span.record("dropped", dropped_bytes.traced());

        // Chain this round's history append on the pool; it overlaps the
        // refill round-trip and the next round's prepare, stage, and select.
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
            pending_append = Some(Box::pin(strategy.spawn(move |_: S| {
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

    // The final account values are computed on this task while the last
    // round's history append drains on the pool.
    let updates_span = info_span!(
        "application.execute.updates",
        accounts = tracing::field::Empty
    );
    let updates = updates_span.in_scope(|| selector.into_updates());
    updates_span.record("accounts", updates.len().traced());

    // The last append drains concurrently with the state merkleize inside
    // `finalize_child`; appending zero digests is an identity, so an empty
    // selection skips the pool round-trip entirely.
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
            updates,
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
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let prepare_span = info_span!("application.execute.prepare", txs = body.len().traced());
    let (transfers, digests) = strategy
        .spawn(move |s| prepare_span.in_scope(|| prepare_lazy(&s, body.as_ref().as_slice())))
        .await?;

    let transaction_count = transfers.len();
    let transfers = Arc::new(transfers);

    // The transaction-history append has no dependency on state execution, so
    // it runs on the pool concurrently with compute.
    let apply_span = info_span!("application.execute.apply", txs = digests.len().traced());
    let apply = strategy.spawn(move |_: S| {
        apply_span.in_scope(|| apply_transaction_digests(transaction_batch, &digests))
    });
    let (staged, updates) = compute(state_batch, transfers, &strategy).await;

    // Join the append before surfacing a rejection so its panics propagate
    // and no job outlives this call.
    let transaction_batch = apply.await;
    let state_updates = updates.ok_or(STATIC_INVALID_TRANSACTION)?;

    Ok(finalize_child(
        staged,
        state_updates,
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
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let transfers = Arc::new(transfers);

    // The transaction-history append has no dependency on state execution, so
    // it runs on the pool concurrently with compute.
    let apply_span = info_span!("application.execute.apply", txs = digests.len().traced());
    let apply = strategy.spawn(move |_: S| {
        apply_span.in_scope(|| {
            apply_transaction_digests(transaction_batch, &digests)
                .with_inactivity_floor(transaction_floor)
        })
    });
    let (staged, updates) = compute(state_batch, transfers, &strategy).await;

    // Join the append before surfacing a rejection so its panics propagate
    // and no job outlives this call.
    let transaction_batch = apply.await;
    let state_updates = updates.ok_or(STATIC_INVALID_TRANSACTION)?;

    db::finalize_execution(staged, state_updates, ready(transaction_batch))
        .await
        .map_err(|_| STATIC_INVALID_TRANSACTION)
}

pub(super) fn commitments_match<E, C, P, H, S>(
    header: &Header<C, H::Digest, P>,
    execution: &BlockExecution<E, H, S>,
) -> bool
where
    E: BufferPooler + Storage + Clock + Metrics,
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
    state_updates: StateUpdates,
    transaction_batch: impl Future<Output = TransactionBatch<E, H, S>>,
    parent_floor: mmr::Location,
    transaction_count: usize,
    expect_message: &'static str,
) -> BlockExecution<E, H, S>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let transaction_batch =
        async move { transaction_batch.await.with_inactivity_floor(parent_floor) };
    let (state, transactions) =
        db::finalize_execution(state_staged, state_updates, transaction_batch)
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

fn range_from_bounds<F>(bounds: &Bounds<F>) -> commonware_utils::range::NonEmptyRange<u64>
where
    F: Family,
{
    non_empty_range!(*bounds.inactivity_floor, bounds.total_size)
}

#[cfg(test)]
mod tests {
    use super::range_from_bounds;
    use commonware_storage::{mmr, qmdb::batch_chain::Bounds};
    use commonware_utils::non_empty_range;

    #[test]
    fn range_comes_from_qmdb_bounds() {
        let bounds = Bounds {
            base_size: 7,
            db_size: 9,
            total_size: 15,
            ancestors: Vec::new(),
            inactivity_floor: mmr::Location::new(11),
        };

        assert_eq!(range_from_bounds(&bounds), non_empty_range!(11, 15));
    }
}
