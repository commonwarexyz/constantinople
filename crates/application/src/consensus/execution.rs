//! Execution and commitment checks for consensus blocks.
//!
//! Proposing, verifying, and replaying a block run the same transition:
//!
//! ```text
//! parent body + parent notarization          block body
//!        |                                       |
//!        v                                       v
//! statuses (signed: authentic;            transaction digests
//!  tags: 2f + 1 approving reports)               |
//!        |                                       |
//!        v                                       |
//! authentic transfers, in order                  |
//!        |                                       |
//!        v                                       |
//! stage the accounts they touch                  |
//!        |                                       |
//!        v                                       |
//! apply each transfer or skip it ---> outcomes   |
//!        |                                       |
//!        v                                       v
//! staged state batch              transaction-history batch
//!        |                                       |
//!        +---------------> merkleized commitments
//! ```
//!
//! [`prepare_parent`] decides which of the parent's transactions are authentic
//! and [`execute`] applies them with the
//! [`SelectiveExecutor`](executor::SelectiveExecutor), which checks every
//! transfer against the state at the start: nonces are consumed in order,
//! debits must be affordable from the balance at the start, and credits never
//! fund a debit of the same block. A transfer that fails a check is skipped and
//! its outcome bit is clear. The block's own transactions are not executed: their
//! digests are appended to the transaction history, and they execute with the
//! next block.
//!
//! Account state is loaded with one awaited QMDB `stage` call, which returns
//! the loaded values plus a staged batch that retains each key's resolved
//! location, so the writes are `(staged read index, account)` updates that skip
//! key re-resolution when the staged batch merkleizes.
//!
//! Parallel fan-out comes from the supplied `Strategy`, which decides per
//! operation whether fanning out beats staying serial. QMDB reads stay on the
//! async path and are not run inside `Strategy` workers.

use super::{
    DUPLICATE_TRANSACTION, MALFORMED_TRANSACTION, Result,
    db::{
        self, StateBatch, StateStaged, StateUpdates, TransactionBatch, apply_transaction_digests,
    },
    reject_verify,
};
use crate::executor::{self, PreparedTransfer};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_glue::stateful::db::Merkleized as _;
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Storage, telemetry::traces::TracedExt as _,
};
use commonware_storage::{merkle::Family, mmr, qmdb::chain::Bounds, translator::EightCap};
use commonware_utils::non_empty_range;
use constantinople_primitives::{
    Account, Header, LazySignedTransaction, Outcomes, ParentNotarization, SignedTransaction,
};
use std::{collections::HashSet, sync::Arc};
use tracing::info_span;

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
    /// Whether each of the parent's transactions was applied.
    pub(super) outcomes: Outcomes,
    /// Number of the parent's transactions that were applied.
    pub(super) applied: usize,
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
    let work_size = transfers.len();
    let plan = {
        let transfers = Arc::clone(&transfers);
        strategy.spawn(work_size, move |_: S| {
            plan_span.in_scope(|| executor::execution_plan(&transfers))
        })
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
        .spawn(work_size, move |_: S| {
            build_span.in_scope(|| build_updates(plan, transfers, values))
        })
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

/// The transactions of a block that are authentic, ready to apply.
pub(super) struct ParentEntries {
    /// The authentic transactions, in block order.
    transfers: Vec<PreparedTransfer>,
    /// The position in the block of each of `transfers`.
    positions: Vec<u64>,
    /// The number of transactions in the block.
    len: u64,
}

impl ParentEntries {
    /// The entries of a block without transactions.
    pub(super) const fn empty() -> Self {
        Self {
            transfers: Vec::new(),
            positions: Vec::new(),
            len: 0,
        }
    }

    /// The number of transactions in the block.
    pub(super) const fn len(&self) -> u64 {
        self.len
    }
}

/// Decides which transactions of `body`, the body of a block's parent, are
/// authentic.
///
/// A signed transaction is authentic: its signature was checked before the
/// parent could be finalized. A transaction authenticated by tags is authentic
/// iff at least `2f + 1` of the reports in `notarization`, the notarization of
/// the parent that the block carries, approve it. Without a notarization none
/// is authentic.
pub(super) fn prepare_parent<C, H, S>(
    strategy: &S,
    body: &[LazySignedTransaction<H>],
    notarization: Option<&ParentNotarization<C>>,
    validators: u32,
) -> Result<ParentEntries>
where
    C: Digest,
    H: Hasher,
    S: Strategy,
{
    // Position among the transactions authenticated by tags, for those.
    let mut tagged = 0usize;
    let mut kinds = Vec::with_capacity(body.len());
    for lazy in body {
        let transaction = lazy.get().ok_or(MALFORMED_TRANSACTION)?;
        kinds.push(transaction.is_mac().then(|| {
            tagged += 1;
            tagged - 1
        }));
    }
    let statuses = notarization.map_or_else(
        || vec![false; tagged],
        |notarization| {
            constantinople_auth::status(notarization.certificate.reports(), validators, tagged)
        },
    );

    let work: Vec<_> = body.iter().zip(kinds).enumerate().collect();
    let prepared = strategy.map_collect_vec(work, |(position, (lazy, kind))| {
        if kind.is_some_and(|tagged| !statuses[tagged]) {
            return None;
        }
        let transaction = lazy.get().expect("decoded above");
        executor::prepare_transfer(transaction).map(|transfer| (transfer, position as u64))
    });
    let (transfers, positions) = prepared.into_iter().flatten().unzip();
    Ok(ParentEntries {
        transfers,
        positions,
        len: body.len() as u64,
    })
}

/// The digests of the transactions of `body`, in order.
///
/// A block lists a transaction at most once.
pub(super) fn body_digests<H, S>(
    strategy: &S,
    body: &[LazySignedTransaction<H>],
) -> Result<Vec<H::Digest>>
where
    H: Hasher,
    S: Strategy,
{
    let digests = strategy.try_map_collect_vec(body, |lazy| {
        lazy.get()
            .map(|transaction| *transaction.message_digest())
            .ok_or(MALFORMED_TRANSACTION)
    })?;
    let mut seen = HashSet::with_capacity(digests.len());
    if !digests.iter().all(|digest| seen.insert(*digest)) {
        return Err(DUPLICATE_TRANSACTION);
    }
    Ok(digests)
}

/// Applies the parent's authentic transactions to the parent's state and
/// appends the block's own transaction digests to the history.
///
/// `transaction_floor` is the inactivity floor of the block's transaction
/// history.
#[tracing::instrument(name = "application.execute", level = "info", skip_all)]
pub(super) async fn execute<E, H, S>(
    strategy: S,
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    transaction_floor: mmr::Location,
    parent: ParentEntries,
    digests: Vec<H::Digest>,
) -> BlockExecution<E, H, S>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    // The history only needs the digests, so it is built while accounts load.
    let append_span = info_span!("application.execute.append", txs = digests.len().traced());
    let append = strategy.spawn(digests.len(), move |_: S| {
        append_span.in_scope(|| {
            apply_transaction_digests(transaction_batch, &digests)
                .with_inactivity_floor(transaction_floor)
        })
    });

    let ParentEntries {
        transfers,
        positions,
        len,
    } = parent;
    let mut outcomes = Outcomes::zeroes(len);
    let (staged, updates) = if transfers.is_empty() {
        (stage_empty(state_batch).await, StateUpdates::new())
    } else {
        // Find the accounts the transfers touch.
        let accounts_span =
            info_span!("application.execute.accounts", keys = tracing::field::Empty);
        let work_size = transfers.len();
        let (mut selector, transfers, missing) = strategy
            .spawn(work_size, {
                let accounts_span = accounts_span.clone();
                move |_: S| {
                    accounts_span.in_scope(|| {
                        let mut selector = executor::SelectiveExecutor::new();
                        let missing = selector.begin_round(&transfers);
                        (selector, transfers, missing)
                    })
                }
            })
            .await;
        accounts_span.record("keys", missing.len().traced());

        // Load them as they were at the end of the parent.
        let keys: Vec<&_> = missing.iter().collect();
        let (values, staged) = state_batch
            .stage(&keys)
            .await
            .expect("account state loading must succeed");
        selector.register(&values);

        // Apply each transfer, or skip it.
        let select_span = info_span!("application.execute.select", txs = work_size.traced());
        let (updates, applied) = strategy
            .spawn(work_size, move |_: S| {
                select_span.in_scope(|| {
                    let applied = selector.apply(&transfers);
                    (selector.into_updates(), applied)
                })
            })
            .await;
        for (position, applied) in positions.into_iter().zip(applied) {
            outcomes.set(position, applied);
        }
        (staged, updates)
    };
    let applied = outcomes.count_ones() as usize;

    let (state, transactions) = db::finalize_execution(staged, updates, append)
        .await
        .expect("database merkleization must succeed");
    let state_sync_range = range_from_bounds(state.bounds());
    let transactions_range = range_from_bounds(transactions.bounds());

    BlockExecution {
        state,
        transactions,
        state_sync_range,
        transactions_range,
        outcomes,
        applied,
    }
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
