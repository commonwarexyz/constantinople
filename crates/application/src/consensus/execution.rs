//! Execution and commitment checks for consensus blocks.
//!
//! This module is the consensus-facing wrapper around the account executor. It
//! prepares block bodies, loads the state needed for account execution, writes
//! account and transaction-history updates into QMDB batches, and returns the
//! merkleized commitments that consensus proposes, verifies, or applies.
//!
//! Preparation partitions a body into two lanes: transfers, executed by the
//! transfer executor described below, and payment-channel operations, executed
//! by the `channel` lane. Both run against block-start state and their writes
//! are folded into the same state batch; a block whose two lanes write the same
//! account is rejected (see `lanes_conflict`). The rest of this module's
//! documentation describes the transfer lane.
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
//!        +--> discrete lane -- load unique senders/recipients    |
//!        |                   -- check nonce/debit, apply credits |
//!        |                                                       |
//!        +--> general lane -- aggregate account effects          |
//!        |                  -- get_many affected accounts        |
//!        |                  -- check/apply each account once     |
//!        |                                                       |
//!        v                                                       |
//! StateWrites ---------------------------------------------------+
//!        |
//!        v
//! state batch + transaction-history batch
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
//! spend. Account values are loaded with awaited QMDB `get_many` calls before
//! `Strategy` workers split CPU-only account mutation. If any debit check or
//! credit addition fails in either lane, the whole batch is rejected; there is no
//! partial execution state to reconcile.
//!
//! A single execution plan separates the workload into these lanes before any
//! state is loaded. This keeps independent work on the cheap path even in mixed
//! blocks, while any contended sender or recipient is handled by the general
//! aggregation rules.
//!
//! Proposing, verifying, and applying certified blocks all use this same
//! transition. `execute_proposal` prepares locally selected transactions and
//! falls back to an empty proposal if the selected body is malformed or invalid.
//! `execute_body` prepares a proposed body, recomputes execution, and compares
//! the resulting commitments to the header. Certified apply prepares from the
//! block's lazy body by reference, so it does not clone the block body or build
//! an intermediate materialized transaction vector. Preparing a transfer does
//! not invent a second transaction identifier: it reads the transaction's sealed
//! message digest. For lazily encoded block bodies, whichever consumer first
//! materializes the transaction computes that seal once and caches the decoded
//! transaction for the other consumers.
//!
//! State writes are returned as independent shard write vectors. For the
//! unordered state database, the state root depends on the final key/value set,
//! not on the order in which these vectors are folded into the QMDB batch.
//! Transaction history is different: transaction digests are appended in block
//! order, so the transaction-history commitment still reflects block order.
//!
//! Parallel fan-out comes from the supplied `Strategy`, so this file avoids
//! fixed worker counts. The same strategy drives preparation, CPU account
//! mutation, and QMDB merkleization beneath the batch APIs. QMDB reads stay on
//! the async path and are not run inside `Strategy` workers.

use super::{
    MALFORMED_TRANSACTION, Result, STATIC_INVALID_TRANSACTION,
    body::PreparedBody,
    channel::{self, ChannelWrites, PreparedChannelOp, prepare_channel_op},
    db::{
        self, StateBatch, TransactionBatch, apply_channel_writes, apply_shard_maps,
        apply_transaction_digests,
    },
    history::parent_transactions_inactivity_floor,
    reject_verify,
};
use crate::executor::{self, PreparedTransfer, ShardWrites};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_glue::stateful::db::Merkleized as _;
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{merkle::Family, mmr, qmdb::batch_chain::Bounds, translator::EightCap};
use commonware_utils::non_empty_range;
use constantinople_primitives::{
    Account, AccountKey, Header, LazySignedTransaction, Operation, SealedBlock, SignedTransaction,
};
use core::{mem::MaybeUninit, ops::Range};
use std::collections::HashSet;
use tracing::{Instrument as _, info_span};

/// A block body prepared into its two execution lanes.
///
/// `digests` holds every transaction's sealed digest in block order (both
/// lanes), so transaction history is appended in order regardless of lane.
pub struct PreparedBatch<H: Hasher> {
    pub transfers: Vec<PreparedTransfer>,
    pub channel_ops: Vec<PreparedChannelOp>,
    pub digests: Vec<H::Digest>,
}

/// One prepared transaction, routed to its execution lane.
///
/// The channel variant is boxed because channel operations are rare and much
/// larger than a transfer; boxing keeps the common transfer case small in the
/// prepared-item vector.
enum PreparedItem {
    Transfer(PreparedTransfer),
    ChannelOp(Box<PreparedChannelOp>),
}

/// Prepares one transaction into its lane plus its sealed digest.
///
/// Returns `None` if the sender key fails to decode (malformed).
fn prepare_item<H>(tx: &SignedTransaction<H>) -> Option<(PreparedItem, H::Digest)>
where
    H: Hasher,
{
    let digest = *tx.message_digest();
    let item = match tx.value().op() {
        Operation::Transfer { .. } => PreparedItem::Transfer(executor::prepare_transfer(tx)?),
        Operation::OpenChannel { .. } | Operation::CloseChannel { .. } => {
            PreparedItem::ChannelOp(Box::new(prepare_channel_op(tx)?))
        }
    };
    Some((item, digest))
}

/// Splits prepared items into the transfer and channel lanes, preserving block
/// order for digests.
fn partition<H: Hasher>(items: Vec<(PreparedItem, H::Digest)>) -> PreparedBatch<H> {
    // The common block is all transfers; preallocate that lane. Channel ops are
    // rare, so leave their lane to grow from empty.
    let mut transfers = Vec::with_capacity(items.len());
    let mut channel_ops = Vec::new();
    let mut digests = Vec::with_capacity(items.len());
    for (item, digest) in items {
        digests.push(digest);
        match item {
            PreparedItem::Transfer(transfer) => transfers.push(transfer),
            PreparedItem::ChannelOp(op) => channel_ops.push(*op),
        }
    }
    PreparedBatch {
        transfers,
        channel_ops,
        digests,
    }
}

/// Prepares an already materialized block body into both lanes.
pub fn prepare_signed_block<H, S>(
    strategy: &S,
    txs: &[SignedTransaction<H>],
) -> Option<PreparedBatch<H>>
where
    H: Hasher,
    S: Strategy,
{
    let items: Option<Vec<(PreparedItem, H::Digest)>> = strategy
        .map_collect_vec(txs.iter(), |tx| prepare_item(tx))
        .into_iter()
        .collect();
    items.map(partition)
}

/// Prepares a lazily-encoded block body into both lanes.
pub(super) fn prepare_lazy_block<H, S>(
    strategy: &S,
    body: &[LazySignedTransaction<H>],
) -> Result<PreparedBatch<H>>
where
    H: Hasher,
    S: Strategy,
{
    let items: Option<Vec<(PreparedItem, H::Digest)>> = strategy
        .map_collect_vec(body.iter(), |lazy| prepare_item(lazy.get()?))
        .into_iter()
        .collect();
    items.map(partition).ok_or(MALFORMED_TRANSACTION)
}

/// Whether any account key is written by both lanes (a same-block conflict).
fn lanes_conflict(transfers: &db::StateWrites, channel_ops: &ChannelWrites) -> bool {
    // The overwhelmingly common block has no channel ops; skip building the
    // transfer key set entirely in that case.
    if channel_ops.is_empty() {
        return false;
    }
    let transfer_keys: HashSet<AccountKey> = transfers
        .shards
        .iter()
        .flatten()
        .map(|(key, _)| *key)
        .collect();
    channel_ops
        .iter()
        .any(|(key, _)| transfer_keys.contains(key))
}

/// Runs both lanes against block-start state and returns their writes.
///
/// Returns `None` if either lane rejects the batch, or if the two lanes write
/// the same account in one block (which would race on a single key).
async fn execute_lanes<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    strategy: &S,
    prepared: &PreparedBatch<H>,
) -> Option<(db::StateWrites, ChannelWrites)>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let transfer_writes = compute(batch, strategy, &prepared.transfers).await?;
    let channel_writes = channel::apply_channel_ops(batch, &prepared.channel_ops).await?;
    if lanes_conflict(&transfer_writes, &channel_writes) {
        return None;
    }
    Some((transfer_writes, channel_writes))
}

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

/// Loads and executes a batch from a deterministic account-touch plan.
///
/// Unique transfers use the discrete lane. Transfers touching contended
/// accounts use the general lane, which loads each affected account once and
/// applies its accumulated effect. Returns `None` if any transfer fails its
/// nonce or balance check or overflows a recipient (the whole batch is
/// rejected). The batch is only borrowed for reads, so the caller may move it
/// afterward to apply the writes.
pub async fn compute<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    strategy: &S,
    transfers: &[PreparedTransfer],
) -> Option<db::StateWrites>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    if transfers.is_empty() {
        return Some(db::StateWrites::new(Vec::new()));
    }

    let plan = executor::execution_plan(transfers)?;
    let executor::ExecutionPlan { discrete, general } = &plan;
    let values = load_accounts(batch, discrete, general).await;
    let mut writes = Vec::new();
    if !discrete.transfers.is_empty() {
        writes.extend(apply_discrete(
            strategy,
            discrete,
            &values.senders,
            &values.recipients,
        )?);
    }
    if !general.is_empty() {
        writes.push(executor::apply_general_accounts(
            values.general,
            general,
            transfers,
        )?);
    }
    Some(db::StateWrites::new(writes))
}

struct LoadedAccounts {
    senders: Vec<Option<Account>>,
    recipients: Vec<Option<Account>>,
    general: Vec<Option<Account>>,
}

async fn load_accounts<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    discrete: &executor::DiscreteWorkload<'_>,
    general: &executor::GeneralWorkload<'_>,
) -> LoadedAccounts
where
    E: Storage + Clock + Metrics,
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
        .copied()
        .collect::<Vec<_>>();

    // One QMDB read lets the storage layer sort and batch journal positions
    // across both lanes.
    let values = batch
        .get_many(keys.as_slice())
        .await
        .expect("account state loading must succeed");
    let mut values = values.into_iter();
    let senders = values.by_ref().take(sender_len).collect();
    let recipients = values.by_ref().take(recipient_len).collect();
    let general = values.by_ref().take(general_len).collect();
    assert_eq!(values.len(), 0);
    LoadedAccounts {
        senders,
        recipients,
        general,
    }
}

fn apply_discrete<S>(
    strategy: &S,
    plan: &executor::DiscreteWorkload<'_>,
    sender_values: &[Option<Account>],
    recipient_values: &[Option<Account>],
) -> Option<Vec<ShardWrites>>
where
    S: Strategy,
{
    let sender_writes = apply_writes(
        strategy,
        plan.transfers.as_slice(),
        sender_values,
        apply_senders,
    )?;

    let mut writes = vec![sender_writes];
    if !plan.recipient_keys.is_empty() {
        let dense = plan.recipient_keys.len() == plan.transfers.len();
        let recipient_writes = if dense {
            apply_writes(
                strategy,
                plan.transfers.as_slice(),
                recipient_values,
                apply_dense_recipients,
            )
        } else {
            apply_sparse_recipients(plan.transfers.as_slice(), recipient_values)
        }?;
        writes.push(recipient_writes);
    }

    Some(writes)
}

// Shared sender/recipient callback shape used after QMDB values are loaded.
// `Strategy` workers only apply CPU mutations; they never block on DB reads.
type ApplyFn =
    fn(&[&PreparedTransfer], &[Option<Account>], &mut [MaybeUninit<(AccountKey, Account)>]) -> bool;

fn apply_writes<S>(
    strategy: &S,
    transfers: &[&PreparedTransfer],
    values: &[Option<Account>],
    apply: ApplyFn,
) -> Option<ShardWrites>
where
    S: Strategy,
{
    let chunks = chunk_count(strategy, transfers.len());
    assert_eq!(values.len(), transfers.len());

    let mut writes = uninit_vec(transfers.len());
    let valid = if chunks <= 1 {
        apply(transfers, values, &mut writes)
    } else {
        apply_write_chunks(strategy, transfers, values, &mut writes, chunks, apply)
    };
    valid.then(|| initialized_copy_vec(writes))
}

fn apply_write_chunks<S>(
    strategy: &S,
    transfers: &[&PreparedTransfer],
    values: &[Option<Account>],
    writes: &mut [MaybeUninit<(AccountKey, Account)>],
    chunks: usize,
    apply: ApplyFn,
) -> bool
where
    S: Strategy,
{
    assert_eq!(transfers.len(), values.len());
    assert_eq!(transfers.len(), writes.len());

    let ranges = chunk_ranges(transfers.len(), chunks);
    let mut remaining_writes = writes;
    let mut work = Vec::with_capacity(ranges.len());
    for range in ranges {
        let len = range.end - range.start;
        let (chunk_writes, rest) = remaining_writes.split_at_mut(len);
        work.push((&transfers[range.clone()], &values[range], chunk_writes));
        remaining_writes = rest;
    }
    assert!(remaining_writes.is_empty());

    strategy
        .map_collect_vec(work, |(transfers, values, writes)| {
            apply(transfers, values, writes)
        })
        .into_iter()
        .all(core::convert::identity)
}

fn apply_senders(
    transfers: &[&PreparedTransfer],
    values: &[Option<Account>],
    writes: &mut [MaybeUninit<(AccountKey, Account)>],
) -> bool {
    for ((transfer, value), write) in transfers.iter().zip(values).zip(writes) {
        let mut account = (*value).unwrap_or_default();
        if account.balance < transfer.value || !account.nonce.consume(transfer.nonce) {
            return false;
        }
        if transfer.sender != transfer.recipient {
            account.balance -= transfer.value;
        }
        write.write((transfer.sender, account));
    }
    true
}

fn apply_dense_recipients(
    transfers: &[&PreparedTransfer],
    values: &[Option<Account>],
    writes: &mut [MaybeUninit<(AccountKey, Account)>],
) -> bool {
    for ((transfer, value), write) in transfers.iter().zip(values).zip(writes) {
        let mut account = (*value).unwrap_or_default();
        if executor::apply_credit(&mut account, transfer.value).is_none() {
            return false;
        }
        write.write((transfer.recipient, account));
    }
    true
}

fn apply_sparse_recipients(
    transfers: &[&PreparedTransfer],
    values: &[Option<Account>],
) -> Option<ShardWrites> {
    let mut values = values.iter();
    let mut writes = ShardWrites::with_capacity(values.size_hint().0);
    for transfer in transfers {
        if transfer.sender == transfer.recipient {
            continue;
        }
        let value = values.next().expect("one value per non-self recipient");
        let mut account = (*value).unwrap_or_default();
        executor::apply_credit(&mut account, transfer.value)?;
        writes.push((transfer.recipient, account));
    }
    assert!(values.next().is_none());
    Some(writes)
}

fn chunk_count<S>(strategy: &S, items: usize) -> usize
where
    S: Strategy,
{
    strategy.parallelism_hint().max(1).min(items.max(1))
}

fn chunk_ranges(items: usize, chunks: usize) -> Vec<Range<usize>> {
    if items == 0 {
        return Vec::new();
    }

    let chunks = chunks.max(1).min(items);
    (0..chunks)
        .map(|chunk| {
            let start = items * chunk / chunks;
            let end = items * (chunk + 1) / chunks;
            start..end
        })
        .collect()
}

fn uninit_vec<T>(len: usize) -> Vec<MaybeUninit<T>> {
    let mut values = Vec::with_capacity(len);
    // SAFETY: `MaybeUninit<T>` does not need initialization.
    unsafe {
        values.set_len(len);
    }
    values
}

fn initialized_copy_vec<T: Copy>(mut values: Vec<MaybeUninit<T>>) -> Vec<T> {
    let ptr = values.as_mut_ptr().cast::<T>();
    let len = values.len();
    let capacity = values.capacity();
    core::mem::forget(values);
    // SAFETY: callers only reach this after every slot has been initialized,
    // and `T: Copy` cannot require drop glue for partially initialized failure paths.
    unsafe { Vec::from_raw_parts(ptr, len, capacity) }
}

/// Executes a proposal's candidate transactions all or nothing.
///
/// If every candidate executes cleanly the block includes them all. If any
/// candidate is malformed, fails its nonce or balance check, or overflows a
/// recipient, the whole batch is dropped and an empty block is proposed so the
/// chain still makes progress.
pub(super) async fn execute_proposal<E, C, P, H, S>(
    strategy: S,
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent: &SealedBlock<C, P, H>,
    transactions: Vec<SignedTransaction<H>>,
) -> ProposalExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    let prepared = prepare_signed_block(&strategy, &transactions);

    let outcome = match prepared {
        Some(prepared) if !(prepared.transfers.is_empty() && prepared.channel_ops.is_empty()) => {
            execute_lanes(&state_batch, &strategy, &prepared)
                .instrument(info_span!("application.execute.compute"))
                .await
                .map(|writes| (transactions, prepared.digests, writes))
        }
        _ => None,
    };

    let (body, digests, state_batch) = match outcome {
        Some((body, digests, (transfer_writes, channel_writes))) => {
            let state_batch = apply_shard_maps(state_batch, transfer_writes);
            let state_batch = apply_channel_writes(state_batch, channel_writes);
            (body, digests, state_batch)
        }
        None => (Vec::new(), Vec::new(), state_batch),
    };

    let transaction_batch = info_span!("application.execute.apply")
        .in_scope(|| apply_transaction_digests(transaction_batch, &digests));

    ProposalExecution {
        block: finalize_child(
            state_batch,
            transaction_batch,
            parent,
            body.len(),
            "database merkleization must succeed",
        )
        .await,
        body,
    }
}

pub(super) async fn execute_body<E, C, P, H, S>(
    strategy: S,
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent: &SealedBlock<C, P, H>,
    body: PreparedBody<H>,
) -> Result<BlockExecution<E, H, S>>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    let prepared = info_span!("application.execute.prepare")
        .in_scope(|| prepare_lazy_block(&strategy, body.as_ref().as_slice()))?;

    let (transfer_writes, channel_writes) = execute_lanes(&state_batch, &strategy, &prepared)
        .instrument(info_span!("application.execute.compute"))
        .await
        .ok_or(STATIC_INVALID_TRANSACTION)?;

    let transaction_count = prepared.transfers.len() + prepared.channel_ops.len();
    let (state_batch, transaction_batch) = info_span!("application.execute.apply").in_scope(|| {
        let state_batch = apply_shard_maps(state_batch, transfer_writes);
        let state_batch = apply_channel_writes(state_batch, channel_writes);
        let transaction_batch = apply_transaction_digests(transaction_batch, &prepared.digests);
        (state_batch, transaction_batch)
    });

    Ok(finalize_child(
        state_batch,
        transaction_batch,
        parent,
        transaction_count,
        "database merkleization during verification must succeed",
    )
    .await)
}

pub(super) async fn apply_prepared_body<E, H, S>(
    strategy: S,
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    transaction_floor: mmr::Location,
    prepared: &PreparedBatch<H>,
) -> Result<db::MerkleizedDatabases<E, H, S>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let (transfer_writes, channel_writes) = execute_lanes(&state_batch, &strategy, prepared)
        .instrument(info_span!("application.execute.compute"))
        .await
        .ok_or(STATIC_INVALID_TRANSACTION)?;

    let (state_batch, transaction_batch) = info_span!("application.execute.apply").in_scope(|| {
        let state_batch = apply_shard_maps(state_batch, transfer_writes);
        let state_batch = apply_channel_writes(state_batch, channel_writes);
        let transaction_batch = apply_transaction_digests(transaction_batch, &prepared.digests)
            .with_inactivity_floor(transaction_floor);
        (state_batch, transaction_batch)
    });

    db::finalize_execution(state_batch, transaction_batch)
        .await
        .map_err(|_| STATIC_INVALID_TRANSACTION)
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

#[tracing::instrument(name = "application.execute.finalize", level = "info", skip_all)]
async fn finalize_child<E, C, P, H, S>(
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent: &SealedBlock<C, P, H>,
    transaction_count: usize,
    expect_message: &'static str,
) -> BlockExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    let transaction_batch =
        transaction_batch.with_inactivity_floor(parent_transactions_inactivity_floor(parent));
    let (state, transactions) = db::finalize_execution(state_batch, transaction_batch)
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
    use super::{chunk_ranges, range_from_bounds};
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

    #[test]
    fn flat_chunk_ranges_cover_items_once() {
        assert_eq!(chunk_ranges(0, 4), Vec::<core::ops::Range<usize>>::new());
        assert_eq!(chunk_ranges(2, 8), vec![0..1, 1..2]);
        assert_eq!(chunk_ranges(10, 3), vec![0..3, 3..6, 6..10]);
    }
}
