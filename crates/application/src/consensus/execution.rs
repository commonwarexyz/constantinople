//! Execution and commitment checks for consensus blocks.
//!
//! This module is the consensus-facing wrapper around the account executor. It
//! prepares block bodies, loads the state needed for account execution, writes
//! account and transaction-history updates into QMDB batches, and returns the
//! merkleized commitments that consensus proposes, verifies, or applies.
//!
//! The important invariant is that parallel account execution is owned by
//! sender, not by every account a transfer touches. Nonces and spends are both
//! sender-local, and credits from this block are not available for spending
//! until the block has finished executing. Because of that rule, a sender shard
//! can load only sender accounts, advance nonces, and apply debits without any
//! shared recipient map, recipient locks, or recipient state loads.
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
//! route transfer debits by sender                                |
//!        |                                                       |
//!        +--> sender shard 0 -- load senders -- check nonce/debit|
//!        +--> sender shard 1 -- load senders -- check nonce/debit|
//!        +--> ...                                                |
//!        |                                                       |
//!        v                                                       |
//! final credit sweep                                             |
//!        |                                                       |
//!        +--> credit recipients already loaded as senders        |
//!        +--> aggregate recipient-only credits                   |
//!        +--> get_many missing recipient accounts                |
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
//! The final credit sweep is what makes sender-only sharding correct. Once all
//! debits have succeeded, every loaded sender account has a single owner and can
//! receive any in-block credits addressed to it. Recipients that were never
//! loaded as senders cannot affect debit validity, so their credits are summed
//! after the sender phase, loaded once with `get_many`, and written once. If any
//! debit check or credit addition fails, the whole batch is rejected; there is no
//! partial execution state to reconcile.
//!
//! There are three execution shapes, all preserving the same account semantics:
//!
//! - The disjoint path proves every non-self account touch is unique, so sender
//!   writes and recipient writes can be loaded and produced directly.
//! - The indexed path is for repeated-sender batches. It loads each unique
//!   sender once, executes all sender debits against that index, credits loaded
//!   senders, and sweeps the recipient-only remainder.
//! - The general path partitions transfers by sender prefix and runs the sender
//!   shards independently before the same final credit sweep.
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
//! fixed worker counts. The same strategy drives preparation, large `get_many`
//! reads, indexed execution, and QMDB merkleization beneath the batch APIs.

use super::{
    MALFORMED_TRANSACTION, Result, STATIC_INVALID_TRANSACTION,
    body::PreparedBody,
    db::{self, StateBatch, TransactionBatch, apply_shard_maps, apply_transaction_digests},
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
    Account, AccountKey, Header, LazySignedTransaction, SealedBlock, SignedTransaction,
};
use core::mem::MaybeUninit;
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

/// Loads and executes a batch as a sender-sharded pipeline.
///
/// Transfers are routed by sender-key prefix; each shard concurrently loads
/// only sender accounts and applies debits. The final sweep applies credits to
/// already-loaded sender accounts first, then aggregates, loads, and credits
/// remaining recipient-only accounts. Returns `None` if any transfer fails its
/// nonce or balance check or overflows a recipient (the whole batch is
/// rejected). The batch is only borrowed for reads, so the caller may move it
/// afterward to apply the writes.
async fn load_and_execute<E, H, S>(
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

    if let Some(disjoint) = executor::disjoint_account_plan(transfers) {
        return load_and_execute_disjoint(batch, strategy, transfers, disjoint).await;
    }

    let sender_index = executor::index_senders(transfers);
    if use_indexed_execution(sender_index.sender_count(), transfers.len()) {
        return load_and_execute_indexed(batch, strategy, &sender_index, transfers).await;
    }

    let shard_count = execution_shard_count(strategy);
    let shards = executor::partition(transfers, shard_count);
    let loaded = futures::future::try_join_all(shards.iter().map(|shard| async move {
        let keys = shard.sender_keys();
        let values = batch.get_many(keys).await?;
        let accounts = values
            .into_iter()
            .map(|value| value.unwrap_or_default())
            .collect();
        Ok::<_, commonware_storage::qmdb::Error<mmr::Family>>(executor::execute_shard(
            accounts, shard, transfers,
        ))
    }))
    .await
    .expect("state loading must succeed");

    let mut outputs = loaded.into_iter().collect::<Option<Vec<_>>>()?;
    let missing = executor::apply_loaded_credits(&mut outputs, &shards, transfers)?;
    let mut recipient_writes = ShardWrites::new();
    if !missing.is_empty() {
        let missing_credits = executor::aggregate_credits(missing, transfers)?;
        let keys = missing_credits
            .iter()
            .map(|(recipient, _)| *recipient)
            .collect::<Vec<_>>();
        let values = get_many_accounts(batch, strategy, &keys)
            .await
            .expect("recipient state loading must succeed");
        recipient_writes = executor::apply_aggregated_credits(missing_credits, values)?;
    }

    let mut writes = outputs
        .into_iter()
        .zip(&shards)
        .map(|(output, shard)| executor::shard_writes(shard, output))
        .collect::<Vec<_>>();
    if !recipient_writes.is_empty() {
        writes.push(recipient_writes);
    }
    Some(db::StateWrites::new(writes))
}

const fn use_indexed_execution(sender_count: usize, transfer_count: usize) -> bool {
    sender_count.saturating_mul(2) <= transfer_count
}

async fn load_and_execute_indexed<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    strategy: &S,
    sender_index: &executor::SenderIndex<'_>,
    transfers: &[PreparedTransfer],
) -> Option<db::StateWrites>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let values = batch
        .get_many(sender_index.sender_keys())
        .await
        .expect("sender state loading must succeed");
    let accounts = values
        .into_iter()
        .map(|value| value.unwrap_or_default())
        .collect();
    let execution = if use_parallel_indexed_execution(strategy, transfers.len()) {
        executor::execute_indexed_parallel(strategy, accounts, sender_index, transfers)?
    } else {
        executor::execute_indexed(accounts, sender_index, transfers)?
    };

    let mut writes = vec![executor::indexed_writes(sender_index, execution.output)];
    if !execution.missing.is_empty() {
        let missing_credits = executor::aggregate_credits(execution.missing, transfers)?;
        let keys = missing_credits
            .iter()
            .map(|(recipient, _)| *recipient)
            .collect::<Vec<_>>();
        let values = get_many_accounts(batch, strategy, &keys)
            .await
            .expect("recipient state loading must succeed");
        writes.push(executor::apply_aggregated_credits(missing_credits, values)?);
    }

    Some(db::StateWrites::new(writes))
}

async fn load_and_execute_disjoint<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    strategy: &S,
    transfers: &[PreparedTransfer],
    disjoint: executor::DisjointAccountPlan<'_>,
) -> Option<db::StateWrites>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let sender_writes =
        load_disjoint_sender_writes(batch, strategy, transfers, disjoint.sender_keys.as_slice())
            .await
            .expect("sender state loading must succeed")?;

    let mut writes = vec![sender_writes];
    if disjoint.recipient_count() > 0 {
        let all_recipients_non_self = disjoint.all_recipients_non_self(transfers);
        let recipient_writes = load_disjoint_recipient_writes(
            batch,
            strategy,
            transfers,
            disjoint.recipient_keys.as_slice(),
            all_recipients_non_self,
        )
        .await
        .expect("recipient state loading must succeed")?;
        writes.push(recipient_writes);
    }

    Some(db::StateWrites::new(writes))
}

async fn load_disjoint_sender_writes<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    strategy: &S,
    transfers: &[PreparedTransfer],
    sender_keys: &[&AccountKey],
) -> core::result::Result<Option<ShardWrites>, commonware_storage::qmdb::Error<mmr::Family>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    load_disjoint_writes(
        batch,
        strategy,
        transfers,
        sender_keys,
        apply_disjoint_sender_values_into,
    )
    .await
}

// These QMDB fan-out helpers split borrowed transfer/key slices with
// `Strategy::join`. The runtime spawner requires `'static` futures, so it
// cannot directly express this borrowed shape without first owning or copying
// each key chunk.
type DisjointApplyFn = fn(
    &[PreparedTransfer],
    Vec<Option<Account>>,
    &mut [MaybeUninit<(AccountKey, Account)>],
) -> bool;

async fn load_disjoint_writes<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    strategy: &S,
    transfers: &[PreparedTransfer],
    keys: &[&AccountKey],
    apply: DisjointApplyFn,
) -> core::result::Result<Option<ShardWrites>, commonware_storage::qmdb::Error<mmr::Family>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let chunks = parallel_chunks(strategy, transfers.len());
    let mut writes = uninit_vec(transfers.len());
    let valid = if chunks <= 1 {
        let values = batch.get_many(keys).await?;
        apply(transfers, values, &mut writes)
    } else {
        parallel_disjoint_writes_into(batch, strategy, transfers, keys, &mut writes, chunks, apply)?
    };
    Ok(valid.then(|| initialized_copy_vec(writes)))
}

fn parallel_disjoint_writes_into<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    strategy: &S,
    transfers: &[PreparedTransfer],
    keys: &[&AccountKey],
    writes: &mut [MaybeUninit<(AccountKey, Account)>],
    chunks: usize,
    apply: DisjointApplyFn,
) -> core::result::Result<bool, commonware_storage::qmdb::Error<mmr::Family>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    debug_assert_eq!(transfers.len(), keys.len());
    if chunks <= 1 {
        let values = futures::executor::block_on(batch.get_many(keys))?;
        return Ok(apply(transfers, values, writes));
    }

    let left_chunks = chunks / 2;
    let right_chunks = chunks - left_chunks;
    let split = transfers.len() * left_chunks / chunks;
    let (left_writes, right_writes) = writes.split_at_mut(split);
    let (left_keys, right_keys) = keys.split_at(split);
    let (left, right) = strategy.join(
        || {
            parallel_disjoint_writes_into(
                batch,
                strategy,
                &transfers[..split],
                left_keys,
                left_writes,
                left_chunks,
                apply,
            )
        },
        || {
            parallel_disjoint_writes_into(
                batch,
                strategy,
                &transfers[split..],
                right_keys,
                right_writes,
                right_chunks,
                apply,
            )
        },
    );
    let left_valid = left?;
    let right_valid = right?;
    Ok(left_valid && right_valid)
}

fn apply_disjoint_sender_values_into(
    transfers: &[PreparedTransfer],
    values: Vec<Option<Account>>,
    writes: &mut [MaybeUninit<(AccountKey, Account)>],
) -> bool {
    for ((transfer, value), write) in transfers.iter().zip(values).zip(writes) {
        let mut account = value.unwrap_or_default();
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

async fn load_disjoint_recipient_writes<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    strategy: &S,
    transfers: &[PreparedTransfer],
    recipient_keys: &[&AccountKey],
    all_recipients_non_self: bool,
) -> core::result::Result<Option<ShardWrites>, commonware_storage::qmdb::Error<mmr::Family>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let chunks = parallel_chunks(strategy, transfers.len());
    if all_recipients_non_self {
        return load_disjoint_writes(
            batch,
            strategy,
            transfers,
            recipient_keys,
            apply_disjoint_dense_recipient_values_into,
        )
        .await;
    }

    if chunks <= 1 {
        let values = batch.get_many(recipient_keys).await?;
        return Ok(apply_disjoint_sparse_recipient_values(transfers, values));
    }
    parallel_disjoint_sparse_recipient_writes(batch, strategy, transfers, recipient_keys, chunks)
}

fn parallel_disjoint_sparse_recipient_writes<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    strategy: &S,
    transfers: &[PreparedTransfer],
    recipient_keys: &[&AccountKey],
    chunks: usize,
) -> core::result::Result<Option<ShardWrites>, commonware_storage::qmdb::Error<mmr::Family>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    if chunks <= 1 {
        if recipient_keys.is_empty() {
            return Ok(Some(ShardWrites::new()));
        }
        let values = futures::executor::block_on(batch.get_many(recipient_keys))?;
        return Ok(apply_disjoint_sparse_recipient_values(transfers, values));
    }

    let left_chunks = chunks / 2;
    let right_chunks = chunks - left_chunks;
    let split = transfers.len() * left_chunks / chunks;
    let recipient_split = transfers[..split]
        .iter()
        .filter(|transfer| transfer.sender != transfer.recipient)
        .count();
    let (left_recipient_keys, right_recipient_keys) = recipient_keys.split_at(recipient_split);
    let (left, right) = strategy.join(
        || {
            parallel_disjoint_sparse_recipient_writes(
                batch,
                strategy,
                &transfers[..split],
                left_recipient_keys,
                left_chunks,
            )
        },
        || {
            parallel_disjoint_sparse_recipient_writes(
                batch,
                strategy,
                &transfers[split..],
                right_recipient_keys,
                right_chunks,
            )
        },
    );
    merge_optional_sparse_recipient_writes(left?, right?)
}

fn apply_disjoint_dense_recipient_values_into(
    transfers: &[PreparedTransfer],
    values: Vec<Option<Account>>,
    writes: &mut [MaybeUninit<(AccountKey, Account)>],
) -> bool {
    for ((transfer, value), write) in transfers.iter().zip(values).zip(writes) {
        let mut account = value.unwrap_or_default();
        if executor::apply_credit(&mut account, transfer.value).is_none() {
            return false;
        }
        write.write((transfer.recipient, account));
    }
    true
}

fn apply_disjoint_sparse_recipient_values(
    transfers: &[PreparedTransfer],
    values: Vec<Option<Account>>,
) -> Option<ShardWrites> {
    let mut values = values.into_iter();
    let mut recipient_writes = ShardWrites::with_capacity(values.size_hint().0);
    for transfer in transfers {
        if transfer.sender == transfer.recipient {
            continue;
        }
        let value = values.next().expect("one value per non-self recipient");
        let mut account = value.unwrap_or_default();
        executor::apply_credit(&mut account, transfer.value)?;
        recipient_writes.push((transfer.recipient, account));
    }
    debug_assert!(values.next().is_none());
    Some(recipient_writes)
}

fn merge_optional_sparse_recipient_writes(
    left: Option<ShardWrites>,
    right: Option<ShardWrites>,
) -> core::result::Result<Option<ShardWrites>, commonware_storage::qmdb::Error<mmr::Family>> {
    let Some(mut left_writes) = left else {
        return Ok(None);
    };
    let Some(right_writes) = right else {
        return Ok(None);
    };
    left_writes.extend(right_writes);
    Ok(Some(left_writes))
}

async fn get_many_accounts<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    strategy: &S,
    keys: &[&AccountKey],
) -> core::result::Result<Vec<Option<Account>>, commonware_storage::qmdb::Error<mmr::Family>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let chunks = parallel_chunks(strategy, keys.len());
    if chunks <= 1 {
        return batch.get_many(keys).await;
    }
    parallel_get_many_accounts(batch, strategy, keys, chunks)
}

/// Fan out a large QMDB read without requiring the borrowed batch/key slices to
/// be `'static`. Callers still choose where this runs; disjoint execution uses
/// this for sender reads first, then recipient reads only during the final sweep.
fn parallel_get_many_accounts<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    strategy: &S,
    keys: &[&AccountKey],
    chunks: usize,
) -> core::result::Result<Vec<Option<Account>>, commonware_storage::qmdb::Error<mmr::Family>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    if chunks <= 1 {
        return futures::executor::block_on(batch.get_many(keys));
    }

    let left_chunks = chunks / 2;
    let right_chunks = chunks - left_chunks;
    let split = keys.len() * left_chunks / chunks;
    let (left, right) = strategy.join(
        || parallel_get_many_accounts(batch, strategy, &keys[..split], left_chunks),
        || parallel_get_many_accounts(batch, strategy, &keys[split..], right_chunks),
    );
    let mut left = left?;
    left.extend(right?);
    Ok(left)
}

fn parallel_chunks<S>(strategy: &S, items: usize) -> usize
where
    S: Strategy,
{
    strategy.parallelism_hint().max(1).min(items.max(1))
}

fn execution_shard_count<S>(strategy: &S) -> usize
where
    S: Strategy,
{
    strategy.parallelism_hint().max(1)
}

fn use_parallel_indexed_execution<S>(strategy: &S, transfer_count: usize) -> bool
where
    S: Strategy,
{
    parallel_chunks(strategy, transfer_count) > 1
}

fn use_parallel_prepare<S>(strategy: &S, transaction_count: usize) -> bool
where
    S: Strategy,
{
    parallel_chunks(strategy, transaction_count) > 1
}

pub(super) fn prepare_signed_transfers_with_digests<H, S>(
    strategy: &S,
    transactions: &[SignedTransaction<H>],
) -> Option<(Vec<PreparedTransfer>, Vec<H::Digest>)>
where
    H: Hasher,
    S: Strategy,
{
    if use_parallel_prepare(strategy, transactions.len()) {
        return parallel_prepare_signed_transfers_with_digests(strategy, transactions);
    }

    let mut transfers = Vec::with_capacity(transactions.len());
    let mut digests = Vec::with_capacity(transactions.len());
    for transaction in transactions {
        transfers.push(executor::prepare_transfer(transaction)?);
        digests.push(*transaction.message_digest());
    }
    Some((transfers, digests))
}

fn parallel_prepare_signed_transfers_with_digests<H, S>(
    strategy: &S,
    transactions: &[SignedTransaction<H>],
) -> Option<(Vec<PreparedTransfer>, Vec<H::Digest>)>
where
    H: Hasher,
    S: Strategy,
{
    let mut transfers = uninit_vec(transactions.len());
    let mut digests = uninit_vec(transactions.len());
    let chunks = parallel_chunks(strategy, transactions.len());
    if !parallel_prepare_signed_transfers_with_digests_into(
        strategy,
        transactions,
        &mut transfers,
        &mut digests,
        chunks,
    ) {
        return None;
    }

    Some((
        initialized_copy_vec(transfers),
        initialized_copy_vec(digests),
    ))
}

fn parallel_prepare_signed_transfers_with_digests_into<H, S>(
    strategy: &S,
    transactions: &[SignedTransaction<H>],
    transfers: &mut [MaybeUninit<PreparedTransfer>],
    digests: &mut [MaybeUninit<H::Digest>],
    chunks: usize,
) -> bool
where
    H: Hasher,
    S: Strategy,
{
    if chunks <= 1 {
        for ((transaction, transfer), digest) in transactions.iter().zip(transfers).zip(digests) {
            let Some(prepared) = executor::prepare_transfer(transaction) else {
                return false;
            };
            transfer.write(prepared);
            digest.write(*transaction.message_digest());
        }
        return true;
    }

    let left_chunks = chunks / 2;
    let right_chunks = chunks - left_chunks;
    let split = transactions.len() * left_chunks / chunks;
    let (left_transactions, right_transactions) = transactions.split_at(split);
    let (left_transfers, right_transfers) = transfers.split_at_mut(split);
    let (left_digests, right_digests) = digests.split_at_mut(split);
    let (left, right) = strategy.join(
        || {
            parallel_prepare_signed_transfers_with_digests_into(
                strategy,
                left_transactions,
                left_transfers,
                left_digests,
                left_chunks,
            )
        },
        || {
            parallel_prepare_signed_transfers_with_digests_into(
                strategy,
                right_transactions,
                right_transfers,
                right_digests,
                right_chunks,
            )
        },
    );
    left && right
}

pub(super) fn prepare_lazy_transfers<H, S>(
    strategy: &S,
    body: &[LazySignedTransaction<H>],
) -> Result<(Vec<PreparedTransfer>, Vec<H::Digest>)>
where
    H: Hasher,
    S: Strategy,
{
    if use_parallel_prepare(strategy, body.len()) {
        return parallel_prepare_lazy_transfers(strategy, body);
    }

    let mut transfers = Vec::with_capacity(body.len());
    let mut digests = Vec::with_capacity(body.len());
    for transaction in body.iter() {
        let transaction = transaction.get().ok_or(MALFORMED_TRANSACTION)?;
        transfers.push(executor::prepare_transfer(transaction).ok_or(MALFORMED_TRANSACTION)?);
        digests.push(*transaction.message_digest());
    }
    Ok((transfers, digests))
}

fn parallel_prepare_lazy_transfers<H, S>(
    strategy: &S,
    body: &[LazySignedTransaction<H>],
) -> Result<(Vec<PreparedTransfer>, Vec<H::Digest>)>
where
    H: Hasher,
    S: Strategy,
{
    let mut transfers = uninit_vec(body.len());
    let mut digests = uninit_vec(body.len());
    let chunks = parallel_chunks(strategy, body.len());
    if !parallel_prepare_lazy_transfers_into(strategy, body, &mut transfers, &mut digests, chunks) {
        return Err(MALFORMED_TRANSACTION);
    }

    Ok((
        initialized_copy_vec(transfers),
        initialized_copy_vec(digests),
    ))
}

fn parallel_prepare_lazy_transfers_into<H, S>(
    strategy: &S,
    body: &[constantinople_primitives::LazySignedTransaction<H>],
    transfers: &mut [MaybeUninit<PreparedTransfer>],
    digests: &mut [MaybeUninit<H::Digest>],
    chunks: usize,
) -> bool
where
    H: Hasher,
    S: Strategy,
{
    if chunks <= 1 {
        for ((transaction, transfer), digest) in body.iter().zip(transfers).zip(digests) {
            let Some(transaction) = transaction.get() else {
                return false;
            };
            let Some(prepared) = executor::prepare_transfer(transaction) else {
                return false;
            };
            transfer.write(prepared);
            digest.write(*transaction.message_digest());
        }
        return true;
    }

    let left_chunks = chunks / 2;
    let right_chunks = chunks - left_chunks;
    let split = body.len() * left_chunks / chunks;
    let (left_body, right_body) = body.split_at(split);
    let (left_transfers, right_transfers) = transfers.split_at_mut(split);
    let (left_digests, right_digests) = digests.split_at_mut(split);
    let (left, right) = strategy.join(
        || {
            parallel_prepare_lazy_transfers_into(
                strategy,
                left_body,
                left_transfers,
                left_digests,
                left_chunks,
            )
        },
        || {
            parallel_prepare_lazy_transfers_into(
                strategy,
                right_body,
                right_transfers,
                right_digests,
                right_chunks,
            )
        },
    );
    left && right
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
    let prepared = prepare_signed_transfers_with_digests(&strategy, &transactions);

    let outcome = match prepared {
        Some((transfers, digests)) if !transfers.is_empty() => {
            load_and_execute(&state_batch, &strategy, &transfers)
                .instrument(info_span!("application.execute.load_execute"))
                .await
                .map(|shard_maps| (transactions, digests, shard_maps))
        }
        _ => None,
    };

    let (body, digests, state_batch) = match outcome {
        Some((body, digests, shard_maps)) => {
            (body, digests, apply_shard_maps(state_batch, shard_maps))
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
    let (transfers, digests) = info_span!("application.execute.prepare")
        .in_scope(|| prepare_lazy_transfers(&strategy, body.as_ref().as_slice()))?;

    let shard_maps = load_and_execute(&state_batch, &strategy, &transfers)
        .instrument(info_span!("application.execute.load_execute"))
        .await
        .ok_or(STATIC_INVALID_TRANSACTION)?;

    let (state_batch, transaction_batch) = info_span!("application.execute.apply").in_scope(|| {
        let state_batch = apply_shard_maps(state_batch, shard_maps);
        let transaction_batch = apply_transaction_digests(transaction_batch, &digests);
        (state_batch, transaction_batch)
    });

    Ok(finalize_child(
        state_batch,
        transaction_batch,
        parent,
        transfers.len(),
        "database merkleization during verification must succeed",
    )
    .await)
}

pub(super) async fn apply_prepared_body<E, H, S>(
    strategy: S,
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    transaction_floor: mmr::Location,
    transfers: &[PreparedTransfer],
    digests: &[H::Digest],
) -> Result<db::MerkleizedDatabases<E, H, S>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let shard_maps = load_and_execute(&state_batch, &strategy, transfers)
        .instrument(info_span!("application.execute.load_execute"))
        .await
        .ok_or(STATIC_INVALID_TRANSACTION)?;

    let (state_batch, transaction_batch) = info_span!("application.execute.apply").in_scope(|| {
        let state_batch = apply_shard_maps(state_batch, shard_maps);
        let transaction_batch = apply_transaction_digests(transaction_batch, digests)
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

/// DB-backed timing harness for the load + execute path against a real QMDB.
///
/// Run with: `cargo test -p constantinople-application --release -- --ignored
/// --nocapture bench_load_execute`. Seeds a committed state DB, then times the
/// sender-sharded `load_and_execute` plus final credit sweep. Note: the
/// deterministic runtime serves reads from memory, so this measures the
/// load+execute CPU/memory path, not the per-shard I/O concurrency, which only
/// helps on cold disk misses.
#[cfg(test)]
mod db_bench {
    use crate::executor::{PreparedTransfer, ShardWrites};
    use commonware_codec::{EncodeSize as _, ReadExt as _, Write as _};
    use commonware_cryptography::{Hasher as _, Sha256, Signer as _, ed25519};
    use commonware_glue::stateful::db::{DatabaseSet, Unmerkleized as _};
    use commonware_parallel::Rayon;
    use commonware_runtime::{Runner as _, buffer::paged::CacheRef, deterministic};
    use commonware_storage::{
        journal::contiguous::fixed::Config as FixedJournalConfig,
        merkle::full::Config as MmrConfig, qmdb::any::FixedConfig, translator::EightCap,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};
    use constantinople_primitives::{
        Account, AccountKey, LazySignedTransaction, Nonce, Transaction, TransactionPublicKey,
        VerifiedTransaction, preload_transaction_slice,
    };
    use core::num::NonZeroU64;
    use std::{
        hint::black_box,
        time::{Duration, Instant},
    };

    type Bench = super::db::StateDatabase<deterministic::Context, Sha256, EightCap, Rayon>;
    type TestTransaction = VerifiedTransaction<Sha256>;

    const ACCOUNTS: u64 = 1_000_000;
    const TRANSACTION_COUNTS: &[usize] = &[16_384, 32_768];
    const MAX_SIGNED_ACCOUNTS: u64 = 65_536;
    const NAMESPACE: &[u8] = b"load-execute-bench";
    const SHARED_FANOUT: usize = 8;
    const WARMUP: u32 = 2;
    const ITERS: u32 = 10;

    #[derive(Clone, Copy)]
    enum Fixture {
        Unique,
        Shared,
    }

    impl Fixture {
        fn name(self) -> &'static str {
            match self {
                Self::Unique => "unique",
                Self::Shared => "shared",
            }
        }
    }

    fn key(index: u64) -> AccountKey {
        AccountKey::from_bytes(Sha256::hash(&index.to_le_bytes()).as_ref()).expect("32-byte key")
    }

    fn signed_key(index: u64) -> AccountKey {
        AccountKey::from_public_key(&TransactionPublicKey::ed25519(
            ed25519::PrivateKey::from_seed(index).public_key(),
        ))
    }

    struct TestSigner {
        key: ed25519::PrivateKey,
        public_key: ed25519::PublicKey,
    }

    impl TestSigner {
        fn from_seed(seed: u64) -> Self {
            let key = ed25519::PrivateKey::from_seed(seed);
            let public_key = key.public_key();
            Self { key, public_key }
        }

        fn sign(&self, to: ed25519::PublicKey, value: u64, nonce: u64) -> TestTransaction {
            Transaction::new(
                TransactionPublicKey::ed25519(self.key.public_key()),
                TransactionPublicKey::ed25519(to),
                NonZeroU64::new(value).expect("bench value must be non-zero"),
                nonce,
            )
            .seal_and_sign(&self.key, NAMESPACE, &mut Sha256::default())
        }
    }

    fn config(strategy: Rayon, cache: CacheRef) -> FixedConfig<EightCap, Rayon> {
        FixedConfig {
            merkle_config: MmrConfig {
                journal_partition: "bench-state-journal".into(),
                metadata_partition: "bench-state-metadata".into(),
                items_per_blob: NZU64!(1 << 20),
                write_buffer: NZUsize!(1 << 20),
                strategy,
                page_cache: cache.clone(),
            },
            journal_config: FixedJournalConfig {
                partition: "bench-state-log".into(),
                items_per_blob: NZU64!(1 << 20),
                page_cache: cache,
                write_buffer: NZUsize!(1 << 20),
            },
            translator: EightCap,
        }
    }

    fn transfers(fixture: Fixture, transaction_count: usize) -> Vec<PreparedTransfer> {
        match fixture {
            Fixture::Unique => (0..transaction_count)
                .map(|i| {
                    let sender = key(i as u64);
                    let recipient = key(transaction_count as u64 + i as u64);
                    PreparedTransfer {
                        sender,
                        recipient,
                        sender_prefix: crate::executor::key_prefix(&sender),
                        recipient_prefix: crate::executor::key_prefix(&recipient),
                        value: 1,
                        nonce: 0,
                    }
                })
                .collect(),
            Fixture::Shared => {
                let account_count = (transaction_count / SHARED_FANOUT).max(1);
                let mut nonces = vec![0u64; account_count];
                (0..transaction_count)
                    .map(|i| {
                        let sender_index = i % account_count;
                        let recipient_index = (i * 7 + 3) % account_count;
                        let nonce = nonces[sender_index];
                        nonces[sender_index] += 1;
                        let sender = key(sender_index as u64);
                        let recipient = key(recipient_index as u64);
                        PreparedTransfer {
                            sender,
                            recipient,
                            sender_prefix: crate::executor::key_prefix(&sender),
                            recipient_prefix: crate::executor::key_prefix(&recipient),
                            value: 1,
                            nonce,
                        }
                    })
                    .collect()
            }
        }
    }

    fn signed_transactions(fixture: Fixture, transaction_count: usize) -> Vec<TestTransaction> {
        match fixture {
            Fixture::Unique => (0..transaction_count)
                .map(|i| {
                    let sender = TestSigner::from_seed(i as u64);
                    let recipient =
                        TestSigner::from_seed(transaction_count as u64 + i as u64).public_key;
                    sender.sign(recipient, 1, 0)
                })
                .collect(),
            Fixture::Shared => {
                let account_count = (transaction_count / SHARED_FANOUT).max(1);
                let signers = (0..account_count)
                    .map(|index| TestSigner::from_seed(index as u64))
                    .collect::<Vec<_>>();
                let mut nonces = vec![0u64; account_count];
                (0..transaction_count)
                    .map(|i| {
                        let sender_index = i % account_count;
                        let recipient_index = (i * 7 + 3) % account_count;
                        let nonce = nonces[sender_index];
                        nonces[sender_index] += 1;
                        signers[sender_index].sign(
                            signers[recipient_index].public_key.clone(),
                            1,
                            nonce,
                        )
                    })
                    .collect()
            }
        }
    }

    fn lazy_body(transactions: &[TestTransaction]) -> Vec<LazySignedTransaction<Sha256>> {
        transactions
            .iter()
            .map(|transaction| {
                let mut encoded_transaction = Vec::with_capacity(transaction.encode_size());
                transaction.write(&mut encoded_transaction);

                let mut encoded_lazy = Vec::with_capacity(
                    encoded_transaction.len().encode_size() + encoded_transaction.len(),
                );
                encoded_transaction.len().write(&mut encoded_lazy);
                encoded_lazy.extend_from_slice(&encoded_transaction);

                LazySignedTransaction::<Sha256>::read(&mut encoded_lazy.as_slice())
                    .expect("lazy transaction should decode")
            })
            .collect()
    }

    async fn timed_current(
        batch: &super::StateBatch<deterministic::Context, Sha256, EightCap, Rayon>,
        strategy: &Rayon,
        transfers: &[PreparedTransfer],
    ) -> (usize, Duration) {
        let start = Instant::now();
        let state_writes = super::load_and_execute(batch, strategy, transfers)
            .await
            .expect("current path");
        let elapsed = start.elapsed();
        let count = state_writes.shards.iter().map(|map| map.len()).sum();
        black_box(&state_writes);
        (count, elapsed)
    }

    async fn timed_current_prepare(
        batch: &super::StateBatch<deterministic::Context, Sha256, EightCap, Rayon>,
        strategy: &Rayon,
        transactions: &[TestTransaction],
    ) -> (usize, Duration) {
        let start = Instant::now();
        let (transfers, digests) =
            super::prepare_signed_transfers_with_digests(strategy, transactions)
                .expect("current prepare");
        let state_writes = super::load_and_execute(batch, strategy, &transfers)
            .await
            .expect("current path");
        let elapsed = start.elapsed();
        let count = state_writes.shards.iter().map(|map| map.len()).sum();
        black_box((&transfers, &digests, &state_writes));
        (count, elapsed)
    }

    #[derive(Default)]
    struct CurrentBreakdown {
        total: Duration,
        disjoint: Duration,
        index: Duration,
        sender_load: Duration,
        debit: Duration,
        recipient_load: Duration,
        writes: Duration,
    }

    async fn timed_current_breakdown(
        batch: &super::StateBatch<deterministic::Context, Sha256, EightCap, Rayon>,
        strategy: &Rayon,
        transfers: &[PreparedTransfer],
    ) -> (usize, CurrentBreakdown) {
        let total = Instant::now();
        let mut breakdown = CurrentBreakdown::default();

        let start = Instant::now();
        let disjoint = crate::executor::disjoint_account_plan(transfers);
        breakdown.disjoint = start.elapsed();
        if let Some(disjoint) = disjoint {
            let start = Instant::now();
            let sender_writes = super::load_disjoint_sender_writes(
                batch,
                strategy,
                transfers,
                disjoint.sender_keys.as_slice(),
            )
            .await
            .expect("sender state loading must succeed")
            .expect("bench transfers should execute");
            breakdown.sender_load = start.elapsed();

            let mut writes = vec![sender_writes];
            if disjoint.recipient_count() > 0 {
                let all_recipients_non_self = disjoint.all_recipients_non_self(transfers);
                let load_start = Instant::now();
                let recipient_writes = super::load_disjoint_recipient_writes(
                    batch,
                    strategy,
                    transfers,
                    disjoint.recipient_keys.as_slice(),
                    all_recipients_non_self,
                )
                .await
                .expect("recipient state loading must succeed")
                .expect("bench transfers should execute");
                breakdown.recipient_load = load_start.elapsed();
                writes.push(recipient_writes);
            }

            let count = writes.iter().map(|map| map.len()).sum();
            black_box(&writes);
            breakdown.total = total.elapsed();
            return (count, breakdown);
        }

        let start = Instant::now();
        let sender_index = crate::executor::index_senders(transfers);
        breakdown.index = start.elapsed();
        if !super::use_indexed_execution(sender_index.sender_count(), transfers.len()) {
            let (count, elapsed) = timed_current(batch, strategy, transfers).await;
            breakdown.total = elapsed;
            return (count, breakdown);
        }

        let start = Instant::now();
        let values = batch
            .get_many(sender_index.sender_keys())
            .await
            .expect("sender state loading must succeed");
        let accounts = values
            .into_iter()
            .map(|value| value.unwrap_or_default())
            .collect();
        breakdown.sender_load = start.elapsed();

        let start = Instant::now();
        let execution = if super::use_parallel_indexed_execution(strategy, transfers.len()) {
            crate::executor::execute_indexed_parallel(strategy, accounts, &sender_index, transfers)
                .expect("current path")
        } else {
            crate::executor::execute_indexed(accounts, &sender_index, transfers)
                .expect("current path")
        };
        breakdown.debit = start.elapsed();

        let mut recipient_writes = ShardWrites::new();
        if !execution.missing.is_empty() {
            let missing_credits = crate::executor::aggregate_credits(execution.missing, transfers)
                .expect("current path");
            let keys = missing_credits
                .iter()
                .map(|(recipient, _)| *recipient)
                .collect::<Vec<_>>();
            let start = Instant::now();
            let values = super::get_many_accounts(batch, strategy, &keys)
                .await
                .expect("recipient state loading must succeed");
            breakdown.recipient_load = start.elapsed();
            recipient_writes = crate::executor::apply_aggregated_credits(missing_credits, values)
                .expect("current path");
        }

        let start = Instant::now();
        let mut writes = vec![crate::executor::indexed_writes(
            &sender_index,
            execution.output,
        )];
        if !recipient_writes.is_empty() {
            writes.push(recipient_writes);
        }
        let count = writes.iter().map(|map| map.len()).sum();
        black_box(&writes);
        breakdown.writes = start.elapsed();
        breakdown.total = total.elapsed();
        (count, breakdown)
    }

    fn timed_lazy_preload(
        strategy: &Rayon,
        body: &[LazySignedTransaction<Sha256>],
    ) -> (usize, Duration) {
        let start = Instant::now();
        assert!(
            preload_transaction_slice(body, strategy),
            "lazy preload should succeed"
        );
        let elapsed = start.elapsed();
        black_box(body);
        (body.len(), elapsed)
    }

    fn timed_lazy_apply_prepare(
        strategy: &Rayon,
        body: &[LazySignedTransaction<Sha256>],
    ) -> (usize, Duration) {
        let start = Instant::now();
        let (transfers, digests) =
            super::prepare_lazy_transfers(strategy, body).expect("prepare lazy body");
        let elapsed = start.elapsed();
        let count = transfers.len();
        black_box((transfers, digests));
        (count, elapsed)
    }

    #[test]
    #[ignore = "timing harness; run explicitly with --ignored --nocapture --release"]
    fn bench_lazy_body_prepare() {
        let transaction_count = std::env::var("CONSTANTINOPLE_BENCH_COUNT")
            .ok()
            .and_then(|count| count.parse::<usize>().ok())
            .unwrap_or(32_768);
        let warmup = std::env::var("CONSTANTINOPLE_BENCH_WARMUP")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(WARMUP);
        let iters = std::env::var("CONSTANTINOPLE_BENCH_ITERS")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(ITERS)
            .max(1);
        let strategy = Rayon::new(NZUsize!(8)).expect("rayon pool");
        let transactions = signed_transactions(Fixture::Unique, transaction_count);
        let body = lazy_body(&transactions);

        assert!(
            preload_transaction_slice(&body, &strategy),
            "bench body should preload"
        );

        let mut preload_total = Duration::ZERO;
        let mut apply_total = Duration::ZERO;
        for iter in 0..(warmup + iters) {
            let (preload_count, preload_elapsed) = timed_lazy_preload(&strategy, &body);
            assert_eq!(
                preload_count, transaction_count,
                "preload count should match"
            );

            let (apply_count, apply_elapsed) = timed_lazy_apply_prepare(&strategy, &body);
            assert_eq!(apply_count, transaction_count, "prepare count should match");

            if iter >= warmup {
                preload_total += preload_elapsed;
                apply_total += apply_elapsed;
            }
        }

        let preload = preload_total / iters;
        let apply = apply_total / iters;
        let tps = |d: Duration| transaction_count as f64 / d.as_secs_f64() / 1e6;
        println!(
            "lazy body prepare  {transaction_count} txs / unique / {} shards\n  verify preload: {preload:?}  ({:.2} Melem/s)\n  apply prepare:  {apply:?}  ({:.2} Melem/s)",
            super::execution_shard_count(&strategy),
            tps(preload),
            tps(apply),
        );
    }

    #[test]
    #[ignore = "timing harness; run explicitly with --ignored --nocapture --release"]
    fn bench_load_execute() {
        deterministic::Runner::default().start(|context| async move {
            let bench_prepare = std::env::var_os("CONSTANTINOPLE_BENCH_PREPARE").is_some();
            let warmup = std::env::var("CONSTANTINOPLE_BENCH_WARMUP")
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or(WARMUP);
            let iters = std::env::var("CONSTANTINOPLE_BENCH_ITERS")
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or(ITERS)
                .max(1);
            let strategy = Rayon::new(NZUsize!(8)).expect("rayon pool");
            let cache = CacheRef::from_pooler(&context, NZU16!(8192), NZUsize!(65536));
            let db = <Bench as DatabaseSet<deterministic::Context>>::init(
                context,
                config(strategy.clone(), cache),
            )
            .await;

            // Seed a committed state of ACCOUNTS funded accounts.
            let mut batch = db.new_batches().await;
            for index in 0..ACCOUNTS {
                batch = batch.write(
                    key(index),
                    Some(Account {
                        balance: 1_000_000,
                        nonce: Nonce::default(),
                    }),
                );
            }
            if bench_prepare {
                for index in 0..MAX_SIGNED_ACCOUNTS {
                    batch = batch.write(
                        signed_key(index),
                        Some(Account {
                            balance: 1_000_000,
                            nonce: Nonce::default(),
                        }),
                    );
                }
            }
            let merkleized = batch.merkleize().await.expect("seed merkleize");
            db.finalize(merkleized).await;

            let fixture_filter = std::env::var("CONSTANTINOPLE_BENCH_FIXTURE").ok();
            let count_filter = std::env::var("CONSTANTINOPLE_BENCH_COUNT")
                .ok()
                .and_then(|count| count.parse::<usize>().ok());
            for &transaction_count in TRANSACTION_COUNTS {
                if count_filter.is_some_and(|filter| filter != transaction_count) {
                    continue;
                }
                for fixture in [Fixture::Unique, Fixture::Shared] {
                    if fixture_filter.as_deref().is_some_and(|filter| filter != fixture.name()) {
                        continue;
                    }
                    let transfers = transfers(fixture, transaction_count);

                    let mut current_total = Duration::ZERO;
                    let mut current_writes = 0usize;
                    for iter in 0..(warmup + iters) {
                        let batch = db.new_batches().await;
                        let (count, elapsed) = timed_current(&batch, &strategy, &transfers).await;
                        current_writes = count;
                        if iter >= warmup {
                            current_total += elapsed;
                        }
                    }
                    let tps = |d: Duration| transaction_count as f64 / d.as_secs_f64() / 1e6;

                    let current = current_total / iters;
                    println!(
                        "load+execute  {transaction_count} txs / {ACCOUNTS} accounts / {} / {} shards\n  current: {current:?}  ({:.2} Melem/s) / {current_writes} writes",
                        fixture.name(),
                        super::execution_shard_count(&strategy),
                        tps(current),
                    );

                    if std::env::var_os("CONSTANTINOPLE_BENCH_BREAKDOWN").is_some() {
                        let batch = db.new_batches().await;
                        let (count, breakdown) =
                            timed_current_breakdown(&batch, &strategy, &transfers).await;
                        assert_eq!(count, current_writes, "breakdown write count should match");
                        println!(
                            "  breakdown: total={:?} disjoint={:?} index={:?} sender_load={:?} debit={:?} recipient_load={:?} writes={:?}",
                            breakdown.total,
                            breakdown.disjoint,
                            breakdown.index,
                            breakdown.sender_load,
                            breakdown.debit,
                            breakdown.recipient_load,
                            breakdown.writes,
                        );
                    }

                    if bench_prepare {
                        let transactions = signed_transactions(fixture, transaction_count);
                        let mut current_total = Duration::ZERO;
                        let mut current_writes = 0usize;
                        for iter in 0..(warmup + iters) {
                            let batch = db.new_batches().await;
                            let (count, elapsed) =
                                timed_current_prepare(&batch, &strategy, &transactions).await;
                            current_writes = count;
                            if iter >= warmup {
                                current_total += elapsed;
                            }
                        }

                        let current = current_total / iters;
                        println!(
                            "prepare+load+execute  {transaction_count} txs / {ACCOUNTS} accounts / {} / {} shards\n  current: {current:?}  ({:.2} Melem/s) / {current_writes} writes",
                            fixture.name(),
                            super::execution_shard_count(&strategy),
                            tps(current),
                        );
                    }
                }
            }
        });
    }
}
