//! Shared block execution output helpers.

use super::{
    db::{
        MerkleizedDatabases, StateBatch, StateMerkleized, TransactionBatch, TransactionMerkleized,
        finalize_execution,
    },
    history::{child_transactions_range, parent_transactions_inactivity_floor},
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::translator::EightCap;
use commonware_utils::non_empty_range;
use constantinople_primitives::SealedBlock;
use std::time::Instant;

/// Timing information for deterministic block execution.
pub(super) struct ExecutionTimings {
    pub(super) prepare_signers_ms: u128,
    pub(super) load_state_ms: u128,
    pub(super) execute_ms: u128,
    pub(super) finalize_ms: u128,
}

impl ExecutionTimings {
    pub(super) const fn before_finalize(
        prepare_signers_ms: u128,
        load_state_ms: u128,
        execute_ms: u128,
    ) -> Self {
        Self {
            prepare_signers_ms,
            load_state_ms,
            execute_ms,
            finalize_ms: 0,
        }
    }

    const fn with_finalize_ms(mut self, finalize_ms: u128) -> Self {
        self.finalize_ms = finalize_ms;
        self
    }
}

/// Merkleized output produced by block execution.
pub(super) struct BlockExecution<E, H, P, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    pub(super) state: StateMerkleized<E, H, P, EightCap, S>,
    pub(super) transactions: TransactionMerkleized<E, H, S>,
    pub(super) state_sync_range: commonware_utils::range::NonEmptyRange<u64>,
    pub(super) transactions_range: commonware_utils::range::NonEmptyRange<u64>,
    pub(super) transaction_count: usize,
    pub(super) timings: ExecutionTimings,
}

impl<E, H, P, S> BlockExecution<E, H, P, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    pub(super) fn into_merkleized(self) -> MerkleizedDatabases<E, H, P, S> {
        (self.state, self.transactions)
    }
}

pub(super) fn child_state_sync_range<C, P, H>(
    parent: &SealedBlock<C, P, H>,
    state_sync_start: u64,
    state_write_count: usize,
) -> commonware_utils::range::NonEmptyRange<u64>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let state_ops = u64::try_from(state_write_count)
        .expect("state write count must fit into u64")
        .checked_add(1)
        .expect("state batch commit must not overflow u64");
    let state_sync_end = parent
        .header
        .state_range
        .end()
        .checked_add(state_ops)
        .expect("state sync range end must not overflow u64");
    non_empty_range!(state_sync_start, state_sync_end)
}

pub(super) async fn finalize_child_execution<E, C, P, H, S>(
    state_batch: StateBatch<E, H, P, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent: &SealedBlock<C, P, H>,
    state_sync_range: commonware_utils::range::NonEmptyRange<u64>,
    transaction_count: usize,
    timings: ExecutionTimings,
    expect_message: &'static str,
) -> BlockExecution<E, H, P, S>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    let transaction_batch =
        transaction_batch.with_inactivity_floor(parent_transactions_inactivity_floor(parent));
    let transactions_range = child_transactions_range(parent, transaction_count);

    let finalize_started_at = Instant::now();
    let (state, transactions) = finalize_execution(state_batch, transaction_batch)
        .await
        .expect(expect_message);
    let finalize_ms = finalize_started_at.elapsed().as_millis();

    BlockExecution {
        state,
        transactions,
        state_sync_range,
        transactions_range,
        transaction_count,
        timings: timings.with_finalize_ms(finalize_ms),
    }
}
