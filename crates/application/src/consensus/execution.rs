//! Shared block execution output helpers.

use super::{
    db::{
        StateBatch, StateMerkleized, TransactionBatch, TransactionMerkleized, finalize_execution,
    },
    history::{child_transactions_range, parent_transactions_inactivity_floor},
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
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
pub(super) struct BlockExecution<E, H, P>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
{
    pub(super) state: StateMerkleized<E, H, P, EightCap>,
    pub(super) transactions: TransactionMerkleized<E, H>,
    pub(super) transactions_range: commonware_utils::range::NonEmptyRange<u64>,
    pub(super) transaction_count: usize,
    pub(super) timings: ExecutionTimings,
}

impl<E, H, P> BlockExecution<E, H, P>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
{
    pub(super) fn state_range(&self) -> commonware_utils::range::NonEmptyRange<u64> {
        non_empty_range!(*self.state.inactivity_floor(), *self.state.size())
    }

    pub(super) fn into_merkleized(
        self,
    ) -> (
        StateMerkleized<E, H, P, EightCap>,
        TransactionMerkleized<E, H>,
    ) {
        (self.state, self.transactions)
    }
}

pub(super) async fn finalize_child_execution<E, C, P, H>(
    state_batch: StateBatch<E, H, P, EightCap>,
    transaction_batch: TransactionBatch<E, H>,
    parent: &SealedBlock<C, P, H>,
    transaction_count: usize,
    timings: ExecutionTimings,
    expect_message: &'static str,
) -> BlockExecution<E, H, P>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
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
        transactions_range,
        transaction_count,
        timings: timings.with_finalize_ms(finalize_ms),
    }
}
