//! Consensus-facing application integration.
//!
//! The wrapper is intentionally thin. It prepares block bodies, delegates
//! account transitions to the executor, updates QMDB batches, and checks the
//! commitments consensus votes on.

use commonware_consensus::types::Height;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock, Metrics, Storage,
    telemetry::metrics::{Counter, MetricsExt},
};
use constantinople_primitives::SealedBlock;
use std::{future::Future, marker::PhantomData, num::NonZeroU64, pin::Pin, sync::Arc};

mod body;
mod db;
mod execution;
mod genesis;
mod glue;
mod history;
mod lifecycle;
#[cfg(test)]
mod tests;
mod time;

pub use db::{
    Databases, StateDatabase, StateSyncTarget, TransactionDatabase, TransactionHistoryDb,
    TransactionHistoryOperation, TransactionHistoryTarget,
};
pub use genesis::{genesis_block, genesis_block_with_parent};

type FinalizedPruneFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
type FinalizedPruneFn = Arc<dyn Fn(Height) -> FinalizedPruneFuture + Send + Sync>;
type FinalizedHookFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
pub type FinalizedHookFn<E, C, H, P, HashSt> = Arc<
    dyn for<'a> Fn(
            &'a SealedBlock<C, P, H>,
            &'a Databases<E, H, commonware_storage::translator::EightCap, HashSt>,
        ) -> FinalizedHookFuture<'a>
        + Send
        + Sync,
>;
type Result<T> = core::result::Result<T, &'static str>;

const INVALID_SIGNATURE: &str = "invalid signature";
const SIGNATURE_TASK_CLOSED: &str = "signature verification task closed";
const MATERIALIZE_TASK_CLOSED: &str = "transaction materialization task closed";
const MALFORMED_TRANSACTION: &str = "malformed transaction";
const STATIC_INVALID_TRANSACTION: &str = "statically invalid transaction";

/// Core Constantinople application.
pub struct Application<E, H, C, S, P, I, B, SigSt, HashSt>
where
    H: Hasher,
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    HashSt: Strategy,
{
    signature_strategy: SigSt,
    hash_strategy: HashSt,
    genesis_leader: P,
    genesis_parent: C,
    transaction_namespace: &'static [u8],
    genesis_state_target: StateSyncTarget<H::Digest>,
    genesis_transactions_target: TransactionHistoryTarget<H::Digest>,
    prune_cadence_blocks: NonZeroU64,
    previous_prune_cadence_state_end: u64,
    finalized_pruner: FinalizedPruneFn,
    finalized_hook: Option<FinalizedHookFn<E, C, H, P, HashSt>>,
    proposed_transactions: Counter,
    _marker: PhantomData<(E, C, S, I, B)>,
}

impl<E, H, C, S, P, I, B, SigSt, HashSt> Clone for Application<E, H, C, S, P, I, B, SigSt, HashSt>
where
    H: Hasher,
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    P: Clone,
    SigSt: Clone,
    HashSt: Strategy + Clone,
{
    fn clone(&self) -> Self {
        Self {
            signature_strategy: self.signature_strategy.clone(),
            hash_strategy: self.hash_strategy.clone(),
            genesis_leader: self.genesis_leader.clone(),
            genesis_parent: self.genesis_parent,
            transaction_namespace: self.transaction_namespace,
            genesis_state_target: self.genesis_state_target.clone(),
            genesis_transactions_target: self.genesis_transactions_target.clone(),
            prune_cadence_blocks: self.prune_cadence_blocks,
            previous_prune_cadence_state_end: self.previous_prune_cadence_state_end,
            finalized_pruner: self.finalized_pruner.clone(),
            finalized_hook: self.finalized_hook.clone(),
            proposed_transactions: self.proposed_transactions.clone(),
            _marker: PhantomData,
        }
    }
}

impl<E, H, C, S, P, I, B, SigSt, HashSt> Application<E, H, C, S, P, I, B, SigSt, HashSt>
where
    H: Hasher,
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    HashSt: Strategy,
{
    /// Creates an application.
    #[expect(
        clippy::too_many_arguments,
        reason = "the engine constructs the application from already grouped config"
    )]
    pub fn new(
        context: impl Metrics,
        signature_strategy: SigSt,
        hash_strategy: HashSt,
        genesis_leader: P,
        genesis_parent: C,
        transaction_namespace: &'static [u8],
        genesis_state_target: StateSyncTarget<H::Digest>,
        genesis_transactions_target: TransactionHistoryTarget<H::Digest>,
        prune_cadence_blocks: NonZeroU64,
        finalized_pruner: FinalizedPruneFn,
        finalized_hook: Option<FinalizedHookFn<E, C, H, P, HashSt>>,
    ) -> Self {
        let proposed_transactions = context.counter(
            "proposed_transactions",
            "The number of transactions proposed into blocks",
        );
        let previous_prune_cadence_state_end = *genesis_state_target.range.end();

        Self {
            signature_strategy,
            hash_strategy,
            genesis_leader,
            genesis_parent,
            transaction_namespace,
            genesis_state_target,
            genesis_transactions_target,
            prune_cadence_blocks,
            previous_prune_cadence_state_end,
            finalized_pruner,
            finalized_hook,
            proposed_transactions,
            _marker: PhantomData,
        }
    }

    const fn should_prune_after_finalize(&self, height: u64) -> bool {
        height != 0 && height.is_multiple_of(self.prune_cadence_blocks.get())
    }
}

fn reject_verify(height: u64, reason: &'static str) {
    tracing::warn!(height, reason, "application.verify.reject");
}
