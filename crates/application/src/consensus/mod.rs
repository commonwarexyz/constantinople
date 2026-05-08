//! Consensus-facing application integration.
//!
//! The wrapper is intentionally thin. It prepares block bodies, delegates
//! account transitions to the executor, updates QMDB batches, and checks the
//! commitments consensus votes on.

use commonware_consensus::types::Height;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_runtime::{
    Metrics,
    telemetry::metrics::{Counter, MetricsExt},
};
use constantinople_primitives::SealedBlock;
use std::{
    future::Future,
    marker::PhantomData,
    num::NonZeroU64,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

mod body;
mod db;
mod execution;
mod genesis;
mod glue;
mod history;
mod lifecycle;
mod telemetry;
#[cfg(test)]
mod tests;
mod time;

pub use db::{
    STATE_BITMAP_CHUNK_BYTES, TransactionHistoryDb, TransactionHistoryOperation,
    TransactionHistoryTarget,
};
pub use genesis::genesis_block;

type FinalizedPruneFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
type FinalizedPruneFn = Arc<dyn Fn(Height) -> FinalizedPruneFuture + Send + Sync>;
type Result<T> = core::result::Result<T, &'static str>;

const INVALID_SIGNATURE: &str = "invalid signature";
const SIGNATURE_TASK_CLOSED: &str = "signature verification task closed";
const MATERIALIZE_TASK_CLOSED: &str = "transaction materialization task closed";
const MALFORMED_TRANSACTION: &str = "malformed transaction";
const STATIC_INVALID_TRANSACTION: &str = "statically invalid transaction";

/// Core Constantinople application.
pub struct Application<H, C, S, P, I, B, SigSt, HashSt>
where
    H: Hasher,
{
    signature_strategy: SigSt,
    hash_strategy: HashSt,
    genesis_leader: P,
    transaction_namespace: &'static [u8],
    genesis_state_root: H::Digest,
    genesis_state_sync_root: H::Digest,
    genesis_state_range: commonware_utils::range::NonEmptyRange<u64>,
    genesis_transactions_target: TransactionHistoryTarget<H::Digest>,
    prune_cadence_blocks: NonZeroU64,
    finalized_pruner: FinalizedPruneFn,
    finalized_state_sync_start: Arc<AtomicU64>,
    proposed_transactions: Counter,
    _marker: PhantomData<(C, S, I, B)>,
}

impl<H, C, S, P, I, B, SigSt, HashSt> Clone for Application<H, C, S, P, I, B, SigSt, HashSt>
where
    H: Hasher,
    P: Clone,
    SigSt: Clone,
    HashSt: Clone,
{
    fn clone(&self) -> Self {
        Self {
            signature_strategy: self.signature_strategy.clone(),
            hash_strategy: self.hash_strategy.clone(),
            genesis_leader: self.genesis_leader.clone(),
            transaction_namespace: self.transaction_namespace,
            genesis_state_root: self.genesis_state_root,
            genesis_state_sync_root: self.genesis_state_sync_root,
            genesis_state_range: self.genesis_state_range.clone(),
            genesis_transactions_target: self.genesis_transactions_target.clone(),
            prune_cadence_blocks: self.prune_cadence_blocks,
            finalized_pruner: self.finalized_pruner.clone(),
            finalized_state_sync_start: self.finalized_state_sync_start.clone(),
            proposed_transactions: self.proposed_transactions.clone(),
            _marker: PhantomData,
        }
    }
}

impl<H, C, S, P, I, B, SigSt, HashSt> Application<H, C, S, P, I, B, SigSt, HashSt>
where
    H: Hasher,
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
        transaction_namespace: &'static [u8],
        genesis_state_root: H::Digest,
        genesis_state_sync_root: H::Digest,
        genesis_state_range: commonware_utils::range::NonEmptyRange<u64>,
        genesis_transactions_target: TransactionHistoryTarget<H::Digest>,
        prune_cadence_blocks: NonZeroU64,
        finalized_pruner: FinalizedPruneFn,
    ) -> Self {
        let proposed_transactions = context.counter(
            "proposed_transactions",
            "The number of transactions proposed into blocks",
        );

        Self {
            signature_strategy,
            hash_strategy,
            genesis_leader,
            transaction_namespace,
            genesis_state_root,
            genesis_state_sync_root,
            genesis_state_range,
            genesis_transactions_target,
            prune_cadence_blocks,
            finalized_pruner,
            finalized_state_sync_start: Arc::new(AtomicU64::new(0)),
            proposed_transactions,
            _marker: PhantomData,
        }
    }

    const fn should_prune_after_finalize(&self, height: u64) -> bool {
        height != 0 && height.is_multiple_of(self.prune_cadence_blocks.get())
    }
}

impl<H, C, S, P, I, B, SigSt, HashSt> Application<H, C, S, P, I, B, SigSt, HashSt>
where
    C: Digest,
    H: Hasher,
    P: PublicKey,
{
    fn state_sync_start(&self, parent: &SealedBlock<C, P, H>) -> u64 {
        parent
            .header
            .state_range
            .start()
            .max(self.finalized_state_sync_start.load(Ordering::Relaxed))
    }
}
