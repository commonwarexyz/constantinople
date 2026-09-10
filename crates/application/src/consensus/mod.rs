//! Consensus-facing application integration.
//!
//! This module is the boundary between consensus and the application state
//! transition. Consensus supplies candidate or certified block bodies; the
//! application prepares those bodies into account transfers, executes them
//! against QMDB-backed state, appends transaction-history entries, and returns
//! the commitments consensus proposes, verifies, or applies.
//!
//! Account execution is based on block-start state. A sender spends only the
//! balance it had at the start of the block, and credits created by the same
//! block cannot fund later debits in that block. The executor therefore builds
//! deterministic account effects first, then applies those effects to loaded
//! accounts all or nothing.
//!
//! The executor builds one account-touch plan for each block. Transfers whose
//! non-self sender/recipient accounts are unique in the block stay on a discrete
//! lane and can write their sender and recipient accounts directly. Transfers
//! that touch contended accounts go through the general account-owned lane: each
//! affected account is loaded once, receives its accumulated nonce/debit/credit
//! effect, and writes once. If any lane fails a nonce check, balance check, or
//! checked credit addition, the whole block body is invalid and no partial state
//! is applied.
//!
//! Touched accounts are staged out of the unordered state QMDB in one read,
//! and final account values are recorded against the staged read indices, so
//! merkleization reuses each key's resolved location. The state commitment
//! depends on the final key/value set. Transaction history is append-only, so
//! transaction digests are still appended in block order.

use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Storage,
    telemetry::metrics::{Counter, MetricsExt},
};
use commonware_storage::{merkle::Proof, mmr};
use constantinople_primitives::{PublicKeyCache, SealedBlock};
use std::{future::Future, marker::PhantomData, pin::Pin, sync::Arc};

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
    DatabaseReaders, Databases, StateBatch, StateDatabase, StateOperation, StateStaged,
    StateSyncTarget, StateUpdates, TransactionDatabase, TransactionHistoryDb,
    TransactionHistoryOperation, TransactionHistoryTarget,
};
pub use execution::{compute, prepare_signed};
pub use genesis::{genesis_block, genesis_block_with_parent};

type FinalizedHookFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// Exact operation range captured from one finalized QMDB batch.
pub struct FinalizedRange<D, Op>
where
    D: Digest,
{
    /// Inclusive operation location where this batch starts.
    pub start: mmr::Location,
    /// Exclusive operation location where this batch ends.
    pub end: mmr::Location,
    /// Root after applying this batch.
    pub root: D,
    /// Proof of the batch operations against `root`.
    pub proof: Proof<mmr::Family, D>,
    /// Prefix frontier in MMR pin order.
    pub pinned_nodes: Vec<D>,
    /// Exact operations introduced by the batch.
    pub operations: Arc<Vec<Op>>,
}

/// Finalized operation artifacts for both application databases.
pub struct FinalizedArtifacts<H>
where
    H: Hasher,
{
    /// Account-state operation range.
    pub state: FinalizedRange<H::Digest, StateOperation>,
    /// Transaction-history operation range.
    pub transactions: FinalizedRange<H::Digest, TransactionHistoryOperation<H>>,
}

pub type FinalizedHookFn<C, H, P> = Arc<
    dyn for<'a> Fn(&'a SealedBlock<C, P, H>, FinalizedArtifacts<H>) -> FinalizedHookFuture<'a>
        + Send
        + Sync,
>;
type Result<T> = core::result::Result<T, &'static str>;

const INVALID_SIGNATURE: &str = "invalid signature";
const MALFORMED_TRANSACTION: &str = "malformed transaction";
const STATIC_INVALID_TRANSACTION: &str = "statically invalid transaction";

/// Core Constantinople application.
pub struct Application<E, H, C, S, P, I, B, St>
where
    H: Hasher,
    E: BufferPooler + Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    St: Strategy,
{
    strategy: St,
    genesis_leader: P,
    genesis_parent: C,
    transaction_namespace: &'static [u8],
    public_key_cache: PublicKeyCache,
    genesis_state_target: StateSyncTarget<H::Digest>,
    genesis_transactions_target: TransactionHistoryTarget<H::Digest>,
    finalized_hook: Option<FinalizedHookFn<C, H, P>>,
    proposed_transactions: Counter,
    _marker: PhantomData<(E, C, S, I, B)>,
}

impl<E, H, C, S, P, I, B, St> Clone for Application<E, H, C, S, P, I, B, St>
where
    H: Hasher,
    E: BufferPooler + Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    P: Clone,
    St: Strategy,
{
    fn clone(&self) -> Self {
        Self {
            strategy: self.strategy.clone(),
            genesis_leader: self.genesis_leader.clone(),
            genesis_parent: self.genesis_parent,
            transaction_namespace: self.transaction_namespace,
            public_key_cache: self.public_key_cache.clone(),
            genesis_state_target: self.genesis_state_target.clone(),
            genesis_transactions_target: self.genesis_transactions_target.clone(),
            finalized_hook: self.finalized_hook.clone(),
            proposed_transactions: self.proposed_transactions.clone(),
            _marker: PhantomData,
        }
    }
}

impl<E, H, C, S, P, I, B, St> Application<E, H, C, S, P, I, B, St>
where
    H: Hasher,
    E: BufferPooler + Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    St: Strategy,
{
    /// Creates an application.
    #[expect(
        clippy::too_many_arguments,
        reason = "the engine constructs the application from already grouped config"
    )]
    pub fn new(
        context: impl Metrics,
        strategy: St,
        genesis_leader: P,
        genesis_parent: C,
        transaction_namespace: &'static [u8],
        public_key_cache: PublicKeyCache,
        genesis_state_target: StateSyncTarget<H::Digest>,
        genesis_transactions_target: TransactionHistoryTarget<H::Digest>,
        finalized_hook: Option<FinalizedHookFn<C, H, P>>,
    ) -> Self {
        let proposed_transactions = context.counter(
            "proposed_transactions",
            "The number of transactions proposed into blocks",
        );

        Self {
            strategy,
            genesis_leader,
            genesis_parent,
            transaction_namespace,
            public_key_cache,
            genesis_state_target,
            genesis_transactions_target,
            finalized_hook,
            proposed_transactions,
            _marker: PhantomData,
        }
    }
}

fn reject_verify(height: u64, reason: &'static str) {
    tracing::warn!(height, reason, "application.verify.reject");
}
