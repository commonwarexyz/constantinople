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

use commonware_consensus::HandoffPolicy;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Storage,
    telemetry::metrics::{Counter, Histogram, MetricsExt},
};
use constantinople_primitives::{PublicKeyCache, SealedBlock};
use std::{future::Future, marker::PhantomData, pin::Pin, sync::Arc, time::Duration};

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
    DatabaseReaders, Databases, MerkleizedDatabases, StateBatch, StateDatabase, StateStaged,
    StateSyncTarget, StateUpdates, TransactionDatabase, TransactionHistoryDb,
    TransactionHistoryOperation, TransactionHistoryTarget,
};
pub use execution::{compute, prepare_signed};
pub use genesis::{genesis_block, genesis_block_with_parent};

/// Owned post-apply work. Stateful awaits this before releasing the block acknowledgement.
pub type FinalizedTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
/// Captures owned upload material before application, then returns its post-apply work.
/// The returned task must not retain database readers or borrow the winning batches.
pub type FinalizedHookFn<E, C, H, P, St> = Arc<
    dyn for<'a> Fn(
            &'a SealedBlock<C, P, H>,
            &'a MerkleizedDatabases<E, H, St>,
            DatabaseReaders<E, H, commonware_storage::translator::EightCap, St>,
        ) -> Pin<Box<dyn Future<Output = FinalizedTask> + Send + 'a>>
        + Send
        + Sync,
>;
type Result<T> = core::result::Result<T, &'static str>;

const INVALID_SIGNATURE: &str = "invalid signature";
const MALFORMED_TRANSACTION: &str = "malformed transaction";
const STATIC_INVALID_TRANSACTION: &str = "statically invalid transaction";

/// Proposal timing buckets: 1ms to 10s.
const PROPOSAL_DURATION_BUCKETS: [f64; 13] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Core Constantinople application.
pub struct Application<E, H, C, S, P, I, B, St>
where
    H: Hasher,
    E: BufferPooler + Storage + Clock + Metrics + commonware_runtime::Spawner,
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
    handoff_policy: HandoffPolicy,
    proposal_build_delay: Duration,
    finalized_hook: Option<FinalizedHookFn<E, C, H, P, St>>,
    proposed_transactions: Counter,
    proposal_build_duration: Histogram,
    proposal_build_delay_duration: Histogram,
    _marker: PhantomData<(E, C, S, I, B)>,
}

impl<E, H, C, S, P, I, B, St> Clone for Application<E, H, C, S, P, I, B, St>
where
    H: Hasher,
    E: BufferPooler + Storage + Clock + Metrics + commonware_runtime::Spawner,
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
            handoff_policy: self.handoff_policy,
            proposal_build_delay: self.proposal_build_delay,
            finalized_hook: self.finalized_hook.clone(),
            proposed_transactions: self.proposed_transactions.clone(),
            proposal_build_duration: self.proposal_build_duration.clone(),
            proposal_build_delay_duration: self.proposal_build_delay_duration.clone(),
            _marker: PhantomData,
        }
    }
}

impl<E, H, C, S, P, I, B, St> Application<E, H, C, S, P, I, B, St>
where
    H: Hasher,
    E: BufferPooler + Storage + Clock + Metrics + commonware_runtime::Spawner,
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
        finalized_hook: Option<FinalizedHookFn<E, C, H, P, St>>,
    ) -> Self {
        let proposed_transactions = context.counter(
            "proposed_transactions",
            "The number of transactions proposed into blocks",
        );
        let proposal_build_duration = context.histogram(
            "proposal_build_duration",
            "Actual proposal construction duration excluding synthetic delay (s)",
            PROPOSAL_DURATION_BUCKETS,
        );
        let proposal_build_delay_duration = context.histogram(
            "proposal_build_delay_duration",
            "Completed synthetic proposal-build delay duration (s)",
            PROPOSAL_DURATION_BUCKETS,
        );

        Self {
            strategy,
            genesis_leader,
            genesis_parent,
            transaction_namespace,
            public_key_cache,
            genesis_state_target,
            genesis_transactions_target,
            handoff_policy: HandoffPolicy::AwaitCertification,
            proposal_build_delay: Duration::ZERO,
            finalized_hook,
            proposed_transactions,
            proposal_build_duration,
            proposal_build_delay_duration,
            _marker: PhantomData,
        }
    }

    /// Overrides how consensus prepares proposals during a term handoff.
    pub const fn with_handoff_policy(mut self, handoff_policy: HandoffPolicy) -> Self {
        self.handoff_policy = handoff_policy;
        self
    }

    /// Injects a synthetic asynchronous delay before proposal construction.
    ///
    /// This benchmarking knob defaults to zero and applies independently of
    /// the configured consensus handoff policy.
    pub const fn with_proposal_build_delay(mut self, delay: Duration) -> Self {
        self.proposal_build_delay = delay;
        self
    }
}

fn reject_verify(height: u64, reason: &'static str) {
    tracing::warn!(height, reason, "application.verify.reject");
}
