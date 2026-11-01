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
//! block cannot fund later debits in that block. What a body changes therefore
//! follows from its transfers alone, so verification plans the body with
//! `commonware_glue::transfers` before reading any account, then settles the
//! loaded accounts all or nothing.
//!
//! The plan holds each account the body touches once, with its debit and credit
//! sums and its nonce effects in block order. Each account is loaded once,
//! settled once, and written once. If any nonce is refused, any debit exceeds
//! its account's starting balance, or any final balance overflows, the whole
//! block body is invalid and no partial state is applied. A proposer instead
//! selects its body one candidate at a time, dropping each that cannot settle,
//! so the body it proposes settles under the verifier's plan.
//!
//! Touched accounts are staged out of the unordered state QMDB in one read,
//! and final account values are recorded as one slot per staged read, so
//! merkleization reuses each key's resolved location. The state commitment
//! depends on the final key/value set. Transaction history is append-only, so
//! transaction digests are still appended in block order.

use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock, Metrics, Storage,
    telemetry::metrics::{Counter, MetricsExt},
};
use commonware_storage::mmr;
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
    DatabaseReaders, Databases, StateBatch, StateDatabase, StateOperation, StateSlots, StateStaged,
    StateSyncTarget, TransactionDatabase, TransactionHistoryDb, TransactionHistoryOperation,
    TransactionHistoryTarget,
};
pub use execution::{compute, prepare_signed};
pub use genesis::{genesis_block, genesis_block_with_parent};

type FinalizedHookFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

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
    dyn Fn(Arc<SealedBlock<C, P, H>>, FinalizedArtifacts<H>) -> FinalizedHookFuture + Send + Sync,
>;
type Result<T> = core::result::Result<T, &'static str>;

const INVALID_SIGNATURE: &str = "invalid signature";
const INVALID_TRANSACTION_FLOOR: &str = "invalid transaction floor";
const MALFORMED_TRANSACTION: &str = "malformed transaction";
const STATIC_INVALID_TRANSACTION: &str = "statically invalid transaction";

/// Core Constantinople application.
pub struct Application<E, H, C, S, P, I, St>
where
    H: Hasher,
    E: Storage + Clock + Metrics,
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
    proposed_transactions: Counter,
    _marker: PhantomData<(E, C, S, I)>,
}

impl<E, H, C, S, P, I, St> Clone for Application<E, H, C, S, P, I, St>
where
    H: Hasher,
    E: Storage + Clock + Metrics,
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
            proposed_transactions: self.proposed_transactions.clone(),
            _marker: PhantomData,
        }
    }
}

impl<E, H, C, S, P, I, St> Application<E, H, C, S, P, I, St>
where
    H: Hasher,
    E: Storage + Clock + Metrics,
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
            proposed_transactions,
            _marker: PhantomData,
        }
    }
}

fn reject_verify(height: u64, reason: &'static str) {
    tracing::warn!(height, reason, "application.verify.reject");
}
