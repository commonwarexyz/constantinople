//! Consensus-facing application integration.
//!
//! This module is the boundary between consensus and the application state
//! transition.
//!
//! # A block's transactions execute one block later
//!
//! A block lists transactions of two kinds. A signed transaction is authentic
//! if its signature verifies, which every validator checks before it votes to
//! finalize the block. A transaction of an X25519 account carries no
//! signature: each validator compares a short tag and reports the result with
//! its vote. Whether such a transaction is authentic is therefore not known
//! when its block is proposed. It is fixed by the notarization of the block
//! that the next block carries: the transaction is authentic iff at least
//! `2f + 1` of the reports in that notarization approve it.
//!
//! So block `h` commits to the state reached by applying the authentic
//! transactions of block `h - 1` to the state of block `h - 1`:
//!
//! ```text
//! state(h) = apply(state(h - 1), authentic transactions of body(h - 1))
//! ```
//!
//! and carries one outcome bit per transaction of block `h - 1`, saying
//! whether it was applied. The transaction history is different: block `h`
//! appends the digests of its own transactions, so its transaction root pins
//! its body.
//!
//! # Applying transactions
//!
//! The authentic transactions of a block are applied in order against the
//! state at the start, each one all or nothing: a transaction with a stale
//! nonce, a debit its sender cannot afford from its balance at the start, or a
//! credit that overflows is skipped and leaves no trace. Credits created by
//! the block cannot fund debits in the same block. This is
//! [`SelectiveExecutor`](crate::executor::SelectiveExecutor)'s rule, and a
//! block is valid whatever the outcome of the transactions it lists.
//!
//! Touched accounts are staged out of the unordered state QMDB, and final
//! account values are recorded against the staged read indices, so
//! merkleization reuses each key's resolved location. The state commitment
//! depends on the final key/value set. Transaction history is append-only, so
//! transaction digests are appended in block order.

use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Storage,
    telemetry::metrics::{Counter, MetricsExt},
};
use commonware_storage::mmr;
use constantinople_primitives::{PublicKeyCache, SealedBlock};
use std::{future::Future, marker::PhantomData, pin::Pin, sync::Arc};

mod body;
mod chain;
mod db;
mod execution;
mod genesis;
mod glue;
mod history;
mod lifecycle;
#[cfg(test)]
mod tests;
mod time;

pub use chain::Chain;
pub use db::{
    DatabaseReaders, Databases, StateBatch, StateDatabase, StateOperation, StateStaged,
    StateSyncTarget, StateUpdates, TransactionDatabase, TransactionHistoryDb,
    TransactionHistoryOperation, TransactionHistoryTarget,
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
const MALFORMED_TRANSACTION: &str = "malformed transaction";
const DUPLICATE_TRANSACTION: &str = "duplicate transaction";
const INVALID_NOTARIZATION: &str = "invalid parent notarization";
const PARENT_COMMITMENT_MISMATCH: &str = "parent notarization or outcomes do not match header";
const OUTCOMES_MISMATCH: &str = "outcomes mismatch";

/// Core Constantinople application.
///
/// `X` is the application's view of the chain ([`Chain`]).
pub struct Application<E, H, C, X, P, I, St>
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
    /// Verifies the notarization of its parent that a block carries.
    scheme: constantinople_auth::Scheme,
    chain: X,
    proposed_transactions: Counter,
    _marker: PhantomData<(E, C, I)>,
}

impl<E, H, C, X, P, I, St> Clone for Application<E, H, C, X, P, I, St>
where
    H: Hasher,
    E: BufferPooler + Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    P: Clone,
    X: Clone,
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
            scheme: self.scheme.clone(),
            chain: self.chain.clone(),
            proposed_transactions: self.proposed_transactions.clone(),
            _marker: PhantomData,
        }
    }
}

impl<E, H, C, X, P, I, St> Application<E, H, C, X, P, I, St>
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
        scheme: constantinople_auth::Scheme,
        chain: X,
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
            scheme,
            chain,
            proposed_transactions,
            _marker: PhantomData,
        }
    }
}

fn reject_verify(height: u64, reason: &'static str) {
    tracing::warn!(height, reason, "application.verify.reject");
}
