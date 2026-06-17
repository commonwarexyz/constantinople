//! Consensus-facing application integration.
//!
//! The wrapper is intentionally thin. It prepares block bodies, delegates
//! account transitions to the executor, updates QMDB batches, and checks the
//! commitments consensus votes on.

use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock, Metrics, Storage,
    telemetry::metrics::{Counter, MetricsExt},
};
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
    Databases, StateDatabase, StateSyncTarget, TransactionDatabase, TransactionHistoryDb,
    TransactionHistoryOperation, TransactionHistoryTarget,
};
pub use genesis::{genesis_block, genesis_block_with_parent};

type FinalizedHookFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
pub type FinalizedHookFn<E, C, H, P, St> = Arc<
    dyn for<'a> Fn(
            &'a SealedBlock<C, P, H>,
            &'a Databases<E, H, commonware_storage::translator::EightCap, St>,
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
pub struct Application<E, H, C, S, P, I, B, St>
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
    finalized_hook: Option<FinalizedHookFn<E, C, H, P, St>>,
    proposed_transactions: Counter,
    _marker: PhantomData<(E, C, S, I, B)>,
}

impl<E, H, C, S, P, I, B, St> Clone for Application<E, H, C, S, P, I, B, St>
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
            finalized_hook: self.finalized_hook.clone(),
            proposed_transactions: self.proposed_transactions.clone(),
            _marker: PhantomData,
        }
    }
}

impl<E, H, C, S, P, I, B, St> Application<E, H, C, S, P, I, B, St>
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
        finalized_hook: Option<FinalizedHookFn<E, C, H, P, St>>,
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
