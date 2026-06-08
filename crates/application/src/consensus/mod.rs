//! Consensus-facing application integration.
//!
//! The wrapper is intentionally thin. It prepares block bodies, delegates
//! account transitions to the executor, updates QMDB batches, and checks the
//! commitments consensus votes on.

use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock, Metrics, Storage,
    telemetry::metrics::{Counter, Histogram, MetricsExt, histogram::Buckets},
};
use commonware_storage::translator::EightCap;
use constantinople_primitives::SealedBlock;
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

type Result<T> = core::result::Result<T, &'static str>;

const INVALID_SIGNATURE: &str = "invalid signature";
const SIGNATURE_TASK_CLOSED: &str = "signature verification task closed";
const MATERIALIZE_TASK_CLOSED: &str = "transaction materialization task closed";
const MALFORMED_TRANSACTION: &str = "malformed transaction";
const STATIC_INVALID_TRANSACTION: &str = "statically invalid transaction";
const BLOCK_TRANSACTION_BUCKETS: [f64; 10] = [
    0.0, 1024.0, 4096.0, 8192.0, 16_384.0, 32_768.0, 49_152.0, 65_536.0, 98_304.0, 131_072.0,
];

/// Future returned by a finalized-block hook.
pub type FinalizedHookFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// Hook that runs after finalized batches are applied to local database handles.
pub type FinalizedHookFn<E, C, H, P, S> = Arc<
    dyn for<'a> Fn(
            &'a SealedBlock<C, P, H>,
            &'a Databases<E, H, EightCap, S>,
        ) -> FinalizedHookFuture<'a>
        + Send
        + Sync,
>;

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
    finalized_hook: Option<FinalizedHookFn<E, C, H, P, HashSt>>,
    metrics: ApplicationMetrics,
    _marker: PhantomData<(E, C, S, I, B)>,
}

#[derive(Clone)]
struct ApplicationMetrics {
    proposed_transactions: Counter,
    propose_transactions_per_block: Histogram,
    propose_input_duration: Histogram,
    propose_prepare_duration: Histogram,
    propose_load_state_duration: Histogram,
    propose_execute_duration: Histogram,
    propose_finalize_duration: Histogram,
    verify_transactions_per_block: Histogram,
    verify_signature_duration: Histogram,
    verify_prepare_duration: Histogram,
    verify_load_state_duration: Histogram,
    verify_execute_duration: Histogram,
    verify_finalize_duration: Histogram,
    apply_transactions_per_block: Histogram,
    apply_materialize_duration: Histogram,
    apply_prepare_duration: Histogram,
    apply_load_state_duration: Histogram,
    apply_execute_duration: Histogram,
    apply_finalize_duration: Histogram,
}

impl ApplicationMetrics {
    fn new(context: &impl Metrics) -> Self {
        Self {
            proposed_transactions: context.counter(
                "proposed_transactions",
                "The number of transactions proposed into blocks",
            ),
            propose_transactions_per_block: context.histogram(
                "propose_transactions_per_block",
                "Histogram of transaction counts in proposed blocks",
                BLOCK_TRANSACTION_BUCKETS,
            ),
            propose_input_duration: context.histogram(
                "propose_input_duration",
                "Histogram of time spent requesting transactions for a proposal, in seconds",
                Buckets::LOCAL,
            ),
            propose_prepare_duration: context.histogram(
                "propose_prepare_duration",
                "Histogram of time spent preparing proposal transactions, in seconds",
                Buckets::LOCAL,
            ),
            propose_load_state_duration: context.histogram(
                "propose_load_state_duration",
                "Histogram of time spent loading proposal state, in seconds",
                Buckets::LOCAL,
            ),
            propose_execute_duration: context.histogram(
                "propose_execute_duration",
                "Histogram of time spent executing proposal transactions, in seconds",
                Buckets::LOCAL,
            ),
            propose_finalize_duration: context.histogram(
                "propose_finalize_duration",
                "Histogram of time spent merkleizing proposal databases, in seconds",
                Buckets::LOCAL,
            ),
            verify_transactions_per_block: context.histogram(
                "verify_transactions_per_block",
                "Histogram of transaction counts in verified blocks",
                BLOCK_TRANSACTION_BUCKETS,
            ),
            verify_signature_duration: context.histogram(
                "verify_signature_duration",
                "Histogram of time spent verifying block transaction signatures, in seconds",
                Buckets::LOCAL,
            ),
            verify_prepare_duration: context.histogram(
                "verify_prepare_duration",
                "Histogram of time spent preparing verified block transactions, in seconds",
                Buckets::LOCAL,
            ),
            verify_load_state_duration: context.histogram(
                "verify_load_state_duration",
                "Histogram of time spent loading verified block state, in seconds",
                Buckets::LOCAL,
            ),
            verify_execute_duration: context.histogram(
                "verify_execute_duration",
                "Histogram of time spent executing verified block transactions, in seconds",
                Buckets::LOCAL,
            ),
            verify_finalize_duration: context.histogram(
                "verify_finalize_duration",
                "Histogram of time spent merkleizing verified block databases, in seconds",
                Buckets::LOCAL,
            ),
            apply_transactions_per_block: context.histogram(
                "apply_transactions_per_block",
                "Histogram of transaction counts in applied certified blocks",
                BLOCK_TRANSACTION_BUCKETS,
            ),
            apply_materialize_duration: context.histogram(
                "apply_materialize_duration",
                "Histogram of time spent materializing certified block transactions, in seconds",
                Buckets::LOCAL,
            ),
            apply_prepare_duration: context.histogram(
                "apply_prepare_duration",
                "Histogram of time spent preparing certified block transactions, in seconds",
                Buckets::LOCAL,
            ),
            apply_load_state_duration: context.histogram(
                "apply_load_state_duration",
                "Histogram of time spent loading certified block state, in seconds",
                Buckets::LOCAL,
            ),
            apply_execute_duration: context.histogram(
                "apply_execute_duration",
                "Histogram of time spent executing certified block transactions, in seconds",
                Buckets::LOCAL,
            ),
            apply_finalize_duration: context.histogram(
                "apply_finalize_duration",
                "Histogram of time spent merkleizing certified block databases, in seconds",
                Buckets::LOCAL,
            ),
        }
    }
}

fn observe_ms(histogram: &Histogram, duration_ms: u128) {
    histogram.observe(duration_ms as f64 / 1000.0);
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
            finalized_hook: self.finalized_hook.clone(),
            metrics: self.metrics.clone(),
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
        finalized_hook: Option<FinalizedHookFn<E, C, H, P, HashSt>>,
    ) -> Self {
        let metrics = ApplicationMetrics::new(&context);

        Self {
            signature_strategy,
            hash_strategy,
            genesis_leader,
            genesis_parent,
            transaction_namespace,
            genesis_state_target,
            genesis_transactions_target,
            finalized_hook,
            metrics,
            _marker: PhantomData,
        }
    }
}

fn reject_verify(height: u64, reason: &'static str) {
    tracing::warn!(height, reason, "application.verify.reject");
}
