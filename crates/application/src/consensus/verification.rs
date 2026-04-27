//! Block verification pipeline helpers.

use super::{
    StateBatch, StateMerkleized, TransactionBatch, TransactionMerkleized, apply_changeset,
    apply_transaction_digests, child_transactions_range, finalize_execution, load_state,
    parent_transactions_inactivity_floor,
};
use crate::processor::executor;
use commonware_codec::types::lazy::Lazy;
use commonware_cryptography::{BatchVerifier, Digest, Hasher, PublicKey};
use commonware_glue::stateful::db::Merkleized as _;
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::translator::EightCap;
use commonware_utils::non_empty_range;
use constantinople_primitives::{
    Address, Header, SealedBlock, SignedTransaction, materialize_transaction_chunks,
    transaction_senders, verify_transaction_batch, verify_transaction_chunks,
};
use rand_core::CryptoRngCore;
use std::time::Instant;
use tracing::warn;

pub(super) type Result<T> = core::result::Result<T, &'static str>;

const INVALID_SIGNATURE: &str = "invalid signature";
const MALFORMED_TRANSACTION: &str = "malformed transaction";
const STATIC_INVALID_TRANSACTION: &str = "statically invalid transaction";

/// Decoded transactions paired with cached sender addresses.
pub(super) struct Prepared<P, H>
where
    H: Hasher,
    P: PublicKey,
{
    pub(super) transactions: Vec<SignedTransaction<P, H>>,
    pub(super) signers: Vec<Address>,
}

/// Timing information for the execution side of verification.
pub(super) struct ExecutionTimings {
    pub(super) prepare_ms: u128,
    pub(super) load_state_ms: u128,
    pub(super) execute_ms: u128,
    pub(super) finalize_ms: u128,
}

/// Merkleized output produced by verification execution.
pub(super) struct Execution<E, H>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
{
    pub(super) state: StateMerkleized<E, H, EightCap>,
    pub(super) transactions: TransactionMerkleized<E, H>,
    pub(super) transactions_range: commonware_utils::range::NonEmptyRange<u64>,
    pub(super) transaction_count: usize,
    pub(super) timings: ExecutionTimings,
}

impl<E, H> Execution<E, H>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
{
    pub(super) fn into_merkleized(
        self,
    ) -> (StateMerkleized<E, H, EightCap>, TransactionMerkleized<E, H>) {
        (self.state, self.transactions)
    }
}

/// Verifies lazily-encoded signed transactions and returns decoded transactions.
pub(super) fn verify_transactions<P, H, B, St>(
    strategy: &St,
    namespace: &'static [u8],
    rng: &mut impl CryptoRngCore,
    transactions: Vec<Lazy<SignedTransaction<P, H>>>,
) -> Option<Vec<SignedTransaction<P, H>>>
where
    P: PublicKey,
    H: Hasher,
    B: BatchVerifier<PublicKey = P>,
    St: Strategy,
{
    let parallelism = strategy.parallelism_hint();
    if parallelism <= 1 || transactions.len() <= parallelism {
        if !verify_transaction_batch::<P, H, B>(namespace, rng, &transactions) {
            return None;
        }
        return transactions
            .into_iter()
            .map(|lazy| lazy.get().cloned())
            .collect();
    }

    verify_transaction_chunks::<P, H, B, _>(strategy, namespace, rng, transactions)
}

/// Spawns signature verification and returns the elapsed time.
pub(super) async fn verify_signatures<E, P, H, B, St>(
    runtime: E,
    strategy: St,
    namespace: &'static [u8],
    transactions: Vec<Lazy<SignedTransaction<P, H>>>,
) -> Result<u128>
where
    E: Spawner + CryptoRngCore,
    P: PublicKey,
    H: Hasher,
    B: BatchVerifier<PublicKey = P> + Send + Sync + 'static,
    St: Strategy + Send + Sync + 'static,
{
    let handle = runtime.shared(true).spawn(move |mut runtime| async move {
        let started_at = Instant::now();
        verify_transactions::<P, H, B, _>(&strategy, namespace, &mut runtime, transactions)
            .map(|_| started_at.elapsed().as_millis())
    });

    handle
        .await
        .expect("signature verification task failed")
        .ok_or(INVALID_SIGNATURE)
}

/// Waits until a block timestamp deadline and returns the elapsed time.
pub(super) async fn wait_for_timestamp<E>(
    runtime: E,
    deadline: std::time::SystemTime,
) -> Result<u128>
where
    E: Clock,
{
    let started_at = Instant::now();
    runtime.sleep_until(deadline).await;
    Ok(started_at.elapsed().as_millis())
}

/// Materializes transactions and caches sender addresses.
pub(super) fn prepare_transactions<P, H, St>(
    strategy: &St,
    transactions: Vec<Lazy<SignedTransaction<P, H>>>,
) -> Option<Prepared<P, H>>
where
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    let transactions = materialize_transaction_chunks(strategy, transactions)?;
    let signers = transaction_senders(strategy, &transactions)?;
    Some(Prepared {
        transactions,
        signers,
    })
}

/// Executes and merkleizes a block body for verification.
pub(super) async fn execute_block<E, C, P, H, St>(
    strategy: &St,
    state_batches: StateBatch<E, H, EightCap>,
    transaction_batch: TransactionBatch<E, H>,
    parent: &SealedBlock<C, P, H>,
    transactions: Vec<Lazy<SignedTransaction<P, H>>>,
) -> Result<Execution<E, H>>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    let prepare_started_at = Instant::now();
    let prepared = prepare_transactions(strategy, transactions).ok_or(MALFORMED_TRANSACTION)?;
    let prepare_ms = prepare_started_at.elapsed().as_millis();

    let load_state_started_at = Instant::now();
    let state = load_state(&state_batches, &prepared.transactions, &prepared.signers)
        .await
        .expect("block state loading during verification must succeed");
    let load_state_ms = load_state_started_at.elapsed().as_millis();

    let execute_started_at = Instant::now();
    let changeset = executor::execute(&state, &prepared.transactions, &prepared.signers)
        .ok_or(STATIC_INVALID_TRANSACTION)?;
    let execute_ms = execute_started_at.elapsed().as_millis();

    let state_batch = apply_changeset(state_batches, &changeset);
    let transaction_batch = apply_transaction_digests(transaction_batch, &prepared.transactions)
        .with_inactivity_floor(parent_transactions_inactivity_floor(parent));
    let transactions_range = child_transactions_range(parent, prepared.transactions.len());

    let finalize_started_at = Instant::now();
    let (state, transactions) = finalize_execution(state_batch, transaction_batch)
        .await
        .expect("database merkleization during verification must succeed");
    let finalize_ms = finalize_started_at.elapsed().as_millis();

    Ok(Execution {
        state,
        transactions,
        transactions_range,
        transaction_count: prepared.transactions.len(),
        timings: ExecutionTimings {
            prepare_ms,
            load_state_ms,
            execute_ms,
            finalize_ms,
        },
    })
}

/// Logs a verification rejection.
pub(super) fn reject(height: u64, reason: &'static str) {
    warn!(height, reason, "verify rejected");
}

/// Returns whether execution output matches the proposed header.
pub(super) fn commitments_match<E, C, P, H>(
    header: &Header<C, H::Digest, P>,
    execution: &Execution<E, H>,
) -> bool
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let state_range =
        non_empty_range!(*execution.state.inactivity_floor(), *execution.state.size());

    if execution.state.root() != header.state_root {
        warn!(
            height = header.height,
            "verify rejected: state root mismatch"
        );
        return false;
    }
    if state_range != header.state_range {
        warn!(
            height = header.height,
            "verify rejected: state range mismatch"
        );
        return false;
    }
    if execution.transactions.root() != header.transactions_root {
        warn!(
            height = header.height,
            "verify rejected: transaction root mismatch"
        );
        return false;
    }
    if execution.transactions_range != header.transactions_range {
        warn!(
            height = header.height,
            "verify rejected: transaction range mismatch"
        );
        return false;
    }

    true
}
