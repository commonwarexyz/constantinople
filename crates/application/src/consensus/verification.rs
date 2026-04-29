//! Block verification pipeline helpers.

use super::{
    db::{
        StateBatch, StateMerkleized, TransactionBatch, TransactionMerkleized, apply_changeset,
        apply_lazy_transaction_digests, finalize_execution,
    },
    execution::{BlockExecution, ExecutionTimings, finalize_child_execution},
    load_lazy_state,
};
use crate::processor::executor;
use bytes::BytesMut;
use commonware_codec::{Write as _, types::lazy::Lazy};
use commonware_cryptography::{BatchVerifier, Digest, Hasher, PublicKey};
use commonware_glue::stateful::db::Merkleized as _;
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::{mmr, translator::EightCap};
use constantinople_primitives::{AccountKey, Header, SealedBlock, SignedTransaction};
use rand::{SeedableRng, rngs::StdRng};
use rand_core::CryptoRngCore;
use std::{sync::Arc, time::Instant};
use tracing::warn;

pub(super) type Result<T> = core::result::Result<T, &'static str>;

const INVALID_SIGNATURE: &str = "invalid signature";
const SIGNATURE_TASK_CLOSED: &str = "signature verification task closed";
const MALFORMED_TRANSACTION: &str = "malformed transaction";
const STATIC_INVALID_TRANSACTION: &str = "statically invalid transaction";

/// Lazily decoded transactions ready for verification and execution.
pub(super) struct Prepared<P, H>
where
    H: Hasher,
    P: PublicKey,
{
    pub(super) transactions: Vec<Lazy<SignedTransaction<P, H>>>,
}

/// Verifies lazily decoded signed transactions.
fn verify_transaction_batch<P, H, B>(
    namespace: &'static [u8],
    rng: &mut impl CryptoRngCore,
    transactions: &[Lazy<SignedTransaction<P, H>>],
) -> bool
where
    P: PublicKey,
    H: Hasher,
    B: BatchVerifier<PublicKey = P>,
{
    let mut verifier = B::new();
    for lazy in transactions {
        let Some(transaction) = lazy.get() else {
            return false;
        };
        let Some(sender) = transaction.value().sender() else {
            return false;
        };
        let Some(signature) = transaction.signature() else {
            return false;
        };
        if !verifier.add(
            namespace,
            transaction.message_digest().as_ref(),
            sender,
            signature,
        ) {
            return false;
        }
    }

    verifier.verify(rng)
}

/// Verifies prepared signed transactions in parallel.
fn verify_transactions<P, H, B, St>(
    strategy: &St,
    namespace: &'static [u8],
    rng: &mut impl CryptoRngCore,
    transactions: &[Lazy<SignedTransaction<P, H>>],
) -> bool
where
    P: PublicKey,
    H: Hasher,
    B: BatchVerifier<PublicKey = P>,
    St: Strategy,
{
    if transactions.is_empty() {
        return true;
    }

    let parallelism = strategy.parallelism_hint();
    if parallelism <= 1 || transactions.len() <= parallelism {
        return verify_transaction_batch::<P, H, B>(namespace, rng, transactions);
    }

    let chunk_count = parallelism.min(transactions.len());
    let chunk_size = transactions.len().div_ceil(chunk_count);
    let chunks = transactions
        .chunks(chunk_size)
        .map(|chunk| {
            let mut rng_seed = [0; 32];
            rng.fill_bytes(&mut rng_seed);
            (rng_seed, chunk)
        })
        .collect::<Vec<_>>();

    strategy
        .map_collect_vec(chunks, |(rng_seed, chunk)| {
            let mut chunk_rng = StdRng::from_seed(rng_seed);
            verify_transaction_batch::<P, H, B>(namespace, &mut chunk_rng, chunk)
        })
        .into_iter()
        .all(|verified| verified)
}

/// Verifies prepared signatures and returns the elapsed time.
pub(super) async fn verify_signatures<E, P, H, B, St>(
    runtime: E,
    strategy: St,
    namespace: &'static [u8],
    prepared: Arc<Prepared<P, H>>,
) -> Result<u128>
where
    E: Spawner + CryptoRngCore,
    P: PublicKey,
    H: Hasher,
    B: BatchVerifier<PublicKey = P> + Send + Sync + 'static,
    St: Strategy + Send + Sync + 'static,
{
    let (result_tx, result_rx) = futures::channel::oneshot::channel();
    let _handle = runtime.shared(true).spawn(move |mut runtime| async move {
        let started_at = Instant::now();
        let result = verify_transactions::<P, H, B, _>(
            &strategy,
            namespace,
            &mut runtime,
            &prepared.transactions,
        )
        .then_some(started_at.elapsed().as_millis())
        .ok_or(INVALID_SIGNATURE);
        let _ = result_tx.send(result);
    });

    result_rx.await.map_err(|_| SIGNATURE_TASK_CLOSED)?
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

/// Wraps transactions for verification and execution.
pub(super) const fn prepare_transactions<P, H>(
    transactions: Vec<Lazy<SignedTransaction<P, H>>>,
) -> Prepared<P, H>
where
    P: PublicKey,
    H: Hasher,
{
    Prepared { transactions }
}

fn prepare_signers<P, H, St>(
    strategy: &St,
    transactions: &[Lazy<SignedTransaction<P, H>>],
) -> Option<Vec<AccountKey<P>>>
where
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    if transactions.is_empty() {
        return Some(Vec::new());
    }

    let parallelism = strategy.parallelism_hint();
    if parallelism <= 1 || transactions.len() <= parallelism {
        let mut signers = Vec::with_capacity(transactions.len());
        for transaction in transactions {
            signers.push(prepare_signer(transaction)?);
        }
        return Some(signers);
    }

    strategy
        .map_collect_vec(transactions, prepare_signer)
        .into_iter()
        .collect()
}

fn prepare_signer<P, H>(transaction: &Lazy<SignedTransaction<P, H>>) -> Option<AccountKey<P>>
where
    P: PublicKey,
    H: Hasher,
{
    let transaction = transaction.get()?;
    account_key_from_public_key_bytes(transaction.value().sender_lazy())
}

fn account_key_from_public_key_bytes<P>(public_key: &Lazy<P>) -> Option<AccountKey<P>>
where
    P: PublicKey,
{
    let mut bytes = BytesMut::with_capacity(P::SIZE);
    public_key.write(&mut bytes);
    AccountKey::from_bytes(bytes.freeze())
}

/// Executes and merkleizes a block body for verification.
pub(super) async fn execute_block<E, C, P, H, St>(
    state_batches: StateBatch<E, H, P, EightCap>,
    transaction_batch: TransactionBatch<E, H>,
    strategy: &St,
    parent: &SealedBlock<C, P, H>,
    prepared: &Prepared<P, H>,
) -> Result<BlockExecution<E, H, P>>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    let prepare_signers_started_at = Instant::now();
    let signers = prepare_signers(strategy, &prepared.transactions).ok_or(MALFORMED_TRANSACTION)?;
    let prepare_signers_ms = prepare_signers_started_at.elapsed().as_millis();

    let load_state_started_at = Instant::now();
    let state = load_lazy_state(&state_batches, &prepared.transactions, &signers)
        .await
        .expect("block state loading during verification must succeed")
        .ok_or(MALFORMED_TRANSACTION)?;
    let load_state_ms = load_state_started_at.elapsed().as_millis();

    let execute_started_at = Instant::now();
    let changeset = executor::execute_lazy(&state, &prepared.transactions, &signers)
        .ok_or(STATIC_INVALID_TRANSACTION)?;
    let execute_ms = execute_started_at.elapsed().as_millis();

    let state_batch = apply_changeset(state_batches, &changeset);
    let transaction_batch =
        apply_lazy_transaction_digests(transaction_batch, &prepared.transactions)
            .ok_or(MALFORMED_TRANSACTION)?;
    let timings = ExecutionTimings::before_finalize(prepare_signers_ms, load_state_ms, execute_ms);
    Ok(finalize_child_execution(
        state_batch,
        transaction_batch,
        parent,
        prepared.transactions.len(),
        timings,
        "database merkleization during verification must succeed",
    )
    .await)
}

/// Executes and merkleizes a certified block body.
pub(super) async fn apply_block<E, P, H, St>(
    state_batches: StateBatch<E, H, P, EightCap>,
    transaction_batch: TransactionBatch<E, H>,
    strategy: &St,
    transactions_floor: mmr::Location,
    prepared: &Prepared<P, H>,
) -> Result<(
    StateMerkleized<E, H, P, EightCap>,
    TransactionMerkleized<E, H>,
)>
where
    E: Storage + Clock + Metrics,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    let signers = prepare_signers(strategy, &prepared.transactions).ok_or(MALFORMED_TRANSACTION)?;
    let state = load_lazy_state(&state_batches, &prepared.transactions, &signers)
        .await
        .expect("state loading must succeed for certified apply")
        .ok_or(MALFORMED_TRANSACTION)?;
    let changeset = executor::execute_lazy(&state, &prepared.transactions, &signers)
        .ok_or(STATIC_INVALID_TRANSACTION)?;

    let state_batch = apply_changeset(state_batches, &changeset);
    let transaction_batch =
        apply_lazy_transaction_digests(transaction_batch, &prepared.transactions)
            .ok_or(MALFORMED_TRANSACTION)?
            .with_inactivity_floor(transactions_floor);
    Ok(finalize_execution(state_batch, transaction_batch)
        .await
        .expect("database merkleization must succeed"))
}

/// Logs a verification rejection.
pub(super) fn reject(height: u64, reason: &'static str) {
    warn!(height, reason, "verify rejected");
}

/// Returns whether execution output matches the proposed header.
pub(super) fn commitments_match<E, C, P, H>(
    header: &Header<C, H::Digest, P>,
    execution: &BlockExecution<E, H, P>,
) -> bool
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    if execution.state.root() != header.state_root {
        warn!(
            height = header.height,
            "verify rejected: state root mismatch"
        );
        return false;
    }
    if execution.state_range() != header.state_range {
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
