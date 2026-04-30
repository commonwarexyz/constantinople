//! Block verification pipeline helpers.

use super::{
    db::{
        StateBatch, StateMerkleized, TransactionBatch, TransactionMerkleized, apply_changeset,
        finalize_execution,
    },
    execution::{BlockExecution, ExecutionTimings, finalize_child_execution},
    utils::load_accounts,
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
use hashbrown::HashSet;
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

/// Transfer metadata prepared once for state loading and execution.
struct PreparedTransfer<P, H>
where
    H: Hasher,
    P: PublicKey,
{
    sender: AccountKey<P>,
    recipient: AccountKey<P>,
    value: u64,
    nonce: u64,
    digest: H::Digest,
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

fn prepare_transfers<P, H>(
    transactions: &[Lazy<SignedTransaction<P, H>>],
) -> Option<Vec<PreparedTransfer<P, H>>>
where
    P: PublicKey,
    H: Hasher,
{
    let mut transfers = Vec::with_capacity(transactions.len());
    for transaction in transactions {
        transfers.push(prepare_transfer(transaction)?);
    }
    Some(transfers)
}

fn prepare_transfer<P, H>(
    transaction: &Lazy<SignedTransaction<P, H>>,
) -> Option<PreparedTransfer<P, H>>
where
    P: PublicKey,
    H: Hasher,
{
    let transaction = transaction.get()?;
    let transfer = transaction.value();
    Some(PreparedTransfer {
        sender: account_key_from_public_key_bytes(transfer.sender_lazy())?,
        recipient: transfer.to.clone(),
        value: transfer.value.get(),
        nonce: transfer.nonce,
        digest: *transaction.message_digest(),
    })
}

fn account_key_from_public_key_bytes<P>(public_key: &Lazy<P>) -> Option<AccountKey<P>>
where
    P: PublicKey,
{
    let mut bytes = BytesMut::with_capacity(P::SIZE);
    public_key.write(&mut bytes);
    AccountKey::from_bytes(bytes.freeze())
}

async fn load_transfer_state<E, H, P>(
    batch: &StateBatch<E, H, P, EightCap>,
    transfers: &[PreparedTransfer<P, H>],
) -> core::result::Result<
    Option<crate::processor::state::State<P>>,
    commonware_storage::qmdb::Error<mmr::Family>,
>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
{
    let mut account_keys = HashSet::with_capacity(transfers.len().saturating_mul(2));
    for transfer in transfers {
        account_keys.insert(transfer.sender.clone());
        account_keys.insert(transfer.recipient.clone());
    }
    load_accounts(batch, account_keys).await
}

fn execute_transfers<P, H>(
    state: &crate::processor::state::State<P>,
    transfers: &[PreparedTransfer<P, H>],
) -> Option<executor::Changeset<P>>
where
    H: Hasher,
    P: PublicKey,
{
    executor::execute_transfers(
        state,
        transfers.len(),
        transfers.iter().map(|transfer| {
            Some(executor::Transfer {
                sender: &transfer.sender,
                recipient: &transfer.recipient,
                value: transfer.value,
                nonce: transfer.nonce,
            })
        }),
    )
}

fn apply_transfer_digests<E, H, P>(
    batch: TransactionBatch<E, H>,
    transfers: &[PreparedTransfer<P, H>],
) -> TransactionBatch<E, H>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
{
    transfers
        .iter()
        .fold(batch, |batch, transfer| batch.append(transfer.digest))
}

/// Executes and merkleizes a block body for verification.
pub(super) async fn execute_block<E, C, P, H, St>(
    state_batches: StateBatch<E, H, P, EightCap>,
    transaction_batch: TransactionBatch<E, H>,
    _strategy: &St,
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
    let transfers = prepare_transfers(&prepared.transactions).ok_or(MALFORMED_TRANSACTION)?;
    let prepare_signers_ms = prepare_signers_started_at.elapsed().as_millis();

    let load_state_started_at = Instant::now();
    let state = load_transfer_state(&state_batches, &transfers)
        .await
        .expect("block state loading during verification must succeed")
        .ok_or(MALFORMED_TRANSACTION)?;
    let load_state_ms = load_state_started_at.elapsed().as_millis();

    let execute_started_at = Instant::now();
    let changeset = execute_transfers(&state, &transfers).ok_or(STATIC_INVALID_TRANSACTION)?;
    let execute_ms = execute_started_at.elapsed().as_millis();

    let state_batch = apply_changeset(state_batches, &changeset);
    let transaction_batch = apply_transfer_digests(transaction_batch, &transfers);
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
    _strategy: &St,
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
    let transfers = prepare_transfers(&prepared.transactions).ok_or(MALFORMED_TRANSACTION)?;
    let state = load_transfer_state(&state_batches, &transfers)
        .await
        .expect("state loading must succeed for certified apply")
        .ok_or(MALFORMED_TRANSACTION)?;
    let changeset = execute_transfers(&state, &transfers).ok_or(STATIC_INVALID_TRANSACTION)?;

    let state_batch = apply_changeset(state_batches, &changeset);
    let transaction_batch = apply_transfer_digests(transaction_batch, &transfers)
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
