//! Consensus-facing application integration.
//!
//! This module bridges consensus, the mempool, the processor, and the backing
//! databases. It is responsible for:
//!
//! - proposing blocks from mempool transactions
//! - filtering or rejecting invalid signatures before execution
//! - loading processor state from speculative database batches
//! - executing transaction slices against that loaded state
//! - finalizing state roots and transaction roots
//! - verifying and applying certified blocks
//!
//! The execution boundary is intentionally narrow: the [`Application`] owns
//! the execution strategy and QMDB integration, while the processor owns the
//! in-memory state transition logic.

use crate::processor::{
    executor::{self, Changeset, ProposalOutput},
    state::State,
};
use commonware_consensus::{
    marshal::ancestry::{AncestorStream, BlockProvider},
    simplex::types::Context,
    types::{Round, View},
};
use commonware_cryptography::{
    BatchVerifier, Digest, Digestible, Hasher, PublicKey, certificate::Scheme,
};
use commonware_glue::stateful::{
    Application as CApplication, Proposed,
    db::{
        DatabaseSet, Merkleized as _, Unmerkleized, any::AnyUnmerkleized,
        immutable::ImmutableUnmerkleized,
    },
};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::{
    index::unordered::Index as UnorderedIndex,
    journal::contiguous::fixed::Journal as FixedJournal,
    mmr,
    qmdb::{
        Error as StorageError,
        any::{
            operation::Operation as AnyOperation,
            unordered::{Update as UnorderedUpdate, fixed},
            value::FixedEncoding,
        },
        sync::Target,
    },
    translator::{EightCap, Translator},
};
use commonware_utils::{non_empty_range, sync::AsyncRwLock};
use constantinople_mempool::TransactionSource;
use constantinople_primitives::{
    Account, Address, Block, Header, Sealable, SealedBlock, SignedTransaction, VerifiedTransaction,
};
use futures::{StreamExt, stream::FuturesUnordered};
use prometheus_client::metrics::counter::Counter;
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand_core::CryptoRngCore;
use std::{
    marker::PhantomData,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tracing::{info, warn};

/// Fixed consensus cutoff for block timestamps: 2200-01-01T00:00:00Z.
///
/// Different platforms have different `SystemTime` limits, so we use a fixed
/// timestamp to ensure consistent application of block validity rules.
const MAX_BLOCK_TIMESTAMP_MS: u64 = 7_258_118_400_000;

/// Number of `load_state` tasks to schedule per available worker.
const LOAD_STATE_TASKS_PER_WORKER: usize = 2;

/// Shared QMDB handle for the application state database.
type StateDatabase<E, H, T> = Arc<AsyncRwLock<fixed::Db<mmr::Family, E, Address, Account, H, T>>>;

/// Shared immutable transaction database handle.
type TransactionDatabase<E, H> = Arc<
    AsyncRwLock<
        commonware_storage::qmdb::immutable::fixed::Db<
            mmr::Family,
            E,
            <H as Hasher>::Digest,
            (),
            H,
            EightCap,
        >,
    >,
>;

/// The pair of backing databases owned by the application.
type Databases<E, H, T> = (StateDatabase<E, H, T>, TransactionDatabase<E, H>);

/// Unmerkleized application state batch used for processor read-through.
type StateBatch<E, H, T> = AnyUnmerkleized<
    E,
    FixedJournal<E, AnyOperation<mmr::Family, UnorderedUpdate<Address, FixedEncoding<Account>>>>,
    UnorderedIndex<T, mmr::Location>,
    H,
    UnorderedUpdate<Address, FixedEncoding<Account>>,
>;

type TransactionJournal<E, H> = FixedJournal<
    E,
    commonware_storage::qmdb::immutable::fixed::Operation<<H as Hasher>::Digest, ()>,
>;

/// Unmerkleized transaction batch used for append-only transaction storage.
type TransactionBatch<E, H> = ImmutableUnmerkleized<
    E,
    <H as Hasher>::Digest,
    FixedEncoding<()>,
    TransactionJournal<E, H>,
    H,
    EightCap,
>;

/// Merkleized state database produced after finalization.
type StateMerkleized<E, H, T> = <StateBatch<E, H, T> as Unmerkleized>::Merkleized;

/// Merkleized transaction database produced after finalization.
type TransactionsMerkleized<E, H> = <TransactionBatch<E, H> as Unmerkleized>::Merkleized;

/// Errors raised while preparing processor state from the backing database.
#[derive(Debug, Error)]
pub enum ProcessorError {
    #[error("state database access failed")]
    Database(#[from] StorageError<mmr::Family>),
}

/// Loads the accounts needed by `transactions` from `batch`.
///
/// The loader gathers every unique sender and recipient across the block body,
/// reads each account at most once, and builds an in-memory [`State`] snapshot
/// for verification.
pub async fn load_state<E, H, P, T>(
    batch: &StateBatch<E, H, T>,
    transactions: &[VerifiedTransaction<P, H>],
    parallelism_hint: usize,
) -> Result<State, ProcessorError>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    T: Translator,
{
    let mut account_keys = Vec::with_capacity(transactions.len().saturating_mul(2));
    for transaction in transactions {
        account_keys.push(transaction.signer());
        account_keys.push(transaction.value().to);
    }

    account_keys.sort_unstable();
    account_keys.dedup();

    if account_keys.is_empty() {
        return Ok(State::from_loaded_accounts(account_keys, Vec::new()));
    }

    let db = batch.lock().await;
    let db = &*db;
    let state_batch = batch.batch();
    let chunk_size = load_state_chunk_size(account_keys.len(), parallelism_hint);
    let pending_reads = account_keys
        .chunks(chunk_size)
        .enumerate()
        .map(|(chunk_index, chunk)| async move {
            let mut accounts = Vec::with_capacity(chunk.len());
            for address in chunk {
                let account = state_batch.get(address, db).await?;
                accounts.push(account.unwrap_or_default());
            }

            Ok::<_, ProcessorError>((chunk_index, accounts))
        })
        .collect::<FuturesUnordered<_>>();
    let mut chunked_accounts = pending_reads
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    chunked_accounts.sort_unstable_by_key(|(chunk_index, _)| *chunk_index);

    let mut accounts = Vec::with_capacity(account_keys.len());
    for (_, chunk_accounts) in chunked_accounts {
        accounts.extend(chunk_accounts);
    }

    Ok(State::from_loaded_accounts(account_keys, accounts))
}

fn load_state_chunk_size(address_count: usize, parallelism_hint: usize) -> usize {
    let worker_count = parallelism_hint.max(1);
    let chunk_count = address_count.min(worker_count * LOAD_STATE_TASKS_PER_WORKER);

    address_count.div_ceil(chunk_count.max(1))
}

/// Writes a changeset of account updates to a state batch.
fn apply_changeset<E, H>(
    batch: StateBatch<E, H, EightCap>,
    changeset: &Changeset,
) -> StateBatch<E, H, EightCap>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
{
    changeset.iter().fold(batch, |batch, (address, account)| {
        batch.write(*address, Some(*account))
    })
}

/// Records verified transaction digests in the transaction batch.
fn record_transactions<E, H, PK>(
    batch: TransactionBatch<E, H>,
    transactions: &[VerifiedTransaction<PK, H>],
) -> TransactionBatch<E, H>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    PK: PublicKey,
{
    transactions.iter().fold(batch, |batch, transaction| {
        batch.set(*transaction.message_digest(), ())
    })
}

/// Returns elapsed milliseconds for a started instant.
fn elapsed_ms(started_at: Instant) -> u128 {
    started_at.elapsed().as_millis()
}

/// Verifies a batch of signed transactions.
fn verify_transaction_batch<P, H, B>(
    namespace: &[u8],
    rng: &mut impl CryptoRngCore,
    transactions: &[SignedTransaction<P, H>],
) -> bool
where
    P: PublicKey,
    H: Hasher,
    B: BatchVerifier<PublicKey = P>,
{
    let mut batch_verifier = B::new();
    for transaction in transactions {
        // Decode the sender and signature inside the worker so decompression
        // happens on the rayon pool instead of the runtime thread.
        let Some(sender) = transaction.value().sender() else {
            return false;
        };
        let Some(signature) = transaction.signature() else {
            return false;
        };

        if !batch_verifier.add(
            namespace,
            transaction.message_digest().as_ref(),
            sender,
            signature,
        ) {
            return false;
        }
    }

    batch_verifier.verify(rng)
}

/// Verifies transactions across strategy partitions and preserves block order.
fn verify_transaction_chunks<P, H, B, St>(
    strategy: &St,
    namespace: &'static [u8],
    rng: &mut impl CryptoRngCore,
    transactions: Vec<SignedTransaction<P, H>>,
) -> Option<Vec<VerifiedTransaction<P, H>>>
where
    P: PublicKey,
    H: Hasher,
    B: BatchVerifier<PublicKey = P>,
    St: Strategy,
{
    if transactions.is_empty() {
        return Some(Vec::new());
    }

    let chunk_count = strategy.parallelism_hint().min(transactions.len());
    let chunk_size = transactions.len().div_ceil(chunk_count);

    let mut pending = transactions.into_iter();
    let mut chunks = Vec::with_capacity(chunk_count);
    loop {
        let mut chunk = Vec::with_capacity(chunk_size);
        for _ in 0..chunk_size {
            let Some(transaction) = pending.next() else {
                break;
            };
            chunk.push(transaction);
        }

        if chunk.is_empty() {
            break;
        }

        let mut rng_seed = [0; 32];
        rng.fill_bytes(&mut rng_seed);
        chunks.push((rng_seed, chunk));
    }

    let verified_chunks = strategy.map_collect_vec(chunks, |(rng_seed, chunk)| {
        let mut chunk_rng = StdRng::from_seed(rng_seed);
        verify_transaction_batch::<P, H, B>(namespace, &mut chunk_rng, &chunk)
            .then(|| chunk.into_iter().map(Into::into).collect::<Vec<_>>())
    });

    let mut verified = Vec::new();
    for chunk in verified_chunks {
        verified.extend(chunk?);
    }
    Some(verified)
}

/// Core constantinople application.
///
/// This type implements the consensus application trait on top of the
/// processor and the managed state databases.
pub struct Application<H, C, S, P, I, B, St> {
    strategy: St,
    genesis_leader: P,
    transaction_namespace: &'static [u8],
    proposed_transactions: Counter,
    _marker: PhantomData<(H, C, S, I, B)>,
}

impl<H, C, S, P, I, B, St> Clone for Application<H, C, S, P, I, B, St>
where
    H: Hasher,
    P: Clone,
    St: Clone,
{
    fn clone(&self) -> Self {
        Self {
            strategy: self.strategy.clone(),
            genesis_leader: self.genesis_leader.clone(),
            transaction_namespace: self.transaction_namespace,
            proposed_transactions: self.proposed_transactions.clone(),
            _marker: PhantomData,
        }
    }
}

impl<H: Hasher, C, S, P, I, B, St> Application<H, C, S, P, I, B, St> {
    /// Creates an application.
    ///
    /// The application keeps the execution strategy, genesis leader, and
    /// transaction signing namespace for all later block proposal,
    /// verification, and application.
    pub fn new(
        context: impl Metrics,
        strategy: St,
        genesis_leader: P,
        transaction_namespace: &'static [u8],
    ) -> Self {
        let proposed_transactions = Counter::default();
        context.register(
            "proposed_transactions",
            "The number of transactions proposed into blocks",
            proposed_transactions.clone(),
        );

        Self {
            strategy,
            genesis_leader,
            transaction_namespace,
            proposed_transactions,
            _marker: PhantomData,
        }
    }
}

impl<H, C, S, P, I, B, St> Application<H, C, S, P, I, B, St>
where
    C: Digest,
    H: Hasher,
    P: PublicKey,
    B: BatchVerifier<PublicKey = P>,
    St: Strategy,
{
    /// Verifies signed wire transactions and returns verified execution transactions.
    fn verify_transactions(
        &self,
        rng: &mut impl CryptoRngCore,
        transactions: Vec<SignedTransaction<P, H>>,
    ) -> Option<Vec<VerifiedTransaction<P, H>>> {
        let parallelism = self.strategy.parallelism_hint();
        if parallelism <= 1 || transactions.len() <= parallelism {
            return verify_transaction_batch::<P, H, B>(
                self.transaction_namespace,
                rng,
                &transactions,
            )
            .then(|| transactions.into_iter().map(Into::into).collect());
        }

        verify_transaction_chunks::<P, H, B, _>(
            &self.strategy,
            self.transaction_namespace,
            rng,
            transactions,
        )
    }

    /// Returns the current Unix timestamp in milliseconds.
    fn timestamp<E>(&self, runtime: &E) -> u64
    where
        E: Clock,
    {
        let timestamp_ms = runtime
            .current()
            .duration_since(UNIX_EPOCH)
            .expect("clock moved before unix epoch")
            .as_millis();
        u64::try_from(timestamp_ms).expect("timestamp milliseconds exceeded u64")
    }

    /// Returns the absolute wakeup time for `block_timestamp_ms`.
    ///
    /// # Panics
    ///
    /// Panics if `block_timestamp_ms` cannot be represented as a
    /// [`SystemTime`] offset from the Unix epoch.
    fn block_deadline(&self, block_timestamp_ms: u64) -> SystemTime {
        UNIX_EPOCH
            .checked_add(Duration::from_millis(block_timestamp_ms))
            .expect("block timestamp exceeded maximum")
    }

    /// Merkleizes the updated databases together.
    ///
    /// This runs the independent finalization work in parallel so proposal,
    /// verification, and application all share the same finalization path.
    ///
    /// # Errors
    ///
    /// Returns any storage error from database merkleization.
    async fn finalize_execution<E>(
        &self,
        state_batch: StateBatch<E, H, EightCap>,
        transaction_batch: TransactionBatch<E, H>,
    ) -> Result<
        (
            StateMerkleized<E, H, EightCap>,
            TransactionsMerkleized<E, H>,
        ),
        StorageError<mmr::Family>,
    >
    where
        E: Storage + Clock + Metrics,
    {
        futures::try_join!(state_batch.merkleize(), transaction_batch.merkleize(),)
    }
}

impl<E, H, C, S, P, I, B, St> CApplication<E> for Application<H, C, S, P, I, B, St>
where
    E: Rng + Spawner + Storage + Metrics + Clock + CryptoRngCore,
    H: Hasher,
    C: Digest,
    S: Scheme<PublicKey = P>,
    P: PublicKey,
    I: TransactionSource<C, P, H> + Sync,
    B: BatchVerifier<PublicKey = P> + Send + Sync + 'static,
    St: Strategy + Clone + Send + Sync + 'static,
{
    type SigningScheme = S;
    type Context = Context<C, P>;
    type Block = SealedBlock<C, P, H>;
    type Databases = Databases<E, H, EightCap>;
    type InputProvider = I;

    /// Returns the sync targets required to fetch the block's state.
    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        let state_target = Target {
            root: block.header.state_root,
            range: non_empty_range!(
                mmr::Location::new(block.header.state_range.start()),
                mmr::Location::new(block.header.state_range.end())
            ),
        };
        let transactions_target = Target {
            root: block.header.transactions_root,
            range: non_empty_range!(
                mmr::Location::new(block.header.transactions_range.start()),
                mmr::Location::new(block.header.transactions_range.end())
            ),
        };

        (state_target, transactions_target)
    }

    /// Builds the genesis block.
    ///
    /// The genesis block always uses timestamp `0` and the configured genesis
    /// leader.
    async fn genesis(&mut self) -> Self::Block {
        genesis_block(&mut H::default(), self.genesis_leader.clone(), 0)
    }

    /// Proposes the next block from the mempool and current ancestry.
    ///
    /// Proposal consumes already-verified mempool transactions, preloads the
    /// touched accounts, filters out statically invalid transfers, and
    /// executes the survivors against in-memory state before block
    /// construction.
    async fn propose<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        (runtime, context): (E, Self::Context),
        mut ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        input: &mut Self::InputProvider,
    ) -> Option<Proposed<Self, E>> {
        let propose_started_at = Instant::now();
        let parent = ancestry.next().await?;

        let input_started_at = Instant::now();
        let body = input.propose(&parent.header, &context).await;
        let input_ms = elapsed_ms(input_started_at);

        let (state_batch, transaction_batch) = batches;

        let load_state_started_at = Instant::now();
        let state = load_state(&state_batch, &body, self.strategy.parallelism_hint())
            .await
            .expect("proposal state loading must succeed");
        let load_state_ms = elapsed_ms(load_state_started_at);

        let execute_started_at = Instant::now();
        let ProposalOutput {
            valid,
            invalid: _,
            changeset,
        } = executor::propose(state, body);
        let execute_ms = elapsed_ms(execute_started_at);

        self.proposed_transactions.inc_by(valid.len() as u64);

        let transaction_batch = record_transactions(transaction_batch, &valid);
        let state_batch = apply_changeset(state_batch, &changeset);

        let finalize_started_at = Instant::now();
        let (state_merkleized, transaction_merkleized) = self
            .finalize_execution(state_batch, transaction_batch)
            .await
            .expect("database merkleization must succeed");
        let finalize_ms = elapsed_ms(finalize_started_at);
        let state_diff_len = state_merkleized.diff_len();
        let transaction_diff_len = transaction_merkleized.diff_len();
        let transactions_end = parent.header.transactions_range.end() + valid.len() as u64 + 1;

        let header = Header {
            context,
            parent: parent.digest(),
            height: parent.header.height + 1,
            timestamp: self.timestamp(&runtime),
            state_root: state_merkleized.root(),
            state_range: non_empty_range!(
                *state_merkleized.inactivity_floor(),
                *state_merkleized.size()
            ),
            transactions_root: transaction_merkleized.root(),
            transactions_range: non_empty_range!(0, transactions_end),
        };
        let body = valid
            .into_iter()
            .map(VerifiedTransaction::into_inner)
            .collect();
        let block = Block::new(header, body).seal(&mut H::default());

        info!(
            epoch = block.header.context.round.epoch().get(),
            view = block.header.context.round.view().get(),
            height = block.header.height,
            txs = block.body.len(),
            timestamp = block.header.timestamp,
            input_ms,
            load_state_ms,
            execute_ms,
            finalize_ms,
            state_diff_len,
            transaction_diff_len,
            total_ms = elapsed_ms(propose_started_at),
            "proposed block"
        );

        Some(Proposed {
            block,
            merkleized: (state_merkleized, transaction_merkleized),
        })
    }

    /// Verifies a proposed block against speculative execution.
    ///
    /// Verification rejects invalid transaction signatures and invalid
    /// timestamps, then waits until the block timestamp has passed to
    /// account for clock skew. After the wait, it re-executes the block
    /// and compares all derived roots and ranges.
    async fn verify<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        (mut runtime, _context): (E, Self::Context),
        mut ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        let verify_started_at = Instant::now();
        let Block { header, body } = ancestry.next().await?.into_inner();
        let parent = ancestry.next().await?;

        let signature_started_at = Instant::now();
        let Some(verified_body) = self.verify_transactions(&mut runtime, body) else {
            warn!(height = header.height, "verify rejected: invalid signature");
            return None;
        };
        let signature_ms = elapsed_ms(signature_started_at);

        if header.timestamp <= parent.header.timestamp || header.timestamp > MAX_BLOCK_TIMESTAMP_MS
        {
            warn!(
                height = header.height,
                block_ts = header.timestamp,
                parent_ts = parent.header.timestamp,
                "verify rejected: invalid timestamp"
            );
            return None;
        }

        // Wait until the block timestamp has passed to vote in case of skew.
        let deadline = self.block_deadline(header.timestamp);
        let sleep_started_at = Instant::now();
        runtime.sleep_until(deadline).await;
        let sleep_ms = elapsed_ms(sleep_started_at);

        let (state_batch, transaction_batch) = batches;

        let load_state_started_at = Instant::now();
        let state = load_state(
            &state_batch,
            &verified_body,
            self.strategy.parallelism_hint(),
        )
        .await
        .expect("block state loading during verification must succeed");
        let load_state_ms = elapsed_ms(load_state_started_at);

        let body_len = verified_body.len();

        let execute_started_at = Instant::now();
        let Some(changeset) = executor::execute(state, &verified_body) else {
            warn!(
                height = header.height,
                "verify rejected: statically invalid transaction"
            );
            return None;
        };
        let execute_ms = elapsed_ms(execute_started_at);

        let transaction_batch = record_transactions(transaction_batch, &verified_body);
        let state_batch = apply_changeset(state_batch, &changeset);

        let finalize_started_at = Instant::now();
        let (state_merkleized, transaction_merkleized) = self
            .finalize_execution(state_batch, transaction_batch)
            .await
            .expect("database merkleization during verification must succeed");
        let finalize_ms = elapsed_ms(finalize_started_at);
        let state_diff_len = state_merkleized.diff_len();
        let transaction_diff_len = transaction_merkleized.diff_len();

        let state_range = non_empty_range!(
            *state_merkleized.inactivity_floor(),
            *state_merkleized.size()
        );
        let transactions_end = parent.header.transactions_range.end() + body_len as u64 + 1;
        let transactions_range = non_empty_range!(0, transactions_end);

        if state_merkleized.root() != header.state_root {
            warn!(
                height = header.height,
                "verify rejected: state root mismatch"
            );
            return None;
        }
        if state_range != header.state_range {
            warn!(
                height = header.height,
                "verify rejected: state range mismatch"
            );
            return None;
        }
        if transaction_merkleized.root() != header.transactions_root {
            warn!(
                height = header.height,
                "verify rejected: transactions root mismatch"
            );
            return None;
        }
        if transactions_range != header.transactions_range {
            warn!(
                height = header.height,
                "verify rejected: transactions range mismatch"
            );
            return None;
        }

        info!(
            epoch = header.context.round.epoch().get(),
            view = header.context.round.view().get(),
            height = header.height,
            txs = verified_body.len(),
            timestamp = header.timestamp,
            signature_ms,
            sleep_ms,
            load_state_ms,
            execute_ms,
            finalize_ms,
            state_diff_len,
            transaction_diff_len,
            total_ms = elapsed_ms(verify_started_at),
            "verified block"
        );
        Some((state_merkleized, transaction_merkleized))
    }

    /// Applies a certified block to speculative batches and returns merkleized state.
    ///
    /// Unlike verification, application assumes consensus has already
    /// certified the block. It reconstitutes verified execution transactions
    /// from the signed wire block and deterministically replays them to
    /// derive the merkleized database pair.
    ///
    /// # Panics
    ///
    /// Panics if the certified block contains an invalid signature or if
    /// execution or database finalization fails.
    async fn apply(
        &mut self,
        (mut runtime, _): (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet<E>>::Merkleized {
        let verified_body = self
            .verify_transactions(&mut runtime, block.body.clone())
            .expect("certified block contained an invalid signature");

        let (state_batch, transaction_batch) = batches;
        let state = load_state(
            &state_batch,
            &verified_body,
            self.strategy.parallelism_hint(),
        )
        .await
        .expect("state loading must succeed for certified apply");
        let changeset = executor::execute(state, &verified_body)
            .expect("certified block contained a statically invalid transaction");
        let transaction_batch = record_transactions(transaction_batch, &verified_body);
        let state_batch = apply_changeset(state_batch, &changeset);
        self.finalize_execution(state_batch, transaction_batch)
            .await
            .expect("database merkleization must succeed")
    }
}

/// Creates the genesis block.
///
/// The genesis block starts with empty state, empty transactions, and the
/// provided leader and timestamp.
pub fn genesis_block<C, P, H>(hasher: &mut H, leader: P, timestamp: u64) -> SealedBlock<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let header = Header {
        context: Context {
            round: Round::zero(),
            leader,
            parent: (View::zero(), C::EMPTY),
        },
        parent: H::Digest::EMPTY,
        height: 0,
        timestamp,
        state_root: H::Digest::EMPTY,
        state_range: non_empty_range!(0, 1),
        transactions_root: H::Digest::EMPTY,
        transactions_range: non_empty_range!(0, 1),
    };

    Block::<C, P, H>::new(header, Vec::new()).seal(hasher)
}

#[cfg(test)]
mod tests {
    use super::{load_state_chunk_size, verify_transaction_chunks};
    use commonware_codec::{DecodeExt, Encode, FixedSize};
    use commonware_cryptography::{Signer as _, blake3, ed25519};
    use commonware_parallel::Rayon;
    use constantinople_primitives::{Address, Signable, SignedTransaction, Transaction};
    use core::num::{NonZeroU64, NonZeroUsize};
    use rand::{SeedableRng, rngs::StdRng};

    const NAMESPACE: &[u8] = b"consensus-test";

    #[derive(Debug, Clone)]
    struct TestSigner {
        key: ed25519::PrivateKey,
        address: Address,
    }

    impl TestSigner {
        fn from_seed(seed: u64) -> Self {
            let key = ed25519::PrivateKey::from_seed(seed);
            let address =
                Address::from_public_key(&mut blake3::Blake3::default(), &key.public_key());
            Self { key, address }
        }
    }

    fn signed_transaction(
        signer: &TestSigner,
        to: Address,
        nonce: u64,
    ) -> SignedTransaction<ed25519::PublicKey, blake3::Blake3> {
        Transaction::new(
            signer.key.public_key(),
            to,
            NonZeroU64::new(nonce + 1).expect("test value should be non-zero"),
            nonce,
        )
        .seal_and_sign(&signer.key, NAMESPACE, &mut blake3::Blake3::default())
    }

    fn invalid_transaction(
        claimed_signer: &TestSigner,
        actual_signer: &TestSigner,
        to: Address,
        nonce: u64,
    ) -> SignedTransaction<ed25519::PublicKey, blake3::Blake3> {
        Transaction::new(
            claimed_signer.key.public_key(),
            to,
            NonZeroU64::new(nonce + 1).expect("test value should be non-zero"),
            nonce,
        )
        .seal_and_sign(
            &actual_signer.key,
            NAMESPACE,
            &mut blake3::Blake3::default(),
        )
    }

    #[test]
    fn chunked_verification_preserves_transaction_order() {
        let strategy =
            Rayon::new(NonZeroUsize::new(4).expect("test thread count should be non-zero"))
                .expect("rayon strategy should construct");
        let sender = TestSigner::from_seed(7);
        let recipient = TestSigner::from_seed(9);
        let transactions = (0..64)
            .map(|nonce| signed_transaction(&sender, recipient.address, nonce))
            .collect::<Vec<_>>();
        let expected_digests = transactions
            .iter()
            .map(|transaction| *transaction.message_digest())
            .collect::<Vec<_>>();
        let mut rng = StdRng::seed_from_u64(11);

        let verified = verify_transaction_chunks::<
            ed25519::PublicKey,
            blake3::Blake3,
            ed25519::Batch,
            _,
        >(&strategy, NAMESPACE, &mut rng, transactions)
        .expect("valid chunked verification should succeed");
        let verified_digests = verified
            .iter()
            .map(|transaction| *transaction.message_digest())
            .collect::<Vec<_>>();

        assert_eq!(verified_digests, expected_digests);
    }

    #[test]
    fn chunked_verification_rejects_invalid_signature() {
        let strategy =
            Rayon::new(NonZeroUsize::new(4).expect("test thread count should be non-zero"))
                .expect("rayon strategy should construct");
        let sender = TestSigner::from_seed(13);
        let attacker = TestSigner::from_seed(17);
        let recipient = TestSigner::from_seed(19);
        let mut transactions = (0..64)
            .map(|nonce| signed_transaction(&sender, recipient.address, nonce))
            .collect::<Vec<_>>();
        transactions[31] = invalid_transaction(&sender, &attacker, recipient.address, 31);
        let mut rng = StdRng::seed_from_u64(23);

        let verified = verify_transaction_chunks::<
            ed25519::PublicKey,
            blake3::Blake3,
            ed25519::Batch,
            _,
        >(&strategy, NAMESPACE, &mut rng, transactions);

        assert!(verified.is_none());
    }

    #[test]
    fn chunked_verification_rejects_malformed_sender() {
        let strategy =
            Rayon::new(NonZeroUsize::new(4).expect("test thread count should be non-zero"))
                .expect("rayon strategy should construct");
        let sender = TestSigner::from_seed(29);
        let recipient = TestSigner::from_seed(31);
        let transaction = signed_transaction(&sender, recipient.address, 0);
        let mut encoded = transaction.encode().to_vec();

        let invalid_sender = (0u8..=u8::MAX)
            .flat_map(|first| (0u8..=u8::MAX).map(move |last| (first, last)))
            .find_map(|(first, last)| {
                let mut candidate = [0; ed25519::PublicKey::SIZE];
                candidate[0] = first;
                candidate[ed25519::PublicKey::SIZE - 1] = last;

                ed25519::PublicKey::decode(&mut &candidate[..])
                    .is_err()
                    .then_some(candidate)
            })
            .expect("test should find invalid sender bytes");
        encoded[..invalid_sender.len()].copy_from_slice(&invalid_sender);

        let malformed =
            SignedTransaction::<ed25519::PublicKey, blake3::Blake3>::decode(&mut &encoded[..])
                .expect("decode should defer sender validation");
        let mut rng = StdRng::seed_from_u64(37);

        let verified = verify_transaction_chunks::<
            ed25519::PublicKey,
            blake3::Blake3,
            ed25519::Batch,
            _,
        >(&strategy, NAMESPACE, &mut rng, vec![malformed]);

        assert!(verified.is_none());
    }

    #[test]
    fn load_state_chunk_size_scales_with_parallelism() {
        assert_eq!(load_state_chunk_size(1, 4), 1);
        assert_eq!(load_state_chunk_size(8, 4), 1);
        assert_eq!(load_state_chunk_size(16, 4), 2);
        assert_eq!(load_state_chunk_size(17, 4), 3);
        assert_eq!(load_state_chunk_size(32, 0), 16);
    }
}
