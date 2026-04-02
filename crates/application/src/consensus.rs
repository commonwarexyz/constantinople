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
use commonware_cryptography::{Digest, Digestible, Hasher, PublicKey, certificate::Scheme};
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
use futures::{StreamExt, future::try_join_all};
use prometheus_client::metrics::counter::Counter;
use rand::Rng;
use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tracing::{info, warn};

/// Fixed consensus cutoff for block timestamps: 2200-01-01T00:00:00Z.
///
/// Different platforms have different `SystemTime` limits, so we use a fixed
/// timestamp to ensure consistent application of block validity rules.
const MAX_BLOCK_TIMESTAMP_MS: u64 = 7_258_118_400_000;

/// Signed transaction carried by the wire block format.
type WireTransaction<H, P> = SignedTransaction<P, H>;

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
) -> Result<State, ProcessorError>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    T: Translator,
{
    let mut accounts = HashSet::with_capacity(transactions.len().saturating_mul(2));
    for transaction in transactions {
        accounts.insert(transaction.signer());
        accounts.insert(transaction.value().to);
    }

    let account_keys = accounts.iter().copied().collect::<Vec<_>>();
    let account_results =
        try_join_all(account_keys.iter().map(|address| batch.get(address))).await?;

    let mut base_accounts = HashMap::with_capacity(accounts.len());
    for (address, result) in account_keys.iter().zip(account_results) {
        if let Some(account) = result {
            base_accounts.insert(*address, account);
        }
    }

    Ok(State::from_loaded(base_accounts, account_keys))
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

/// Core constantinople application.
///
/// This type implements the consensus application trait on top of the
/// processor and the managed state databases.
pub struct Application<H, C, S, P, I, St> {
    strategy: St,
    genesis_leader: P,
    transaction_namespace: &'static [u8],
    proposed_transactions: Counter,
    _marker: PhantomData<(H, C, S, I)>,
}

impl<H, C, S, P, I, St> Clone for Application<H, C, S, P, I, St>
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

impl<H: Hasher, C, S, P, I, St> Application<H, C, S, P, I, St> {
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

impl<H, C, S, P, I, St> Application<H, C, S, P, I, St>
where
    C: Digest,
    H: Hasher,
    P: PublicKey,
    St: Strategy,
{
    /// Verifies signed wire transactions and returns verified execution transactions.
    fn verify_transactions(
        &self,
        transactions: Vec<SignedTransaction<P, H>>,
    ) -> Option<Vec<VerifiedTransaction<P, H>>> {
        self.strategy
            .map_collect_vec(transactions, |transaction: WireTransaction<H, P>| {
                transaction.into_verified(self.transaction_namespace).ok()
            })
            .into_iter()
            .collect()
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

impl<E, H, C, S, P, I, St> CApplication<E> for Application<H, C, S, P, I, St>
where
    E: Rng + Spawner + Storage + Metrics + Clock,
    H: Hasher,
    C: Digest,
    S: Scheme<PublicKey = P>,
    P: PublicKey,
    St: Strategy + Clone + Send + Sync + 'static,
    I: TransactionSource<C, P, H> + Sync,
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
        let parent = ancestry.next().await?;
        let body = input.propose(&parent.header, &context).await;
        let (state_batch, transaction_batch) = batches;
        let state = load_state(&state_batch, &body)
            .await
            .expect("proposal state loading must succeed");
        let ProposalOutput {
            valid,
            invalid: _,
            changeset,
        } = executor::propose(state, body);

        self.proposed_transactions.inc_by(valid.len() as u64);

        let transaction_batch = record_transactions(transaction_batch, &valid);
        let state_batch = apply_changeset(state_batch, &changeset);
        let (state_merkleized, transaction_merkleized) = self
            .finalize_execution(state_batch, transaction_batch)
            .await
            .expect("database merkleization must succeed");
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
        (runtime, _context): (E, Self::Context),
        mut ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        let Block { header, body } = ancestry.next().await?.into_inner();
        let parent = ancestry.next().await?;

        let Some(verified_body) = self.verify_transactions(body) else {
            warn!(height = header.height, "verify rejected: invalid signature");
            return None;
        };

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
        runtime.sleep_until(deadline).await;

        let (state_batch, transaction_batch) = batches;
        let state = load_state(&state_batch, &verified_body)
            .await
            .expect("block state loading during verification must succeed");
        let body_len = verified_body.len();
        let Some(changeset) = executor::execute(state, &verified_body) else {
            warn!(
                height = header.height,
                "verify rejected: statically invalid transaction"
            );
            return None;
        };

        let transaction_batch = record_transactions(transaction_batch, &verified_body);
        let state_batch = apply_changeset(state_batch, &changeset);
        let (state_merkleized, transaction_merkleized) = self
            .finalize_execution(state_batch, transaction_batch)
            .await
            .expect("database merkleization during verification must succeed");

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
        _context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet<E>>::Merkleized {
        let verified_body = self
            .verify_transactions(block.body.clone())
            .expect("certified block contained an invalid signature");

        let (state_batch, transaction_batch) = batches;
        let state = load_state(&state_batch, &verified_body)
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
