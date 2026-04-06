//! Consensus-facing application integration.
//!
//! This module bridges consensus, the mempool, the processor, and the backing
//! databases. It is responsible for:
//!
//! - proposing blocks from mempool transactions
//! - filtering or rejecting invalid signatures before execution
//! - loading processor state from speculative database batches
//! - executing transaction slices against that loaded state
//! - finalizing state roots while carrying placeholder transaction history
//! - verifying and applying certified blocks
//!
//! The execution boundary is intentionally narrow: the [`Application`] owns
//! the execution strategy and QMDB integration, while the processor owns the
//! in-memory state transition logic.

use crate::processor::executor::{self, Changeset, ProposalOutput};
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
    db::{DatabaseSet, Merkleized as _, Unmerkleized, any::AnyUnmerkleized},
};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::{
    index::unordered::Index as UnorderedIndex,
    journal::contiguous::fixed::Journal as FixedJournal,
    mmr,
    qmdb::{
        any::{
            operation::Operation as AnyOperation,
            unordered::{Update as UnorderedUpdate, fixed},
            value::FixedEncoding,
        },
        sync::Target,
    },
    translator::EightCap,
};
use commonware_utils::{non_empty_range, sync::AsyncRwLock};
use constantinople_mempool::TransactionSource;
use constantinople_primitives::{
    Account, Address, Block, Header, Sealable, SealedBlock, SignedTransaction, VerifiedTransaction,
};
use futures::StreamExt;
use prometheus_client::metrics::counter::Counter;
use rand::Rng;
use rand_core::CryptoRngCore;
use std::{
    marker::PhantomData,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tracing::{info, warn};

mod utils;
pub use utils::load_state;
use utils::{verify_transaction_batch, verify_transaction_chunks};

/// Fixed consensus cutoff for block timestamps: 2200-01-01T00:00:00Z.
///
/// Different platforms have different `SystemTime` limits, so we use a fixed
/// timestamp to ensure consistent application of block validity rules.
const MAX_BLOCK_TIMESTAMP_MS: u64 = 7_258_118_400_000;

/// Shared QMDB handle for the application state database.
type StateDatabase<E, H, T> = Arc<AsyncRwLock<fixed::Db<mmr::Family, E, Address, Account, H, T>>>;

/// Unmerkleized application state batch used for processor read-through.
type StateBatch<E, H, T> = AnyUnmerkleized<
    E,
    FixedJournal<E, AnyOperation<mmr::Family, UnorderedUpdate<Address, FixedEncoding<Account>>>>,
    UnorderedIndex<T, mmr::Location>,
    H,
    UnorderedUpdate<Address, FixedEncoding<Account>>,
>;

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

impl<H, C, S, P, I, B, St> Application<H, C, S, P, I, B, St>
where
    C: Digest,
    H: Hasher,
    P: PublicKey,
    B: BatchVerifier<PublicKey = P>,
    St: Strategy,
{
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
    type Databases = StateDatabase<E, H, EightCap>;
    type InputProvider = I;

    /// Returns the sync targets required to fetch the block's state.
    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        Target {
            root: block.header.state_root,
            range: non_empty_range!(
                mmr::Location::new(block.header.state_range.start()),
                mmr::Location::new(block.header.state_range.end())
            ),
        }
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
        let input_ms = input_started_at.elapsed().as_millis();

        let load_state_started_at = Instant::now();
        let state = load_state(&batches, &body)
            .await
            .expect("proposal state loading must succeed");
        let load_state_ms = load_state_started_at.elapsed().as_millis();

        let execute_started_at = Instant::now();
        let ProposalOutput {
            valid,
            invalid: _,
            changeset,
        } = executor::propose(&state, body);
        let execute_ms = execute_started_at.elapsed().as_millis();

        self.proposed_transactions.inc_by(valid.len() as u64);

        let state_batch = apply_changeset(batches, &changeset);

        let finalize_started_at = Instant::now();
        let state_merkleized = state_batch
            .merkleize()
            .await
            .expect("database merkleization must succeed");
        let finalize_ms = finalize_started_at.elapsed().as_millis();

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
            transactions_root: H::Digest::EMPTY,
            transactions_range: non_empty_range!(0, 1),
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
            total_ms = propose_started_at.elapsed().as_millis(),
            "proposed block"
        );

        Some(Proposed {
            block,
            merkleized: state_merkleized,
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
        let signature_ms = signature_started_at.elapsed().as_millis();

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
        let sleep_ms = sleep_started_at.elapsed().as_millis();

        let load_state_started_at = Instant::now();
        let state = load_state(&batches, &verified_body)
            .await
            .expect("block state loading during verification must succeed");
        let load_state_ms = load_state_started_at.elapsed().as_millis();

        let execute_started_at = Instant::now();
        let Some(changeset) = executor::execute(&state, &verified_body) else {
            warn!(
                height = header.height,
                "verify rejected: statically invalid transaction"
            );
            return None;
        };
        let execute_ms = execute_started_at.elapsed().as_millis();

        let state_batch = apply_changeset(batches, &changeset);

        let finalize_started_at = Instant::now();
        let state_merkleized = state_batch
            .merkleize()
            .await
            .expect("database merkleization during verification must succeed");
        let finalize_ms = finalize_started_at.elapsed().as_millis();

        let state_range = non_empty_range!(
            *state_merkleized.inactivity_floor(),
            *state_merkleized.size()
        );

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
        if header.transactions_root != H::Digest::EMPTY {
            warn!(
                height = header.height,
                "verify rejected: unexpected transactions root"
            );
            return None;
        }
        if header.transactions_range != non_empty_range!(0, 1) {
            warn!(
                height = header.height,
                "verify rejected: unexpected transactions range"
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
            total_ms = verify_started_at.elapsed().as_millis(),
            "verified block"
        );
        Some(state_merkleized)
    }

    /// Applies a certified block to speculative batches and returns merkleized state.
    ///
    /// Unlike verification, application assumes consensus has already
    /// certified the block. It reconstitutes verified execution transactions
    /// from the signed wire block and deterministically replays them to
    /// derive the merkleized state batch.
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

        let state = load_state(&batches, &verified_body)
            .await
            .expect("state loading must succeed for certified apply");
        let changeset = executor::execute(&state, &verified_body)
            .expect("certified block contained a statically invalid transaction");
        let state_batch = apply_changeset(batches, &changeset);
        state_batch
            .merkleize()
            .await
            .expect("database merkleization must succeed")
    }
}

/// Creates the genesis block.
///
/// The genesis block starts with empty state, empty transaction-history
/// placeholders, and the provided leader and timestamp.
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
