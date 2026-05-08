//! `commonware_glue::stateful` trait integration.

use super::{Application, db::Databases, genesis_block, history::header_range_to_target};
use commonware_consensus::marshal::ancestry::{AncestorStream, BlockProvider};
use commonware_cryptography::{BatchVerifier, Digest, Hasher, PublicKey, certificate::Scheme};
use commonware_glue::stateful::{Application as CApplication, Proposed, db::DatabaseSet};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::{mmr, qmdb::sync::Target, translator::EightCap};
use commonware_utils::non_empty_range;
use constantinople_mempool::TransactionSource;
use constantinople_primitives::SealedBlock;
use futures::StreamExt;
use rand::Rng;
use rand_core::CryptoRngCore;
use std::sync::atomic::Ordering;

impl<E, H, C, S, P, I, B, SigSt, HashSt> CApplication<E>
    for Application<H, C, S, P, I, B, SigSt, HashSt>
where
    E: Rng + Spawner + Storage + Metrics + Clock + CryptoRngCore,
    H: Hasher,
    C: Digest,
    S: Scheme<PublicKey = P>,
    P: PublicKey,
    I: TransactionSource<C, P, H> + Sync,
    B: BatchVerifier<PublicKey = P> + Send + Sync + 'static,
    SigSt: Strategy + Clone + Send + Sync + 'static,
    HashSt: Strategy + Clone + Send + Sync + 'static,
{
    type SigningScheme = S;
    type Context = commonware_consensus::simplex::types::Context<C, P>;
    type Block = SealedBlock<C, P, H>;
    type Databases = Databases<E, H, P, EightCap, HashSt>;
    type InputProvider = I;

    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        (
            Target {
                root: block.header.state_sync_root,
                range: non_empty_range!(
                    mmr::Location::new(block.header.state_range.start()),
                    mmr::Location::new(block.header.state_range.end())
                ),
            },
            header_range_to_target(
                block.header.transactions_root,
                block.header.transactions_range.clone(),
            ),
        )
    }

    async fn genesis(&mut self) -> Self::Block {
        genesis_block(
            &mut H::default(),
            self.genesis_leader.clone(),
            0,
            self.genesis_state_root,
            self.genesis_state_sync_root,
            self.genesis_state_range.clone(),
            self.genesis_transactions_target.clone(),
        )
    }

    async fn propose<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        context: (E, Self::Context),
        mut ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        input: &mut Self::InputProvider,
    ) -> Option<Proposed<Self, E>> {
        let parent = ancestry.next().await?;
        self.propose_child(context, &parent, batches, input).await
    }

    async fn verify<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        context: (E, Self::Context),
        mut ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        let block = ancestry.next().await?;
        let parent = ancestry.next().await?;
        self.verify_child(context, block, &parent, batches).await
    }

    async fn apply(
        &mut self,
        context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet<E>>::Merkleized {
        self.apply_certified(context, block, batches).await
    }

    async fn finalized(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        databases: &Self::Databases,
    ) {
        let height = block.header.height;
        if !self.should_prune_after_finalize(height) {
            return;
        }

        (self.finalized_pruner)(commonware_consensus::types::Height::new(height)).await;

        let (state, _) = databases;
        let mut state = state.write().await;
        let prune_to = state.sync_boundary();
        state
            .prune(prune_to)
            .await
            .expect("state db prune must not fail at the sync boundary");
        self.finalized_state_sync_start
            .store(*prune_to, Ordering::Relaxed);
    }
}
