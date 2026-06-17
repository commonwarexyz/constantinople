//! `commonware_glue::stateful` trait integration.

use super::{
    Application, db::Databases, genesis_block_with_parent, history::header_range_to_target,
};
use commonware_cryptography::{Digest, Hasher, PublicKey, certificate::Scheme};
use commonware_glue::stateful::{Application as CApplication, Proposed, db::DatabaseSet};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::{mmr, qmdb::sync::Target as AnyTarget, translator::EightCap};
use commonware_utils::non_empty_range;
use constantinople_mempool::TransactionSource;
use constantinople_primitives::SealedBlock;
use futures::{Stream, StreamExt};
use rand::Rng;
use rand_core::CryptoRngCore;

impl<E, H, C, S, P, I, B, St> CApplication<E> for Application<E, H, C, S, P, I, B, St>
where
    E: Rng + Spawner + Storage + Metrics + Clock + CryptoRngCore,
    H: Hasher,
    C: Digest,
    S: Scheme<PublicKey = P>,
    P: PublicKey,
    I: TransactionSource<C, P, H> + Sync,
    B: Send + Sync + 'static,
    St: Strategy,
{
    type SigningScheme = S;
    type Context = commonware_consensus::simplex::types::Context<C, P>;
    type Block = SealedBlock<C, P, H>;
    type Databases = Databases<E, H, EightCap, St>;
    type InputProvider = I;

    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        (
            AnyTarget::new(
                block.header.state_root,
                non_empty_range!(
                    mmr::Location::new(block.header.state_range.start()),
                    mmr::Location::new(block.header.state_range.end())
                ),
            ),
            header_range_to_target(
                block.header.transactions_root,
                block.header.transactions_range.clone(),
            ),
        )
    }

    async fn genesis(&mut self) -> Self::Block {
        genesis_block_with_parent(
            &mut H::default(),
            self.genesis_leader.clone(),
            (
                commonware_consensus::types::View::zero(),
                self.genesis_parent,
            ),
            0,
            self.genesis_state_target.clone(),
            self.genesis_transactions_target.clone(),
        )
    }

    async fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Stream<Item = Self::Block> + Send,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        input: &mut Self::InputProvider,
    ) -> Option<Proposed<Self, E>> {
        let mut ancestry = Box::pin(ancestry);
        let parent = ancestry.next().await?;
        let result = self.propose_child(context, &parent, batches, input).await;
        let cleanup = tracing::info_span!("application.propose.cleanup").entered();
        drop(parent);
        drop(ancestry);
        drop(cleanup);
        result
    }

    async fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Stream<Item = Self::Block> + Send,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        let mut ancestry = Box::pin(ancestry);
        let block = ancestry.next().await?;
        let parent = ancestry.next().await?;
        let result = self.verify_child(context, block, &parent, batches).await;
        let cleanup = tracing::info_span!("application.verify.cleanup").entered();
        drop(parent);
        drop(ancestry);
        drop(cleanup);
        result
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
        if let Some(hook) = &self.finalized_hook {
            hook(block, databases).await;
        }
    }
}
