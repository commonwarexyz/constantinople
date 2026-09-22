//! Adapt execution blocks to the nominal block used by typed coding commitments.

use crate::{
    ThresholdScheme,
    types::{EngineBlock, EngineCommitment},
};
use commonware_consensus::{HandoffPolicy, marshal::ancestry::Ancestry, simplex::types::Context};
use commonware_cryptography::{Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_glue::stateful::{
    Application as StatefulApplication, Input, Proposed, db::DatabaseSet,
};
use commonware_parallel::Strategy;
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage};
use constantinople_application::consensus::Application;
use constantinople_mempool::TransactionSource;
use futures::StreamExt;
use rand::{CryptoRng, Rng};

type Execution<E, H, P, V, I, B, St> =
    Application<E, H, EngineCommitment<H, P>, ThresholdScheme<P, V>, P, I, B, St>;

pub(crate) struct App<E, H, P, V, I, B, St>(pub Execution<E, H, P, V, I, B, St>)
where
    E: BufferPooler + Storage + Clock + Metrics + Spawner,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    St: Strategy;

impl<E, H, P, V, I, B, St> Clone for App<E, H, P, V, I, B, St>
where
    E: BufferPooler + Storage + Clock + Metrics + Spawner,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    St: Strategy,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<E, H, P, V, I, B, St> StatefulApplication<E> for App<E, H, P, V, I, B, St>
where
    E: Rng + CryptoRng + BufferPooler + Storage + Clock + Metrics + Spawner,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    St: Strategy,
    I: TransactionSource<EngineCommitment<H, P>, P, H> + Sync,
    B: Send + Sync + 'static,
{
    type SigningScheme = ThresholdScheme<P, V>;
    type Context = Context<EngineCommitment<H, P>, P>;
    type Block = EngineBlock<H, P>;
    type Databases = <Execution<E, H, P, V, I, B, St> as StatefulApplication<E>>::Databases;
    type Captured = <Execution<E, H, P, V, I, B, St> as StatefulApplication<E>>::Captured;
    type Provider = I;
    type Input = ();

    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        Execution::<E, H, P, V, I, B, St>::sync_targets(block)
    }
    async fn genesis(&mut self) -> Self::Block {
        self.0.genesis().await.into()
    }
    fn handoff_policy(&self, context: &Self::Context) -> HandoffPolicy {
        self.0.handoff_policy(context)
    }
    async fn propose(
        &mut self,
        context: (E, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        mut input: Input<(), I>,
    ) -> Option<Proposed<Self, E>> {
        let parent = ancestry.next().await?.shared_execution();
        let proposed = self
            .0
            .propose_child(context, parent, batches, &mut input.provider)
            .await?;
        Some(Proposed {
            block: proposed.block.into(),
            merkleized: proposed.merkleized,
        })
    }
    async fn verify(
        &mut self,
        context: (E, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        let block = ancestry.next().await?.shared_execution();
        self.0
            .verify_child(
                context,
                block,
                async move {
                    ancestry
                        .next()
                        .await
                        .map(|parent| parent.shared_execution())
                },
                batches,
            )
            .await
    }
    async fn apply(
        &mut self,
        context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        self.0.apply(context, block, batches).await
    }
    async fn capture(
        &mut self,
        context: (E, Self::Context),
        block: &Self::Block,
        batches: &<Self::Databases as DatabaseSet<E>>::Merkleized,
        readers: <Self::Databases as DatabaseSet<E>>::Readers,
    ) -> Self::Captured {
        self.0.capture(context, block, batches, readers).await
    }
    async fn finalized(
        &mut self,
        context: (E, Self::Context),
        block: &Self::Block,
        captured: Self::Captured,
        readers: <Self::Databases as DatabaseSet<E>>::Readers,
    ) {
        self.0.finalized(context, block, captured, readers).await
    }
}
