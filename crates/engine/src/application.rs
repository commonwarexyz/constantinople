use crate::{
    ThresholdScheme,
    block::{ApplicationBlock, EngineBlock, EngineCommitment},
};
use commonware_actor::Feedback;
use commonware_consensus::{
    Reporter,
    marshal::{Update, ancestry::Ancestry},
};
use commonware_cryptography::{
    Hasher, PublicKey, bls12381::primitives::variant::Variant, certificate::Scheme,
};
use commonware_glue::stateful::{
    Application as StatefulApplication, Input, Proposed, db::DatabaseSet,
};
use commonware_parallel::Strategy;
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage};
use constantinople_application::consensus::Application;
use constantinople_mempool::TransactionSource;
use futures::Stream;
use rand::{CryptoRng, Rng};
use std::{
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

type InnerApplication<E, H, P, V, I, B, St> =
    Application<E, H, EngineCommitment<H, P>, ThresholdScheme<P, V>, P, I, B, St>;

pub(crate) struct EngineApplication<E, H, P, V, I, B, St>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    St: Strategy,
{
    inner: InnerApplication<E, H, P, V, I, B, St>,
}

pub(crate) struct EngineReporter<R, H, P> {
    inner: R,
    _marker: PhantomData<fn() -> (H, P)>,
}

impl<R, H, P> EngineReporter<R, H, P> {
    pub(crate) const fn new(inner: R) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }
}

impl<R: Clone, H, P> Clone for EngineReporter<R, H, P> {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

impl<R, H, P> Reporter for EngineReporter<R, H, P>
where
    H: Hasher,
    P: PublicKey,
    R: Reporter<Activity = Update<ApplicationBlock<H, P>>>,
{
    type Activity = Update<EngineBlock<H, P>>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let activity = match activity {
            Update::Tip(round, height, digest) => Update::Tip(round, height, digest),
            Update::Block(block, acknowledgement) => {
                Update::Block(block.inner_shared(), acknowledgement)
            }
        };
        self.inner.report(activity)
    }
}

impl<E, H, P, V, I, B, St> EngineApplication<E, H, P, V, I, B, St>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    St: Strategy,
{
    pub(crate) const fn new(inner: InnerApplication<E, H, P, V, I, B, St>) -> Self {
        Self { inner }
    }
}

impl<E, H, P, V, I, B, St> Clone for EngineApplication<E, H, P, V, I, B, St>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    St: Strategy,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

struct InnerAncestry<A, H, P> {
    ancestry: A,
    _marker: PhantomData<fn() -> (H, P)>,
}

impl<A, H, P> InnerAncestry<A, H, P> {
    const fn new(ancestry: A) -> Self {
        Self {
            ancestry,
            _marker: PhantomData,
        }
    }
}

impl<A: Clone, H, P> Clone for InnerAncestry<A, H, P> {
    fn clone(&self) -> Self {
        Self::new(self.ancestry.clone())
    }
}

impl<A, H, P> Stream for InnerAncestry<A, H, P>
where
    A: Ancestry<EngineBlock<H, P>>,
    H: Hasher,
    P: PublicKey,
{
    type Item = Arc<ApplicationBlock<H, P>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().ancestry)
            .poll_next(cx)
            .map(|block| block.map(|block| block.inner_shared()))
    }
}

impl<A, H, P> Ancestry<ApplicationBlock<H, P>> for InnerAncestry<A, H, P>
where
    A: Ancestry<EngineBlock<H, P>>,
    H: Hasher,
    P: PublicKey,
{
    fn peek(&self) -> Option<&ApplicationBlock<H, P>> {
        self.ancestry.peek().map(|block| &**block)
    }
}

impl<E, H, P, V, I, B, St> StatefulApplication<E> for EngineApplication<E, H, P, V, I, B, St>
where
    E: Rng + Spawner + BufferPooler + Storage + Metrics + Clock + CryptoRng,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    ThresholdScheme<P, V>: Scheme<PublicKey = P>,
    I: TransactionSource<EngineCommitment<H, P>, P, H> + Clone + Sync,
    B: Send + Sync + 'static,
    St: Strategy,
{
    type SigningScheme = ThresholdScheme<P, V>;
    type Context = commonware_consensus::simplex::types::Context<EngineCommitment<H, P>, P>;
    type Block = EngineBlock<H, P>;
    type Databases = <InnerApplication<E, H, P, V, I, B, St> as StatefulApplication<E>>::Databases;
    type Captured = <InnerApplication<E, H, P, V, I, B, St> as StatefulApplication<E>>::Captured;
    type Provider = I;
    type Input = ();

    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        InnerApplication::<E, H, P, V, I, B, St>::sync_targets(block)
    }

    async fn genesis(&mut self) -> Self::Block {
        self.inner.genesis().await.into()
    }

    async fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        input: Input<Self::Input, Self::Provider>,
    ) -> Option<Proposed<Self, E>> {
        let proposed = self
            .inner
            .propose(context, InnerAncestry::new(ancestry), batches, input)
            .await?;
        Some(Proposed {
            block: proposed.block.into(),
            merkleized: proposed.merkleized,
        })
    }

    async fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        self.inner
            .verify(context, InnerAncestry::new(ancestry), batches)
            .await
    }

    async fn apply(
        &mut self,
        context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet<E>>::Merkleized {
        self.inner.apply(context, block, batches).await
    }

    async fn capture(
        &mut self,
        context: (E, Self::Context),
        block: &Self::Block,
        batches: &<Self::Databases as DatabaseSet<E>>::Merkleized,
        readers: <Self::Databases as DatabaseSet<E>>::Readers,
    ) -> Self::Captured {
        self.inner.capture(context, block, batches, readers).await
    }

    async fn finalized(
        &mut self,
        context: (E, Self::Context),
        block: &Self::Block,
        captured: Self::Captured,
        readers: <Self::Databases as DatabaseSet<E>>::Readers,
    ) {
        self.inner
            .finalized(context, block, captured, readers)
            .await;
    }
}
