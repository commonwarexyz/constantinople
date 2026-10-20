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
    Digested, Digestible, Hasher, PublicKey, bls12381::primitives::variant::Variant,
    certificate::Scheme,
};
use commonware_glue::stateful::{
    Application as StatefulApplication, Input, Proposed, db::DatabaseSet,
};
use commonware_parallel::Strategy;
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage};
use constantinople_application::consensus::{Application, FinalizedArtifacts, FinalizedHookFn};
use constantinople_mempool::TransactionSource;
use futures::Stream;
use rand::{CryptoRng, Rng};
use std::{
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

type InnerApplication<E, H, P, V, I, B, St> =
    Application<E, H, EngineCommitment<H, P>, ThresholdScheme<P, V>, P, I, B, St>;

// An engine block and its inner block share one digest. Pairing the inner block
// with the marshal's digest keeps this conversion synchronous.
fn application_block<H, P>(block: &Digested<EngineBlock<H, P>>) -> Digested<ApplicationBlock<H, P>>
where
    H: Hasher,
    P: PublicKey,
{
    Digested::precomputed(block.inner().inner_shared(), block.digest())
}

pub(crate) struct EngineApplication<E, H, P, V, I, B, St>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    St: Strategy,
{
    inner: InnerApplication<E, H, P, V, I, B, St>,
    finalized_hook: Option<FinalizedHookFn<EngineCommitment<H, P>, H, P>>,
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
                Update::Block(application_block(&block), acknowledgement)
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
    pub(crate) const fn new(
        inner: InnerApplication<E, H, P, V, I, B, St>,
        finalized_hook: Option<FinalizedHookFn<EngineCommitment<H, P>, H, P>>,
    ) -> Self {
        Self {
            inner,
            finalized_hook,
        }
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
            finalized_hook: self.finalized_hook.clone(),
        }
    }
}

struct InnerAncestry<A, H, P>
where
    H: Hasher,
    P: PublicKey,
{
    ancestry: A,

    // `peek` returns a borrow, so the converted head is refreshed whenever
    // polling can change the wrapped stream's head.
    head: Option<Digested<ApplicationBlock<H, P>>>,
}

impl<A, H, P> InnerAncestry<A, H, P>
where
    A: Ancestry<EngineBlock<H, P>>,
    H: Hasher,
    P: PublicKey,
{
    fn new(ancestry: A) -> Self {
        let head = ancestry.peek().map(application_block);
        Self { ancestry, head }
    }
}

impl<A, H, P> Clone for InnerAncestry<A, H, P>
where
    A: Clone,
    H: Hasher,
    P: PublicKey,
{
    fn clone(&self) -> Self {
        Self {
            ancestry: self.ancestry.clone(),
            head: self.head.clone(),
        }
    }
}

// Fields are never pinned structurally, so the cached head can move freely
// even when the digest type itself is not `Unpin`.
impl<A, H, P> Unpin for InnerAncestry<A, H, P>
where
    A: Unpin,
    H: Hasher,
    P: PublicKey,
{
}

impl<A, H, P> Stream for InnerAncestry<A, H, P>
where
    A: Ancestry<EngineBlock<H, P>>,
    H: Hasher,
    P: PublicKey,
{
    type Item = Digested<ApplicationBlock<H, P>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let next = Pin::new(&mut this.ancestry).poll_next(cx);
        this.head = this.ancestry.peek().map(application_block);
        next.map(|block| block.as_ref().map(application_block))
    }
}

impl<A, H, P> Ancestry<ApplicationBlock<H, P>> for InnerAncestry<A, H, P>
where
    A: Ancestry<EngineBlock<H, P>>,
    H: Hasher,
    P: PublicKey,
{
    fn peek(&self) -> Option<&Digested<ApplicationBlock<H, P>>> {
        self.head.as_ref()
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
    type Captured = Option<FinalizedArtifacts<H>>;
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
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        self.inner.apply(context, block, batches).await
    }

    async fn capture(
        &mut self,
        context: (E, Self::Context),
        block: &Self::Block,
        batches: &<Self::Databases as DatabaseSet<E>>::Merkleized,
        readers: <Self::Databases as DatabaseSet<E>>::Readers,
    ) -> Self::Captured {
        self.finalized_hook.as_ref()?;
        Some(self.inner.capture(context, block, batches, readers).await)
    }

    async fn finalized(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        captured: Self::Captured,
        _readers: <Self::Databases as DatabaseSet<E>>::Readers,
    ) {
        if let Some(hook) = &self.finalized_hook {
            let artifacts = captured
                .expect("finalized artifact capture was skipped while a hook was installed");
            hook(block.inner_shared(), artifacts).await;
        }
    }
}

#[cfg(test)]
mod tests;
