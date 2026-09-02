//! `commonware_glue::stateful` trait integration.

use super::{
    Application, FinalizedArtifacts, FinalizedRange, db::Databases, genesis_block_with_parent,
    history::header_range_to_target,
};
use commonware_cryptography::{Digest, Hasher, PublicKey, certificate::Scheme};
use commonware_glue::stateful::{
    Application as CApplication, Input as CInput, Proposed, db::DatabaseSet,
};
use commonware_parallel::Strategy;
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage};
use commonware_storage::{mmr, qmdb::sync::Target as AnyTarget, translator::EightCap};
use commonware_utils::non_empty_range;
use constantinople_mempool::TransactionSource;
use constantinople_primitives::SealedBlock;
use futures::{Stream, StreamExt};
use rand::{CryptoRng, Rng};
use std::sync::Arc;

impl<E, H, C, S, P, I, B, St> CApplication<E> for Application<E, H, C, S, P, I, B, St>
where
    E: Rng + Spawner + BufferPooler + Storage + Metrics + Clock + CryptoRng,
    H: Hasher,
    C: Digest,
    S: Scheme<PublicKey = P>,
    P: PublicKey,
    I: TransactionSource<C, P, H> + Clone + Sync,
    B: Send + Sync + 'static,
    St: Strategy,
{
    type SigningScheme = S;
    type Context = commonware_consensus::simplex::types::Context<C, P>;
    type Block = SealedBlock<C, P, H>;
    type Databases = Databases<E, H, EightCap, St>;
    type Captured = Option<FinalizedArtifacts<H>>;
    type Provider = I;
    type Input = ();

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
        ancestry: impl Stream<Item = Arc<Self::Block>> + Send,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        input: CInput<Self::Input, Self::Provider>,
    ) -> Option<Proposed<Self, E>> {
        let mut input = input.provider;
        let mut ancestry = Box::pin(ancestry);
        let parent = ancestry.next().await?;
        let result = self
            .propose_child(context, parent, batches, &mut input)
            .await;

        // propose_child releases the parent on the strategy's pool, so only
        // the drained ancestry stream remains; the span keeps its drop cost
        // visible in traces.
        {
            let _cleanup = tracing::info_span!("application.propose.cleanup").entered();
            drop(ancestry);
        }
        result
    }

    async fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Stream<Item = Arc<Self::Block>> + Send,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        let mut ancestry = Box::pin(ancestry);
        let block = ancestry.next().await?;

        // The parent fetch is passed as a future so verify_child can start
        // signature verification (which needs only the block body) while the
        // parent is still in flight.
        let result = self
            .verify_child(context, block, ancestry.next(), batches)
            .await;

        // verify_child's offloaded tasks release the body and parent (early
        // rejections drop inline), so only the drained ancestry stream
        // remains; the span keeps its drop cost visible in traces.
        {
            let _cleanup = tracing::info_span!("application.verify.cleanup").entered();
            drop(ancestry);
        }
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

    async fn capture(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        batches: &<Self::Databases as DatabaseSet<E>>::Merkleized,
        readers: <Self::Databases as DatabaseSet<E>>::Readers,
    ) -> Self::Captured {
        self.finalized_hook.as_ref()?;

        let state = {
            let database = readers.0.read().await;
            let (start, operations) = batches.0.operations();
            let end = batches.0.bounds().tip.size;
            let root = batches.0.root();
            assert_eq!(end.as_u64(), block.header.state_range.end());
            assert_eq!(
                end.as_u64() - start.as_u64(),
                u64::try_from(operations.len()).expect("state operation count must fit u64")
            );
            assert_eq!(root, block.header.state_root);
            let proof = batches
                .0
                .proof(&database)
                .expect("finalized state batch proof must be available before apply");
            let pinned_nodes = database
                .pinned_nodes_at(start)
                .await
                .expect("finalized state frontier must be available before apply");
            FinalizedRange {
                start,
                end,
                root,
                proof,
                pinned_nodes,
                operations,
            }
        };

        let transactions = {
            let database = readers.1.read().await;
            let (start, operations) = batches.1.operations();
            let end = batches.1.bounds().tip.size;
            let root = batches.1.root();
            assert_eq!(end.as_u64(), block.header.transactions_range.end());
            assert_eq!(
                end.as_u64() - start.as_u64(),
                u64::try_from(operations.len()).expect("transaction operation count must fit u64")
            );
            assert_eq!(root, block.header.transactions_root);
            let proof = batches
                .1
                .proof(&database)
                .expect("finalized transaction batch proof must be available before apply");
            let pinned_nodes = batches
                .1
                .pinned_nodes(&database)
                .expect("finalized transaction frontier must be available before apply");
            FinalizedRange {
                start,
                end,
                root,
                proof,
                pinned_nodes,
                operations,
            }
        };

        Some(FinalizedArtifacts {
            state,
            transactions,
        })
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
            hook(block, artifacts).await;
        }
    }
}
