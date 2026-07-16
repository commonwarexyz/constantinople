//! Propose, verify, and apply entry points.

use super::{
    Application,
    body::{verify_signatures, wait_for_timestamp},
    execution::{
        apply_prepared_body, commitments_match, execute_body, execute_proposal, prepare_lazy,
    },
    history::parent_transactions_inactivity_floor,
    reject_verify, time,
};
use commonware_consensus::simplex::types::Context;
use commonware_cryptography::{Digest, Digestible, Hasher, PublicKey, certificate::Scheme};
use commonware_glue::stateful::{
    Application as CApplication, Proposed,
    db::{DatabaseSet, Merkleized as _},
};
use commonware_macros::boxed;
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Spawner, Storage, telemetry::traces::TracedExt as _,
};
use commonware_storage::mmr;
use constantinople_mempool::TransactionSource;
use constantinople_primitives::{Block, Header, Sealable, SealedBlock};
use rand::{CryptoRng, Rng};
use std::{future::Future, sync::Arc};
use tracing::{Instrument as _, info, info_span, warn};

impl<E, H, C, S, P, I, B, St> Application<E, H, C, S, P, I, B, St>
where
    E: BufferPooler + Storage + Metrics + Clock,
    C: Digest,
    H: Hasher,
    P: PublicKey,
    B: Send + Sync + 'static,
    St: Strategy,
{
    /// Proposes a child block from an already fetched parent.
    #[doc(hidden)]
    #[boxed]
    #[tracing::instrument(
        name = "application.propose",
        skip_all,
        fields(
            epoch = context.round.epoch().get().traced(),
            view = context.round.view().get().traced(),
            parent_height = parent.header.height.traced(),
            height = (parent.header.height + 1).traced(),
        )
    )]
    pub async fn propose_child(
        &mut self,
        (runtime, context): (E, Context<C, P>),
        parent: Arc<SealedBlock<C, P, H>>,
        batches: <<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Unmerkleized,
        input: &mut I,
    ) -> Option<Proposed<Self, E>>
    where
        E: Rng + Spawner + BufferPooler + Storage + Metrics + Clock + CryptoRng,
        S: Scheme<PublicKey = P>,
        I: TransactionSource<C, P, H> + Sync,
        St: Strategy,
    {
        let parent_digest = parent.digest();
        let parent_height = parent.header.height;

        // Select from the mempool, then execute the selection best effort
        // against the parent's state: anything inapplicable there fails its
        // nonce or balance check and is dropped, and the block tops up from
        // the live mempool toward the proposal budget.
        let seed = input
            .propose(&parent.header, context.round, 0)
            .instrument(info_span!("application.propose.input"))
            .await;
        let (state_batch, transaction_batch) = batches;
        let execution = execute_proposal(
            self.strategy.clone(),
            &runtime,
            state_batch,
            transaction_batch,
            parent_transactions_inactivity_floor(&parent),
            &parent.header,
            context.round,
            seed,
            input,
        )
        .await;

        // The parent reference (possibly the last one to a full block of
        // decoded transactions) is released on the strategy's pool so the
        // drop stays off the propose path.
        let drop_span = info_span!("application.propose.drop_parent");
        drop(
            self.strategy
                .spawn(move |_: St| drop_span.in_scope(|| drop(parent))),
        );

        self.proposed_transactions
            .inc_by(execution.block.transaction_count as u64);

        let header = Header {
            context,
            parent: parent_digest,
            height: parent_height + 1,
            timestamp: time::timestamp_ms(&runtime),
            state_root: execution.block.state.root(),
            state_range: execution.block.state_sync_range.clone(),
            transactions_root: execution.block.transactions.root(),
            transactions_range: execution.block.transactions_range.clone(),
        };
        let block = Block::new(header, execution.body).seal(&mut H::default());

        info!(
            epoch = block.header.context.round.epoch().get(),
            view = block.header.context.round.view().get(),
            height = block.header.height,
            txs = execution.block.transaction_count,
            timestamp = block.header.timestamp,
            "application.propose.complete"
        );

        Some(Proposed {
            block,
            merkleized: execution.block.into_merkleized(),
        })
    }

    /// Verifies a child block against a parent that may still be in flight.
    #[doc(hidden)]
    #[boxed]
    #[tracing::instrument(
        name = "application.verify",
        skip_all,
        fields(
            height = block.header.height.traced(),
            parent_height = tracing::field::Empty,
        )
    )]
    pub async fn verify_child(
        &mut self,
        (runtime, _context): (E, Context<C, P>),
        block: Arc<SealedBlock<C, P, H>>,
        parent: impl Future<Output = Option<Arc<SealedBlock<C, P, H>>>> + Send,
        batches: <<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Merkleized>
    where
        E: Rng + Spawner + BufferPooler + Storage + Metrics + Clock + CryptoRng,
        S: Scheme<PublicKey = P>,
        I: TransactionSource<C, P, H> + Sync,
        St: Strategy,
    {
        // The glue actor retains its own references to the block, so the
        // header and lazy body are cloned out of the shared reference
        // (per-transaction refcount bumps) instead of moved.
        let header = block.header.clone();
        let body = Arc::new(block.body.clone());
        drop(block);

        // Signature verification needs only the block body, so it starts
        // immediately and overlaps the parent fetch below. The child context
        // serves only as an owned CryptoRng for the pool job; no runtime task
        // is spawned under its label.
        let (state_batch, transaction_batch) = batches;
        let signatures = verify_signatures::<E, H, St>(
            runtime.child("verify_signatures"),
            self.transaction_namespace,
            self.public_key_cache.clone(),
            Arc::clone(&body),
            &self.strategy,
        );

        let parent = parent
            .instrument(info_span!("application.verify.parent"))
            .await?;
        tracing::Span::current().record("parent_height", parent.header.height.traced());

        if !time::is_valid_child_timestamp(parent.header.timestamp, header.timestamp) {
            warn!(
                height = header.height,
                block_ts = header.timestamp,
                parent_ts = parent.header.timestamp,
                reason = "invalid_timestamp",
                "application.verify.reject"
            );
            return None;
        }

        // Signatures verify concurrently with execution on the shared pool:
        // the join measures ~2ms faster than sequencing the merkleize after
        // the signature burst, and the merkleize's stretched wall time
        // during the burst reflects pool sharing, not lost work.
        let execution = execute_body(
            self.strategy.clone(),
            state_batch,
            transaction_batch,
            parent_transactions_inactivity_floor(&parent),
            body,
        );
        let wait = wait_for_timestamp(runtime, time::block_deadline(header.timestamp));

        let result = futures::try_join!(signatures, execution, wait);

        // The parent reference (possibly the last one to a full block of
        // decoded transactions) is released on the strategy's pool so the
        // drop stays off the verify path.
        let drop_span = info_span!("application.verify.drop_parent");
        drop(
            self.strategy
                .spawn(move |_: St| drop_span.in_scope(|| drop(parent))),
        );

        let execution = match result {
            Ok(((), execution, ())) => execution,
            Err(reason) => {
                reject_verify(header.height, reason);
                return None;
            }
        };

        if !commitments_match(&header, &execution) {
            return None;
        }

        info!(
            epoch = header.context.round.epoch().get(),
            view = header.context.round.view().get(),
            height = header.height,
            txs = execution.transaction_count,
            timestamp = header.timestamp,
            "application.verify.complete"
        );

        Some(execution.into_merkleized())
    }

    /// Applies a certified block to speculative batches.
    #[doc(hidden)]
    #[boxed]
    #[tracing::instrument(
        name = "application.apply",
        skip_all,
        fields(height = block.header.height.traced())
    )]
    pub async fn apply_certified(
        &mut self,
        (_, _): (E, Context<C, P>),
        block: &SealedBlock<C, P, H>,
        batches: <<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Merkleized
    where
        E: Rng + Spawner + BufferPooler + Storage + Metrics + Clock + CryptoRng,
        S: Scheme<PublicKey = P>,
        I: TransactionSource<C, P, H> + Sync,
        St: Strategy,
    {
        let strategy = self.strategy.clone();
        let body = block.body.clone();
        let prepare_span = info_span!("application.apply.prepare", txs = body.len().traced());
        let (body, digests) = strategy
            .spawn(move |s| prepare_span.in_scope(|| prepare_lazy(&s, &body)))
            .await
            .unwrap_or_else(|reason| panic!("certified block contained {reason}"));

        let (state_batch, transaction_batch) = batches;
        apply_prepared_body::<E, H, St>(
            state_batch,
            transaction_batch,
            mmr::Location::new(block.header.transactions_range.start()),
            body,
            digests,
            strategy,
        )
        .await
        .unwrap_or_else(|reason| panic!("certified block contained {reason}"))
    }
}
