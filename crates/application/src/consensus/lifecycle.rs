//! Propose, verify, and apply entry points.

use super::{
    Application,
    body::{verify_signatures, wait_for_timestamp},
    execution::{
        ProposalExecution, apply_prepared_body, commitments_match, execute_body, execute_proposal,
        prepare_lazy,
    },
    history::parent_transactions_inactivity_floor,
    reject_verify,
    speculation::PreBuilt,
    time,
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
        parent: SealedBlock<C, P, H>,
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

        // A pre-built execution for this exact parent is the finished
        // proposal: only the header (real context, fresh timestamp) remains.
        // A pre-build for any other parent still owns transactions that were
        // consumed from the mempool, so its selection seeds a best-effort
        // re-execution against the actual parent: anything already included
        // upstream (or otherwise inapplicable there) fails its nonce or
        // balance check and is dropped, and the block tops up from the live
        // mempool toward the proposal budget.
        let speculation = match &self.speculator {
            Some(speculator) => speculator.take().await,
            None => None,
        };
        let (execution, batches) = match speculation {
            Some(prebuilt) if prebuilt.parent == parent_digest => {
                self.speculator
                    .as_ref()
                    .expect("speculation implies speculator")
                    .record_hit();
                (prebuilt.execution, Some(batches))
            }
            speculation => {
                let seed = match speculation {
                    Some(prebuilt) => {
                        self.speculator
                            .as_ref()
                            .expect("speculation implies speculator")
                            .record_reuse();
                        // Release the mismatched execution off the propose
                        // path; only its transaction selection is reused.
                        let PreBuilt { execution, .. } = prebuilt;
                        let ProposalExecution { block, body } = execution;
                        let drop_span = info_span!("application.propose.drop_speculation");
                        drop(
                            self.strategy
                                .spawn(move |_: St| drop_span.in_scope(|| drop(block))),
                        );
                        body
                    }
                    None => {
                        input
                            .propose(&parent.header, context.round, 0)
                            .instrument(info_span!("application.propose.input"))
                            .await
                    }
                };
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
                    Some(input),
                )
                .await;
                (execution, None)
            }
        };

        // The parent (a full block of decoded transactions) and, on the
        // pre-built path, the unused batches are released on the strategy's
        // pool so the drops stay off the propose path.
        let drop_span = info_span!("application.propose.drop_parent");
        drop(
            self.strategy
                .spawn(move |_: St| drop_span.in_scope(|| drop((parent, batches)))),
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
        block: SealedBlock<C, P, H>,
        parent: impl Future<Output = Option<SealedBlock<C, P, H>>> + Send,
        batches: <<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Merkleized>
    where
        E: Rng + Spawner + BufferPooler + Storage + Metrics + Clock + CryptoRng,
        S: Scheme<PublicKey = P>,
        I: TransactionSource<C, P, H> + Sync,
        St: Strategy,
    {
        let block_digest = block.digest();
        let Block { header, body } = block.into_inner();

        // Signature verification needs only the block body, so it starts
        // immediately and overlaps the parent fetch below. The child context
        // serves only as an owned CryptoRng for the pool job; no runtime task
        // is spawned under its label.
        let body = Arc::new(body);
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

        // Execution stays on this async task; CPU-heavy stages are dispatched
        // to the strategy's pool, so a failure surfaces as a graceful
        // rejection below.
        let execution = execute_body(
            self.strategy.clone(),
            state_batch,
            transaction_batch,
            parent_transactions_inactivity_floor(&parent),
            body,
        );
        let wait = wait_for_timestamp(
            runtime.child("wait"),
            time::block_deadline(header.timestamp),
        );

        let result = futures::try_join!(signatures, execution, wait);

        // The parent (a full block of decoded transactions) is released on
        // the strategy's pool so the drop stays off the verify path.
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

        let transaction_count = execution.transaction_count;
        let merkleized = execution.into_merkleized();

        // The verified block is the likely parent of the next proposal. If
        // this node leads the next round, pre-build that proposal on top of
        // the just-computed state so the propose request finds it finished.
        if let Some(speculator) = &self.speculator {
            speculator.maybe_prebuild(
                &self.strategy,
                &header,
                block_digest,
                u64::try_from(transaction_count).expect("transaction count exceeded u64"),
                &merkleized,
            );
        }

        Some(merkleized)
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
