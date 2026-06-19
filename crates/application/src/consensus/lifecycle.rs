//! Propose, verify, and apply entry points.

use super::{
    Application,
    body::{verify_signatures, wait_for_timestamp},
    execution::{
        apply_prepared_body, commitments_match, execute_body, execute_proposal, prepare_lazy,
    },
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
use commonware_runtime::{Clock, Metrics, Spawner, Storage, telemetry::traces::TracedExt as _};
use commonware_storage::mmr;
use constantinople_mempool::TransactionSource;
use constantinople_primitives::{Block, Header, Sealable, SealedBlock};
use rand::Rng;
use rand_core::CryptoRngCore;
use std::sync::Arc;
use tracing::{Instrument as _, info, info_span, warn};

impl<E, H, C, S, P, I, B, St> Application<E, H, C, S, P, I, B, St>
where
    E: Storage + Metrics + Clock,
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
        parent: &SealedBlock<C, P, H>,
        batches: <<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Unmerkleized,
        input: &mut I,
    ) -> Option<Proposed<Self, E>>
    where
        E: Rng + Spawner + Storage + Metrics + Clock + CryptoRngCore,
        S: Scheme<PublicKey = P>,
        I: TransactionSource<C, P, H> + Sync,
        St: Strategy,
    {
        let body = input
            .propose(&parent.header, &context)
            .instrument(info_span!("application.propose.input"))
            .await;

        let (state_batch, transaction_batch) = batches;
        let execution = execute_proposal(
            self.strategy.clone(),
            state_batch,
            transaction_batch,
            parent,
            body,
        )
        .await;

        self.proposed_transactions
            .inc_by(execution.block.transaction_count as u64);

        let header = Header {
            context,
            parent: parent.digest(),
            height: parent.header.height + 1,
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

    /// Verifies a child block against an already fetched parent.
    #[doc(hidden)]
    #[boxed]
    #[tracing::instrument(
        name = "application.verify",
        skip_all,
        fields(
            height = block.header.height.traced(),
            parent_height = parent.header.height.traced(),
        )
    )]
    pub async fn verify_child(
        &mut self,
        (runtime, _context): (E, Context<C, P>),
        block: SealedBlock<C, P, H>,
        parent: &SealedBlock<C, P, H>,
        batches: <<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Merkleized>
    where
        E: Rng + Spawner + Storage + Metrics + Clock + CryptoRngCore,
        S: Scheme<PublicKey = P>,
        I: TransactionSource<C, P, H> + Sync,
        St: Strategy,
    {
        let Block { header, body } = block.into_inner();

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

        let body = Arc::new(body);
        let (state_batch, transaction_batch) = batches;
        let signatures = verify_signatures::<E, H, St>(
            runtime.child("verify_signatures"),
            self.transaction_namespace,
            self.public_key_cache.clone(),
            Arc::clone(&body),
            self.strategy.clone(),
        );
        let execution = execute_body(
            self.strategy.clone(),
            state_batch,
            transaction_batch,
            parent,
            Arc::clone(&body),
        );
        let wait = wait_for_timestamp(runtime, time::block_deadline(header.timestamp));

        let execution = match futures::try_join!(signatures, execution, wait) {
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
        E: Rng + Spawner + Storage + Metrics + Clock + CryptoRngCore,
        S: Scheme<PublicKey = P>,
        I: TransactionSource<C, P, H> + Sync,
        St: Strategy,
    {
        let (body, digests) = info_span!("application.apply.prepare")
            .in_scope(|| prepare_lazy(&self.strategy, block.body.as_slice()))
            .unwrap_or_else(|reason| panic!("certified block contained {reason}"));

        let (state_batch, transaction_batch) = batches;
        apply_prepared_body(
            self.strategy.clone(),
            state_batch,
            transaction_batch,
            mmr::Location::new(block.header.transactions_range.start()),
            &body,
            &digests,
        )
        .await
        .unwrap_or_else(|reason| panic!("certified block contained {reason}"))
    }
}
