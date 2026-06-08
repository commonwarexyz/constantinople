//! Propose, verify, and apply entry points.

use super::{
    Application, MALFORMED_TRANSACTION,
    body::{materialize_body, verify_signatures, wait_for_timestamp},
    execution::{apply_prepared_body, commitments_match, execute_body, execute_proposal},
    reject_verify, time,
};
use crate::executor;
use commonware_consensus::simplex::types::Context;
use commonware_cryptography::{Digest, Digestible, Hasher, PublicKey, certificate::Scheme};
use commonware_glue::stateful::{
    Application as CApplication, Proposed,
    db::{DatabaseSet, Merkleized as _},
};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::mmr;
use constantinople_mempool::TransactionSource;
use constantinople_primitives::{Block, Header, Sealable, SealedBlock};
use rand::Rng;
use rand_core::CryptoRngCore;
use std::{sync::Arc, time::Instant};
use tracing::{info, warn};

impl<E, H, C, S, P, I, B, SigSt, HashSt> Application<E, H, C, S, P, I, B, SigSt, HashSt>
where
    E: Storage + Metrics + Clock,
    C: Digest,
    H: Hasher,
    P: PublicKey,
    B: Send + Sync + 'static,
    HashSt: Strategy,
{
    /// Proposes a child block from an already fetched parent.
    #[doc(hidden)]
    #[tracing::instrument(
        name = "application.propose",
        skip_all,
        fields(
            epoch = context.round.epoch().get(),
            view = context.round.view().get(),
            parent_height = parent.header.height,
            height = parent.header.height + 1,
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
        SigSt: Strategy + Clone + Send + Sync + 'static,
        HashSt: Strategy + Clone + Send + Sync + 'static,
    {
        let started_at = Instant::now();

        let input_started_at = Instant::now();
        let body = input.propose(&parent.header, &context).await;
        let input_ms = input_started_at.elapsed().as_millis();

        let prepare_started_at = Instant::now();
        let input = executor::prepare_proposal(body);
        let candidate_transfers = input
            .candidates
            .iter()
            .map(|candidate| candidate.transfer.clone())
            .collect::<Vec<_>>();
        let prepare_ms = prepare_started_at.elapsed().as_millis();

        let (state_batch, transaction_batch) = batches;
        let execution = execute_proposal(
            state_batch,
            transaction_batch,
            parent,
            input,
            &candidate_transfers,
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
            input_ms,
            prepare_ms,
            load_state_ms = execution.block.timings.load_state_ms,
            execute_ms = execution.block.timings.execute_ms,
            finalize_ms = execution.block.timings.finalize_ms,
            total_ms = started_at.elapsed().as_millis(),
            "application.propose.complete"
        );

        Some(Proposed {
            merkleized: execution.block.into_merkleized(),
            block,
        })
    }

    /// Verifies a child block against an already fetched parent.
    #[doc(hidden)]
    #[tracing::instrument(
        name = "application.verify",
        skip_all,
        fields(
            height = block.header.height,
            parent_height = parent.header.height,
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
        SigSt: Strategy + Clone + Send + Sync + 'static,
        HashSt: Strategy + Clone + Send + Sync + 'static,
    {
        let started_at = Instant::now();
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
        let signatures = verify_signatures::<E, H, SigSt, HashSt>(
            runtime.child("verify_signatures"),
            self.signature_strategy.clone(),
            self.hash_strategy.clone(),
            self.transaction_namespace,
            Arc::clone(&body),
        );
        let execution = execute_body(state_batch, transaction_batch, parent, Arc::clone(&body));
        let wait = wait_for_timestamp(runtime, time::block_deadline(header.timestamp));

        let (signature_ms, execution, sleep_ms) =
            match futures::try_join!(signatures, execution, wait) {
                Ok(result) => result,
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
            signature_ms,
            sleep_ms,
            prepare_ms = execution.timings.prepare_ms,
            load_state_ms = execution.timings.load_state_ms,
            execute_ms = execution.timings.execute_ms,
            finalize_ms = execution.timings.finalize_ms,
            total_ms = started_at.elapsed().as_millis(),
            "application.verify.complete"
        );

        Some(execution.into_merkleized())
    }

    /// Applies a certified block to speculative batches.
    #[doc(hidden)]
    #[tracing::instrument(
        name = "application.apply",
        skip_all,
        fields(height = block.header.height)
    )]
    pub async fn apply_certified(
        &mut self,
        (runtime, _): (E, Context<C, P>),
        block: &SealedBlock<C, P, H>,
        batches: <<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Merkleized
    where
        E: Rng + Spawner + Storage + Metrics + Clock + CryptoRngCore,
        S: Scheme<PublicKey = P>,
        I: TransactionSource<C, P, H> + Sync,
        SigSt: Strategy + Clone + Send + Sync + 'static,
        HashSt: Strategy + Clone + Send + Sync + 'static,
    {
        let materialized =
            materialize_body(runtime, self.hash_strategy.clone(), block.body.clone())
                .await
                .unwrap_or_else(|reason| panic!("certified block contained {reason}"));
        let body = materialized
            .iter()
            .map(executor::prepare_transfer)
            .collect::<Option<Vec<_>>>()
            .unwrap_or_else(|| panic!("certified block contained {MALFORMED_TRANSACTION}"));

        let (state_batch, transaction_batch) = batches;
        apply_prepared_body(
            state_batch,
            transaction_batch,
            mmr::Location::new(block.header.transactions_range.start()),
            &body,
        )
        .await
        .unwrap_or_else(|reason| panic!("certified block contained {reason}"))
    }
}
