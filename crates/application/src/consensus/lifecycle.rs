//! Propose, verify, and apply entry points.

use super::{
    Application, Chain, Databases, INVALID_NOTARIZATION, OUTCOMES_MISMATCH,
    PARENT_COMMITMENT_MISMATCH, Result,
    body::{verify_signatures, wait_for_timestamp},
    execution::{ParentEntries, body_digests, commitments_match, execute, prepare_parent},
    history::parent_transactions_inactivity_floor,
    reject_verify, time,
};
use commonware_codec::EncodeSize as _;
use commonware_consensus::simplex::types::Context;
use commonware_cryptography::{Digest, Digestible, Hasher, PublicKey, certificate::Scheme as _};
use commonware_glue::stateful::{
    Application as CApplication, Proposed,
    db::{DatabaseSet, Merkleized as _},
};
use commonware_macros::boxed;
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Spawner, Storage, telemetry::traces::TracedExt as _,
};
use commonware_storage::{mmr, translator::EightCap};
use constantinople_mempool::TransactionSource;
use constantinople_primitives::{
    Block, Header, Outcomes, ParentNotarization, Sealable, SealedBlock, SignedTransaction,
    notarization_digest, outcomes_digest,
    proposal::{MAXIMUM_BLOCK_SIZE, parent_bytes},
};
use rand::{CryptoRng, Rng};
use std::{collections::HashSet, future::Future, sync::Arc};
use tracing::{Instrument as _, error, info, info_span, warn};

/// Whether `notarization` is what a child with consensus context `context` must
/// carry about `parent`: a notarization of the parent's proposal, or none if
/// the parent is the genesis block.
///
/// The signatures in the notarization are not checked here.
fn notarizes_parent<C, P, H>(
    notarization: Option<&ParentNotarization<C>>,
    parent: &Header<C, H::Digest, P>,
    context: &Context<C, P>,
) -> bool
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    match notarization {
        None => parent.height == 0,
        Some(notarization) => {
            parent.height != 0
                && notarization.proposal.round == parent.context.round
                && notarization.proposal.parent == parent.context.parent.0
                && notarization.proposal.payload == context.parent.1
        }
    }
}

impl<E, H, C, X, P, I, St> Application<E, H, C, X, P, I, St>
where
    E: BufferPooler + Storage + Metrics + Clock,
    C: Digest,
    H: Hasher,
    P: PublicKey,
    X: Chain<C, P, H>,
    St: Strategy,
{
    /// The number of validators whose reports fix the status of a transaction.
    fn validators(&self) -> u32 {
        u32::try_from(self.scheme.participants().len()).expect("validator count fits in u32")
    }

    /// Decides which of `parent`'s transactions are authentic, off this task.
    async fn prepare_parent(
        &self,
        parent: Arc<SealedBlock<C, P, H>>,
        notarization: Option<ParentNotarization<C>>,
    ) -> Result<ParentEntries> {
        let span = info_span!(
            "application.execute.prepare",
            txs = parent.body.len().traced()
        );
        let validators = self.validators();
        let work_size = parent.body.len();

        // The last parent reference destroys the whole body, so it is released
        // on the strategy's pool with the rest of this job.
        self.strategy
            .spawn(work_size, move |strategy| {
                span.in_scope(|| {
                    prepare_parent(&strategy, &parent.body, notarization.as_ref(), validators)
                })
            })
            .await
    }

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
        Self: CApplication<E, Block = SealedBlock<C, P, H>, Databases = Databases<E, H, EightCap, St>>,
        I: TransactionSource<C, P, H> + Sync,
    {
        let parent_digest = parent.digest();
        let parent_header = parent.header.clone();

        // The block must carry a notarization of its parent. Consensus proposes
        // on a parent it holds a notarization for, so one is missing only if
        // this node learned of the parent some other way.
        let notarization = if parent_header.height == 0 {
            None
        } else {
            let notarization = self
                .chain
                .notarization(parent_header.context.round, context.parent.1)
                .instrument(info_span!("application.propose.notarization"))
                .await;
            if !notarization
                .as_ref()
                .is_some_and(|n| notarizes_parent::<C, P, H>(Some(n), &parent_header, &context))
            {
                warn!(
                    height = parent_header.height + 1,
                    parent_round = %parent_header.context.round,
                    "application.propose.missing_notarization"
                );
                return None;
            }
            notarization
        };

        // Apply the parent's authentic transactions to the parent's state.
        let transaction_floor = parent_transactions_inactivity_floor(&parent);
        let entries = self
            .prepare_parent(parent, notarization.clone())
            .await
            .inspect_err(|&reason| error!(reason, "application.propose.parent"))
            .ok()?;

        // Select this block's transactions. They execute with the next block, so
        // nothing here depends on the state: a transaction is left out only if
        // it is listed twice or lacks what its kind requires.
        //
        // The byte budget of the transaction source assumes a block that says
        // nothing about its parent. What this block says takes from it.
        let reserved = parent_bytes(notarization.as_ref(), &Outcomes::zeroes(entries.len()))
            - parent_bytes::<C>(None, &Outcomes::new());
        let candidates = input
            .propose(&parent_header, context.round, reserved)
            .instrument(info_span!("application.propose.input"))
            .await;
        let validators = self.validators() as usize;
        let bits = constantinople_auth::tag_bits(self.validators());
        let mut seen = HashSet::with_capacity(candidates.len());
        let mut body: Vec<SignedTransaction<H>> = Vec::with_capacity(candidates.len());
        let mut authenticators = Vec::new();
        for candidate in candidates {
            let tagged = candidate.transaction.is_mac();
            let authenticator = match (tagged, candidate.authenticator) {
                (false, _) => None,
                (true, Some(tags)) if tags.len() == validators && tags.bits() == bits => Some(tags),
                (true, _) => continue,
            };
            if !seen.insert(*candidate.transaction.message_digest()) {
                continue;
            }
            body.push(candidate.transaction);
            authenticators.extend(authenticator);
        }
        let digests = body.iter().map(|tx| *tx.message_digest()).collect();

        let (state_batch, transaction_batch) = batches;
        let execution = execute(
            self.strategy.clone(),
            state_batch,
            transaction_batch,
            transaction_floor,
            entries,
            digests,
        )
        .await;

        let hasher = &mut H::default();
        let header = Header {
            context,
            parent: parent_digest,
            height: parent_header.height + 1,
            timestamp: time::timestamp_ms(&runtime),
            parent_notarization: notarization_digest(notarization.as_ref(), hasher),
            parent_outcomes: outcomes_digest(&execution.outcomes, hasher),
            state_root: execution.state.root(),
            state_range: execution.state_sync_range.clone(),
            transactions_root: execution.transactions.root(),
            transactions_range: execution.transactions_range.clone(),
        };
        let transaction_count = body.len();
        let block = Block::with_parent(header, notarization, execution.outcomes.clone(), body);
        let encoded_size = block.encode_size();

        // A transaction source may exceed its budget. Trimming here would
        // invalidate the execution commitments.
        if encoded_size > MAXIMUM_BLOCK_SIZE {
            warn!(
                height = block.header.height,
                encoded_size,
                maximum_size = MAXIMUM_BLOCK_SIZE,
                "application.propose.oversized"
            );
            return None;
        }

        let block = block.seal(hasher);
        self.chain.built(&block, authenticators);
        self.proposed_transactions.inc_by(transaction_count as u64);

        info!(
            epoch = block.header.context.round.epoch().get(),
            view = block.header.context.round.view().get(),
            height = block.header.height,
            txs = transaction_count,
            parent_applied = execution.applied,
            timestamp = block.header.timestamp,
            "application.propose.complete"
        );

        Some(Proposed {
            block,
            merkleized: execution.into_merkleized(),
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
        (runtime, context): (E, Context<C, P>),
        block: Arc<SealedBlock<C, P, H>>,
        parent: impl Future<Output = Option<Arc<SealedBlock<C, P, H>>>> + Send,
        batches: <<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Merkleized>
    where
        E: Rng + Spawner + BufferPooler + Storage + Metrics + Clock + CryptoRng,
        Self: CApplication<E, Block = SealedBlock<C, P, H>, Databases = Databases<E, H, EightCap, St>>,
        I: TransactionSource<C, P, H> + Sync,
    {
        let encoded_size = block.encode_size();
        if encoded_size > MAXIMUM_BLOCK_SIZE {
            warn!(
                height = block.header.height,
                encoded_size,
                maximum_size = MAXIMUM_BLOCK_SIZE,
                reason = "oversized_block",
                "application.verify.reject"
            );
            return None;
        }

        // The glue actor retains its own references to the block, so the
        // header and lazy body are cloned out of the shared reference
        // (per-transaction refcount bumps) instead of moved.
        let header = block.header.clone();
        if !block.commits_to_parent(&mut H::default()) {
            reject_verify(header.height, PARENT_COMMITMENT_MISMATCH);
            return None;
        }
        let notarization = block.notarization.clone();
        let outcomes = block.outcomes.clone();
        let body = Arc::new(block.body.clone());
        drop(block);

        // Signature verification and the block's own digests need only the
        // block body, so they start before the parent fetch and can overlap it
        // when offloaded. The child context supplies an owned CryptoRng.
        let (state_batch, transaction_batch) = batches;
        let signatures = verify_signatures::<E, H, St>(
            runtime.child("verify_signatures"),
            self.transaction_namespace,
            self.public_key_cache.clone(),
            Arc::clone(&body),
            &self.strategy,
        );
        let digests_span = info_span!("application.verify.digests", txs = body.len().traced());
        let digests = self.strategy.spawn(body.len(), move |strategy| {
            digests_span.in_scope(|| body_digests(&strategy, &body))
        });

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

        // The block's notarization of its parent decides which of the parent's
        // transactions are authentic, so it must be one: the votes of a quorum
        // for the parent's proposal.
        if !notarizes_parent::<C, P, H>(notarization.as_ref(), &parent.header, &context) {
            reject_verify(header.height, INVALID_NOTARIZATION);
            return None;
        }
        let certificate = {
            let notarization = notarization.clone();
            let scheme = self.scheme.clone();
            let mut rng = runtime.child("verify_notarization");
            let span = info_span!("application.verify.notarization");
            self.strategy
                .spawn(scheme.participants().len(), move |strategy| {
                    span.in_scope(|| {
                        notarization
                            .is_none_or(|n| n.verify(&mut rng, &scheme, &strategy))
                            .then_some(())
                            .ok_or(INVALID_NOTARIZATION)
                    })
                })
        };

        // Join the checks with execution so offloaded work can overlap
        // execution and the timestamp wait.
        let transaction_floor = parent_transactions_inactivity_floor(&parent);
        let strategy = self.strategy.clone();
        let entries = self.prepare_parent(parent, notarization);
        let execution = async move {
            let (entries, digests) = futures::try_join!(entries, digests)?;
            Ok(execute(
                strategy,
                state_batch,
                transaction_batch,
                transaction_floor,
                entries,
                digests,
            )
            .await)
        };
        let wait = wait_for_timestamp(runtime, time::block_deadline(header.timestamp));

        let execution = match futures::try_join!(signatures, certificate, execution, wait) {
            Ok(((), (), execution, ())) => execution,
            Err(reason) => {
                reject_verify(header.height, reason);
                return None;
            }
        };

        if execution.outcomes != outcomes {
            reject_verify(header.height, OUTCOMES_MISMATCH);
            return None;
        }
        if !commitments_match(&header, &execution) {
            return None;
        }

        info!(
            epoch = header.context.round.epoch().get(),
            view = header.context.round.view().get(),
            height = header.height,
            parent_applied = execution.applied,
            timestamp = header.timestamp,
            "application.verify.complete"
        );

        Some(execution.into_merkleized())
    }

    /// Replays a block into speculative batches.
    ///
    /// The block is finalized, so its signatures and the signatures in its
    /// notarization of the parent are not checked again. Its commitments are.
    #[doc(hidden)]
    #[boxed]
    #[tracing::instrument(
        name = "application.apply",
        skip_all,
        fields(height = block.header.height.traced())
    )]
    pub async fn apply_block(
        &mut self,
        (_, context): (E, Context<C, P>),
        block: &SealedBlock<C, P, H>,
        batches: <<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Merkleized>
    where
        E: Rng + Spawner + BufferPooler + Storage + Metrics + Clock + CryptoRng,
        Self: CApplication<E, Block = SealedBlock<C, P, H>, Databases = Databases<E, H, EightCap, St>>,
        I: TransactionSource<C, P, H> + Sync,
    {
        let height = block.header.height;
        let reject = |reason: &'static str| error!(height, reason, "application.apply.reject");
        if !block.commits_to_parent(&mut H::default()) {
            reject(PARENT_COMMITMENT_MISMATCH);
            return None;
        }

        // The parent's transactions execute with this block. The child of the
        // genesis block has none to execute.
        let entries = if height <= 1 {
            if block.notarization.is_some() {
                reject(INVALID_NOTARIZATION);
                return None;
            }
            ParentEntries::empty()
        } else {
            let parent = self
                .chain
                .parent(block)
                .instrument(info_span!("application.apply.parent"))
                .await?;
            if parent.digest() != block.header.parent
                || !notarizes_parent::<C, P, H>(
                    block.notarization.as_ref(),
                    &parent.header,
                    &context,
                )
            {
                reject(INVALID_NOTARIZATION);
                return None;
            }
            self.prepare_parent(parent, block.notarization.clone())
                .await
                .inspect_err(|&reason| reject(reason))
                .ok()?
        };

        let strategy = self.strategy.clone();
        let body = block.body.clone();
        let digests_span = info_span!("application.apply.digests", txs = body.len().traced());
        let digests = strategy
            .spawn(body.len(), move |s| {
                digests_span.in_scope(|| body_digests(&s, &body))
            })
            .await
            .inspect_err(|&reason| reject(reason))
            .ok()?;

        let (state_batch, transaction_batch) = batches;
        let execution = execute(
            strategy,
            state_batch,
            transaction_batch,
            mmr::Location::new(block.header.transactions_range.start()),
            entries,
            digests,
        )
        .await;
        if execution.outcomes != block.outcomes {
            reject(OUTCOMES_MISMATCH);
            return None;
        }
        Some(execution.into_merkleized())
    }
}
