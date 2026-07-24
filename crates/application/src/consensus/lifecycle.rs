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
use commonware_consensus::{simplex::types::Context, types::Epoch};
use commonware_cryptography::{
    Digest, Digestible, Hasher, PublicKey, Signer, bls12381::primitives::variant::Variant,
    certificate::Scheme, ed25519,
};
use commonware_glue::{
    dkg::{network::Directory, types::Payload},
    stateful::{
        Application as CApplication, Proposed,
        db::{DatabaseSet, Merkleized as _},
    },
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

type LifecycleBlock<C, H, V, D, Dir> = SealedBlock<C, ed25519::PublicKey, H, Payload<V, D, Dir>>;

fn mempool_header<C, D, P, R>(header: &Header<C, D, P, R>) -> Header<C, D, P>
where
    C: Digest,
    D: Digest,
    P: PublicKey,
{
    Header {
        context: header.context.clone(),
        parent: header.parent,
        height: header.height,
        timestamp: header.timestamp,
        eligible_peers_root: header.eligible_peers_root,
        state_root: header.state_root,
        state_range: header.state_range.clone(),
        transactions_root: header.transactions_root,
        transactions_range: header.transactions_range.clone(),
        committee_root: header.committee_root,
        committee_range: header.committee_range.clone(),
        payload: None,
    }
}

fn valid_payload<V, D, Dir>(
    height: u64,
    blocks_per_epoch: u64,
    payload: Option<&Payload<V, D, Dir>>,
    entering: &super::Committee,
    selected: &super::Committee,
) -> bool
where
    V: Variant,
    D: Signer<PublicKey = ed25519::PublicKey>,
    Dir: Directory<ed25519::PublicKey>,
{
    let relative = height % blocks_per_epoch;
    if relative == blocks_per_epoch - 1 {
        let Some(Payload::EpochInfo(info)) = payload else {
            return false;
        };
        let epoch = Epoch::new(height / blocks_per_epoch);
        return info.epoch == epoch.next()
            && &info.players == entering.members()
            && &info.next_players == selected.members();
    }

    match payload {
        None => true,
        Some(Payload::DealerLog(_)) => relative >= blocks_per_epoch / 2,
        Some(Payload::EpochInfo(_)) => false,
    }
}

impl<E, H, C, S, I, V, D, Dir, St>
    Application<E, H, C, S, ed25519::PublicKey, I, Payload<V, D, Dir>, St>
where
    E: BufferPooler + Storage + Metrics + Clock,
    C: Digest,
    H: Hasher,
    V: Variant,
    D: Signer<PublicKey = ed25519::PublicKey>,
    Dir: Directory<ed25519::PublicKey>,
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
        (runtime, context): (E, Context<C, ed25519::PublicKey>),
        parent: Arc<LifecycleBlock<C, H, V, D, Dir>>,
        batches: <<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Unmerkleized,
        payload: Option<Payload<V, D, Dir>>,
        input: &mut I,
    ) -> Option<Proposed<Self, E>>
    where
        E: Rng + Spawner + BufferPooler + Storage + Metrics + Clock + CryptoRng,
        S: Scheme<PublicKey = ed25519::PublicKey>,
        I: TransactionSource<C, ed25519::PublicKey, H> + Sync,
        St: Strategy,
    {
        let parent_digest = parent.digest();
        let parent_height = parent.header.height;
        if parent.header.eligible_peers_root != self.eligible_peers_root {
            warn!(
                height = parent_height,
                reason = "eligible_peers_root_mismatch",
                "application.propose.reject"
            );
            return None;
        }

        // Select from the mempool, then execute the selection best effort
        // against the parent's state: anything inapplicable there fails its
        // nonce or balance check and is dropped, and the block tops up from
        // the live mempool toward the proposal budget.
        let mempool_parent = mempool_header(&parent.header);
        let seed = input
            .propose(&mempool_parent, context.round, 0)
            .instrument(info_span!("application.propose.input"))
            .await;
        let (state_batch, transaction_batch, committee_batch) = batches;
        let execution = execute_proposal(
            self.strategy.clone(),
            &runtime,
            state_batch,
            transaction_batch,
            committee_batch,
            parent_transactions_inactivity_floor(&parent),
            &parent.header,
            &mempool_parent,
            context.round,
            seed,
            input,
            &self.initial_committee,
            &self.initial_next_committee,
            self.eligible_committee_members.clone(),
            self.blocks_per_epoch.get(),
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

        if !valid_payload(
            parent_height + 1,
            self.blocks_per_epoch.get(),
            payload.as_ref(),
            &execution.block.entering_committee,
            &execution.block.selected_committee,
        ) {
            return None;
        }

        let header = Header {
            context,
            parent: parent_digest,
            height: parent_height + 1,
            timestamp: time::timestamp_ms(&runtime),
            eligible_peers_root: self.eligible_peers_root,
            state_root: execution.block.state.root(),
            state_range: execution.block.state_sync_range.clone(),
            transactions_root: execution.block.transactions.root(),
            transactions_range: execution.block.transactions_range.clone(),
            committee_root: execution.block.committee.root(),
            committee_range: execution.block.committee_range.clone(),
            payload,
        };
        let block =
            Block::<C, ed25519::PublicKey, H, Payload<V, D, Dir>>::new(header, execution.body)
                .seal(&mut H::default());

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
        (runtime, _context): (E, Context<C, ed25519::PublicKey>),
        block: Arc<LifecycleBlock<C, H, V, D, Dir>>,
        parent: impl Future<Output = Option<Arc<LifecycleBlock<C, H, V, D, Dir>>>> + Send,
        batches: <<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Merkleized>
    where
        E: Rng + Spawner + BufferPooler + Storage + Metrics + Clock + CryptoRng,
        S: Scheme<PublicKey = ed25519::PublicKey>,
        I: TransactionSource<C, ed25519::PublicKey, H> + Sync,
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
        let (state_batch, transaction_batch, committee_batch) = batches;
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
        if header.eligible_peers_root != self.eligible_peers_root
            || header.eligible_peers_root != parent.header.eligible_peers_root
        {
            warn!(
                height = header.height,
                reason = "eligible_peers_root_mismatch",
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
            committee_batch,
            parent_transactions_inactivity_floor(&parent),
            header.height,
            body,
            &self.initial_committee,
            &self.initial_next_committee,
            self.eligible_committee_members.clone(),
            self.blocks_per_epoch.get(),
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

        if !commitments_match(&header, &execution)
            || !valid_payload(
                header.height,
                self.blocks_per_epoch.get(),
                header.payload.as_ref(),
                &execution.entering_committee,
                &execution.selected_committee,
            )
        {
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
        (_, _): (E, Context<C, ed25519::PublicKey>),
        block: &LifecycleBlock<C, H, V, D, Dir>,
        batches: <<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Merkleized
    where
        E: Rng + Spawner + BufferPooler + Storage + Metrics + Clock + CryptoRng,
        S: Scheme<PublicKey = ed25519::PublicKey>,
        I: TransactionSource<C, ed25519::PublicKey, H> + Sync,
        St: Strategy,
    {
        assert!(
            block.header.eligible_peers_root == self.eligible_peers_root,
            "certified block committed an unexpected eligible peer catalog"
        );
        let strategy = self.strategy.clone();
        let body = block.body.clone();
        let prepare_span = info_span!("application.apply.prepare", txs = body.len().traced());
        let (body, digests) = strategy
            .spawn(move |s| prepare_span.in_scope(|| prepare_lazy(&s, &body)))
            .await
            .unwrap_or_else(|reason| panic!("certified block contained {reason}"));

        let (state_batch, transaction_batch, committee_batch) = batches;
        let execution = apply_prepared_body::<E, H, St>(
            state_batch,
            transaction_batch,
            committee_batch,
            mmr::Location::new(block.header.transactions_range.start()),
            block.header.height,
            body,
            digests,
            strategy,
            &self.initial_committee,
            &self.initial_next_committee,
            &self.eligible_committee_members,
            self.blocks_per_epoch.get(),
        )
        .await
        .unwrap_or_else(|reason| panic!("certified block contained {reason}"));
        assert!(
            valid_payload(
                block.header.height,
                self.blocks_per_epoch.get(),
                block.header.payload.as_ref(),
                &execution.entering_committee,
                &execution.selected_committee,
            ),
            "certified block contained invalid reshare payload"
        );
        execution.into_merkleized()
    }
}

#[cfg(test)]
mod tests {
    use super::valid_payload;
    use crate::consensus::{BLOCKS_PER_EPOCH, Committee};
    use commonware_consensus::types::Epoch;
    use commonware_cryptography::{
        Signer as _,
        bls12381::{
            dkg::feldman_desmedt::{self, Dealer, Info},
            primitives::{sharing::Mode, variant::MinSig},
        },
        ed25519,
    };
    use commonware_glue::dkg::types::{EpochInfo, EpochOutcome, Payload};
    use commonware_utils::{N3f1, ordered::Set};

    type TestPayload = Payload<MinSig, ed25519::PrivateKey>;

    fn key(seed: u64) -> ed25519::PrivateKey {
        ed25519::PrivateKey::from_seed(seed)
    }

    fn epoch_info(
        epoch: Epoch,
        players: Set<ed25519::PublicKey>,
        next_players: Set<ed25519::PublicKey>,
    ) -> EpochInfo<MinSig, ed25519::PublicKey> {
        let (output, _) = feldman_desmedt::deal::<MinSig, _, N3f1>(
            &mut commonware_utils::test_rng(),
            Mode::NonZeroCounter,
            players.clone(),
        )
        .expect("test DKG setup");
        EpochInfo {
            outcome: EpochOutcome::Success,
            epoch,
            output,
            players,
            next_players,
            directory: (),
        }
    }

    fn dealer_log() -> TestPayload {
        let dealer = key(201);
        let participants = Set::from_iter_dedup([dealer.public_key()]);
        let info = Info::<MinSig, _>::new::<N3f1>(
            b"constantinople-application-payload-test",
            0,
            None,
            Mode::NonZeroCounter,
            participants.clone(),
            participants,
        )
        .expect("dealer info");
        let (dealer, _, _) =
            Dealer::start::<N3f1>(&mut commonware_utils::test_rng(), info, dealer, None)
                .expect("dealer start");
        TestPayload::DealerLog(dealer.finalize::<N3f1>())
    }

    #[test]
    fn final_payload_binds_epoch_and_both_committee_snapshots() {
        assert_eq!(BLOCKS_PER_EPOCH, 64);
        let a = key(211).public_key();
        let b = key(212).public_key();
        let c = key(213).public_key();
        let entering = Committee::new(Set::from_iter_dedup([a, b.clone()])).unwrap();
        let selected = Committee::new(Set::from_iter_dedup([b, c])).unwrap();
        let epoch = Epoch::new(7);
        let height = epoch.get() * BLOCKS_PER_EPOCH + BLOCKS_PER_EPOCH - 1;
        let valid = epoch_info(
            epoch.next(),
            entering.members().clone(),
            selected.members().clone(),
        );

        assert!(valid_payload(
            height,
            BLOCKS_PER_EPOCH,
            Some(&TestPayload::EpochInfo(valid.clone())),
            &entering,
            &selected,
        ));

        let mut wrong_epoch = valid.clone();
        wrong_epoch.epoch = epoch;
        let mut wrong_players = valid.clone();
        wrong_players.players = selected.members().clone();
        let mut wrong_next_players = valid;
        wrong_next_players.next_players = entering.members().clone();
        for invalid in [wrong_epoch, wrong_players, wrong_next_players] {
            assert!(!valid_payload(
                height,
                BLOCKS_PER_EPOCH,
                Some(&TestPayload::EpochInfo(invalid)),
                &entering,
                &selected,
            ));
        }
        assert!(!valid_payload::<MinSig, ed25519::PrivateKey, ()>(
            height,
            BLOCKS_PER_EPOCH,
            None,
            &entering,
            &selected,
        ));
        assert!(!valid_payload(
            height,
            BLOCKS_PER_EPOCH,
            Some(&dealer_log()),
            &entering,
            &selected,
        ));
    }

    #[test]
    fn dealer_logs_are_allowed_from_midpoint_until_before_final_block() {
        let member = key(221).public_key();
        let committee = Committee::new(Set::from_iter_dedup([member])).unwrap();
        let log = dealer_log();
        let midpoint = BLOCKS_PER_EPOCH / 2;

        assert!(!valid_payload(
            midpoint - 1,
            BLOCKS_PER_EPOCH,
            Some(&log),
            &committee,
            &committee,
        ));
        assert!(valid_payload(
            midpoint,
            BLOCKS_PER_EPOCH,
            Some(&log),
            &committee,
            &committee,
        ));
        assert!(valid_payload(
            BLOCKS_PER_EPOCH - 2,
            BLOCKS_PER_EPOCH,
            Some(&log),
            &committee,
            &committee,
        ));

        let early_info = epoch_info(
            Epoch::new(1),
            committee.members().clone(),
            committee.members().clone(),
        );
        assert!(!valid_payload(
            midpoint,
            BLOCKS_PER_EPOCH,
            Some(&TestPayload::EpochInfo(early_info)),
            &committee,
            &committee,
        ));
    }
}
