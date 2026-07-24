use super::{
    Application, BLOCKS_PER_EPOCH, Committee, CommitteeSyncTarget, Databases, MAX_COMMITTEE_SIZE,
    StateSyncTarget, TransactionHistoryTarget, execution::execute_body, genesis_block,
    history::parent_transactions_inactivity_floor, seed_committees,
};
use commonware_consensus::{
    simplex::{
        scheme::bls12381_threshold::standard as threshold, types::Context as SimplexContext,
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    Digest as _, Hasher as _, Signer as _,
    bls12381::{
        dkg::feldman_desmedt,
        primitives::{sharing::Mode, variant::MinSig},
    },
    ed25519, sha256,
};
use commonware_glue::{
    dkg::types::{EpochInfo, EpochOutcome, Payload},
    stateful::db::{DatabaseSet as _, Merkleized as _, Unmerkleized as _},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{
    journal::contiguous::{
        fixed::Config as FixedJournalConfig, variable::Config as VariableJournalConfig,
    },
    merkle::{full::Config as MmrConfig, mmr},
    qmdb::{any::FixedConfig, batch_chain::Bounds, keyless::fixed as keyless_fixed},
    translator::EightCap,
};
use commonware_utils::{N3f1, NZU16, NZU64, NZUsize, non_empty_range, ordered::Set};
use constantinople_mempool::mocks::StaticTransactionSource;
use constantinople_primitives::{
    Account, AccountKey, Block, Header, LazySignedTransaction, Nonce, PublicKeyCache, Sealable,
    SealedBlock, SignedTransaction, Transaction, TransactionPublicKey,
};
use futures::FutureExt as _;
use std::{num::NonZeroU64, panic::AssertUnwindSafe, sync::Arc, time::Duration};

type TestPayload = Payload<MinSig, ed25519::PrivateKey>;
type TestApp = Application<
    deterministic::Context,
    sha256::Sha256,
    sha256::Digest,
    threshold::Scheme<ed25519::PublicKey, MinSig>,
    ed25519::PublicKey,
    StaticTransactionSource<sha256::Digest, ed25519::PublicKey, sha256::Sha256>,
    TestPayload,
    Sequential,
>;
type TestDbs = Databases<deterministic::Context, sha256::Sha256, EightCap, Sequential>;

const TEST_TX_NS: &[u8] = b"constantinople-application-test-transactions";

fn empty_state_target() -> StateSyncTarget<sha256::Digest> {
    StateSyncTarget::new(
        sha256::Digest::EMPTY,
        non_empty_range!(mmr::Location::new(0), mmr::Location::new(1)),
    )
}

fn empty_committee_target() -> CommitteeSyncTarget<sha256::Digest> {
    CommitteeSyncTarget::new(
        sha256::Digest::EMPTY,
        non_empty_range!(mmr::Location::new(0), mmr::Location::new(1)),
    )
}

fn state_config(cache: CacheRef) -> FixedConfig<EightCap, Sequential> {
    FixedConfig {
        merkle_config: MmrConfig {
            journal_partition: "verify-invalid-state-merkle-journal".into(),
            metadata_partition: "verify-invalid-state-merkle-metadata".into(),
            items_per_blob: NZU64!(1024),
            write_buffer: NZUsize!(4096),
            strategy: Sequential,
            page_cache: cache.clone(),
        },
        journal_config: FixedJournalConfig {
            partition: "verify-invalid-state-log".into(),
            items_per_blob: NZU64!(1024),
            page_cache: cache,
            write_buffer: NZUsize!(4096),
        },
        translator: EightCap,
        init_cache_size: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(1 << 20),
        init_concurrency: (),
    }
}

fn committee_config(cache: CacheRef) -> FixedConfig<EightCap, Sequential> {
    FixedConfig {
        merkle_config: MmrConfig {
            journal_partition: "verify-invalid-committee-merkle-journal".into(),
            metadata_partition: "verify-invalid-committee-merkle-metadata".into(),
            items_per_blob: NZU64!(1024),
            write_buffer: NZUsize!(4096),
            strategy: Sequential,
            page_cache: cache.clone(),
        },
        journal_config: FixedJournalConfig {
            partition: "verify-invalid-committee-log".into(),
            items_per_blob: NZU64!(1024),
            page_cache: cache,
            write_buffer: NZUsize!(4096),
        },
        translator: EightCap,
        init_cache_size: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(1 << 20),
        init_concurrency: (),
    }
}

fn transaction_config(cache: CacheRef) -> keyless_fixed::CompactConfig<Sequential> {
    keyless_fixed::CompactConfig {
        strategy: Sequential,
        witness: VariableJournalConfig {
            partition: "verify-invalid-transactions-witness".into(),
            items_per_section: NZU64!(1024),
            compression: None,
            codec_config: (),
            page_cache: cache,
            write_buffer: NZUsize!(4096),
        },
        commit_codec_config: (),
    }
}

fn sync_range_from_bounds(
    bounds: &Bounds<mmr::Family>,
) -> commonware_utils::range::NonEmptyRange<mmr::Location> {
    non_empty_range!(
        bounds.inactivity_floor,
        mmr::Location::new(bounds.total_size)
    )
}

type TestBlock = SealedBlock<sha256::Digest, ed25519::PublicKey, sha256::Sha256, TestPayload>;

fn test_genesis_info(members: Set<ed25519::PublicKey>) -> EpochInfo<MinSig, ed25519::PublicKey> {
    let (output, _) = feldman_desmedt::deal::<MinSig, _, N3f1>(
        &mut commonware_utils::test_rng(),
        Mode::NonZeroCounter,
        members.clone(),
    )
    .expect("test DKG setup");
    EpochInfo {
        outcome: EpochOutcome::Success,
        epoch: Epoch::zero(),
        output,
        players: members.clone(),
        next_players: members,
        directory: (),
    }
}

/// Genesis-backed fixture shared by the propose/verify tests.
///
/// `sender` and `alt_sender` are funded at genesis so tests can execute real
/// transfers; `recipient` starts empty.
struct VerifyHarness {
    app: TestApp,
    dbs: TestDbs,
    parent: TestBlock,
    leader: ed25519::PrivateKey,
    sender: ed25519::PrivateKey,
    alt_sender: ed25519::PrivateKey,
    recipient: ed25519::PrivateKey,
    state_target: StateSyncTarget<sha256::Digest>,
    transaction_target: TransactionHistoryTarget<sha256::Digest>,
    committee_target: CommitteeSyncTarget<sha256::Digest>,
    eligible_committee_members: Set<ed25519::PublicKey>,
}

async fn verify_harness(context: &deterministic::Context) -> VerifyHarness {
    let cache = CacheRef::from_pooler(context, NZU16!(16), NZUsize!(4096));
    let dbs = TestDbs::init(
        context.child("dbs"),
        (
            state_config(cache.clone()),
            transaction_config(cache.clone()),
            committee_config(cache.clone()),
        ),
    )
    .await;

    let leader = ed25519::PrivateKey::from_seed(21);
    let sender = ed25519::PrivateKey::from_seed(22);
    let recipient = ed25519::PrivateKey::from_seed(23);
    let alt_sender = ed25519::PrivateKey::from_seed(24);

    let (mut state_batch, transaction_batch, committee_batch) = dbs.new_batches().await;
    for funded in [&sender, &alt_sender] {
        state_batch = state_batch.write(
            AccountKey::from_public_key(&TransactionPublicKey::ed25519(funded.public_key())),
            Some(Account {
                balance: 1_000_000,
                nonce: Nonce::default(),
            }),
        );
    }
    let state = state_batch.merkleize().await.expect("genesis state");
    let transactions = transaction_batch
        .merkleize()
        .await
        .expect("genesis transactions");
    let genesis_committee = Committee::new(Set::from_iter_dedup([leader.public_key()]))
        .expect("test genesis committee");
    let genesis_info = test_genesis_info(genesis_committee.members().clone());
    let committee = seed_committees(committee_batch, genesis_committee.clone())
        .merkleize()
        .await
        .expect("genesis committee");
    let state_target = StateSyncTarget::new(state.root(), sync_range_from_bounds(state.bounds()));
    let transaction_target = TransactionHistoryTarget::new(
        transactions.root(),
        mmr::Location::new(transactions.bounds().total_size),
    );
    let committee_target =
        CommitteeSyncTarget::new(committee.root(), sync_range_from_bounds(committee.bounds()));
    dbs.finalize((state, transactions, committee)).await;

    let parent = genesis_block::<sha256::Digest, _, sha256::Sha256, _>(
        &mut sha256::Sha256::default(),
        leader.public_key(),
        0,
        state_target.clone(),
        transaction_target.clone(),
        committee_target.clone(),
        TestPayload::EpochInfo(genesis_info.clone()),
    );
    let eligible_committee_members = Set::from_iter_dedup([
        leader.public_key(),
        sender.public_key(),
        recipient.public_key(),
        alt_sender.public_key(),
    ]);
    VerifyHarness {
        app: TestApp::new(
            context.child("app"),
            Sequential,
            leader.public_key(),
            sha256::Digest::EMPTY,
            TEST_TX_NS,
            PublicKeyCache::new(context.child("public_key_cache"), NZUsize!(64)),
            state_target.clone(),
            transaction_target.clone(),
            committee_target.clone(),
            genesis_info,
            NonZeroU64::new(BLOCKS_PER_EPOCH).expect("epoch length is non-zero"),
            genesis_committee,
            eligible_committee_members.clone(),
            None,
        ),
        dbs,
        parent,
        leader,
        sender,
        alt_sender,
        recipient,
        state_target,
        transaction_target,
        committee_target,
        eligible_committee_members,
    }
}

type TestSource = StaticTransactionSource<sha256::Digest, ed25519::PublicKey, sha256::Sha256>;

fn transfer(
    sender: &ed25519::PrivateKey,
    recipient: &ed25519::PrivateKey,
    value: u64,
) -> SignedTransaction<sha256::Sha256> {
    Transaction::new(
        TransactionPublicKey::ed25519(sender.public_key()),
        TransactionPublicKey::ed25519(recipient.public_key()),
        NonZeroU64::new(value).expect("test value should be non-zero"),
        0,
    )
    .seal_and_sign(sender, TEST_TX_NS, &mut sha256::Sha256::default())
}

fn committee_transaction(
    sender: &ed25519::PrivateKey,
    target_epoch: Epoch,
    peer: ed25519::PublicKey,
    registered: bool,
    nonce: u64,
) -> SignedTransaction<sha256::Sha256> {
    Transaction::set_committee_member(
        TransactionPublicKey::ed25519(sender.public_key()),
        target_epoch,
        peer,
        registered,
        nonce,
    )
    .seal_and_sign(sender, TEST_TX_NS, &mut sha256::Sha256::default())
}

/// Minimal committed-state fixture for executing committee transactions at
/// selected heights without manufacturing all 1,024 blocks in an epoch.
struct ReducerHarness {
    dbs: TestDbs,
    initial: Committee,
    eligible: Set<ed25519::PublicKey>,
    sender: ed25519::PrivateKey,
}

async fn reducer_harness(
    context: &deterministic::Context,
    initial: Committee,
    eligible: Set<ed25519::PublicKey>,
    sender: ed25519::PrivateKey,
) -> ReducerHarness {
    let cache = CacheRef::from_pooler(context, NZU16!(16), NZUsize!(4096));
    let dbs = TestDbs::init(
        context.child("reducer_dbs"),
        (
            state_config(cache.clone()),
            transaction_config(cache.clone()),
            committee_config(cache),
        ),
    )
    .await;

    // Only the transaction sender needs account state. Committee state is
    // deliberately left empty so height one exercises reducer seeding.
    let (state_batch, transaction_batch, committee_batch) = dbs.new_batches().await;
    let state_batch = state_batch.write(
        AccountKey::from_public_key(&TransactionPublicKey::ed25519(sender.public_key())),
        Some(Account {
            balance: 1,
            nonce: Nonce::default(),
        }),
    );
    let (state, transactions, committee) = futures::join!(
        state_batch.merkleize(),
        transaction_batch.merkleize(),
        committee_batch.merkleize(),
    );
    dbs.finalize((
        state.expect("reducer state seed"),
        transactions.expect("reducer transaction seed"),
        committee.expect("empty reducer committee seed"),
    ))
    .await;

    ReducerHarness {
        dbs,
        initial,
        eligible,
        sender,
    }
}

async fn execute_committee_block(
    harness: &ReducerHarness,
    height: u64,
    transactions: Vec<SignedTransaction<sha256::Sha256>>,
) -> Result<(Committee, Committee), &'static str> {
    let (state_batch, transaction_batch, committee_batch) = harness.dbs.new_batches().await;
    let body = Arc::new(
        transactions
            .into_iter()
            .map(LazySignedTransaction::new)
            .collect(),
    );
    let execution = execute_body(
        Sequential,
        state_batch,
        transaction_batch,
        committee_batch,
        mmr::Location::new(0),
        height,
        body,
        &harness.initial,
        Arc::new(harness.eligible.clone()),
        BLOCKS_PER_EPOCH,
    )
    .await?;
    let committees = (
        execution.entering_committee.clone(),
        execution.selected_committee.clone(),
    );
    harness.dbs.finalize(execution.into_merkleized()).await;
    Ok(committees)
}

async fn exact_committee_row(dbs: &TestDbs, epoch: u64) -> Option<Committee> {
    dbs.2
        .read()
        .await
        .get(&commonware_utils::sequence::U64::new(epoch))
        .await
        .expect("committee row read")
}

/// Builds a child header that reuses the parent's commitments.
fn unexecuted_child_header(
    parent: &TestBlock,
    consensus_context: &SimplexContext<sha256::Digest, ed25519::PublicKey>,
) -> Header<sha256::Digest, sha256::Digest, ed25519::PublicKey, TestPayload> {
    Header {
        context: consensus_context.clone(),
        parent: *parent.seal(),
        height: 1,
        timestamp: 1,
        state_root: parent.header.state_root,
        state_range: parent.header.state_range.clone(),
        transactions_root: parent.header.transactions_root,
        transactions_range: parent.header.transactions_range.clone(),
        committee_root: parent.header.committee_root,
        committee_range: parent.header.committee_range.clone(),
        payload: None,
    }
}

#[test]
fn committee_reducer_seeds_genesis_rows_and_materializes_final_carry_forward() {
    deterministic::Runner::default().start(|context| async move {
        assert_eq!(BLOCKS_PER_EPOCH, 1024);
        let sender = ed25519::PrivateKey::from_seed(101);
        let initial = Committee::new(Set::from_iter_dedup([sender.public_key()])).unwrap();
        let harness =
            reducer_harness(&context, initial.clone(), initial.members().clone(), sender).await;

        let (entering, selected) = execute_committee_block(&harness, 1, Vec::new())
            .await
            .expect("first reducer block");
        assert_eq!(entering, initial);
        assert_eq!(selected, initial);
        assert_eq!(
            exact_committee_row(&harness.dbs, 0).await,
            Some(initial.clone())
        );
        assert_eq!(
            exact_committee_row(&harness.dbs, 1).await,
            Some(initial.clone())
        );
        assert_eq!(exact_committee_row(&harness.dbs, 2).await, None);

        // Jump directly to the final block. With no E+2 row, the reducer must
        // materialize the value DKG read by fallback from E+1.
        let (entering, selected) =
            execute_committee_block(&harness, BLOCKS_PER_EPOCH - 1, Vec::new())
                .await
                .expect("final reducer block");
        assert_eq!(entering, initial);
        assert_eq!(selected, initial);
        assert_eq!(exact_committee_row(&harness.dbs, 2).await, Some(initial));
    });
}

#[test]
fn committee_reducer_composes_ordered_idempotent_mutations_across_blocks() {
    deterministic::Runner::default().start(|context| async move {
        let sender = ed25519::PrivateKey::from_seed(111);
        let b = ed25519::PrivateKey::from_seed(112).public_key();
        let c = ed25519::PrivateKey::from_seed(113).public_key();
        let initial = Committee::new(Set::from_iter_dedup([sender.public_key()])).unwrap();
        let eligible = Set::from_iter_dedup([sender.public_key(), b.clone(), c.clone()]);
        let harness = reducer_harness(&context, initial.clone(), eligible, sender).await;

        let target = Epoch::new(2);
        let first = vec![
            committee_transaction(&harness.sender, target, b.clone(), true, 0),
            committee_transaction(&harness.sender, target, b.clone(), true, 1),
            committee_transaction(&harness.sender, target, c.clone(), true, 2),
            committee_transaction(&harness.sender, target, b.clone(), false, 3),
            committee_transaction(&harness.sender, target, b.clone(), false, 4),
        ];
        let (entering, selected) = execute_committee_block(&harness, 1, first)
            .await
            .expect("first committee mutation block");
        assert_eq!(entering, initial);
        assert_eq!(
            selected.members(),
            &Set::from_iter_dedup([harness.sender.public_key(), c.clone()])
        );

        let second = vec![
            committee_transaction(&harness.sender, target, b.clone(), true, 5),
            committee_transaction(&harness.sender, target, c.clone(), false, 6),
            committee_transaction(&harness.sender, target, c, false, 7),
        ];
        let (entering, selected) = execute_committee_block(&harness, 2, second)
            .await
            .expect("second committee mutation block");
        let expected =
            Committee::new(Set::from_iter_dedup([harness.sender.public_key(), b])).unwrap();
        assert_eq!(entering, initial);
        assert_eq!(selected, expected);
        assert_eq!(exact_committee_row(&harness.dbs, 2).await, Some(expected));
    });
}

#[test]
fn committee_reducer_rejects_ineligible_wrong_epoch_empty_and_final_mutations() {
    deterministic::Runner::default().start(|context| async move {
        let sender = ed25519::PrivateKey::from_seed(121);
        let eligible_peer = ed25519::PrivateKey::from_seed(122).public_key();
        let ineligible_peer = ed25519::PrivateKey::from_seed(123).public_key();
        let initial = Committee::new(Set::from_iter_dedup([sender.public_key()])).unwrap();
        let harness = reducer_harness(
            &context,
            initial,
            Set::from_iter_dedup([sender.public_key(), eligible_peer.clone()]),
            sender,
        )
        .await;

        let invalid = [
            (
                1,
                committee_transaction(&harness.sender, Epoch::new(2), ineligible_peer, true, 0),
            ),
            (
                1,
                committee_transaction(
                    &harness.sender,
                    Epoch::new(3),
                    eligible_peer.clone(),
                    true,
                    0,
                ),
            ),
            (
                1,
                committee_transaction(
                    &harness.sender,
                    Epoch::new(2),
                    harness.sender.public_key(),
                    false,
                    0,
                ),
            ),
            (
                BLOCKS_PER_EPOCH - 1,
                committee_transaction(&harness.sender, Epoch::new(2), eligible_peer, true, 0),
            ),
        ];
        for (height, transaction) in invalid {
            assert!(
                execute_committee_block(&harness, height, vec![transaction])
                    .await
                    .is_err()
            );
        }
        assert_eq!(exact_committee_row(&harness.dbs, 2).await, None);
    });
}

#[test]
fn committee_reducer_rejects_growth_past_maximum_size() {
    deterministic::Runner::default().start(|context| async move {
        let sender = ed25519::PrivateKey::from_seed(131);
        let members = Set::from_iter_dedup(
            (0..MAX_COMMITTEE_SIZE)
                .map(|index| ed25519::PrivateKey::from_seed(1_000 + index as u64).public_key()),
        );
        let initial = Committee::new(members.clone()).expect("maximum-size committee");
        let extra = ed25519::PrivateKey::from_seed(2_000).public_key();
        let eligible = Set::from_iter_dedup(members.iter().cloned().chain([extra.clone()]));
        let harness = reducer_harness(&context, initial, eligible, sender).await;
        let transaction = committee_transaction(&harness.sender, Epoch::new(2), extra, true, 0);

        assert!(
            execute_committee_block(&harness, 1, vec![transaction])
                .await
                .is_err()
        );
        assert_eq!(exact_committee_row(&harness.dbs, 2).await, None);
    });
}

#[test]
fn verify_rejects_invalid_body() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent,
            leader,
            sender,
            recipient,
            ..
        } = verify_harness(&context).await;

        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };
        let header = unexecuted_child_header(&parent, &consensus_context);
        let block = Block::<sha256::Digest, _, sha256::Sha256, _>::new(
            header,
            vec![
                transfer(&sender, &recipient, 1),
                transfer(&sender, &recipient, 2),
            ],
        )
        .seal(&mut sha256::Sha256::default());

        let result = app
            .verify_child(
                (context.child("verify"), consensus_context),
                Arc::new(block),
                std::future::ready(Some(Arc::new(parent))),
                dbs.new_batches().await,
            )
            .await;

        assert!(result.is_none());
    });
}

#[test]
fn verify_rejects_missing_parent() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent,
            leader,
            sender,
            recipient,
            ..
        } = verify_harness(&context).await;

        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };
        let header = unexecuted_child_header(&parent, &consensus_context);
        let block = Block::<sha256::Digest, _, sha256::Sha256, _>::new(
            header,
            vec![transfer(&sender, &recipient, 1)],
        )
        .seal(&mut sha256::Sha256::default());

        // Signature verification dispatches before the parent resolves; a
        // parent that never arrives must still reject the block.
        let result = app
            .verify_child(
                (context.child("verify"), consensus_context),
                Arc::new(block),
                std::future::ready(None),
                dbs.new_batches().await,
            )
            .await;

        assert!(result.is_none());
    });
}

#[test]
fn propose_drops_inapplicable_and_refills() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent,
            leader,
            sender,
            alt_sender,
            recipient,
            ..
        } = verify_harness(&context).await;

        context.sleep(Duration::from_millis(10)).await;

        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };

        // Both selected transfers consume the same nonce: proposing keeps the
        // first, drops the duplicate, and tops the block up from the mempool
        // toward the proposal budget. The proposed block is the applicable
        // subset plus the top-up.
        let keep = transfer(&sender, &recipient, 1);
        let duplicate = transfer(&sender, &recipient, 2);
        let refill = transfer(&alt_sender, &recipient, 3);
        let mut input =
            StaticTransactionSource::new(vec![vec![keep.clone(), duplicate], vec![refill.clone()]]);
        let proposed = app
            .propose_child(
                (context.child("propose"), consensus_context.clone()),
                Arc::new(parent.clone()),
                dbs.new_batches().await,
                None,
                &mut input,
            )
            .await
            .expect("best-effort proposal must succeed");
        assert_eq!(
            body_digests(&proposed.block),
            vec![*keep.message_digest(), *refill.message_digest()]
        );

        // The surviving subset re-executes cleanly under all-or-nothing
        // verification.
        let accepted = app
            .verify_child(
                (context.child("verify"), consensus_context),
                Arc::new(proposed.block.clone()),
                std::future::ready(Some(Arc::new(parent))),
                dbs.new_batches().await,
            )
            .await;
        assert!(accepted.is_some());
    });
}

#[test]
fn verify_accepts_proposed_child_and_rejects_stale_timestamp() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent,
            leader,
            ..
        } = verify_harness(&context).await;

        // Advance past the genesis timestamp so the proposal's clock-derived
        // timestamp is strictly greater than the parent's.
        context.sleep(Duration::from_millis(10)).await;

        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };
        let mut input = StaticTransactionSource::new(Vec::new());
        let proposed = app
            .propose_child(
                (context.child("propose"), consensus_context.clone()),
                Arc::new(parent.clone()),
                dbs.new_batches().await,
                None,
                &mut input,
            )
            .await
            .expect("empty proposal must succeed");

        // The freshly proposed child verifies against the same parent.
        let accepted = app
            .verify_child(
                (context.child("verify"), consensus_context.clone()),
                Arc::new(proposed.block.clone()),
                std::future::ready(Some(Arc::new(parent.clone()))),
                dbs.new_batches().await,
            )
            .await;
        assert!(accepted.is_some());

        // The identical block with its timestamp rewound to the parent's is
        // rejected by the timestamp check alone.
        let Block { mut header, body } = proposed.block.into_inner();
        assert!(
            body.is_empty(),
            "stale block must mirror the empty proposal"
        );
        header.timestamp = parent.header.timestamp;
        let stale = Block::<sha256::Digest, _, sha256::Sha256, _>::new(header, Vec::new())
            .seal(&mut sha256::Sha256::default());
        let rejected = app
            .verify_child(
                (context.child("verify_stale"), consensus_context),
                Arc::new(stale),
                std::future::ready(Some(Arc::new(parent))),
                dbs.new_batches().await,
            )
            .await;
        assert!(rejected.is_none());
    });
}

#[test]
fn final_epoch_info_mismatches_are_rejected_by_verify_and_certified_replay() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            app,
            dbs,
            parent,
            leader,
            recipient,
            ..
        } = verify_harness(&context).await;

        // Re-seal the otherwise valid genesis-backed parent at the penultimate
        // height so the next proposal is E's final block. No intermediate
        // state transitions are needed because the reducer is height-indexed.
        let Block {
            mut header,
            body: _,
        } = parent.into_inner();
        header.height = BLOCKS_PER_EPOCH - 2;
        let parent = Block::<sha256::Digest, _, sha256::Sha256, _>::new(header, Vec::new())
            .seal(&mut sha256::Sha256::default());
        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };
        let members = Set::from_iter_dedup([leader.public_key()]);
        let mut valid_info = test_genesis_info(members.clone());
        valid_info.epoch = Epoch::new(1);
        valid_info.players = members.clone();
        valid_info.next_players = members;

        context.sleep(Duration::from_millis(10)).await;
        let mut proposer = app.clone();
        let mut input = StaticTransactionSource::new(Vec::new());
        let proposed = proposer
            .propose_child(
                (context.child("propose_final"), consensus_context.clone()),
                Arc::new(parent.clone()),
                dbs.new_batches().await,
                Some(TestPayload::EpochInfo(valid_info.clone())),
                &mut input,
            )
            .await
            .expect("matching final epoch info");
        let valid_block = proposed.block.clone();
        drop(proposed);

        let mut verifier = app.clone();
        assert!(
            verifier
                .verify_child(
                    (
                        context.child("verify_valid_final"),
                        consensus_context.clone()
                    ),
                    Arc::new(valid_block.clone()),
                    std::future::ready(Some(Arc::new(parent.clone()))),
                    dbs.new_batches().await,
                )
                .await
                .is_some()
        );

        let other = Set::from_iter_dedup([recipient.public_key()]);
        let mut wrong_epoch = valid_info.clone();
        wrong_epoch.epoch = Epoch::zero();
        let mut wrong_players = valid_info.clone();
        wrong_players.players = other.clone();
        let mut wrong_next_players = valid_info;
        wrong_next_players.next_players = other;

        for (name, info) in [
            ("epoch", wrong_epoch),
            ("players", wrong_players),
            ("next_players", wrong_next_players),
        ] {
            let Block {
                mut header,
                body: _,
            } = valid_block.clone().into_inner();
            header.payload = Some(TestPayload::EpochInfo(info));
            let invalid = Block::<sha256::Digest, _, sha256::Sha256, _>::new(header, Vec::new())
                .seal(&mut sha256::Sha256::default());

            let mut verifier = app.clone();
            assert!(
                verifier
                    .verify_child(
                        (
                            context.child(name).child("verify_wrong"),
                            consensus_context.clone(),
                        ),
                        Arc::new(invalid.clone()),
                        std::future::ready(Some(Arc::new(parent.clone()))),
                        dbs.new_batches().await,
                    )
                    .await
                    .is_none(),
                "verify accepted mismatched {name}"
            );

            let mut replay = app.clone();
            let batches = dbs.new_batches().await;
            let replayed = AssertUnwindSafe(replay.apply_certified(
                (
                    context.child(name).child("replay_wrong"),
                    consensus_context.clone(),
                ),
                &invalid,
                batches,
            ))
            .catch_unwind()
            .await;
            assert!(
                replayed.is_err(),
                "certified replay accepted mismatched {name}"
            );
        }
    });
}

#[test]
fn parent_inactivity_floor_skips_the_parent_commit() {
    let leader = ed25519::PrivateKey::from_seed(7);
    let recipient = ed25519::PrivateKey::from_seed(8);
    let genesis_target = TransactionHistoryTarget {
        root: sha256::Digest::EMPTY,
        leaf_count: commonware_storage::mmr::Location::new(1),
    };
    let mut header = genesis_block::<sha256::Digest, _, sha256::Sha256, _>(
        &mut sha256::Sha256::default(),
        leader.public_key(),
        0,
        empty_state_target(),
        genesis_target,
        empty_committee_target(),
        TestPayload::EpochInfo(test_genesis_info(Set::from_iter_dedup([
            leader.public_key()
        ]))),
    )
    .into_inner()
    .header;
    header.transactions_range = non_empty_range!(5, 10);

    let to = recipient.public_key();
    let parent = Block::<sha256::Digest, _, sha256::Sha256, _>::new(
        header,
        (0..3)
            .map(|nonce| {
                Transaction::new(
                    TransactionPublicKey::ed25519(leader.public_key()),
                    TransactionPublicKey::ed25519(to.clone()),
                    NonZeroU64::new(nonce + 1).expect("test value should be non-zero"),
                    nonce,
                )
                .seal_and_sign(
                    &leader,
                    constantinople_primitives::TRANSACTION_NAMESPACE,
                    &mut sha256::Sha256::default(),
                )
            })
            .collect(),
    )
    .seal(&mut sha256::Sha256::default());

    assert_eq!(
        parent_transactions_inactivity_floor(&parent),
        commonware_storage::mmr::Location::new(6)
    );
}

#[test]
fn genesis_block_uses_the_initialized_transaction_target() {
    let leader = ed25519::PrivateKey::from_seed(11).public_key();
    let target = TransactionHistoryTarget {
        root: sha256::Sha256::hash(&[b"genesis"]),
        leaf_count: commonware_storage::mmr::Location::new(1),
    };

    let block = genesis_block::<sha256::Digest, _, sha256::Sha256, _>(
        &mut sha256::Sha256::default(),
        leader.clone(),
        0,
        empty_state_target(),
        target.clone(),
        empty_committee_target(),
        TestPayload::EpochInfo(test_genesis_info(Set::from_iter_dedup([leader.clone()]))),
    );

    assert_eq!(block.header.transactions_root, target.root);
    assert_eq!(block.header.transactions_range, non_empty_range!(0, 1));
}

/// Digests of a sealed block's body transactions.
fn body_digests(block: &TestBlock) -> Vec<sha256::Digest> {
    block
        .body
        .iter()
        .map(|tx| {
            *tx.get()
                .expect("test bodies are materialized")
                .message_digest()
        })
        .collect()
}

/// Wraps a static source with a virtual-time delay so a test can control how
/// much of the build budget each mempool round trip consumes.
struct DelayedSource {
    context: deterministic::Context,
    delay: Duration,
    inner: TestSource,
}

// Required by `TransactionSource`'s `Reporter: Clone` supertrait; never
// invoked in these tests.
impl Clone for DelayedSource {
    fn clone(&self) -> Self {
        Self {
            context: self.context.child("clone"),
            delay: self.delay,
            inner: self.inner.clone(),
        }
    }
}

impl constantinople_mempool::TransactionSource<sha256::Digest, ed25519::PublicKey, sha256::Sha256>
    for DelayedSource
{
    async fn propose(
        &mut self,
        parent: &Header<sha256::Digest, sha256::Digest, ed25519::PublicKey>,
        round: Round,
        filled: usize,
    ) -> Vec<constantinople_primitives::VerifiedTransaction<sha256::Sha256>> {
        self.context.sleep(self.delay).await;
        self.inner.propose(parent, round, filled).await
    }
}

impl commonware_consensus::Reporter for DelayedSource {
    type Activity = commonware_consensus::marshal::Update<
        SealedBlock<sha256::Digest, ed25519::PublicKey, sha256::Sha256>,
    >;

    fn report(&mut self, activity: Self::Activity) -> commonware_actor::Feedback {
        self.inner.report(activity)
    }
}

#[test]
fn build_timeout_bounds_refill_rounds() {
    deterministic::Runner::default().start(|context| async move {
        let harness = verify_harness(&context).await;
        let seed_keep = transfer(&harness.sender, &harness.recipient, 1);
        let seed_dup = transfer(&harness.sender, &harness.recipient, 2);
        let refill_one = transfer(&harness.alt_sender, &harness.recipient, 3);
        let never_pulled = transfer(&harness.recipient, &harness.sender, 4);

        // Each mempool round trip burns 60ms of virtual time — past the 50ms
        // build deadline after one refill.
        let slow = |batches| DelayedSource {
            context: context.child("slow_clock"),
            delay: Duration::from_millis(60),
            inner: StaticTransactionSource::new(batches),
        };
        let mut app: Application<
            deterministic::Context,
            sha256::Sha256,
            sha256::Digest,
            threshold::Scheme<ed25519::PublicKey, MinSig>,
            ed25519::PublicKey,
            DelayedSource,
            TestPayload,
            Sequential,
        > = Application::new(
            context.child("deadline_app"),
            Sequential,
            harness.leader.public_key(),
            sha256::Digest::EMPTY,
            TEST_TX_NS,
            PublicKeyCache::new(context.child("deadline_pkc"), NZUsize!(64)),
            harness.state_target.clone(),
            harness.transaction_target.clone(),
            harness.committee_target.clone(),
            test_genesis_info(Set::from_iter_dedup([harness.leader.public_key()])),
            NonZeroU64::new(BLOCKS_PER_EPOCH).expect("epoch length is non-zero"),
            Committee::new(Set::from_iter_dedup([harness.leader.public_key()]))
                .expect("deadline genesis committee"),
            harness.eligible_committee_members.clone(),
            None,
        );

        context.sleep(Duration::from_millis(10)).await;

        // The seed pull happens before the build deadline starts; the first
        // refill (delayed 60ms) lands past the deadline, so a second refill
        // is never requested even though headroom and candidates remain.
        let mut input = slow(vec![
            vec![seed_keep.clone(), seed_dup],
            vec![refill_one.clone()],
            vec![never_pulled],
        ]);
        let ctx1 = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: harness.leader.public_key(),
            parent: (View::zero(), *harness.parent.seal()),
        };
        let proposed = app
            .propose_child(
                (context.child("propose_deadline"), ctx1),
                Arc::new(harness.parent.clone()),
                harness.dbs.new_batches().await,
                None,
                &mut input,
            )
            .await
            .expect("proposal must succeed");

        assert_eq!(
            body_digests(&proposed.block),
            vec![*seed_keep.message_digest(), *refill_one.message_digest()],
            "the deadline must stop the loop after the first refill"
        );
    });
}
