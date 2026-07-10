use super::{
    Application, Databases, SpeculationConfig, StateSyncTarget, TransactionHistoryTarget,
    genesis_block, history::parent_transactions_inactivity_floor,
};
use commonware_consensus::{
    simplex::{
        scheme::bls12381_threshold::standard as threshold, types::Context as SimplexContext,
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    Digest as _, Hasher as _, Signer as _, bls12381::primitives::variant::MinSig, ed25519, sha256,
};
use commonware_glue::stateful::db::{DatabaseSet as _, Merkleized as _, Unmerkleized as _};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{
    journal::contiguous::{
        fixed::Config as FixedJournalConfig, variable::Config as VariableJournalConfig,
    },
    merkle::{full::Config as MmrConfig, mmr},
    qmdb::{any::FixedConfig, batch_chain::Bounds, keyless::fixed as keyless_fixed},
    translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range};
use constantinople_mempool::mocks::StaticTransactionSource;
use constantinople_primitives::{
    Account, AccountKey, Block, Header, Nonce, PublicKeyCache, Sealable, SealedBlock,
    SignedTransaction, Transaction, TransactionPublicKey,
};
use std::{future::ready, num::NonZeroU64, sync::Arc, time::Duration};

type TestApp = Application<
    deterministic::Context,
    sha256::Sha256,
    sha256::Digest,
    threshold::Scheme<ed25519::PublicKey, MinSig>,
    ed25519::PublicKey,
    StaticTransactionSource<sha256::Digest, ed25519::PublicKey, sha256::Sha256>,
    (),
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

type TestBlock = SealedBlock<sha256::Digest, ed25519::PublicKey, sha256::Sha256>;

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
}

async fn verify_harness(context: &deterministic::Context) -> VerifyHarness {
    let cache = CacheRef::from_pooler(context, NZU16!(16), NZUsize!(4096));
    let dbs = TestDbs::init(
        context.child("dbs"),
        (
            state_config(cache.clone()),
            transaction_config(cache.clone()),
        ),
    )
    .await;

    let leader = ed25519::PrivateKey::from_seed(21);
    let sender = ed25519::PrivateKey::from_seed(22);
    let recipient = ed25519::PrivateKey::from_seed(23);
    let alt_sender = ed25519::PrivateKey::from_seed(24);

    let (mut state_batch, transaction_batch) = dbs.new_batches().await;
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
    let state_target = StateSyncTarget::new(state.root(), sync_range_from_bounds(state.bounds()));
    let transaction_target = TransactionHistoryTarget::new(
        transactions.root(),
        mmr::Location::new(transactions.bounds().total_size),
    );
    dbs.finalize((state, transactions)).await;

    let parent = genesis_block::<sha256::Digest, _, sha256::Sha256>(
        &mut sha256::Sha256::default(),
        leader.public_key(),
        0,
        state_target.clone(),
        transaction_target.clone(),
    );
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
            None,
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
    }
}

type TestSource = StaticTransactionSource<sha256::Digest, ed25519::PublicKey, sha256::Sha256>;

/// Builds an additional application over the harness's databases, optionally
/// with an always-leader speculator fed by `speculative_batches`.
fn make_app(
    context: &deterministic::Context,
    harness: &VerifyHarness,
    label: &'static str,
    speculative_batches: Option<Vec<Vec<SignedTransaction<sha256::Sha256>>>>,
) -> TestApp {
    let speculation = speculative_batches.map(|batches| SpeculationConfig {
        input: StaticTransactionSource::new(batches),
        is_leader: Arc::new(|_| true),
        max_reuse_views: 8,
    });
    TestApp::new(
        context.child(label),
        Sequential,
        harness.leader.public_key(),
        sha256::Digest::EMPTY,
        TEST_TX_NS,
        PublicKeyCache::new(context.child(label).child("public_key_cache"), NZUsize!(64)),
        harness.state_target.clone(),
        harness.transaction_target.clone(),
        None,
        speculation,
    )
}

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

/// Builds a child header that reuses the parent's commitments.
fn unexecuted_child_header(
    parent: &TestBlock,
    consensus_context: &SimplexContext<sha256::Digest, ed25519::PublicKey>,
) -> Header<sha256::Digest, sha256::Digest, ed25519::PublicKey> {
    Header {
        context: consensus_context.clone(),
        parent: *parent.seal(),
        height: 1,
        timestamp: 1,
        state_root: parent.header.state_root,
        state_range: parent.header.state_range.clone(),
        transactions_root: parent.header.transactions_root,
        transactions_range: parent.header.transactions_range.clone(),
    }
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
        let block = Block::<sha256::Digest, _, sha256::Sha256>::new(
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
                block,
                std::future::ready(Some(parent)),
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
        let block = Block::<sha256::Digest, _, sha256::Sha256>::new(
            header,
            vec![transfer(&sender, &recipient, 1)],
        )
        .seal(&mut sha256::Sha256::default());

        // Signature verification dispatches before the parent resolves; a
        // parent that never arrives must still reject the block.
        let result = app
            .verify_child(
                (context.child("verify"), consensus_context),
                block,
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
        // first, drops the duplicate, and refills the dropped bytes from the
        // mempool. The proposed block is the applicable subset.
        let keep = transfer(&sender, &recipient, 1);
        let duplicate = transfer(&sender, &recipient, 2);
        let refill = transfer(&alt_sender, &recipient, 3);
        let mut input =
            StaticTransactionSource::new(vec![vec![keep.clone(), duplicate], vec![refill.clone()]]);
        let proposed = app
            .propose_child(
                (context.child("propose"), consensus_context.clone()),
                parent.clone(),
                dbs.new_batches().await,
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
                proposed.block.clone(),
                ready(Some(parent)),
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
                parent.clone(),
                dbs.new_batches().await,
                &mut input,
            )
            .await
            .expect("empty proposal must succeed");

        // The freshly proposed child verifies against the same parent.
        let accepted = app
            .verify_child(
                (context.child("verify"), consensus_context.clone()),
                proposed.block.clone(),
                std::future::ready(Some(parent.clone())),
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
        let stale = Block::<sha256::Digest, _, sha256::Sha256>::new(header, Vec::new())
            .seal(&mut sha256::Sha256::default());
        let rejected = app
            .verify_child(
                (context.child("verify_stale"), consensus_context),
                stale,
                std::future::ready(Some(parent)),
                dbs.new_batches().await,
            )
            .await;
        assert!(rejected.is_none());
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
    let mut header = genesis_block::<sha256::Digest, _, sha256::Sha256>(
        &mut sha256::Sha256::default(),
        leader.public_key(),
        0,
        empty_state_target(),
        genesis_target,
    )
    .into_inner()
    .header;
    header.transactions_range = non_empty_range!(5, 10);

    let to = recipient.public_key();
    let parent = Block::<sha256::Digest, _, sha256::Sha256>::new(
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
        root: sha256::Sha256::hash(b"genesis"),
        leaf_count: commonware_storage::mmr::Location::new(1),
    };

    let block = genesis_block::<sha256::Digest, _, sha256::Sha256>(
        &mut sha256::Sha256::default(),
        leader,
        0,
        empty_state_target(),
        target.clone(),
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

fn consensus_context(
    view: u64,
    leader: &ed25519::PrivateKey,
    parent_view: u64,
    parent: &TestBlock,
) -> SimplexContext<sha256::Digest, ed25519::PublicKey> {
    SimplexContext {
        round: Round::new(Epoch::zero(), View::new(view)),
        leader: leader.public_key(),
        parent: (View::new(parent_view), *parent.seal()),
    }
}

/// Proposes, then verifies, an empty child of `parent`, returning the sealed
/// block and its merkleized databases. Verifying through `app` triggers that
/// app's speculative pre-build (if configured) on top of the child.
async fn build_and_verify_empty_child(
    context: &deterministic::Context,
    app: &mut TestApp,
    parent: &TestBlock,
    batches: <TestDbs as commonware_glue::stateful::db::DatabaseSet<deterministic::Context>>::Unmerkleized,
    verify_batches: <TestDbs as commonware_glue::stateful::db::DatabaseSet<
        deterministic::Context,
    >>::Unmerkleized,
    view: u64,
    leader: &ed25519::PrivateKey,
) -> (
    TestBlock,
    <TestDbs as commonware_glue::stateful::db::DatabaseSet<deterministic::Context>>::Merkleized,
) {
    let ctx = consensus_context(view, leader, view - 1, parent);
    let mut empty: TestSource = StaticTransactionSource::new(Vec::new());
    let proposed = app
        .propose_child(
            (context.child("propose_child_block"), ctx.clone()),
            parent.clone(),
            batches,
            &mut empty,
        )
        .await
        .expect("empty proposal must succeed");
    let merkleized = app
        .verify_child(
            (context.child("verify_child_block"), ctx),
            proposed.block.clone(),
            ready(Some(parent.clone())),
            verify_batches,
        )
        .await
        .expect("own proposal must verify");
    (proposed.block, merkleized)
}

#[test]
fn speculation_hit_reuses_prebuilt_execution() {
    deterministic::Runner::default().start(|context| async move {
        let harness = verify_harness(&context).await;
        let tx = transfer(&harness.sender, &harness.recipient, 1);
        let mut app = make_app(&context, &harness, "spec_hit", Some(vec![vec![tx.clone()]]));

        context.sleep(Duration::from_millis(10)).await;
        // Verifying block B triggers the pre-build of B's child.
        let (block_b, b_merkleized) = build_and_verify_empty_child(
            &context,
            &mut app,
            &harness.parent,
            harness.dbs.new_batches().await,
            harness.dbs.new_batches().await,
            1,
            &harness.leader,
        )
        .await;
        context.sleep(Duration::from_millis(10)).await;

        // Consensus asks for exactly the speculated parent. The canary batch
        // must stay untouched: the block is the pre-built one.
        let canary = transfer(&harness.alt_sender, &harness.recipient, 7);
        let mut fresh: TestSource = StaticTransactionSource::new(vec![vec![canary]]);
        let ctx2 = consensus_context(2, &harness.leader, 1, &block_b);
        let proposed = app
            .propose_child(
                (context.child("propose_hit"), ctx2.clone()),
                block_b.clone(),
                TestDbs::fork_batches(&b_merkleized),
                &mut fresh,
            )
            .await
            .expect("pre-built proposal must succeed");

        assert_eq!(proposed.block.header.height, 2);
        assert_eq!(body_digests(&proposed.block), vec![*tx.message_digest()]);

        let metrics = context.encode();
        assert!(
            metrics.contains("speculation_prebuilds_total 1"),
            "{metrics}"
        );
        assert!(metrics.contains("speculation_hits_total 1"), "{metrics}");

        // An independent application accepts the pre-built block, proving the
        // speculative execution's commitments and floors are the real ones.
        let mut verifier = make_app(&context, &harness, "spec_hit_verifier", None);
        let accepted = verifier
            .verify_child(
                (context.child("verify_hit"), ctx2),
                proposed.block.clone(),
                ready(Some(block_b)),
                TestDbs::fork_batches(&b_merkleized),
            )
            .await;
        assert!(accepted.is_some());
    });
}

#[test]
fn speculation_recovers_on_unexpected_parent() {
    deterministic::Runner::default().start(|context| async move {
        let harness = verify_harness(&context).await;
        let tx1 = transfer(&harness.sender, &harness.recipient, 1);
        let tx2 = transfer(&harness.alt_sender, &harness.recipient, 2);
        let mut app = make_app(
            &context,
            &harness,
            "spec_recover",
            Some(vec![vec![tx1.clone(), tx2.clone()]]),
        );

        context.sleep(Duration::from_millis(10)).await;
        // The pre-build runs on top of block B...
        let (_block_b, _b_merkleized) = build_and_verify_empty_child(
            &context,
            &mut app,
            &harness.parent,
            harness.dbs.new_batches().await,
            harness.dbs.new_batches().await,
            1,
            &harness.leader,
        )
        .await;
        context.sleep(Duration::from_millis(10)).await;

        // ...but consensus asks to propose on the genesis parent instead
        // (e.g. B's view nullified). The consumed transactions must carry
        // over: the fresh input is empty, so a non-empty body proves reuse.
        let mut fresh: TestSource = StaticTransactionSource::new(Vec::new());
        let ctx2 = consensus_context(2, &harness.leader, 0, &harness.parent);
        let proposed = app
            .propose_child(
                (context.child("propose_recover"), ctx2.clone()),
                harness.parent.clone(),
                harness.dbs.new_batches().await,
                &mut fresh,
            )
            .await
            .expect("reused proposal must succeed");

        assert_eq!(proposed.block.header.height, 1);
        assert_eq!(
            body_digests(&proposed.block),
            vec![*tx1.message_digest(), *tx2.message_digest()]
        );

        let metrics = context.encode();
        assert!(metrics.contains("speculation_reuses_total 1"), "{metrics}");
        assert!(metrics.contains("speculation_hits_total 0"), "{metrics}");

        // The rebuilt block is a valid child of the unexpected parent.
        let mut verifier = make_app(&context, &harness, "spec_recover_verifier", None);
        let accepted = verifier
            .verify_child(
                (context.child("verify_recover"), ctx2),
                proposed.block.clone(),
                ready(Some(harness.parent.clone())),
                harness.dbs.new_batches().await,
            )
            .await;
        assert!(accepted.is_some());
    });
}

#[test]
fn speculation_reuse_filters_transactions_already_in_parent() {
    deterministic::Runner::default().start(|context| async move {
        let harness = verify_harness(&context).await;
        let tx1 = transfer(&harness.sender, &harness.recipient, 1);
        let tx2 = transfer(&harness.alt_sender, &harness.recipient, 2);
        let mut app = make_app(
            &context,
            &harness,
            "spec_filter",
            Some(vec![vec![tx1.clone(), tx2.clone()]]),
        );

        context.sleep(Duration::from_millis(10)).await;
        // Pre-build on top of the empty block B.
        let (_block_b, _b_merkleized) = build_and_verify_empty_child(
            &context,
            &mut app,
            &harness.parent,
            harness.dbs.new_batches().await,
            harness.dbs.new_batches().await,
            1,
            &harness.leader,
        )
        .await;
        context.sleep(Duration::from_millis(10)).await;

        // A sibling B' that already includes tx1 certifies instead of B.
        let mut sibling_app = make_app(&context, &harness, "spec_filter_builder", None);
        let mut sibling_input: TestSource = StaticTransactionSource::new(vec![vec![tx1.clone()]]);
        let ctx1 = consensus_context(1, &harness.leader, 0, &harness.parent);
        let sibling = sibling_app
            .propose_child(
                (context.child("propose_sibling"), ctx1),
                harness.parent.clone(),
                harness.dbs.new_batches().await,
                &mut sibling_input,
            )
            .await
            .expect("sibling proposal must succeed");
        context.sleep(Duration::from_millis(10)).await;

        // Proposing on B' reuses the speculative selection minus tx1: keeping
        // it would replay a nonce and reject the whole block.
        let mut fresh: TestSource = StaticTransactionSource::new(Vec::new());
        let ctx2 = consensus_context(2, &harness.leader, 1, &sibling.block);
        let proposed = app
            .propose_child(
                (context.child("propose_filtered"), ctx2.clone()),
                sibling.block.clone(),
                TestDbs::fork_batches(&sibling.merkleized),
                &mut fresh,
            )
            .await
            .expect("filtered reuse must succeed");

        assert_eq!(proposed.block.header.height, 2);
        assert_eq!(body_digests(&proposed.block), vec![*tx2.message_digest()]);

        // And it verifies as a child of B'.
        let mut verifier = make_app(&context, &harness, "spec_filter_verifier", None);
        let accepted = verifier
            .verify_child(
                (context.child("verify_filtered"), ctx2),
                proposed.block.clone(),
                ready(Some(sibling.block.clone())),
                TestDbs::fork_batches(&sibling.merkleized),
            )
            .await;
        assert!(accepted.is_some());
    });
}

#[test]
fn speculation_empty_selection_falls_back_to_fresh_input() {
    deterministic::Runner::default().start(|context| async move {
        let harness = verify_harness(&context).await;
        // The speculative source has nothing to select.
        let mut app = make_app(&context, &harness, "spec_empty", Some(Vec::new()));

        context.sleep(Duration::from_millis(10)).await;
        let (block_b, b_merkleized) = build_and_verify_empty_child(
            &context,
            &mut app,
            &harness.parent,
            harness.dbs.new_batches().await,
            harness.dbs.new_batches().await,
            1,
            &harness.leader,
        )
        .await;
        context.sleep(Duration::from_millis(10)).await;

        // With no pre-build available, propose selects from the live mempool.
        let tx = transfer(&harness.sender, &harness.recipient, 3);
        let mut fresh: TestSource = StaticTransactionSource::new(vec![vec![tx.clone()]]);
        let ctx2 = consensus_context(2, &harness.leader, 1, &block_b);
        let proposed = app
            .propose_child(
                (context.child("propose_fallback"), ctx2),
                block_b,
                TestDbs::fork_batches(&b_merkleized),
                &mut fresh,
            )
            .await
            .expect("fallback proposal must succeed");

        assert_eq!(body_digests(&proposed.block), vec![*tx.message_digest()]);

        let metrics = context.encode();
        assert!(
            metrics.contains("speculation_prebuilds_total 1"),
            "{metrics}"
        );
        assert!(metrics.contains("speculation_hits_total 0"), "{metrics}");
        assert!(metrics.contains("speculation_reuses_total 0"), "{metrics}");
    });
}

#[test]
fn speculation_discards_replaced_prebuild() {
    deterministic::Runner::default().start(|context| async move {
        let harness = verify_harness(&context).await;
        let tx1 = transfer(&harness.sender, &harness.recipient, 1);
        let tx2 = transfer(&harness.alt_sender, &harness.recipient, 2);
        let mut app = make_app(
            &context,
            &harness,
            "spec_discard",
            Some(vec![vec![tx1], vec![tx2.clone()]]),
        );

        context.sleep(Duration::from_millis(10)).await;
        // Verify B: first pre-build (tx1) targets B's child.
        let (block_b, b_merkleized) = build_and_verify_empty_child(
            &context,
            &mut app,
            &harness.parent,
            harness.dbs.new_batches().await,
            harness.dbs.new_batches().await,
            1,
            &harness.leader,
        )
        .await;
        context.sleep(Duration::from_millis(10)).await;

        // C (B's empty child) is built by another proposer: proposing it
        // through the speculating app would consume the first pre-build as a
        // legitimate hit. Verifying C through the speculating app makes the
        // second pre-build (tx2) replace the first, which is then discarded.
        let mut builder = make_app(&context, &harness, "spec_discard_builder", None);
        let mut empty: TestSource = StaticTransactionSource::new(Vec::new());
        let ctx2 = consensus_context(2, &harness.leader, 1, &block_b);
        let block_c = builder
            .propose_child(
                (context.child("propose_c"), ctx2.clone()),
                block_b.clone(),
                TestDbs::fork_batches(&b_merkleized),
                &mut empty,
            )
            .await
            .expect("empty child of B must succeed")
            .block;
        let c_merkleized = app
            .verify_child(
                (context.child("verify_c"), ctx2),
                block_c.clone(),
                ready(Some(block_b)),
                TestDbs::fork_batches(&b_merkleized),
            )
            .await
            .expect("C must verify");
        context.sleep(Duration::from_millis(10)).await;

        let mut fresh: TestSource = StaticTransactionSource::new(Vec::new());
        let ctx3 = consensus_context(3, &harness.leader, 2, &block_c);
        let proposed = app
            .propose_child(
                (context.child("propose_replaced"), ctx3),
                block_c,
                TestDbs::fork_batches(&c_merkleized),
                &mut fresh,
            )
            .await
            .expect("replacement pre-build must serve the proposal");

        assert_eq!(body_digests(&proposed.block), vec![*tx2.message_digest()]);

        let metrics = context.encode();
        assert!(
            metrics.contains("speculation_prebuilds_total 2"),
            "{metrics}"
        );
        assert!(
            metrics.contains("speculation_discards_total 1"),
            "{metrics}"
        );
        assert!(metrics.contains("speculation_hits_total 1"), "{metrics}");
    });
}

#[test]
fn speculation_reuse_drops_transactions_included_upstream() {
    deterministic::Runner::default().start(|context| async move {
        let harness = verify_harness(&context).await;
        let tx1 = transfer(&harness.sender, &harness.recipient, 1);
        let mut app = make_app(
            &context,
            &harness,
            "spec_stale",
            Some(vec![vec![tx1.clone()]]),
        );

        context.sleep(Duration::from_millis(10)).await;
        // Arm a pre-build of [tx1] on top of B (targets height 2).
        let (block_b, b_merkleized) = build_and_verify_empty_child(
            &context,
            &mut app,
            &harness.parent,
            harness.dbs.new_batches().await,
            harness.dbs.new_batches().await,
            1,
            &harness.leader,
        )
        .await;
        context.sleep(Duration::from_millis(10)).await;

        // The chain advances past the pre-build with a block that already
        // includes tx1 (e.g. it was multi-submitted to another leader).
        let mut builder = make_app(&context, &harness, "spec_stale_builder", None);
        let mut c_input: TestSource = StaticTransactionSource::new(vec![vec![tx1.clone()]]);
        let ctx2 = consensus_context(2, &harness.leader, 1, &block_b);
        let proposed_c = builder
            .propose_child(
                (context.child("propose_c"), ctx2),
                block_b.clone(),
                TestDbs::fork_batches(&b_merkleized),
                &mut c_input,
            )
            .await
            .expect("child of B must succeed");
        assert_eq!(body_digests(&proposed_c.block), vec![*tx1.message_digest()]);
        context.sleep(Duration::from_millis(10)).await;

        // Proposing on C reuses the pre-built selection, but execution
        // against C's state drops tx1 (its nonce is already consumed there)
        // and the dropped bytes refill from the live mempool. No structural
        // assumption about C's relationship to B is needed.
        let fresh_tx = transfer(&harness.alt_sender, &harness.recipient, 5);
        let mut fresh: TestSource = StaticTransactionSource::new(vec![vec![fresh_tx.clone()]]);
        let ctx3 = consensus_context(3, &harness.leader, 2, &proposed_c.block);
        let proposed = app
            .propose_child(
                (context.child("propose_reused"), ctx3.clone()),
                proposed_c.block.clone(),
                TestDbs::fork_batches(&proposed_c.merkleized),
                &mut fresh,
            )
            .await
            .expect("reused proposal must succeed");

        assert_eq!(proposed.block.header.height, 3);
        assert_eq!(
            body_digests(&proposed.block),
            vec![*fresh_tx.message_digest()]
        );

        let metrics = context.encode();
        assert!(metrics.contains("speculation_reuses_total 1"), "{metrics}");
        assert!(metrics.contains("speculation_hits_total 0"), "{metrics}");

        // The rebuilt block is a valid child of C.
        let mut verifier = make_app(&context, &harness, "spec_stale_verifier", None);
        let accepted = verifier
            .verify_child(
                (context.child("verify_reused"), ctx3),
                proposed.block.clone(),
                ready(Some(proposed_c.block.clone())),
                TestDbs::fork_batches(&proposed_c.merkleized),
            )
            .await;
        assert!(accepted.is_some());
    });
}

/// Wraps a static source with a virtual-time delay so a test can observe (and
/// cancel around) an in-flight pre-build.
struct DelayedSource {
    context: deterministic::Context,
    delay: Duration,
    inner: TestSource,
}

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
        limit: Option<usize>,
    ) -> Vec<constantinople_primitives::VerifiedTransaction<sha256::Sha256>> {
        self.context.sleep(self.delay).await;
        self.inner.propose(parent, round, limit).await
    }
}

impl commonware_consensus::Reporter for DelayedSource {
    type Activity = commonware_consensus::marshal::Update<TestBlock>;

    fn report(&mut self, activity: Self::Activity) -> commonware_actor::Feedback {
        self.inner.report(activity)
    }
}

#[test]
fn speculation_survives_cancelled_propose() {
    deterministic::Runner::default().start(|context| async move {
        let mut harness = verify_harness(&context).await;
        let tx = transfer(&harness.sender, &harness.recipient, 1);
        let delayed = |delay, batches| DelayedSource {
            context: context.child("delay_clock"),
            delay,
            inner: StaticTransactionSource::new(batches),
        };
        let mut app: Application<
            deterministic::Context,
            sha256::Sha256,
            sha256::Digest,
            threshold::Scheme<ed25519::PublicKey, MinSig>,
            ed25519::PublicKey,
            DelayedSource,
            (),
            Sequential,
        > = Application::new(
            context.child("spec_cancel"),
            Sequential,
            harness.leader.public_key(),
            sha256::Digest::EMPTY,
            TEST_TX_NS,
            PublicKeyCache::new(context.child("spec_cancel_pkc"), NZUsize!(64)),
            harness.state_target.clone(),
            harness.transaction_target.clone(),
            None,
            Some(SpeculationConfig {
                input: delayed(Duration::from_millis(200), vec![vec![tx.clone()]]),
                is_leader: Arc::new(|_| true),
                max_reuse_views: 8,
            }),
        );

        context.sleep(Duration::from_millis(10)).await;
        // Build B with the harness app, then verify it through the
        // speculating app: this arms a pre-build whose selection sleeps.
        let mut empty: TestSource = StaticTransactionSource::new(Vec::new());
        let ctx1 = consensus_context(1, &harness.leader, 0, &harness.parent);
        let proposed_b = harness
            .app
            .propose_child(
                (context.child("propose_b"), ctx1.clone()),
                harness.parent.clone(),
                harness.dbs.new_batches().await,
                &mut empty,
            )
            .await
            .expect("empty proposal must succeed");
        let block_b = proposed_b.block.clone();
        let b_merkleized = app
            .verify_child(
                (context.child("verify_b"), ctx1),
                block_b.clone(),
                ready(Some(harness.parent.clone())),
                harness.dbs.new_batches().await,
            )
            .await
            .expect("B must verify");

        // Consensus requests a proposal but moves on before the pre-build
        // finishes: the propose future is dropped mid-take. The pre-build
        // must survive for the next attempt.
        let ctx2 = consensus_context(2, &harness.leader, 1, &block_b);
        {
            let mut cancelled_input = delayed(Duration::ZERO, Vec::new());
            let fut = app.propose_child(
                (context.child("propose_cancelled"), ctx2.clone()),
                block_b.clone(),
                TestDbs::fork_batches(&b_merkleized),
                &mut cancelled_input,
            );
            futures::pin_mut!(fut);
            assert!(
                futures::poll!(fut.as_mut()).is_pending(),
                "pre-build must still be in flight"
            );
        }

        // Let the pre-build finish, then propose again on the same parent:
        // the restored pre-build serves it.
        context.sleep(Duration::from_millis(300)).await;
        let canary = transfer(&harness.alt_sender, &harness.recipient, 9);
        let mut fresh = delayed(Duration::ZERO, vec![vec![canary]]);
        let proposed = app
            .propose_child(
                (context.child("propose_after_cancel"), ctx2),
                block_b,
                TestDbs::fork_batches(&b_merkleized),
                &mut fresh,
            )
            .await
            .expect("restored pre-build must serve the proposal");

        assert_eq!(body_digests(&proposed.block), vec![*tx.message_digest()]);
        let metrics = context.encode();
        assert!(metrics.contains("speculation_hits_total 1"), "{metrics}");
        assert!(
            metrics.contains("speculation_discards_total 0"),
            "{metrics}"
        );
    });
}

#[test]
fn speculation_discards_prebuild_older_than_reuse_window() {
    deterministic::Runner::default().start(|context| async move {
        let harness = verify_harness(&context).await;
        let tx1 = transfer(&harness.sender, &harness.recipient, 1);
        let mut app = make_app(&context, &harness, "spec_aged", Some(vec![vec![tx1]]));

        context.sleep(Duration::from_millis(10)).await;
        // Arm a pre-build targeting view 2.
        let (_block_b, b_merkleized) = build_and_verify_empty_child(
            &context,
            &mut app,
            &harness.parent,
            harness.dbs.new_batches().await,
            harness.dbs.new_batches().await,
            1,
            &harness.leader,
        )
        .await;
        context.sleep(Duration::from_millis(10)).await;

        // A mismatched-parent request far beyond the reuse window (many
        // nullified views later) must not reuse the selection: at that
        // distance its mempool bookkeeping may already have resolved. The
        // pre-build is discarded and the live mempool serves the proposal.
        let fresh_tx = transfer(&harness.alt_sender, &harness.recipient, 5);
        let mut fresh: TestSource = StaticTransactionSource::new(vec![vec![fresh_tx.clone()]]);
        let ctx_late = consensus_context(50, &harness.leader, 0, &harness.parent);
        let proposed = app
            .propose_child(
                (context.child("propose_late"), ctx_late),
                harness.parent.clone(),
                harness.dbs.new_batches().await,
                &mut fresh,
            )
            .await
            .expect("fresh proposal must succeed");

        assert_eq!(proposed.block.header.height, 1);
        assert_eq!(
            body_digests(&proposed.block),
            vec![*fresh_tx.message_digest()]
        );

        let metrics = context.encode();
        assert!(
            metrics.contains("speculation_discards_total 1"),
            "{metrics}"
        );
        assert!(metrics.contains("speculation_hits_total 0"), "{metrics}");
        assert!(metrics.contains("speculation_reuses_total 0"), "{metrics}");
        drop(b_merkleized);
    });
}

#[test]
fn speculation_hit_survives_any_view_distance() {
    deterministic::Runner::default().start(|context| async move {
        let harness = verify_harness(&context).await;
        let tx1 = transfer(&harness.sender, &harness.recipient, 1);
        let mut app = make_app(
            &context,
            &harness,
            "spec_late_hit",
            Some(vec![vec![tx1.clone()]]),
        );

        context.sleep(Duration::from_millis(10)).await;
        let (block_b, b_merkleized) = build_and_verify_empty_child(
            &context,
            &mut app,
            &harness.parent,
            harness.dbs.new_batches().await,
            harness.dbs.new_batches().await,
            1,
            &harness.leader,
        )
        .await;
        context.sleep(Duration::from_millis(10)).await;

        // The exact parent arriving after many nullified views is still a
        // hit: the chain never finalized past B, so the selection's mempool
        // bookkeeping is still live.
        let mut fresh: TestSource = StaticTransactionSource::new(Vec::new());
        let ctx_late = consensus_context(50, &harness.leader, 1, &block_b);
        let proposed = app
            .propose_child(
                (context.child("propose_late_hit"), ctx_late),
                block_b,
                TestDbs::fork_batches(&b_merkleized),
                &mut fresh,
            )
            .await
            .expect("late hit must succeed");

        assert_eq!(body_digests(&proposed.block), vec![*tx1.message_digest()]);
        let metrics = context.encode();
        assert!(metrics.contains("speculation_hits_total 1"), "{metrics}");
        assert!(
            metrics.contains("speculation_discards_total 0"),
            "{metrics}"
        );
    });
}
