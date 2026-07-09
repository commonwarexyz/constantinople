use super::{
    Application, Databases, StateSyncTarget, TransactionHistoryTarget, genesis_block,
    history::parent_transactions_inactivity_floor,
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
use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range};
use constantinople_mempool::mocks::StaticTransactionSource;
use constantinople_primitives::{
    Block, Header, PublicKeyCache, Sealable, SealedBlock, SignedTransaction, Transaction,
    TransactionPublicKey,
};
use std::{num::NonZeroU64, time::Duration};

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
struct VerifyHarness {
    app: TestApp,
    dbs: TestDbs,
    parent: TestBlock,
    leader: ed25519::PrivateKey,
    sender: ed25519::PrivateKey,
    recipient: ed25519::PrivateKey,
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
    let (state_batch, transaction_batch) = dbs.new_batches().await;
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

    let leader = ed25519::PrivateKey::from_seed(21);
    let sender = ed25519::PrivateKey::from_seed(22);
    let recipient = ed25519::PrivateKey::from_seed(23);
    let app = TestApp::new(
        context.child("app"),
        Sequential,
        leader.public_key(),
        sha256::Digest::EMPTY,
        TEST_TX_NS,
        PublicKeyCache::new(context.child("public_key_cache"), NZUsize!(64)),
        state_target.clone(),
        transaction_target.clone(),
        None,
    );
    let parent = genesis_block::<sha256::Digest, _, sha256::Sha256>(
        &mut sha256::Sha256::default(),
        leader.public_key(),
        0,
        state_target,
        transaction_target,
    );

    VerifyHarness {
        app,
        dbs,
        parent,
        leader,
        sender,
        recipient,
    }
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
