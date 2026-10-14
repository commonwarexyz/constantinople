use super::EngineApplication;
use crate::block::{EngineBlock, EngineCommitment};
use commonware_consensus::CertifiableBlock as _;
use commonware_cryptography::{
    Signer as _, bls12381::primitives::variant::MinSig, ed25519, sha256,
};
use commonware_glue::stateful::{
    Application as StatefulApplication,
    db::{DatabaseSet as _, Merkleized as _, Unmerkleized as _},
};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::contiguous::{
        fixed::Config as FixedJournalConfig, variable::Config as VariableJournalConfig,
    },
    merkle::full::Config as MmrConfig,
    qmdb::{any::FixedConfig, keyless::fixed as keyless_fixed},
    translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range};
use constantinople_application::consensus::{
    Application, Databases, FinalizedHookFn, StateSyncTarget, TransactionHistoryTarget,
};
use constantinople_mempool::mocks::StaticTransactionSource;
use constantinople_primitives::{Account, AccountKey, Nonce, PublicKeyCache};
use std::sync::{Arc, Mutex};

type TestCommitment = EngineCommitment<sha256::Sha256, ed25519::PublicKey>;
type TestBlock = EngineBlock<sha256::Sha256, ed25519::PublicKey>;
type TestHook = FinalizedHookFn<TestCommitment, sha256::Sha256, ed25519::PublicKey>;
type TestApp = EngineApplication<
    deterministic::Context,
    sha256::Sha256,
    ed25519::PublicKey,
    MinSig,
    StaticTransactionSource<TestCommitment, ed25519::PublicKey, sha256::Sha256>,
    (),
    Sequential,
>;
type TestDbs = Databases<deterministic::Context, sha256::Sha256, EightCap, Sequential>;
type TestBatches =
    <TestDbs as commonware_glue::stateful::db::DatabaseSet<deterministic::Context>>::Merkleized;

async fn fixture(context: &deterministic::Context) -> (TestApp, TestDbs, TestBatches, TestBlock) {
    let cache = CacheRef::from_pooler(context, NZU16!(16), NZUsize!(4096));
    let state_config = FixedConfig {
        merkle_config: MmrConfig {
            journal_partition: "hook-state-merkle-journal".into(),
            metadata_partition: "hook-state-merkle-metadata".into(),
            items_per_blob: NZU64!(1024),
            write_buffer: NZUsize!(4096),
            replay_buffer: NZUsize!(4096),
            strategy: Sequential,
            page_cache: cache.clone(),
        },
        journal_config: FixedJournalConfig {
            partition: "hook-state-log".into(),
            items_per_blob: NZU64!(1024),
            page_cache: cache.clone(),
            write_buffer: NZUsize!(4096),
            replay_buffer: NZUsize!(4096),
        },
        translator: EightCap,
        init_cache: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    };
    let transaction_config = keyless_fixed::CompactConfig {
        strategy: Sequential,
        witness: VariableJournalConfig {
            partition: "hook-transactions-witness".into(),
            items_per_section: NZU64!(1024),
            compression: None,
            codec_config: (),
            page_cache: cache,
            write_buffer: NZUsize!(4096),
            replay_buffer: NZUsize!(4096),
        },
        commit_codec_config: (),
    };
    let dbs = TestDbs::init(
        context.child("dbs"),
        (state_config, transaction_config),
        None,
    )
    .await;

    let (state, transactions) = dbs.new_batches().await;
    let state = state
        .write(
            AccountKey::from([1; 32]),
            Some(Account {
                balance: 1,
                nonce: Nonce::default(),
            }),
        )
        .merkleize()
        .await
        .expect("merkleize state");
    let transactions = transactions.merkleize().await.expect("merkleize history");
    let state_target = StateSyncTarget::new(
        state.root(),
        non_empty_range!(state.bounds().inactivity_floor, state.bounds().tip.size),
    );
    let transaction_target = TransactionHistoryTarget {
        root: transactions.root(),
        size: transactions.bounds().tip.size,
    };
    let inner = Application::new(
        context.child("app"),
        Sequential,
        ed25519::PrivateKey::from_seed(1).public_key(),
        TestCommitment::default(),
        b"engine-finalized-hook-test",
        PublicKeyCache::new(context.child("public_key_cache"), NZUsize!(64)),
        state_target,
        transaction_target,
    );
    let mut app = TestApp::new(inner, None);
    let block = app.genesis().await;
    (app, dbs, (state, transactions), block)
}

#[test]
fn finalized_hook_shares_the_engine_block_allocation() {
    deterministic::Runner::default().start(|context| async move {
        let (mut app, dbs, batches, block) = fixture(&context).await;
        let expected = block.inner_shared();
        let observed = Arc::new(Mutex::new(None));
        let hook_observed = observed.clone();
        let hook_expected = expected.clone();
        let hook: TestHook = Arc::new(move |shared, artifacts| {
            let observed = hook_observed.clone();
            let expected = hook_expected.clone();
            Box::pin(async move {
                assert!(Arc::ptr_eq(&shared, &expected));
                assert_eq!(artifacts.state.root, shared.header.state_root);
                assert_eq!(artifacts.transactions.root, shared.header.transactions_root);
                assert!(!artifacts.state.operations.is_empty());

                // Retaining the wrapper after the callback also checks owned delivery.
                let wrapped = TestBlock::from(shared);
                assert!(Arc::ptr_eq(&wrapped.inner_shared(), &expected));
                *observed.lock().expect("observation lock") = Some(wrapped);
            })
        });
        app = TestApp::new(app.inner, Some(hook));
        let captured = app
            .capture(
                (context.child("capture"), block.context()),
                &block,
                &batches,
                dbs.readers(),
            )
            .await;
        assert!(captured.is_some());
        Box::pin(dbs.apply(batches)).await;
        assert!(Box::pin(dbs.finalize()).await.durable().await);

        // The hook must survive application cloning and finish before finalized returns.
        app.clone()
            .finalized(
                (context.child("finalized"), block.context()),
                &block,
                captured,
                dbs.readers(),
            )
            .await;
        let retained = observed
            .lock()
            .expect("observation lock")
            .take()
            .expect("hook awaited");
        assert!(Arc::ptr_eq(&retained.inner_shared(), &expected));
    });
}

#[test]
fn capture_is_disabled_without_a_finalized_hook() {
    deterministic::Runner::default().start(|context| async move {
        let (mut app, dbs, batches, block) = fixture(&context).await;
        let captured = app
            .capture(
                (context.child("capture"), block.context()),
                &block,
                &batches,
                dbs.readers(),
            )
            .await;
        assert!(captured.is_none());
        Box::pin(dbs.apply(batches)).await;
        assert!(Box::pin(dbs.finalize()).await.durable().await);
        app.finalized(
            (context.child("finalized"), block.context()),
            &block,
            captured,
            dbs.readers(),
        )
        .await;
    });
}
