//! End-to-end integration: drive `BlockReporter` against two in-process
//! `exoware-simulator` instances (raw KV, sql) and read every
//! artifact back out via `IndexerClient` (KV) and a fresh DataFusion
//! `SessionContext` (SQL). Also asserts that metadata-only mode leaves the
//! raw KV store untouched.

use bytes::Bytes;
use commonware_codec::Encode;
use commonware_coding::Config as CodingConfig;
use commonware_consensus::{
    Reporter,
    marshal::Update,
    simplex::types::Context,
    types::{Epoch, Round, View, coding::Commitment},
};
use commonware_cryptography::{
    Digest, Signer,
    ed25519::{self, PublicKey},
    sha256::{self, Sha256},
};
use commonware_math::algebra::Random;
use commonware_utils::{
    Acknowledgement, NZU16, acknowledgement::Exact, non_empty_range, range::NonEmptyRange,
};
use constantinople_engine::types::EngineBlock;
use constantinople_indexer::{
    BlockReporter, IndexerClient, UploaderHandles, keys as indexer_keys, spawn_uploaders,
    sql_schema::{
        BLOCK_META_DIGEST, BLOCK_META_HEIGHT, BLOCK_META_TABLE, BLOCK_META_TRANSACTIONS_ROOT,
        BLOCK_META_TRANSACTIONS_TIP, BLOCK_META_TX_COUNT, TX_META_QMDB_LOCATION, TX_META_TABLE,
        build_meta_schema,
    },
};
use constantinople_primitives::{
    Block, Header, Sealable, Signable, SignedTransaction, TRANSACTION_NAMESPACE, Transaction,
};
use core::num::NonZeroU64;
use datafusion::{
    arrow::array::{FixedSizeBinaryArray, UInt64Array},
    prelude::SessionContext,
};
use exoware_sdk::{RangeMode, RetryConfig, StoreClient, keys::Key};
use rand::{SeedableRng, rngs::StdRng};
use std::time::Duration;
use tempfile::TempDir;

type TestBlock = EngineBlock<Sha256, PublicKey>;

const TEST_NAMESPACE: &[u8] = TRANSACTION_NAMESPACE;

/// Build a block with `tx_count` synthetic transactions at the given height.
fn build_block(height: u64, tx_count: usize, seed: u64) -> TestBlock {
    let mut rng = StdRng::seed_from_u64(seed);

    let leader = ed25519::PrivateKey::random(&mut rng).public_key();
    let context = Context::<Commitment, PublicKey> {
        round: Round::new(Epoch::zero(), View::new(height)),
        leader,
        parent: (View::new(height.saturating_sub(1)), valid_commitment()),
    };
    let transactions_end = tx_count as u64 + 2;
    let header = Header {
        context,
        parent: sha256::Digest::EMPTY,
        height,
        timestamp: 1_000 + height,
        state_root: sha256::Digest::EMPTY,
        state_range: non_empty_range!(0u64, 1u64) as NonEmptyRange<u64>,
        transactions_root: sha256::Digest::EMPTY,
        transactions_range: non_empty_range!(0u64, transactions_end) as NonEmptyRange<u64>,
    };

    let txs: Vec<SignedTransaction<PublicKey, Sha256>> = (0..tx_count)
        .map(|i| {
            let signer = ed25519::PrivateKey::random(&mut rng);
            let to = ed25519::PrivateKey::random(&mut rng).public_key();
            let value = NonZeroU64::new(100 + i as u64).expect("non-zero");
            let tx = Transaction::<sha256::Digest, PublicKey>::new(
                signer.public_key(),
                to,
                value,
                i as u64,
            );
            tx.seal_and_sign(&signer, TEST_NAMESPACE, &mut Sha256::default())
        })
        .collect();

    Block::<Commitment, PublicKey, Sha256>::new(header, txs).seal(&mut Sha256::default())
}

/// A valid (round-trippable) `Commitment` value for synthetic test contexts.
fn valid_commitment() -> Commitment {
    let cfg = CodingConfig {
        minimum_shards: NZU16!(1),
        extra_shards: NZU16!(1),
    };
    Commitment::from((
        sha256::Digest::EMPTY,
        sha256::Digest::EMPTY,
        sha256::Digest::EMPTY,
        cfg,
    ))
}

/// Running simulators with their connected store clients. The temp dirs
/// and join handles are kept alive for the duration of the test.
struct Stores {
    raw: StoreClient,
    sql: StoreClient,
    _handles: [tokio::task::JoinHandle<()>; 2],
    _dirs: [TempDir; 2],
}

async fn spawn_stores() -> Stores {
    async fn one() -> (tokio::task::JoinHandle<()>, TempDir, StoreClient) {
        let dir = TempDir::new().expect("tempdir");
        let (handle, url) = exoware_simulator::spawn_for_test(dir.path())
            .await
            .expect("spawn simulator");
        let client = StoreClient::with_retry_config(&url, RetryConfig::disabled());
        (handle, dir, client)
    }

    let (h_r, d_r, raw) = one().await;
    let (h_s, d_s, sql) = one().await;
    Stores {
        raw,
        sql,
        _handles: [h_r, h_s],
        _dirs: [d_r, d_s],
    }
}

/// Convenience constructor that mirrors the validator-side wiring.
fn make_uploaders(stores: &Stores) -> UploaderHandles {
    spawn_uploaders(stores.raw.clone(), stores.sql.clone(), 16)
}

fn make_client(stores: &Stores) -> IndexerClient {
    IndexerClient::new(stores.raw.clone(), stores.raw.clone())
}

/// Sum of rows visible in `client` across every indexer KV family.
async fn count_all(client: &StoreClient) -> usize {
    let bounds: [(Key, Key); 6] = [
        indexer_keys::block_bounds(),
        indexer_keys::block_by_height_bounds(),
        indexer_keys::finalized_bounds(),
        indexer_keys::notarized_bounds(),
        indexer_keys::tx_bounds(),
        indexer_keys::tx_by_height_bounds(),
    ];
    let mut total = 0;
    for (lo, hi) in bounds {
        let rows = client
            .query()
            .range_with_mode(&lo, &hi, 1024, RangeMode::Forward)
            .await
            .expect("range scan");
        total += rows.len();
    }
    total
}

#[tokio::test]
async fn block_reporter_uploads_block_transactions_and_meta_to_raw_store() {
    let stores = spawn_stores().await;
    let uploaders = make_uploaders(&stores);
    let mut reporter: BlockReporter<Sha256, PublicKey> =
        BlockReporter::new(uploaders.raw.clone(), uploaders.sql.clone());

    // Build, hand off to reporter, and wait for both uploaders to ack.
    let block = build_block(7, 3, 0xC0FFEE);
    let (ack, waiter) = Exact::handle();
    assert!(
        reporter
            .report(Update::Block(block.clone(), ack))
            .accepted()
    );

    waiter.await.expect("uploader must acknowledge");

    // Verify routing: raw KV has BLOCK + BLOCK_BY_H (= 2 rows) plus
    // 2 KV rows per tx. SQL metadata is verified separately
    // by `block_reporter_writes_block_meta_and_tx_meta_rows`.
    assert_eq!(count_all(&stores.raw).await, 2 + 2 * block.body.len());

    // Verify every row of the logical batch is readable by the typed client.
    let client = make_client(&stores);
    assert_eq!(
        client.latest_height().await.expect("latest_height"),
        Some(7),
    );

    let stored_block = client
        .block_bytes_by_digest(block.seal())
        .await
        .expect("block_bytes_by_digest")
        .expect("block must be present");
    let expected: Bytes = block.encode();
    assert_eq!(
        stored_block, expected,
        "stored block must match encoded value"
    );

    let stored_digest: sha256::Digest = client
        .digest_by_height(7)
        .await
        .expect("digest_by_height")
        .expect("digest must be present");
    assert_eq!(&stored_digest, block.seal());

    for (idx, lazy) in block.body.iter().enumerate() {
        let tx = lazy.get().expect("tx must materialize");
        let bytes = client
            .transaction_bytes(tx.message_digest())
            .await
            .expect("transaction_bytes")
            .expect("tx must be present");
        assert_eq!(bytes, lazy.encode(), "tx[{idx}] encoding mismatch");
    }

    // Range scan over the raw store: heights round-trip in order.
    let listed = client
        .list_block_heights::<sha256::Digest>(16)
        .await
        .expect("list_block_heights");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].0, 7);
    assert_eq!(&listed[0].1, block.seal());

    drop(uploaders);
}

#[tokio::test]
async fn block_reporter_advances_latest_height_monotonically() {
    let stores = spawn_stores().await;
    let uploaders = make_uploaders(&stores);
    let mut reporter: BlockReporter<Sha256, PublicKey> =
        BlockReporter::new(uploaders.raw.clone(), uploaders.sql.clone());

    for height in 1u64..=4 {
        let block = build_block(height, 1, height);
        let (ack, waiter) = Exact::handle();
        assert!(reporter.report(Update::Block(block, ack)).accepted());
        waiter
            .await
            .expect("uploader must acknowledge each height in order");
    }

    let client = make_client(&stores);
    assert_eq!(client.latest_height().await.unwrap(), Some(4));

    let listed = client
        .list_block_heights::<sha256::Digest>(16)
        .await
        .expect("list_block_heights");
    let heights: Vec<u64> = listed.iter().map(|(h, _)| *h).collect();
    assert_eq!(heights, vec![1, 2, 3, 4]);

    drop(uploaders);
}

/// A block with no transactions must still produce a complete ack.
#[tokio::test]
async fn block_reporter_handles_empty_block_body() {
    let stores = spawn_stores().await;
    let uploaders = make_uploaders(&stores);
    let mut reporter: BlockReporter<Sha256, PublicKey> =
        BlockReporter::new(uploaders.raw.clone(), uploaders.sql.clone());

    let block = build_block(1, 0, 0xBABE);
    let (ack, waiter) = Exact::handle();
    assert!(reporter.report(Update::Block(block, ack)).accepted());
    waiter.await.expect("uploader must acknowledge empty body");

    assert_eq!(count_all(&stores.raw).await, 2);

    drop(uploaders);
}

/// Tip updates carry no payload and must not interact with any store.
#[tokio::test]
async fn block_reporter_ignores_tip_updates() {
    let stores = spawn_stores().await;
    let uploaders = make_uploaders(&stores);
    let mut reporter: BlockReporter<Sha256, PublicKey> =
        BlockReporter::new(uploaders.raw.clone(), uploaders.sql.clone());

    reporter.report(Update::<TestBlock, Exact>::Tip(
        Round::new(Epoch::zero(), View::new(99)),
        commonware_consensus::types::Height::new(99),
        sha256::Digest::EMPTY,
    ));

    // Give the uploaders a moment to (not) write anything.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = make_client(&stores);
    assert_eq!(client.latest_height().await.unwrap(), None);
    assert_eq!(count_all(&stores.raw).await, 0);

    drop(uploaders);
}

/// SQL metadata path: a finalized block must produce one `block_meta` row
/// (with the matching height, digest, and tx_count) and one `tx_meta` row
/// per contained transaction. This drives the same store URL through both
/// the writer (`build_meta_schema(...).batch_writer()`, owned by the
/// uploader task) and the reader (`SessionContext` registered against the
/// same schema), confirming the metadata is queryable end-to-end.
#[tokio::test]
async fn block_reporter_writes_block_meta_and_tx_meta_rows() {
    let stores = spawn_stores().await;
    let uploaders = make_uploaders(&stores);
    let mut reporter: BlockReporter<Sha256, PublicKey> =
        BlockReporter::new(uploaders.raw.clone(), uploaders.sql.clone());

    let block = build_block(42, 3, 0xDECAF);
    let expected_digest: [u8; 32] = block.seal().as_ref().try_into().expect("32-byte digest");
    let expected_tx_count = block.body.len() as u64;

    let (ack, waiter) = Exact::handle();
    assert!(
        reporter
            .report(Update::Block(block.clone(), ack))
            .accepted()
    );
    waiter.await.expect("uploader must acknowledge");

    // Register a fresh DataFusion session against the SQL store; the
    // uploader has already committed so all rows are visible.
    let ctx = SessionContext::new();
    build_meta_schema(stores.sql.clone())
        .expect("build schema")
        .register_all(&ctx)
        .expect("register schema");

    // block_meta: exactly one row matching the encoded block.
    let block_meta_query = format!(
        "SELECT {BLOCK_META_HEIGHT}, {BLOCK_META_DIGEST}, {BLOCK_META_TX_COUNT}, {BLOCK_META_TRANSACTIONS_ROOT}, {BLOCK_META_TRANSACTIONS_TIP} FROM {BLOCK_META_TABLE}",
    );
    let batches = ctx
        .sql(&block_meta_query)
        .await
        .expect("block_meta select")
        .collect()
        .await
        .expect("collect block_meta");
    let total: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(total, 1, "exactly one block_meta row expected");
    let batch = &batches[0];
    let height = batch
        .column(0)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .expect("height col")
        .value(0);
    assert_eq!(height, 42);
    let digest = batch
        .column(1)
        .as_any()
        .downcast_ref::<FixedSizeBinaryArray>()
        .expect("digest col")
        .value(0);
    assert_eq!(digest, expected_digest);
    let tx_count = batch
        .column(2)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .expect("tx_count col")
        .value(0);
    assert_eq!(tx_count, expected_tx_count);
    let transactions_root = batch
        .column(3)
        .as_any()
        .downcast_ref::<FixedSizeBinaryArray>()
        .expect("transactions_root col")
        .value(0);
    assert_eq!(transactions_root, block.header.transactions_root.as_ref());
    let transactions_tip = batch
        .column(4)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .expect("transactions_tip col")
        .value(0);
    assert_eq!(transactions_tip, block.header.transactions_range.end() - 1);

    // tx_meta: exactly `expected_tx_count` rows, all at height=42.
    let tx_meta_query = format!("SELECT COUNT(*) FROM {TX_META_TABLE}");
    let agg = ctx
        .sql(&tx_meta_query)
        .await
        .expect("tx_meta count")
        .collect()
        .await
        .expect("collect tx_meta");
    let agg_batch = &agg[0];
    let count = agg_batch
        .column(0)
        .as_any()
        .downcast_ref::<datafusion::arrow::array::Int64Array>()
        .expect("count col")
        .value(0);
    assert_eq!(count as u64, expected_tx_count);

    let location_rows = ctx
        .sql(&format!(
            "SELECT {TX_META_QMDB_LOCATION} FROM {TX_META_TABLE} ORDER BY {TX_META_QMDB_LOCATION}"
        ))
        .await
        .expect("tx_meta locations query")
        .collect()
        .await
        .expect("collect tx_meta locations");
    let locations = location_rows[0]
        .column(0)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .expect("qmd location col");
    assert_eq!(locations.value(0), 1);
    assert_eq!(locations.value(1), 2);
    assert_eq!(locations.value(2), 3);

    drop(uploaders);
}

#[tokio::test]
async fn metadata_only_block_reporter_writes_only_sql_rows() {
    let stores = spawn_stores().await;
    let (sql, _sql_join) =
        constantinople_indexer::publisher::spawn_sql_uploader(stores.sql.clone(), 16);
    let mut reporter: BlockReporter<Sha256, PublicKey> = BlockReporter::metadata_only(sql);

    let block = build_block(9, 2, 0x51A9);
    let (ack, waiter) = Exact::handle();
    assert!(reporter.report(Update::Block(block, ack)).accepted());
    waiter.await.expect("uploader must acknowledge");

    assert_eq!(count_all(&stores.raw).await, 0);

    let ctx = SessionContext::new();
    build_meta_schema(stores.sql.clone())
        .expect("build schema")
        .register_all(&ctx)
        .expect("register schema");

    let block_rows = ctx
        .sql(&format!(
            "SELECT {BLOCK_META_HEIGHT} FROM {BLOCK_META_TABLE} ORDER BY {BLOCK_META_HEIGHT}"
        ))
        .await
        .expect("build query")
        .collect()
        .await
        .expect("run query");
    let height = block_rows[0]
        .column(0)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .expect("height should be u64")
        .value(0);
    assert_eq!(height, 9);
}
