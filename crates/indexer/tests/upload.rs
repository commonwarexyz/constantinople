//! End-to-end integration: drive `BlockReporter` against three in-process
//! `exoware-simulator` instances (blocks, transactions, meta) and read every
//! artifact back out via `IndexerClient`. Also asserts that each store only
//! contains the families it owns.

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
};
use constantinople_primitives::{
    Block, Header, Sealable, Signable, SignedTransaction, TRANSACTION_NAMESPACE, Transaction,
};
use core::num::NonZeroU64;
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
    let header = Header {
        context,
        parent: sha256::Digest::EMPTY,
        height,
        timestamp: 1_000 + height,
        state_root: sha256::Digest::EMPTY,
        state_range: non_empty_range!(0u64, 1u64) as NonEmptyRange<u64>,
        transactions_root: sha256::Digest::EMPTY,
        transactions_range: non_empty_range!(0u64, 1u64) as NonEmptyRange<u64>,
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

/// Three running simulators with their connected store clients. The temp dirs
/// and join handles are kept alive for the duration of the test.
struct Stores {
    blocks: StoreClient,
    transactions: StoreClient,
    meta: StoreClient,
    _handles: [tokio::task::JoinHandle<()>; 3],
    _dirs: [TempDir; 3],
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

    let (h_b, d_b, blocks) = one().await;
    let (h_t, d_t, transactions) = one().await;
    let (h_m, d_m, meta) = one().await;
    Stores {
        blocks,
        transactions,
        meta,
        _handles: [h_b, h_t, h_m],
        _dirs: [d_b, d_t, d_m],
    }
}

/// Convenience constructor that mirrors the validator-side wiring.
fn make_uploaders(stores: &Stores) -> UploaderHandles {
    spawn_uploaders(
        stores.blocks.clone(),
        stores.transactions.clone(),
        stores.meta.clone(),
        16,
    )
}

fn make_client(stores: &Stores) -> IndexerClient {
    IndexerClient::new(
        stores.blocks.clone(),
        stores.transactions.clone(),
        stores.meta.clone(),
    )
}

/// Sum of rows visible in `client` across every indexer key family.
async fn count_all(client: &StoreClient) -> usize {
    let bounds: [(Key, Key); 7] = [
        indexer_keys::block_bounds(),
        indexer_keys::block_by_height_bounds(),
        indexer_keys::finalized_bounds(),
        indexer_keys::notarized_bounds(),
        indexer_keys::tx_bounds(),
        indexer_keys::tx_by_height_bounds(),
        indexer_keys::META.prefix_bounds(),
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
async fn block_reporter_uploads_block_transactions_and_meta_to_separate_stores() {
    let stores = spawn_stores().await;
    let uploaders = make_uploaders(&stores);
    let mut reporter: BlockReporter<Sha256, PublicKey> = BlockReporter::new(
        uploaders.blocks.clone(),
        uploaders.transactions.clone(),
        uploaders.meta.clone(),
    );

    // Build, hand off to reporter, and wait for all three uploaders to ack.
    let block = build_block(7, 3, 0xC0FFEE);
    let (ack, waiter) = Exact::handle();
    reporter.report(Update::Block(block.clone(), ack)).await;

    waiter.await.expect("uploader must acknowledge");

    // Verify routing: blocks store has BLOCK + BLOCK_BY_H (= 2 rows), the tx
    // store has 2 rows per tx, and the meta store has exactly 1 row.
    assert_eq!(count_all(&stores.blocks).await, 2);
    assert_eq!(count_all(&stores.transactions).await, 2 * block.body.len());
    assert_eq!(count_all(&stores.meta).await, 1);

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

    // Range scan over the blocks store: heights round-trip in order.
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
    let mut reporter: BlockReporter<Sha256, PublicKey> = BlockReporter::new(
        uploaders.blocks.clone(),
        uploaders.transactions.clone(),
        uploaders.meta.clone(),
    );

    for height in 1u64..=4 {
        let block = build_block(height, 1, height);
        let (ack, waiter) = Exact::handle();
        reporter.report(Update::Block(block, ack)).await;
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

/// A block with no transactions must still produce a complete ack — the
/// transactions-store batch is empty and dispatched as an immediate ack.
#[tokio::test]
async fn block_reporter_handles_empty_block_body() {
    let stores = spawn_stores().await;
    let uploaders = make_uploaders(&stores);
    let mut reporter: BlockReporter<Sha256, PublicKey> = BlockReporter::new(
        uploaders.blocks.clone(),
        uploaders.transactions.clone(),
        uploaders.meta.clone(),
    );

    let block = build_block(1, 0, 0xBABE);
    let (ack, waiter) = Exact::handle();
    reporter.report(Update::Block(block, ack)).await;
    waiter.await.expect("uploader must acknowledge empty body");

    assert_eq!(count_all(&stores.blocks).await, 2);
    assert_eq!(count_all(&stores.transactions).await, 0);
    assert_eq!(count_all(&stores.meta).await, 1);

    drop(uploaders);
}

/// Tip updates carry no payload and must not interact with any store.
#[tokio::test]
async fn block_reporter_ignores_tip_updates() {
    let stores = spawn_stores().await;
    let uploaders = make_uploaders(&stores);
    let mut reporter: BlockReporter<Sha256, PublicKey> = BlockReporter::new(
        uploaders.blocks.clone(),
        uploaders.transactions.clone(),
        uploaders.meta.clone(),
    );

    reporter
        .report(Update::<TestBlock, Exact>::Tip(
            Round::new(Epoch::zero(), View::new(99)),
            commonware_consensus::types::Height::new(99),
            sha256::Digest::EMPTY,
        ))
        .await;

    // Give the uploaders a moment to (not) write anything.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = make_client(&stores);
    assert_eq!(client.latest_height().await.unwrap(), None);
    assert_eq!(count_all(&stores.blocks).await, 0);
    assert_eq!(count_all(&stores.transactions).await, 0);
    assert_eq!(count_all(&stores.meta).await, 0);

    drop(uploaders);
}
