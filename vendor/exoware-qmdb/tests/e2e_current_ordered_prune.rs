//! Ordered current-boundary recovery across local bitmap-chunk pruning.
//! Recovery must skip pruned chunks, including the previous commit's chunk.
//! Remote current roots and proofs must match the source at every batch boundary,
//! including historical watermarks and keys below the latest inactivity floor.

mod common;

use std::num::NonZeroU64;

use commonware_cryptography::Sha256;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::{buffer::paged::CacheRef, Runner as _, Supervisor as _};
use commonware_storage::merkle::{mmr, Location};
use commonware_storage::qmdb::operation::Operation as _;
use commonware_storage::qmdb::{
    any::ordered::variable::Operation as OrderedOp,
    current::ordered::variable::Db as LocalOrderedDb,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::{
    recover_boundary_state, CurrentBoundaryState, OrderedClient, MAX_OPERATION_SIZE,
};
use exoware_sdk::PrefixedStoreClient;

const N: usize = 32;
type Digest = commonware_cryptography::sha256::Digest;
type BatchOp = OrderedOp<mmr::Family, Vec<u8>, Vec<u8>>;
type Db = LocalOrderedDb<
    mmr::Family,
    cw_tokio::Context,
    Vec<u8>,
    Vec<u8>,
    Sha256,
    TwoCap,
    N,
    commonware_parallel::Sequential,
>;

/// Each batch appends 3 fresh writes and rewrites the key 3 counter-positions
/// behind. With `N = 32` the bitmap chunk spans 256 bits; the inactivity floor
/// crosses 256 after roughly ~85 batches, so 150 comfortably forces chunk 0 to
/// be pruned (and then exercises several more post-prune batches).
const BATCHES: u64 = 150;

struct BatchOutcome {
    watermark: Location<mmr::Family>,
    root: Digest,
    delta_ops: Vec<BatchOp>,
    boundary: CurrentBoundaryState<Digest, N, mmr::Family>,
}

struct ExpiredKeySnapshot {
    watermark: Location<mmr::Family>,
    root: Digest,
    key: Vec<u8>,
    value: Vec<u8>,
}

async fn boundary_from_db(
    db: &Db,
    previous_ops: Option<&[BatchOp]>,
    operations: &[BatchOp],
) -> CurrentBoundaryState<Digest, N, mmr::Family> {
    let ops_root_witness = db.ops_root_witness().await.expect("ops root witness");
    recover_boundary_state::<mmr::Family, Sha256, _, N, _, _>(
        previous_ops,
        operations,
        db.root(),
        *db.sync_boundary() / ((N as u64) * 8),
        ops_root_witness,
        |location| common::current_proof_chunk(db.range_proof(location, NZU64!(1))),
    )
    .await
    .expect("recover_boundary_state")
}

#[tokio::test]
async fn test_mirror_ordered_prune_past_chunk_zero() {
    let store_client = common::local_store_client().await;

    // Phase 1 (blocking tokio runtime): drive the local QMDB through BATCHES
    // batches, capturing each batch's delta, root, and boundary delta. The
    // boundary recovery must not panic even once chunk 0 has been pruned.
    let (batches, chunk_zero_pruned, expired_key_snapshot) =
        tokio::task::spawn_blocking(move || {
            cw_tokio::Runner::default().start(move |context| async move {
                let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
                let cfg = common::current_variable_config(
                    "current_ordered_variable_mmr_pruned_source",
                    page_cache,
                    (
                        ((0..=MAX_OPERATION_SIZE).into(), ()),
                        ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ),
                    NZU64!(8),
                );
                let mut db: Db = Db::init(
                    context.child("current_ordered_variable_mmr_pruned_source"),
                    cfg,
                )
                .await
                .expect("init");

                let mut previous_ops: Vec<BatchOp> = Vec::new();
                let mut counter: u64 = 0;
                let mut batches: Vec<BatchOutcome> = Vec::with_capacity(BATCHES as usize);
                let mut expired_key_snapshot = None;

                for _ in 0..BATCHES {
                    let finalized = {
                        let mut batch = db.new_batch();
                        for offset in 0..3u64 {
                            let key = format!("k-{:08x}", counter + offset).into_bytes();
                            let value = format!("v-{:08x}", counter + offset).into_bytes();
                            batch = batch.write(key, Some(value));
                        }
                        if counter >= 3 {
                            let rewrite_key = format!("k-{:08x}", counter - 3).into_bytes();
                            let rewrite_value = format!("v-{:08x}-r", counter).into_bytes();
                            batch = batch.write(rewrite_key, Some(rewrite_value));
                        }
                        if counter == 12 {
                            batch = batch.write(b"k-00000006".to_vec(), None);
                        }
                        counter += 3;
                        batch
                            .merkleize(&db, None::<Vec<u8>>)
                            .await
                            .expect("merkleize")
                    };
                    (db, _) = db.apply_batch(finalized).await.expect("apply");
                    // Current pruning is now explicit in Commonware. Keep the
                    // historical operation log intact for this mirror test while
                    // allowing the current bitmap/grafted overlay to prune as far
                    // as the sync boundary permits.
                    db = db
                        .prune(Location::<mmr::Family>::new(0))
                        .await
                        .expect("prune current");

                    let latest = db.bounds().end - 1;
                    let total = NonZeroU64::new(*latest + 1).expect("non-zero");
                    let (_proof, cumulative) = db
                        .ops_historical_proof(latest + 1, Location::<mmr::Family>::new(0), total)
                        .await
                        .expect("ops_historical_proof");
                    let previous_slice = if previous_ops.is_empty() {
                        None
                    } else {
                        Some(previous_ops.as_slice())
                    };
                    let boundary = boundary_from_db(&db, previous_slice, &cumulative).await;
                    let delta_ops: Vec<BatchOp> = cumulative[previous_ops.len()..].to_vec();
                    if counter == 9 {
                        expired_key_snapshot = Some(ExpiredKeySnapshot {
                            watermark: latest,
                            root: db.root(),
                            key: b"k-00000006".to_vec(),
                            value: b"v-00000006".to_vec(),
                        });
                    }
                    batches.push(BatchOutcome {
                        watermark: latest,
                        root: db.root(),
                        delta_ops,
                        boundary,
                    });
                    previous_ops = cumulative;
                }

                // Probe whether the bitmap-level chunk 0 has been pruned by
                // asking for a range proof at Location(0); this is exactly the
                // failure mode `current::Db` exhibits once the inactivity floor
                // crosses the first chunk boundary.
                let chunk_zero_pruned = {
                    match db
                        .range_proof(Location::<mmr::Family>::new(0), NZU64!(1))
                        .await
                    {
                        Err(e) => e.to_string().contains("operation pruned"),
                        Ok(_) => false,
                    }
                };
                db = db.sync().await.expect("sync");
                db.destroy().await.expect("destroy");
                (
                    batches,
                    chunk_zero_pruned,
                    expired_key_snapshot.expect("expired key snapshot"),
                )
            })
        })
        .await
        .expect("join");

    // The bitmap-level chunk 0 must be pruned by the time we stop, otherwise
    // we are not exercising the failure mode this regression covers.
    assert!(
        chunk_zero_pruned,
        "expected local DB to prune bitmap chunk 0; test did not exercise the failure mode"
    );

    // Phase 2: mirror each batch to the remote store and verify current_root
    // agrees with the local root at THAT batch's watermark. For batches
    // uploaded after chunk 0's last republish, the stored chunk 0 payload on
    // the remote still carries the bit of the CommitFloor that was current
    // when it was last published; the server-side masking in
    // `load_bitmap_chunk` must fold that bit to 0 for the root recomputation
    // to match.
    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    let qmdb_client: OrderedClient<mmr::Family, Sha256, Vec<u8>, Vec<u8>, N> = OrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        (
            ((0..=MAX_OPERATION_SIZE).into(), ()),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        ),
        ((0..=MAX_OPERATION_SIZE).into(), ()),
    );

    let mut operations = Vec::new();
    for outcome in &batches {
        operations.extend_from_slice(&outcome.delta_ops);
        common::commit_current_operations(
            &upload_client,
            &operations,
            &(
                ((0..=MAX_OPERATION_SIZE).into(), ()),
                ((0..=MAX_OPERATION_SIZE).into(), ()),
            ),
            &outcome.boundary,
        )
        .await
        .expect("upload");
        let remote_root = qmdb_client
            .current_root_at(outcome.watermark)
            .await
            .expect("current_root_at");
        assert_eq!(
            remote_root, outcome.root,
            "remote current_root disagrees with local at watermark {}",
            outcome.watermark
        );
    }

    // Spot-check that old watermarks still verify: re-query the very first
    // batch's watermark after all later batches have been published. This
    // hits `load_bitmap_chunk` for chunk 0 at an old watermark whose stored
    // value predates every subsequent CommitFloor, forcing the mask path.
    let first = &batches[0];
    let remote_root_old = qmdb_client
        .current_root_at(first.watermark)
        .await
        .expect("current_root_at (old watermark)");
    assert_eq!(
        remote_root_old, first.root,
        "remote current_root at first watermark disagrees with local root"
    );

    // `k-00000006` is present at the captured old watermark, then rewritten
    // and deleted by later batches. Verifying it after all uploads proves
    // historical current-state proofs use the requested watermark's root and
    // update index, not the final active-key set.
    let expired_key_proof = qmdb_client
        .key_value_proof_at(
            expired_key_snapshot.watermark,
            expired_key_snapshot.key.as_slice(),
        )
        .await
        .expect("old watermark proof for later-expired key");
    assert_eq!(expired_key_proof.root, expired_key_snapshot.root);
    match &expired_key_proof.operation {
        OrderedOp::Update(update) => {
            assert_eq!(update.key, expired_key_snapshot.key);
            assert_eq!(update.value, expired_key_snapshot.value);
        }
        _ => panic!("expected Update operation for old expired-key proof"),
    }

    let final_watermark = batches.last().expect("at least one batch").watermark;
    let latest_err = qmdb_client
        .key_value_proof_at(final_watermark, expired_key_snapshot.key.as_slice())
        .await
        .expect_err("expired key should be inactive at final watermark");
    match latest_err {
        exoware_qmdb::QmdbError::KeyNotActive { .. }
        | exoware_qmdb::QmdbError::ProofKeyNotFound { .. } => {}
        other => panic!("unexpected final expired-key error: {other:?}"),
    }

    let old_range = qmdb_client
        .key_range_proof_raw_at(
            first.watermark,
            b"k-00000000".to_vec(),
            Some(b"k-00000001".to_vec()),
            10,
        )
        .await
        .expect("old watermark range proof");
    assert_eq!(old_range.watermark, first.watermark);
    assert_eq!(old_range.entries.len(), 1);
    let entry = &old_range.entries[0];
    assert_eq!(entry.operation.key(), Some(&b"k-00000000".to_vec()));
    assert_eq!(entry.root, first.root);
    assert!(entry.verify::<Sha256>());
}
