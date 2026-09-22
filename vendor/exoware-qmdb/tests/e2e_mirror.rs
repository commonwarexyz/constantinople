//! Mirror local Commonware QMDB operations into an Exoware store and verify
//! the remote roots against the independent local roots across two batches.
//! Test fixtures authenticate each complete operation prefix and attach the
//! proof-derived current boundary for ordered databases.

mod common;

use std::num::NonZeroU64;

use commonware_cryptography::Sha256;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner as _, Supervisor as _};
use commonware_storage::merkle::{mmr, Location};
use commonware_storage::qmdb::{
    any::unordered::variable::Db as LocalUnorderedDb,
    current::ordered::variable::Db as LocalOrderedDb,
    immutable::variable::{Db as Immutable, Operation as ImmutableOperation},
    keyless::variable::{Db as Keyless, Operation as KeylessOperation},
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use exoware_qmdb::{
    recover_boundary_state, CurrentBoundaryState, ImmutableClient, KeylessClient, OrderedClient,
    UnorderedClient, MAX_OPERATION_SIZE,
};
use exoware_sdk::PrefixedStoreClient;

type Digest = commonware_cryptography::sha256::Digest;

// -------------------- Keyless --------------------

#[tokio::test]
async fn test_mirror_keyless_from_local() {
    let store_client = common::local_store_client().await;

    // Apply one batch locally and upload its authenticated operation prefix
    let (ops1, latest1, root1) = build_keyless_source(vec![vec![
        b"alpha".to_vec(),
        b"beta".to_vec(),
        b"gamma".to_vec(),
    ]])
    .await;
    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    common::commit_operations::<mmr::Family, _>(
        &upload_client,
        &ops1,
        &((0..=MAX_OPERATION_SIZE).into(), ()),
    )
    .await
    .expect("upload 1");
    let qmdb_client: KeylessClient<mmr::Family, Sha256, Vec<u8>> = KeylessClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        ((0..=MAX_OPERATION_SIZE).into(), ()),
    );
    assert_eq!(
        qmdb_client.root_at(latest1).await.expect("root_at 1"),
        root1,
        "remote root must match local (after batch 1)"
    );

    // Upload the complete operation prefix after a second local batch
    let (ops_total, latest2, root2) = build_keyless_source(vec![
        vec![b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()],
        vec![b"delta".to_vec(), b"epsilon".to_vec()],
    ])
    .await;
    common::commit_operations::<mmr::Family, _>(
        &upload_client,
        &ops_total,
        &((0..=MAX_OPERATION_SIZE).into(), ()),
    )
    .await
    .expect("upload 2");
    assert_eq!(
        qmdb_client.root_at(latest2).await.expect("root_at 2"),
        root2,
        "remote root must match local (after batch 2)"
    );
}

async fn build_keyless_source(
    batches: Vec<Vec<Vec<u8>>>,
) -> (
    Vec<KeylessOperation<mmr::Family, Vec<u8>>>,
    Location<mmr::Family>,
    Digest,
) {
    tokio::task::spawn_blocking(move || {
        deterministic::Runner::default().start(|context| async move {
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::keyless_variable_config(
                "keyless_variable_full_mmr_mirror_source",
                page_cache,
                ((0..=MAX_OPERATION_SIZE).into(), ()),
                NZU64!(7),
            );
            let mut db: Keyless<
                mmr::Family,
                deterministic::Context,
                Vec<u8>,
                Sha256,
                commonware_parallel::Sequential,
            > = Keyless::init(
                context.child("keyless_variable_full_mmr_mirror_source"),
                cfg,
            )
            .await
            .expect("init");
            for batch in batches {
                let finalized = {
                    let mut b = db.new_batch();
                    for v in batch {
                        b = b.append(v);
                    }
                    b.merkleize(&db, None::<Vec<u8>>, db.inactivity_floor_loc())
                        .await
                };
                (db, _) = db.apply_batch(finalized).await.expect("apply");
            }
            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_, ops) = db
                .historical_proof(latest + 1, Location::<mmr::Family>::new(0), n)
                .await
                .expect("historical_proof");
            let root = db.root();
            db.destroy().await.expect("destroy");
            (ops, latest, root)
        })
    })
    .await
    .expect("join")
}

// -------------------- Unordered --------------------

type UnorderedOp =
    commonware_storage::qmdb::any::unordered::variable::Operation<mmr::Family, Vec<u8>, Vec<u8>>;

#[tokio::test]
async fn test_mirror_unordered_from_local() {
    let store_client = common::local_store_client().await;

    let (ops1, latest1, root1) = build_any_unordered_source(vec![vec![
        (b"alpha".to_vec(), Some(b"one".to_vec())),
        (b"beta".to_vec(), Some(b"two".to_vec())),
    ]])
    .await;
    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    common::commit_operations::<mmr::Family, _>(
        &upload_client,
        &ops1,
        &(
            ((0..=MAX_OPERATION_SIZE).into(), ()),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        ),
    )
    .await
    .expect("upload 1");
    let qmdb_client: UnorderedClient<mmr::Family, Sha256, Vec<u8>, Vec<u8>> = UnorderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        (
            ((0..=MAX_OPERATION_SIZE).into(), ()),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        ),
    );
    assert_eq!(
        qmdb_client.root_at(latest1).await.expect("root_at 1"),
        root1,
        "remote root must match local (after batch 1)"
    );

    let (ops_total, latest2, root2) = build_any_unordered_source(vec![
        vec![
            (b"alpha".to_vec(), Some(b"one".to_vec())),
            (b"beta".to_vec(), Some(b"two".to_vec())),
        ],
        vec![
            (b"alpha".to_vec(), Some(b"one-updated".to_vec())),
            (b"gamma".to_vec(), Some(b"three".to_vec())),
        ],
    ])
    .await;
    common::commit_operations::<mmr::Family, _>(
        &upload_client,
        &ops_total,
        &(
            ((0..=MAX_OPERATION_SIZE).into(), ()),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        ),
    )
    .await
    .expect("upload 2");
    assert_eq!(
        qmdb_client.root_at(latest2).await.expect("root_at 2"),
        root2,
        "remote root must match local (after batch 2)"
    );
}

type UnorderedBatch = Vec<(Vec<u8>, Option<Vec<u8>>)>;

async fn build_any_unordered_source(
    batches: Vec<UnorderedBatch>,
) -> (Vec<UnorderedOp>, Location<mmr::Family>, Digest) {
    tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(|context| async move {
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::any_variable_config(
                "any_unordered_variable_mmr_mirror_source",
                page_cache,
                (
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                ),
                NZU64!(8),
            );
            let mut db: LocalUnorderedDb<
                mmr::Family,
                cw_tokio::Context,
                Vec<u8>,
                Vec<u8>,
                Sha256,
                TwoCap,
                commonware_parallel::Sequential,
            > = LocalUnorderedDb::init(
                context.child("any_unordered_variable_mmr_mirror_source"),
                cfg,
            )
            .await
            .expect("init");
            for batch in batches {
                let finalized = {
                    let mut b = db.new_batch();
                    for (k, v) in batch {
                        b = b.write(k, v);
                    }
                    b.merkleize(&db, None::<Vec<u8>>).await.expect("merkleize")
                };
                (db, _) = db.apply_batch(finalized).await.expect("apply");
            }
            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_, ops) = db
                .historical_proof(latest + 1, Location::<mmr::Family>::new(0), n)
                .await
                .expect("historical_proof");
            let root = db.root();
            db.destroy().await.expect("destroy");
            (ops, latest, root)
        })
    })
    .await
    .expect("join")
}

// -------------------- Immutable --------------------

type ImmK = FixedBytes<32>;

#[tokio::test]
async fn test_mirror_immutable_from_local() {
    let store_client = common::local_store_client().await;

    let (ops1, latest1, root1) = build_immutable_source(vec![vec![
        (FixedBytes::new([0x11; 32]), b"one".to_vec()),
        (FixedBytes::new([0x22; 32]), b"two".to_vec()),
    ]])
    .await;
    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    common::commit_operations::<mmr::Family, _>(
        &upload_client,
        &ops1,
        &((), ((0..=MAX_OPERATION_SIZE).into(), ())),
    )
    .await
    .expect("upload 1");
    let qmdb_client: ImmutableClient<mmr::Family, Sha256, ImmK, Vec<u8>> = ImmutableClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        ((), ((0..=MAX_OPERATION_SIZE).into(), ())),
    );
    assert_eq!(
        qmdb_client.root_at(latest1).await.expect("root_at 1"),
        root1,
        "remote root must match local (after batch 1)"
    );

    let (ops_total, latest2, root2) = build_immutable_source(vec![
        vec![
            (FixedBytes::new([0x11; 32]), b"one".to_vec()),
            (FixedBytes::new([0x22; 32]), b"two".to_vec()),
        ],
        vec![(FixedBytes::new([0x33; 32]), b"three".to_vec())],
    ])
    .await;
    common::commit_operations::<mmr::Family, _>(
        &upload_client,
        &ops_total,
        &((), ((0..=MAX_OPERATION_SIZE).into(), ())),
    )
    .await
    .expect("upload 2");
    assert_eq!(
        qmdb_client.root_at(latest2).await.expect("root_at 2"),
        root2,
        "remote root must match local (after batch 2)"
    );
}

async fn build_immutable_source(
    batches: Vec<Vec<(ImmK, Vec<u8>)>>,
) -> (
    Vec<ImmutableOperation<mmr::Family, ImmK, Vec<u8>>>,
    Location<mmr::Family>,
    Digest,
) {
    tokio::task::spawn_blocking(move || {
        deterministic::Runner::default().start(|context| async move {
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::immutable_variable_config(
                "immutable_variable_full_mmr_mirror_source",
                page_cache,
                ((), ((0..=MAX_OPERATION_SIZE).into(), ())),
                NZU64!(5),
            );
            let mut db: Immutable<
                mmr::Family,
                deterministic::Context,
                ImmK,
                Vec<u8>,
                Sha256,
                TwoCap,
                commonware_parallel::Sequential,
            > = Immutable::init(
                context.child("immutable_variable_full_mmr_mirror_source"),
                cfg,
            )
            .await
            .expect("init");
            for batch in batches {
                let finalized = {
                    let mut b = db.new_batch();
                    for (k, v) in batch {
                        b = b.set(k, v);
                    }
                    b.merkleize(&db, None::<Vec<u8>>, db.inactivity_floor_loc())
                        .await
                };
                (db, _) = db.apply_batch(finalized).await.expect("apply");
            }
            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_, ops) = db
                .historical_proof(latest + 1, Location::<mmr::Family>::new(0), n)
                .await
                .expect("historical_proof");
            let root = db.root();
            db.destroy().await.expect("destroy");
            (ops, latest, root)
        })
    })
    .await
    .expect("join")
}

// -------------------- Ordered (with current boundary) --------------------

const N: usize = 32;
type OrderedOp =
    commonware_storage::qmdb::any::ordered::variable::Operation<mmr::Family, Vec<u8>, Vec<u8>>;

async fn boundary_from_current_ordered_source(
    db: &LocalOrderedDb<
        mmr::Family,
        cw_tokio::Context,
        Vec<u8>,
        Vec<u8>,
        Sha256,
        TwoCap,
        N,
        commonware_parallel::Sequential,
    >,
    previous_operations: Option<&[OrderedOp]>,
    operations: &[OrderedOp],
) -> CurrentBoundaryState<Digest, N, mmr::Family> {
    let ops_root_witness = db.ops_root_witness().await.expect("ops root witness");
    recover_boundary_state::<mmr::Family, Sha256, _, N, _, _>(
        previous_operations,
        operations,
        db.root(),
        0,
        ops_root_witness,
        |location| common::current_proof_chunk(db.range_proof(location, NZU64!(1))),
    )
    .await
    .expect("recover_boundary_state")
}

#[tokio::test]
async fn test_mirror_ordered_from_local() {
    let store_client = common::local_store_client().await;

    let (ops1, latest1, root1, boundary1) = build_current_ordered_source(
        vec![vec![
            (b"alpha".to_vec(), Some(b"one".to_vec())),
            (b"beta".to_vec(), Some(b"two".to_vec())),
        ]],
        None,
    )
    .await;
    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    common::commit_current_operations::<mmr::Family, _, N>(
        &upload_client,
        &ops1,
        &(
            ((0..=MAX_OPERATION_SIZE).into(), ()),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        ),
        &boundary1,
    )
    .await
    .expect("upload 1");

    let qmdb_client: OrderedClient<mmr::Family, Sha256, Vec<u8>, Vec<u8>, N> = OrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        (
            ((0..=MAX_OPERATION_SIZE).into(), ()),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        ),
        ((0..=MAX_OPERATION_SIZE).into(), ()),
    );
    assert_eq!(
        qmdb_client
            .current_root_at(latest1)
            .await
            .expect("root_at 1"),
        root1,
        "remote root must match local (after batch 1)"
    );

    // Compute the per-batch boundary delta for the new batch
    let (ops_total, latest2, root2, boundary_delta) = build_current_ordered_source(
        vec![
            vec![
                (b"alpha".to_vec(), Some(b"one".to_vec())),
                (b"beta".to_vec(), Some(b"two".to_vec())),
            ],
            vec![(b"alpha".to_vec(), Some(b"one-updated".to_vec()))],
        ],
        Some(ops1.clone()),
    )
    .await;

    common::commit_current_operations::<mmr::Family, _, N>(
        &upload_client,
        &ops_total,
        &(
            ((0..=MAX_OPERATION_SIZE).into(), ()),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        ),
        &boundary_delta,
    )
    .await
    .expect("upload 2");
    assert_eq!(
        qmdb_client
            .current_root_at(latest2)
            .await
            .expect("root_at 2"),
        root2,
        "remote root must match local (after batch 2)"
    );
}

type OrderedBatch = Vec<(Vec<u8>, Option<Vec<u8>>)>;

async fn build_current_ordered_source(
    batches: Vec<OrderedBatch>,
    previous_operations: Option<Vec<OrderedOp>>,
) -> (
    Vec<OrderedOp>,
    Location<mmr::Family>,
    Digest,
    CurrentBoundaryState<Digest, N, mmr::Family>,
) {
    tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(|context| async move {
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::current_variable_config(
                "current_ordered_variable_mmr_mirror_source",
                page_cache,
                (
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                ),
                NZU64!(8),
            );
            let mut db: LocalOrderedDb<
                mmr::Family,
                cw_tokio::Context,
                Vec<u8>,
                Vec<u8>,
                Sha256,
                TwoCap,
                N,
                commonware_parallel::Sequential,
            > = LocalOrderedDb::init(
                context.child("current_ordered_variable_mmr_mirror_source"),
                cfg,
            )
            .await
            .expect("init");
            for batch in batches {
                let finalized = {
                    let mut b = db.new_batch();
                    for (k, v) in batch {
                        b = b.write(k, v);
                    }
                    b.merkleize(&db, None::<Vec<u8>>).await.expect("merkleize")
                };
                (db, _) = db.apply_batch(finalized).await.expect("apply");
            }
            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_, ops) = db
                .ops_historical_proof(latest + 1, Location::<mmr::Family>::new(0), n)
                .await
                .expect("ops_historical_proof");
            let boundary =
                boundary_from_current_ordered_source(&db, previous_operations.as_deref(), &ops)
                    .await;
            let root = db.root();
            db = db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");
            (ops, latest, root, boundary)
        })
    })
    .await
    .expect("join")
}
