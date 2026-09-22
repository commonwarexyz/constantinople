//! Ordered QMDB E2E: run a local Commonware ordered DB, upload its
//! operations + current boundary state to a live store stack, then
//! verify roots and proofs match.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use commonware_cryptography::Sha256;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::Runner as _;
use commonware_storage::journal::contiguous::fixed::Config as FixedJournalConfig;
use commonware_storage::merkle::{mmb, mmr, Family, Graftable, Location, Proof};
use commonware_storage::qmdb::any::ordered::fixed::Operation as FixedQmdbOperation;
use commonware_storage::qmdb::any::ordered::variable::Operation as QmdbOperation;
use commonware_storage::qmdb::any::value::FixedEncoding;
use commonware_storage::qmdb::current::ordered::fixed::Db as LocalFixedQmdbDb;
use commonware_storage::qmdb::current::ordered::variable::Db as LocalQmdbDb;
use commonware_storage::qmdb::operation::Operation as _;
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::MAX_OPERATION_SIZE;
use exoware_qmdb::{recover_boundary_state, CurrentBoundaryState, OrderedClient};
use exoware_sdk::{PrefixedStoreClient, StoreClient};

const N: usize = 32;
type Digest = commonware_cryptography::sha256::Digest;
type BatchOperation<F> = QmdbOperation<F, Vec<u8>, Vec<u8>>;
type FixedBatchOperation<F> = FixedQmdbOperation<F, Digest, Digest>;
type VariableClient<F> = OrderedClient<F, Sha256, Vec<u8>, Vec<u8>, N>;
type FixedClient<F> = OrderedClient<F, Sha256, Digest, Digest, N, FixedEncoding<Digest>>;
type VariableDb<F> = LocalQmdbDb<
    F,
    cw_tokio::Context,
    Vec<u8>,
    Vec<u8>,
    Sha256,
    TwoCap,
    N,
    commonware_parallel::Sequential,
>;

type FixedDb<F> = LocalFixedQmdbDb<
    F,
    cw_tokio::Context,
    Digest,
    Digest,
    Sha256,
    TwoCap,
    N,
    commonware_parallel::Sequential,
>;

async fn boundary_from_source_db<F>(
    db: &VariableDb<F>,
    previous_operations: Option<&[BatchOperation<F>]>,
    operations: &[BatchOperation<F>],
) -> CurrentBoundaryState<Digest, N, F>
where
    F: Graftable,
    BatchOperation<F>: commonware_codec::Codec,
{
    let ops_root_witness = db.ops_root_witness().await.expect("ops root witness");
    recover_boundary_state::<F, Sha256, _, N, _, _>(
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

async fn upload_source<F>(store_client: &StoreClient, source: &VariableSource<F>)
where
    F: Graftable,
    BatchOperation<F>:
        commonware_codec::Codec + commonware_codec::Encode + commonware_codec::Decode,
{
    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    common::commit_current_operations(
        &upload_client,
        &source.operations,
        &op_cfg::<F>(),
        &source.current_boundary,
    )
    .await
    .expect("commit upload");
}

async fn boundary_from_fixed_source_db<F>(
    db: &FixedDb<F>,
    previous_operations: Option<&[FixedBatchOperation<F>]>,
    operations: &[FixedBatchOperation<F>],
) -> CurrentBoundaryState<Digest, N, F>
where
    F: Graftable,
    FixedBatchOperation<F>: commonware_codec::CodecFixed<Cfg = ()> + Send + Sync,
{
    let ops_root_witness = db.ops_root_witness().await.expect("fixed ops root witness");
    recover_boundary_state::<F, Sha256, _, N, _, _>(
        previous_operations,
        operations,
        db.root(),
        0,
        ops_root_witness,
        |location| common::current_proof_chunk(db.range_proof(location, NZU64!(1))),
    )
    .await
    .expect("recover fixed boundary state")
}

fn op_cfg<F: Family>() -> <BatchOperation<F> as commonware_codec::Read>::Cfg {
    (
        ((0..=MAX_OPERATION_SIZE).into(), ()),
        ((0..=MAX_OPERATION_SIZE).into(), ()),
    )
}

fn key_cfg() -> <Vec<u8> as commonware_codec::Read>::Cfg {
    ((0..=MAX_OPERATION_SIZE).into(), ())
}

struct VariableSource<F: Graftable> {
    latest_location: Location<F>,
    operations: Vec<BatchOperation<F>>,
    current_boundary: CurrentBoundaryState<Digest, N, F>,
    values: std::collections::BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

struct ChunkSizedVariableSource<F: Graftable, const M: usize> {
    latest_location: Location<F>,
    operations: Vec<BatchOperation<F>>,
    current_boundary: CurrentBoundaryState<Digest, M, F>,
}

struct FixedSource<F: Graftable> {
    latest_location: Location<F>,
    operations: Vec<FixedBatchOperation<F>>,
    current_boundary: CurrentBoundaryState<Digest, N, F>,
    values: std::collections::BTreeMap<Vec<u8>, Option<Digest>>,
}

async fn build_variable_source<F>() -> VariableSource<F>
where
    F: Graftable,
    BatchOperation<F>: commonware_codec::Codec + Clone,
{
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::current_variable_config(
                "current_ordered_variable_source",
                page_cache,
                op_cfg::<F>(),
                NZU64!(8),
            );
            let mut db: VariableDb<F> =
                VariableDb::init(context.child("current_ordered_variable_source"), cfg)
                    .await
                    .expect("init");

            let finalized = {
                let batch = db
                    .new_batch()
                    .write(b"alpha".to_vec(), Some(b"one".to_vec()))
                    .write(b"beta".to_vec(), Some(b"two".to_vec()));
                batch
                    .merkleize(&db, None::<Vec<u8>>)
                    .await
                    .expect("merkleize")
            };
            (db, _) = db.apply_batch(finalized).await.expect("apply");

            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops): (Proof<F, Digest>, Vec<BatchOperation<F>>) = db
                .ops_historical_proof(latest + 1, Location::<F>::new(0), n)
                .await
                .expect("proof");

            let boundary = boundary_from_source_db(&db, None, &ops).await;

            let mut values = std::collections::BTreeMap::new();
            values.insert(
                b"alpha".to_vec(),
                db.get(&b"alpha".to_vec()).await.expect("get"),
            );
            values.insert(
                b"beta".to_vec(),
                db.get(&b"beta".to_vec()).await.expect("get"),
            );

            db = db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            VariableSource {
                latest_location: latest,
                operations: ops,
                current_boundary: boundary,
                values,
            }
        })
    })
    .await
    .expect("join")
}

async fn boundary_from_source_db_with_chunk_size<F, const M: usize>(
    db: &LocalQmdbDb<
        F,
        cw_tokio::Context,
        Vec<u8>,
        Vec<u8>,
        Sha256,
        TwoCap,
        M,
        commonware_parallel::Sequential,
    >,
    previous_operations: Option<&[BatchOperation<F>]>,
    operations: &[BatchOperation<F>],
) -> CurrentBoundaryState<Digest, M, F>
where
    F: Graftable,
    BatchOperation<F>: commonware_codec::Codec,
{
    let ops_root_witness = db.ops_root_witness().await.expect("ops root witness");
    recover_boundary_state::<F, Sha256, _, M, _, _>(
        previous_operations,
        operations,
        db.root(),
        0,
        ops_root_witness,
        |location| common::current_proof_chunk(db.range_proof(location, NZU64!(1))),
    )
    .await
    .expect("recover boundary state")
}

async fn build_variable_source_with_write_count<F, const M: usize>(
    partition_prefix: &'static str,
    write_count: usize,
) -> ChunkSizedVariableSource<F, M>
where
    F: Graftable,
    BatchOperation<F>: commonware_codec::Codec + Clone,
{
    tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::current_variable_config(
                partition_prefix,
                page_cache,
                op_cfg::<F>(),
                NZU64!(8),
            );
            let mut db: LocalQmdbDb<
                F,
                cw_tokio::Context,
                Vec<u8>,
                Vec<u8>,
                Sha256,
                TwoCap,
                M,
                commonware_parallel::Sequential,
            > = LocalQmdbDb::init(context.child(partition_prefix), cfg)
                .await
                .expect("init");

            let finalized = {
                let mut batch = db.new_batch();
                for index in 0..write_count {
                    batch = batch.write(
                        format!("k-{index:08}").into_bytes(),
                        Some(format!("v-{index:08}").into_bytes()),
                    );
                }
                batch
                    .merkleize(&db, None::<Vec<u8>>)
                    .await
                    .expect("merkleize")
            };
            (db, _) = db.apply_batch(finalized).await.expect("apply");

            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops): (Proof<F, Digest>, Vec<BatchOperation<F>>) = db
                .ops_historical_proof(latest + 1, Location::<F>::new(0), n)
                .await
                .expect("proof");

            let boundary = boundary_from_source_db_with_chunk_size::<F, M>(&db, None, &ops).await;

            db = db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            ChunkSizedVariableSource {
                latest_location: latest,
                operations: ops,
                current_boundary: boundary,
            }
        })
    })
    .await
    .expect("join")
}

async fn build_fixed_source<F>() -> FixedSource<F>
where
    F: Graftable,
    FixedBatchOperation<F>: commonware_codec::CodecFixed<Cfg = ()> + Clone + Send + Sync,
{
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = commonware_storage::qmdb::current::Config {
                merkle_config: common::merkle_config(
                    "current_ordered_fixed_source",
                    page_cache.clone(),
                ),
                journal_config: FixedJournalConfig {
                    partition: "current_ordered_fixed_source-log".to_string(),
                    items_per_blob: NZU64!(8),
                    page_cache,
                    write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                },
                grafted_metadata_partition: "current_ordered_fixed_source-grafted-metadata"
                    .to_string(),
                translator: TwoCap,
                init_cache_size: None,
                init_buffer: NZUsize!(1 << 21),
                init_concurrency: (),
            };
            let mut db: FixedDb<F> =
                FixedDb::init(context.child("current_ordered_fixed_source"), cfg)
                    .await
                    .expect("init fixed");

            let alpha = Sha256::fill(0xA1);
            let beta = Sha256::fill(0xB2);
            let one = Sha256::fill(0x01);
            let two = Sha256::fill(0x02);
            let finalized = {
                let batch = db
                    .new_batch()
                    .write(alpha, Some(one))
                    .write(beta, Some(two));
                batch
                    .merkleize(&db, None::<Digest>)
                    .await
                    .expect("fixed merkleize")
            };
            (db, _) = db.apply_batch(finalized).await.expect("apply fixed");

            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops): (Proof<F, Digest>, Vec<FixedBatchOperation<F>>) = db
                .ops_historical_proof(latest + 1, Location::<F>::new(0), n)
                .await
                .expect("fixed proof");

            let boundary = boundary_from_fixed_source_db(&db, None, &ops).await;

            let mut values = std::collections::BTreeMap::new();
            values.insert(
                alpha.as_ref().to_vec(),
                db.get(&alpha).await.expect("get alpha"),
            );
            values.insert(
                beta.as_ref().to_vec(),
                db.get(&beta).await.expect("get beta"),
            );

            db = db.sync().await.expect("sync fixed");
            db.destroy().await.expect("destroy fixed");

            FixedSource {
                latest_location: latest,
                operations: ops,
                current_boundary: boundary,
                values,
            }
        })
    })
    .await
    .expect("join")
}

#[tokio::test]
async fn test_ordered_round_trip() {
    let store_client = common::local_store_client().await;
    let source = build_variable_source::<mmr::Family>().await;

    upload_source(&store_client, &source).await;

    let qmdb_client = VariableClient::<mmr::Family>::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg::<mmr::Family>(),
        key_cfg(),
    );
    let watermark = qmdb_client
        .writer_location_watermark()
        .await
        .expect("watermark");
    assert_eq!(watermark, Some(source.latest_location));

    let queried = qmdb_client
        .query_many_at(
            &[b"alpha".as_slice(), b"beta".as_slice()],
            source.latest_location,
        )
        .await
        .expect("query_many_at");
    assert_eq!(
        queried[0].as_ref().and_then(|v| v.value.clone()),
        source.values[b"alpha".as_slice()]
    );
    assert_eq!(
        queried[1].as_ref().and_then(|v| v.value.clone()),
        source.values[b"beta".as_slice()]
    );

    let proof = qmdb_client
        .operation_range_proof(
            source.latest_location,
            Location::<mmr::Family>::new(0),
            source.operations.len() as u32,
        )
        .await
        .expect("proof");
    assert_eq!(proof.operations, source.operations);
}

#[tokio::test]
async fn test_ordered_mmb_round_trip() {
    let store_client = common::local_store_client().await;
    let source = build_variable_source::<mmb::Family>().await;

    upload_source(&store_client, &source).await;

    let qmdb_client = VariableClient::<mmb::Family>::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg::<mmb::Family>(),
        key_cfg(),
    );
    let watermark = qmdb_client
        .writer_location_watermark()
        .await
        .expect("watermark");
    assert_eq!(watermark, Some(source.latest_location));

    let range = qmdb_client
        .operation_range_proof(
            source.latest_location,
            Location::<mmb::Family>::new(0),
            source.operations.len() as u32,
        )
        .await
        .expect("operation range proof");
    assert_eq!(range.operations, source.operations);

    let current = qmdb_client
        .current_operation_range_proof(
            source.latest_location,
            Location::<mmb::Family>::new(0),
            source.operations.len() as u32,
        )
        .await
        .expect("current operation range proof");
    assert_eq!(current.operations, source.operations);

    let key_proof = qmdb_client
        .key_value_proof_at(source.latest_location, b"alpha".as_slice())
        .await
        .expect("key_value_proof_at");
    match &key_proof.operation {
        QmdbOperation::Update(update) => {
            assert_eq!(update.key, b"alpha".to_vec());
            assert_eq!(update.value, b"one".to_vec());
        }
        _ => panic!("expected Update operation"),
    }
}

#[tokio::test]
async fn test_ordered_mmb_multi_peak_grafted_chunk_round_trip() {
    let store_client = common::local_store_client().await;
    let source = build_variable_source_with_write_count::<mmb::Family, N>(
        "current_ordered_variable_mmb_grafted_source",
        767,
    )
    .await;
    assert!(
        source.current_boundary.grafted_nodes.len() >= 2,
        "test must cross a grafted chunk boundary"
    );

    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    common::commit_current_operations(
        &upload_client,
        &source.operations,
        &op_cfg::<mmb::Family>(),
        &source.current_boundary,
    )
    .await
    .expect("commit upload");

    let qmdb_client: OrderedClient<mmb::Family, Sha256, Vec<u8>, Vec<u8>, N> = OrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg::<mmb::Family>(),
        key_cfg(),
    );
    let current = qmdb_client
        .current_operation_range_proof(
            source.latest_location,
            Location::<mmb::Family>::new(0),
            source.operations.len() as u32,
        )
        .await
        .expect("current operation range proof");
    assert_eq!(current.operations, source.operations);

    let key = b"k-00000007".to_vec();
    let key_proof = qmdb_client
        .key_value_proof_at(source.latest_location, key.as_slice())
        .await
        .expect("key_value_proof_at");
    assert_eq!(key_proof.root, source.current_boundary.root);
    match &key_proof.operation {
        QmdbOperation::Update(update) => {
            assert_eq!(update.key, key);
            assert_eq!(update.value, b"v-00000007".to_vec());
        }
        _ => panic!("expected Update operation"),
    }
}

async fn assert_incremental_seed_batches_keep_current_proofs_verifiable<F>(
    partition_prefix: &'static str,
) where
    F: Graftable + Send + Sync + 'static,
    BatchOperation<F>:
        commonware_codec::Codec + commonware_codec::Encode + commonware_codec::Decode + Clone,
{
    let store_client = common::local_store_client().await;
    let (uploads, latest_location, latest_key, expected_root, expected_active) =
        tokio::task::spawn_blocking(move || {
            cw_tokio::Runner::default().start(|context| async move {
                use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
                let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
                let cfg = common::current_variable_config(
                    partition_prefix,
                    page_cache,
                    op_cfg::<F>(),
                    NZU64!(8),
                );
                let mut db: VariableDb<F> = LocalQmdbDb::init(context.child(partition_prefix), cfg)
                    .await
                    .expect("init");

                let mut previous_ops = Vec::<BatchOperation<F>>::new();
                let mut uploads =
                    Vec::<(Vec<BatchOperation<F>>, CurrentBoundaryState<Digest, N, F>)>::new();
                let mut expected_active = BTreeMap::<Vec<u8>, Vec<u8>>::new();
                let mut counter = 0u64;

                for _ in 0..80 {
                    let finalized = {
                        let mut batch = db.new_batch();
                        for offset in 0..3u64 {
                            let key = format!("k-{:08x}", counter + offset).into_bytes();
                            let value = format!("v-{:08x}", counter + offset).into_bytes();
                            expected_active.insert(key.clone(), value.clone());
                            batch = batch.write(key, Some(value));
                        }
                        if counter >= 3 {
                            let rewrite_key = format!("k-{:08x}", counter - 3).into_bytes();
                            let rewrite_value = format!("v-{:08x}-r", counter).into_bytes();
                            expected_active.insert(rewrite_key.clone(), rewrite_value.clone());
                            batch = batch.write(rewrite_key, Some(rewrite_value));
                        }
                        if counter >= 6 && counter.is_multiple_of(12) {
                            let delete_key = format!("k-{:08x}", counter - 6).into_bytes();
                            expected_active.remove(&delete_key);
                            batch = batch.write(delete_key, None);
                        }
                        counter += 3;
                        batch
                            .merkleize(&db, None::<Vec<u8>>)
                            .await
                            .expect("merkleize")
                    };
                    (db, _) = db.apply_batch(finalized).await.expect("apply");

                    let latest = db.bounds().end - 1;
                    let count = NonZeroU64::new(*latest + 1).expect("non-zero op count");
                    let (_proof, cumulative_ops) = db
                        .ops_historical_proof(latest + 1, Location::<F>::new(0), count)
                        .await
                        .expect("historical proof");
                    let previous_slice = if previous_ops.is_empty() {
                        None
                    } else {
                        Some(previous_ops.as_slice())
                    };
                    let boundary =
                        boundary_from_source_db(&db, previous_slice, &cumulative_ops).await;
                    let delta = cumulative_ops[previous_ops.len()..].to_vec();
                    uploads.push((delta, boundary));
                    previous_ops = cumulative_ops;
                }

                let latest_location = db.bounds().end - 1;
                let latest_key = format!("k-{:08x}", counter - 3).into_bytes();
                let expected_root = db.root();
                db.destroy().await.expect("destroy");
                (
                    uploads,
                    latest_location,
                    latest_key,
                    expected_root,
                    expected_active,
                )
            })
        })
        .await
        .expect("join");

    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    let mut operations = Vec::new();
    for (delta, boundary) in &uploads {
        operations.extend_from_slice(delta);
        common::commit_current_operations(&upload_client, &operations, &op_cfg::<F>(), boundary)
            .await
            .expect("commit upload");
    }

    let qmdb_client: VariableClient<F> = OrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg::<F>(),
        key_cfg(),
    );
    let key_proof = qmdb_client
        .key_value_proof_at(latest_location, latest_key.as_slice())
        .await
        .expect("latest key proof");
    assert_eq!(key_proof.root, expected_root);
    match &key_proof.operation {
        QmdbOperation::Update(update) => {
            assert_eq!(update.key, latest_key);
        }
        _ => panic!("expected Update operation"),
    }

    let mut sample_keys = BTreeSet::new();
    sample_keys.extend(expected_active.keys().take(24).cloned());
    sample_keys.extend(expected_active.keys().rev().take(8).cloned());
    for key in sample_keys {
        let expected_value = expected_active
            .get(&key)
            .expect("sample key must be active");
        let proof = qmdb_client
            .key_value_proof_at(latest_location, key.as_slice())
            .await
            .unwrap_or_else(|error| panic!("active key proof for {key:?}: {error:?}"));
        assert_eq!(proof.root, expected_root);
        match &proof.operation {
            QmdbOperation::Update(update) => {
                assert_eq!(update.key, key);
                assert_eq!(update.value, *expected_value);
            }
            _ => panic!("expected Update operation"),
        }
    }

    let raw_range = qmdb_client
        .key_range_proof_raw_at(
            latest_location,
            b"k-00000000".to_vec(),
            Some(b"k-00000020".to_vec()),
            10,
        )
        .await
        .expect("old-key range proof");
    let expected_range_keys = expected_active
        .range(b"k-00000000".to_vec()..b"k-00000020".to_vec())
        .take(10)
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    assert_eq!(raw_range.entries.len(), expected_range_keys.len());
    for (entry, expected_key) in raw_range.entries.iter().zip(expected_range_keys) {
        assert_eq!(entry.operation.key(), Some(&expected_key));
        assert!(entry.verify::<Sha256>());
    }
}

#[tokio::test]
async fn test_ordered_mmb_incremental_seed_batches_keep_current_proofs_verifiable() {
    assert_incremental_seed_batches_keep_current_proofs_verifiable::<mmb::Family>(
        "current_ordered_variable_mmb_incremental_seed_source",
    )
    .await;
}

#[tokio::test]
async fn test_ordered_mmb_persistent_interleaved_seed_batches_keep_current_proofs_verifiable() {
    let store_client = common::local_store_client().await;
    let storage_dir = tempfile::tempdir().expect("tempdir");
    let storage_path = storage_dir.path().to_owned();
    let store = store_client.clone();

    let (latest_location, expected_root, expected_ops_root) =
        tokio::task::spawn_blocking(move || {
            cw_tokio::Runner::new(cw_tokio::Config::new().with_storage_directory(storage_path))
                .start(|context| async move {
                    use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
                    let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
                    let cfg = common::current_variable_config(
                        "current_ordered_variable_mmb_persistent_seed_source",
                        page_cache,
                        op_cfg::<mmb::Family>(),
                        NZU64!(8),
                    );
                    let mut db: VariableDb<mmb::Family> = LocalQmdbDb::init(
                        context.child("current_ordered_variable_mmb_persistent_seed_source"),
                        cfg,
                    )
                    .await
                    .expect("init");
                    let upload_client = PrefixedStoreClient::empty(store.clone());
                    let mut previous_ops = Vec::<BatchOperation<mmb::Family>>::new();
                    let mut counter = 0u64;

                    for _ in 0..2 {
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
                            counter += 3;
                            batch
                                .merkleize(&db, None::<Vec<u8>>)
                                .await
                                .expect("merkleize")
                        };
                        (db, _) = db.apply_batch(finalized).await.expect("apply");
                        db = db.sync().await.expect("sync");

                        let latest = db.bounds().end - 1;
                        let count = NonZeroU64::new(*latest + 1).expect("non-zero op count");
                        let (proof, cumulative_ops) = db
                            .ops_historical_proof(
                                latest + 1,
                                Location::<mmb::Family>::new(0),
                                count,
                            )
                            .await
                            .expect("historical proof");
                        assert!(commonware_storage::qmdb::verify_proof::<Sha256, _, _>(
                            &proof,
                            Location::<mmb::Family>::new(0),
                            &cumulative_ops,
                            &db.ops_root()
                        ));
                        let previous_slice = if previous_ops.is_empty() {
                            None
                        } else {
                            Some(previous_ops.as_slice())
                        };
                        let boundary =
                            boundary_from_source_db(&db, previous_slice, &cumulative_ops).await;
                        common::commit_current_operations(
                            &upload_client,
                            &cumulative_ops,
                            &op_cfg::<mmb::Family>(),
                            &boundary,
                        )
                        .await
                        .expect("commit upload");
                        previous_ops = cumulative_ops;
                    }

                    let latest_location = db.bounds().end - 1;
                    let expected_root = db.root();
                    let expected_ops_root = db.ops_root();
                    db.sync().await.expect("sync");
                    (latest_location, expected_root, expected_ops_root)
                })
        })
        .await
        .expect("join");

    let qmdb_client: VariableClient<mmb::Family> = OrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg::<mmb::Family>(),
        key_cfg(),
    );
    assert_eq!(
        qmdb_client
            .current_root_at(latest_location)
            .await
            .expect("current root"),
        expected_root
    );
    assert_eq!(
        qmdb_client
            .root_at(latest_location)
            .await
            .expect("ops root"),
        expected_ops_root
    );
    let proof = qmdb_client
        .key_value_proof_at(latest_location, b"k-00000005".as_slice())
        .await
        .expect("key proof");
    assert_eq!(proof.root, expected_root);
}

#[tokio::test]
async fn test_ordered_mmr_incremental_seed_batches_keep_current_proofs_verifiable() {
    assert_incremental_seed_batches_keep_current_proofs_verifiable::<mmr::Family>(
        "current_ordered_variable_mmr_incremental_seed_source",
    )
    .await;
}

#[tokio::test]
async fn test_ordered_fixed_round_trip() {
    let store_client = common::local_store_client().await;
    let source = build_fixed_source::<mmr::Family>().await;

    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    common::commit_current_operations(
        &upload_client,
        &source.operations,
        &(),
        &source.current_boundary,
    )
    .await
    .expect("commit fixed upload");

    let qmdb_client =
        FixedClient::<mmr::Family>::new(PrefixedStoreClient::empty(store_client.clone()), (), ());
    let watermark = qmdb_client
        .writer_location_watermark()
        .await
        .expect("watermark");
    assert_eq!(watermark, Some(source.latest_location));

    let keys: Vec<Vec<u8>> = source.values.keys().cloned().collect();
    let queried = qmdb_client
        .query_many_at(&keys, source.latest_location)
        .await
        .expect("fixed query_many_at");
    for (key, value) in keys.iter().zip(queried.iter()) {
        assert_eq!(
            value.as_ref().and_then(|value| value.value),
            source.values[key.as_slice()]
        );
    }

    let range = qmdb_client
        .operation_range_proof(
            source.latest_location,
            Location::<mmr::Family>::new(0),
            source.operations.len() as u32,
        )
        .await
        .expect("fixed operation range proof");
    assert_eq!(range.operations, source.operations);

    let current = qmdb_client
        .current_operation_range_proof(
            source.latest_location,
            Location::<mmr::Family>::new(0),
            source.operations.len() as u32,
        )
        .await
        .expect("fixed current operation range proof");
    assert_eq!(current.operations, source.operations);

    let alpha = Sha256::fill(0xA1);
    let one = Sha256::fill(0x01);
    let key_proof = qmdb_client
        .key_value_proof_at(source.latest_location, alpha.as_ref())
        .await
        .expect("fixed key_value_proof_at");
    match &key_proof.operation {
        FixedQmdbOperation::Update(update) => {
            assert_eq!(update.key, alpha);
            assert_eq!(update.value, one);
        }
        _ => panic!("expected fixed Update operation"),
    }
}

#[tokio::test]
async fn test_current_root_at() {
    let store_client = common::local_store_client().await;
    let source = build_variable_source::<mmr::Family>().await;

    upload_source(&store_client, &source).await;

    let qmdb_client = VariableClient::<mmr::Family>::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg::<mmr::Family>(),
        key_cfg(),
    );
    let root = qmdb_client
        .current_root_at(source.latest_location)
        .await
        .expect("current_root_at");
    assert!(!root.as_ref().iter().all(|&b| b == 0));
}

#[tokio::test]
async fn test_current_operation_range_proof() {
    let store_client = common::local_store_client().await;
    let source = build_variable_source::<mmr::Family>().await;

    upload_source(&store_client, &source).await;

    let qmdb_client = VariableClient::<mmr::Family>::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg::<mmr::Family>(),
        key_cfg(),
    );
    let proof = qmdb_client
        .current_operation_range_proof(
            source.latest_location,
            Location::<mmr::Family>::new(0),
            source.operations.len() as u32,
        )
        .await
        .expect("current_operation_range_proof");
    assert_eq!(proof.operations, source.operations);
}

#[tokio::test]
async fn test_key_value_proof() {
    let store_client = common::local_store_client().await;
    let source = build_variable_source::<mmr::Family>().await;

    upload_source(&store_client, &source).await;

    let qmdb_client = VariableClient::<mmr::Family>::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg::<mmr::Family>(),
        key_cfg(),
    );
    let result = qmdb_client
        .key_value_proof_at(source.latest_location, b"alpha".as_slice())
        .await
        .expect("key_value_proof_at");
    match &result.operation {
        QmdbOperation::Update(u) => {
            assert_eq!(u.key, b"alpha".to_vec());
            assert_eq!(u.value, b"one".to_vec());
        }
        _ => panic!("expected Update operation"),
    }
}

#[tokio::test]
async fn test_multi_proof() {
    let store_client = common::local_store_client().await;
    let source = build_variable_source::<mmr::Family>().await;

    upload_source(&store_client, &source).await;

    let qmdb_client = VariableClient::<mmr::Family>::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg::<mmr::Family>(),
        key_cfg(),
    );
    let result = qmdb_client
        .multi_proof_at(
            source.latest_location,
            &[b"alpha".as_slice(), b"beta".as_slice()],
        )
        .await
        .expect("multi_proof_at");
    assert_eq!(result.operations.len(), 2);
}

struct CountingQuery {
    store: std::sync::Arc<exoware_simulator::RocksStore>,
    bitmap_chunks: std::sync::Mutex<BTreeSet<u64>>,
}

impl exoware_server::Sequence for CountingQuery {
    fn current_sequence(&self) -> u64 {
        exoware_server::Sequence::current_sequence(self.store.as_ref())
    }
}

impl exoware_server::Query for CountingQuery {
    type RangeScan = <exoware_simulator::RocksStore as exoware_server::Query>::RangeScan;

    async fn get(
        &self,
        key: bytes::Bytes,
    ) -> Result<(Option<bytes::Bytes>, exoware_server::QueryExtra), String> {
        exoware_server::Query::get(self.store.as_ref(), key).await
    }

    async fn get_many(
        &self,
        keys: Vec<bytes::Bytes>,
    ) -> Result<
        (
            Vec<(bytes::Bytes, Option<bytes::Bytes>)>,
            exoware_server::QueryExtra,
        ),
        String,
    > {
        exoware_server::Query::get_many(self.store.as_ref(), keys).await
    }

    async fn range_scan(
        &self,
        start: bytes::Bytes,
        end: bytes::Bytes,
        limit: usize,
        forward: bool,
    ) -> Result<Self::RangeScan, String> {
        // A chunk row key is the chunk family byte, the u64 chunk index, then the u64 boundary location
        if start.first() == Some(&exoware_qmdb::CHUNK_FAMILY) && start.len() == 17 {
            self.bitmap_chunks
                .lock()
                .unwrap()
                .insert(u64::from_be_bytes(start[1..9].try_into().unwrap()));
        }
        exoware_server::Query::range_scan(self.store.as_ref(), start, end, limit, forward).await
    }
}

async fn assert_point_proof_reads_bounded_bitmap_chunks<F: Graftable>() {
    let store = std::sync::Arc::new(
        exoware_simulator::RocksStore::open_owned(tempfile::tempdir().unwrap(), None).unwrap(),
    );
    let query = std::sync::Arc::new(CountingQuery {
        store: store.clone(),
        bitmap_chunks: Default::default(),
    });
    let (store_server, store_url) = common::spawn_connect_service(exoware_server::connect_stack(
        exoware_server::AppState::new(store),
    ))
    .await;
    let (query_server, query_url) = common::spawn_connect_service(exoware_server::query_service(
        exoware_server::QueryState::new(query.clone()),
    ))
    .await;
    let store_client = StoreClient::builder()
        .url(&store_url)
        .query_url(&query_url)
        .build()
        .unwrap();
    let source = build_variable_source_with_write_count::<F, N>(
        "current_ordered_variable_bounded_bitmap_source",
        2048,
    )
    .await;
    assert!(source.operations.len() / (N * 8) > 3);
    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    common::commit_current_operations(
        &upload_client,
        &source.operations,
        &op_cfg::<F>(),
        &source.current_boundary,
    )
    .await
    .unwrap();
    let qmdb_client: VariableClient<F> = OrderedClient::new(
        PrefixedStoreClient::empty(store_client),
        op_cfg::<F>(),
        key_cfg(),
    );
    query.bitmap_chunks.lock().unwrap().clear();
    let proof = qmdb_client
        .key_value_proof_raw_at(source.latest_location, b"k-00000007")
        .await
        .unwrap();
    assert_eq!(proof.root, source.current_boundary.root);
    assert!(proof.verify::<Sha256>());
    let chunks = query.bitmap_chunks.lock().unwrap().clone();
    assert!(
        chunks.len() <= 3,
        "point proof fetched unrelated bitmap chunks: {chunks:?}"
    );
    store_server.abort();
    query_server.abort();
}

#[tokio::test]
async fn test_ordered_mmr_point_proof_reads_bounded_bitmap_chunks() {
    assert_point_proof_reads_bounded_bitmap_chunks::<mmr::Family>().await;
}

#[tokio::test]
async fn test_ordered_mmb_point_proof_reads_bounded_bitmap_chunks() {
    assert_point_proof_reads_bounded_bitmap_chunks::<mmb::Family>().await;
}

async fn assert_current_boundaries_survive_coalesced_publication<F>()
where
    F: Graftable,
    BatchOperation<F>: commonware_codec::Codec + Clone,
{
    use commonware_codec::Encode as _;
    use commonware_parallel::Sequential;
    use exoware_qmdb::{
        prepare_authenticated_range, stage_authenticated_range, stage_watermark,
        AuthenticatedOperationRange,
    };
    use exoware_sdk::StoreWriteBatch;

    let prepared_boundaries = tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};

            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::current_variable_config(
                "current_ordered_variable_coalesced_source",
                page_cache,
                op_cfg::<F>(),
                NZU64!(8),
            );
            let mut db: VariableDb<F> = VariableDb::init(
                context.child("current_ordered_variable_coalesced_source"),
                cfg,
            )
            .await
            .expect("init source current DB");
            let mut previous_operations = Vec::<BatchOperation<F>>::new();
            let mut prepared_boundaries = Vec::new();
            for (batch_index, value) in [b"one".to_vec(), b"updated".to_vec()]
                .into_iter()
                .enumerate()
            {
                let start = Location::new(previous_operations.len() as u64);
                let mut batch = db
                    .new_batch()
                    .write(b"alpha".to_vec(), Some(value.clone()))
                    .write(b"beta".to_vec(), Some(b"stable".to_vec()));
                for index in 0..300 {
                    let index = batch_index * 300 + index;
                    batch = batch.write(
                        format!("k-{index:08}").into_bytes(),
                        Some(format!("v-{index:08}").into_bytes()),
                    );
                }
                let batch = batch
                    .merkleize(&db, None::<Vec<u8>>)
                    .await
                    .expect("merkleize source batch");
                (db, _) = db.apply_batch(batch).await.expect("apply source batch");
                let end = db.bounds().end;
                let latest = end - 1;
                let expected_root = db.root();
                let expected_ops_root = db.ops_root();
                assert!(*end / (N * 8) as u64 > *start / (N * 8) as u64);
                assert_eq!(
                    db.get(&b"alpha".to_vec()).await.unwrap(),
                    Some(value.clone())
                );
                let (proof, operations) = db
                    .ops_historical_proof(
                        end,
                        start,
                        NonZeroU64::new(*end - *start).expect("source has new operations"),
                    )
                    .await
                    .expect("source operation proof");
                let pinned_nodes = db
                    .pinned_nodes_at(start)
                    .await
                    .expect("source pinned nodes");
                let mut cumulative_operations = previous_operations.clone();
                cumulative_operations.extend(operations.iter().cloned());
                let previous = if previous_operations.is_empty() {
                    None
                } else {
                    Some(previous_operations.as_slice())
                };
                let boundary = boundary_from_source_db(&db, previous, &cumulative_operations).await;
                if batch_index == 1 {
                    assert!(start > Location::new(0));
                    assert!(!pinned_nodes.is_empty());
                    assert!(!boundary.grafted_nodes.is_empty());
                }

                // Include bootstrap in the first range and use the native proof and pins for the continuation
                let encoded = operations
                    .iter()
                    .map(|operation| operation.encode().to_vec())
                    .collect::<Vec<_>>();
                let authenticated = AuthenticatedOperationRange {
                    start_location: start,
                    proof: &proof,
                    pinned_nodes: &pinned_nodes,
                    encoded_operations: &encoded,
                };
                let prepared = prepare_authenticated_range::<F, Sha256, BatchOperation<F>, _>(
                    &authenticated,
                    &expected_ops_root,
                    &op_cfg::<F>(),
                    &Sequential,
                )
                .expect("authenticate source operation range")
                .with_current_boundary::<Sha256, N>(&boundary)
                .expect("attach authenticated source current boundary");
                prepared_boundaries.push((latest, expected_root, value, prepared));
                previous_operations = cumulative_operations;
            }
            db.destroy().await.expect("destroy source DB");
            prepared_boundaries
        })
    })
    .await
    .expect("join source DB");

    let store_client = common::local_store_client().await;
    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    let qmdb_client: VariableClient<F> =
        OrderedClient::new(upload_client.clone(), op_cfg::<F>(), key_cfg());
    let mut expected_boundaries = Vec::new();
    for (latest, root, value, prepared) in prepared_boundaries {
        let mut batch = StoreWriteBatch::new();
        stage_authenticated_range(&upload_client, prepared, &mut batch)
            .expect("stage current range without publishing");
        batch
            .commit(&store_client)
            .await
            .expect("persist current range");
        expected_boundaries.push((latest, root, value));
    }
    assert_eq!(qmdb_client.writer_location_watermark().await.unwrap(), None);
    for (boundary, _, _) in &expected_boundaries {
        assert!(matches!(
            qmdb_client.current_root_at(*boundary).await,
            Err(exoware_qmdb::QmdbError::WatermarkTooLow { requested, available: 0 })
                if requested == boundary.as_u64()
        ));
    }

    // Publish once after both prefixes and their versioned current boundary rows are durable
    let latest = expected_boundaries.last().unwrap().0;
    let mut publication = StoreWriteBatch::new();
    stage_watermark(&upload_client, latest, &mut publication).expect("stage final watermark");
    publication
        .commit(&store_client)
        .await
        .expect("publish final watermark");
    assert_eq!(
        qmdb_client.writer_location_watermark().await.unwrap(),
        Some(latest)
    );

    for (boundary, expected_root, expected_value) in expected_boundaries {
        let root = qmdb_client
            .current_root_at(boundary)
            .await
            .unwrap_or_else(|error| {
                panic!("current root at uploaded boundary {boundary}: {error}")
            });
        assert_eq!(root, expected_root);
        let proof = qmdb_client
            .key_value_proof_raw_at(boundary, b"alpha".as_slice())
            .await
            .unwrap_or_else(|error| {
                panic!("current proof at uploaded boundary {boundary}: {error}")
            });
        assert_eq!(proof.root, expected_root);
        assert!(proof.verify::<Sha256>());
        match proof.operation {
            BatchOperation::Update(update) => {
                assert_eq!(update.key, b"alpha".to_vec());
                assert_eq!(update.value, expected_value);
            }
            _ => panic!("expected alpha's update operation"),
        }
    }
}

#[tokio::test]
async fn test_ordered_mmr_current_boundaries_survive_coalesced_publication() {
    assert_current_boundaries_survive_coalesced_publication::<mmr::Family>().await;
}

#[tokio::test]
async fn test_ordered_mmb_current_boundaries_survive_coalesced_publication() {
    assert_current_boundaries_survive_coalesced_publication::<mmb::Family>().await;
}
