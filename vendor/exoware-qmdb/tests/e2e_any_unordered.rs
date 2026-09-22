//! Unordered QMDB E2E: run a local Commonware unordered DB, upload its
//! operations to a live store stack, then verify roots and proofs match.

mod common;

use std::num::NonZeroU64;

use commonware_cryptography::Sha256;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::Runner as _;
use commonware_storage::journal::contiguous::fixed::Config as FixedJournalConfig;
use commonware_storage::merkle::{mmr, Location, Proof};
use commonware_storage::qmdb::any::unordered::fixed::{
    Db as LocalFixedUnorderedDb, Operation as FixedUnorderedOperation,
};
use commonware_storage::qmdb::any::unordered::variable::Db as LocalUnorderedDb;
use commonware_storage::qmdb::any::unordered::variable::Operation as UnorderedQmdbOperation;
use commonware_storage::qmdb::any::value::FixedEncoding;
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::{UnorderedClient, MAX_OPERATION_SIZE};
use exoware_sdk::PrefixedStoreClient;

type Digest = commonware_cryptography::sha256::Digest;
type BatchProof = Proof<mmr::Family, Digest>;
type UnorderedBatchOperation = UnorderedQmdbOperation<mmr::Family, Vec<u8>, Vec<u8>>;
type FixedUnorderedBatchOperation = FixedUnorderedOperation<mmr::Family, Digest, Digest>;
type VariableClient = UnorderedClient<mmr::Family, Sha256, Vec<u8>, Vec<u8>>;
type FixedClient = UnorderedClient<mmr::Family, Sha256, Digest, Digest, FixedEncoding<Digest>>;
type VariableDb = LocalUnorderedDb<
    mmr::Family,
    cw_tokio::Context,
    Vec<u8>,
    Vec<u8>,
    Sha256,
    TwoCap,
    commonware_parallel::Sequential,
>;
type FixedDb = LocalFixedUnorderedDb<
    mmr::Family,
    cw_tokio::Context,
    Digest,
    Digest,
    Sha256,
    TwoCap,
    commonware_parallel::Sequential,
>;

fn op_cfg() -> <UnorderedBatchOperation as commonware_codec::Read>::Cfg {
    (
        ((0..=MAX_OPERATION_SIZE).into(), ()),
        ((0..=MAX_OPERATION_SIZE).into(), ()),
    )
}

struct VariableSource {
    latest_location: Location<mmr::Family>,
    operations: Vec<UnorderedBatchOperation>,
    values: std::collections::BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

struct FixedSource {
    latest_location: Location<mmr::Family>,
    operations: Vec<FixedUnorderedBatchOperation>,
    values: std::collections::BTreeMap<Vec<u8>, Option<Digest>>,
}

async fn build_variable_source() -> VariableSource {
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::any_variable_config(
                "any_unordered_variable_mmr_source",
                page_cache,
                (
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                ),
                NZU64!(8),
            );
            let mut db: VariableDb =
                VariableDb::init(context.child("any_unordered_variable_mmr_source"), cfg)
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
            let (_proof, ops): (BatchProof, Vec<UnorderedBatchOperation>) = db
                .historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");

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
                values,
            }
        })
    })
    .await
    .expect("join")
}

async fn build_fixed_source() -> FixedSource {
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = commonware_storage::qmdb::any::Config {
                merkle_config: common::merkle_config(
                    "any_unordered_fixed_mmr_source",
                    page_cache.clone(),
                ),
                journal_config: FixedJournalConfig {
                    partition: "any_unordered_fixed_mmr_source-log".to_string(),
                    items_per_blob: NZU64!(8),
                    page_cache,
                    write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                },
                translator: TwoCap,
                init_cache_size: None,
                init_buffer: NZUsize!(1 << 21),
                init_concurrency: (),
            };
            let mut db: FixedDb =
                FixedDb::init(context.child("any_unordered_fixed_mmr_source"), cfg)
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
                    .expect("merkleize fixed")
            };
            (db, _) = db.apply_batch(finalized).await.expect("apply fixed");

            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops): (BatchProof, Vec<FixedUnorderedBatchOperation>) = db
                .historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("fixed proof");

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
                values,
            }
        })
    })
    .await
    .expect("join")
}

#[tokio::test]
async fn test_unordered_round_trip() {
    let store_client = common::local_store_client().await;
    let source = build_variable_source().await;

    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    common::commit_operations::<mmr::Family, _>(&upload_client, &source.operations, &op_cfg())
        .await
        .expect("commit upload");

    let qmdb_client =
        VariableClient::new(PrefixedStoreClient::empty(store_client.clone()), op_cfg());
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
            Location::new(0),
            source.operations.len() as u32,
        )
        .await
        .expect("proof");
    assert_eq!(proof.operations, source.operations);
}

#[tokio::test]
async fn test_unordered_fixed_round_trip() {
    let store_client = common::local_store_client().await;
    let source = build_fixed_source().await;

    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    common::commit_operations::<mmr::Family, _>(&upload_client, &source.operations, &())
        .await
        .expect("commit fixed upload");

    let qmdb_client = FixedClient::new(PrefixedStoreClient::empty(store_client.clone()), ());
    let watermark = qmdb_client
        .writer_location_watermark()
        .await
        .expect("watermark");
    assert_eq!(watermark, Some(source.latest_location));

    let keys: Vec<Vec<u8>> = source.values.keys().cloned().collect();
    let queried = qmdb_client
        .query_many_at(&keys, source.latest_location)
        .await
        .expect("query_many_at fixed");
    for (key, value) in keys.iter().zip(queried.iter()) {
        assert_eq!(
            value.as_ref().and_then(|value| value.value),
            source.values[key.as_slice()]
        );
    }

    let proof = qmdb_client
        .operation_range_proof(
            source.latest_location,
            Location::new(0),
            source.operations.len() as u32,
        )
        .await
        .expect("fixed proof");
    assert_eq!(proof.operations, source.operations);
}
