//! Immutable QMDB E2E: run a local Commonware immutable DB, upload its
//! operations to a live store stack, then verify roots and proofs match.

mod common;

use std::num::NonZeroU64;

use commonware_runtime::{deterministic, Runner as _};
use commonware_storage::journal::contiguous::fixed::Config as FixedJournalConfig;
use commonware_storage::merkle::{mmr, Location};
use commonware_storage::qmdb::any::value::FixedEncoding;
use commonware_storage::qmdb::immutable::fixed::{
    Db as FixedImmutable, Operation as FixedImmutableOperation,
};
use commonware_storage::qmdb::immutable::variable::{
    Db as Immutable, Operation as ImmutableOperation,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use exoware_qmdb::ImmutableClient;
use exoware_sdk::{PrefixedStoreClient, StoreClient};

use common::retry;

type Digest = commonware_cryptography::sha256::Digest;
type VariableDb = Immutable<
    mmr::Family,
    deterministic::Context,
    Vec<u8>,
    Vec<u8>,
    commonware_cryptography::Sha256,
    TwoCap,
    commonware_parallel::Sequential,
>;
type FixedDb = FixedImmutable<
    mmr::Family,
    deterministic::Context,
    FixedBytes<32>,
    Digest,
    commonware_cryptography::Sha256,
    TwoCap,
    commonware_parallel::Sequential,
>;

type VariableClient =
    ImmutableClient<mmr::Family, commonware_cryptography::Sha256, Vec<u8>, Vec<u8>>;
type FixedClient = ImmutableClient<
    mmr::Family,
    commonware_cryptography::Sha256,
    FixedBytes<32>,
    Digest,
    FixedEncoding<Digest>,
>;

fn variable_client(store_client: StoreClient) -> VariableClient {
    VariableClient::new(
        PrefixedStoreClient::empty(store_client),
        (((0..=10000).into(), ()), ((0..=10000).into(), ())),
    )
}

fn fixed_client(store_client: StoreClient) -> FixedClient {
    FixedClient::new(PrefixedStoreClient::empty(store_client), ())
}

struct VariableSource {
    latest_location: Location<mmr::Family>,
    root: Digest,
    operations: Vec<ImmutableOperation<mmr::Family, Vec<u8>, Vec<u8>>>,
    queried_key: Vec<u8>,
    queried_value: Vec<u8>,
}

struct FixedSource {
    latest_location: Location<mmr::Family>,
    root: Digest,
    operations: Vec<FixedImmutableOperation<mmr::Family, FixedBytes<32>, Digest>>,
    queried_key: FixedBytes<32>,
    queried_value: Digest,
}

async fn build_variable_source() -> VariableSource {
    tokio::task::spawn_blocking(|| {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::immutable_variable_config(
                "immutable_variable_full_mmr_source",
                page_cache,
                (((0..=10000).into(), ()), ((0..=10000).into(), ())),
                NZU64!(5),
            );
            let mut db: VariableDb =
                VariableDb::init(context.child("immutable_variable_full_mmr_source"), cfg)
                    .await
                    .expect("init");

            let key_a = b"a".to_vec();
            let key_b = b"a\0".to_vec();
            let val_a = b"alpha".to_vec();
            let val_b = b"beta".to_vec();

            let finalized = {
                let batch = db
                    .new_batch()
                    .set(key_a, val_a)
                    .set(key_b.clone(), val_b.clone());
                batch
                    .merkleize(&db, None::<Vec<u8>>, db.inactivity_floor_loc())
                    .await
            };
            (db, _) = db.apply_batch(finalized).await.expect("apply");

            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .historical_proof(latest + 1, Location::<mmr::Family>::new(0), n)
                .await
                .expect("proof");
            let root = db.root();
            db.destroy().await.expect("destroy");

            VariableSource {
                latest_location: latest,
                root,
                operations: ops,
                queried_key: key_b,
                queried_value: val_b,
            }
        })
    })
    .await
    .expect("join")
}

async fn build_fixed_source() -> FixedSource {
    tokio::task::spawn_blocking(|| {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = commonware_storage::qmdb::immutable::Config {
                merkle_config: common::merkle_config(
                    "immutable_fixed_full_mmr_source",
                    page_cache.clone(),
                ),
                log: FixedJournalConfig {
                    partition: "immutable_fixed_full_mmr_source-log".to_string(),
                    items_per_blob: NZU64!(5),
                    page_cache,
                    write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                },
                translator: TwoCap,
                init_buffer: NZUsize!(1 << 21),
            };
            let mut db: FixedDb =
                FixedDb::init(context.child("immutable_fixed_full_mmr_source"), cfg)
                    .await
                    .expect("init fixed");

            let key_a = FixedBytes::new([0x11; 32]);
            let key_b = FixedBytes::new([0x22; 32]);
            let val_a = commonware_cryptography::Sha256::fill(0xA1);
            let val_b = commonware_cryptography::Sha256::fill(0xB2);

            let finalized = {
                let batch = db.new_batch().set(key_a, val_a).set(key_b.clone(), val_b);
                batch
                    .merkleize(&db, None::<Digest>, db.inactivity_floor_loc())
                    .await
            };
            (db, _) = db.apply_batch(finalized).await.expect("apply fixed");

            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .historical_proof(latest + 1, Location::<mmr::Family>::new(0), n)
                .await
                .expect("fixed proof");
            let root = db.root();
            db.destroy().await.expect("destroy fixed");

            FixedSource {
                latest_location: latest,
                root,
                operations: ops,
                queried_key: key_b,
                queried_value: val_b,
            }
        })
    })
    .await
    .expect("join")
}

#[tokio::test]
async fn test_immutable_round_trip() {
    let store_client = common::local_store_client().await;
    let source = build_variable_source().await;

    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    common::commit_operations::<mmr::Family, _>(
        &upload_client,
        &source.operations,
        &(((0..=10000).into(), ()), ((0..=10000).into(), ())),
    )
    .await
    .expect("commit upload");

    let root = retry(
        || {
            let qmdb_client = variable_client(store_client.clone());
            let loc = source.latest_location;
            async move { qmdb_client.root_at(loc).await }
        },
        "root_at",
    )
    .await;
    assert_eq!(root, source.root, "remote root must match local DB root");

    let qmdb_client = variable_client(store_client.clone());
    let got = qmdb_client
        .get_at(&source.queried_key, source.latest_location)
        .await
        .expect("get_at")
        .expect("present");
    assert_eq!(got.key, source.queried_key);
    assert_eq!(got.value, Some(source.queried_value.clone()));
    assert_eq!(
        qmdb_client
            .get_at(&b"a".to_vec(), source.latest_location)
            .await
            .expect("prefix key")
            .expect("present")
            .value,
        Some(b"alpha".to_vec()),
    );
    assert!(qmdb_client
        .get_at(&b"a\0\0".to_vec(), source.latest_location)
        .await
        .expect("missing key")
        .is_none());

    let proof = qmdb_client
        .operation_range_proof(
            source.latest_location,
            Location::<mmr::Family>::new(0),
            source.operations.len() as u32,
        )
        .await
        .expect("proof");
    assert_eq!(proof.root, source.root);
    assert_eq!(proof.operations, source.operations);
}

#[tokio::test]
async fn test_immutable_fixed_round_trip() {
    let store_client = common::local_store_client().await;
    let source = build_fixed_source().await;

    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    common::commit_operations::<mmr::Family, _>(&upload_client, &source.operations, &())
        .await
        .expect("commit fixed upload");

    let root = retry(
        || {
            let qmdb_client = fixed_client(store_client.clone());
            let loc = source.latest_location;
            async move { qmdb_client.root_at(loc).await }
        },
        "fixed root_at",
    )
    .await;
    assert_eq!(
        root, source.root,
        "remote root must match local fixed DB root"
    );

    let qmdb_client = fixed_client(store_client.clone());
    let got = qmdb_client
        .get_at(&source.queried_key, source.latest_location)
        .await
        .expect("fixed get_at")
        .expect("present");
    assert_eq!(got.key, source.queried_key);
    assert_eq!(got.value, Some(source.queried_value));

    let proof = qmdb_client
        .operation_range_proof(
            source.latest_location,
            Location::<mmr::Family>::new(0),
            source.operations.len() as u32,
        )
        .await
        .expect("fixed proof");
    assert_eq!(proof.root, source.root);
    assert_eq!(proof.operations, source.operations);
}
