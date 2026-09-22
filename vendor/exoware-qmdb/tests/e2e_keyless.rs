//! Keyless QMDB E2E: run a local Commonware keyless DB, upload its
//! operations to a live store stack, then verify roots and proofs match.

mod common;

use std::num::NonZeroU64;

use commonware_runtime::{deterministic, Runner as _};
use commonware_storage::journal::contiguous::fixed::Config as FixedJournalConfig;
use commonware_storage::merkle::{mmb, mmr, Family, Graftable, Location};
use commonware_storage::qmdb::any::value::FixedEncoding;
use commonware_storage::qmdb::keyless::fixed::{
    Db as FixedKeyless, Operation as FixedKeylessOperation,
};
use commonware_storage::qmdb::keyless::variable::{Db as Keyless, Operation as KeylessOperation};
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::KeylessClient;
use exoware_sdk::{PrefixedStoreClient, StoreClient};

use common::retry;

type Digest = commonware_cryptography::sha256::Digest;
type VariableDb<F> = Keyless<
    F,
    deterministic::Context,
    Vec<u8>,
    commonware_cryptography::Sha256,
    commonware_parallel::Sequential,
>;
type FixedDb<F> = FixedKeyless<
    F,
    deterministic::Context,
    Digest,
    commonware_cryptography::Sha256,
    commonware_parallel::Sequential,
>;

type VariableClient<F> = KeylessClient<F, commonware_cryptography::Sha256, Vec<u8>>;
type FixedClient<F> =
    KeylessClient<F, commonware_cryptography::Sha256, Digest, FixedEncoding<Digest>>;

fn variable_client<F: Graftable>(store_client: StoreClient) -> VariableClient<F> {
    VariableClient::new(
        PrefixedStoreClient::empty(store_client),
        ((0..=10000).into(), ()),
    )
}

fn fixed_client<F: Graftable>(store_client: StoreClient) -> FixedClient<F>
where
    FixedKeylessOperation<F, Digest>: commonware_codec::Read<Cfg = ()>,
{
    FixedClient::new(PrefixedStoreClient::empty(store_client), ())
}

struct VariableSource<F: Family> {
    latest_location: Location<F>,
    root: Digest,
    operations: Vec<KeylessOperation<F, Vec<u8>>>,
    continuation_operations: Vec<KeylessOperation<F, Vec<u8>>>,
    continued_latest_location: Location<F>,
    continued_root: Digest,
    queried_location: Location<F>,
    queried_value: Vec<u8>,
}

struct FixedSource<F: Family> {
    latest_location: Location<F>,
    root: Digest,
    operations: Vec<FixedKeylessOperation<F, Digest>>,
    queried_location: Location<F>,
    queried_value: Digest,
}

async fn build_variable_source<F: Family>() -> VariableSource<F>
where
    KeylessOperation<F, Vec<u8>>:
        commonware_codec::Codec<Cfg = <Vec<u8> as commonware_codec::Read>::Cfg> + Clone,
{
    tokio::task::spawn_blocking(|| {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::keyless_variable_config(
                "keyless_variable_full_source",
                page_cache,
                ((0..=10000).into(), ()),
                NZU64!(7),
            );
            let mut db: VariableDb<F> =
                VariableDb::init(context.child("keyless_variable_full_source"), cfg)
                    .await
                    .expect("init");

            let first = b"first-value".to_vec();
            let second = b"second-value".to_vec();
            let third = b"third-value".to_vec();
            let fourth = b"fourth-value".to_vec();
            let finalized = {
                let batch = db
                    .new_batch()
                    .append(first.clone())
                    .append(second)
                    .append(third)
                    .append(fourth)
                    .append(b"fifth-value".to_vec())
                    .append(b"sixth-value".to_vec())
                    .append(b"seventh-value".to_vec());
                batch
                    .merkleize(&db, None::<Vec<u8>>, db.inactivity_floor_loc())
                    .await
            };
            (db, _) = db.apply_batch(finalized).await.expect("apply");

            let finalized = {
                let batch = db.new_batch().append(b"eighth-value".to_vec());
                batch
                    .merkleize(&db, None::<Vec<u8>>, db.bounds().end - 1)
                    .await
            };
            (db, _) = db.apply_batch(finalized).await.expect("apply second");

            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .historical_proof(latest + 1, Location::<F>::new(0), n)
                .await
                .expect("proof");
            let root = db.root();

            let finalized = {
                let batch = db.new_batch().append(b"ninth-value".to_vec());
                batch
                    .merkleize(&db, None::<Vec<u8>>, db.bounds().end - 1)
                    .await
            };
            (db, _) = db.apply_batch(finalized).await.expect("apply third");

            let continued_latest_location = db.bounds().end - 1;
            let n = NonZeroU64::new(*continued_latest_location + 1).unwrap();
            let (_proof, all_operations) = db
                .historical_proof(continued_latest_location + 1, Location::<F>::new(0), n)
                .await
                .expect("continued proof");
            let continuation_operations = all_operations[ops.len()..].to_vec();
            let continued_root = db.root();
            db.destroy().await.expect("destroy");
            let queried_location = ops
                .iter()
                .enumerate()
                .find_map(|(index, operation)| {
                    (operation.clone().into_value() == Some(first.clone()))
                        .then_some(Location::new(index as u64))
                })
                .expect("value location");

            VariableSource {
                latest_location: latest,
                root,
                operations: ops,
                continuation_operations,
                continued_latest_location,
                continued_root,
                queried_location,
                queried_value: first,
            }
        })
    })
    .await
    .expect("join")
}

async fn build_fixed_source<F: Family>() -> FixedSource<F>
where
    FixedKeylessOperation<F, Digest>: commonware_codec::CodecFixed<Cfg = ()> + Clone,
{
    tokio::task::spawn_blocking(|| {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = commonware_storage::qmdb::keyless::Config {
                merkle: common::merkle_config("keyless_fixed_full_source", page_cache.clone()),
                log: FixedJournalConfig {
                    partition: "keyless_fixed_full_source-log".to_string(),
                    items_per_blob: NZU64!(7),
                    page_cache,
                    write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                },
            };
            let mut db: FixedDb<F> = FixedDb::init(context.child("keyless_fixed_full_source"), cfg)
                .await
                .expect("init fixed");

            let first = commonware_cryptography::Sha256::fill(0x11);
            let second = commonware_cryptography::Sha256::fill(0x22);
            let finalized = {
                let batch = db.new_batch().append(first).append(second);
                batch
                    .merkleize(&db, None::<Digest>, db.inactivity_floor_loc())
                    .await
            };
            (db, _) = db.apply_batch(finalized).await.expect("apply fixed");

            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .historical_proof(latest + 1, Location::<F>::new(0), n)
                .await
                .expect("fixed proof");
            let root = db.root();
            db.destroy().await.expect("destroy fixed");
            let queried_location = ops
                .iter()
                .enumerate()
                .find_map(|(index, operation)| {
                    (operation.clone().into_value() == Some(first))
                        .then_some(Location::new(index as u64))
                })
                .expect("fixed value location");

            FixedSource {
                latest_location: latest,
                root,
                operations: ops,
                queried_location,
                queried_value: first,
            }
        })
    })
    .await
    .expect("join")
}

async fn keyless_round_trip_for_family<F: Graftable>()
where
    KeylessOperation<F, Vec<u8>>:
        commonware_codec::Codec<Cfg = <Vec<u8> as commonware_codec::Read>::Cfg> + Clone + PartialEq,
{
    let store_client = common::local_store_client().await;
    let source = build_variable_source::<F>().await;

    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    common::commit_operations::<F, _>(
        &upload_client,
        &source.operations,
        &((0..=10000).into(), ()),
    )
    .await
    .expect("commit upload");

    let root = retry(
        || {
            let qmdb_client = variable_client::<F>(store_client.clone());
            let loc = source.latest_location;
            async move { qmdb_client.root_at(loc).await }
        },
        "root_at",
    )
    .await;
    assert_eq!(root, source.root, "remote root must match local DB root");

    let qmdb_client = variable_client::<F>(store_client.clone());
    let got: Vec<u8> = qmdb_client
        .get_at(source.queried_location, source.latest_location)
        .await
        .expect("get_at")
        .expect("present");
    assert_eq!(got, source.queried_value);

    let proof = qmdb_client
        .operation_range_proof(
            source.latest_location,
            Location::new(0),
            source.operations.len() as u32,
        )
        .await
        .expect("proof");
    assert_eq!(proof.root, source.root);
    assert_eq!(proof.operations, source.operations);

    let checkpoint = qmdb_client
        .operation_range_checkpoint(
            source.latest_location,
            Location::new(0),
            source.operations.len() as u32,
        )
        .await
        .expect("checkpoint");
    assert!(checkpoint.verify::<commonware_cryptography::Sha256>());
    let mut malformed_checkpoint = checkpoint.clone();
    malformed_checkpoint
        .pinned_nodes
        .push(malformed_checkpoint.root);
    assert!(
        !malformed_checkpoint.verify::<commonware_cryptography::Sha256>(),
        "zero-start checkpoints must not verify with pinned nodes"
    );
    assert!(malformed_checkpoint
        .reconstruct_peaks::<commonware_cryptography::Sha256>()
        .is_err());
    let peaks = checkpoint
        .reconstruct_peaks::<commonware_cryptography::Sha256>()
        .expect("reconstruct_peaks");
    let hasher = commonware_storage::qmdb::hasher::<commonware_cryptography::Sha256>();
    let reconstructed_root = commonware_storage::merkle::hasher::Hasher::<F>::root(
        &hasher,
        checkpoint.proof.leaves,
        checkpoint.proof.inactive_peaks,
        peaks.iter().map(|(_, _, digest)| digest),
    )
    .expect("reconstruct root");
    assert_eq!(reconstructed_root, checkpoint.root);

    let suffix_checkpoint = qmdb_client
        .operation_range_checkpoint(source.latest_location, source.latest_location, 1)
        .await
        .expect("suffix checkpoint");
    assert!(suffix_checkpoint.verify::<commonware_cryptography::Sha256>());
    assert!(!suffix_checkpoint.pinned_nodes.is_empty());
    assert!(
        suffix_checkpoint.proof.inactive_peaks > 0,
        "suffix checkpoint must exercise folded inactive peaks"
    );
    let range_digests = suffix_checkpoint
        .proof
        .verify_range_inclusion_and_extract_digests(
            &hasher,
            &suffix_checkpoint.encoded_operations,
            suffix_checkpoint.start_location,
            &suffix_checkpoint.root,
        )
        .expect("verify suffix range");
    assert!(
        peaks
            .iter()
            .any(|(peak, _, _)| !range_digests.iter().any(|(position, _)| position == peak)),
        "suffix checkpoint must exercise a peak omitted by range extraction"
    );
    assert_eq!(
        suffix_checkpoint
            .reconstruct_peaks::<commonware_cryptography::Sha256>()
            .expect("reconstruct suffix peaks"),
        peaks,
    );

    let mut suffix_without_pins = suffix_checkpoint.clone();
    suffix_without_pins.pinned_nodes.clear();
    let mut suffix_with_wrong_pin = suffix_checkpoint.clone();
    suffix_with_wrong_pin.pinned_nodes[0] = suffix_with_wrong_pin.root;
    let mut suffix_with_extra_pin = suffix_checkpoint.clone();
    suffix_with_extra_pin
        .pinned_nodes
        .push(suffix_with_extra_pin.root);
    for malformed in [
        &suffix_without_pins,
        &suffix_with_wrong_pin,
        &suffix_with_extra_pin,
    ] {
        assert!(!malformed.verify::<commonware_cryptography::Sha256>());
        assert!(malformed
            .reconstruct_peaks::<commonware_cryptography::Sha256>()
            .is_err());
    }

    let mut checkpoint_with_wrong_watermark = suffix_checkpoint.clone();
    checkpoint_with_wrong_watermark.watermark -= 1;
    assert!(checkpoint_with_wrong_watermark.verify::<commonware_cryptography::Sha256>());
    assert!(checkpoint_with_wrong_watermark
        .reconstruct_peaks::<commonware_cryptography::Sha256>()
        .is_err());

    let middle_checkpoint = qmdb_client
        .operation_range_checkpoint(source.latest_location, source.latest_location - 1, 1)
        .await
        .expect("middle checkpoint");
    assert!(middle_checkpoint.verify::<commonware_cryptography::Sha256>());
    assert!(middle_checkpoint
        .reconstruct_peaks::<commonware_cryptography::Sha256>()
        .is_err());

    let mut continued_operations = source.operations.clone();
    continued_operations.extend_from_slice(&source.continuation_operations);
    common::commit_operations::<F, _>(
        &upload_client,
        &continued_operations,
        &((0..=10000).into(), ()),
    )
    .await
    .expect("continued upload");
    assert_eq!(
        qmdb_client
            .writer_location_watermark()
            .await
            .expect("continued watermark"),
        Some(source.continued_latest_location),
    );

    let continued_root = retry(
        || {
            let qmdb_client = variable_client::<F>(store_client.clone());
            let loc = source.continued_latest_location;
            async move { qmdb_client.root_at(loc).await }
        },
        "continued root_at",
    )
    .await;
    assert_eq!(continued_root, source.continued_root);
}

#[tokio::test]
async fn test_keyless_fixed_round_trip() {
    let store_client = common::local_store_client().await;
    let source = build_fixed_source::<mmr::Family>().await;

    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    common::commit_operations::<mmr::Family, _>(&upload_client, &source.operations, &())
        .await
        .expect("commit fixed upload");

    let root = retry(
        || {
            let qmdb_client = fixed_client::<mmr::Family>(store_client.clone());
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

    let qmdb_client = fixed_client::<mmr::Family>(store_client.clone());
    let got: Digest = qmdb_client
        .get_at(source.queried_location, source.latest_location)
        .await
        .expect("fixed get_at")
        .expect("present");
    assert_eq!(got, source.queried_value);

    let proof = qmdb_client
        .operation_range_proof(
            source.latest_location,
            Location::new(0),
            source.operations.len() as u32,
        )
        .await
        .expect("fixed proof");
    assert_eq!(proof.root, source.root);
    assert_eq!(proof.operations, source.operations);
}

#[tokio::test]
async fn test_keyless_round_trip() {
    keyless_round_trip_for_family::<mmr::Family>().await;
}

#[tokio::test]
async fn test_keyless_mmb_round_trip() {
    keyless_round_trip_for_family::<mmb::Family>().await;
}
