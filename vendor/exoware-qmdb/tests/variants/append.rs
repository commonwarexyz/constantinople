#![allow(clippy::type_complexity)]

//! Full and compact append-only QMDB sources share the same Store and Connect adapters

use crate::common;

use std::{fmt::Debug, sync::Arc};

use commonware_codec::{Codec, Read};
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner as _, Supervisor as _};
use commonware_storage::{
    journal::contiguous::fixed::Config as FixedJournalConfig,
    merkle::{mmb, mmr, Family, Graftable, Location, Proof},
    qmdb::{
        any::value::{FixedEncoding, ValueEncoding, VariableEncoding},
        immutable, keyless,
        operation::Key as QmdbKey,
        verify_proof_and_pinned_nodes,
    },
    translator::TwoCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use exoware_qmdb::{
    immutable_operation_log_connect_stack, keyless_operation_log_connect_stack,
    prepare_authenticated_range, proto::qmdb::v1::GetOperationRangeRequest,
    stage_authenticated_range, stage_watermark, AuthenticatedOperationRange, ImmutableClient,
    KeylessClient, OperationLogClient, PreparedAuthenticatedRange, QmdbError, UploadOperation,
};
use exoware_sdk::{PrefixedStoreClient, StoreWriteBatch};

type FixedKey = FixedBytes<32>;
type FixedValue = FixedBytes<16>;
type ByteConfig = <Vec<u8> as Read>::Cfg;

struct SourceBatch<F: Family, Op> {
    start: Location<F>,
    operations: Vec<Op>,
    root: Digest,
    proof: Proof<F, Digest>,
    pinned_nodes: Vec<Digest>,
}

struct Source<F: Family, Op> {
    bootstrap: Op,
    bootstrap_root: Digest,
    batches: Vec<SourceBatch<F, Op>>,
}

fn byte_config() -> ByteConfig {
    ((0..=10_000).into(), ())
}

fn fixed_key(index: u8) -> FixedKey {
    FixedBytes::new([index; 32])
}

fn variable_key(index: u8) -> Vec<u8> {
    vec![index; usize::from(index % 3 + 1)]
}

fn fixed_value(index: u8) -> FixedValue {
    FixedBytes::new([index; 16])
}

fn variable_value(index: u8) -> Vec<u8> {
    vec![index; usize::from(index % 5 + 1)]
}

fn page_cache(context: &deterministic::Context) -> CacheRef {
    CacheRef::from_pooler(context, NZU16!(64), NZUsize!(8))
}

fn fixed_journal_config(prefix: &str, cache: CacheRef) -> FixedJournalConfig {
    FixedJournalConfig {
        partition: format!("{prefix}-log"),
        items_per_blob: NZU64!(7),
        page_cache: cache,
        write_buffer: NZUsize!(1024),
        replay_buffer: NZUsize!(1024),
    }
}

fn keyless_fixed_full_config(
    prefix: &str,
    context: &deterministic::Context,
) -> keyless::fixed::Config<Sequential> {
    let cache = page_cache(context);
    keyless::Config {
        merkle: common::merkle_config(prefix, cache.clone()),
        log: fixed_journal_config(prefix, cache),
    }
}

fn immutable_fixed_full_config(
    prefix: &str,
    context: &deterministic::Context,
) -> immutable::fixed::Config<TwoCap, Sequential> {
    let cache = page_cache(context);
    immutable::Config {
        merkle_config: common::merkle_config(prefix, cache.clone()),
        log: fixed_journal_config(prefix, cache),
        translator: TwoCap,
        init_buffer: NZUsize!(1024),
    }
}

fn compact_config<C>(
    prefix: &str,
    context: &deterministic::Context,
    codec: C,
) -> immutable::CompactConfig<C, Sequential> {
    immutable::CompactConfig {
        strategy: Sequential,
        witness: common::variable_journal_config(
            &format!("{prefix}-witness"),
            page_cache(context),
            (),
            NZU64!(7),
        ),
        commit_codec_config: codec,
    }
}

macro_rules! stage_value {
    (immutable, $batch:ident, $index:ident, $key:path, $value:path) => {
        $batch.set($key($index), $value($index))
    };
    (keyless, $batch:ident, $index:ident, $key:path, $value:path) => {
        $batch.append($value($index))
    };
}

// Full and compact batches expose the same operation, root, and proof interfaces
macro_rules! source {
    (
        $name:ident, $family:ident, $operation:ty, $database:ty,
        $config:expr, $kind:ident, $key:path, $value:path
    ) => {
        fn $name<$family: Graftable + Eq>(prefix: &'static str) -> Source<$family, $operation> {
            deterministic::Runner::default().start(move |context| async move {
                let config = ($config)(prefix, &context);
                let mut db: $database = <$database>::init(context.child(prefix), config)
                    .await
                    .expect("initialize Commonware source");
                let bootstrap = <$operation>::Commit(None, Location::new(0));
                let bootstrap_root = db.root();
                let mut next_location = Location::<$family>::new(1);
                let mut index = 1u8;
                let mut batches = Vec::new();

                for (batch_index, count) in [7, 2].into_iter().enumerate() {
                    let floor = next_location - 1;
                    let mut batch = db.new_batch();
                    for _ in 0..count {
                        batch = stage_value!($kind, batch, index, $key, $value);
                        index += 1;
                    }
                    let batch = batch
                        .merkleize(&db, Some($value(200 + batch_index as u8)), floor)
                        .await;
                    let (start, operations) = batch.operations();
                    let root = batch.root();
                    let end = start + operations.len() as u64;
                    assert_eq!(start, next_location);
                    assert_eq!(
                        operations
                            .last()
                            .and_then(|operation| operation.has_floor()),
                        Some(floor)
                    );
                    if batch_index > 0 {
                        assert!(floor > Location::new(0));
                        assert!($family::inactive_peaks(end, floor) > 0);
                    }

                    // Capture and authenticate the source suffix before compact history is discarded
                    let proof = batch.proof(&db).expect("source batch proof");
                    let pinned_nodes = batch.pinned_nodes(&db).expect("source pinned frontier");
                    assert!(verify_proof_and_pinned_nodes::<Sha256, _, _>(
                        &proof,
                        start,
                        &operations,
                        &pinned_nodes,
                        &root,
                    ));
                    batches.push(SourceBatch {
                        start,
                        operations: operations.as_ref().clone(),
                        root,
                        proof,
                        pinned_nodes,
                    });
                    next_location = end;
                    (db, _) = db.apply_batch(batch).await.expect("apply source batch");
                    db = db.commit().await.expect("commit source batch");
                    assert_eq!(db.root(), root);
                }

                db.destroy().await.expect("destroy Commonware source");
                Source {
                    bootstrap,
                    bootstrap_root,
                    batches,
                }
            })
        }
    };
}

source!(
    immutable_fixed_full_fixed_keys_fixed_values_source, F,
    immutable::Operation<F, FixedKey, FixedEncoding<FixedValue>>,
    immutable::fixed::Db<F, deterministic::Context, FixedKey, FixedValue, Sha256, TwoCap, Sequential>,
    immutable_fixed_full_config,
    immutable, fixed_key, fixed_value
);

source!(
    immutable_fixed_compact_fixed_keys_fixed_values_source, F,
    immutable::Operation<F, FixedKey, FixedEncoding<FixedValue>>,
    immutable::fixed::CompactDb<F, deterministic::Context, FixedKey, FixedValue, Sha256, Sequential>,
    |prefix, context| compact_config(prefix, context, ()),
    immutable, fixed_key, fixed_value
);

source!(
    immutable_variable_full_fixed_keys_fixed_values_source, F,
    immutable::Operation<F, FixedKey, VariableEncoding<FixedValue>>,
    immutable::variable::Db<F, deterministic::Context, FixedKey, FixedValue, Sha256, TwoCap, Sequential>,
    |prefix, context| common::immutable_variable_config(
        prefix, page_cache(context), ((), ()), NZU64!(7)
    ),
    immutable, fixed_key, fixed_value
);

source!(
    immutable_variable_compact_fixed_keys_fixed_values_source, F,
    immutable::Operation<F, FixedKey, VariableEncoding<FixedValue>>,
    immutable::variable::CompactDb<F, deterministic::Context, FixedKey, FixedValue, Sha256, ((), ()), Sequential>,
    |prefix, context| compact_config(prefix, context, ((), ())),
    immutable, fixed_key, fixed_value
);

source!(
    immutable_variable_full_fixed_keys_variable_values_source, F,
    immutable::Operation<F, FixedKey, VariableEncoding<Vec<u8>>>,
    immutable::variable::Db<F, deterministic::Context, FixedKey, Vec<u8>, Sha256, TwoCap, Sequential>,
    |prefix, context| common::immutable_variable_config(
        prefix, page_cache(context), ((), byte_config()), NZU64!(7)
    ),
    immutable, fixed_key, variable_value
);

source!(
    immutable_variable_compact_fixed_keys_variable_values_source, F,
    immutable::Operation<F, FixedKey, VariableEncoding<Vec<u8>>>,
    immutable::variable::CompactDb<F, deterministic::Context, FixedKey, Vec<u8>, Sha256, ((), ByteConfig), Sequential>,
    |prefix, context| compact_config(prefix, context, ((), byte_config())),
    immutable, fixed_key, variable_value
);

source!(
    immutable_variable_full_variable_keys_fixed_values_source, F,
    immutable::Operation<F, Vec<u8>, VariableEncoding<FixedValue>>,
    immutable::variable::Db<F, deterministic::Context, Vec<u8>, FixedValue, Sha256, TwoCap, Sequential>,
    |prefix, context| common::immutable_variable_config(
        prefix, page_cache(context), (byte_config(), ()), NZU64!(7)
    ),
    immutable, variable_key, fixed_value
);

source!(
    immutable_variable_compact_variable_keys_fixed_values_source, F,
    immutable::Operation<F, Vec<u8>, VariableEncoding<FixedValue>>,
    immutable::variable::CompactDb<F, deterministic::Context, Vec<u8>, FixedValue, Sha256, (ByteConfig, ()), Sequential>,
    |prefix, context| compact_config(prefix, context, (byte_config(), ())),
    immutable, variable_key, fixed_value
);

source!(
    immutable_variable_full_variable_keys_variable_values_source, F,
    immutable::Operation<F, Vec<u8>, VariableEncoding<Vec<u8>>>,
    immutable::variable::Db<F, deterministic::Context, Vec<u8>, Vec<u8>, Sha256, TwoCap, Sequential>,
    |prefix, context| common::immutable_variable_config(
        prefix, page_cache(context), (byte_config(), byte_config()), NZU64!(7)
    ),
    immutable, variable_key, variable_value
);

source!(
    immutable_variable_compact_variable_keys_variable_values_source, F,
    immutable::Operation<F, Vec<u8>, VariableEncoding<Vec<u8>>>,
    immutable::variable::CompactDb<F, deterministic::Context, Vec<u8>, Vec<u8>, Sha256, (ByteConfig, ByteConfig), Sequential>,
    |prefix, context| compact_config(prefix, context, (byte_config(), byte_config())),
    immutable, variable_key, variable_value
);

source!(
    keyless_fixed_full_fixed_values_source, F,
    keyless::Operation<F, FixedEncoding<FixedValue>>,
    keyless::fixed::Db<F, deterministic::Context, FixedValue, Sha256, Sequential>,
    keyless_fixed_full_config,
    keyless, fixed_key, fixed_value
);

source!(
    keyless_fixed_compact_fixed_values_source, F,
    keyless::Operation<F, FixedEncoding<FixedValue>>,
    keyless::fixed::CompactDb<F, deterministic::Context, FixedValue, Sha256, Sequential>,
    |prefix, context| compact_config(prefix, context, ()),
    keyless, fixed_key, fixed_value
);

source!(
    keyless_variable_full_fixed_values_source, F,
    keyless::Operation<F, VariableEncoding<FixedValue>>,
    keyless::variable::Db<F, deterministic::Context, FixedValue, Sha256, Sequential>,
    |prefix, context| common::keyless_variable_config(
        prefix, page_cache(context), (), NZU64!(7)
    ),
    keyless, fixed_key, fixed_value
);

source!(
    keyless_variable_compact_fixed_values_source, F,
    keyless::Operation<F, VariableEncoding<FixedValue>>,
    keyless::variable::CompactDb<F, deterministic::Context, FixedValue, Sha256, (), Sequential>,
    |prefix, context| compact_config(prefix, context, ()),
    keyless, fixed_key, fixed_value
);

source!(
    keyless_variable_full_variable_values_source, F,
    keyless::Operation<F, VariableEncoding<Vec<u8>>>,
    keyless::variable::Db<F, deterministic::Context, Vec<u8>, Sha256, Sequential>,
    |prefix, context| common::keyless_variable_config(
        prefix, page_cache(context), byte_config(), NZU64!(7)
    ),
    keyless, fixed_key, variable_value
);

source!(
    keyless_variable_compact_variable_values_source, F,
    keyless::Operation<F, VariableEncoding<Vec<u8>>>,
    keyless::variable::CompactDb<F, deterministic::Context, Vec<u8>, Sha256, ByteConfig, Sequential>,
    |prefix, context| compact_config(prefix, context, byte_config()),
    keyless, fixed_key, variable_value
);

async fn publish<F: Family>(
    client: &PrefixedStoreClient,
    prepared: PreparedAuthenticatedRange<Digest, F>,
    latest: Location<F>,
) {
    assert_eq!(prepared.latest_location(), latest);
    let mut data = StoreWriteBatch::new();
    stage_authenticated_range(client, prepared, &mut data)
        .expect("stage authenticated source range");
    data.commit(client.client())
        .await
        .expect("persist source proof rows");
    let mut publication = StoreWriteBatch::new();
    stage_watermark::<F>(client, latest, &mut publication)
        .expect("stage published source boundary");
    publication
        .commit(client.client())
        .await
        .expect("publish source boundary");
}

async fn publish_source_batch<F, Op>(
    client: &PrefixedStoreClient,
    batch: &SourceBatch<F, Op>,
    codec: &Op::Cfg,
) where
    F: Family,
    Op: UploadOperation<F>,
{
    let encoded_operations = batch
        .operations
        .iter()
        .map(|op| op.encode().to_vec())
        .collect::<Vec<_>>();
    let range = AuthenticatedOperationRange {
        start_location: batch.start,
        proof: &batch.proof,
        pinned_nodes: &batch.pinned_nodes,
        encoded_operations: &encoded_operations,
    };
    let mut wrong_root = batch.root;
    wrong_root.0[0] ^= 1;
    assert!(prepare_authenticated_range::<F, Sha256, Op, Sequential>(
        &range,
        &wrong_root,
        codec,
        &Sequential,
    )
    .is_err());
    let prepared = prepare_authenticated_range::<F, Sha256, Op, Sequential>(
        &range,
        &batch.root,
        codec,
        &Sequential,
    )
    .expect("prepare captured Commonware batch proof");
    let latest = batch.proof.leaves - 1;
    assert_eq!(latest, batch.start + batch.operations.len() as u64 - 1);
    publish(client, prepared, latest).await;
}

async fn check_connect<F, Op>(
    case_name: &str,
    url: &str,
    codec: Op::Cfg,
    batch: &SourceBatch<F, Op>,
    all_operations: &[Op],
    is_final_batch: bool,
) where
    F: Graftable + Eq,
    Op: Codec + Clone + Debug + PartialEq,
{
    let client = OperationLogClient::<_, F, Sha256, Op>::plaintext(url, codec);
    let latest = batch.start + batch.operations.len() as u64 - 1;
    let suffix = GetOperationRangeRequest {
        tip: latest.as_u64(),
        start_location: batch.start.as_u64(),
        max_locations: batch.operations.len() as u32,
        ..Default::default()
    };
    let verified = client
        .get_operation_range(suffix.clone(), &batch.root)
        .await
        .expect("verify Connect suffix against Commonware root");
    assert_eq!(verified.root, batch.root);
    assert_eq!(verified.start_location, batch.start);
    assert_eq!(verified.operations, batch.operations);

    let verified_prefix = client
        .get_operation_range(
            GetOperationRangeRequest {
                tip: latest.as_u64(),
                start_location: 0,
                max_locations: all_operations.len() as u32,
                ..Default::default()
            },
            &batch.root,
        )
        .await
        .expect("verify Connect prefix against Commonware root");
    assert_eq!(verified_prefix.operations, all_operations);

    if is_final_batch {
        let response = common::operation_log_rpc_client(url)
            .get_operation_range(suffix.clone())
            .await
            .expect("browser fixture source proof")
            .into_view()
            .to_owned_message();
        let encoded_operations = batch
            .operations
            .iter()
            .map(|operation| operation.encode().to_vec())
            .collect::<Vec<_>>();
        crate::browser::assert_fixture(
            case_name,
            &batch.root,
            &suffix,
            &response,
            &encoded_operations,
        );
    }

    let mut wrong_root = batch.root;
    wrong_root.0[0] ^= 1;
    let error = client
        .get_operation_range(suffix, &wrong_root)
        .await
        .expect_err("reject a modified trusted root");
    assert!(matches!(error, QmdbError::ProofVerification { .. }));
}

async fn check_immutable<F, K, V, E>(
    case_name: &'static str,
    source: impl FnOnce(&'static str) -> Source<F, immutable::Operation<F, K, E>> + Send + 'static,
    codec: <immutable::Operation<F, K, E> as Read>::Cfg,
) where
    F: Graftable + Eq,
    K: QmdbKey,
    V: Codec + Clone + AsRef<[u8]> + Debug + PartialEq + Send + Sync + 'static,
    E: ValueEncoding<Value = V>,
    immutable::Operation<F, K, E>: Codec + Clone + Debug + PartialEq + Send + Sync,
{
    let source = tokio::task::spawn_blocking(move || source(case_name))
        .await
        .expect("join immutable source runner");
    let store = common::local_store_client().await;
    let prefixed = PrefixedStoreClient::empty(store);
    let reader = Arc::new(ImmutableClient::<F, Sha256, K, V, E>::new(
        prefixed.clone(),
        codec.clone(),
    ));
    let (server, url) =
        common::spawn_connect_service(immutable_operation_log_connect_stack(reader.clone())).await;
    let mut all_operations = vec![source.bootstrap];
    let (bootstrap_root, bootstrap) = common::prepare_operations::<F, _>(&all_operations, &codec);
    assert_eq!(bootstrap_root, source.bootstrap_root);
    publish(&prefixed, bootstrap, Location::new(0)).await;

    for (batch_index, batch) in source.batches.iter().enumerate() {
        assert_eq!(batch.start.as_u64(), all_operations.len() as u64);
        all_operations.extend_from_slice(&batch.operations);
        publish_source_batch(&prefixed, batch, &codec).await;
        let latest = batch.proof.leaves - 1;
        assert_eq!(
            reader
                .writer_location_watermark()
                .await
                .expect("published watermark"),
            Some(latest)
        );
        let root = common::retry(|| reader.root_at(latest), "immutable variant root").await;
        assert_eq!(root, batch.root);

        for (offset, operation) in batch.operations.iter().enumerate() {
            if let immutable::Operation::Set(key, value) = operation {
                let found = reader
                    .get_at(key, latest)
                    .await
                    .expect("read immutable key")
                    .expect("immutable key exists");
                assert_eq!(&found.key, key);
                assert_eq!(found.location, batch.start + offset as u64);
                assert_eq!(found.value.as_ref(), Some(value));
            }
        }
        check_connect::<F, _>(
            case_name,
            &url,
            codec.clone(),
            batch,
            &all_operations,
            batch_index + 1 == source.batches.len(),
        )
        .await;
    }
    server.abort();
}

async fn check_keyless<F, V, E>(
    case_name: &'static str,
    source: impl FnOnce(&'static str) -> Source<F, keyless::Operation<F, E>> + Send + 'static,
    codec: <keyless::Operation<F, E> as Read>::Cfg,
) where
    F: Graftable + Eq,
    V: Codec + Clone + AsRef<[u8]> + Debug + PartialEq + Send + Sync + 'static,
    E: ValueEncoding<Value = V>,
    keyless::Operation<F, E>: Codec + Clone + Debug + PartialEq + Send + Sync,
{
    let source = tokio::task::spawn_blocking(move || source(case_name))
        .await
        .expect("join keyless source runner");
    let store = common::local_store_client().await;
    let prefixed = PrefixedStoreClient::empty(store);
    let reader = Arc::new(KeylessClient::<F, Sha256, V, E>::new(
        prefixed.clone(),
        codec.clone(),
    ));
    let (server, url) =
        common::spawn_connect_service(keyless_operation_log_connect_stack(reader.clone())).await;
    let mut all_operations = vec![source.bootstrap];
    let (bootstrap_root, bootstrap) = common::prepare_operations::<F, _>(&all_operations, &codec);
    assert_eq!(bootstrap_root, source.bootstrap_root);
    publish(&prefixed, bootstrap, Location::new(0)).await;

    for (batch_index, batch) in source.batches.iter().enumerate() {
        assert_eq!(batch.start.as_u64(), all_operations.len() as u64);
        all_operations.extend_from_slice(&batch.operations);
        publish_source_batch(&prefixed, batch, &codec).await;
        let latest = batch.proof.leaves - 1;
        assert_eq!(
            reader
                .writer_location_watermark()
                .await
                .expect("published watermark"),
            Some(latest)
        );
        let root = common::retry(|| reader.root_at(latest), "keyless variant root").await;
        assert_eq!(root, batch.root);

        for (offset, operation) in batch.operations.iter().enumerate() {
            let expected = match operation {
                keyless::Operation::Append(value) => Some(value.clone()),
                keyless::Operation::Commit(metadata, _) => metadata.clone(),
            };
            assert_eq!(
                reader
                    .get_at(batch.start + offset as u64, latest)
                    .await
                    .expect("read keyless location"),
                expected,
            );
        }
        check_connect::<F, _>(
            case_name,
            &url,
            codec.clone(),
            batch,
            &all_operations,
            batch_index + 1 == source.batches.len(),
        )
        .await;
    }
    server.abort();
}

macro_rules! immutable_case {
    ($name:ident, $family:ty, $source:ident, $key:ty, $value:ty, $encoding:ty, $codec:expr) => {
        #[tokio::test]
        async fn $name() {
            check_immutable::<$family, $key, $value, $encoding>(
                stringify!($name),
                $source::<$family>,
                $codec,
            )
            .await;
        }
    };
}

macro_rules! keyless_case {
    ($name:ident, $family:ty, $source:ident, $value:ty, $encoding:ty, $codec:expr) => {
        #[tokio::test]
        async fn $name() {
            check_keyless::<$family, $value, $encoding>(
                stringify!($name),
                $source::<$family>,
                $codec,
            )
            .await;
        }
    };
}

immutable_case!(
    test_immutable_fixed_full_fixed_keys_fixed_values_mmr,
    mmr::Family,
    immutable_fixed_full_fixed_keys_fixed_values_source,
    FixedKey,
    FixedValue,
    FixedEncoding<FixedValue>,
    ()
);

immutable_case!(
    test_immutable_fixed_full_fixed_keys_fixed_values_mmb,
    mmb::Family,
    immutable_fixed_full_fixed_keys_fixed_values_source,
    FixedKey,
    FixedValue,
    FixedEncoding<FixedValue>,
    ()
);

immutable_case!(
    test_immutable_fixed_compact_fixed_keys_fixed_values_mmr,
    mmr::Family,
    immutable_fixed_compact_fixed_keys_fixed_values_source,
    FixedKey,
    FixedValue,
    FixedEncoding<FixedValue>,
    ()
);

immutable_case!(
    test_immutable_fixed_compact_fixed_keys_fixed_values_mmb,
    mmb::Family,
    immutable_fixed_compact_fixed_keys_fixed_values_source,
    FixedKey,
    FixedValue,
    FixedEncoding<FixedValue>,
    ()
);

immutable_case!(
    test_immutable_variable_full_fixed_keys_fixed_values_mmr,
    mmr::Family,
    immutable_variable_full_fixed_keys_fixed_values_source,
    FixedKey,
    FixedValue,
    VariableEncoding<FixedValue>,
    ((), ())
);

immutable_case!(
    test_immutable_variable_full_fixed_keys_fixed_values_mmb,
    mmb::Family,
    immutable_variable_full_fixed_keys_fixed_values_source,
    FixedKey,
    FixedValue,
    VariableEncoding<FixedValue>,
    ((), ())
);

immutable_case!(
    test_immutable_variable_compact_fixed_keys_fixed_values_mmr,
    mmr::Family,
    immutable_variable_compact_fixed_keys_fixed_values_source,
    FixedKey,
    FixedValue,
    VariableEncoding<FixedValue>,
    ((), ())
);

immutable_case!(
    test_immutable_variable_compact_fixed_keys_fixed_values_mmb,
    mmb::Family,
    immutable_variable_compact_fixed_keys_fixed_values_source,
    FixedKey,
    FixedValue,
    VariableEncoding<FixedValue>,
    ((), ())
);

immutable_case!(
    test_immutable_variable_full_fixed_keys_variable_values_mmr,
    mmr::Family,
    immutable_variable_full_fixed_keys_variable_values_source,
    FixedKey,
    Vec<u8>,
    VariableEncoding<Vec<u8>>,
    ((), byte_config())
);

immutable_case!(
    test_immutable_variable_full_fixed_keys_variable_values_mmb,
    mmb::Family,
    immutable_variable_full_fixed_keys_variable_values_source,
    FixedKey,
    Vec<u8>,
    VariableEncoding<Vec<u8>>,
    ((), byte_config())
);

immutable_case!(
    test_immutable_variable_compact_fixed_keys_variable_values_mmr,
    mmr::Family,
    immutable_variable_compact_fixed_keys_variable_values_source,
    FixedKey,
    Vec<u8>,
    VariableEncoding<Vec<u8>>,
    ((), byte_config())
);

immutable_case!(
    test_immutable_variable_compact_fixed_keys_variable_values_mmb,
    mmb::Family,
    immutable_variable_compact_fixed_keys_variable_values_source,
    FixedKey,
    Vec<u8>,
    VariableEncoding<Vec<u8>>,
    ((), byte_config())
);

immutable_case!(
    test_immutable_variable_full_variable_keys_fixed_values_mmr,
    mmr::Family,
    immutable_variable_full_variable_keys_fixed_values_source,
    Vec<u8>,
    FixedValue,
    VariableEncoding<FixedValue>,
    (byte_config(), ())
);

immutable_case!(
    test_immutable_variable_full_variable_keys_fixed_values_mmb,
    mmb::Family,
    immutable_variable_full_variable_keys_fixed_values_source,
    Vec<u8>,
    FixedValue,
    VariableEncoding<FixedValue>,
    (byte_config(), ())
);

immutable_case!(
    test_immutable_variable_compact_variable_keys_fixed_values_mmr,
    mmr::Family,
    immutable_variable_compact_variable_keys_fixed_values_source,
    Vec<u8>,
    FixedValue,
    VariableEncoding<FixedValue>,
    (byte_config(), ())
);

immutable_case!(
    test_immutable_variable_compact_variable_keys_fixed_values_mmb,
    mmb::Family,
    immutable_variable_compact_variable_keys_fixed_values_source,
    Vec<u8>,
    FixedValue,
    VariableEncoding<FixedValue>,
    (byte_config(), ())
);

immutable_case!(
    test_immutable_variable_full_variable_keys_variable_values_mmr,
    mmr::Family,
    immutable_variable_full_variable_keys_variable_values_source,
    Vec<u8>,
    Vec<u8>,
    VariableEncoding<Vec<u8>>,
    (byte_config(), byte_config())
);

immutable_case!(
    test_immutable_variable_full_variable_keys_variable_values_mmb,
    mmb::Family,
    immutable_variable_full_variable_keys_variable_values_source,
    Vec<u8>,
    Vec<u8>,
    VariableEncoding<Vec<u8>>,
    (byte_config(), byte_config())
);

immutable_case!(
    test_immutable_variable_compact_variable_keys_variable_values_mmr,
    mmr::Family,
    immutable_variable_compact_variable_keys_variable_values_source,
    Vec<u8>,
    Vec<u8>,
    VariableEncoding<Vec<u8>>,
    (byte_config(), byte_config())
);

immutable_case!(
    test_immutable_variable_compact_variable_keys_variable_values_mmb,
    mmb::Family,
    immutable_variable_compact_variable_keys_variable_values_source,
    Vec<u8>,
    Vec<u8>,
    VariableEncoding<Vec<u8>>,
    (byte_config(), byte_config())
);

keyless_case!(
    test_keyless_fixed_full_fixed_values_mmr,
    mmr::Family,
    keyless_fixed_full_fixed_values_source,
    FixedValue,
    FixedEncoding<FixedValue>,
    ()
);

keyless_case!(
    test_keyless_fixed_full_fixed_values_mmb,
    mmb::Family,
    keyless_fixed_full_fixed_values_source,
    FixedValue,
    FixedEncoding<FixedValue>,
    ()
);

keyless_case!(
    test_keyless_fixed_compact_fixed_values_mmr,
    mmr::Family,
    keyless_fixed_compact_fixed_values_source,
    FixedValue,
    FixedEncoding<FixedValue>,
    ()
);

keyless_case!(
    test_keyless_fixed_compact_fixed_values_mmb,
    mmb::Family,
    keyless_fixed_compact_fixed_values_source,
    FixedValue,
    FixedEncoding<FixedValue>,
    ()
);

keyless_case!(
    test_keyless_variable_full_fixed_values_mmr,
    mmr::Family,
    keyless_variable_full_fixed_values_source,
    FixedValue,
    VariableEncoding<FixedValue>,
    ()
);

keyless_case!(
    test_keyless_variable_full_fixed_values_mmb,
    mmb::Family,
    keyless_variable_full_fixed_values_source,
    FixedValue,
    VariableEncoding<FixedValue>,
    ()
);

keyless_case!(
    test_keyless_variable_compact_fixed_values_mmr,
    mmr::Family,
    keyless_variable_compact_fixed_values_source,
    FixedValue,
    VariableEncoding<FixedValue>,
    ()
);

keyless_case!(
    test_keyless_variable_compact_fixed_values_mmb,
    mmb::Family,
    keyless_variable_compact_fixed_values_source,
    FixedValue,
    VariableEncoding<FixedValue>,
    ()
);

keyless_case!(
    test_keyless_variable_full_variable_values_mmr,
    mmr::Family,
    keyless_variable_full_variable_values_source,
    Vec<u8>,
    VariableEncoding<Vec<u8>>,
    byte_config()
);

keyless_case!(
    test_keyless_variable_full_variable_values_mmb,
    mmb::Family,
    keyless_variable_full_variable_values_source,
    Vec<u8>,
    VariableEncoding<Vec<u8>>,
    byte_config()
);

keyless_case!(
    test_keyless_variable_compact_variable_values_mmr,
    mmr::Family,
    keyless_variable_compact_variable_values_source,
    Vec<u8>,
    VariableEncoding<Vec<u8>>,
    byte_config()
);

keyless_case!(
    test_keyless_variable_compact_variable_values_mmb,
    mmb::Family,
    keyless_variable_compact_variable_values_source,
    Vec<u8>,
    VariableEncoding<Vec<u8>>,
    byte_config()
);
