//! Immutable QMDB ConnectRPC e2e: streamed range checkpoints plus client-side
//! validation of tampered proofs.

mod common;

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use commonware_runtime::{deterministic, Runner as _};
use commonware_storage::merkle::{mmr, Location};
use commonware_storage::qmdb::immutable::variable::{
    Db as Immutable, Operation as ImmutableOperation,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use exoware_qmdb::proto::qmdb::v1::{
    GetOperationRangeRequest as ProtoGetOperationRangeRequest,
    SubscribeRequest as ProtoSubscribeRequest,
};
use exoware_qmdb::{
    immutable_operation_log_connect_stack, ImmutableClient, OperationLogClient,
    OperationLogSubscribeProof, QmdbError,
};
use exoware_sdk::proto::PreferZstdHttpClient;
use exoware_sdk::{PrefixedStoreClient, StoreClient};

type Digest = commonware_cryptography::sha256::Digest;
type Db = Immutable<
    mmr::Family,
    deterministic::Context,
    FixedBytes<32>,
    Vec<u8>,
    commonware_cryptography::Sha256,
    TwoCap,
    commonware_parallel::Sequential,
>;
type TestImmutableClient =
    ImmutableClient<mmr::Family, commonware_cryptography::Sha256, FixedBytes<32>, Vec<u8>>;
type BatchOperation = ImmutableOperation<mmr::Family, FixedBytes<32>, Vec<u8>>;

async fn spawn_qmdb_server(
    qmdb_client: Arc<TestImmutableClient>,
) -> (tokio::task::JoinHandle<()>, String) {
    common::spawn_connect_service(immutable_operation_log_connect_stack(qmdb_client)).await
}

fn operation_log_client(
    base: &str,
) -> OperationLogClient<
    PreferZstdHttpClient,
    mmr::Family,
    commonware_cryptography::Sha256,
    BatchOperation,
> {
    OperationLogClient::plaintext(base, ((), ((0..=10000).into(), ())))
}

struct SourceBatch {
    operations: Vec<BatchOperation>,
    root: Digest,
    inactivity_floor: Location<mmr::Family>,
}

async fn build_source_batch() -> SourceBatch {
    tokio::task::spawn_blocking(|| {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::immutable_variable_config(
                "immutable_variable_full_mmr_connect_source",
                page_cache,
                ((), ((0..=10000).into(), ())),
                NZU64!(5),
            );
            let mut db: Db = Db::init(
                context.child("immutable_variable_full_mmr_connect_source"),
                cfg,
            )
            .await
            .expect("init");

            let key_a = FixedBytes::new([0x11; 32]);
            let key_b = FixedBytes::new([0x22; 32]);
            let key_c = FixedBytes::new([0x33; 32]);
            let finalized = {
                let batch = db
                    .new_batch()
                    .set(key_a, b"alpha".to_vec())
                    .set(key_b, b"beta".to_vec());
                batch
                    .merkleize(&db, None::<Vec<u8>>, db.inactivity_floor_loc())
                    .await
            };
            (db, _) = db.apply_batch(finalized).await.expect("apply");
            let finalized = {
                let batch = db.new_batch().set(key_c, b"gamma".to_vec());
                batch
                    .merkleize(&db, None::<Vec<u8>>, db.bounds().end - 1)
                    .await
            };
            (db, _) = db.apply_batch(finalized).await.expect("apply second");

            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");
            let inactivity_floor = latest_inactivity_floor(&ops);
            let root = db.root();
            db.destroy().await.expect("destroy");

            SourceBatch {
                operations: ops,
                root,
                inactivity_floor,
            }
        })
    })
    .await
    .expect("join")
}

fn latest_inactivity_floor(ops: &[BatchOperation]) -> Location<mmr::Family> {
    match ops.last().expect("non-empty operations") {
        ImmutableOperation::Commit(_, floor) => *floor,
        ImmutableOperation::Set(_, _) => panic!("operations must end with Commit"),
    }
}

async fn commit_upload(store_client: &StoreClient, batch: &SourceBatch) {
    common::commit_operations::<mmr::Family, BatchOperation>(
        &PrefixedStoreClient::empty(store_client.clone()),
        &batch.operations,
        &((), ((0..=10000).into(), ())),
    )
    .await
    .expect("commit upload");
}

#[tokio::test]
async fn test_immutable_connect_subscribe_emits_verifiable_multi_proof() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    assert!(
        *source.inactivity_floor > 0,
        "test must not rely on inactivity_floor = 0"
    );
    let immutable_client = Arc::new(TestImmutableClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        ((), ((0..=10000).into(), ())),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(immutable_client).await;
    let connect_client = operation_log_client(&qmdb_url);

    let mut stream = connect_client
        .subscribe(ProtoSubscribeRequest::default())
        .await
        .expect("subscribe");

    tokio::time::sleep(Duration::from_millis(50)).await;
    commit_upload(&store_client, &source).await;

    let frame: OperationLogSubscribeProof<Digest, BatchOperation, mmr::Family> =
        tokio::time::timeout(
            Duration::from_secs(5),
            stream.message_with_root(common::trusted_root(source.root)),
        )
        .await
        .expect("timeout")
        .expect("stream result")
        .expect("stream frame");

    assert!(frame.resume_sequence_number > 0);
    assert_eq!(frame.root, source.root);
    let expected: Vec<(Location<mmr::Family>, BatchOperation)> = source
        .operations
        .iter()
        .enumerate()
        .map(|(i, op)| (Location::new(i as u64), op.clone()))
        .collect();
    assert_eq!(frame.operations, expected);
}

#[tokio::test]
async fn test_immutable_connect_get_operation_range_returns_verifiable_proof() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    assert!(
        *source.inactivity_floor > 0,
        "test must not rely on inactivity_floor = 0"
    );
    commit_upload(&store_client, &source).await;

    let immutable_client = Arc::new(TestImmutableClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        ((), ((0..=10000).into(), ())),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(immutable_client).await;
    let connect_client = operation_log_client(&qmdb_url);

    for min_sequence_number in [None, Some(1)] {
        let proof = connect_client
            .get_operation_range(
                ProtoGetOperationRangeRequest {
                    tip: u64::try_from(source.operations.len() - 1).expect("tip fits"),
                    start_location: 1,
                    max_locations: 1,
                    min_sequence_number,
                    ..Default::default()
                },
                &source.root,
            )
            .await
            .expect("get operation range");

        assert!(proof.sequence_number >= 1);
        assert_eq!(proof.root, source.root);
        assert_eq!(proof.start_location, Location::new(1));
        assert_eq!(proof.operations, vec![source.operations[1].clone()]);
    }

    let error = common::operation_log_rpc_client(&qmdb_url)
        .get_operation_range(ProtoGetOperationRangeRequest {
            tip: u64::try_from(source.operations.len() - 1).expect("tip fits"),
            start_location: 1,
            max_locations: 1,
            min_sequence_number: Some(u64::MAX),
            ..Default::default()
        })
        .await
        .expect_err("unavailable sequence floor");
    assert_eq!(error.code, connectrpc::ErrorCode::Aborted);
}

#[tokio::test]
async fn test_immutable_connect_client_rejects_invalid_streamed_proof() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    assert!(
        *source.inactivity_floor > 0,
        "test must not rely on inactivity_floor = 0"
    );
    commit_upload(&store_client, &source).await;

    let immutable_client = Arc::new(TestImmutableClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        ((), ((0..=10000).into(), ())),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(immutable_client).await;
    let rpc = common::operation_log_rpc_client(&qmdb_url);
    let mut raw_stream = rpc
        .subscribe(ProtoSubscribeRequest {
            since_sequence_number: Some(1),
            ..Default::default()
        })
        .await
        .expect("subscribe");
    let raw_response = raw_stream
        .message()
        .await
        .expect("stream result")
        .expect("stream frame")
        .to_owned_message();

    let (_static_server, static_url) =
        common::spawn_static_operation_log_service(common::StaticOperationLogService {
            subscribe_response: common::tamper_subscribe_response(raw_response),
        })
        .await;
    let connect_client = operation_log_client(&static_url);
    let mut stream = connect_client
        .subscribe(ProtoSubscribeRequest::default())
        .await
        .expect("subscribe");

    let err = stream
        .message_with_root(common::trusted_root(source.root))
        .await
        .expect_err("tampered streamed proof should fail");
    assert!(matches!(
        err,
        QmdbError::ProofVerification {
            kind: exoware_qmdb::ProofKind::BatchMulti
        }
    ));
}
