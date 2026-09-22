//! Keyless QMDB ConnectRPC e2e: streamed range checkpoints plus client-side
//! validation of tampered proofs.

mod common;

use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use commonware_codec::Encode;
use commonware_glue::stateful::db::{StateSyncDb, SyncEngineConfig};
use commonware_runtime::{deterministic, tokio as cw_tokio, Runner as _};
use commonware_storage::merkle::{mmr, Location};
use commonware_storage::qmdb::keyless::variable::{Db as Keyless, Operation as KeylessOperation};
use commonware_storage::qmdb::sync::{Request, Response, Source as _, Target};
use commonware_utils::channel::mpsc;
use commonware_utils::{NZUsize, NZU16, NZU64};
use connectrpc::client::{BoxFuture, ClientBody, ClientTransport};
use exoware_qmdb::proto::qmdb::v1::{
    GetOperationRangeRequest as ProtoGetOperationRangeRequest,
    SubscribeRequest as ProtoSubscribeRequest,
};
use exoware_qmdb::{
    keyless_operation_log_connect_stack, KeylessClient, OperationLogClient,
    OperationLogSubscribeProof, QmdbError,
};
use exoware_sdk::common::kv::v1::{filter as proto_filter, Filter as ProtoFilter};
use exoware_sdk::proto::PreferZstdHttpClient;
use exoware_sdk::{PrefixedStoreClient, RetryConfig, StoreClient};

type Digest = commonware_cryptography::sha256::Digest;
type Db = Keyless<
    mmr::Family,
    deterministic::Context,
    Vec<u8>,
    commonware_cryptography::Sha256,
    commonware_parallel::Sequential,
>;
type SyncDb = Keyless<
    mmr::Family,
    cw_tokio::Context,
    Vec<u8>,
    commonware_cryptography::Sha256,
    commonware_parallel::Sequential,
>;
type TestKeylessClient = KeylessClient<mmr::Family, commonware_cryptography::Sha256, Vec<u8>>;
type BatchOperation = KeylessOperation<mmr::Family, Vec<u8>>;

async fn spawn_qmdb_server(
    qmdb_client: Arc<TestKeylessClient>,
) -> (tokio::task::JoinHandle<()>, String) {
    common::spawn_connect_service(keyless_operation_log_connect_stack(qmdb_client)).await
}

fn operation_log_client(
    base: &str,
) -> OperationLogClient<
    PreferZstdHttpClient,
    mmr::Family,
    commonware_cryptography::Sha256,
    BatchOperation,
> {
    OperationLogClient::plaintext(base, ((0..=10000).into(), ()))
}

#[tokio::test]
async fn test_overlapping_atomic_uploads_emit_each_operation_once() {
    use exoware_qmdb::{stage_authenticated_range, stage_watermark};
    use exoware_sdk::StoreWriteBatch;

    let store_client = common::local_store_client().await;
    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    let operations = vec![
        KeylessOperation::Append(b"first".to_vec()),
        KeylessOperation::Commit(None, Location::new(0)),
        KeylessOperation::Append(b"second".to_vec()),
        KeylessOperation::Commit(None, Location::new(0)),
    ];
    let config = ((0..=10000).into(), ());
    let (_, first) =
        common::prepare_operations::<mmr::Family, BatchOperation>(&operations[..2], &config);
    let (root, second) =
        common::prepare_operations::<mmr::Family, BatchOperation>(&operations, &config);
    let mut batch = StoreWriteBatch::new();
    // An atomic batch may stage overlapping upload ranges in either order
    stage_authenticated_range(&upload_client, second, &mut batch).unwrap();
    stage_authenticated_range(&upload_client, first, &mut batch).unwrap();
    stage_watermark::<mmr::Family>(&upload_client, Location::new(3), &mut batch).unwrap();
    let sequence = batch.commit(&store_client).await.unwrap();

    let qmdb_client = Arc::new(TestKeylessClient::new(
        PrefixedStoreClient::empty(store_client),
        ((0..=10000).into(), ()),
    ));
    let (server, url) = spawn_qmdb_server(qmdb_client).await;
    let mut stream = operation_log_client(&url)
        .subscribe(ProtoSubscribeRequest {
            since_sequence_number: Some(sequence),
            ..Default::default()
        })
        .await
        .unwrap();
    let frame = stream
        .message_with_root(common::trusted_root(root))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(frame.resume_sequence_number, sequence);
    assert_eq!(
        frame.operations,
        operations
            .into_iter()
            .enumerate()
            .map(|(index, operation)| (Location::new(index as u64), operation))
            .collect::<Vec<_>>()
    );
    server.abort();
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
            let cfg = common::keyless_variable_config(
                "keyless_variable_full_mmr_connect_source",
                page_cache,
                ((0..=10000).into(), ()),
                NZU64!(7),
            );
            let mut db: Db = Db::init(
                context.child("keyless_variable_full_mmr_connect_source"),
                cfg,
            )
            .await
            .expect("init");

            let finalized = {
                let batch = db
                    .new_batch()
                    .append(b"first-value".to_vec())
                    .append(b"second-value".to_vec());
                batch
                    .merkleize(&db, None::<Vec<u8>>, db.inactivity_floor_loc())
                    .await
            };
            (db, _) = db.apply_batch(finalized).await.expect("apply");
            let finalized = {
                let batch = db.new_batch().append(b"third-value".to_vec());
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
        KeylessOperation::Commit(_, floor) => *floor,
        KeylessOperation::Append(_) => panic!("operations must end with Commit"),
    }
}

async fn commit_upload(store_client: &StoreClient, batch: &SourceBatch) {
    common::commit_operations::<mmr::Family, BatchOperation>(
        &PrefixedStoreClient::empty(store_client.clone()),
        &batch.operations,
        &((0..=10000).into(), ()),
    )
    .await
    .expect("commit upload");
}

#[tokio::test]
async fn test_keyless_connect_subscribe_emits_verifiable_multi_proof() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    assert!(
        *source.inactivity_floor > 0,
        "test must not rely on inactivity_floor = 0"
    );
    let keyless_client = Arc::new(TestKeylessClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        ((0..=10000).into(), ()),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(keyless_client).await;
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
async fn test_keyless_connect_get_operation_range_returns_verifiable_proof() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    assert!(
        *source.inactivity_floor > 0,
        "test must not rely on inactivity_floor = 0"
    );
    commit_upload(&store_client, &source).await;

    let keyless_client = Arc::new(TestKeylessClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        ((0..=10000).into(), ()),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(keyless_client).await;
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
async fn test_operation_range_preserves_late_consistency_errors() {
    #[derive(Clone)]
    struct ReplicaTransport {
        origins: Vec<axum::http::Uri>,
        calls: Arc<Mutex<Vec<String>>>,
        inner: PreferZstdHttpClient,
    }

    impl ClientTransport for ReplicaTransport {
        type ResponseBody = <PreferZstdHttpClient as ClientTransport>::ResponseBody;
        type Error = <PreferZstdHttpClient as ClientTransport>::Error;

        fn send(
            &self,
            mut request: axum::http::Request<ClientBody>,
        ) -> BoxFuture<'static, Result<axum::http::Response<Self::ResponseBody>, Self::Error>>
        {
            let index = {
                let mut calls = self.calls.lock().unwrap();
                let index = calls.len();
                calls.push(request.uri().path().to_string());
                index
            };
            let replica = if index < 4 {
                0
            } else if index == 4 {
                1
            } else {
                2
            };
            let mut parts = request.uri().clone().into_parts();
            parts.scheme = self.origins[replica].scheme().cloned();
            parts.authority = self.origins[replica].authority().cloned();
            *request.uri_mut() = axum::http::Uri::from_parts(parts).unwrap();
            self.inner.send(request)
        }
    }

    let operations = vec![
        KeylessOperation::Append(b"first".to_vec()),
        KeylessOperation::Commit(None, Location::new(0)),
        KeylessOperation::Append(b"second".to_vec()),
        KeylessOperation::Commit(None, Location::new(0)),
    ];
    let config = ((0..=10000).into(), ());
    let mut origins = Vec::new();
    let mut handles = Vec::new();
    let mut replicas = Vec::new();
    for frontier in [100, 200, 150] {
        let (handle, url) = exoware_simulator::open_temp().await.unwrap();
        let store = PrefixedStoreClient::empty(StoreClient::new(&url));
        common::commit_operations::<mmr::Family, BatchOperation>(&store, &operations, &config)
            .await
            .unwrap();
        for sequence in 2u64..=frontier {
            let key = Bytes::from(format!("unrelated/{sequence}"));
            assert_eq!(
                store.ingest().put(&[(&key, b"value")]).await.unwrap(),
                sequence
            );
        }
        origins.push(url.parse().unwrap());
        handles.push(handle);
        replicas.push(store);
    }

    // All proof rows precede these frontiers. A later read raises the floor above the last replica.
    let calls = Arc::new(Mutex::new(Vec::new()));
    let client = StoreClient::builder()
        .url("http://replicas.test")
        .client_transport(ReplicaTransport {
            origins,
            calls: calls.clone(),
            inner: PreferZstdHttpClient::plaintext(),
        })
        .retry_config(RetryConfig::disabled())
        .build()
        .unwrap();
    let (root, _) = common::prepare_operations::<mmr::Family, BatchOperation>(&operations, &config);
    let keyless = Arc::new(TestKeylessClient::new(
        PrefixedStoreClient::empty(client),
        config,
    ));
    let (qmdb_handle, url) = spawn_qmdb_server(keyless).await;
    let error = common::operation_log_rpc_client(&url)
        .get_operation_range(ProtoGetOperationRangeRequest {
            tip: 3,
            start_location: 1,
            max_locations: 1,
            ..Default::default()
        })
        .await
        .expect_err("last replica cannot satisfy the advanced floor");
    assert_eq!(
        calls
            .lock()
            .unwrap()
            .iter()
            .map(|path| path.rsplit('/').next().unwrap())
            .collect::<Vec<_>>(),
        ["Range", "Get", "Get", "GetMany", "Range", "GetMany"]
    );
    assert_eq!(error.code, connectrpc::ErrorCode::Aborted);

    for sequence in 151u64..=200 {
        let key = Bytes::from(format!("unrelated/{sequence}"));
        assert_eq!(
            replicas[2].ingest().put(&[(&key, b"value")]).await.unwrap(),
            sequence
        );
    }
    let proof = operation_log_client(&url)
        .get_operation_range(
            ProtoGetOperationRangeRequest {
                tip: 3,
                start_location: 1,
                max_locations: 1,
                min_sequence_number: Some(200),
                ..Default::default()
            },
            &root,
        )
        .await
        .expect("caught-up replica supplies a valid proof");
    assert_eq!(proof.sequence_number, 200);
    qmdb_handle.abort();
    for handle in handles {
        handle.abort();
    }
}

#[tokio::test]
async fn test_keyless_operation_log_source_fetches_api_batches() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    commit_upload(&store_client, &source).await;

    let keyless_client = Arc::new(TestKeylessClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        ((0..=10000).into(), ()),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(keyless_client).await;
    let resolver = OperationLogClient::<
        _,
        mmr::Family,
        commonware_cryptography::Sha256,
        BatchOperation,
    >::plaintext(&qmdb_url, ((0..=10000).into(), ()));
    let op_count = Location::new(source.operations.len() as u64);

    let (response, callback) = resolver
        .serve(Request::Operations {
            size: op_count,
            start: Location::new(0),
            max_ops: NZU64!(2),
        })
        .await
        .expect("fetch sync operations");
    let Response::Operations { proof, operations } = response else {
        panic!("operation request returned boundary response");
    };
    assert_eq!(operations.as_slice(), &source.operations[..2]);

    let hasher = commonware_storage::qmdb::hasher::<commonware_cryptography::Sha256>();
    let elements = operations
        .iter()
        .map(|operation| operation.encode())
        .collect::<Vec<_>>();
    assert!(proof.verify_range_inclusion(&hasher, &elements, Location::new(0), &source.root));
    assert!(
        callback.is_none(),
        "direct sync source fetches do not allocate an unused validation callback"
    );

    let (response, _) = resolver
        .serve(Request::Operations {
            size: op_count,
            start: Location::new(0),
            max_ops: std::num::NonZeroU64::MAX,
        })
        .await
        .expect("a large maximum permits a smaller API batch");
    let Response::Operations { operations, .. } = response else {
        panic!("operation request returned boundary response");
    };
    assert_eq!(operations, source.operations);
}

#[tokio::test]
async fn test_keyless_commonware_glue_state_sync_uses_operation_log_client() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    assert!(
        *source.inactivity_floor > 0,
        "glue state-sync test must exercise a nonzero replay floor"
    );
    commit_upload(&store_client, &source).await;

    let keyless_client = Arc::new(TestKeylessClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        ((0..=10000).into(), ()),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(keyless_client).await;
    let resolver = OperationLogClient::<
        _,
        mmr::Family,
        commonware_cryptography::Sha256,
        BatchOperation,
    >::plaintext(&qmdb_url, ((0..=10000).into(), ()));
    let op_count = Location::new(source.operations.len() as u64);
    let target = Target::new(
        source.root,
        commonware_utils::non_empty_range!(source.inactivity_floor, op_count),
    );

    let start = source.inactivity_floor;
    let start_index = usize::try_from(*start).expect("start fits usize");
    let expected_values = source
        .operations
        .iter()
        .enumerate()
        .skip(start_index)
        .filter_map(|(idx, operation)| match operation {
            KeylessOperation::Append(value) => Some((Location::new(idx as u64), value.clone())),
            KeylessOperation::Commit(Some(value), _) => {
                Some((Location::new(idx as u64), value.clone()))
            }
            KeylessOperation::Commit(None, _) => None,
        })
        .collect::<Vec<_>>();
    assert!(
        !expected_values.is_empty(),
        "fixture must leave readable values inside the limited sync range"
    );

    tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(move |context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};

            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::keyless_variable_config(
                "keyless_variable_full_mmr_sync_target",
                page_cache,
                ((0..=10000).into(), ()),
                NZU64!(7),
            );
            let (_update_tx, update_rx) = mpsc::channel(1);
            let synced: SyncDb = <SyncDb as StateSyncDb<_, _>>::sync_db(
                context.child("keyless_variable_full_mmr_sync_target"),
                cfg,
                resolver,
                target,
                update_rx,
                None,
                None,
                SyncEngineConfig {
                    fetch_batch_size: NZU64!(1),
                    apply_batch_size: NZU64!(1),
                    max_outstanding_requests: 2,
                    update_channel_size: NZUsize!(1),
                    max_retained_roots: 4,
                },
            )
            .await
            .expect("commonware glue state sync");

            assert_eq!(synced.root(), source.root);
            let bounds = synced.bounds();
            assert_eq!(bounds.start, start);
            assert_eq!(bounds.end, op_count);
            for (location, expected) in expected_values {
                assert_eq!(
                    synced.get(location).await.expect("synced get"),
                    Some(expected)
                );
            }
            synced.destroy().await.expect("destroy synced db");
        });
    })
    .await
    .expect("join glue state sync runner");
}

#[tokio::test]
async fn test_keyless_connect_client_rejects_invalid_streamed_proof() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    assert!(
        *source.inactivity_floor > 0,
        "test must not rely on inactivity_floor = 0"
    );
    commit_upload(&store_client, &source).await;

    let keyless_client = Arc::new(TestKeylessClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        ((0..=10000).into(), ()),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(keyless_client).await;
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

fn match_exact(bytes: &[u8]) -> ProtoFilter {
    ProtoFilter {
        kind: Some(proto_filter::Kind::Exact(Bytes::copy_from_slice(bytes))),
        ..Default::default()
    }
}

fn match_regex(regex: &str) -> ProtoFilter {
    ProtoFilter {
        kind: Some(proto_filter::Kind::Regex(regex.to_string())),
        ..Default::default()
    }
}

#[tokio::test]
async fn test_keyless_connect_subscribe_filters_by_value_regex() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    assert!(
        *source.inactivity_floor > 0,
        "test must not rely on inactivity_floor = 0"
    );
    let keyless_client = Arc::new(TestKeylessClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        ((0..=10000).into(), ()),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(keyless_client).await;
    let connect_client = operation_log_client(&qmdb_url);

    // Only include ops whose value begins with "second".
    let mut stream = connect_client
        .subscribe(ProtoSubscribeRequest {
            value_filters: vec![match_regex("^second.*$")],
            ..Default::default()
        })
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

    assert_eq!(frame.root, source.root);
    let expected: Vec<(Location<mmr::Family>, BatchOperation)> = source
        .operations
        .iter()
        .enumerate()
        .filter_map(|(i, op)| match op {
            KeylessOperation::Append(value) if value.starts_with(b"second") => {
                Some((Location::new(i as u64), op.clone()))
            }
            _ => None,
        })
        .collect();
    assert!(!expected.is_empty());
    assert_eq!(frame.operations, expected);
}

#[tokio::test]
async fn test_keyless_connect_subscribe_rejects_key_filters() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    assert!(
        *source.inactivity_floor > 0,
        "test must not rely on inactivity_floor = 0"
    );
    let keyless_client = Arc::new(TestKeylessClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        ((0..=10000).into(), ()),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(keyless_client).await;

    let rpc = common::operation_log_rpc_client(&qmdb_url);
    let mut stream = rpc
        .subscribe(ProtoSubscribeRequest {
            key_filters: vec![match_exact(b"anything")],
            ..Default::default()
        })
        .await
        .expect("subscribe opens");

    // Even if we upload a batch that would otherwise match, the stream must
    // not emit a proof because keyless rejects key_filters server-side before it
    // opens the store subscription.
    commit_upload(&store_client, &source).await;

    match tokio::time::timeout(Duration::from_millis(500), stream.message()).await {
        Ok(Ok(Some(_))) => {
            panic!("keyless stream must not emit a proof when key_filters is set")
        }
        Ok(Ok(None)) => {}
        Ok(Err(err)) => {
            let msg = err.to_string();
            assert!(msg.contains("key_filters"), "unexpected error: {msg}");
        }
        Err(_) => panic!("stream hung instead of rejecting key_filters"),
    }
}

#[tokio::test]
async fn test_keyless_data_only_frames_replay_in_store_order_after_delayed_publication() {
    use exoware_qmdb::{stage_authenticated_range, stage_watermark, NODE_FAMILY};
    use exoware_sdk::StoreWriteBatch;

    let store_client = common::local_store_client().await;
    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    let operations: Vec<BatchOperation> = vec![
        KeylessOperation::Append(b"first".to_vec()),
        KeylessOperation::Append(b"second".to_vec()),
        KeylessOperation::Commit(None, Location::new(0)),
        KeylessOperation::Append(b"third".to_vec()),
        KeylessOperation::Append(b"fourth".to_vec()),
        KeylessOperation::Commit(None, Location::new(0)),
    ];
    let (root, prepared) = common::prepare_operations::<mmr::Family, BatchOperation>(
        &operations,
        &((0..=10000).into(), ()),
    );
    let mut data = StoreWriteBatch::new();
    stage_authenticated_range(&upload_client, prepared, &mut data).unwrap();
    let mut earlier = StoreWriteBatch::new();
    let mut later = StoreWriteBatch::new();
    for (key, value) in data.entries() {
        // Store chunks may carry operations separately from their source boundary marker
        if value.is_empty() {
            continue;
        }
        let is_earlier_operation =
            key[0] != NODE_FAMILY && u64::from_be_bytes(key[1..].try_into().unwrap()) < 3;
        let target = if is_earlier_operation {
            &mut earlier
        } else {
            &mut later
        };
        target.push(&upload_client, key, value.clone()).unwrap();
    }
    let later_sequence = later.commit(&store_client).await.unwrap();
    let qmdb_client = Arc::new(TestKeylessClient::new(
        upload_client.clone(),
        ((0..=10000).into(), ()),
    ));
    assert_eq!(qmdb_client.writer_location_watermark().await.unwrap(), None);
    let earlier_sequence = earlier.commit(&store_client).await.unwrap();
    assert_eq!(qmdb_client.writer_location_watermark().await.unwrap(), None);
    let mut publication = StoreWriteBatch::new();
    stage_watermark(
        &upload_client,
        Location::<mmr::Family>::new(5),
        &mut publication,
    )
    .unwrap();
    let publication_sequence = publication.commit(&store_client).await.unwrap();
    assert!(later_sequence < earlier_sequence && earlier_sequence < publication_sequence);

    let (server, url) = spawn_qmdb_server(qmdb_client).await;
    let mut stream = operation_log_client(&url)
        .subscribe(ProtoSubscribeRequest {
            since_sequence_number: Some(later_sequence),
            ..Default::default()
        })
        .await
        .unwrap();
    let first = stream
        .message_with_root(common::trusted_root(root))
        .await
        .expect("data-only frames must wait for publication without requiring presence")
        .unwrap();
    let second = stream
        .message_with_root(common::trusted_root(root))
        .await
        .unwrap()
        .unwrap();
    let expected = operations
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, operation)| (Location::new(index as u64), operation))
        .collect::<Vec<_>>();
    assert_eq!(first.resume_sequence_number, later_sequence);
    assert_eq!(first.operations, expected[3..]);
    assert_eq!(second.resume_sequence_number, earlier_sequence);
    assert_eq!(second.operations, expected[..3]);

    let mut resumed = operation_log_client(&url)
        .subscribe(ProtoSubscribeRequest {
            since_sequence_number: Some(first.resume_sequence_number + 1),
            ..Default::default()
        })
        .await
        .unwrap();
    let replayed = resumed
        .message_with_root(common::trusted_root(root))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        replayed.resume_sequence_number,
        second.resume_sequence_number
    );
    assert_eq!(replayed.operations, second.operations);
    server.abort();
}
