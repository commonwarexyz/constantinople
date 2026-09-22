//! Unordered QMDB ConnectRPC e2e: streamed range checkpoints plus client-side
//! validation of tampered proofs.

mod common;

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use commonware_cryptography::Sha256;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::Runner as _;
use commonware_storage::merkle::{mmb, mmr, Location, Proof};
use commonware_storage::qmdb::any::unordered::variable::Db as LocalUnorderedDb;
use commonware_storage::qmdb::any::unordered::variable::Operation as UnorderedQmdbOperation;
use commonware_storage::qmdb::current::unordered::variable::Db as LocalCurrentUnorderedDb;
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use connectrpc::client::ClientConfig;
use connectrpc::ErrorCode;
use exoware_qmdb::proto::qmdb::v1::{
    GetCurrentOperationRangeRequest as ProtoGetCurrentOperationRangeRequest,
    GetManyRequest as ProtoGetManyRequest,
    GetOperationRangeRequest as ProtoGetOperationRangeRequest,
    GetRangeRequest as ProtoGetRangeRequest, GetRequest as ProtoGetRequest, KeyLookupServiceClient,
    OrderedKeyRangeServiceClient, SubscribeRequest as ProtoSubscribeRequest,
};
use exoware_qmdb::{
    recover_boundary_state, unordered_connect_stack, unordered_operation_log_connect_stack,
    CurrentBoundaryState, CurrentOperationClient, OperationLogClient, OperationLogSubscribeProof,
    QmdbError, UnorderedClient, UnorderedConnectClient, MAX_OPERATION_SIZE,
};
use exoware_sdk::proto::PreferZstdHttpClient;
use exoware_sdk::{PrefixedStoreClient, StoreClient};

const N: usize = 32;
type Digest = commonware_cryptography::sha256::Digest;
type BatchProof = Proof<mmr::Family, Digest>;
type BatchOperation = UnorderedQmdbOperation<mmr::Family, Vec<u8>, Vec<u8>>;
type MmbBatchProof = Proof<mmb::Family, Digest>;
type MmbBatchOperation = UnorderedQmdbOperation<mmb::Family, Vec<u8>, Vec<u8>>;
type FixedKeyOperation = UnorderedQmdbOperation<mmr::Family, Digest, Vec<u8>>;
type TestUnorderedClient = UnorderedClient<mmr::Family, Sha256, Vec<u8>, Vec<u8>>;
type MmbTestUnorderedClient = UnorderedClient<mmb::Family, Sha256, Vec<u8>, Vec<u8>>;
type FixedKeyClient = UnorderedClient<mmr::Family, Sha256, Digest, Vec<u8>>;
type AnyDb = LocalUnorderedDb<
    mmr::Family,
    cw_tokio::Context,
    Vec<u8>,
    Vec<u8>,
    Sha256,
    TwoCap,
    commonware_parallel::Sequential,
>;
type MmbAnyDb = LocalUnorderedDb<
    mmb::Family,
    cw_tokio::Context,
    Vec<u8>,
    Vec<u8>,
    Sha256,
    TwoCap,
    commonware_parallel::Sequential,
>;
type CurrentDb = LocalCurrentUnorderedDb<
    mmr::Family,
    cw_tokio::Context,
    Digest,
    Vec<u8>,
    Sha256,
    TwoCap,
    N,
    commonware_parallel::Sequential,
>;

async fn spawn_qmdb_range_server(
    qmdb_client: Arc<TestUnorderedClient>,
) -> (tokio::task::JoinHandle<()>, String) {
    common::spawn_connect_service(unordered_operation_log_connect_stack(qmdb_client)).await
}

async fn spawn_mmb_qmdb_range_server(
    qmdb_client: Arc<MmbTestUnorderedClient>,
) -> (tokio::task::JoinHandle<()>, String) {
    common::spawn_connect_service(unordered_operation_log_connect_stack(qmdb_client)).await
}

async fn spawn_qmdb_full_server(
    qmdb_client: Arc<FixedKeyClient>,
) -> (tokio::task::JoinHandle<()>, String) {
    common::spawn_connect_service(unordered_connect_stack::<
        mmr::Family,
        Sha256,
        Digest,
        Vec<u8>,
        N,
        _,
    >(qmdb_client, ()))
    .await
}

fn operation_log_client(
    base: &str,
) -> OperationLogClient<PreferZstdHttpClient, mmr::Family, Sha256, BatchOperation> {
    OperationLogClient::plaintext(base, op_cfg())
}

fn mmb_operation_log_client(
    base: &str,
) -> OperationLogClient<PreferZstdHttpClient, mmb::Family, Sha256, MmbBatchOperation> {
    OperationLogClient::plaintext(base, op_cfg())
}

fn key_lookup_client(
    base: &str,
) -> UnorderedConnectClient<PreferZstdHttpClient, mmr::Family, Sha256, Digest, Vec<u8>, N> {
    UnorderedConnectClient::plaintext(base, fixed_key_op_cfg())
}

fn current_operation_client(
    base: &str,
) -> CurrentOperationClient<PreferZstdHttpClient, mmr::Family, Sha256, FixedKeyOperation, N> {
    CurrentOperationClient::plaintext(base, fixed_key_op_cfg())
}

fn key_lookup_rpc_client(base: &str) -> KeyLookupServiceClient<PreferZstdHttpClient> {
    KeyLookupServiceClient::new(
        PreferZstdHttpClient::plaintext(),
        ClientConfig::new(base.parse().expect("qmdb uri")),
    )
}

fn ordered_range_rpc_client(base: &str) -> OrderedKeyRangeServiceClient<PreferZstdHttpClient> {
    OrderedKeyRangeServiceClient::new(
        PreferZstdHttpClient::plaintext(),
        ClientConfig::new(base.parse().expect("qmdb uri")),
    )
}

fn op_cfg() -> <BatchOperation as commonware_codec::Read>::Cfg {
    (
        ((0..=MAX_OPERATION_SIZE).into(), ()),
        ((0..=MAX_OPERATION_SIZE).into(), ()),
    )
}

fn fixed_key_op_cfg() -> <FixedKeyOperation as commonware_codec::Read>::Cfg {
    ((), ((0..=MAX_OPERATION_SIZE).into(), ()))
}

struct AnySourceBatch {
    operations: Vec<BatchOperation>,
    root: Digest,
    inactivity_floor: Location<mmr::Family>,
}

struct MmbAnySourceBatch {
    operations: Vec<MmbBatchOperation>,
    root: Digest,
    inactivity_floor: Location<mmb::Family>,
}

struct CurrentSourceBatch {
    latest_location: Location<mmr::Family>,
    alpha: Digest,
    beta: Digest,
    root: Digest,
    operations: Vec<FixedKeyOperation>,
    current_boundary: CurrentBoundaryState<Digest, N, mmr::Family>,
}

async fn boundary_from_current_source_db(
    db: &CurrentDb,
    operations: &[FixedKeyOperation],
) -> CurrentBoundaryState<Digest, N, mmr::Family> {
    let ops_root_witness = db.ops_root_witness().await.expect("ops root witness");
    recover_boundary_state::<mmr::Family, Sha256, _, N, _, _>(
        None,
        operations,
        db.root(),
        0,
        ops_root_witness,
        |location| common::current_proof_chunk(db.range_proof(location, NZU64!(1))),
    )
    .await
    .expect("recover unordered current boundary")
}

async fn build_any_source_batch() -> AnySourceBatch {
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::any_variable_config(
                "any_unordered_variable_mmr_connect_source",
                page_cache,
                (
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                ),
                NZU64!(8),
            );
            let mut db: AnyDb = AnyDb::init(
                context.child("any_unordered_variable_mmr_connect_source"),
                cfg,
            )
            .await
            .expect("init");

            let mut ops = Vec::new();
            let mut inactivity_floor = Location::<mmr::Family>::new(0);
            for batch_index in 0..64 {
                let finalized = {
                    let batch = db
                        .new_batch()
                        .write(b"alpha".to_vec(), Some(b"one".to_vec()))
                        .write(
                            format!("k-{batch_index:08}").into_bytes(),
                            Some(b"two".to_vec()),
                        );
                    batch
                        .merkleize(&db, None::<Vec<u8>>)
                        .await
                        .expect("merkleize")
                };
                (db, _) = db.apply_batch(finalized).await.expect("apply");

                let latest = db.bounds().end - 1;
                let n = NonZeroU64::new(*latest + 1).unwrap();
                let (_proof, cumulative): (BatchProof, Vec<BatchOperation>) = db
                    .historical_proof(latest + 1, Location::new(0), n)
                    .await
                    .expect("proof");
                inactivity_floor = latest_inactivity_floor(&cumulative);
                ops = cumulative;
                if *inactivity_floor > 0 {
                    break;
                }
            }
            assert!(
                *inactivity_floor > 0,
                "unordered MMR subscribe fixture must exercise nonzero inactivity floor"
            );
            let root = db.root();

            db = db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            AnySourceBatch {
                operations: ops,
                root,
                inactivity_floor,
            }
        })
    })
    .await
    .expect("join")
}

fn latest_inactivity_floor(operations: &[BatchOperation]) -> Location<mmr::Family> {
    operations
        .iter()
        .rev()
        .find_map(|operation| match operation {
            BatchOperation::CommitFloor(_, floor) => Some(*floor),
            _ => None,
        })
        .expect("batch has CommitFloor")
}

async fn build_mmb_any_source_batch() -> MmbAnySourceBatch {
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::any_variable_config(
                "any_unordered_variable_mmb_connect_source",
                page_cache,
                (
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                ),
                NZU64!(8),
            );
            let mut db: MmbAnyDb = MmbAnyDb::init(
                context.child("any_unordered_variable_mmb_connect_source"),
                cfg,
            )
            .await
            .expect("init");

            let mut ops = Vec::new();
            let mut inactivity_floor = Location::<mmb::Family>::new(0);
            for batch_index in 0..64 {
                let finalized = {
                    let batch = db
                        .new_batch()
                        .write(b"alpha".to_vec(), Some(b"one".to_vec()))
                        .write(
                            format!("k-{batch_index:08}").into_bytes(),
                            Some(b"two".to_vec()),
                        );
                    batch
                        .merkleize(&db, None::<Vec<u8>>)
                        .await
                        .expect("merkleize")
                };
                (db, _) = db.apply_batch(finalized).await.expect("apply");

                let latest = db.bounds().end - 1;
                let n = NonZeroU64::new(*latest + 1).unwrap();
                let (_proof, cumulative): (MmbBatchProof, Vec<MmbBatchOperation>) = db
                    .historical_proof(latest + 1, Location::new(0), n)
                    .await
                    .expect("proof");
                inactivity_floor = latest_mmb_inactivity_floor(&cumulative);
                ops = cumulative;
                if *inactivity_floor > 0 {
                    break;
                }
            }
            assert!(
                *inactivity_floor > 0,
                "unordered MMB subscribe fixture must exercise nonzero inactivity floor"
            );
            let root = db.root();

            db = db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            MmbAnySourceBatch {
                operations: ops,
                root,
                inactivity_floor,
            }
        })
    })
    .await
    .expect("join")
}

fn latest_mmb_inactivity_floor(operations: &[MmbBatchOperation]) -> Location<mmb::Family> {
    operations
        .iter()
        .rev()
        .find_map(|operation| match operation {
            MmbBatchOperation::CommitFloor(_, floor) => Some(*floor),
            _ => None,
        })
        .expect("batch has CommitFloor")
}

async fn build_current_source_batch() -> CurrentSourceBatch {
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::current_variable_config(
                "current_unordered_variable_mmr_connect_source",
                page_cache,
                fixed_key_op_cfg(),
                NZU64!(8),
            );
            let mut db: CurrentDb = CurrentDb::init(
                context.child("current_unordered_variable_mmr_connect_source"),
                cfg,
            )
            .await
            .expect("init");

            let alpha = Sha256::fill(0xA1);
            let beta = Sha256::fill(0xB2);
            let finalized = {
                let batch = db
                    .new_batch()
                    .write(alpha, Some(b"one".to_vec()))
                    .write(beta, Some(b"two".to_vec()));
                batch
                    .merkleize(&db, None::<Vec<u8>>)
                    .await
                    .expect("merkleize")
            };
            (db, _) = db.apply_batch(finalized).await.expect("apply");

            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops): (BatchProof, Vec<FixedKeyOperation>) = db
                .ops_historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");
            let boundary = boundary_from_current_source_db(&db, &ops).await;

            db = db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            CurrentSourceBatch {
                latest_location: latest,
                alpha,
                beta,
                root: boundary.root,
                operations: ops,
                current_boundary: boundary,
            }
        })
    })
    .await
    .expect("join")
}

async fn commit_upload(store_client: &StoreClient, batch: &AnySourceBatch) {
    common::commit_operations::<mmr::Family, BatchOperation>(
        &PrefixedStoreClient::empty(store_client.clone()),
        &batch.operations,
        &op_cfg(),
    )
    .await
    .expect("commit upload");
}

async fn commit_mmb_upload(store_client: &StoreClient, batch: &MmbAnySourceBatch) {
    common::commit_operations::<mmb::Family, MmbBatchOperation>(
        &PrefixedStoreClient::empty(store_client.clone()),
        &batch.operations,
        &op_cfg(),
    )
    .await
    .expect("commit upload");
}

async fn commit_current_upload(store_client: &StoreClient, batch: &CurrentSourceBatch) {
    common::commit_current_operations::<mmr::Family, FixedKeyOperation, N>(
        &PrefixedStoreClient::empty(store_client.clone()),
        &batch.operations,
        &fixed_key_op_cfg(),
        &batch.current_boundary,
    )
    .await
    .expect("commit current upload");
}

fn latest_operation_for_fixed_key(
    operations: &[FixedKeyOperation],
    key: &[u8],
) -> (Location<mmr::Family>, FixedKeyOperation) {
    operations
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, operation)| match operation {
            FixedKeyOperation::Update(update) if update.0.as_ref() == key => {
                Some((Location::new(index as u64), operation.clone()))
            }
            FixedKeyOperation::Delete(found) if found.as_ref() == key => {
                Some((Location::new(index as u64), operation.clone()))
            }
            _ => None,
        })
        .expect("matching operation")
}

#[tokio::test]
async fn test_unordered_range_stack_does_not_expose_key_lookup_or_ordered_range_services() {
    let store_client = common::local_store_client().await;
    let unordered_client = Arc::new(TestUnorderedClient::new(
        PrefixedStoreClient::empty(store_client),
        op_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_range_server(unordered_client).await;

    let err = key_lookup_rpc_client(&qmdb_url)
        .get_many(ProtoGetManyRequest {
            keys: vec![b"alpha".to_vec()],
            tip: 0,
            ..Default::default()
        })
        .await
        .expect_err("unordered stack should not expose KeyLookupService");
    assert_eq!(err.code, ErrorCode::Unimplemented);

    let err = ordered_range_rpc_client(&qmdb_url)
        .get_range(ProtoGetRangeRequest {
            start_key: b"a".to_vec(),
            limit: 1,
            tip: 0,
            ..Default::default()
        })
        .await
        .expect_err("unordered stack should not expose OrderedKeyRangeService");
    assert_eq!(err.code, ErrorCode::Unimplemented);
}

#[tokio::test]
async fn test_unordered_connect_get_operation_range_returns_verifiable_proof() {
    let store_client = common::local_store_client().await;
    let source = build_any_source_batch().await;
    commit_upload(&store_client, &source).await;

    let unordered_client = Arc::new(TestUnorderedClient::new(
        PrefixedStoreClient::empty(store_client),
        op_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_range_server(unordered_client).await;
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
async fn test_unordered_connect_get_many_returns_present_key_proofs() {
    let store_client = common::local_store_client().await;
    let source = build_current_source_batch().await;
    commit_current_upload(&store_client, &source).await;

    let unordered_client = Arc::new(FixedKeyClient::new(
        PrefixedStoreClient::empty(store_client),
        fixed_key_op_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_full_server(unordered_client).await;
    let connect_client = key_lookup_client(&qmdb_url);

    let results = connect_client
        .get_many(
            ProtoGetManyRequest {
                keys: vec![
                    source.alpha.as_ref().to_vec(),
                    source.beta.as_ref().to_vec(),
                ],
                tip: source.latest_location.as_u64(),
                ..Default::default()
            },
            &source.root,
        )
        .await
        .expect("get_many");

    let expected_alpha = latest_operation_for_fixed_key(&source.operations, source.alpha.as_ref());
    let expected_beta = latest_operation_for_fixed_key(&source.operations, source.beta.as_ref());
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].root, source.root);
    assert_eq!(results[0].location, expected_alpha.0);
    assert_eq!(results[0].operation, expected_alpha.1);
    assert_eq!(results[1].root, source.root);
    assert_eq!(results[1].location, expected_beta.0);
    assert_eq!(results[1].operation, expected_beta.1);

    let one = connect_client
        .get(
            ProtoGetRequest {
                key: source.alpha.as_ref().to_vec(),
                tip: source.latest_location.as_u64(),
                ..Default::default()
            },
            &source.root,
        )
        .await
        .expect("get");
    assert_eq!(one.location, expected_alpha.0);
    assert_eq!(one.operation, expected_alpha.1);
}

#[tokio::test]
async fn test_unordered_current_operation_range_connect_returns_verifiable_proof() {
    let store_client = common::local_store_client().await;
    let source = build_current_source_batch().await;
    commit_current_upload(&store_client, &source).await;

    let unordered_client = Arc::new(FixedKeyClient::new(
        PrefixedStoreClient::empty(store_client),
        fixed_key_op_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_full_server(unordered_client).await;
    let connect_client = current_operation_client(&qmdb_url);

    let proof = connect_client
        .get_current_operation_range(
            ProtoGetCurrentOperationRangeRequest {
                tip: source.latest_location.as_u64(),
                start_location: 0,
                max_locations: source.operations.len() as u32,
                ..Default::default()
            },
            &source.root,
        )
        .await
        .expect("current operation range");

    assert_eq!(proof.root, source.root);
    assert_eq!(proof.start_location, Location::new(0));
    assert_eq!(proof.operations, source.operations);
    assert!(!proof.chunks.is_empty());
}

async fn aligned_commit_boundary<F: commonware_storage::merkle::Graftable + PartialEq>(
    case_name: &'static str,
) where
    F::PendingChunk<Digest>: 'static,
{
    type Operation<F> = UnorderedQmdbOperation<F, Digest, Vec<u8>>;
    type Db<F> = LocalCurrentUnorderedDb<
        F,
        cw_tokio::Context,
        Digest,
        Vec<u8>,
        Sha256,
        TwoCap,
        N,
        commonware_parallel::Sequential,
    >;
    fn key(index: u16) -> Digest {
        let mut key = Sha256::fill(0);
        key.0[..2].copy_from_slice(&index.to_be_bytes());
        key
    }
    let snapshots = tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::current_variable_config(
                case_name,
                cache,
                ((), ((0..=MAX_OPERATION_SIZE).into(), ())),
                NZU64!(8),
            );
            let mut db = Db::<F>::init(context.child(case_name), cfg)
                .await
                .expect("source init");
            let mut previous: Vec<Operation<F>> = Vec::new();
            let mut snapshots = Vec::new();
            for round in 0..2 {
                let mut batch = db.new_batch();
                if round == 0 {
                    // Fresh writes plus one floor move and the commit fill two bitmap chunks
                    for index in 1u16..=509 {
                        batch = batch.write(key(index), Some(index.to_be_bytes().to_vec()));
                    }
                }
                let batch = batch
                    .merkleize(&db, None::<Vec<u8>>)
                    .await
                    .expect("source merkleize");
                (db, _) = db.apply_batch(batch).await.expect("source apply");
                assert_eq!(*db.bounds().end, if round == 0 { 512 } else { 514 });
                let (_, operations): (_, Vec<Operation<F>>) = db
                    .ops_historical_proof(
                        db.bounds().end,
                        Location::new(0),
                        NonZeroU64::new(*db.bounds().end).unwrap(),
                    )
                    .await
                    .expect("source operations");

                assert!(matches!(
                    operations.last(),
                    Some(Operation::CommitFloor(_, floor)) if floor.as_u64() == round + 2
                ));

                // The empty second batch moves an early key and clears commit 511 in chunk 1
                let (proof, proof_ops, chunks) = db
                    .range_proof(Location::new(257), NZU64!(1))
                    .await
                    .expect("source current proof");
                assert!(proof.verify::<Sha256, _, N>(
                    Location::new(257),
                    &proof_ops,
                    &chunks,
                    &db.root(),
                ));
                assert_eq!(chunks[0][N - 1] & 0x80 != 0, round == 0);
                let source = &db;
                let boundary = recover_boundary_state::<F, Sha256, _, N, _, _>(
                    (!previous.is_empty()).then_some(previous.as_slice()),
                    &operations,
                    db.root(),
                    0,
                    db.ops_root_witness()
                        .await
                        .expect("source ops root witness"),
                    |location| common::current_proof_chunk(source.range_proof(location, NZU64!(1))),
                )
                .await
                .expect("recover current boundary");
                previous = operations.clone();
                snapshots.push((operations, boundary));
            }
            db.destroy().await.expect("destroy source");
            snapshots
        })
    })
    .await
    .expect("join source");

    let store = common::local_store_client().await;
    let prefixed = PrefixedStoreClient::empty(store);
    let op_cfg = ((), ((0..=MAX_OPERATION_SIZE).into(), ()));
    let client = Arc::new(UnorderedClient::<F, Sha256, Digest, Vec<u8>>::new(
        prefixed.clone(),
        op_cfg,
    ));
    let (server, url) =
        common::spawn_connect_service(unordered_connect_stack::<F, Sha256, Digest, Vec<u8>, N, _>(
            client,
            (),
        ))
        .await;
    let connect_client =
        UnorderedConnectClient::<_, F, Sha256, Digest, Vec<u8>, N>::plaintext(&url, op_cfg);
    for (operations, boundary) in snapshots {
        common::commit_current_operations(&prefixed, &operations, &op_cfg, &boundary)
            .await
            .expect("publish current boundary");
        let proof = connect_client
            .get(
                ProtoGetRequest {
                    key: key(257).as_ref().to_vec(),
                    tip: operations.len() as u64 - 1,
                    ..Default::default()
                },
                &boundary.root,
            )
            .await
            .expect("current proof after aligned commit boundary");
        assert_eq!(proof.location, Location::new(257));
        assert_eq!(proof.operation, operations[257]);
    }
    server.abort();
}

#[tokio::test]
async fn test_current_unordered_variable_fixed_keys_variable_values_mmr_aligned_commit_boundary() {
    aligned_commit_boundary::<mmr::Family>(
        "current_unordered_variable_fixed_keys_variable_values_mmr_aligned_commit_boundary",
    )
    .await;
}

#[tokio::test]
async fn test_current_unordered_variable_fixed_keys_variable_values_mmb_aligned_commit_boundary() {
    aligned_commit_boundary::<mmb::Family>(
        "current_unordered_variable_fixed_keys_variable_values_mmb_aligned_commit_boundary",
    )
    .await;
}

async fn current_boundary_nodes<F: commonware_storage::merkle::Graftable + PartialEq>(
    case_name: &'static str,
    key_count: u16,
    empty_batches: u64,
    appended_keys: u16,
) where
    F::PendingChunk<Digest>: 'static,
{
    type Operation<F> = UnorderedQmdbOperation<F, Digest, Vec<u8>>;
    type Db<F> = LocalCurrentUnorderedDb<
        F,
        cw_tokio::Context,
        Digest,
        Vec<u8>,
        Sha256,
        TwoCap,
        N,
        commonware_parallel::Sequential,
    >;
    fn key(index: u16) -> Digest {
        let mut key = Sha256::fill(0);
        key.0[..2].copy_from_slice(&index.to_be_bytes());
        key
    }
    let snapshots = tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::current_variable_config(
                case_name,
                cache,
                ((), ((0..=MAX_OPERATION_SIZE).into(), ())),
                NZU64!(8),
            );
            let mut db = Db::<F>::init(context.child(case_name), cfg)
                .await
                .expect("source init");
            let mut previous: Vec<Operation<F>> = Vec::new();
            let mut snapshots = Vec::new();
            for round in 0..=empty_batches + 1 {
                let mut batch = db.new_batch();
                if round == 0 {
                    for index in 1..=key_count {
                        batch = batch.write(key(index), Some(index.to_be_bytes().to_vec()));
                    }
                } else if round == empty_batches + 1 {
                    for index in key_count + 1..=key_count + appended_keys {
                        batch = batch.write(key(index), Some(index.to_be_bytes().to_vec()));
                    }
                }
                let batch = batch
                    .merkleize(&db, None::<Vec<u8>>)
                    .await
                    .expect("source merkleize");
                (db, _) = db.apply_batch(batch).await.expect("source apply");
                if round < empty_batches {
                    continue;
                }

                // Capture the boundaries before and after the final batch, retaining the operation log
                db = db.prune(Location::new(0)).await.expect("source prune");
                let (_, operations): (_, Vec<Operation<F>>) = db
                    .ops_historical_proof(
                        db.bounds().end,
                        Location::new(0),
                        NonZeroU64::new(*db.bounds().end).unwrap(),
                    )
                    .await
                    .expect("source operations");
                assert_eq!(
                    operations.len() as u64,
                    u64::from(key_count)
                        + 3
                        + 2 * round
                        + if round > empty_batches {
                            u64::from(appended_keys)
                        } else {
                            0
                        }
                );
                assert!(matches!(
                    operations.last(),
                    Some(Operation::CommitFloor(_, floor)) if floor.as_u64() == round + 2
                ));
                let pruned_chunks = *db.sync_boundary() / (N as u64 * 8);
                assert_eq!(pruned_chunks, (round + 2) / (N as u64 * 8));

                // Keys straddling chunk boundaries exercise mixed ancestors and delayed parent creation
                let queries = [255, 256, 512]
                    .into_iter()
                    .filter(|index| *index <= key_count)
                    .map(|index| {
                        let location = operations
                            .iter()
                            .rposition(|operation| {
                                matches!(operation, Operation::Update(update) if update.0 == key(index))
                            })
                            .expect("source key location");
                        (index, Location::new(location as u64))
                    })
                    .collect::<Vec<_>>();
                for (_, location) in &queries {
                    let (proof, proof_ops, chunks) = db
                        .range_proof(*location, NZU64!(1))
                        .await
                        .expect("source current proof");
                    assert!(proof.verify::<Sha256, _, N>(
                        *location,
                        &proof_ops,
                        &chunks,
                        &db.root(),
                    ));
                }

                let source = &db;
                let boundary = recover_boundary_state::<F, Sha256, _, N, _, _>(
                    (!previous.is_empty()).then_some(previous.as_slice()),
                    &operations,
                    db.root(),
                    pruned_chunks,
                    db.ops_root_witness()
                        .await
                        .expect("source ops root witness"),
                    |location| common::current_proof_chunk(source.range_proof(location, NZU64!(1))),
                )
                .await
                .expect("recover current boundary");
                previous = operations.clone();
                snapshots.push((operations, boundary, queries));
            }
            db.destroy().await.expect("destroy source");
            snapshots
        })
    })
    .await
    .expect("join source");

    let store = common::local_store_client().await;
    let prefixed = PrefixedStoreClient::empty(store);
    let op_cfg = ((), ((0..=MAX_OPERATION_SIZE).into(), ()));
    let client = Arc::new(UnorderedClient::<F, Sha256, Digest, Vec<u8>>::new(
        prefixed.clone(),
        op_cfg,
    ));
    let (server, url) =
        common::spawn_connect_service(unordered_connect_stack::<F, Sha256, Digest, Vec<u8>, N, _>(
            client,
            (),
        ))
        .await;
    let key_client =
        UnorderedConnectClient::<_, F, Sha256, Digest, Vec<u8>, N>::plaintext(&url, op_cfg);
    let range_client =
        CurrentOperationClient::<_, F, Sha256, Operation<F>, N>::plaintext(&url, op_cfg);

    // Re-query the older boundary after publication advances to preserve its bitmap and node versions
    for (pass, index) in [0, 1, 0].into_iter().enumerate() {
        let (operations, boundary, queries) = &snapshots[index];
        if pass < 2 {
            common::commit_current_operations(&prefixed, operations, &op_cfg, boundary)
                .await
                .expect("publish current boundary");
        }
        let tip = operations.len() as u64 - 1;
        for (key_index, location) in queries {
            let proof = key_client
                .get(
                    ProtoGetRequest {
                        key: key(*key_index).as_ref().to_vec(),
                        tip,
                        ..Default::default()
                    },
                    &boundary.root,
                )
                .await
                .expect("current key proof across boundary transition");
            assert_eq!(proof.location, *location);
            assert_eq!(proof.operation, operations[**location as usize]);
            let proof = range_client
                .get_current_operation_range(
                    ProtoGetCurrentOperationRangeRequest {
                        tip,
                        start_location: **location,
                        max_locations: 1,
                        ..Default::default()
                    },
                    &boundary.root,
                )
                .await
                .expect("current range proof across boundary transition");
            assert_eq!(proof.operations, operations[**location as usize..][..1]);
        }
    }
    server.abort();
}

#[tokio::test]
async fn test_current_unordered_variable_fixed_keys_variable_values_mmr_pruned_peak() {
    current_boundary_nodes::<mmr::Family>(
        "current_unordered_variable_fixed_keys_variable_values_mmr_pruned_peak",
        500,
        253,
        0,
    )
    .await;
}

#[tokio::test]
async fn test_current_unordered_variable_fixed_keys_variable_values_mmb_pruned_peak() {
    current_boundary_nodes::<mmb::Family>(
        "current_unordered_variable_fixed_keys_variable_values_mmb_pruned_peak",
        500,
        253,
        0,
    )
    .await;
}

#[tokio::test]
async fn test_current_unordered_variable_fixed_keys_variable_values_mmr_pruned_nested_peak() {
    current_boundary_nodes::<mmr::Family>(
        "current_unordered_variable_fixed_keys_variable_values_mmr_pruned_nested_peak",
        1040,
        253,
        0,
    )
    .await;
}

#[tokio::test]
async fn test_current_unordered_variable_fixed_keys_variable_values_mmb_pruned_nested_peak() {
    current_boundary_nodes::<mmb::Family>(
        "current_unordered_variable_fixed_keys_variable_values_mmb_pruned_nested_peak",
        1040,
        253,
        0,
    )
    .await;
}

#[tokio::test]
async fn test_current_unordered_variable_fixed_keys_variable_values_mmb_delayed_parent() {
    current_boundary_nodes::<mmb::Family>(
        "current_unordered_variable_fixed_keys_variable_values_mmb_delayed_parent",
        2400,
        0,
        200,
    )
    .await;
}

#[tokio::test]
async fn test_unordered_connect_omits_missing_and_rejects_duplicate_range_and_stale_root() {
    let store_client = common::local_store_client().await;
    let source = build_current_source_batch().await;
    commit_current_upload(&store_client, &source).await;

    let unordered_client = Arc::new(FixedKeyClient::new(
        PrefixedStoreClient::empty(store_client),
        fixed_key_op_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_full_server(unordered_client).await;

    let missing = Sha256::fill(0xCC);
    let connect_client = key_lookup_client(&qmdb_url);
    let existing = connect_client
        .get_many(
            ProtoGetManyRequest {
                keys: vec![source.alpha.as_ref().to_vec(), missing.as_ref().to_vec()],
                tip: source.latest_location.as_u64(),
                ..Default::default()
            },
            &source.root,
        )
        .await
        .expect("unordered get_many with missing key");
    let expected_alpha = latest_operation_for_fixed_key(&source.operations, source.alpha.as_ref());
    assert_eq!(existing.len(), 1);
    assert_eq!(existing[0].location, expected_alpha.0);
    assert_eq!(existing[0].operation, expected_alpha.1);

    let err = key_lookup_rpc_client(&qmdb_url)
        .get_many(ProtoGetManyRequest {
            keys: vec![
                source.alpha.as_ref().to_vec(),
                source.alpha.as_ref().to_vec(),
            ],
            tip: source.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect_err("duplicate keys should be rejected");
    assert_eq!(err.code, ErrorCode::InvalidArgument);

    let err = ordered_range_rpc_client(&qmdb_url)
        .get_range(ProtoGetRangeRequest {
            start_key: source.alpha.as_ref().to_vec(),
            limit: 1,
            tip: source.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect_err("unordered stack should not expose OrderedKeyRangeService");
    assert_eq!(err.code, ErrorCode::Unimplemented);

    let stale_root = Sha256::fill(0xDD);
    let err = connect_client
        .get_many(
            ProtoGetManyRequest {
                keys: vec![source.alpha.as_ref().to_vec()],
                tip: source.latest_location.as_u64(),
                ..Default::default()
            },
            &stale_root,
        )
        .await
        .expect_err("stale root should be rejected");
    assert!(matches!(
        err,
        QmdbError::ProofVerification {
            kind: exoware_qmdb::ProofKind::CurrentKeyValue
        }
    ));
}

#[tokio::test]
async fn test_current_unordered_variable_fixed_keys_variable_values_mmr_get_many_key_binding() {
    use exoware_qmdb::proto::qmdb::v1::{
        current_key_lookup_result, CurrentKeyLookupResult, GetManyResponse, GetResponse,
        KeyLookupService, KeyLookupServiceServer,
    };

    #[derive(Clone)]
    struct StaticLookup(GetManyResponse);

    #[allow(refining_impl_trait)]
    impl KeyLookupService for StaticLookup {
        async fn get(
            &self,
            _: connectrpc::RequestContext,
            _: connectrpc::ServiceRequest<'_, ProtoGetRequest>,
        ) -> connectrpc::ServiceResult<GetResponse> {
            Err(connectrpc::ConnectError::unimplemented("unused"))
        }

        async fn get_many(
            &self,
            _: connectrpc::RequestContext,
            _: connectrpc::ServiceRequest<'_, ProtoGetManyRequest>,
        ) -> connectrpc::ServiceResult<GetManyResponse> {
            connectrpc::Response::ok(self.0.clone())
        }
    }

    let store = common::local_store_client().await;
    let source = build_current_source_batch().await;
    commit_current_upload(&store, &source).await;
    let client = Arc::new(FixedKeyClient::new(
        PrefixedStoreClient::empty(store),
        fixed_key_op_cfg(),
    ));
    let (server, url) = spawn_qmdb_full_server(client).await;
    let request = ProtoGetManyRequest {
        keys: vec![
            source.alpha.as_ref().to_vec(),
            source.beta.as_ref().to_vec(),
        ],
        tip: *source.latest_location,
        ..Default::default()
    };
    let response = key_lookup_rpc_client(&url)
        .get_many(request.clone())
        .await
        .unwrap()
        .into_view()
        .to_owned_message();
    server.abort();
    let [alpha, beta] = response.results.as_slice() else {
        panic!("two source hits")
    };
    let miss = CurrentKeyLookupResult {
        result: Some(current_key_lookup_result::Result::Miss(Default::default())),
        ..Default::default()
    };
    for (keys, results, valid) in [
        (request.keys.clone(), vec![beta.clone()], true),
        (
            request.keys.clone(),
            vec![beta.clone(), alpha.clone()],
            false,
        ),
        (
            request.keys.clone(),
            vec![alpha.clone(), alpha.clone()],
            false,
        ),
        (vec![request.keys[0].clone()], vec![beta.clone()], false),
        (request.keys.clone(), vec![miss], false),
        (
            request.keys.clone(),
            vec![CurrentKeyLookupResult::default()],
            false,
        ),
    ] {
        let (server, url) = common::spawn_connect_service(connectrpc::ConnectRpcService::new(
            KeyLookupServiceServer::new(StaticLookup(GetManyResponse {
                results,
                ..Default::default()
            })),
        ))
        .await;
        let result = key_lookup_client(&url)
            .get_many(
                ProtoGetManyRequest {
                    keys,
                    ..request.clone()
                },
                &source.root,
            )
            .await;
        server.abort();
        if valid {
            let hits = result.expect("unordered omissions are allowed");
            assert_eq!(hits.len(), 1);
            assert!(
                matches!(&hits[0].operation, FixedKeyOperation::Update(update) if update.0 == source.beta)
            );
        } else {
            assert!(matches!(
                result,
                Err(QmdbError::ProofVerification { .. } | QmdbError::CorruptData(_))
            ));
        }
    }
}

#[tokio::test]
async fn test_unordered_connect_subscribe_emits_verifiable_range_proof() {
    let store_client = common::local_store_client().await;
    let source = build_any_source_batch().await;
    assert!(
        *source.inactivity_floor > 0,
        "test must not rely on inactivity_floor = 0"
    );
    let unordered_client = Arc::new(TestUnorderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_range_server(unordered_client).await;
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
    let expected: Vec<(Location<mmr::Family>, BatchOperation)> = source
        .operations
        .iter()
        .enumerate()
        .map(|(i, op)| (Location::new(i as u64), op.clone()))
        .collect();
    assert_eq!(frame.operations, expected);
}

#[tokio::test]
async fn test_unordered_mmb_connect_subscribe_emits_verifiable_range_proof() {
    let store_client = common::local_store_client().await;
    let source = build_mmb_any_source_batch().await;
    assert!(
        *source.inactivity_floor > 0,
        "test must not rely on inactivity_floor = 0"
    );
    let unordered_client = Arc::new(MmbTestUnorderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_mmb_qmdb_range_server(unordered_client).await;
    let connect_client = mmb_operation_log_client(&qmdb_url);

    let mut stream = connect_client
        .subscribe(ProtoSubscribeRequest::default())
        .await
        .expect("subscribe");

    tokio::time::sleep(Duration::from_millis(50)).await;
    commit_mmb_upload(&store_client, &source).await;

    let frame: OperationLogSubscribeProof<Digest, MmbBatchOperation, mmb::Family> =
        tokio::time::timeout(
            Duration::from_secs(5),
            stream.message_with_root(common::trusted_root(source.root)),
        )
        .await
        .expect("timeout")
        .expect("stream result")
        .expect("stream frame");

    assert!(frame.resume_sequence_number > 0);
    let expected: Vec<(Location<mmb::Family>, MmbBatchOperation)> = source
        .operations
        .iter()
        .enumerate()
        .map(|(i, op)| (Location::<mmb::Family>::new(i as u64), op.clone()))
        .collect();
    assert_eq!(frame.operations, expected);
}

#[tokio::test]
async fn test_unordered_connect_client_rejects_invalid_streamed_proof() {
    let store_client = common::local_store_client().await;
    let source = build_any_source_batch().await;
    commit_upload(&store_client, &source).await;

    let unordered_client = Arc::new(TestUnorderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_range_server(unordered_client).await;
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
