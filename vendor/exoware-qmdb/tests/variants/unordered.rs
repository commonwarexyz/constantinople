//! Unordered QMDB codecs and proof families through native and Connect adapters

use crate::common;

use std::fmt::Debug;
use std::num::NonZeroU64;
use std::sync::Arc;

use commonware_codec::{Codec, Encode, Read};
use commonware_cryptography::Sha256;
use commonware_parallel::Sequential;
use commonware_runtime::{tokio as cw_tokio, Runner as _};
use commonware_storage::merkle::{mmb, mmr, Graftable, Location, Proof};
use commonware_storage::qmdb::{
    any::{
        unordered,
        value::{FixedEncoding, ValueEncoding, VariableEncoding},
    },
    operation::Key as QmdbKey,
};
use commonware_utils::{iter::zip_eq, NZUsize, NZU16, NZU64};
use exoware_qmdb::proto::qmdb::v1::{
    GetCurrentOperationRangeRequest, GetManyRequest, GetOperationRangeRequest, GetRequest,
};
use exoware_qmdb::{
    prepare_authenticated_range, recover_boundary_state, stage_authenticated_range,
    stage_watermark, unordered_connect_stack, unordered_operation_log_connect_stack,
    AuthenticatedOperationRange, CurrentBoundaryState, CurrentOperationClient, OperationLogClient,
    UnorderedClient, UnorderedConnectClient, UploadOperation, MAX_OPERATION_SIZE,
};
use exoware_sdk::{PrefixedStoreClient, StoreWriteBatch};

const N: usize = 32;
type Digest = commonware_cryptography::sha256::Digest;

struct Snapshot<F: Graftable, K: QmdbKey, E: ValueEncoding> {
    start: Location<F>,
    proof: Proof<F, Digest>,
    pinned_nodes: Vec<Digest>,
    operations: Vec<unordered::Operation<F, K, E>>,
    ops_root: Digest,
    current: Option<CurrentBoundaryState<Digest, N, F>>,
    values: Vec<Option<E::Value>>,
}

async fn check_mirror<F, K, V, E>(
    case_name: &str,
    snapshots: Vec<Snapshot<F, K, E>>,
    keys: Vec<K>,
    op_cfg: <unordered::Operation<F, K, E> as Read>::Cfg,
    key_cfg: K::Cfg,
) where
    F: Graftable,
    K: QmdbKey + Codec + Send + Sync,
    V: Codec + Clone + AsRef<[u8]> + Debug + Eq + Send + Sync + 'static,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: UploadOperation<F> + Debug + PartialEq,
    F::PendingChunk<Digest>: 'static,
{
    let store = common::local_store_client().await;
    let prefixed = PrefixedStoreClient::empty(store.clone());
    let local = Arc::new(UnorderedClient::<F, Sha256, K, V, E>::new(
        prefixed.clone(),
        op_cfg.clone(),
    ));
    let (server, url) = if snapshots[0].current.is_some() {
        common::spawn_connect_service(unordered_connect_stack::<F, Sha256, K, V, N, E>(
            local.clone(),
            key_cfg,
        ))
        .await
    } else {
        common::spawn_connect_service(unordered_operation_log_connect_stack(local.clone())).await
    };
    let remote = OperationLogClient::<_, F, Sha256, unordered::Operation<F, K, E>>::plaintext(
        &url,
        op_cfg.clone(),
    );
    let current =
        CurrentOperationClient::<_, F, Sha256, unordered::Operation<F, K, E>, N>::plaintext(
            &url,
            op_cfg.clone(),
        );
    let lookup =
        UnorderedConnectClient::<_, F, Sha256, K, V, N, E>::plaintext(&url, op_cfg.clone());
    let wrong_root = Sha256::fill(0xDD);
    for snapshot in &snapshots {
        let tip = Location::<F>::new(snapshot.operations.len() as u64 - 1);
        let encoded_operations = snapshot.operations[*snapshot.start as usize..]
            .iter()
            .map(|operation| operation.encode().to_vec())
            .collect::<Vec<_>>();
        let authenticated = AuthenticatedOperationRange {
            start_location: snapshot.start,
            proof: &snapshot.proof,
            pinned_nodes: &snapshot.pinned_nodes,
            encoded_operations: &encoded_operations,
        };
        assert!(
            prepare_authenticated_range::<F, Sha256, unordered::Operation<F, K, E>, Sequential>(
                &authenticated,
                &wrong_root,
                &op_cfg,
                &Sequential
            )
            .is_err()
        );
        let mut malformed = snapshot.proof.clone();
        malformed.digests.push(wrong_root);
        assert!(
            prepare_authenticated_range::<F, Sha256, unordered::Operation<F, K, E>, Sequential>(
                &AuthenticatedOperationRange {
                    start_location: snapshot.start,
                    proof: &malformed,
                    pinned_nodes: &snapshot.pinned_nodes,
                    encoded_operations: &encoded_operations,
                },
                &snapshot.ops_root,
                &op_cfg,
                &Sequential,
            )
            .is_err()
        );
        let mut prepared = prepare_authenticated_range::<
            F,
            Sha256,
            unordered::Operation<F, K, E>,
            Sequential,
        >(&authenticated, &snapshot.ops_root, &op_cfg, &Sequential)
        .expect("prepare source batch");
        if let Some(boundary) = &snapshot.current {
            prepared = prepared
                .with_current_boundary::<Sha256, N>(boundary)
                .expect("attach current boundary");
        }
        let mut data = StoreWriteBatch::new();
        stage_authenticated_range(&prefixed, prepared, &mut data).expect("stage source batch");
        data.commit(&store).await.expect("persist source batch");

        // Identical overlapping uploads need no uploader state or ordering information
        data.commit(&store).await.expect("retry source batch");
        let mut publish = StoreWriteBatch::new();
        stage_watermark::<F>(&prefixed, tip, &mut publish).expect("stage publication");
        publish.commit(&store).await.expect("publish source batch");

        let uploaded = snapshot.operations.len();
        assert_eq!(
            local.root_at(tip).await.expect("ops root"),
            snapshot.ops_root
        );
        let found = local
            .query_many_at(&keys, tip)
            .await
            .expect("native lookup");
        for (found, expected) in zip_eq(&found, &snapshot.values) {
            assert_eq!(
                found.as_ref().and_then(|item| item.value.as_ref()),
                expected.as_ref()
            );
        }
        let native_range = local
            .operation_range_proof(tip, Location::new(0), uploaded as u32)
            .await
            .expect("native historical proof");
        assert_eq!(native_range.root, snapshot.ops_root);
        assert_eq!(native_range.operations, snapshot.operations);

        // Current RPCs authenticate historical ranges through the source's canonical root
        let trusted_root = snapshot
            .current
            .as_ref()
            .map_or(snapshot.ops_root, |b| b.root);
        let request = GetOperationRangeRequest {
            tip: tip.as_u64(),
            start_location: 0,
            max_locations: uploaded as u32,
            ..Default::default()
        };
        let proof = remote
            .get_operation_range(request.clone(), &trusted_root)
            .await
            .expect("remote historical proof");
        assert_eq!(proof.root, trusted_root);
        assert_eq!(proof.operations, snapshot.operations);
        if uploaded >= 3 {
            let suffix = remote
                .get_operation_range(
                    GetOperationRangeRequest {
                        start_location: 1,
                        max_locations: 2,
                        ..request.clone()
                    },
                    &trusted_root,
                )
                .await
                .expect("nonzero historical proof");
            assert_eq!(suffix.operations, snapshot.operations[1..3]);
        }
        assert!(remote
            .get_operation_range(request.clone(), &wrong_root)
            .await
            .is_err());

        if snapshot.operations.len() == snapshots.last().unwrap().operations.len() {
            let request = GetOperationRangeRequest {
                tip: *tip,
                start_location: *snapshot.start,
                max_locations: encoded_operations.len() as u32,
                ..Default::default()
            };
            let response = common::operation_log_rpc_client(&url)
                .get_operation_range(request.clone())
                .await
                .expect("browser fixture proof")
                .into_view()
                .to_owned_message();
            crate::browser::assert_fixture(
                case_name,
                &trusted_root,
                &request,
                &response,
                &encoded_operations,
            );
        }

        // A trusted root must not make a malformed wire proof acceptable
        let mut response = common::operation_log_rpc_client(&url)
            .get_operation_range(request.clone())
            .await
            .expect("raw historical proof")
            .into_view()
            .to_owned_message();
        response.proof.as_option_mut().expect("proof").proof = Vec::new().into();
        let (bad_server, bad_url) =
            common::spawn_static_operation_range_service(common::StaticOperationRangeService {
                operation_range_response: response,
            })
            .await;
        let bad_remote =
            OperationLogClient::<_, F, Sha256, unordered::Operation<F, K, E>>::plaintext(
                &bad_url,
                op_cfg.clone(),
            );
        assert!(bad_remote
            .get_operation_range(request, &trusted_root)
            .await
            .is_err());
        bad_server.abort();

        if snapshot.current.is_some() {
            assert_eq!(
                local.current_root_at(tip).await.expect("current root"),
                trusted_root
            );
            let range_request = GetCurrentOperationRangeRequest {
                tip: tip.as_u64(),
                start_location: 0,
                max_locations: uploaded as u32,
                ..Default::default()
            };
            let proof = current
                .get_current_operation_range(range_request.clone(), &trusted_root)
                .await
                .expect("current operation range");
            assert_eq!(proof.root, trusted_root);
            assert_eq!(proof.operations, snapshot.operations);
            assert!(current
                .get_current_operation_range(range_request, &wrong_root)
                .await
                .is_err());

            // Reversed request order also checks omission of absent or deleted keys
            let results = lookup
                .get_many(
                    GetManyRequest {
                        tip: tip.as_u64(),
                        keys: keys.iter().rev().map(|key| key.encode().to_vec()).collect(),
                        ..Default::default()
                    },
                    &trusted_root,
                )
                .await
                .expect("current key hits");
            let expected: Vec<_> = keys
                .iter()
                .zip(&snapshot.values)
                .rev()
                .filter_map(|(key, value)| value.as_ref().map(|value| (key, value)))
                .collect();
            assert_eq!(results.len(), expected.len());
            for (result, (key, value)) in results.iter().zip(expected) {
                let unordered::Operation::Update(update) = &result.operation else {
                    panic!("key hit must authenticate an update");
                };
                assert_eq!(&update.0, key);
                assert_eq!(&update.1, value);
                assert_eq!(result.root, trusted_root);
            }
            let get_request = GetRequest {
                tip: tip.as_u64(),
                key: keys[0].encode().to_vec(),
                ..Default::default()
            };
            if let Some(value) = &snapshot.values[0] {
                let hit = lookup
                    .get(get_request.clone(), &trusted_root)
                    .await
                    .expect("current key hit");
                let unordered::Operation::Update(update) = hit.operation else {
                    panic!("key hit must authenticate an update");
                };
                assert_eq!(update.0, keys[0]);
                assert_eq!(&update.1, value);
            }
            assert!(lookup.get(get_request, &wrong_root).await.is_err());
        }
    }

    // Publishing a later batch must preserve proofs at the earlier trusted tip
    let first = &snapshots[0];
    let trusted_root = first.current.as_ref().map_or(first.ops_root, |b| b.root);
    let proof = remote
        .get_operation_range(
            GetOperationRangeRequest {
                tip: first.operations.len() as u64 - 1,
                start_location: 0,
                max_locations: first.operations.len() as u32,
                ..Default::default()
            },
            &trusted_root,
        )
        .await
        .expect("historical tip after continuation");
    assert_eq!(proof.operations, first.operations);
    server.abort();
}

macro_rules! key_type {
    (variable) => { Vec<u8> };
    (fixed) => { Digest };
}

macro_rules! keys {
    (variable) => {
        vec![b"a".to_vec(), b"a\0".to_vec(), b"a\0b".to_vec()]
    };
    (fixed) => {
        vec![Sha256::fill(0x11), Sha256::fill(0x22), Sha256::fill(0x33)]
    };
}

macro_rules! value_type {
    (variable) => { Vec<u8> };
    (fixed) => { Digest };
}

macro_rules! encoding_type {
    (variable, $v:ty) => { VariableEncoding<$v> };
    (fixed, $v:ty) => { FixedEncoding<$v> };
}

macro_rules! values {
    (variable) => {
        [b"one".to_vec(), b"second".to_vec(), b"replacement".to_vec()]
    };
    (fixed) => {
        [Sha256::fill(0x41), Sha256::fill(0x42), Sha256::fill(0x43)]
    };
}

macro_rules! codec_cfg {
    (variable) => {
        ((0..=MAX_OPERATION_SIZE).into(), ())
    };
    (fixed) => {
        ()
    };
}

macro_rules! op_cfg {
    (variable, $key:ident, $value:ident) => {
        (codec_cfg!($key), codec_cfg!($value))
    };
    (fixed, fixed, fixed) => {
        ()
    };
}

macro_rules! source_proof {
    (any, $db:ident, $count:expr) => {
        $db.historical_proof($db.bounds().end, Location::new(0), $count)
            .await
            .expect("source historical proof")
    };
    (current, $db:ident, $count:expr) => {
        $db.ops_historical_proof($db.bounds().end, Location::new(0), $count)
            .await
            .expect("source historical proof")
    };
}

macro_rules! ops_root {
    (any, $db:ident) => {
        $db.root()
    };
    (current, $db:ident) => {
        $db.ops_root()
    };
}

macro_rules! current_boundary {
    (any, $f:ty, $db:ident, $ops:ident, $previous:expr) => {
        None
    };
    (current, $f:ty, $db:ident, $ops:ident, $previous:expr) => {{
        let source = &$db;
        Some(
            recover_boundary_state::<$f, Sha256, _, N, _, _>(
                $previous,
                &$ops,
                $db.root(),
                0,
                $db.ops_root_witness()
                    .await
                    .expect("source ops root witness"),
                |location| common::current_proof_chunk(source.range_proof(location, NZU64!(1))),
            )
            .await
            .expect("recover source current boundary"),
        )
    }};
}

macro_rules! capture_batch_proof {
    (any, $batch:ident, $db:ident) => {
        Some((
            $batch.proof(&$db).expect("source batch proof before apply"),
            $batch
                .pinned_nodes(&$db)
                .expect("source batch pins before apply"),
        ))
    };
    (current, $batch:ident, $db:ident) => {
        None
    };
}

macro_rules! applied_batch_proof {
    (any, $db:ident, $start:expr, $count:expr) => {
        $db.historical_proof($db.bounds().end, $start, $count)
            .await
            .expect("source batch historical proof")
    };
    (current, $db:ident, $start:expr, $count:expr) => {
        $db.ops_historical_proof($db.bounds().end, $start, $count)
            .await
            .expect("source batch historical proof")
    };
}

macro_rules! case {
    ($name:ident, $state:ident, $family:ty, $encoding:ident, $key:ident, $value:ident) => {
        #[tokio::test]
        async fn $name() {
            type F = $family;
            type K = key_type!($key);
            type V = value_type!($value);
            type E = encoding_type!($encoding, V);
            type Op = unordered::Operation<F, K, E>;
            type Db = source_type!($state, unordered, $encoding, F, K, V);

            let keys: Vec<K> = keys!($key);
            let source_keys = keys.clone();
            let snapshots = tokio::task::spawn_blocking(move || {
                cw_tokio::Runner::default().start(|context| async move {
                    use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
                    let cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
                    let cfg = source_config!(
                        $state,
                        $encoding,
                        stringify!($name),
                        cache,
                        op_cfg!($encoding, $key, $value)
                    );
                    let mut db = Db::init(context.child(stringify!($name)), cfg)
                        .await
                        .expect("source init");
                    let values: [V; 3] = values!($value);
                    let mut snapshots: Vec<Snapshot<F, K, E>> = Vec::new();

                    // The initial commit is a separate packet, just like a retained prefix
                    let initial_count = NonZeroU64::new(*db.bounds().end).expect("initial commit");
                    let (proof, operations): (_, Vec<Op>) =
                        source_proof!($state, db, initial_count);
                    let initial_boundary =
                        current_boundary!($state, F, db, operations, None::<&[Op]>);
                    snapshots.push(Snapshot {
                        start: Location::new(0),
                        proof,
                        pinned_nodes: Vec::new(),
                        operations,
                        ops_root: ops_root!($state, db),
                        current: initial_boundary,
                        values: vec![None, None, None],
                    });

                    for round in 0..2 {
                        let batch = if round == 0 {
                            db.new_batch()
                                .write(source_keys[0].clone(), Some(values[0].clone()))
                                .write(source_keys[1].clone(), Some(values[1].clone()))
                        } else {
                            db.new_batch()
                                .write(source_keys[0].clone(), Some(values[2].clone()))
                                .write(source_keys[1].clone(), None)
                                .write(source_keys[2].clone(), Some(values[1].clone()))
                        };
                        let batch = batch
                            .merkleize(&db, None::<V>)
                            .await
                            .expect("source merkleize");
                        let (start, appended) = batch.operations();
                        let batch_root = batch.root();
                        let captured: Option<(Proof<F, Digest>, Vec<Digest>)> =
                            capture_batch_proof!($state, batch, db);
                        (db, _) = db.apply_batch(batch).await.expect("source apply");
                        assert_eq!(db.root(), batch_root);
                        let count = NonZeroU64::new(*db.bounds().end).expect("nonempty source");
                        let (_, operations): (_, Vec<Op>) = source_proof!($state, db, count);
                        assert_eq!(&operations[*start as usize..], appended.as_slice());
                        if let Some(previous) = snapshots.last() {
                            assert_eq!(
                                &operations[..previous.operations.len()],
                                previous.operations
                            );
                        }
                        let (proof, pinned_nodes) = match captured {
                            Some(proof) => proof,
                            None => {
                                let appended_count = NonZeroU64::new(appended.len() as u64)
                                    .expect("batch has a commit");
                                let (proof, proof_operations) =
                                    applied_batch_proof!($state, db, start, appended_count);
                                assert_eq!(proof_operations, *appended);
                                let pins = db.pinned_nodes_at(start).await.expect("source pins");
                                (proof, pins)
                            }
                        };
                        let expected = if round == 0 {
                            vec![Some(values[0].clone()), Some(values[1].clone()), None]
                        } else {
                            vec![Some(values[2].clone()), None, Some(values[1].clone())]
                        };
                        for (key, value) in source_keys.iter().zip(&expected) {
                            assert_eq!(db.get(key).await.expect("source get"), *value);
                        }
                        let boundary = current_boundary!(
                            $state,
                            F,
                            db,
                            operations,
                            snapshots
                                .last()
                                .map(|previous| previous.operations.as_slice())
                        );
                        snapshots.push(Snapshot {
                            start,
                            proof,
                            pinned_nodes,
                            ops_root: ops_root!($state, db),
                            operations,
                            current: boundary,
                            values: expected,
                        });
                    }
                    db.destroy().await.expect("destroy source");
                    snapshots
                })
            })
            .await
            .expect("source task");

            check_mirror::<F, K, V, E>(
                stringify!($name),
                snapshots,
                keys,
                op_cfg!($encoding, $key, $value),
                codec_cfg!($key),
            )
            .await;
        }
    };
}

macro_rules! cases {
    ($( $name:ident: $state:ident, $family:ty, $encoding:ident, $key:ident, $value:ident; )*) => {
        $(case!($name, $state, $family, $encoding, $key, $value);)*
    };
}

cases! {
    test_any_unordered_fixed_fixed_keys_fixed_values_mmr: any, mmr::Family, fixed, fixed, fixed;
    test_any_unordered_fixed_fixed_keys_fixed_values_mmb: any, mmb::Family, fixed, fixed, fixed;
    test_any_unordered_variable_fixed_keys_fixed_values_mmr: any, mmr::Family, variable, fixed, fixed;
    test_any_unordered_variable_fixed_keys_fixed_values_mmb: any, mmb::Family, variable, fixed, fixed;
    test_any_unordered_variable_fixed_keys_variable_values_mmr: any, mmr::Family, variable, fixed, variable;
    test_any_unordered_variable_fixed_keys_variable_values_mmb: any, mmb::Family, variable, fixed, variable;
    test_any_unordered_variable_variable_keys_fixed_values_mmr: any, mmr::Family, variable, variable, fixed;
    test_any_unordered_variable_variable_keys_fixed_values_mmb: any, mmb::Family, variable, variable, fixed;
    test_any_unordered_variable_variable_keys_variable_values_mmr: any, mmr::Family, variable, variable, variable;
    test_any_unordered_variable_variable_keys_variable_values_mmb: any, mmb::Family, variable, variable, variable;
    test_current_unordered_fixed_fixed_keys_fixed_values_mmr: current, mmr::Family, fixed, fixed, fixed;
    test_current_unordered_fixed_fixed_keys_fixed_values_mmb: current, mmb::Family, fixed, fixed, fixed;
    test_current_unordered_variable_fixed_keys_fixed_values_mmr: current, mmr::Family, variable, fixed, fixed;
    test_current_unordered_variable_fixed_keys_fixed_values_mmb: current, mmb::Family, variable, fixed, fixed;
    test_current_unordered_variable_fixed_keys_variable_values_mmr: current, mmr::Family, variable, fixed, variable;
    test_current_unordered_variable_fixed_keys_variable_values_mmb: current, mmb::Family, variable, fixed, variable;
    test_current_unordered_variable_variable_keys_fixed_values_mmr: current, mmr::Family, variable, variable, fixed;
    test_current_unordered_variable_variable_keys_fixed_values_mmb: current, mmb::Family, variable, variable, fixed;
    test_current_unordered_variable_variable_keys_variable_values_mmr: current, mmr::Family, variable, variable, variable;
    test_current_unordered_variable_variable_keys_variable_values_mmb: current, mmb::Family, variable, variable, variable;
}
