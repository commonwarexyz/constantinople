#![allow(clippy::type_complexity)]

//! Public ordered source variants through shared native and Connect adapters

use crate::common;

use exoware_qmdb::proof::RawKeyLookupProof;

use std::{collections::BTreeMap, fmt::Debug, sync::Arc};

use commonware_codec::{Codec, Encode, Read};
use commonware_cryptography::Sha256;
use commonware_parallel::Sequential;
use commonware_runtime::{
    buffer::paged::CacheRef, tokio as cw_tokio, Runner as _, Supervisor as _,
};
use commonware_storage::{
    merkle::{mmb, mmr, Graftable, Location, Proof},
    qmdb::{
        any::{
            ordered,
            value::{FixedEncoding, ValueEncoding, VariableEncoding},
        },
        current::ordered::ExclusionProof,
        operation::Key as QmdbKey,
    },
};
use commonware_utils::{
    bitmap::Readable as _, iter::zip_eq, sequence::FixedBytes, NZUsize, NZU16, NZU64,
};
use exoware_qmdb::proto::qmdb::v1::{
    GetCurrentOperationRangeRequest, GetManyRequest, GetOperationRangeRequest, GetRangeRequest,
    GetRequest, SubscribeRequest,
};
use exoware_qmdb::{
    ordered_connect_stack, ordered_operation_log_connect_stack, prepare_authenticated_range,
    recover_boundary_state, stage_authenticated_range, stage_watermark,
    AuthenticatedOperationRange, CurrentBoundaryState, CurrentOperationClient, OperationLogClient,
    OrderedClient, OrderedConnectClient, UploadOperation, VerifiedKeyLookup, MAX_OPERATION_SIZE,
};
use exoware_sdk::{proto::PreferZstdHttpClient, PrefixedStoreClient, StoreWriteBatch};

const N: usize = 32;
type Digest = commonware_cryptography::sha256::Digest;
type Operation<F, K, E> = ordered::Operation<F, K, E>;

const KEY_BYTES: [&[u8]; 7] = [
    b"\x10\x20\x30",
    b"\x10\x20\x30\x00",
    b"\x10\x20\x30\x00\x01",
    b"\x10\x20\x31",
    b"\x10\x21\x00",
    b"\x11\x00\x00",
    b"\xff\xff\xff",
];

fn byte_cfg() -> <Vec<u8> as Read>::Cfg {
    ((0..=MAX_OPERATION_SIZE).into(), ())
}

fn fixed_key(index: usize) -> FixedBytes<32> {
    let key = KEY_BYTES[index];
    let mut bytes = [0; 32];
    bytes[..key.len()].copy_from_slice(key);
    bytes[31] = key.len() as u8;
    FixedBytes::new(bytes)
}

mod variable_variable_keys_variable_values {
    use super::*;
    pub type Key = Vec<u8>;
    pub type Value = Vec<u8>;
    pub type Encoding = VariableEncoding<Value>;
    pub fn key(index: usize) -> Key {
        KEY_BYTES[index].to_vec()
    }
    pub fn value(index: u8) -> Value {
        vec![index; usize::from(index) + 1]
    }
    pub fn key_cfg() -> <Key as Read>::Cfg {
        byte_cfg()
    }
    pub fn value_cfg() -> <Value as Read>::Cfg {
        byte_cfg()
    }
    pub fn op_cfg<F: Graftable>() -> <Operation<F, Key, Encoding> as Read>::Cfg {
        (key_cfg(), value_cfg())
    }
    pub fn update_cfg() -> <ordered::Update<Key, Encoding> as Read>::Cfg {
        (key_cfg(), value_cfg())
    }
}

mod variable_fixed_keys_variable_values {
    use super::*;
    pub type Key = FixedBytes<32>;
    pub type Value = Vec<u8>;
    pub type Encoding = VariableEncoding<Value>;
    pub fn key(index: usize) -> Key {
        fixed_key(index)
    }
    pub fn value(index: u8) -> Value {
        variable_variable_keys_variable_values::value(index)
    }
    pub fn key_cfg() -> <Key as Read>::Cfg {}
    pub fn value_cfg() -> <Value as Read>::Cfg {
        byte_cfg()
    }
    pub fn op_cfg<F: Graftable>() -> <Operation<F, Key, Encoding> as Read>::Cfg {
        (key_cfg(), value_cfg())
    }
    pub fn update_cfg() -> <ordered::Update<Key, Encoding> as Read>::Cfg {
        (key_cfg(), value_cfg())
    }
}

mod fixed_fixed_keys_fixed_values {
    use super::*;
    pub type Key = FixedBytes<32>;
    pub type Value = FixedBytes<32>;
    pub type Encoding = FixedEncoding<Value>;
    pub fn key(index: usize) -> Key {
        fixed_key(index)
    }
    pub fn value(index: u8) -> Value {
        FixedBytes::new([index; 32])
    }
    pub fn key_cfg() -> <Key as Read>::Cfg {}
    pub fn value_cfg() -> <Value as Read>::Cfg {}
    pub fn op_cfg<F: Graftable>() -> <Operation<F, Key, Encoding> as Read>::Cfg {}
    pub fn update_cfg() -> <ordered::Update<Key, Encoding> as Read>::Cfg {}
}

mod variable_variable_keys_fixed_values {
    use super::*;
    pub type Key = Vec<u8>;
    pub type Value = FixedBytes<32>;
    pub type Encoding = VariableEncoding<Value>;
    pub fn key(index: usize) -> Key {
        KEY_BYTES[index].to_vec()
    }
    pub fn value(index: u8) -> Value {
        FixedBytes::new([index; 32])
    }
    pub fn key_cfg() -> <Key as Read>::Cfg {
        byte_cfg()
    }
    pub fn value_cfg() -> <Value as Read>::Cfg {}
    pub fn op_cfg<F: Graftable>() -> <Operation<F, Key, Encoding> as Read>::Cfg {
        (key_cfg(), value_cfg())
    }
    pub fn update_cfg() -> <ordered::Update<Key, Encoding> as Read>::Cfg {
        (key_cfg(), value_cfg())
    }
}

mod variable_fixed_keys_fixed_values {
    use super::*;
    pub type Key = FixedBytes<32>;
    pub type Value = FixedBytes<32>;
    pub type Encoding = VariableEncoding<Value>;
    pub fn key(index: usize) -> Key {
        fixed_key(index)
    }
    pub fn value(index: u8) -> Value {
        FixedBytes::new([index; 32])
    }
    pub fn key_cfg() -> <Key as Read>::Cfg {}
    pub fn value_cfg() -> <Value as Read>::Cfg {}
    pub fn op_cfg<F: Graftable>() -> <Operation<F, Key, Encoding> as Read>::Cfg {
        (key_cfg(), value_cfg())
    }
    pub fn update_cfg() -> <ordered::Update<Key, Encoding> as Read>::Cfg {
        (key_cfg(), value_cfg())
    }
}

struct SourcePacket<F: Graftable> {
    start_location: Location<F>,
    proof: Proof<F, Digest>,
    pinned_nodes: Vec<Digest>,
    encoded_operations: Vec<Vec<u8>>,
}

struct Snapshot<F: Graftable, Op, K, V> {
    root: Digest,
    ops_root: Digest,
    operations: Vec<Op>,
    packet: SourcePacket<F>,
    boundary: Option<CurrentBoundaryState<Digest, N, F>>,
    activity: Option<Vec<bool>>,
    values: BTreeMap<K, V>,
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn assert_update<F, K, V, E>(operation: &Operation<F, K, E>, key: &K, value: &V)
where
    F: Graftable,
    K: QmdbKey,
    V: Codec + Clone + Send + Sync + PartialEq + Debug,
    E: ValueEncoding<Value = V>,
{
    match operation {
        Operation::Update(update) => {
            assert_eq!(&update.key, key);
            assert_eq!(&update.value, value);
        }
        _ => panic!("expected authenticated update"),
    }
}

async fn verify_snapshots<F, K, V, E>(
    case_name: &str,
    snapshots: Vec<Snapshot<F, Operation<F, K, E>, K, V>>,
    all_keys: Vec<K>,
    op_cfg: <Operation<F, K, E> as Read>::Cfg,
    update_cfg: <ordered::Update<K, E> as Read>::Cfg,
    key_cfg: K::Cfg,
    value_cfg: V::Cfg,
) where
    F: Graftable,
    K: QmdbKey,
    V: Codec + Clone + Send + Sync + Eq + Debug + AsRef<[u8]> + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
    Operation<F, K, E>: UploadOperation<F> + Codec + Clone + PartialEq + Debug + Send + Sync,
    ordered::Update<K, E>: Read,
    ExclusionProof<F, K, E, Digest, N>:
        Encode + Read<Cfg = (usize, <ordered::Update<K, E> as Read>::Cfg, V::Cfg)>,
{
    assert_eq!(snapshots.len(), 2);
    let is_current = snapshots[0].boundary.is_some();
    assert!(snapshots
        .iter()
        .all(|snapshot| snapshot.boundary.is_some() == is_current));
    let store = common::local_store_client().await;
    let prefixed = PrefixedStoreClient::empty(store);
    let native = Arc::new(OrderedClient::<F, Sha256, K, V, N, E>::new(
        prefixed.clone(),
        op_cfg.clone(),
        key_cfg.clone(),
    ));
    let (task, url) = if is_current {
        common::spawn_connect_service(ordered_connect_stack(native.clone())).await
    } else {
        common::spawn_connect_service(ordered_operation_log_connect_stack(native.clone())).await
    };
    let _server = AbortOnDrop(task);
    let historical =
        OperationLogClient::<PreferZstdHttpClient, F, Sha256, Operation<F, K, E>>::plaintext(
            &url,
            op_cfg.clone(),
        );
    let current_operations = CurrentOperationClient::<
        PreferZstdHttpClient,
        F,
        Sha256,
        Operation<F, K, E>,
        N,
    >::plaintext(&url, op_cfg.clone());
    let lookup = OrderedConnectClient::<PreferZstdHttpClient, F, Sha256, K, V, N, E>::plaintext(
        &url,
        op_cfg.clone(),
        update_cfg,
        key_cfg,
        value_cfg,
    );
    let mut subscription = historical
        .subscribe(SubscribeRequest::default())
        .await
        .expect("subscribe");
    let wrong_root = Sha256::fill(0xEC);
    let mut previous_count = 0;

    for snapshot in &snapshots {
        let count = snapshot.operations.len();
        assert!(count > previous_count);
        let tip = Location::<F>::new(count as u64 - 1);
        let delta = snapshot.operations[previous_count..].to_vec();
        let packet = &snapshot.packet;
        assert_eq!(*packet.start_location, previous_count as u64);
        assert_eq!(
            packet.encoded_operations,
            delta
                .iter()
                .map(|operation| operation.encode().to_vec())
                .collect::<Vec<_>>()
        );
        let range = AuthenticatedOperationRange {
            start_location: packet.start_location,
            proof: &packet.proof,
            pinned_nodes: &packet.pinned_nodes,
            encoded_operations: &packet.encoded_operations,
        };
        assert!(
            prepare_authenticated_range::<F, Sha256, Operation<F, K, E>, Sequential>(
                &range,
                &wrong_root,
                &op_cfg,
                &Sequential,
            )
            .is_err()
        );
        let mut prepared =
            prepare_authenticated_range::<F, Sha256, Operation<F, K, E>, Sequential>(
                &range,
                &snapshot.ops_root,
                &op_cfg,
                &Sequential,
            )
            .expect("prepare authenticated source range");
        if let Some(boundary) = &snapshot.boundary {
            prepared = prepared
                .with_current_boundary::<Sha256, N>(boundary)
                .expect("attach authenticated current boundary");
        }
        let mut data = StoreWriteBatch::new();
        stage_authenticated_range(&prefixed, prepared, &mut data)
            .expect("stage authenticated source range");
        let data_sequence = data
            .commit(prefixed.client())
            .await
            .expect("persist source proof rows");
        let mut publication = StoreWriteBatch::new();
        stage_watermark::<F>(&prefixed, tip, &mut publication)
            .expect("stage published source boundary");
        publication
            .commit(prefixed.client())
            .await
            .expect("publish source boundary");
        assert_eq!(
            native.root_at(tip).await.expect("native ops root"),
            snapshot.ops_root
        );

        if count == snapshots.last().unwrap().operations.len() {
            let request = GetOperationRangeRequest {
                tip: *tip,
                start_location: *packet.start_location,
                max_locations: packet.encoded_operations.len() as u32,
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
                &snapshot.root,
                &request,
                &response,
                &packet.encoded_operations,
            );

            if case_name.starts_with("test_current_ordered_variable_variable_keys_variable_values_")
            {
                use connectrpc::client::ClientConfig;
                use exoware_qmdb::proto::qmdb::v1::{
                    KeyLookupServiceClient, OrderedKeyRangeServiceClient,
                };

                let name = case_name.strip_prefix("test_").unwrap();
                let rpc = KeyLookupServiceClient::new(
                    PreferZstdHttpClient::plaintext(),
                    ClientConfig::new(url.parse().unwrap()),
                );
                let ranges = OrderedKeyRangeServiceClient::new(
                    PreferZstdHttpClient::plaintext(),
                    ClientConfig::new(url.parse().unwrap()),
                );
                let subscribe_request = SubscribeRequest {
                    since_sequence_number: Some(data_sequence),
                    key_filters: vec![exoware_sdk::common::kv::v1::Filter {
                        kind: Some(exoware_sdk::common::kv::v1::filter::Kind::Exact(
                            all_keys[0].as_ref().to_vec().into(),
                        )),
                        ..Default::default()
                    }],
                    ..Default::default()
                };
                let mut stream = common::operation_log_rpc_client(&url)
                    .subscribe(subscribe_request.clone())
                    .await
                    .unwrap();
                let response = stream.message().await.unwrap().unwrap().to_owned_message();
                assert_eq!(response.resume_sequence_number, data_sequence);
                let expected = std::iter::once(tip.as_u64().to_string())
                    .chain(
                        delta
                            .iter()
                            .enumerate()
                            .filter_map(|(offset, op)| match op {
                                Operation::Update(update) if update.key == all_keys[0] => {
                                    Some(format!(
                                        "{} {} {}",
                                        hex::encode(update.key.as_ref()),
                                        hex::encode(update.value.as_ref()),
                                        previous_count + offset,
                                    ))
                                }
                                _ => None,
                            }),
                    )
                    .collect::<Vec<_>>();
                let operations = &response.proof.as_option().unwrap().operations;
                assert!(!operations.is_empty());
                assert_eq!(operations.len(), expected.len() - 1);
                assert!(operations.iter().all(|op| op.location < *tip));
                crate::browser::assert_current_fixture(
                    &format!("{name}_subscribe"),
                    &snapshot.root,
                    N,
                    &subscribe_request,
                    &response,
                    &expected,
                );
                let expected_row = |key: &K| {
                    let key_hex = hex::encode(key.as_ref());
                    match snapshot.values.get(key) {
                        None => format!("{key_hex} - -"),
                        Some(value) => {
                            let location = snapshot.operations.iter().rposition(|operation| {
                                matches!(operation, Operation::Update(update) if &update.key == key)
                            }).expect("source update");
                            format!("{key_hex} {} {location}", hex::encode(value.as_ref()))
                        }
                    }
                };
                let request = GetRequest {
                    key: all_keys[0].encode().to_vec(),
                    tip: *tip,
                    ..Default::default()
                };
                let response = rpc
                    .get(request.clone())
                    .await
                    .unwrap()
                    .into_view()
                    .to_owned_message();
                crate::browser::assert_current_fixture(
                    &format!("{name}_get"),
                    &snapshot.root,
                    N,
                    &request,
                    &response,
                    &[expected_row(&all_keys[0])],
                );

                let indices = [3, 1, 0];
                let request = GetManyRequest {
                    keys: indices
                        .map(|index| all_keys[index].encode().to_vec())
                        .to_vec(),
                    tip: *tip,
                    ..Default::default()
                };
                let response = rpc
                    .get_many(request.clone())
                    .await
                    .unwrap()
                    .into_view()
                    .to_owned_message();
                crate::browser::assert_current_fixture(
                    &format!("{name}_get_many"),
                    &snapshot.root,
                    N,
                    &request,
                    &response,
                    &indices.map(|index| expected_row(&all_keys[index])),
                );

                for (suffix, start, end, limit) in [
                    ("range_first", 1, None, 2),
                    ("range_last", 5, None, 2),
                    ("range_empty", 1, Some(2), 2),
                ] {
                    let request = GetRangeRequest {
                        start_key: all_keys[start].encode().to_vec(),
                        end_key: end.map(|index| all_keys[index].encode().to_vec()),
                        limit,
                        tip: *tip,
                        ..Default::default()
                    };
                    let response = ranges
                        .get_range(request.clone())
                        .await
                        .unwrap()
                        .into_view()
                        .to_owned_message();
                    let expected_keys = snapshot
                        .values
                        .keys()
                        .filter(|key| {
                            **key >= all_keys[start]
                                && end.is_none_or(|index| **key < all_keys[index])
                        })
                        .collect::<Vec<_>>();
                    let next = expected_keys
                        .get(limit as usize)
                        .map_or_else(|| "-".to_string(), |key| hex::encode(key.as_ref()));
                    let mut expected = vec![next];
                    expected.extend(
                        expected_keys
                            .into_iter()
                            .take(limit as usize)
                            .map(expected_row),
                    );
                    crate::browser::assert_current_fixture(
                        &format!("{name}_{suffix}"),
                        &snapshot.root,
                        N,
                        &request,
                        &response,
                        &expected,
                    );
                }
            }
        }
        assert_ne!(snapshot.root, wrong_root);
        let queried = native
            .query_many_at(&all_keys, tip)
            .await
            .expect("native ordered lookup rows");
        for (key, row) in zip_eq(&all_keys, queried) {
            assert_eq!(
                row.as_ref().and_then(|row| row.value.clone()),
                snapshot.values.get(key).cloned()
            );
            if let Some(row) = row {
                assert_eq!(&row.key, key);
                assert!(row.location <= tip);
            }
        }

        let frame = subscription
            .message_with_root(|frame_tip| {
                assert_eq!(frame_tip, tip);
                Ok(snapshot.root)
            })
            .await
            .expect("authenticate subscription")
            .expect("batch frame");
        assert_eq!(frame.tip, tip);
        assert_eq!(frame.root, snapshot.root);
        assert_eq!(
            frame.operations,
            delta
                .iter()
                .cloned()
                .enumerate()
                .map(|(offset, op)| { (Location::<F>::new((previous_count + offset) as u64), op) })
                .collect::<Vec<_>>()
        );

        // Exercise both the initial root and pinned prefix nodes at a nonzero start
        for start in [0, 1] {
            let request = GetOperationRangeRequest {
                tip: *tip,
                start_location: start,
                max_locations: count as u32,
                ..Default::default()
            };
            let proof = historical
                .get_operation_range(request.clone(), &snapshot.root)
                .await
                .expect("Connect historical range");
            assert_eq!(proof.root, snapshot.root);
            assert_eq!(proof.start_location, Location::new(start));
            assert_eq!(proof.operations, snapshot.operations[start as usize..]);
            assert!(historical
                .get_operation_range(request, &wrong_root)
                .await
                .is_err());
            let checkpoint = native
                .operation_range_checkpoint(tip, Location::new(start), count as u32)
                .await
                .expect("native checkpoint");
            assert_eq!(checkpoint.root, snapshot.ops_root);
            assert_eq!(checkpoint.ops_root_witness.is_some(), is_current);
            assert!(checkpoint.verify::<Sha256>());
            assert_eq!(
                checkpoint.encoded_operations,
                snapshot.operations[start as usize..]
                    .iter()
                    .map(|operation| operation.encode().to_vec())
                    .collect::<Vec<_>>()
            );
        }

        if is_current {
            assert_eq!(
                native
                    .current_root_at(tip)
                    .await
                    .expect("native current root"),
                snapshot.root
            );
            let request = GetCurrentOperationRangeRequest {
                tip: *tip,
                start_location: 0,
                max_locations: count as u32,
                ..Default::default()
            };
            let current = current_operations
                .get_current_operation_range(request.clone(), &snapshot.root)
                .await
                .expect("Connect current range");
            assert_eq!(current.operations, snapshot.operations);
            assert_eq!(current.root, snapshot.root);
            assert!(current_operations
                .get_current_operation_range(request, &wrong_root)
                .await
                .is_err());
            let native_current = native
                .current_operation_range_proof(tip, Location::new(0), count as u32)
                .await
                .expect("native current range");
            assert_eq!(native_current.root, snapshot.root);
            assert_eq!(native_current.operations, snapshot.operations);
            assert_eq!(native_current.chunks, current.chunks);
            let activity = snapshot.activity.as_ref().expect("source activity");
            let proved_activity = (0..count)
                .map(|location| {
                    let chunk = &current.chunks[location / (N * 8)];
                    let bit = location % (N * 8);
                    chunk[bit / 8] & (1 << (bit % 8)) != 0
                })
                .collect::<Vec<_>>();
            assert_eq!(&proved_activity, activity);
            if previous_count > 0 {
                assert!(activity[..previous_count].iter().any(|active| !active));
            }

            let request = GetManyRequest {
                tip: *tip,
                keys: all_keys.iter().map(|key| key.encode().to_vec()).collect(),
                ..Default::default()
            };
            let lookups = lookup
                .get_many(request.clone(), &snapshot.root)
                .await
                .expect("Connect hits and misses");
            assert!(lookup.get_many(request, &wrong_root).await.is_err());
            assert_eq!(lookups.len(), all_keys.len());
            let raw_lookups = native
                .key_lookup_proofs_raw_at(tip, &all_keys)
                .await
                .expect("native hits and misses");
            assert_eq!(raw_lookups.len(), all_keys.len());
            for ((key, result), raw) in all_keys.iter().zip(lookups).zip(raw_lookups) {
                match (snapshot.values.get(key), result, raw) {
                    (Some(value), VerifiedKeyLookup::Hit(hit), RawKeyLookupProof::Hit(raw)) => {
                        assert_update(&hit.operation, key, value);
                        assert_eq!(hit.root, snapshot.root);
                        assert!(raw.verify::<Sha256>());
                        assert_eq!(raw.root, snapshot.root);
                        assert_eq!(hit.location, raw.proof.loc);
                        let request = GetRequest {
                            key: key.encode().to_vec(),
                            tip: *tip,
                            ..Default::default()
                        };
                        let one = lookup
                            .get(request.clone(), &snapshot.root)
                            .await
                            .expect("Connect key hit");
                        assert_update(&one.operation, key, value);
                        assert!(lookup.get(request, &wrong_root).await.is_err());
                    }
                    (
                        None,
                        VerifiedKeyLookup::Miss { key: missed },
                        RawKeyLookupProof::Miss(raw),
                    ) => {
                        assert_eq!(missed.as_ref(), key.encode().as_ref());
                        assert!(raw.verify::<Sha256>());
                        assert_eq!(raw.root, snapshot.root);
                    }
                    _ => panic!("lookup disagrees with source state"),
                }
            }

            // Authenticate successor links across multiple pages
            let expected = snapshot.values.iter().collect::<Vec<_>>();
            let mut cursor = all_keys[0].encode().to_vec();
            let mut seen = Vec::new();
            loop {
                let request = GetRangeRequest {
                    start_key: cursor.clone(),
                    end_key: None,
                    limit: 2,
                    tip: *tip,
                    ..Default::default()
                };
                let page = lookup
                    .get_range(request.clone(), &snapshot.root)
                    .await
                    .expect("Connect ordered page");
                assert!(lookup.get_range(request, &wrong_root).await.is_err());
                assert!(page.entries.len() <= 2);
                for entry in page.entries {
                    let Operation::Update(update) = entry.operation else {
                        panic!("range entry must update");
                    };
                    seen.push((update.key, update.value));
                }
                match page.next_start_key {
                    Some(next) => {
                        assert_ne!(next.as_ref(), cursor.as_slice());
                        assert!(
                            seen.len() < expected.len(),
                            "continuation must advance within the source range"
                        );
                        cursor = next.to_vec();
                    }
                    None => break,
                }
            }
            assert_eq!(
                seen,
                expected
                    .iter()
                    .map(|(key, value)| ((*key).clone(), (*value).clone()))
                    .collect::<Vec<_>>()
            );

            // The second snapshot starts this bounded range at a deleted key
            let request = GetRangeRequest {
                start_key: all_keys[1].encode().to_vec(),
                end_key: Some(all_keys[5].encode().to_vec()),
                limit: 20,
                tip: *tip,
                ..Default::default()
            };
            let bounded = lookup
                .get_range(request, &snapshot.root)
                .await
                .expect("bounded range with exclusion");
            assert!(bounded.next_start_key.is_none());
            let expected = snapshot
                .values
                .range(all_keys[1].clone()..all_keys[5].clone())
                .collect::<Vec<_>>();
            assert_eq!(bounded.entries.len(), expected.len());
            for (entry, (key, value)) in bounded.entries.iter().zip(expected) {
                assert_update(&entry.operation, key, value);
            }
            let raw = native
                .key_range_proof_raw_at(tip, all_keys[1].clone(), Some(all_keys[5].clone()), 20)
                .await
                .expect("native bounded range");
            assert_eq!(raw.entries.len(), bounded.entries.len());
            if !snapshot.values.contains_key(&all_keys[1]) {
                let exclusion = raw.start_proof.as_ref().expect("excluded start");
                assert_eq!(exclusion.root, snapshot.root);
                assert!(exclusion.verify::<Sha256>());
            }
        } else {
            assert!(native.current_root_at(tip).await.is_err());
            assert!(current_operations
                .get_current_operation_range(
                    GetCurrentOperationRangeRequest {
                        tip: *tip,
                        start_location: 0,
                        max_locations: count as u32,
                        ..Default::default()
                    },
                    &snapshot.root
                )
                .await
                .is_err());
            assert!(lookup
                .get(
                    GetRequest {
                        key: all_keys[0].encode().to_vec(),
                        tip: *tip,
                        ..Default::default()
                    },
                    &snapshot.root
                )
                .await
                .is_err());
        }
        previous_count = count;
    }
}

macro_rules! capture_source_batch {
    (any, $family:ty, $db:ident, $batch:ident) => {{
        let (start_location, operations) = $batch.operations();
        let root = $batch.root();
        let proof = $batch.proof(&$db).expect("source batch proof before apply");
        let pinned_nodes = $batch
            .pinned_nodes(&$db)
            .expect("source batch pins before apply");
        assert!(
            commonware_storage::qmdb::verify::verify_proof_and_pinned_nodes::<Sha256, _, _>(
                &proof,
                start_location,
                operations.as_slice(),
                &pinned_nodes,
                &root,
            )
        );
        Some(SourcePacket::<$family> {
            start_location,
            proof,
            pinned_nodes,
            encoded_operations: operations
                .iter()
                .map(|operation| operation.encode().to_vec())
                .collect(),
        })
    }};
    (current, $family:ty, $db:ident, $batch:ident) => {
        None::<SourcePacket<$family>>
    };
}

macro_rules! source_snapshot {
    (any, $family:ty, $db:ident, $previous:ident, $captured:ident) => {{
        let root = $db.root();
        let end = $db.bounds().end;
        let (proof, operations) = $db
            .historical_proof(
                end,
                Location::new(0),
                std::num::NonZeroU64::new(*end).unwrap(),
            )
            .await
            .expect("source historical proof");
        assert!(
            commonware_storage::qmdb::verify::verify_proof::<Sha256, _, _>(
                &proof,
                Location::new(0),
                &operations,
                &root,
            )
        );
        let captured = $captured.expect("captured any batch proof");
        assert_eq!(
            captured.encoded_operations,
            operations[*captured.start_location as usize..]
                .iter()
                .map(|operation| operation.encode().to_vec())
                .collect::<Vec<_>>()
        );
        let packet = if $previous.is_empty() {
            // Include the source's initial commit in the first upload
            SourcePacket {
                start_location: Location::new(0),
                proof,
                pinned_nodes: Vec::new(),
                encoded_operations: operations
                    .iter()
                    .map(|operation| operation.encode().to_vec())
                    .collect(),
            }
        } else {
            assert_eq!(*captured.start_location, $previous.len() as u64);
            captured
        };
        (root, root, operations, packet, None, None)
    }};
    (current, $family:ty, $db:ident, $previous:ident, $captured:ident) => {{
        let root = $db.root();
        let ops_root = $db.ops_root();
        let end = $db.bounds().end;
        let (proof, operations) = $db
            .ops_historical_proof(
                end,
                Location::new(0),
                std::num::NonZeroU64::new(*end).unwrap(),
            )
            .await
            .expect("source historical proof");
        assert!(
            commonware_storage::qmdb::verify::verify_proof::<Sha256, _, _>(
                &proof,
                Location::new(0),
                &operations,
                &ops_root,
            )
        );
        let activity = (0..*end)
            .map(|location| $db.bitmap().get_bit(location))
            .collect();
        assert!($captured.is_none());
        let boundary = recover_boundary_state::<$family, Sha256, _, N, _, _>(
            if $previous.is_empty() {
                None
            } else {
                Some($previous.as_slice())
            },
            &operations,
            root,
            0,
            $db.ops_root_witness().await.expect("source root witness"),
            |location| common::current_proof_chunk($db.range_proof(location, NZU64!(1))),
        )
        .await
        .expect("recover source current boundary");
        let start = Location::new($previous.len() as u64);
        let (proof, packet_ops) = $db
            .ops_historical_proof(
                end,
                start,
                std::num::NonZeroU64::new(*end - *start).unwrap(),
            )
            .await
            .expect("source current batch ops proof");
        let pinned_nodes = $db
            .pinned_nodes_at(start)
            .await
            .expect("source current batch pins");
        assert!(
            commonware_storage::qmdb::verify::verify_proof_and_pinned_nodes::<Sha256, _, _>(
                &proof,
                start,
                &packet_ops,
                &pinned_nodes,
                &ops_root,
            )
        );
        let packet = SourcePacket {
            start_location: start,
            proof,
            pinned_nodes,
            encoded_operations: packet_ops
                .iter()
                .map(|operation| operation.encode().to_vec())
                .collect(),
        };
        (
            root,
            ops_root,
            operations,
            packet,
            Some(boundary),
            Some(activity),
        )
    }};
}

macro_rules! variant_case {
    ($name:ident, $state:ident, $encoding:ident, $family:ty, $fixture:ident) => {
        #[tokio::test]
        async fn $name() {
            type Source = source_type!(
                $state,
                ordered,
                $encoding,
                $family,
                $fixture::Key,
                $fixture::Value
            );
            type Op = Operation<$family, $fixture::Key, $fixture::Encoding>;
            let snapshots = tokio::task::spawn_blocking(|| {
                cw_tokio::Runner::default().start(|context| async move {
                    let cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
                    let cfg = source_config!(
                        $state,
                        $encoding,
                        stringify!($name),
                        cache,
                        $fixture::op_cfg::<$family>()
                    );
                    let mut db: Source = Source::init(context.child(stringify!($name)), cfg)
                        .await
                        .expect("init source alias");
                    let batches = [
                        vec![
                            ($fixture::key(0), Some($fixture::value(1))),
                            ($fixture::key(1), Some($fixture::value(2))),
                            ($fixture::key(2), Some($fixture::value(3))),
                            ($fixture::key(4), Some($fixture::value(4))),
                            ($fixture::key(5), Some($fixture::value(5))),
                        ],
                        vec![
                            ($fixture::key(0), Some($fixture::value(10))),
                            ($fixture::key(1), None),
                            ($fixture::key(3), Some($fixture::value(12))),
                            ($fixture::key(4), None),
                        ],
                    ];
                    let mut previous: Vec<Op> = Vec::new();
                    let mut values = BTreeMap::new();
                    let mut snapshots = Vec::new();
                    for writes in batches {
                        let mut batch = db.new_batch();
                        for (key, value) in writes {
                            batch = batch.write(key.clone(), value.clone());
                            if let Some(value) = value {
                                values.insert(key, value);
                            } else {
                                values.remove(&key);
                            }
                        }
                        let finalized = batch
                            .merkleize(&db, None::<$fixture::Value>)
                            .await
                            .expect("source merkleize");
                        let captured = capture_source_batch!($state, $family, db, finalized);
                        let batch_root = finalized.root();
                        (db, _) = db.apply_batch(finalized).await.expect("source apply");
                        assert_eq!(db.root(), batch_root);
                        for index in 0..KEY_BYTES.len() {
                            let key = $fixture::key(index);
                            assert_eq!(
                                db.get(&key).await.expect("source get"),
                                values.get(&key).cloned()
                            );
                        }
                        let (root, ops_root, operations, packet, boundary, activity) =
                            source_snapshot!($state, $family, db, previous, captured);
                        assert!(operations.starts_with(&previous));
                        previous = operations.clone();
                        snapshots.push(Snapshot {
                            root,
                            ops_root,
                            operations,
                            packet,
                            boundary,
                            activity,
                            values: values.clone(),
                        });
                    }
                    db = db.sync().await.expect("source sync");
                    db.destroy().await.expect("source destroy");
                    snapshots
                })
            })
            .await
            .expect("source task");
            let all_keys = (0..KEY_BYTES.len()).map($fixture::key).collect::<Vec<_>>();
            assert!(all_keys.windows(2).all(|keys| keys[0] < keys[1]));
            verify_snapshots::<$family, $fixture::Key, $fixture::Value, $fixture::Encoding>(
                stringify!($name),
                snapshots,
                all_keys,
                $fixture::op_cfg::<$family>(),
                $fixture::update_cfg(),
                $fixture::key_cfg(),
                $fixture::value_cfg(),
            )
            .await;
        }
    };
}

variant_case!(
    test_any_ordered_fixed_fixed_keys_fixed_values_mmr,
    any,
    fixed,
    mmr::Family,
    fixed_fixed_keys_fixed_values
);

variant_case!(
    test_any_ordered_fixed_fixed_keys_fixed_values_mmb,
    any,
    fixed,
    mmb::Family,
    fixed_fixed_keys_fixed_values
);

variant_case!(
    test_any_ordered_variable_fixed_keys_fixed_values_mmr,
    any,
    variable,
    mmr::Family,
    variable_fixed_keys_fixed_values
);

variant_case!(
    test_any_ordered_variable_fixed_keys_fixed_values_mmb,
    any,
    variable,
    mmb::Family,
    variable_fixed_keys_fixed_values
);

variant_case!(
    test_any_ordered_variable_fixed_keys_variable_values_mmr,
    any,
    variable,
    mmr::Family,
    variable_fixed_keys_variable_values
);

variant_case!(
    test_any_ordered_variable_fixed_keys_variable_values_mmb,
    any,
    variable,
    mmb::Family,
    variable_fixed_keys_variable_values
);

variant_case!(
    test_any_ordered_variable_variable_keys_fixed_values_mmr,
    any,
    variable,
    mmr::Family,
    variable_variable_keys_fixed_values
);

variant_case!(
    test_any_ordered_variable_variable_keys_fixed_values_mmb,
    any,
    variable,
    mmb::Family,
    variable_variable_keys_fixed_values
);

variant_case!(
    test_any_ordered_variable_variable_keys_variable_values_mmr,
    any,
    variable,
    mmr::Family,
    variable_variable_keys_variable_values
);

variant_case!(
    test_any_ordered_variable_variable_keys_variable_values_mmb,
    any,
    variable,
    mmb::Family,
    variable_variable_keys_variable_values
);

variant_case!(
    test_current_ordered_fixed_fixed_keys_fixed_values_mmr,
    current,
    fixed,
    mmr::Family,
    fixed_fixed_keys_fixed_values
);

variant_case!(
    test_current_ordered_fixed_fixed_keys_fixed_values_mmb,
    current,
    fixed,
    mmb::Family,
    fixed_fixed_keys_fixed_values
);

variant_case!(
    test_current_ordered_variable_fixed_keys_fixed_values_mmr,
    current,
    variable,
    mmr::Family,
    variable_fixed_keys_fixed_values
);

variant_case!(
    test_current_ordered_variable_fixed_keys_fixed_values_mmb,
    current,
    variable,
    mmb::Family,
    variable_fixed_keys_fixed_values
);

variant_case!(
    test_current_ordered_variable_fixed_keys_variable_values_mmr,
    current,
    variable,
    mmr::Family,
    variable_fixed_keys_variable_values
);

variant_case!(
    test_current_ordered_variable_fixed_keys_variable_values_mmb,
    current,
    variable,
    mmb::Family,
    variable_fixed_keys_variable_values
);

variant_case!(
    test_current_ordered_variable_variable_keys_fixed_values_mmr,
    current,
    variable,
    mmr::Family,
    variable_variable_keys_fixed_values
);

variant_case!(
    test_current_ordered_variable_variable_keys_fixed_values_mmb,
    current,
    variable,
    mmb::Family,
    variable_variable_keys_fixed_values
);

variant_case!(
    test_current_ordered_variable_variable_keys_variable_values_mmr,
    current,
    variable,
    mmr::Family,
    variable_variable_keys_variable_values
);

variant_case!(
    test_current_ordered_variable_variable_keys_variable_values_mmb,
    current,
    variable,
    mmb::Family,
    variable_variable_keys_variable_values
);
