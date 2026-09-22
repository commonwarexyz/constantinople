//! Small batches over a caller-trusted pruned frontier exercise absolute location widths

mod common;

use std::sync::Arc;

use buffa::Message as _;
use commonware_codec::Encode;
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_parallel::Sequential;
use commonware_storage::merkle::{
    hasher::Hasher as _, mem::Mem, mmb, mmr, Graftable, Location, Position,
};
use commonware_storage::qmdb::{
    keyless::variable::Operation,
    sync::{Request, Response, Source as _},
};
use exoware_qmdb::proto::qmdb::v1::GetOperationRangeRequest;
use exoware_qmdb::{
    keyless_operation_log_connect_stack, prepare_authenticated_range, stage_authenticated_range,
    stage_watermark, AuthenticatedOperationRange, KeylessClient, OperationLogClient,
};
use exoware_sdk::{PrefixedStoreClient, StoreWriteBatch};

async fn check_large_locations<F: Graftable + PartialEq>(family: &str, start: u64) {
    let store_client = common::local_store_client().await;
    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    let start = Location::<F>::new(start);
    let previous_size = Position::try_from(start).unwrap();
    // Opaque digests stand for a trusted pruned history, not four billion generated operations
    let peaks = F::peaks(previous_size)
        .enumerate()
        .map(|(index, (position, height))| (position, height, Sha256::fill(index as u8)))
        .collect::<Vec<_>>();
    let pins = peaks
        .iter()
        .map(|(_, _, digest)| *digest)
        .collect::<Vec<_>>();
    let reference = Mem::<F, Digest>::from_components(Vec::new(), start, pins.clone()).unwrap();

    let operations: Vec<Operation<F, Vec<u8>>> = vec![
        Operation::Append(b"left".to_vec()),
        Operation::Append(b"right".to_vec()),
        Operation::Commit(None, start),
    ];
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    let digests = operations.iter().enumerate().map(|(offset, operation)| {
        let position = Position::try_from(start + offset as u64).unwrap();
        hasher.leaf_digest(position, operation.encode().as_ref())
    });
    let reference_batch = reference
        .new_batch()
        .add_leaf_digests(digests)
        .merkleize(&reference, &hasher);
    let end = start + operations.len() as u64;
    let expected_root = reference_batch
        .root(&reference, &hasher, F::inactive_peaks(end, start))
        .unwrap();
    let proof = reference_batch
        .range_proof(
            &reference,
            &hasher,
            start..end,
            F::inactive_peaks(end, start),
        )
        .unwrap();
    let encoded_operations = operations
        .iter()
        .map(|operation| operation.encode().to_vec())
        .collect::<Vec<_>>();
    let range = AuthenticatedOperationRange {
        start_location: start,
        proof: &proof,
        pinned_nodes: &pins,
        encoded_operations: &encoded_operations,
    };
    let config = ((0..=10000).into(), ());
    let prepared = prepare_authenticated_range::<F, Sha256, Operation<F, Vec<u8>>, Sequential>(
        &range,
        &expected_root,
        &config,
        &Sequential,
    )
    .unwrap();
    assert_eq!(prepared.latest_location(), end - 1);
    let mut data = StoreWriteBatch::new();
    stage_authenticated_range(&upload_client, prepared, &mut data).unwrap();
    data.commit(&store_client).await.unwrap();
    let mut publication = StoreWriteBatch::new();
    stage_watermark(&upload_client, end - 1, &mut publication).unwrap();
    publication.commit(&store_client).await.unwrap();

    let qmdb_client = Arc::new(KeylessClient::<F, Sha256, Vec<u8>>::new(
        upload_client,
        config,
    ));
    assert_eq!(
        qmdb_client.writer_location_watermark().await.unwrap(),
        Some(end - 1)
    );
    assert_eq!(qmdb_client.root_at(end - 1).await.unwrap(), expected_root);
    let (server, url) =
        common::spawn_connect_service(keyless_operation_log_connect_stack(qmdb_client)).await;
    let request = GetOperationRangeRequest {
        tip: (end - 1).as_u64(),
        start_location: start.as_u64(),
        max_locations: 10,
        ..Default::default()
    };
    let raw = common::operation_log_rpc_client(&url)
        .get_operation_range(request.clone())
        .await
        .unwrap()
        .into_view()
        .to_owned_message();
    let fixture = format!(
        "{}\n{}\n",
        hex::encode(expected_root),
        hex::encode(raw.proof.as_option().unwrap().encode_to_vec())
    );
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../ts/test/fixtures/keyless_variable_variable_values_{family}_start_{}.txt",
        start.as_u64()
    ));
    // The same proof bytes exercise the generated WASM exports in the browser client tests.
    // Set UPDATE_FIXTURES=1 to rewrite them after an intentional encoding change.
    if std::env::var_os("UPDATE_FIXTURES").is_some() {
        std::fs::write(&fixture_path, &fixture).unwrap();
    }
    assert_eq!(std::fs::read_to_string(fixture_path).unwrap(), fixture);
    let rpc = OperationLogClient::<_, F, Sha256, Operation<F, Vec<u8>>>::plaintext(&url, config);
    let verified = rpc
        .get_operation_range(request, &expected_root)
        .await
        .unwrap();
    assert_eq!(verified.start_location, start);
    assert_eq!(verified.operations, operations);
    let (response, _) = rpc
        .serve(Request::Operations {
            size: end,
            start,
            max_ops: std::num::NonZeroU64::MAX,
        })
        .await
        .unwrap();
    let Response::Operations {
        proof,
        operations: received,
    } = response
    else {
        panic!("expected operation batch")
    };
    let encoded = received.iter().map(Encode::encode).collect::<Vec<_>>();
    assert!(proof.verify_range_inclusion(&hasher, &encoded, start, &expected_root));
    assert_eq!(received, operations);
    server.abort();
}

#[tokio::test]
async fn test_mmr_store_and_sync_cross_u32_locations() {
    check_large_locations::<mmr::Family>("mmr", u32::MAX as u64 - 1).await;
    check_large_locations::<mmr::Family>("mmr", (1u64 << 53) + 1).await;
}

#[tokio::test]
async fn test_mmb_store_and_sync_cross_u32_locations() {
    check_large_locations::<mmb::Family>("mmb", u32::MAX as u64 - 1).await;
    check_large_locations::<mmb::Family>("mmb", (1u64 << 53) + 1).await;
}
