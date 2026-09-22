/// Compare a native Connect proof with the bytes verified by the browser matrix
pub fn assert_fixture(
    case_name: &str,
    expected_root: &commonware_cryptography::sha256::Digest,
    request: &exoware_qmdb::proto::qmdb::v1::GetOperationRangeRequest,
    response: &exoware_qmdb::proto::qmdb::v1::GetOperationRangeResponse,
    expected_operations: &[Vec<u8>],
) {
    use buffa::Message as _;

    let name = case_name
        .strip_prefix("test_")
        .expect("structured test name");
    assert!(name.ends_with("_mmr") || name.ends_with("_mmb"));
    let proof = response
        .proof
        .as_option()
        .expect("Connect operation range proof");
    assert!(
        request.start_location > 0,
        "fixture must exercise pinned history"
    );
    assert_eq!(proof.start_location, request.start_location);
    assert!(!proof.pinned_nodes.is_empty(), "fixture must include pins");
    assert_eq!(
        proof
            .encoded_operations
            .iter()
            .map(|bytes| bytes.to_vec())
            .collect::<Vec<_>>(),
        expected_operations,
    );
    assert_eq!(
        !proof.ops_root_witness.is_empty(),
        name.starts_with("current_"),
        "current fixtures must authenticate their operation root witness",
    );
    assert_eq!(
        request.start_location + expected_operations.len() as u64,
        request.tip + 1,
        "fixture must reach its source tip",
    );

    // Root, exact request, wire proof, then the independently encoded source operations
    let fixture = format!(
        "{}\n{} {} {}\n{}\n{}\n",
        hex::encode(expected_root),
        request.tip,
        request.start_location,
        request.max_locations,
        hex::encode(proof.encode_to_vec()),
        expected_operations
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>()
            .join("\n"),
    );
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ts/test/fixtures/variants")
        .join(format!("{name}.txt"));
    if std::env::var_os("UPDATE_FIXTURES").is_some() {
        std::fs::create_dir_all(fixture_path.parent().unwrap()).unwrap();
        std::fs::write(&fixture_path, &fixture).unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(&fixture_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", fixture_path.display())),
        fixture,
        "browser fixture {name} must match the native source proof",
    );
}

/// Bind browser current-query fixtures to native responses and source-state expectations
pub fn assert_current_fixture(
    name: &str,
    root: &commonware_cryptography::sha256::Digest,
    chunk_size: usize,
    request: &impl buffa::Message,
    response: &impl buffa::Message,
    expected: &[String],
) {
    let fixture = format!(
        "{}\n{chunk_size}\n{}\n{}\n{}\n",
        hex::encode(root),
        hex::encode(request.encode_to_vec()),
        hex::encode(response.encode_to_vec()),
        expected.join("\n")
    );
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ts/test/fixtures/current")
        .join(format!("{name}.txt"));
    if std::env::var_os("UPDATE_FIXTURES").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &fixture).unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
        fixture
    );
}
