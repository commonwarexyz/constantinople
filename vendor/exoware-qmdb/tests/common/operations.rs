use commonware_parallel::Sequential;
use commonware_storage::merkle::Family;

/// Build a range fixture with Commonware, independently of the Exoware adapter
#[allow(dead_code)]
pub fn prepare_operation_range<F, Op>(
    operations: &[Op],
    start: commonware_storage::merkle::Location<F>,
    cfg: &Op::Cfg,
) -> (
    commonware_cryptography::sha256::Digest,
    exoware_qmdb::PreparedAuthenticatedRange<commonware_cryptography::sha256::Digest, F>,
)
where
    F: Family,
    Op: exoware_qmdb::UploadOperation<F>,
{
    use commonware_cryptography::Sha256;
    use commonware_storage::merkle::{hasher::Hasher as _, mem::Mem, Location, Position};
    let encoded = operations
        .iter()
        .map(|op| op.encode().to_vec())
        .collect::<Vec<_>>();
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    let base = Mem::<F, commonware_cryptography::sha256::Digest>::new();
    let digests = encoded.iter().enumerate().map(|(index, op)| {
        hasher.leaf_digest(
            Position::try_from(Location::<F>::new(index as u64)).unwrap(),
            op,
        )
    });
    let merkle = base
        .new_batch()
        .add_leaf_digests(digests)
        .merkleize(&base, &hasher);
    let end = Location::new(operations.len() as u64);
    let floor = operations
        .last()
        .unwrap()
        .has_floor()
        .expect("final commit");
    let inactive = F::inactive_peaks(end, floor);
    let root = merkle.root(&base, &hasher, inactive).unwrap();
    let proof = merkle
        .range_proof(&base, &hasher, start..end, inactive)
        .unwrap();
    let pinned_nodes = F::nodes_to_pin(start)
        .map(|position| merkle.get_node(position).expect("source pinned node"))
        .collect::<Vec<_>>();
    let range = exoware_qmdb::AuthenticatedOperationRange {
        start_location: start,
        proof: &proof,
        pinned_nodes: &pinned_nodes,
        encoded_operations: &encoded[usize::try_from(*start).expect("source start")..],
    };
    let prepared = exoware_qmdb::prepare_authenticated_range::<F, Sha256, Op, Sequential>(
        &range,
        &root,
        cfg,
        &Sequential,
    )
    .expect("prepare authenticated fixture");
    (root, prepared)
}

/// Prepare the complete operation prefix
#[allow(dead_code)]
pub fn prepare_operations<F, Op>(
    operations: &[Op],
    cfg: &Op::Cfg,
) -> (
    commonware_cryptography::sha256::Digest,
    exoware_qmdb::PreparedAuthenticatedRange<commonware_cryptography::sha256::Digest, F>,
)
where
    F: Family,
    Op: exoware_qmdb::UploadOperation<F>,
{
    prepare_operation_range(
        operations,
        commonware_storage::merkle::Location::new(0),
        cfg,
    )
}
