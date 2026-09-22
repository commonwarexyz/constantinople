//! Stateless preparation of authenticated Commonware operation ranges.
//!
//! Ranges may overlap and contain several commits. All uploads to a namespace must belong to
//! the same operation history, so repeated operation and Merkle node keys have identical values.
//! The caller owns publication of the durable contiguous prefix through [`stage_watermark`].

use commonware_codec::{Codec, Encode};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_storage::{
    merkle::{Family, Graftable, Location, Position, Proof},
    qmdb::{
        any::{
            operation::{Operation as AnyOperation, Update},
            value::ValueEncoding,
        },
        current::grafting,
        immutable, keyless,
        operation::{Floored, Key as QmdbKey},
    },
};
use exoware_sdk::{keys::Key, PrefixedStoreClient, StoreWriteBatch};

use crate::{
    codec::{
        encode_chunk_key, encode_current_meta_key, encode_grafted_node_key, encode_node_key,
        encode_operation_key, encode_ops_root_witness_key, encode_presence_key,
        encode_update_index_value, encode_update_key, encode_watermark_key,
        ensure_encoded_value_size, CurrentBoundaryMetadata,
    },
    core::extend_merkle_from_pinned_nodes,
    CurrentBoundaryState, ProofKind, QmdbError,
};

/// An operation range ending at the leaf count committed by its proof.
#[derive(Clone, Copy, Debug, PartialEq)]
#[must_use]
pub struct AuthenticatedOperationRange<'a, D: Digest, F: Family> {
    /// Inclusive operation location where the range starts.
    pub start_location: Location<F>,
    /// Range proof whose leaves determine the exclusive range end.
    pub proof: &'a Proof<F, D>,
    /// Prefix frontier in [`Family::nodes_to_pin`] order.
    pub pinned_nodes: &'a [D],
    /// Canonical operation encodings in location order.
    pub encoded_operations: &'a [Vec<u8>],
}

/// A QMDB operation whose keyed changes can be indexed for historical queries.
pub trait UploadOperation<F: Family>: Codec + Floored<F> {
    /// Return the affected key and whether its value is present after this operation.
    ///
    /// Commits and keyless operations return `None`. Deletions return `Some((key, false))`.
    fn indexed_key(&self) -> Option<(&[u8], bool)>;
}

impl<F: Family, U: Update> UploadOperation<F> for AnyOperation<F, U>
where
    Self: Codec,
{
    fn indexed_key(&self) -> Option<(&[u8], bool)> {
        match self {
            Self::Delete(key) => Some((key.as_ref(), false)),
            Self::Update(update) => Some((update.key().as_ref(), true)),
            Self::CommitFloor(_, _) => None,
        }
    }
}

impl<F: Family, K: QmdbKey, E: ValueEncoding> UploadOperation<F> for immutable::Operation<F, K, E>
where
    Self: Codec,
{
    fn indexed_key(&self) -> Option<(&[u8], bool)> {
        match self {
            Self::Set(key, _) => Some((key.as_ref(), true)),
            Self::Commit(_, _) => None,
        }
    }
}

impl<F: Family, E: ValueEncoding> UploadOperation<F> for keyless::Operation<F, E>
where
    Self: Codec,
{
    fn indexed_key(&self) -> Option<(&[u8], bool)> {
        None
    }
}

/// Deterministic logical Store rows authenticated against an independently trusted root.
#[derive(Debug, PartialEq)]
#[must_use]
pub struct PreparedAuthenticatedRange<D: Digest, F: Family> {
    rows: Vec<(Key, Vec<u8>)>,
    start_location: Location<F>,
    latest_location: Location<F>,
    ops_root: D,
}

impl<D: Digest, F: Family> PreparedAuthenticatedRange<D, F> {
    /// Inclusive first operation location in this range.
    pub const fn start_location(&self) -> Location<F> {
        self.start_location
    }

    /// Inclusive final operation location in this range.
    pub const fn latest_location(&self) -> Location<F> {
        self.latest_location
    }
}

impl<D: Digest, F: Graftable> PreparedAuthenticatedRange<D, F> {
    /// Add caller-authenticated current-state boundary rows for this operation root.
    ///
    /// The boundary, including its `pruned_chunks` count, must come from the same trusted producer.
    /// Use `recover_boundary_state` to authenticate recovered chunks and nodes against that
    /// producer's current root. This method checks only the binding to the verified operation
    /// root. It does not authenticate the supplied chunks, nodes, or pruned chunk count.
    pub fn with_current_boundary<H: Hasher<Digest = D>, const N: usize>(
        mut self,
        boundary: &CurrentBoundaryState<D, N, F>,
    ) -> Result<Self, QmdbError> {
        if boundary.ops_root_witness.root::<H>(&self.ops_root) != boundary.root {
            return Err(QmdbError::CorruptData(
                "current boundary does not commit to the authenticated operation root".into(),
            ));
        }
        self.rows
            .reserve(2 + boundary.chunks.len() + boundary.grafted_nodes.len());
        self.rows.push((
            encode_current_meta_key(self.latest_location),
            CurrentBoundaryMetadata {
                root: boundary.root,
                pruned_chunks: boundary.pruned_chunks,
            }
            .encode()
            .to_vec(),
        ));
        self.rows.push((
            encode_ops_root_witness_key(self.latest_location),
            boundary.ops_root_witness.encode().to_vec(),
        ));
        for &(chunk_index, chunk) in &boundary.chunks {
            self.rows.push((
                encode_chunk_key(chunk_index, self.latest_location),
                chunk.encode().to_vec(),
            ));
        }
        for &(ops_position, digest) in &boundary.grafted_nodes {
            let grafted_position =
                grafting::ops_to_grafted_pos::<F>(ops_position, grafting::height::<N>());
            self.rows.push((
                encode_grafted_node_key(grafted_position, self.latest_location),
                digest.encode().to_vec(),
            ));
        }
        Ok(self)
    }
}

/// Verify an operation range and prepare its operation, index, and Merkle node rows.
///
/// `expected_root` must be trusted independently of the supplied proof and operations. The range
/// must end at a commit whose floor determines the proof's canonical inactive peak count. Earlier
/// commits are accepted, allowing bootstrap, prefixes, and overlapping uploads to use this API.
/// The operation codec configuration must match the originating QMDB variant.
pub fn prepare_authenticated_range<F, H, Op, S>(
    authenticated: &AuthenticatedOperationRange<'_, H::Digest, F>,
    expected_root: &H::Digest,
    operation_cfg: &Op::Cfg,
    strategy: &S,
) -> Result<PreparedAuthenticatedRange<H::Digest, F>, QmdbError>
where
    F: Family,
    H: Hasher,
    Op: UploadOperation<F>,
    S: Strategy,
{
    let start = authenticated.start_location;
    let end = authenticated.proof.leaves;
    if !start.is_valid_index() || !end.is_valid() || start >= end {
        return Err(QmdbError::CorruptData(format!(
            "invalid authenticated operation range [{start}, {end})"
        )));
    }
    let expected_count = usize::try_from(*end - *start).map_err(|_| {
        QmdbError::CorruptData("authenticated operation count exceeds usize".into())
    })?;
    if authenticated.encoded_operations.len() != expected_count {
        return Err(QmdbError::CorruptData(format!(
            "authenticated range [{start}, {end}) contains {} operations",
            authenticated.encoded_operations.len()
        )));
    }
    for encoded in authenticated.encoded_operations {
        ensure_encoded_value_size(encoded.len())?;
    }

    let pinned_positions = F::nodes_to_pin(start).collect::<Vec<_>>();
    if authenticated.pinned_nodes.len() != pinned_positions.len() {
        return Err(QmdbError::CorruptData(format!(
            "authenticated range has {} pins, expected {}",
            authenticated.pinned_nodes.len(),
            pinned_positions.len()
        )));
    }
    let hasher = commonware_storage::qmdb::hasher::<H>();
    if !authenticated.proof.verify_proof_and_pinned_nodes(
        &hasher,
        authenticated.encoded_operations,
        start,
        authenticated.pinned_nodes,
        expected_root,
    ) {
        return Err(QmdbError::ProofVerification {
            kind: ProofKind::RangeCheckpoint,
        });
    }

    let latest_location = end.checked_sub(1).ok_or_else(|| {
        QmdbError::CorruptData("authenticated range has no final operation".into())
    })?;
    let mut operation_rows = Vec::with_capacity(expected_count);
    let mut index_rows = Vec::new();
    let mut final_floor = None;
    for (offset, encoded) in authenticated.encoded_operations.iter().enumerate() {
        let location = start.checked_add(offset as u64).ok_or_else(|| {
            QmdbError::CorruptData("authenticated operation location overflow".into())
        })?;
        let operation = Op::decode_cfg(
            commonware_codec::Copying(encoded.as_slice()),
            operation_cfg,
        )
        .map_err(|error| {
            QmdbError::CorruptData(format!(
                "failed to decode authenticated operation at {location}: {error}"
            ))
        })?;
        if operation.encode().as_ref() != encoded.as_slice() {
            return Err(QmdbError::CorruptData(format!(
                "authenticated operation at {location} is not canonically encoded"
            )));
        }
        final_floor = operation.has_floor();
        if let Some(floor) = final_floor {
            if !floor.is_valid() || floor > location {
                return Err(QmdbError::CorruptData(format!(
                    "authenticated commit floor {floor} exceeds commit location {location}"
                )));
            }
        }
        if let Some((key, value_present)) = operation.indexed_key() {
            index_rows.push((
                encode_update_key(key, location)?,
                encode_update_index_value(value_present),
            ));
        }
        operation_rows.push((encode_operation_key(location), encoded.clone()));
    }
    let floor = final_floor
        .ok_or_else(|| QmdbError::CorruptData("authenticated range must end at a commit".into()))?;
    if !authenticated
        .proof
        .matches_canonical_inactive_peaks(end, floor)
    {
        return Err(QmdbError::CorruptData(
            "authenticated proof has a noncanonical inactive peak count".into(),
        ));
    }

    // Replaying verified pins also creates delayed MMB parents hidden by folded proof prefixes
    let extension = extend_merkle_from_pinned_nodes::<F, H, S, _>(
        authenticated.pinned_nodes.to_vec(),
        start,
        authenticated.encoded_operations.iter().map(Vec::as_slice),
        authenticated.proof.inactive_peaks,
        strategy,
    )?;
    let expected_size = Position::try_from(end).map_err(|error| {
        QmdbError::CorruptData(format!("invalid authenticated range end: {error}"))
    })?;
    if extension.size != expected_size || extension.root != *expected_root {
        return Err(QmdbError::ProofVerification {
            kind: ProofKind::RangeCheckpoint,
        });
    }

    let mut rows = operation_rows;
    rows.extend(index_rows);
    rows.extend(
        pinned_positions
            .into_iter()
            .zip(authenticated.pinned_nodes.iter())
            .map(|(position, digest)| (encode_node_key(position), digest.encode().to_vec())),
    );
    rows.extend(
        extension
            .new_nodes
            .into_iter()
            .map(|(position, digest)| (encode_node_key(position), digest.encode().to_vec())),
    );
    rows.push((encode_presence_key(latest_location), Vec::new()));
    Ok(PreparedAuthenticatedRange {
        rows,
        start_location: start,
        latest_location,
        ops_root: *expected_root,
    })
}

/// Stage authenticated range rows under the client's configured namespace.
pub fn stage_authenticated_range<D: Digest, F: Family>(
    client: &PrefixedStoreClient,
    prepared: PreparedAuthenticatedRange<D, F>,
    batch: &mut StoreWriteBatch,
) -> Result<(), QmdbError> {
    batch.reserve(prepared.rows.len());
    for (key, value) in prepared.rows {
        batch.push(client, &key, value)?;
    }
    Ok(())
}

/// Stage a published commit location under the client's configured namespace.
///
/// The caller must only advance this location after every required row in the contiguous prefix
/// is durable, or when those rows are staged in the same atomic Store batch. For current QMDBs,
/// the corresponding authenticated current boundary rows must also be available.
pub fn stage_watermark<F: Family>(
    client: &PrefixedStoreClient,
    watermark: Location<F>,
    batch: &mut StoreWriteBatch,
) -> Result<(), QmdbError> {
    if !watermark.is_valid_index() {
        return Err(QmdbError::CorruptData(format!(
            "invalid published operation watermark {watermark}"
        )));
    }
    batch.push(client, &encode_watermark_key(watermark), Vec::new())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;
    use commonware_codec::Buf;
    use commonware_codec::{FixedSize, Read, Write};
    use commonware_cryptography::{sha256::Digest as Sha256Digest, Sha256};
    use commonware_parallel::{Rayon, Sequential};
    use commonware_storage::{
        merkle::{mem::Mem, mmb, mmr},
        qmdb::any::{
            ordered, unordered,
            value::{FixedEncoding, VariableEncoding},
        },
    };
    use commonware_utils::sequence::FixedBytes;
    use exoware_sdk::{StoreClient, StoreKeyPrefix};
    use std::{collections::BTreeMap, num::NonZeroUsize};

    type FixedValueEncoding = FixedEncoding<FixedBytes<8>>;
    type FixedKeylessOperation<F> = keyless::Operation<F, FixedValueEncoding>;

    #[derive(Clone)]
    struct AuthenticatedRangeFixture<F: Family> {
        start_location: Location<F>,
        root: Sha256Digest,
        proof: Proof<F, Sha256Digest>,
        pinned_nodes: Vec<Sha256Digest>,
        encoded_operations: Vec<Vec<u8>>,
        merkle_nodes: BTreeMap<Position<F>, Sha256Digest>,
    }

    impl<F: Family> AuthenticatedRangeFixture<F> {
        fn view(&self) -> AuthenticatedOperationRange<'_, Sha256Digest, F> {
            AuthenticatedOperationRange {
                start_location: self.start_location,
                proof: &self.proof,
                pinned_nodes: &self.pinned_nodes,
                encoded_operations: &self.encoded_operations,
            }
        }

        fn prepare(&self) -> Result<PreparedAuthenticatedRange<Sha256Digest, F>, QmdbError> {
            prepare_authenticated_range::<F, Sha256, FixedKeylessOperation<F>, _>(
                &self.view(),
                &self.root,
                &(),
                &Sequential,
            )
        }
    }

    fn authenticated_range_fixture<F: Family>(
        encoded_history: &[Vec<u8>],
        start_location: u64,
        inactive_peaks: usize,
    ) -> AuthenticatedRangeFixture<F> {
        let hasher = commonware_storage::qmdb::hasher::<Sha256>();
        let mut memory = Mem::<F, _>::new();
        let mut batch = memory.new_batch();
        for operation in encoded_history {
            batch = batch.add(&hasher, operation);
        }
        let batch = batch.merkleize(&memory, &hasher);
        memory.apply_batch(&batch).expect("apply test operations");
        let start_location = Location::new(start_location);
        let end = Location::new(encoded_history.len() as u64);
        let size = Position::try_from(end).expect("valid size");
        AuthenticatedRangeFixture {
            start_location,
            root: memory.root(&hasher, inactive_peaks).expect("test root"),
            proof: memory
                .range_proof(&hasher, start_location..end, inactive_peaks)
                .expect("test range proof"),
            pinned_nodes: F::nodes_to_pin(start_location)
                .map(|position| memory.get_node(position).expect("test pin"))
                .collect(),
            encoded_operations: encoded_history[*start_location as usize..].to_vec(),
            merkle_nodes: (0..*size)
                .map(|position| {
                    let position = Position::new(position);
                    (position, memory.get_node(position).expect("test node"))
                })
                .collect(),
        }
    }

    fn encode<Op: Encode>(operations: &[Op]) -> Vec<Vec<u8>> {
        operations.iter().map(|op| op.encode().to_vec()).collect()
    }

    fn committed_encoded_operations<F: Family>() -> Vec<Vec<u8>> {
        encode(&[
            FixedKeylessOperation::<F>::Commit(None, Location::new(0)),
            FixedKeylessOperation::<F>::Append(FixedBytes::new([1; 8])),
            FixedKeylessOperation::<F>::Commit(None, Location::new(0)),
            FixedKeylessOperation::<F>::Append(FixedBytes::new([2; 8])),
            FixedKeylessOperation::<F>::Commit(None, Location::new(2)),
        ])
    }

    fn reject_tampering<F: Family>() {
        let operations = committed_encoded_operations::<F>();
        let original = authenticated_range_fixture::<F>(&operations, 3, 0);
        let _ = original.prepare().expect("valid authenticated range");
        let changed_digest = Sha256::hash(&[b"changed digest"]);

        let mut changed = original.clone();
        assert!(!changed.proof.digests.is_empty());
        changed.proof.digests[0] = changed_digest;
        assert!(matches!(
            changed.prepare(),
            Err(QmdbError::ProofVerification { .. })
        ));

        let mut changed = original.clone();
        assert!(!changed.pinned_nodes.is_empty());
        changed.pinned_nodes[0] = changed_digest;
        assert!(matches!(
            changed.prepare(),
            Err(QmdbError::ProofVerification { .. })
        ));

        let mut changed = original.clone();
        changed.encoded_operations[0][1] ^= 1;
        assert!(matches!(
            changed.prepare(),
            Err(QmdbError::ProofVerification { .. })
        ));

        assert!(matches!(
            prepare_authenticated_range::<F, Sha256, FixedKeylessOperation<F>, _>(
                &original.view(),
                &changed_digest,
                &(),
                &Sequential,
            ),
            Err(QmdbError::ProofVerification { .. })
        ));

        let mut changed = original.clone();
        changed.encoded_operations.pop();
        assert!(matches!(changed.prepare(), Err(QmdbError::CorruptData(_))));

        let mut changed = original;
        changed.pinned_nodes.pop();
        assert!(matches!(changed.prepare(), Err(QmdbError::CorruptData(_))));
    }

    #[test]
    fn test_rejects_tampered_proof_pins_operations_and_trusted_root() {
        reject_tampering::<mmr::Family>();
        reject_tampering::<mmb::Family>();
    }

    // This decoder deliberately accepts aliases so canonical encoding validation is exercised
    struct AliasedCommit(u8);

    impl Write for AliasedCommit {
        fn write(&self, buf: &mut impl BufMut) {
            self.0.write(buf);
        }
    }

    impl FixedSize for AliasedCommit {
        const SIZE: usize = 1;
    }

    impl Read for AliasedCommit {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, cfg: &()) -> Result<Self, commonware_codec::Error> {
            Ok(Self(u8::read_cfg(buf, cfg)? & 1))
        }
    }

    impl<F: Family> Floored<F> for AliasedCommit {
        fn has_floor(&self) -> Option<Location<F>> {
            Some(Location::new(0))
        }
    }

    impl<F: Family> UploadOperation<F> for AliasedCommit {
        fn indexed_key(&self) -> Option<(&[u8], bool)> {
            None
        }
    }

    #[test]
    fn test_rejects_authenticated_noncanonical_operation_encoding() {
        let authenticated = authenticated_range_fixture::<mmr::Family>(&[vec![2]], 0, 0);
        let error = prepare_authenticated_range::<mmr::Family, Sha256, AliasedCommit, _>(
            &authenticated.view(),
            &authenticated.root,
            &(),
            &Sequential,
        )
        .expect_err("noncanonical authenticated bytes must fail");
        assert!(
            matches!(error, QmdbError::CorruptData(message) if message.contains("not canonically encoded"))
        );
    }

    fn reject_invalid_commit_contract<F: Family>() {
        let mut operations = committed_encoded_operations::<F>();

        operations[0] = FixedKeylessOperation::<F>::Commit(None, Location::new(1))
            .encode()
            .to_vec();
        let error = authenticated_range_fixture::<F>(&operations, 0, 0)
            .prepare()
            .expect_err("invalid earlier floor");
        assert!(
            matches!(error, QmdbError::CorruptData(message) if message.contains("exceeds commit location"))
        );

        operations = committed_encoded_operations::<F>();
        operations[4] = FixedKeylessOperation::<F>::Commit(None, Location::new(5))
            .encode()
            .to_vec();
        let error = authenticated_range_fixture::<F>(&operations, 0, 0)
            .prepare()
            .expect_err("invalid final floor");
        assert!(
            matches!(error, QmdbError::CorruptData(message) if message.contains("exceeds commit location"))
        );

        operations[4] = FixedKeylessOperation::<F>::Append(FixedBytes::new([3; 8]))
            .encode()
            .to_vec();
        let error = authenticated_range_fixture::<F>(&operations, 0, 0)
            .prepare()
            .expect_err("missing final commit");
        assert!(
            matches!(error, QmdbError::CorruptData(message) if message.contains("must end at a commit"))
        );

        operations = committed_encoded_operations::<F>();
        let error = authenticated_range_fixture::<F>(&operations, 0, 1)
            .prepare()
            .expect_err("noncanonical inactive peaks");
        assert!(
            matches!(error, QmdbError::CorruptData(message) if message.contains("noncanonical inactive peak count"))
        );
    }

    #[test]
    fn test_rejects_invalid_commit_floors_and_inactive_peak_count() {
        reject_invalid_commit_contract::<mmr::Family>();
        reject_invalid_commit_contract::<mmb::Family>();
    }

    fn accept_overlap<F: Family>() {
        let operations = committed_encoded_operations::<F>();
        let bootstrap = authenticated_range_fixture::<F>(&operations[..1], 0, 0)
            .prepare()
            .expect("bootstrap commit");
        assert_eq!(bootstrap.start_location(), Location::new(0));
        assert_eq!(bootstrap.latest_location(), Location::new(0));

        let prefix = authenticated_range_fixture::<F>(&operations[..3], 0, 0)
            .prepare()
            .expect("prefix with two commits");
        let overlap = authenticated_range_fixture::<F>(&operations, 1, 0)
            .prepare()
            .expect("overlap with two commits");
        let full = authenticated_range_fixture::<F>(&operations, 0, 0)
            .prepare()
            .expect("full history with three commits");
        let mut expected = full.rows.into_iter().collect::<BTreeMap<_, _>>();
        let mut combined = prefix.rows.into_iter().collect::<BTreeMap<_, _>>();
        let mut repeated_rows = 0;
        for (key, value) in overlap.rows {
            if let Some(previous) = combined.insert(key, value.clone()) {
                repeated_rows += 1;
                assert_eq!(previous, value, "overlapping rows must be identical");
            }
        }
        assert!(repeated_rows > 0);
        // Overlapping ranges can advertise additional intermediate batch boundaries
        expected.retain(|key, _| !crate::codec::PRESENCE_PREFIX.matches(key));
        combined.retain(|key, _| !crate::codec::PRESENCE_PREFIX.matches(key));
        assert_eq!(combined, expected);
    }

    #[test]
    fn test_bootstrap_and_overlapping_ranges_with_multiple_commits_are_accepted() {
        accept_overlap::<mmr::Family>();
        accept_overlap::<mmb::Family>();
    }

    #[test]
    fn test_indexed_keys_distinguish_updates_deletions_and_commits() {
        type Unordered = unordered::Operation<mmr::Family, FixedBytes<8>, FixedValueEncoding>;
        type Ordered = ordered::Operation<mmr::Family, FixedBytes<8>, FixedValueEncoding>;
        type Immutable = immutable::Operation<mmr::Family, Vec<u8>, VariableEncoding<Vec<u8>>>;
        let key = FixedBytes::new([1; 8]);
        let value = FixedBytes::new([2; 8]);
        let unordered_update = Unordered::Update(unordered::Update(key.clone(), value.clone()));
        let ordered_update = Ordered::Update(ordered::Update {
            key: key.clone(),
            value: value.clone(),
            next_key: FixedBytes::new([3; 8]),
        });
        assert_eq!(unordered_update.indexed_key(), Some((key.as_ref(), true)));
        assert_eq!(ordered_update.indexed_key(), Some((key.as_ref(), true)));
        assert_eq!(
            Unordered::Delete(key.clone()).indexed_key(),
            Some((key.as_ref(), false))
        );
        assert_eq!(
            Ordered::Delete(key.clone()).indexed_key(),
            Some((key.as_ref(), false))
        );
        assert_eq!(
            Unordered::CommitFloor(None, Location::new(0)).indexed_key(),
            None
        );
        assert_eq!(
            Ordered::CommitFloor(None, Location::new(0)).indexed_key(),
            None
        );
        let immutable = Immutable::Set(vec![1, 0, 2], vec![3, 4]);
        assert_eq!(immutable.indexed_key(), Some(([1, 0, 2].as_slice(), true)));
        assert_eq!(
            Immutable::Commit(None, Location::new(0)).indexed_key(),
            None
        );
        assert_eq!(
            FixedKeylessOperation::<mmr::Family>::Append(value).indexed_key(),
            None
        );
    }

    fn assert_parallel_preparation<F: Family + PartialEq>() {
        // Force parallel work even for this small fixture
        let strategy = Rayon::new(NonZeroUsize::new(2).unwrap())
            .expect("Rayon strategy")
            .manual();
        for floor in [0, 512] {
            let mut operations = vec![FixedKeylessOperation::<F>::Commit(None, Location::new(0))];
            operations.extend(
                (1u64..769).map(|index| {
                    FixedKeylessOperation::Append(FixedBytes::new(index.to_be_bytes()))
                }),
            );
            operations.push(FixedKeylessOperation::Commit(None, Location::new(floor)));
            let inactive_peaks =
                F::inactive_peaks(Location::new(operations.len() as u64), Location::new(floor));
            assert_eq!(inactive_peaks == 0, floor == 0);
            let authenticated =
                authenticated_range_fixture::<F>(&encode(&operations), 513, inactive_peaks);
            assert!(!authenticated.pinned_nodes.is_empty());
            let sequential = authenticated.prepare().expect("sequential preparation");
            let parallel = prepare_authenticated_range::<F, Sha256, FixedKeylessOperation<F>, _>(
                &authenticated.view(),
                &authenticated.root,
                &(),
                &strategy,
            )
            .expect("parallel preparation");
            assert_eq!(parallel, sequential);
        }
    }

    #[test]
    fn test_parallel_preparation_mmr() {
        assert_parallel_preparation::<mmr::Family>();
    }

    #[test]
    fn test_parallel_preparation_mmb() {
        assert_parallel_preparation::<mmb::Family>();
    }

    #[test]
    fn test_current_boundary_must_bind_to_the_authenticated_operation_root() {
        use commonware_storage::qmdb::current::proof::OpsRootWitness;

        let operations = committed_encoded_operations::<mmr::Family>();
        let authenticated = authenticated_range_fixture::<mmr::Family>(&operations, 0, 0);
        let witness = OpsRootWitness::<mmr::Family, _> {
            grafted_root: Sha256::hash(&[b"grafted root"]),
            pending_chunk_digest: Default::default(),
            partial_chunk: None,
        };
        let mut boundary = CurrentBoundaryState::<_, 32, mmr::Family> {
            root: witness.root::<Sha256>(&authenticated.root),
            pruned_chunks: 0,
            ops_root_witness: witness,
            chunks: Vec::new(),
            grafted_nodes: Vec::new(),
        };
        let prepared = authenticated.prepare().expect("prepare operation range");
        let initial_rows = prepared.rows.len();
        let prepared = prepared
            .with_current_boundary::<Sha256, 32>(&boundary)
            .expect("matching binding");
        assert_eq!(prepared.rows.len(), initial_rows + 2);

        boundary.root = Sha256::hash(&[b"unrelated current root"]);
        assert!(authenticated
            .prepare()
            .unwrap()
            .with_current_boundary::<Sha256, 32>(&boundary)
            .is_err());
    }

    #[test]
    fn test_current_boundary_upload_keys_grafted_nodes_by_grafted_space_position() {
        let digest = Sha256::hash(&[b"grafted-node"]);
        let ops_position = Position::new(2046);
        let latest_location = Location::new(1024);
        let witness = commonware_storage::qmdb::current::proof::OpsRootWitness::<mmr::Family, _> {
            grafted_root: digest,
            pending_chunk_digest: Default::default(),
            partial_chunk: None,
        };
        let boundary = CurrentBoundaryState::<_, 32, mmr::Family> {
            root: witness.root::<Sha256>(&digest),
            pruned_chunks: 0,
            ops_root_witness: witness,
            chunks: Vec::new(),
            grafted_nodes: vec![(ops_position, digest)],
        };
        let prepared = PreparedAuthenticatedRange {
            rows: Vec::new(),
            start_location: Location::new(0),
            latest_location,
            ops_root: digest,
        }
        .with_current_boundary::<Sha256, 32>(&boundary)
        .expect("matching binding");
        let grafted_position = grafting::ops_to_grafted_pos(ops_position, grafting::height::<32>());
        let expected_key = encode_grafted_node_key(grafted_position, latest_location);
        let stale_ops_key = encode_grafted_node_key(ops_position, latest_location);

        assert!(prepared
            .rows
            .iter()
            .any(|(key, value)| key == &expected_key && value.as_slice() == digest.as_ref()));
        assert!(!prepared.rows.iter().any(|(key, _)| key == &stale_ops_key));
    }

    #[test]
    fn test_mmb_replays_delayed_parent_hidden_by_inactive_prefix() {
        let operations = encode(&[
            FixedKeylessOperation::<mmb::Family>::Commit(None, Location::new(0)),
            FixedKeylessOperation::<mmb::Family>::Append(FixedBytes::new([1; 8])),
            FixedKeylessOperation::<mmb::Family>::Append(FixedBytes::new([2; 8])),
            FixedKeylessOperation::<mmb::Family>::Commit(None, Location::new(0)),
            FixedKeylessOperation::<mmb::Family>::Commit(None, Location::new(4)),
        ]);
        let authenticated = authenticated_range_fixture::<mmb::Family>(&operations, 4, 1);
        let parent = Position::new(7);
        let extracted = authenticated
            .proof
            .verify_range_inclusion_and_extract_digests(
                &commonware_storage::qmdb::hasher::<Sha256>(),
                &authenticated.encoded_operations,
                authenticated.start_location,
                &authenticated.root,
            )
            .expect("verify source proof");
        assert!(!extracted.iter().any(|(position, _)| *position == parent));

        let prepared = authenticated
            .prepare()
            .expect("replay authenticated MMB pins");
        let rows = prepared.rows.into_iter().collect::<BTreeMap<_, _>>();
        assert_eq!(
            rows.get(&encode_node_key(parent)),
            Some(&authenticated.merkle_nodes[&parent].encode().to_vec()),
        );
        for (position, digest) in
            mmb::Family::nodes_to_pin(authenticated.start_location).zip(&authenticated.pinned_nodes)
        {
            assert_eq!(
                rows.get(&encode_node_key(position)),
                Some(&digest.encode().to_vec())
            );
        }
    }

    #[test]
    fn test_staging_keeps_publication_explicit_and_uses_the_client_namespace() {
        let operations = committed_encoded_operations::<mmr::Family>();
        let prepared = authenticated_range_fixture::<mmr::Family>(&operations, 0, 0)
            .prepare()
            .expect("prepare range");
        let latest = prepared.latest_location();
        let client = StoreClient::new("http://127.0.0.1:1")
            .prefixed(StoreKeyPrefix::new(b"authenticated-range/".to_vec()).expect("prefix"));
        let mut batch = StoreWriteBatch::new();
        stage_authenticated_range(&client, prepared, &mut batch).expect("stage range");
        let mut has_boundary = false;
        for (physical, _) in batch.entries() {
            let logical = client.decode_store_key(physical).expect("client namespace");
            has_boundary |= logical == encode_presence_key(latest);
            assert_ne!(logical, encode_watermark_key(latest));
        }
        assert!(has_boundary);
        let data_rows = batch.len();
        stage_watermark(&client, latest, &mut batch).expect("stage publication");
        let publication = &batch.entries()[data_rows..];
        assert_eq!(publication.len(), 1);
        assert_eq!(
            client.decode_store_key(&publication[0].0).unwrap(),
            encode_watermark_key(latest)
        );
        assert!(publication.iter().all(|(_, value)| value.is_empty()));
        let staged = batch.len();
        assert!(stage_watermark(&client, mmr::Family::MAX_LEAVES, &mut batch).is_err());
        assert_eq!(batch.len(), staged);
    }
}
