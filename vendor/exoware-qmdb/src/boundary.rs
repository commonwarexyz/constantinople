use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use commonware_codec::{Codec, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::merkle::{
    hasher::{Hasher as MerkleHasher, Standard as StandardHasher},
    path, Family, Graftable, Location, Position,
};
use commonware_storage::qmdb::{
    current::{
        grafting,
        proof::{verify_proof_and_extract_digests, OpsRootWitness, RangeProof},
    },
    operation::Operation as QmdbOperation,
};

use crate::codec::{bitmap_chunk_bits, chunk_index_for_location};
use crate::error::QmdbError;
use crate::CurrentBoundaryState;

fn merge_authenticated_digest<F: Family, D: Copy + PartialEq>(
    authenticated_digests: &mut BTreeMap<Position<F>, D>,
    position: Position<F>,
    digest: D,
) -> Result<(), QmdbError> {
    if let Some(existing) = authenticated_digests.insert(position, digest) {
        if existing != digest {
            return Err(QmdbError::CorruptData(format!(
                "current range proofs disagree on digest at position {position}"
            )));
        }
    }
    Ok(())
}

async fn authenticate_location<M, H, Op, const N: usize, Prove, Fut>(
    location: Location<M>,
    operations: &[Op],
    root: H::Digest,
    prove_at: &mut Prove,
    authenticated_digests: &mut BTreeMap<Position<M>, H::Digest>,
) -> Result<(u64, [u8; N]), QmdbError>
where
    M: Graftable,
    H: Hasher,
    Op: QmdbOperation<M> + Codec,
    Prove: FnMut(Location<M>) -> Fut,
    Fut: Future<Output = Result<(RangeProof<M, H::Digest>, [u8; N]), QmdbError>>,
{
    let (proof, chunk) = prove_at(location).await?;
    let operation = operations.get(*location as usize).ok_or_else(|| {
        QmdbError::CorruptData(format!(
            "missing operation at location {location} in current boundary input"
        ))
    })?;
    let digests = verify_proof_and_extract_digests::<_, _, H, _, N>(
        &proof,
        location,
        std::slice::from_ref(operation),
        std::slice::from_ref(&chunk),
        &root,
    )
    .map_err(|_| QmdbError::ProofVerification {
        kind: crate::ProofKind::CurrentRange,
    })?;
    for (position, digest) in digests {
        merge_authenticated_digest(authenticated_digests, position, digest)?;
    }
    Ok((chunk_index_for_location::<M, N>(location), chunk))
}

/// Recover the current-boundary delta for one batch from local proof material
/// emitted by a Commonware `current` QMDB.
///
/// This derives upload rows from a caller-owned local Commonware current DB.
/// Callers apply a batch locally,
/// then use this function to recover the exact versioned current-state rows
/// that must be uploaded for that batch boundary:
///
/// - `root`: the local current DB root after applying `operations`
/// - `pruned_chunks`: the local current bitmap's pruned complete-chunk count
/// - `ops_root_witness`: the local proof that the operation-log root is
///   committed by `root`
/// - `chunks`: only the bitmap chunks whose contents changed at this boundary
/// - `grafted_nodes`: only the complete-chunk grafted nodes whose digests
///   changed at this boundary
///
/// `previous_operations` and `operations` are the cumulative operation logs
/// before and after one finalized local batch respectively, not just the delta
/// batch itself. In the intended flow `operations` therefore includes the
/// new batch's appended `CommitFloor`, and `previous_operations` is the exact
/// cumulative prefix immediately before that batch was applied.
///
/// With a previous log, the inputs must differ by exactly one finalized batch.
/// With no previous log, the function recovers a complete boundary from the
/// retained prefix, including bootstrap and restart material.
///
/// `prove_at(location)` must return a current range proof plus the bitmap
/// chunk for that exact `location`, taken from the same local DB state as
/// `root`.
///
/// The caller must obtain `root`, `pruned_chunks`, and `ops_root_witness` from the
/// same trusted local state. This function authenticates recovered chunks and nodes
/// against `root`. It does not independently authenticate the pruned chunk count.
/// Attach the result with [`crate::PreparedAuthenticatedRange::with_current_boundary`].
pub async fn recover_boundary_state<M, H, Op, const N: usize, Prove, Fut>(
    previous_operations: Option<&[Op]>,
    operations: &[Op],
    root: H::Digest,
    pruned_chunks: u64,
    ops_root_witness: OpsRootWitness<M, H::Digest>,
    mut prove_at: Prove,
) -> Result<CurrentBoundaryState<H::Digest, N, M>, QmdbError>
where
    M: Graftable,
    H: Hasher,
    Op: QmdbOperation<M> + Codec,
    Op::Key: AsRef<[u8]>,
    Prove: FnMut(Location<M>) -> Fut,
    Fut: Future<Output = Result<(RangeProof<M, H::Digest>, [u8; N]), QmdbError>>,
{
    if operations.is_empty() {
        return Err(QmdbError::EmptyBatch);
    }

    let previous_len = previous_operations.map_or(0usize, |ops| ops.len());
    if previous_len >= operations.len() {
        return Err(QmdbError::CorruptData(format!(
            "current operations length {} must exceed previous length {}",
            operations.len(),
            previous_len
        )));
    }
    validate_recovery_input::<M, Op>(previous_operations, operations)?;

    let grafting_height = grafting::height::<N>();
    let ops_leaves = u64::try_from(operations.len())
        .map_err(|_| QmdbError::CorruptData("operation count does not fit in u64".into()))?;
    let previous_ops_leaves = previous_operations.map_or(0u64, |ops| ops.len() as u64);
    let complete_chunks = ops_leaves / bitmap_chunk_bits::<N>();
    let graftable_chunks =
        grafting::graftable_chunks::<M>(ops_leaves, grafting_height).min(complete_chunks);
    if pruned_chunks > graftable_chunks {
        return Err(QmdbError::CorruptData(format!(
            "current pruned chunks {pruned_chunks} exceeds graftable chunks {graftable_chunks}"
        )));
    }
    let changed_chunks =
        changed_chunk_representatives::<M, Op, N>(previous_operations, operations, pruned_chunks);
    let previous_complete_chunks = previous_ops_leaves / bitmap_chunk_bits::<N>();
    let previous_graftable_chunks =
        grafting::graftable_chunks::<M>(previous_ops_leaves, grafting_height)
            .min(previous_complete_chunks);

    let mut chunks = BTreeMap::<u64, [u8; N]>::new();
    let mut authenticated_digests = BTreeMap::<Position<M>, H::Digest>::new();
    let mut grafted_digests = BTreeMap::<Position<M>, H::Digest>::new();
    let mut changed_complete_chunks = Vec::new();

    for (_chunk_index, location) in changed_chunks {
        let (chunk_index, chunk) = authenticate_location::<M, H, Op, N, _, _>(
            location,
            operations,
            root,
            &mut prove_at,
            &mut authenticated_digests,
        )
        .await?;
        chunks.entry(chunk_index).or_insert(chunk);

        if chunk_index >= graftable_chunks {
            continue;
        }

        let (leaf_grafted_pos, leaf_digest) = changed_grafted_leaf_digest_for_chunk::<M, H>(
            chunk_index,
            grafting_height,
            &authenticated_digests,
        )?;
        grafted_digests.insert(leaf_grafted_pos, leaf_digest);
        changed_complete_chunks.push(chunk_index);
    }

    for chunk_index in previous_graftable_chunks.max(pruned_chunks)..graftable_chunks {
        let location = Location::new(chunk_index * bitmap_chunk_bits::<N>());
        if chunks.contains_key(&chunk_index) {
            continue;
        }
        let (chunk_index, chunk) = authenticate_location::<M, H, Op, N, _, _>(
            location,
            operations,
            root,
            &mut prove_at,
            &mut authenticated_digests,
        )
        .await?;
        chunks.entry(chunk_index).or_insert(chunk);

        let (leaf_grafted_pos, leaf_digest) = changed_grafted_leaf_digest_for_chunk::<M, H>(
            chunk_index,
            grafting_height,
            &authenticated_digests,
        )?;
        grafted_digests.insert(leaf_grafted_pos, leaf_digest);
        changed_complete_chunks.push(chunk_index);
    }

    for chunk_index in changed_complete_chunks {
        let ancestors = {
            let mut ctx = GraftedDigestContext {
                grafting_height,
                pruned_chunks,
                digest_map: &mut authenticated_digests,
                computed: &mut grafted_digests,
                operations,
                root,
                prove_at: &mut prove_at,
            };
            changed_grafted_ancestor_digests_for_chunk::<M, H, Op, N, _, _>(
                chunk_index,
                graftable_chunks,
                &mut ctx,
            )
            .await?
        };
        for (position, digest) in ancestors {
            grafted_digests.insert(position, digest);
        }
    }

    Ok(CurrentBoundaryState {
        root,
        pruned_chunks,
        ops_root_witness,
        chunks: chunks.into_iter().collect(),
        grafted_nodes: grafted_digests
            .into_iter()
            .map(|(grafted_position, digest)| {
                (
                    grafting::grafted_to_ops_pos::<M>(grafted_position, grafting_height),
                    digest,
                )
            })
            .collect(),
    })
}

fn validate_recovery_input<F: Family, Op>(
    previous_operations: Option<&[Op]>,
    operations: &[Op],
) -> Result<(), QmdbError>
where
    Op: QmdbOperation<F> + Encode,
{
    if operations.last().is_none_or(|op| op.has_floor().is_none()) {
        return Err(QmdbError::CorruptData(
            "recover_boundary_state requires operations to end with a commit floor".into(),
        ));
    }

    let Some(previous) = previous_operations else {
        return Ok(());
    };

    for (index, (expected, actual)) in previous.iter().zip(operations.iter()).enumerate() {
        if expected.encode() != actual.encode() {
            return Err(QmdbError::CorruptData(format!(
                "recover_boundary_state requires previous_operations to be an exact prefix of operations; mismatch at location {index}"
            )));
        }
    }

    let delta = &operations[previous.len()..];
    let commit_count = delta
        .iter()
        .filter(|operation| operation.has_floor().is_some())
        .count();
    if commit_count != 1 {
        return Err(QmdbError::CorruptData(format!(
            "recover_boundary_state requires exactly one commit floor in the appended batch delta, found {commit_count}"
        )));
    }

    if delta.last().is_none_or(|op| op.has_floor().is_none()) {
        return Err(QmdbError::CorruptData(
            "recover_boundary_state requires the appended batch delta to end with a commit floor"
                .into(),
        ));
    }

    Ok(())
}

fn changed_chunk_representatives<F: Family, Op, const N: usize>(
    previous_operations: Option<&[Op]>,
    operations: &[Op],
    pruned_chunks: u64,
) -> BTreeMap<u64, Location<F>>
where
    Op: QmdbOperation<F>,
    Op::Key: AsRef<[u8]>,
{
    let previous_floor = previous_operations
        .and_then(|ops| ops.last())
        .and_then(|operation| operation.has_floor())
        .unwrap_or(Location::new(0));
    let floor = operations
        .last()
        .and_then(|operation| operation.has_floor())
        .unwrap_or(Location::new(0));
    let chunk_bits = bitmap_chunk_bits::<N>();

    let previous_len = previous_operations.map_or(0usize, |ops| ops.len());
    let mut changed = BTreeMap::<u64, Location<F>>::new();

    for raw_location in previous_len..operations.len() {
        let location = Location::new(raw_location as u64);
        let chunk_index = chunk_index_for_location::<F, N>(location);
        if chunk_index >= pruned_chunks {
            changed.entry(chunk_index).or_insert(location);
        }
    }

    if floor > previous_floor {
        let start_chunk = (*previous_floor / chunk_bits).max(pruned_chunks);
        let end_chunk = (*floor - 1) / chunk_bits;
        for chunk_index in start_chunk..=end_chunk {
            changed
                .entry(chunk_index)
                .or_insert(Location::new(chunk_index * chunk_bits));
        }
    }

    let Some(previous) = previous_operations else {
        return changed;
    };

    let mut touched_keys = operations[previous_len..]
        .iter()
        .filter_map(|operation| operation.key().map(|key| key.as_ref().to_vec()))
        .collect::<BTreeSet<_>>();

    for index in (0..previous.len()).rev() {
        if touched_keys.is_empty() {
            break;
        }
        let location = Location::new(index as u64);
        if let Some(key) = previous[index].key() {
            if touched_keys.remove(key.as_ref()) && previous[index].is_update() {
                let chunk_index = chunk_index_for_location::<F, N>(location);
                if chunk_index >= pruned_chunks {
                    changed.entry(chunk_index).or_insert(location);
                }
            }
        }
    }

    // Each batch clears the previous commit bit even when no key in that chunk changes
    if let Some(index) = previous.len().checked_sub(1) {
        let location = Location::new(index as u64);
        let chunk_index = chunk_index_for_location::<F, N>(location);
        if chunk_index >= pruned_chunks {
            changed.entry(chunk_index).or_insert(location);
        }
    }

    changed
}

fn changed_grafted_leaf_digest_for_chunk<F, H>(
    chunk_index: u64,
    grafting_height: u32,
    digest_map: &BTreeMap<Position<F>, H::Digest>,
) -> Result<(Position<F>, H::Digest), QmdbError>
where
    F: Graftable,
    H: Hasher,
{
    let grafted_pos = Position::<F>::try_from(Location::new(chunk_index))
        .expect("chunk index is a valid grafted leaf location");
    let ops_pos = grafting::grafted_to_ops_pos::<F>(grafted_pos, grafting_height);
    if let Some(digest) = digest_map.get(&ops_pos).copied() {
        return Ok((grafted_pos, digest));
    }

    Err(QmdbError::CorruptData(format!(
        "current range proof did not expose grafted leaf digest at ops position {ops_pos}"
    )))
}

fn grafted_subtree_is_pruned<F: Graftable>(
    grafted_pos: Position<F>,
    pruned_chunks: u64,
) -> Result<bool, QmdbError> {
    if pruned_chunks == 0 {
        return Ok(false);
    }
    let height = F::pos_to_height(grafted_pos);
    let leftmost = F::leftmost_leaf(grafted_pos, height);
    let covered_chunks = 1u64
        .checked_shl(height)
        .ok_or_else(|| QmdbError::CorruptData("grafted subtree height overflow".into()))?;
    Ok((*leftmost).saturating_add(covered_chunks) <= pruned_chunks)
}

fn ops_subtree_digest<F, H, Op>(
    position: Position<F>,
    operations: &[Op],
) -> Result<H::Digest, QmdbError>
where
    F: Graftable,
    H: Hasher,
    Op: Encode,
{
    let hasher = commonware_storage::qmdb::hasher::<H>();
    let height = F::pos_to_height(position);
    if height == 0 {
        let location = F::leftmost_leaf(position, height);
        let operation = operations.get(*location as usize).ok_or_else(|| {
            QmdbError::CorruptData(format!(
                "missing operation at location {location} for pruned grafted digest"
            ))
        })?;
        return Ok(<StandardHasher<H> as MerkleHasher<F>>::leaf_digest(
            &hasher,
            position,
            operation.encode().as_ref(),
        ));
    }

    let (left_pos, right_pos) = F::children(position, height);
    let left = ops_subtree_digest::<F, H, Op>(left_pos, operations)?;
    let right = ops_subtree_digest::<F, H, Op>(right_pos, operations)?;
    Ok(<StandardHasher<H> as MerkleHasher<F>>::node_digest(
        &hasher, position, &left, &right,
    ))
}

struct GraftedDigestContext<'a, F, H, Op, const N: usize, Prove>
where
    F: Graftable,
    H: Hasher,
{
    grafting_height: u32,
    pruned_chunks: u64,
    digest_map: &'a mut BTreeMap<Position<F>, H::Digest>,
    computed: &'a mut BTreeMap<Position<F>, H::Digest>,
    operations: &'a [Op],
    root: H::Digest,
    prove_at: &'a mut Prove,
}

async fn ensure_authenticated_grafted_digest<F, H, Op, const N: usize, Prove, Fut>(
    grafted_pos: Position<F>,
    ctx: &mut GraftedDigestContext<'_, F, H, Op, N, Prove>,
) -> Result<H::Digest, QmdbError>
where
    F: Graftable,
    H: Hasher,
    Op: QmdbOperation<F> + Codec,
    Prove: FnMut(Location<F>) -> Fut,
    Fut: Future<Output = Result<(RangeProof<F, H::Digest>, [u8; N]), QmdbError>>,
{
    if let Some(digest) = ctx.computed.get(&grafted_pos).copied() {
        return Ok(digest);
    }

    let ops_pos = grafting::grafted_to_ops_pos::<F>(grafted_pos, ctx.grafting_height);
    if let Some(digest) = ctx.digest_map.get(&ops_pos).copied() {
        return Ok(digest);
    }

    if grafted_subtree_is_pruned::<F>(grafted_pos, ctx.pruned_chunks)? {
        return ops_subtree_digest::<F, H, Op>(ops_pos, ctx.operations);
    }

    let chunk = F::leftmost_leaf(grafted_pos, F::pos_to_height(grafted_pos));
    let location = Location::new(
        (*chunk)
            .checked_mul(bitmap_chunk_bits::<N>())
            .ok_or_else(|| QmdbError::CorruptData("grafted chunk location overflow".into()))?,
    );
    authenticate_location::<F, H, Op, N, _, _>(
        location,
        ctx.operations,
        ctx.root,
        ctx.prove_at,
        ctx.digest_map,
    )
    .await?;
    ctx.digest_map.get(&ops_pos).copied().ok_or_else(|| {
        QmdbError::CorruptData(format!(
            "current range proof did not expose grafted digest at ops position {ops_pos}"
        ))
    })
}

async fn changed_grafted_ancestor_digests_for_chunk<F, H, Op, const N: usize, Prove, Fut>(
    chunk_index: u64,
    graftable_chunks: u64,
    ctx: &mut GraftedDigestContext<'_, F, H, Op, N, Prove>,
) -> Result<Vec<(Position<F>, H::Digest)>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    Op: QmdbOperation<F> + Codec,
    Prove: FnMut(Location<F>) -> Fut,
    Fut: Future<Output = Result<(RangeProof<F, H::Digest>, [u8; N]), QmdbError>>,
{
    if chunk_index >= graftable_chunks {
        return Ok(Vec::new());
    }

    let grafting_height = ctx.grafting_height;
    let grafted_size = Position::<F>::try_from(Location::new(graftable_chunks))
        .map_err(|e| QmdbError::CorruptData(format!("invalid grafted current size: {e}")))?;
    let grafted_leaf_pos = Position::<F>::try_from(Location::new(chunk_index))
        .expect("chunk index is a valid grafted leaf location");
    let (grafted_peak_pos, grafted_peak_height) =
        containing_peak::<F>(grafted_size, grafted_leaf_pos).ok_or_else(|| {
            QmdbError::CorruptData(format!(
                "missing containing grafted peak for chunk {chunk_index} at grafted position {grafted_leaf_pos}"
            ))
        })?;

    let first_leaf = F::leftmost_leaf(grafted_peak_pos, grafted_peak_height);
    let parents = path::Iterator::<F>::new(
        grafted_peak_pos,
        grafted_peak_height,
        first_leaf,
        Location::new(chunk_index),
    )
    .map(|(parent, _sibling, _height)| parent)
    .collect::<Vec<_>>();

    let hasher = commonware_storage::qmdb::hasher::<H>();
    let mut out = Vec::with_capacity(parents.len());
    for parent_grafted_pos in parents.into_iter().rev() {
        if let Some(digest) = ctx.computed.get(&parent_grafted_pos).copied() {
            out.push((parent_grafted_pos, digest));
            continue;
        }

        let parent_ops_pos = grafting::grafted_to_ops_pos::<F>(parent_grafted_pos, grafting_height);
        let parent_digest = if let Some(digest) = ctx.digest_map.get(&parent_ops_pos).copied() {
            digest
        } else {
            let parent_height = F::pos_to_height(parent_grafted_pos);
            let (left_pos, right_pos) = F::children(parent_grafted_pos, parent_height);
            let left_digest =
                ensure_authenticated_grafted_digest::<F, H, Op, N, _, _>(left_pos, ctx).await?;
            let right_digest =
                ensure_authenticated_grafted_digest::<F, H, Op, N, _, _>(right_pos, ctx).await?;
            <StandardHasher<H> as MerkleHasher<F>>::node_digest(
                &hasher,
                parent_ops_pos,
                &left_digest,
                &right_digest,
            )
        };
        ctx.computed.insert(parent_grafted_pos, parent_digest);
        out.push((parent_grafted_pos, parent_digest));
    }
    Ok(out)
}

fn containing_peak<F: Graftable>(
    merkle_size: Position<F>,
    position: Position<F>,
) -> Option<(Position<F>, u32)> {
    F::peaks(merkle_size).find(|(peak_pos, height)| {
        let leftmost = F::leftmost_leaf(*peak_pos, *height);
        let rightmost = leftmost + ((1u64 << *height) - 1);
        let position_leaf = F::leftmost_leaf(position, F::pos_to_height(position));
        leftmost <= position_leaf && position_leaf <= rightmost
    })
}

#[cfg(test)]
mod tests {
    use super::changed_chunk_representatives;
    use commonware_storage::merkle::{mmr, Location};
    use commonware_storage::qmdb::any::ordered::{
        variable::Operation as TestOperation, Update as OrderedUpdate,
    };
    use std::collections::BTreeMap;

    fn update(key: &[u8], value: &[u8]) -> TestOperation<mmr::Family, Vec<u8>, Vec<u8>> {
        TestOperation::Update(OrderedUpdate {
            key: key.to_vec(),
            value: value.to_vec(),
            next_key: Vec::new(),
        })
    }

    fn commit(floor: u64) -> TestOperation<mmr::Family, Vec<u8>, Vec<u8>> {
        TestOperation::CommitFloor(None, Location::new(floor))
    }

    fn previous_ops() -> Vec<TestOperation<mmr::Family, Vec<u8>, Vec<u8>>> {
        let mut ops = vec![commit(0)];
        for index in 1..8 {
            ops.push(update(
                format!("fill-{index}").as_bytes(),
                format!("value-{index}").as_bytes(),
            ));
        }
        ops.push(update(b"target", b"old"));
        for index in 9..16 {
            ops.push(update(
                format!("fill-{index}").as_bytes(),
                format!("value-{index}").as_bytes(),
            ));
        }
        ops
    }

    #[test]
    fn test_rewrite_pulls_in_old_update_chunk_when_floor_preserves_it() {
        // No trailing CommitFloor -> floor defaults to 0 -> no filtering.
        // The rewrite of "target" pulls in its old-location chunk.
        let previous = previous_ops();
        let mut operations = previous.clone();
        operations.push(update(b"target", b"new"));

        let changed = changed_chunk_representatives::<mmr::Family, TestOperation<_, _, _>, 1>(
            Some(&previous),
            &operations,
            0,
        );

        assert_eq!(
            changed,
            BTreeMap::from([(1u64, Location::new(8)), (2u64, Location::new(16)),])
        );
    }

    #[test]
    fn test_floor_crossed_chunks_are_published() {
        // Trailing CommitFloor(floor=16) means chunks 0 and 1 (covering
        // locations 0..15) become logically zeroed. They still need to be
        // published so remote proof builders can materialize the same bitmap
        // view as the local current DB.
        let previous = previous_ops();
        let mut operations = previous.clone();
        operations.push(update(b"target", b"new"));
        operations.push(commit(16));

        let changed = changed_chunk_representatives::<mmr::Family, TestOperation<_, _, _>, 1>(
            Some(&previous),
            &operations,
            0,
        );

        assert_eq!(
            changed,
            BTreeMap::from([
                (0u64, Location::new(0)),
                (1u64, Location::new(8)),
                (2u64, Location::new(16)),
            ])
        );
    }

    #[test]
    fn test_straddling_chunk_keeps_first_new_representative() {
        // With floor=18, chunks 0 and 1 (locations 0..15) become logically
        // zeroed and chunk 2 (locations 16..23) straddles the new floor. The
        // first appended operation also lands in chunk 2, so that newer
        // representative is retained.
        let previous = previous_ops();
        let mut operations = previous.clone();
        operations.push(update(b"neighbor1", b"v"));
        operations.push(update(b"neighbor2", b"v"));
        operations.push(update(b"neighbor3", b"v"));
        operations.push(commit(18));

        let changed = changed_chunk_representatives::<mmr::Family, TestOperation<_, _, _>, 1>(
            Some(&previous),
            &operations,
            0,
        );

        assert_eq!(
            changed,
            BTreeMap::from([
                (0u64, Location::new(0)),
                (1u64, Location::new(8)),
                (2u64, Location::new(16)),
            ])
        );
    }

    #[test]
    fn test_pruned_chunks_are_not_represented() {
        let previous = previous_ops();
        let mut operations = previous.clone();
        operations.push(update(b"target", b"new"));
        operations.push(commit(16));

        let changed = changed_chunk_representatives::<mmr::Family, TestOperation<_, _, _>, 1>(
            Some(&previous),
            &operations,
            2,
        );

        assert_eq!(changed, BTreeMap::from([(2u64, Location::new(16))]));
    }

    #[test]
    fn test_rejects_inputs_that_do_not_end_with_commit_floor() {
        let previous = previous_ops();
        let mut operations = previous.clone();
        operations.push(update(b"target", b"new"));

        let err =
            super::validate_recovery_input(Some(&previous), &operations).expect_err("must reject");
        assert!(
            err.to_string().contains("end with a commit floor"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_rejects_delta_with_multiple_commit_floors() {
        let previous = previous_ops();
        let mut operations = previous.clone();
        operations.push(commit(16));
        operations.push(commit(17));

        let err =
            super::validate_recovery_input(Some(&previous), &operations).expect_err("must reject");
        assert!(
            err.to_string().contains("exactly one commit floor"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_rejects_non_prefix_previous_operations() {
        let previous = previous_ops();
        let mut operations = previous.clone();
        operations[3] = update(b"mutated", b"value");
        operations.push(commit(16));

        let err =
            super::validate_recovery_input(Some(&previous), &operations).expect_err("must reject");
        assert!(
            err.to_string().contains("exact prefix"),
            "unexpected error: {err}"
        );
    }
}
