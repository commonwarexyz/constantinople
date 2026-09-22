use bytes::Bytes;
use commonware_codec::{Codec, Encode};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::{Sequential, Strategy};
use commonware_storage::{
    merkle::{
        self, storage::Storage as MerkleStorage, Family, Graftable, Location, Position, Proof,
    },
    qmdb::{
        any::{
            ordered,
            value::{ValueEncoding, VariableEncoding},
        },
        current::{
            ordered::proof::constant::ExclusionProof,
            proof::{OpsRootWitness, RangeProof, constant::OperationProof},
        },
        operation::{Key as QmdbKey, Operation},
        verify::verify_multi_proof,
    },
};

use crate::QmdbError;

/// Historical operation range plus the raw Merkle proof material used to verify
/// it. This is suitable for checkpointing and local Merkle continuation.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct OperationRangeCheckpoint<D: Digest, F: Graftable> {
    pub watermark: Location<F>,
    pub root: D,
    pub ops_root_witness: Option<OpsRootWitness<F, D>>,
    pub start_location: Location<F>,
    pub pinned_nodes: Vec<D>,
    pub proof: Proof<F, D>,
    pub encoded_operations: Vec<Vec<u8>>,
}

impl<D: Digest, F: Graftable> OperationRangeCheckpoint<D, F> {
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let hasher = commonware_storage::qmdb::hasher::<H>();
        self.proof.verify_proof_and_pinned_nodes(
            &hasher,
            &self.encoded_operations,
            self.start_location,
            &self.pinned_nodes,
            &self.root,
        )
    }

    /// Reconstruct the Merkle frontier from an authenticated range ending at the watermark.
    pub fn reconstruct_peaks<H: Hasher<Digest = D>>(
        &self,
    ) -> Result<Vec<(Position<F>, u32, D)>, QmdbError> {
        self.reconstruct_peaks_with_strategy::<H, Sequential>(&Sequential)
    }

    /// Reconstruct the Merkle frontier using `strategy` for Merkle hashing.
    pub fn reconstruct_peaks_with_strategy<H, S>(
        &self,
        strategy: &S,
    ) -> Result<Vec<(Position<F>, u32, D)>, QmdbError>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        let size = Position::try_from(self.proof.leaves)
            .map_err(|e| QmdbError::CorruptData(format!("invalid checkpoint leaf count: {e}")))?;

        let checkpoint_leaves = self.watermark.checked_add(1).ok_or_else(|| {
            QmdbError::CorruptData("checkpoint watermark exceeds the location domain".into())
        })?;
        if checkpoint_leaves != self.proof.leaves {
            return Err(QmdbError::CorruptData(format!(
                "checkpoint watermark implies {checkpoint_leaves} leaves, proof has {}",
                self.proof.leaves
            )));
        }

        let operation_count = u64::try_from(self.encoded_operations.len())
            .map_err(|_| QmdbError::CorruptData("checkpoint operation count exceeds u64".into()))?;
        let end_location = self
            .start_location
            .checked_add(operation_count)
            .ok_or_else(|| QmdbError::CorruptData("checkpoint range end overflow".into()))?;
        if end_location != self.proof.leaves {
            return Err(QmdbError::CorruptData(format!(
                "checkpoint range ends at {end_location}, expected {}",
                self.proof.leaves
            )));
        }

        if !self.verify::<H>() {
            return Err(QmdbError::CorruptData(
                "reconstruct checkpoint peaks failed because the proof or pins are invalid".into(),
            ));
        }

        let extension = crate::core::extend_merkle_from_pinned_nodes::<F, H, S, _>(
            self.pinned_nodes.clone(),
            self.start_location,
            self.encoded_operations.iter().map(Vec::as_slice),
            self.proof.inactive_peaks,
            strategy,
        )?;
        if extension.size != size {
            return Err(QmdbError::CorruptData(format!(
                "checkpoint extension size mismatch. Expected {size}, got {}",
                extension.size
            )));
        }
        if extension.root != self.root {
            return Err(QmdbError::CorruptData(
                "checkpoint extension root mismatch".into(),
            ));
        }

        Ok(extension.peaks)
    }
}

/// Historical multi-proof plus the exact operations it authenticates.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct RawMultiProof<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    F: Family,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> {
    pub watermark: Location<F>,
    pub root: D,
    pub proof: Proof<F, D>,
    pub operations: Vec<(Location<F>, ordered::Operation<F, K, E>)>,
}

impl<
        D: Digest,
        K: QmdbKey + Codec,
        V: Codec + Clone + Send + Sync,
        F: Family,
        E: ValueEncoding<Value = V>,
    > RawMultiProof<D, K, V, F, E>
where
    ordered::Operation<F, K, E>: Encode,
{
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        verify_multi_proof::<H, _, _>(&self.proof, &self.operations, &self.root)
    }
}

/// Backend-agnostic historical multi-proof keyed to an authorized batch. The
/// operations are stored as encoded bytes so this type is shared across
/// ordered, unordered, immutable, and keyless backends.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct RawBatchMultiProof<D: Digest, F: Graftable> {
    pub watermark: Location<F>,
    pub root: D,
    pub ops_root_witness: Option<OpsRootWitness<F, D>>,
    pub proof: Proof<F, D>,
    pub operations: Vec<(Location<F>, Vec<u8>)>,
}

impl<D: Digest, F: Graftable> RawBatchMultiProof<D, F> {
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let hasher = commonware_storage::qmdb::hasher::<H>();
        let elements: Vec<_> = self
            .operations
            .iter()
            .map(|(loc, bytes)| (bytes.as_slice(), *loc))
            .collect();
        self.proof
            .verify_multi_inclusion(&hasher, &elements, &self.root)
    }
}

/// Validate a `[start, start + max_locations)` window against the published
/// watermark. Returns the exclusive end bound clamped to the watermark's
/// available count (watermark + 1).
pub(crate) fn resolve_range_bounds<F: Family>(
    watermark: Location<F>,
    start_location: Location<F>,
    max_locations: u32,
) -> Result<Location<F>, crate::QmdbError> {
    if max_locations == 0 {
        return Err(crate::QmdbError::InvalidRangeLength);
    }
    let count = watermark
        .checked_add(1)
        .ok_or_else(|| crate::QmdbError::CorruptData("watermark overflow".to_string()))?;
    if start_location >= count {
        return Err(crate::QmdbError::RangeStartOutOfBounds {
            start: start_location.as_u64(),
            count: count.as_u64(),
        });
    }
    Ok(start_location
        .saturating_add(max_locations as u64)
        .min(count))
}

/// Build and self-verify a `RawBatchMultiProof` over the given operations,
/// sourcing Merkle nodes from `storage` and using the caller-supplied `root`.
pub(crate) async fn build_batch_multi_proof<F, H, S>(
    storage: &S,
    watermark: Location<F>,
    root: H::Digest,
    inactive_peaks: usize,
    operations: Vec<(Location<F>, Vec<u8>)>,
) -> Result<RawBatchMultiProof<H::Digest, F>, crate::QmdbError>
where
    F: Graftable,
    H: Hasher,
    S: MerkleStorage<F, Digest = H::Digest>,
{
    if operations.is_empty() {
        return Err(crate::QmdbError::EmptyProofRequest);
    }
    let locations: Vec<Location<F>> = operations.iter().map(|(loc, _)| *loc).collect();
    let hasher = commonware_storage::qmdb::hasher::<H>();
    let proof = merkle::verification::multi_proof(
        storage,
        inactive_peaks,
        hasher.root_bagging(),
        &locations,
    )
    .await
    .map_err(crate::error::merkle_error)?;
    let raw = RawBatchMultiProof {
        watermark,
        root,
        ops_root_witness: None,
        proof,
        operations,
    };
    if !raw.verify::<H>() {
        return Err(crate::QmdbError::ProofVerification {
            kind: crate::ProofKind::BatchMulti,
        });
    }
    Ok(raw)
}

/// Build and self-verify an `OperationRangeCheckpoint` over the given
/// contiguous span, sourcing Merkle nodes from `storage` and using the
/// caller-supplied `root` and pre-loaded `encoded_operations`.
pub(crate) async fn build_operation_range_checkpoint<F, H, S>(
    storage: &S,
    watermark: Location<F>,
    start_location: Location<F>,
    end_location_exclusive: Location<F>,
    root: H::Digest,
    inactive_peaks: usize,
    encoded_operations: Vec<Vec<u8>>,
) -> Result<OperationRangeCheckpoint<H::Digest, F>, crate::QmdbError>
where
    F: Graftable,
    H: Hasher,
    S: MerkleStorage<F, Digest = H::Digest>,
{
    let hasher = commonware_storage::qmdb::hasher::<H>();
    let proof = merkle::verification::range_proof(
        &hasher,
        storage,
        start_location..end_location_exclusive,
        inactive_peaks,
    )
    .await
    .map_err(crate::error::merkle_error)?;
    let pinned_nodes = if start_location == Location::new(0) {
        Vec::new()
    } else {
        futures::future::try_join_all(F::nodes_to_pin(start_location).map(|position| async move {
            storage
                .get_node(position)
                .await
                .map_err(crate::error::merkle_error)?
                .ok_or_else(|| {
                    crate::QmdbError::CommonwareMerkle(format!(
                        "missing pinned node at position {position}"
                    ))
                })
        }))
        .await?
    };
    let checkpoint = OperationRangeCheckpoint {
        watermark,
        root,
        ops_root_witness: None,
        start_location,
        pinned_nodes,
        proof,
        encoded_operations,
    };
    if !checkpoint.verify::<H>() {
        return Err(crate::QmdbError::ProofVerification {
            kind: crate::ProofKind::RangeCheckpoint,
        });
    }
    Ok(checkpoint)
}

/// Current proof for one active key's update operation.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct RawKeyValueProof<D: Digest, Op, const N: usize, F: Graftable> {
    pub watermark: Location<F>,
    pub root: D,
    pub proof: OperationProof<F, D, N>,
    pub operation: Op,
}

pub(crate) fn verify_ordered_exclusion_proof<F, H, K, E, const N: usize>(
    key: &K,
    proof: &ExclusionProof<F, K, E, H::Digest, N>,
    root: &H::Digest,
) -> bool
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    E: ValueEncoding,
    ordered::Operation<F, K, E>: Codec,
{
    proof.verify::<H>(key, root)
}

impl<D: Digest, Op, const N: usize, F: Graftable> RawKeyValueProof<D, Op, N, F>
where
    Op: Codec + Clone + Operation<F>,
{
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        self.operation.is_update()
            && self
                .proof
                .verify::<H, _>(self.operation.clone(), &self.root)
    }
}

/// Current ordered key-exclusion proof payload.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct RawKeyExclusionProof<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
    F: Graftable,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> {
    pub watermark: Location<F>,
    pub root: D,
    pub requested_key: K,
    pub proof: ExclusionProof<F, K, E, D, N>,
}

impl<
        D: Digest,
        K: QmdbKey + Codec,
        V: Codec + Clone + Send + Sync,
        const N: usize,
        F: Graftable,
        E: ValueEncoding<Value = V>,
    > RawKeyExclusionProof<D, K, V, N, F, E>
where
    ordered::Operation<F, K, E>: Codec + Clone,
{
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        verify_ordered_exclusion_proof::<F, H, K, E, N>(
            &self.requested_key,
            &self.proof,
            &self.root,
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub enum RawKeyLookupProof<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
    F: Graftable,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> {
    Hit(RawKeyValueProof<D, ordered::Operation<F, K, E>, N, F>),
    Miss(RawKeyExclusionProof<D, K, V, N, F, E>),
}

#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct RawKeyRangeProof<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
    F: Graftable,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> {
    pub watermark: Location<F>,
    pub entries: Vec<RawKeyValueProof<D, ordered::Operation<F, K, E>, N, F>>,
    pub start_proof: Option<RawKeyExclusionProof<D, K, V, N, F, E>>,
}

// `Verified*` types below all share one invariant: the Merkle proof has already
// been checked against the store's root and the proof blob has been dropped.
// Callers work with the plain payload fields.

/// Contiguous range of operations verified against the store's root. Shared
/// across ordered, unordered, immutable, and keyless variants.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedOperationRange<D: Digest, Op, F: Family> {
    pub root: D,
    pub start_location: Location<F>,
    pub operations: Vec<Op>,
}

/// Set of (location, operation) pairs verified as a multi-proof.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedMultiOperations<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    F: Family,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> {
    pub root: D,
    pub operations: Vec<(Location<F>, ordered::Operation<F, K, E>)>,
}

/// A single key's `Update` operation verified against the current-state root.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedKeyValue<D: Digest, Op, F: Family> {
    pub root: D,
    pub location: Location<F>,
    pub operation: Op,
}

/// A verified current lookup result for one requested key.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub enum VerifiedKeyLookup<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    F: Family,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> {
    Hit(VerifiedKeyValue<D, ordered::Operation<F, K, E>, F>),
    Miss { key: Bytes },
}

/// A verified ordered current key range.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedKeyRange<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    F: Family,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> {
    pub entries: Vec<VerifiedKeyValue<D, ordered::Operation<F, K, E>, F>>,
    pub next_start_key: Option<Bytes>,
}

/// Contiguous range of operations plus bitmap chunks verified against the
/// current-state root.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedCurrentRange<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
    F: Family,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> {
    pub root: D,
    pub start_location: Location<F>,
    pub operations: Vec<ordered::Operation<F, K, E>>,
    pub chunks: Vec<[u8; N]>,
}

#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct CurrentOperationRangeProofResult<D: Digest, Op, const N: usize, F: Graftable> {
    pub watermark: Location<F>,
    pub root: D,
    pub start_location: Location<F>,
    pub proof: RangeProof<F, D>,
    pub operations: Vec<Op>,
    pub chunks: Vec<[u8; N]>,
}

impl<D: Digest, Op, const N: usize, F: Graftable> CurrentOperationRangeProofResult<D, Op, N, F>
where
    Op: Codec,
{
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        self.proof.verify::<H, _, N>(
            self.start_location,
            &self.operations,
            &self.chunks,
            &self.root,
        )
    }
}
