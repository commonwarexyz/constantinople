#![allow(clippy::type_complexity)]

//! Store-backed bridge for Commonware authenticated storage proofs.
//!
//! The crate currently supports multiple Commonware authenticated backends:
//! - ordered QMDB (`qmdb::any::ordered` and `qmdb::current::ordered`)
//! - unordered QMDB (`qmdb::any::unordered` and current hit proofs when callers
//!   upload current-boundary rows)
//! - immutable (`qmdb::immutable`)
//! - keyless (`qmdb::keyless`)
//!
//! Callers provide authenticated Commonware operation ranges and stage their Store rows
//! without constructing an uploader or reading remote state. An application-owned durable
//! queue publishes the watermark after the whole contiguous prefix is durable.
//!
//! Uploads may still happen concurrently and out of order. Current batch-boundary
//! state may also be uploaded ahead of publication. Only watermark publication is
//! monotonic: publishing watermark `W` means the whole contiguous prefix
//! `[0, W]` is available and may now be trusted by readers.
//!
//! Readers fence historical queries against that low watermark. Historical proofs
//! use the global ops Merkle nodes stored by `Position`.
//!
//! Current QMDB proofs use versioned current-state deltas:
//! - bitmap chunk rows
//! - grafted-node rows
//!
//! Those rows are versioned by uploaded batch boundary `Location`, not by the
//! final published watermark. That is what preserves lower-boundary current
//! proofs below a later published low watermark.

mod auth;
mod boundary;
pub(crate) mod codec;
#[cfg(feature = "test-utils")]
pub use codec::{CHUNK_FAMILY, NODE_FAMILY};
mod connect;
mod connect_client;
mod core;
pub mod error;
pub mod proof;
pub mod proto;
pub mod prune;
mod request;
pub(crate) mod storage;

mod authenticated_range;
mod immutable;
mod keyless;
mod ordered;
mod subscription;
mod unordered;

pub use authenticated_range::{
    prepare_authenticated_range, stage_authenticated_range, stage_watermark,
    AuthenticatedOperationRange, PreparedAuthenticatedRange, UploadOperation,
};
pub use error::{ProofKind, QmdbError};
pub use immutable::ImmutableClient;
pub use keyless::KeylessClient;
pub use ordered::OrderedClient;
pub use proof::{
    CurrentOperationRangeProofResult, OperationRangeCheckpoint, RawKeyValueProof, RawMultiProof,
    VerifiedCurrentRange, VerifiedKeyLookup, VerifiedKeyRange, VerifiedKeyValue,
    VerifiedMultiOperations, VerifiedOperationRange,
};
pub use unordered::UnorderedClient;

pub use boundary::recover_boundary_state;
pub use connect::{
    immutable_operation_log_connect_stack, keyless_operation_log_connect_stack,
    ordered_connect_stack, ordered_operation_log_connect_stack, unordered_connect_stack,
    unordered_operation_log_connect_stack, OrderedConnect, UnorderedConnect,
};
pub use connect_client::{
    CurrentOperationClient, CurrentOperationRangeProof, OperationLogClient, OperationLogRangeProof,
    OperationLogSubscribeProof, OperationLogSubscription, OrderedConnectClient,
    UnorderedConnectClient,
};

use commonware_cryptography::Digest;
use commonware_storage::merkle::{self, Family, Graftable, Location};
use commonware_storage::qmdb::current::proof::OpsRootWitness;

/// Maximum encoded operation size for QMDB key and value payloads (u16 length on the wire).
pub const MAX_OPERATION_SIZE: usize = u16::MAX as usize;

/// Historical value resolved for one logical key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionedValue<K, V, F: Family> {
    pub key: K,
    pub location: Location<F>,
    pub value: Option<V>,
}

/// Current-state rows for one uploaded current batch boundary.
///
/// Current QMDB uploads carry more than the historical op log: each published
/// batch boundary also stores the current-state root, op-root witness, and the
/// subset of bitmap chunks and grafted nodes that changed at that boundary.
/// This struct is that versioned delta payload.
///
/// Callers typically obtain it from [`recover_boundary_state`], using a local
/// Commonware current DB, then attach it with
/// [`PreparedAuthenticatedRange::with_current_boundary`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentBoundaryState<D: Digest, const N: usize, F: Graftable> {
    /// Canonical current-state root at this batch boundary.
    pub root: D,
    /// Number of complete, all-zero chunks discarded from the start of the source bitmap.
    /// Source pruning preserves the root. This count does not delete backend rows.
    pub pruned_chunks: u64,
    /// Proof that the raw operation-log root is committed by `root`.
    pub ops_root_witness: OpsRootWitness<F, D>,
    /// Changed bitmap chunks keyed by chunk index.
    pub chunks: Vec<(u64, [u8; N])>,
    /// Changed grafted digests keyed by ops-space Merkle position.
    pub grafted_nodes: Vec<(merkle::Position<F>, D)>,
}

// The native crate owns tests for request constraints shared with the WASM verifier.
#[cfg(test)]
mod tests {
    use crate::request::{span_contains, validate_key_range, InvalidWindow, OperationWindow};

    #[test]
    fn test_spans_wrap_past_the_greatest_key() {
        assert!(span_contains(&2, &6, &2));
        assert!(span_contains(&2, &6, &5));
        assert!(!span_contains(&2, &6, &6));
        assert!(!span_contains(&2, &6, &1));
        assert!(span_contains(&6, &2, &7));
        assert!(span_contains(&6, &2, &1));
        assert!(!span_contains(&6, &2, &2));
        assert!(!span_contains(&6, &2, &4));
        assert!(span_contains(&3, &3, &9));
    }

    #[test]
    fn test_operation_windows_preserve_large_absolute_positions() {
        for start in [u32::MAX as u64 - 1, u32::MAX as u64 + 1, (1u64 << 53) + 1] {
            let window = OperationWindow::new(start + 2, start, 10).unwrap();
            assert!(window.validate(start, 3, start + 3).is_ok());
            assert!(window.validate(start + 1, 3, start + 3).is_err());
            assert!(window.validate(start, 2, start + 3).is_err());
            assert!(window.validate(start, 3, start + 4).is_err());
        }
        assert!(matches!(
            OperationWindow::new(u64::MAX, 0, 1),
            Err(InvalidWindow::TipOverflow)
        ));
        assert!(matches!(
            OperationWindow::new(10, 11, 1),
            Err(InvalidWindow::StartOutOfBounds {
                start: 11,
                count: 11
            })
        ));
        assert!(matches!(
            OperationWindow::new(10, 0, 0),
            Err(InvalidWindow::ZeroMaximum)
        ));
    }

    #[test]
    fn test_linear_key_ranges_match_sorted_map_pages() {
        let keys = [2, 4, 6];
        for start in 0..9 {
            for end in (start + 1)..10 {
                for limit in 1..5 {
                    let matching = keys
                        .iter()
                        .filter(|key| **key >= start && **key < end)
                        .collect::<Vec<_>>();
                    let selected = matching
                        .iter()
                        .take(limit as usize)
                        .map(|key| {
                            let index =
                                keys.iter().position(|candidate| candidate == *key).unwrap();
                            (*key, &keys[(index + 1) % keys.len()])
                        })
                        .collect::<Vec<_>>();
                    let successor = keys.iter().find(|key| **key > start).or(keys.first());
                    let next = matching.get(limit as usize).copied();
                    assert_eq!(
                        validate_key_range(&start, Some(&end), limit, &selected, successor)
                            .unwrap(),
                        next,
                    );
                }
            }
        }
    }

    #[test]
    fn test_key_ranges_reject_wraparound_and_incomplete_pages() {
        assert!(validate_key_range(&1, Some(&7), 3, &[], Some(&2)).is_err());
        assert!(validate_key_range(&1, Some(&7), 3, &[(&2, &4)], Some(&2)).is_err());
        assert!(validate_key_range(&4, None, 3, &[(&4, &6), (&6, &2), (&2, &4)], None).is_err());
        assert!(validate_key_range(&1, Some(&7), 1, &[(&2, &4), (&4, &6)], Some(&2)).is_err());
        // An empty-database start proof cannot precede entries
        assert!(validate_key_range(&1, Some(&7), 3, &[(&2, &4)], None).is_err());
        // Entries must chain through their authenticated successors
        assert!(validate_key_range(&1, Some(&7), 3, &[(&2, &4), (&6, &2)], Some(&2)).is_err());
        assert!(validate_key_range(&1, Some(&7), 0, &[], Some(&2)).is_err());
        assert!(validate_key_range(&7, Some(&7), 3, &[], None).is_err());
    }

    #[test]
    fn test_single_key_databases_accept_self_successors() {
        assert_eq!(
            validate_key_range(&0, None, 5, &[(&3, &3)], Some(&3)),
            Ok(None)
        );
        assert_eq!(validate_key_range(&3, None, 5, &[(&3, &3)], None), Ok(None));
        // A start above the only key wraps to it, so an empty page is complete
        assert_eq!(validate_key_range(&4, None, 5, &[], Some(&3)), Ok(None));
    }
}
