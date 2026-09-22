//! Authenticated range preparation and contiguous-prefix publication.
//!
//! The in-memory Merkle frontier is only a preparation cache. Every production
//! upload is authenticated against the finalized block's independently trusted
//! root before any rows are staged. Store watermarks advance only over persisted
//! ranges, or ranges included atomically with that watermark.

use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Sequential;
use commonware_storage::merkle::{Family, Graftable, Location, mem::Mem};
use exoware_qmdb::{
    AuthenticatedOperationRange, OperationRangeCheckpoint, QmdbError, UploadOperation,
    prepare_authenticated_range, stage_authenticated_range, stage_watermark,
};
use exoware_sdk::{PrefixedStoreClient, StoreWriteBatch};
use std::{collections::BTreeMap, marker::PhantomData};
use tokio::sync::Mutex;

type Stage = Box<
    dyn FnOnce(&PrefixedStoreClient, &mut StoreWriteBatch) -> Result<(), QmdbError> + Send + Sync,
>;

pub(super) struct PreparedUpload<F: Family> {
    start: Location<F>,
    end: Location<F>,
    stage: Option<Stage>,
}
impl<F: Family> PreparedUpload<F> {
    pub(super) fn latest_location(&self) -> Location<F> {
        self.end - 1
    }
}

pub(super) struct PreparedWatermark<F: Family> {
    pub(super) latest_location: Location<F>,
}
pub(super) struct Receipt<F: Family> {
    pub(super) latest_location: Location<F>,
}

pub(super) struct WriterState<D: Digest, F: Family> {
    merkle: Mem<F, D>,
    published: Option<Location<F>>,
}
impl<D: Digest, F: Graftable> WriterState<D, F> {
    pub(super) fn empty() -> Self {
        Self {
            merkle: Mem::default(),
            published: None,
        }
    }
    pub(super) fn from_checkpoint<H: Hasher<Digest = D>>(
        checkpoint: &OperationRangeCheckpoint<D, F>,
    ) -> Result<Self, QmdbError> {
        let peaks = checkpoint.reconstruct_peaks::<H>()?;
        let end = checkpoint.proof.leaves;
        let pins = F::nodes_to_pin(end)
            .map(|pos| {
                peaks
                    .iter()
                    .find(|(p, _, _)| *p == pos)
                    .map(|(_, _, d)| *d)
                    .ok_or_else(|| {
                        QmdbError::CorruptData("checkpoint is missing a frontier node".into())
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let merkle = Mem::from_components(Vec::new(), end, pins).map_err(merkle_error)?;
        Ok(Self {
            merkle,
            published: Some(checkpoint.watermark),
        })
    }
}

struct Pending<F: Family> {
    end: Location<F>,
    persisted: bool,
}
struct State<D: Digest, F: Family> {
    merkle: Mem<F, D>,
    published: Option<Location<F>>,
    pending: BTreeMap<Location<F>, Pending<F>>,
}
impl<D: Digest, F: Family> State<D, F> {
    fn contiguous_end(&self, atomic: &[PreparedUpload<F>]) -> Location<F> {
        let mut end = self.published.map_or(Location::new(0), |p| p + 1);
        while let Some(pending) = self.pending.get(&end) {
            if !pending.persisted
                && !atomic
                    .iter()
                    .any(|upload| upload.start == end && upload.end == pending.end)
            {
                break;
            }
            end = pending.end;
        }
        end
    }
}

pub(super) struct Writer<F: Family, H: Hasher, Op> {
    client: PrefixedStoreClient,
    state: Mutex<State<H::Digest, F>>,
    _operation: PhantomData<fn() -> Op>,
}
impl<F: Graftable, H: Hasher, Op: UploadOperation<F>> Writer<F, H, Op> {
    pub(super) fn new(client: PrefixedStoreClient, state: WriterState<H::Digest, F>) -> Self {
        Self {
            client,
            state: Mutex::new(State {
                merkle: state.merkle,
                published: state.published,
                pending: BTreeMap::new(),
            }),
            _operation: PhantomData,
        }
    }
    #[cfg(test)]
    pub(super) fn fresh(client: PrefixedStoreClient) -> Self {
        Self::new(client, WriterState::empty())
    }
    pub(super) async fn latest_published_watermark(&self) -> Option<Location<F>> {
        self.state.lock().await.published
    }

    pub(super) async fn prepare_authenticated_upload(
        &self,
        operations: &[Op],
        expected_root: &H::Digest,
    ) -> Result<PreparedUpload<F>, QmdbError>
    where
        Op::Cfg: Default,
    {
        self.prepare(operations, Some(*expected_root)).await
    }
    #[cfg(test)]
    pub(super) async fn prepare_upload(
        &self,
        operations: &[Op],
    ) -> Result<PreparedUpload<F>, QmdbError>
    where
        Op::Cfg: Default,
    {
        self.prepare(operations, None).await
    }

    async fn prepare(
        &self,
        operations: &[Op],
        expected_root: Option<H::Digest>,
    ) -> Result<PreparedUpload<F>, QmdbError>
    where
        Op::Cfg: Default,
    {
        let floor = operations
            .last()
            .ok_or(QmdbError::EmptyBatch)?
            .has_floor()
            .ok_or_else(|| QmdbError::CorruptData("upload does not end at a commit".into()))?;
        let mut state = self.state.lock().await;
        let start = state.merkle.leaves();
        let pins = F::nodes_to_pin(start)
            .map(|pos| {
                state
                    .merkle
                    .get_node(pos)
                    .ok_or_else(|| QmdbError::CorruptData("missing cached frontier node".into()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let encoded: Vec<Vec<u8>> = operations.iter().map(|op| op.encode().to_vec()).collect();
        let hasher = commonware_storage::qmdb::hasher::<H>();
        let mut batch = state.merkle.new_batch();
        for operation in &encoded {
            batch = batch.add(&hasher, operation);
        }
        let batch = batch.merkleize(&state.merkle, &hasher);
        let end = batch.leaves();
        let inactive = F::inactive_peaks(end, floor);
        let proof = batch
            .range_proof(&state.merkle, &hasher, start..end, inactive)
            .map_err(merkle_error)?;
        let expected = match expected_root {
            Some(root) => root,
            None => batch
                .root(&state.merkle, &hasher, inactive)
                .map_err(merkle_error)?,
        };
        let prepared = prepare_authenticated_range::<F, H, Op, _>(
            &AuthenticatedOperationRange {
                start_location: start,
                proof: &proof,
                pinned_nodes: &pins,
                encoded_operations: &encoded,
            },
            &expected,
            &Op::Cfg::default(),
            &Sequential,
        )?;
        state.merkle.apply_batch(&batch).map_err(merkle_error)?;
        state.merkle.prune_all();
        assert!(
            state
                .pending
                .insert(
                    start,
                    Pending {
                        end,
                        persisted: false
                    }
                )
                .is_none()
        );
        Ok(PreparedUpload {
            start,
            end,
            stage: Some(Box::new(move |client, batch| {
                stage_authenticated_range(client, prepared, batch)
            })),
        })
    }
    pub(super) fn stage_upload(
        &self,
        upload: &mut PreparedUpload<F>,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), QmdbError> {
        upload
            .stage
            .take()
            .expect("upload must be staged exactly once")(&self.client, batch)
    }
    pub(super) async fn mark_upload_persisted(
        &self,
        upload: PreparedUpload<F>,
        _seq: u64,
    ) -> Receipt<F> {
        let mut state = self.state.lock().await;
        assert!(upload.stage.is_none(), "cannot persist an unstaged upload");
        let pending = state
            .pending
            .get_mut(&upload.start)
            .expect("prepared upload exists");
        assert_eq!(pending.end, upload.end);
        pending.persisted = true;
        Receipt {
            latest_location: upload.latest_location(),
        }
    }
    pub(super) async fn prepare_flush_for_uploads(
        &self,
        uploads: &[PreparedUpload<F>],
    ) -> Result<Option<PreparedWatermark<F>>, QmdbError> {
        let state = self.state.lock().await;
        let end = state.contiguous_end(uploads);
        Ok(
            (end > state.published.map_or(Location::new(0), |p| p + 1)).then(|| {
                PreparedWatermark {
                    latest_location: end - 1,
                }
            }),
        )
    }
    pub(super) async fn prepare_flush(&self) -> Result<Option<PreparedWatermark<F>>, QmdbError> {
        self.prepare_flush_for_uploads(&[]).await
    }
    pub(super) fn stage_flush(
        &self,
        watermark: &PreparedWatermark<F>,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), QmdbError> {
        stage_watermark(&self.client, watermark.latest_location, batch)
    }
    pub(super) async fn mark_flush_persisted(&self, watermark: PreparedWatermark<F>, _seq: u64) {
        let mut state = self.state.lock().await;
        assert!(
            watermark.latest_location < state.contiguous_end(&[]),
            "watermark cannot cross a persistence hole"
        );
        state.published = Some(state.published.map_or(watermark.latest_location, |old| {
            old.max(watermark.latest_location)
        }));
        let end = state.published.unwrap() + 1;
        state.pending.retain(|_, pending| pending.end > end);
    }
}
fn merkle_error(error: impl std::fmt::Display) -> QmdbError {
    QmdbError::CommonwareMerkle(error.to_string())
}
