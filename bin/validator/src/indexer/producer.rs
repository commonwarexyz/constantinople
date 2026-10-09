//! Captures finalized artifacts before their source state can be pruned.

use super::{
    DURATION_BUCKETS, EngineCapturedUpload, EngineMarshal, FinalizedPayloads,
    queue::{FinalizedQueueRecord, FinalizedQueueWriter, LatestCaptureReceipt},
    traces::CaptureTraces,
};
use commonware_codec::Encode;
use commonware_cryptography::{ed25519::PublicKey, sha256::Sha256};
use commonware_runtime::{
    Metrics,
    telemetry::metrics::{Histogram, MetricsExt as _},
};
use constantinople_application::consensus::FinalizedArtifacts;
use constantinople_engine::types::EngineBlock;
use std::{
    sync::{Arc, OnceLock},
    time::Instant,
};
use tokio::sync::Mutex;
use tracing::{Instrument as _, Span, info, info_span};

const INITIAL_QMDB_END: u64 = 1;

/// Stage timings for the finalized hook, which runs on the stateful actor's
/// critical path. Lock wait on the shared queue is `record_enqueue` minus the
/// queue journal's own append and commit timers.
#[derive(Clone)]
pub(super) struct FinalizedCaptureMetrics {
    finalization_lookup: Histogram,
    construct: Histogram,
    record_enqueue: Histogram,
    total: Histogram,
}

impl FinalizedCaptureMetrics {
    pub(super) fn new(context: &impl Metrics) -> Self {
        Self {
            finalization_lookup: context.histogram(
                "finalization_lookup_duration",
                "Marshal finalization lookup time in the finalized hook (s)",
                DURATION_BUCKETS,
            ),
            construct: context.histogram(
                "construct_duration",
                "Queue payload construction and encoding time in the finalized hook (s)",
                DURATION_BUCKETS,
            ),
            record_enqueue: context.histogram(
                "record_enqueue_duration",
                "Finalized queue record enqueue time including lock wait (s)",
                DURATION_BUCKETS,
            ),
            total: context.histogram(
                "duration",
                "Finalized hook time from artifact handoff to durable capture (s)",
                DURATION_BUCKETS,
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CapturePosition {
    Captured,
    Next,
}

#[derive(Clone)]
pub(super) struct FinalizedUploadProducer {
    pub(super) writer: FinalizedQueueWriter,
    pub(super) payloads: FinalizedPayloads,
    pub(super) receipt: Arc<Mutex<Option<LatestCaptureReceipt>>>,
    pub(super) capture_metrics: FinalizedCaptureMetrics,
    pub(super) marshal: Arc<OnceLock<EngineMarshal>>,
    pub(super) traces: CaptureTraces,
}

impl FinalizedUploadProducer {
    pub(super) async fn enqueue(
        self,
        block: &EngineBlock<Sha256, PublicKey>,
        artifacts: FinalizedArtifacts<Sha256>,
        trace: Span,
    ) {
        let height = block.header.height;
        let mut current = self
            .receipt
            .lock()
            .instrument(info_span!("indexer.capture.receipt_lock", height))
            .await;
        match capture_position(*current, height) {
            CapturePosition::Captured => {
                trace.record("outcome", "already_captured");
                if let Some(receipt) = *current
                    && receipt.height == height
                {
                    assert!(
                        receipt.matches_block(block),
                        "finalized replay conflicts with the durable capture receipt"
                    );
                }
                return;
            }
            CapturePosition::Next => {}
        }

        info_span!("indexer.capture.validate", height)
            .in_scope(|| validate_next_capture(*current, &artifacts));
        let started = Instant::now();
        let marshal = self
            .marshal
            .get()
            .expect("marshal mailbox must be installed before engine start");
        let finalization = marshal
            .get_finalization(commonware_consensus::types::Height::new(height))
            .instrument(info_span!("indexer.capture.finalization_lookup", height))
            .await;
        self.capture_metrics
            .finalization_lookup
            .observe(started.elapsed().as_secs_f64());

        // Construction is synchronous, so the span guard never crosses an await.
        let construct_started = Instant::now();
        let (receipt, encoded) = {
            let _span = info_span!("indexer.capture.construct", height).entered();
            let upload = info_span!("indexer.capture.artifacts", height)
                .in_scope(|| {
                    EngineCapturedUpload::from_finalized_artifacts(
                        block,
                        finalization,
                        current_time_micros(),
                        artifacts,
                    )
                })
                .expect("captured finalized artifacts must form a valid queue entry");
            let encoded = info_span!("indexer.capture.encode", height).in_scope(|| upload.encode());
            (LatestCaptureReceipt::from_upload(&upload), encoded)
        };
        self.capture_metrics
            .construct
            .observe(construct_started.elapsed().as_secs_f64());

        // The payload is durable before its record commits, so a committed
        // record never points at bytes a crash could lose.
        let payload = self
            .payloads
            .write(height, encoded)
            .instrument(info_span!("indexer.capture.payload_write", height))
            .await
            .unwrap_or_else(|error| {
                panic!("failed to persist finalized index payload at height {height}. {error}")
            });
        let record = FinalizedQueueRecord { receipt, payload };

        trace.record("payload_bytes", payload.len);
        self.traces.register(height, trace.clone());
        let enqueue_started = Instant::now();
        let position = self
            .writer
            .enqueue(record)
            .instrument(info_span!("indexer.capture.record_enqueue", height))
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "failed to durably enqueue finalized index upload at height {height}. {error}"
                )
            });
        self.capture_metrics
            .record_enqueue
            .observe(enqueue_started.elapsed().as_secs_f64());
        trace.record("position", position);

        // The queue tail is the receipt while any record exists. The consumer
        // persists a separate receipt only when a section prunes, avoiding a
        // per-block receipt sync in this hook.
        *current = Some(receipt);
        self.capture_metrics
            .total
            .observe(started.elapsed().as_secs_f64());
        info!(
            height,
            position,
            state_end = receipt.state_end,
            transaction_end = receipt.transaction_end,
            "queued finalized index upload"
        );
    }
}

fn capture_position(current: Option<LatestCaptureReceipt>, height: u64) -> CapturePosition {
    assert_ne!(height, 0, "genesis must not invoke finalized capture");

    let Some(receipt) = current else {
        assert_eq!(height, 1, "first finalized capture must have height one");
        return CapturePosition::Next;
    };
    if height <= receipt.height {
        return CapturePosition::Captured;
    }
    assert_eq!(
        height,
        receipt
            .height
            .checked_add(1)
            .expect("finalized capture height must not overflow"),
        "finalized capture height must advance without gaps"
    );
    CapturePosition::Next
}

fn validate_next_capture(
    current: Option<LatestCaptureReceipt>,
    artifacts: &FinalizedArtifacts<Sha256>,
) {
    let (expected_state_start, expected_transaction_start) = current
        .map_or((INITIAL_QMDB_END, INITIAL_QMDB_END), |receipt| {
            (receipt.state_end, receipt.transaction_end)
        });
    assert_eq!(artifacts.state.start.as_u64(), expected_state_start);
    assert_eq!(
        artifacts.transactions.start.as_u64(),
        expected_transaction_start
    );
}

fn current_time_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_micros()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{super::queue::capture_receipt, CapturePosition, capture_position};

    #[test]
    fn capture_receipt_covers_older_replays() {
        let receipt = capture_receipt(7, 11, 13);

        assert_eq!(capture_position(None, 1), CapturePosition::Next);
        assert_eq!(
            capture_position(Some(receipt), 6),
            CapturePosition::Captured
        );
        assert_eq!(
            capture_position(Some(receipt), 7),
            CapturePosition::Captured
        );
        assert_eq!(capture_position(Some(receipt), 8), CapturePosition::Next);
    }

    #[test]
    #[should_panic(expected = "genesis must not invoke finalized capture")]
    fn capture_receipt_rejects_genesis() {
        let _ = capture_position(None, 0);
    }

    #[test]
    #[should_panic(expected = "finalized capture height must advance without gaps")]
    fn capture_receipt_rejects_future_gap() {
        let _ = capture_position(Some(capture_receipt(7, 11, 13)), 9);
    }
}
