//! Retains queued payloads until both remote durability and local pruning permit deletion.

use super::{
    DURATION_BUCKETS, EngineCertReporter, EngineQueuedUpload, FinalizedPayloads, LazyPublisher,
    budget::{UploadBudget, UploadCharge, UploadReservation},
    payloads::PayloadDescriptor,
    queue::{
        FinalizedQueueReader, FinalizedQueueRecord, FinalizedQueueWriter, FinalizedReceiptStore,
        LatestCaptureReceipt, pruned_record_boundary,
    },
    traces::CaptureTraces,
};
use bytes::Bytes;
use commonware_codec::Decode as _;
use commonware_runtime::{
    Clock as _, Metrics,
    telemetry::metrics::{Histogram, MetricsExt as _},
    tokio::Context as RuntimeContext,
};
use commonware_storage::queue;
use constantinople_indexer::publisher::{
    certificate::CertificateUploaderStopped,
    qmdb::{PublishError, QueuedFinalizedUploadCfg},
};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::oneshot, task::JoinSet};
use tracing::{Instrument as _, Span, info_span, warn};

#[derive(Clone)]
pub(super) struct FinalizedUploadMetrics {
    queue_read: Histogram,
    active_capacity_wait: Histogram,
    admission_wait: Histogram,
    decode_schedule_wait: Histogram,
    decode: Histogram,
    turn_wait: Histogram,
    receipt_sync: Histogram,
    queue_sync: Histogram,
}

impl FinalizedUploadMetrics {
    pub(super) fn new(context: &impl Metrics) -> Self {
        Self {
            queue_read: context.histogram(
                "queue_read_duration",
                "Finalized queue record read time (s)",
                DURATION_BUCKETS,
            ),
            active_capacity_wait: context.histogram(
                "active_capacity_wait_duration",
                "Consumer wait for an upload task while at the active limit (s)",
                DURATION_BUCKETS,
            ),
            admission_wait: context.histogram(
                "admission_wait_duration",
                "Time from queue record read to byte budget admission (s)",
                DURATION_BUCKETS,
            ),
            decode_schedule_wait: context.histogram(
                "decode_schedule_wait_duration",
                "Payload decode wait for a blocking worker (s)",
                DURATION_BUCKETS,
            ),
            decode: context.histogram(
                "decode_duration",
                "Payload decode wall time inside the blocking worker (s)",
                DURATION_BUCKETS,
            ),
            turn_wait: context.histogram(
                "turn_wait_duration",
                "Decoded upload wait for predecessor publisher admission (s)",
                DURATION_BUCKETS,
            ),
            receipt_sync: context.histogram(
                "receipt_sync_duration",
                "Capture receipt sync time before a section prune (s)",
                DURATION_BUCKETS,
            ),
            queue_sync: context.histogram(
                "queue_sync_duration",
                "Finalized queue sync and prune time per acknowledged section (s)",
                DURATION_BUCKETS,
            ),
        }
    }
}

pub(super) struct FinalizedUploadConsumer {
    pub(super) publisher: Arc<LazyPublisher>,
    pub(super) cert_reporter: EngineCertReporter,
    pub(super) writer: FinalizedQueueWriter,
    pub(super) reader: FinalizedQueueReader,
    pub(super) payloads: FinalizedPayloads,
    pub(super) receipt_store: FinalizedReceiptStore,
    pub(super) max_active: usize,
    pub(super) budget: UploadBudget,
    pub(super) metrics: FinalizedUploadMetrics,
    pub(super) payload_floor: u64,
    pub(super) traces: CaptureTraces,
    pub(super) replay_through: u64,
}

struct RetainedUpload {
    record: FinalizedQueueRecord,
    trace: Span,
    wait: Option<Span>,
}

struct PendingQueuedUpload {
    position: u64,
    record: FinalizedQueueRecord,
    charge: UploadCharge,
    admission_started: Instant,
    trace: Span,
    admission_span: Span,
}

impl PendingQueuedUpload {
    fn new(
        position: u64,
        record: FinalizedQueueRecord,
        budget: &UploadBudget,
        trace: Span,
    ) -> Self {
        let admission_span = info_span!(
            parent: &trace,
            "indexer.queue.admission_wait",
            height = record.height(),
            bytes = record.payload.len
        );
        Self {
            position,
            record,
            charge: budget.charge(record.payload.len),
            admission_started: Instant::now(),
            trace,
            admission_span,
        }
    }
}

impl FinalizedUploadConsumer {
    pub(super) async fn run(self, context: RuntimeContext) {
        let Self {
            publisher,
            cert_reporter,
            writer,
            mut reader,
            payloads,
            receipt_store,
            max_active,
            budget,
            metrics,
            mut payload_floor,
            traces,
            replay_through,
        } = self;
        let mut active = JoinSet::new();
        let mut retained_records: BTreeMap<u64, RetainedUpload> = BTreeMap::new();
        let mut waiting: Option<PendingQueuedUpload> = None;
        let mut admission_turn = None;

        loop {
            let can_read = waiting.is_none() && active.len() < max_active;

            // Reading without waiting first keeps idle time out of the read timer.
            let read = if can_read {
                try_read_finalized_queue_entry(&mut reader, &metrics).await
            } else {
                Ok(None)
            };
            let read = match read {
                Ok(None) => tokio::select! {
                    reservation = async {
                        budget
                            .reserve(waiting.as_ref().expect("waiting upload exists").charge)
                            .await
                    }, if waiting.is_some() && active.len() < max_active => {
                        let pending = waiting.take().expect("waiting upload exists");
                        active.spawn(queued_upload(
                            publisher.clone(),
                            cert_reporter.clone(),
                            &payloads,
                            &metrics,
                            &mut admission_turn,
                            pending,
                            reservation,
                        ));
                        continue;
                    }
                    read = reader.recv(), if can_read => read,
                    result = next_completed_upload(&mut active, max_active, &metrics), if !active.is_empty() => {
                        let (position, height) = result;
                        reader.ack(position).unwrap_or_else(|error| {
                            panic!("failed to ack finalized index queue at height {height}. {error}")
                        });
                        let retained = retained_records
                            .get_mut(&position)
                            .expect("completed upload is retained");
                        retained.wait = Some(info_span!(
                            parent: &retained.trace,
                            "indexer.queue.prune_wait",
                            height
                        ));
                        prune_finalized_queue(
                            &reader,
                            &writer,
                            &payloads,
                            &receipt_store,
                            &metrics,
                            &mut retained_records,
                            &mut payload_floor,
                        )
                        .await;
                        continue;
                    }
                },
                read => read,
            };
            let (position, record) = match read {
                Ok(Some(item)) => item,
                Ok(None) => panic!("finalized queue writer was lost"),
                Err(error) => {
                    warn!(error = %error, "failed to read finalized index queue, retrying");
                    context.sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let height = record.height();
            let trace = traces.take(height, height <= replay_through);
            trace.record("position", position);
            trace.record("payload_bytes", record.payload.len);
            let pending = PendingQueuedUpload::new(position, record, &budget, trace.clone());
            retained_records.insert(
                position,
                RetainedUpload {
                    record,
                    trace,
                    wait: None,
                },
            );
            match budget.try_reserve(pending.charge) {
                Some(reservation) => {
                    active.spawn(queued_upload(
                        publisher.clone(),
                        cert_reporter.clone(),
                        &payloads,
                        &metrics,
                        &mut admission_turn,
                        pending,
                        reservation,
                    ));
                }
                None => waiting = Some(pending),
            }
        }
    }
}

async fn next_completed_upload(
    active: &mut JoinSet<(u64, u64)>,
    max_active: usize,
    metrics: &FinalizedUploadMetrics,
) -> (u64, u64) {
    let capacity_wait_started = (active.len() >= max_active).then(Instant::now);
    let result = active.join_next().await;
    if let Some(started) = capacity_wait_started {
        metrics
            .active_capacity_wait
            .observe(started.elapsed().as_secs_f64());
    }
    result
        .expect("active upload set is not empty")
        .expect("finalized index upload task panicked")
}

async fn try_read_finalized_queue_entry(
    reader: &mut FinalizedQueueReader,
    metrics: &FinalizedUploadMetrics,
) -> Result<Option<(u64, FinalizedQueueRecord)>, queue::Error> {
    let started = Instant::now();
    let item = reader.try_recv().await?;
    if item.is_some() {
        metrics.queue_read.observe(started.elapsed().as_secs_f64());
    }
    Ok(item)
}

/// Persist the receipt, sync the queue, and delete payloads once a whole record
/// section is acknowledged.
///
/// A restart redelivers every record above the queue's pruning boundary, so
/// payloads outlive their acknowledgement until the section holding their
/// record prunes. The receipt for the last pruned record is synced first,
/// because a crash between a prune and its receipt would leave an empty queue
/// with no capture boundary. Syncing once per section rather than per
/// acknowledgement removes most consumer fsyncs.
async fn prune_finalized_queue(
    reader: &FinalizedQueueReader,
    writer: &FinalizedQueueWriter,
    payloads: &FinalizedPayloads,
    receipt_store: &FinalizedReceiptStore,
    metrics: &FinalizedUploadMetrics,
    retained: &mut BTreeMap<u64, RetainedUpload>,
    payload_floor: &mut u64,
) {
    let boundary = pruned_record_boundary(reader.ack_floor());
    if boundary <= *payload_floor {
        return;
    }
    let last_pruned = boundary
        .checked_sub(1)
        .expect("a pruning boundary above the payload floor is positive");
    let receipt = retained
        .get(&last_pruned)
        .expect("every acknowledged record was read by the consumer")
        .record
        .receipt;

    let first_height = *payload_floor + 1;
    let prune = info_span!(
        parent: None,
        "indexer.queue.prune",
        first_height,
        last_height = boundary,
        blocks = boundary - *payload_floor
    );
    for (_, entry) in retained.range(*payload_floor..boundary) {
        prune.follows_from(entry.trace.id());
    }
    let receipt_started = Instant::now();
    receipt_store
        .persist(receipt)
        .instrument(info_span!(
            parent: &prune,
            "indexer.queue.receipt_sync",
            height = receipt.height
        ))
        .await;
    metrics
        .receipt_sync
        .observe(receipt_started.elapsed().as_secs_f64());

    let sync_started = Instant::now();
    writer
        .sync()
        .instrument(info_span!(
            parent: &prune,
            "indexer.queue.sync",
            first_height,
            last_height = boundary
        ))
        .await
        .expect("failed to sync finalized index queue");
    metrics
        .queue_sync
        .observe(sync_started.elapsed().as_secs_f64());

    // Deletion is best effort. Startup removes any payload left behind.
    let remaining = retained.split_off(&boundary);
    for (
        position,
        RetainedUpload {
            record,
            trace,
            wait,
        },
    ) in std::mem::replace(retained, remaining)
    {
        drop(wait);
        let height = record.height();
        info_span!(parent: &trace, "indexer.queue.pruned", height, position)
            .follows_from(prune.id());
        match payloads
            .remove(height, record.payload.len)
            .instrument(info_span!(parent: &trace, "indexer.payload.remove", height))
            .await
        {
            Ok(()) => {
                trace.record("outcome", "deleted");
            }
            Err(error) => warn!(error = %error, height, "failed to remove finalized index payload"),
        }
    }
    *payload_floor = boundary;
}

/// Build the upload task for an admitted record.
///
/// Payload reads and decodes run concurrently across admitted uploads so the
/// consumer loop never waits on them. The publisher still needs heights in
/// queue order, so each task waits for its predecessor to finish admitting
/// before it admits its own block, then hands the turn to its successor.
fn queued_upload(
    publisher: Arc<LazyPublisher>,
    cert_reporter: EngineCertReporter,
    payloads: &FinalizedPayloads,
    metrics: &FinalizedUploadMetrics,
    admission_turn: &mut Option<oneshot::Receiver<()>>,
    pending: PendingQueuedUpload,
    reservation: UploadReservation,
) -> impl Future<Output = (u64, u64)> + Send + 'static {
    let PendingQueuedUpload {
        position,
        record,
        admission_started,
        trace,
        admission_span,
        ..
    } = pending;
    drop(admission_span);
    metrics
        .admission_wait
        .observe(admission_started.elapsed().as_secs_f64());
    let height = record.height();
    assert_eq!(
        height,
        position
            .checked_add(1)
            .expect("finalized queue position must not overflow")
    );
    let payloads = payloads.clone();
    let metrics = metrics.clone();
    let (admitted_tx, admitted_rx) = oneshot::channel();
    let turn = admission_turn.replace(admitted_rx);

    let upload_span = info_span!(parent: &trace, "indexer.upload", height, position);
    async move {
        let bytes = read_finalized_payload(&payloads, height, record.payload)
            .instrument(info_span!(
                "indexer.payload.load",
                height,
                bytes = record.payload.len
            ))
            .await;

        // Decoding is CPU work over hundreds of thousands of operations, so it
        // runs on the blocking pool instead of a runtime worker.
        let upload = decode_finalized_payload(height, bytes, &metrics).await;
        trace.record(
            "block_digest",
            tracing::field::display(upload.block().seal()),
        );
        assert_eq!(
            LatestCaptureReceipt::from_upload(&upload),
            record.receipt,
            "finalized index payload at height {height} does not match its record"
        );
        let block = Arc::new(upload.block().clone());
        let finalization = upload.finalization().cloned();

        wait_for_upload_turn(turn, &metrics)
            .instrument(info_span!("indexer.queue.admission_turn", height))
            .await;
        let engine_publisher = publisher
            .publisher()
            .instrument(info_span!("indexer.publisher.connect", height))
            .await;
        let mut completion = engine_publisher
            .enqueue_queued_finalized(upload)
            .await
            .unwrap_or_else(|error| {
                panic!("failed to start finalized index upload at height {height}. {error}")
            });
        let _ = admitted_tx.send(());

        let simplex_completion = cert_reporter
            .publish_finalized_block(block, finalization)
            .await
            .unwrap_or_else(|error| {
                panic!("failed to start finalized block upload at height {height}. {error}")
            });
        release_reservation_after_uploads(
            height,
            completion
                .persisted()
                .instrument(info_span!("indexer.upload.metadata_wait", height)),
            simplex_completion
                .wait()
                .instrument(info_span!("indexer.upload.simplex_wait", height)),
            reservation,
        )
        .await;
        completion
            .published()
            .instrument(info_span!("indexer.upload.publication_wait", height))
            .await
            .unwrap_or_else(|error| {
                panic!("finalized index publication failed at height {height}. {error}")
            });
        (position, height)
    }
    .instrument(upload_span)
}

async fn wait_for_upload_turn(
    turn: Option<oneshot::Receiver<()>>,
    metrics: &FinalizedUploadMetrics,
) {
    let started = Instant::now();
    if let Some(turn) = turn {
        turn.await
            .expect("earlier finalized index upload exited before admitting its block");
    }
    metrics.turn_wait.observe(started.elapsed().as_secs_f64());
}

/// Hold the admission reservation only until this block's own uploads are durable.
///
/// Publication of the contiguous prefix is ordered and can wait on earlier
/// blocks. Holding memory through it would let one slow block pin the budget
/// of everything admitted behind it. A failure in either upload panics as soon
/// as it resolves.
async fn release_reservation_after_uploads(
    height: u64,
    persisted: impl Future<Output = Result<(), PublishError>>,
    simplex: impl Future<Output = Result<(), CertificateUploaderStopped>>,
    reservation: UploadReservation,
) {
    tokio::join!(
        async {
            persisted
                .await
                .unwrap_or_else(|error| panic!("QMDB upload failed at height {height}. {error}"));
        },
        async {
            simplex.await.unwrap_or_else(|error| {
                panic!("finalized block upload failed at height {height}. {error}")
            });
        },
    );
    drop(reservation);
}

/// Read the payload for a queue record.
///
/// This panics on failure. The record committed only after the payload was
/// synced, so a mismatch is corruption rather than an expected state.
async fn read_finalized_payload(
    payloads: &FinalizedPayloads,
    height: u64,
    descriptor: PayloadDescriptor,
) -> Bytes {
    payloads
        .read(height, descriptor)
        .await
        .unwrap_or_else(|error| {
            panic!("failed to read finalized index payload at height {height}. {error}")
        })
}

async fn decode_finalized_payload(
    height: u64,
    bytes: Bytes,
    metrics: &FinalizedUploadMetrics,
) -> EngineQueuedUpload {
    let metrics = metrics.clone();
    let scheduled = Instant::now();
    let parent = Span::current();
    let queued = info_span!(parent: &parent, "indexer.payload.decode_schedule", height);
    tokio::task::spawn_blocking(move || {
        drop(queued);
        let _span =
            info_span!(parent: &parent, "indexer.payload.decode", height, bytes = bytes.len())
                .entered();
        metrics
            .decode_schedule_wait
            .observe(scheduled.elapsed().as_secs_f64());
        let started = Instant::now();
        let upload = EngineQueuedUpload::decode_cfg(bytes, &QueuedFinalizedUploadCfg::default());
        metrics.decode.observe(started.elapsed().as_secs_f64());
        upload.unwrap_or_else(|error| {
            panic!("failed to decode finalized index payload at height {height}. {error}")
        })
    })
    .await
    .expect("finalized index payload decode task panicked")
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            budget::FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
            payloads::PayloadStore,
            queue::{
                FINALIZED_QUEUE_ITEMS_PER_SECTION, capture_receipt, init_finalized_queue,
                recover_capture_receipt, scan_finalized_queue_records, sweep_finalized_payloads,
            },
        },
        CertificateUploaderStopped, FinalizedPayloads, FinalizedQueueReader, FinalizedQueueRecord,
        FinalizedQueueWriter, FinalizedReceiptStore, FinalizedUploadMetrics, PublishError,
        RetainedUpload, RuntimeContext, UploadBudget, prune_finalized_queue,
        release_reservation_after_uploads,
    };
    use bytes::Bytes;
    use commonware_runtime::{Runner as _, Supervisor as _};
    use std::collections::BTreeMap;
    use tokio::sync::oneshot;
    use tracing::Span;

    struct PruneFixture {
        writer: FinalizedQueueWriter,
        reader: FinalizedQueueReader,
        payloads: FinalizedPayloads,
        receipt_store: FinalizedReceiptStore,
        metrics: FinalizedUploadMetrics,
        retained: BTreeMap<u64, RetainedUpload>,
    }

    impl PruneFixture {
        /// Commit one full section plus one record, each with a payload, and
        /// read the full section.
        async fn new(context: &RuntimeContext, name: &str) -> Self {
            let (mut queue, mut reader) = init_finalized_queue(context.child("queue"), name).await;
            let payloads = PayloadStore::new(context.child("payloads"), format!("{name}-payloads"));
            let section = FINALIZED_QUEUE_ITEMS_PER_SECTION.get();
            let mut retained = BTreeMap::new();
            for height in 1..=section + 1 {
                let payload = payloads
                    .write(height, Bytes::from_static(b"payload"))
                    .await
                    .unwrap();
                let record = FinalizedQueueRecord {
                    receipt: capture_receipt(height, height + 1, height + 1),
                    payload,
                };
                let position;
                (queue, position) = queue.append(record).await.unwrap();
                assert_eq!(position, height - 1);
                retained.insert(
                    position,
                    RetainedUpload {
                        record,
                        trace: Span::none(),
                        wait: None,
                    },
                );
            }
            let queue = queue.sync().await.unwrap();
            for position in 0..section {
                assert_eq!(reader.try_recv().await.unwrap().unwrap().0, position);
            }
            let (receipt_store, _) =
                FinalizedReceiptStore::open(context.child("receipt"), name).await;
            Self {
                writer: FinalizedQueueWriter::new(queue),
                reader,
                payloads,
                receipt_store,
                metrics: FinalizedUploadMetrics::new(&context.child("upload")),
                retained,
            }
        }

        async fn prune(&mut self, payload_floor: &mut u64) {
            prune_finalized_queue(
                &self.reader,
                &self.writer,
                &self.payloads,
                &self.receipt_store,
                &self.metrics,
                &mut self.retained,
                payload_floor,
            )
            .await;
        }

        /// Close every storage handle and return the records the consumer still retains.
        fn crash(self) -> Vec<(u64, FinalizedQueueRecord)> {
            let Self {
                writer,
                reader,
                payloads,
                receipt_store,
                retained,
                ..
            } = self;
            drop((writer, reader, payloads, receipt_store));
            retained
                .into_iter()
                .map(|(position, entry)| (position, entry.record))
                .collect()
        }
    }

    #[test]
    fn restart_sweeps_payloads_left_after_durable_prune() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let section = FINALIZED_QUEUE_ITEMS_PER_SECTION.get();
            let mut fixture = PruneFixture::new(&context, "sweep").await;
            let mut payload_floor = 0;

            // A completion gap must retain both its receipt and every payload.
            for position in (1..section).rev() {
                fixture.reader.ack(position).unwrap();
            }
            assert_eq!(fixture.reader.ack_floor(), 0);
            fixture.prune(&mut payload_floor).await;
            assert_eq!(payload_floor, 0);
            assert_eq!(
                fixture.retained.len(),
                usize::try_from(section + 1).unwrap()
            );
            assert_eq!(
                fixture.payloads.heights().await.unwrap().len(),
                fixture.retained.len()
            );
            assert!(fixture.receipt_store.current().await.is_none());

            fixture.reader.ack(0).unwrap();
            assert_eq!(fixture.reader.ack_floor(), section);
            fixture.prune(&mut payload_floor).await;
            assert_eq!(payload_floor, section);
            assert_eq!(
                fixture.retained.keys().copied().collect::<Vec<_>>(),
                vec![section]
            );
            assert_eq!(
                fixture.payloads.heights().await.unwrap(),
                [section + 1].into()
            );

            // Leave behind the orphan that a failed deletion would.
            fixture
                .payloads
                .write(1, Bytes::from_static(b"payload"))
                .await
                .unwrap();
            let retained = fixture.crash();

            let (_queue, mut reader) =
                init_finalized_queue(context.child("recovered_queue"), "sweep").await;
            let (_store, stored_receipt) =
                FinalizedReceiptStore::open(context.child("recovered_receipt"), "sweep").await;
            assert_eq!(
                stored_receipt,
                Some(capture_receipt(section, section + 1, section + 1))
            );
            let records = scan_finalized_queue_records(&mut reader).await;
            assert_eq!(records, retained);
            let payloads =
                PayloadStore::new(context.child("recovered_payloads"), "sweep-payloads".into());
            sweep_finalized_payloads(&payloads, &records).await;
            assert_eq!(payloads.heights().await.unwrap(), [section + 1].into());
            assert_eq!(
                payloads
                    .read(section + 1, records[0].1.payload)
                    .await
                    .unwrap(),
                b"payload"[..]
            );
        });
    }

    #[test]
    fn restart_after_a_failed_queue_sync_recovers_from_the_queue_tail() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let section = FINALIZED_QUEUE_ITEMS_PER_SECTION.get();
            let mut fixture = PruneFixture::new(&context, "failed-sync").await;
            let mut payload_floor = 0;
            for position in 0..section {
                fixture.reader.ack(position).unwrap();
            }

            // A lost writer fails the queue sync after the receipt is durable.
            fixture.writer.lose_queue().await;
            let prune = std::panic::AssertUnwindSafe(fixture.prune(&mut payload_floor));
            assert!(futures::FutureExt::catch_unwind(prune).await.is_err());
            assert_eq!(payload_floor, 0);
            assert_eq!(
                fixture.receipt_store.current().await,
                Some(capture_receipt(section, section + 1, section + 1))
            );
            assert_eq!(
                fixture.payloads.heights().await.unwrap().len(),
                usize::try_from(section + 1).unwrap()
            );
            let retained = fixture.crash();

            let (_queue, mut reader) =
                init_finalized_queue(context.child("recovered_queue"), "failed-sync").await;
            let (_store, stored_receipt) =
                FinalizedReceiptStore::open(context.child("recovered_receipt"), "failed-sync")
                    .await;
            let records = scan_finalized_queue_records(&mut reader).await;
            assert_eq!(records, retained);
            assert_eq!(
                recover_capture_receipt(
                    stored_receipt,
                    records.last().map(|(_, record)| record.receipt),
                ),
                Some(capture_receipt(section + 1, section + 2, section + 2))
            );
            let payloads = PayloadStore::new(
                context.child("recovered_payloads"),
                "failed-sync-payloads".into(),
            );
            sweep_finalized_payloads(&payloads, &records).await;
            for (_, record) in &records {
                assert_eq!(
                    payloads
                        .read(record.height(), record.payload)
                        .await
                        .unwrap(),
                    b"payload"[..]
                );
            }
        });
    }

    #[test]
    fn reservation_is_released_once_both_uploads_are_durable() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let budget = UploadBudget::new(
                &context.child("upload_budget"),
                FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
            );
            let charge = budget.charge(FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES / 8);
            let reservation = budget.try_reserve(charge).expect("test charge fits budget");
            let (qmdb_tx, qmdb_rx) = oneshot::channel();
            let (simplex_tx, simplex_rx) = oneshot::channel();
            let mut release = Box::pin(release_reservation_after_uploads(
                1,
                async move {
                    qmdb_rx
                        .await
                        .map_err(|_| PublishError::CommitterStopped { height: 1 })
                },
                async move { simplex_rx.await.map_err(|_| CertificateUploaderStopped) },
                reservation,
            ));

            qmdb_tx.send(()).expect("QMDB gate is open");
            assert!(futures::poll!(release.as_mut()).is_pending());
            assert!(budget.try_reserve(charge).is_none());

            simplex_tx.send(()).expect("Simplex gate is open");
            release.await;
            assert!(budget.try_reserve(charge).is_some());
        });
    }
}
