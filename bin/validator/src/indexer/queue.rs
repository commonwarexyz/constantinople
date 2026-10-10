//! Keeps capture recovery independent of payload size and remote availability.

use super::{FinalizedPayloads, payloads::PayloadDescriptor};
use commonware_codec::{Buf, FixedSize, Read, ReadExt as _, Write};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig,
    ed25519::PublicKey,
    sha256::{Digest, Sha256},
};
use commonware_runtime::{
    Supervisor,
    buffer::paged::{self, CacheRef},
    tokio::Context as RuntimeContext,
};
use commonware_storage::{
    Context as StorageContext,
    metadata::{Config as MetadataConfig, Metadata},
    queue,
};
use commonware_utils::{NZU64, NZUsize, sequence::U64};
use constantinople_engine::types::EngineBlock;
use constantinople_indexer::publisher::qmdb::{OperationList, QueuedFinalizedUpload};
use std::{
    collections::BTreeSet,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    sync::Arc,
};
use tokio::sync::Mutex;
use tracing::info;

// Queue records are under a hundred bytes. Small sections keep the payload
// blobs of acknowledged entries on disk only until their section prunes.
pub(super) const FINALIZED_QUEUE_ITEMS_PER_SECTION: NonZeroU64 = NZU64!(16);
const FINALIZED_QUEUE_PAGE_SIZE: NonZeroU16 = paged::page_size(4_096);
const FINALIZED_QUEUE_PAGE_CACHE_PAGES: NonZeroUsize = NZUsize!(256);
const FINALIZED_QUEUE_WRITE_BUFFER: NonZeroUsize = NZUsize!(64 * 1024);
const CAPTURE_RECEIPT_KEY: U64 = U64::new(0);
type CaptureMetadata<E> = Metadata<E, U64, LatestCaptureReceipt>;
pub(super) type FinalizedQueue = queue::Queue<RuntimeContext, FinalizedQueueRecord>;
pub(super) type FinalizedQueueReader = queue::Reader<RuntimeContext, FinalizedQueueRecord>;

// Storage mutations take the queue by value. A failed or canceled mutation
// drops it, which ends the reader so the consumer forces restart recovery.
#[derive(Clone)]
pub(super) struct FinalizedQueueWriter {
    queue: Arc<Mutex<Option<FinalizedQueue>>>,
}

impl FinalizedQueueWriter {
    pub(super) fn new(queue: FinalizedQueue) -> Self {
        Self {
            queue: Arc::new(Mutex::new(Some(queue))),
        }
    }

    pub(super) async fn enqueue(&self, record: FinalizedQueueRecord) -> Result<u64, queue::Error> {
        let mut current = self.queue.lock().await;
        let queue = current.take().expect("finalized queue writer was lost");
        let (queue, position) = queue.enqueue(record).await?;
        *current = Some(queue);
        Ok(position)
    }

    pub(super) async fn sync(&self) -> Result<(), queue::Error> {
        let mut current = self.queue.lock().await;
        let queue = current.take().expect("finalized queue writer was lost");
        *current = Some(queue.sync().await?);
        Ok(())
    }

    #[cfg(test)]
    pub(super) async fn lose_queue(&self) {
        drop(self.queue.lock().await.take());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LatestCaptureReceipt {
    pub(super) height: u64,
    block_digest: Digest,
    pub(super) state_end: u64,
    pub(super) transaction_end: u64,
}

impl LatestCaptureReceipt {
    pub(super) fn from_upload<S: OperationList, T: OperationList>(
        upload: &QueuedFinalizedUpload<Sha256, PublicKey, MinSig, S, T>,
    ) -> Self {
        Self {
            height: upload.height(),
            block_digest: *upload.block().seal(),
            state_end: upload.state_end(),
            transaction_end: upload.transaction_end(),
        }
    }

    pub(super) fn matches_block(&self, block: &EngineBlock<Sha256, PublicKey>) -> bool {
        self.height == block.header.height
            && self.block_digest == *block.seal()
            && self.state_end == block.header.state_range.end()
            && self.transaction_end == block.header.transactions_range.end()
    }
}

impl FixedSize for LatestCaptureReceipt {
    const SIZE: usize = u64::SIZE + Digest::SIZE + u64::SIZE + u64::SIZE;
}

impl Write for LatestCaptureReceipt {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.height.write(buf);
        self.block_digest.write(buf);
        self.state_end.write(buf);
        self.transaction_end.write(buf);
    }
}

impl Read for LatestCaptureReceipt {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            height: u64::read(buf)?,
            block_digest: Digest::read(buf)?,
            state_end: u64::read(buf)?,
            transaction_end: u64::read(buf)?,
        })
    }
}

/// Durable queue entry for one finalized block.
///
/// The queue holds only this record. The encoded upload lives in the payload
/// partition, so restart recovers the queue without reading any payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FinalizedQueueRecord {
    pub(super) receipt: LatestCaptureReceipt,
    pub(super) payload: PayloadDescriptor,
}

impl FinalizedQueueRecord {
    pub(super) const fn height(&self) -> u64 {
        self.receipt.height
    }
}

impl FixedSize for FinalizedQueueRecord {
    const SIZE: usize = LatestCaptureReceipt::SIZE + u64::SIZE + u32::SIZE;
}

impl Write for FinalizedQueueRecord {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.receipt.write(buf);
        self.payload.len.write(buf);
        self.payload.crc.write(buf);
    }
}

impl Read for FinalizedQueueRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            receipt: LatestCaptureReceipt::read(buf)?,
            payload: PayloadDescriptor {
                len: u64::read(buf)?,
                crc: u32::read(buf)?,
            },
        })
    }
}

pub(super) struct FinalizedReceiptStore<E: StorageContext = RuntimeContext> {
    metadata: Mutex<Option<CaptureMetadata<E>>>,
}

impl<E: StorageContext + Supervisor> FinalizedReceiptStore<E> {
    /// Open the store and return the receipt it last persisted.
    pub(super) async fn open(
        context: E,
        partition_prefix: &str,
    ) -> (Self, Option<LatestCaptureReceipt>) {
        let config = MetadataConfig {
            partition: format!("{partition_prefix}-finalized-capture-receipt"),
            codec_config: (),
        };
        let metadata = Metadata::init(context.child("metadata"), config)
            .await
            .expect("failed to initialize finalized capture receipt");
        let receipt = metadata.get(&CAPTURE_RECEIPT_KEY).copied();
        let store = Self {
            metadata: Mutex::new(Some(metadata)),
        };
        (store, receipt)
    }

    pub(super) async fn persist(&self, receipt: LatestCaptureReceipt) {
        let mut metadata = self.metadata.lock().await;
        let mut current = metadata
            .take()
            .expect("finalized capture receipt store was lost");
        current.put(CAPTURE_RECEIPT_KEY, receipt);
        *metadata = Some(
            current
                .sync()
                .await
                .expect("failed to persist finalized capture receipt"),
        );
    }

    #[cfg(test)]
    pub(super) async fn current(&self) -> Option<LatestCaptureReceipt> {
        self.metadata
            .lock()
            .await
            .as_ref()
            .and_then(|metadata| metadata.get(&CAPTURE_RECEIPT_KEY).copied())
    }
}

pub(super) async fn init_finalized_queue(
    context: RuntimeContext,
    partition_prefix: &str,
) -> (FinalizedQueue, FinalizedQueueReader) {
    let page_cache = CacheRef::from_pooler(
        &context,
        FINALIZED_QUEUE_PAGE_SIZE,
        FINALIZED_QUEUE_PAGE_CACHE_PAGES,
    );
    let config = queue::Config {
        partition: format!("{partition_prefix}-finalized-index-records"),
        items_per_section: FINALIZED_QUEUE_ITEMS_PER_SECTION,
        compression: None,
        codec_config: (),
        page_cache,
        write_buffer: FINALIZED_QUEUE_WRITE_BUFFER,
        replay_buffer: FINALIZED_QUEUE_WRITE_BUFFER,
    };
    queue::Queue::init(context, config)
        .await
        .expect("failed to initialize finalized index queue")
}

/// Read every unacknowledged record in order and rewind the reader.
///
/// Records are tiny, so a restart with a deep backlog recovers without
/// touching a payload.
pub(super) async fn scan_finalized_queue_records(
    reader: &mut FinalizedQueueReader,
) -> Vec<(u64, FinalizedQueueRecord)> {
    let mut records: Vec<(u64, FinalizedQueueRecord)> = Vec::new();
    loop {
        match reader.try_recv().await {
            Ok(Some((position, record))) => {
                assert_eq!(
                    record.height(),
                    position
                        .checked_add(1)
                        .expect("finalized queue position must not overflow")
                );
                if let Some((_, previous)) = records.last() {
                    assert_eq!(record.height(), previous.height() + 1);
                }
                records.push((position, record));
            }
            Ok(None) => {
                reader.reset();
                return records;
            }
            Err(error) => panic!("failed to scan finalized index queue. {error}"),
        }
    }
}

/// Reconcile payload blobs with the scanned records.
///
/// Every record must have a payload of the recorded length. Reads verify its
/// checksum. A blob without a record is left over from a crash between a payload
/// sync and its record commit, or from a deletion that failed or never ran after
/// its section pruned, and is removed here.
pub(super) async fn sweep_finalized_payloads(
    payloads: &FinalizedPayloads,
    records: &[(u64, FinalizedQueueRecord)],
) {
    let on_disk = payloads
        .heights()
        .await
        .expect("failed to list finalized index payloads");
    let mut referenced = BTreeSet::new();
    let mut retained_bytes = 0u64;
    for (_, record) in records {
        let height = record.height();
        assert!(
            on_disk.contains(&height),
            "finalized queue record at height {height} has no payload"
        );

        // Reading a missing payload creates an empty blob, so presence alone does not
        // prove the payload survived.
        let len = payloads
            .stored_len(height)
            .await
            .expect("failed to open finalized index payload");
        assert_eq!(
            len, record.payload.len,
            "finalized queue record at height {height} has a {len}-byte payload"
        );
        referenced.insert(height);
        retained_bytes = retained_bytes.saturating_add(record.payload.len);
    }
    for height in on_disk.difference(&referenced) {
        info!(height, "removing orphaned finalized index payload");
        payloads
            .remove(*height, 0)
            .await
            .expect("failed to remove orphaned finalized index payload");
    }
    payloads.set_retained(referenced.len(), retained_bytes);
}

pub(super) fn recover_capture_receipt(
    metadata: Option<LatestCaptureReceipt>,
    queue: Option<LatestCaptureReceipt>,
) -> Option<LatestCaptureReceipt> {
    match (metadata, queue) {
        (Some(metadata), Some(queue)) if metadata.height == queue.height => {
            assert_eq!(metadata, queue, "capture receipt conflicts with queue tail");
            Some(metadata)
        }
        (Some(metadata), Some(queue)) if metadata.height > queue.height => {
            panic!("capture receipt is ahead of the durable queue tail")
        }
        (_, Some(queue)) => Some(queue),
        (Some(metadata), None) => Some(metadata),
        (None, None) => None,
    }
}

/// First position still recoverable after the queue prunes below `ack_floor`.
pub(super) const fn pruned_record_boundary(ack_floor: u64) -> u64 {
    let section = FINALIZED_QUEUE_ITEMS_PER_SECTION.get();
    ack_floor / section * section
}

#[cfg(test)]
pub(super) fn capture_receipt(
    height: u64,
    state_end: u64,
    transaction_end: u64,
) -> LatestCaptureReceipt {
    LatestCaptureReceipt {
        height,
        block_digest: Digest::from([height as u8; Digest::SIZE]),
        state_end,
        transaction_end,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::payloads::PayloadDescriptor, FINALIZED_QUEUE_ITEMS_PER_SECTION,
        FinalizedQueueRecord, FinalizedReceiptStore, capture_receipt, pruned_record_boundary,
        recover_capture_receipt,
    };
    use commonware_codec::{DecodeExt as _, Encode as _, FixedSize as _};
    use commonware_runtime::{Clock as _, Runner as _, Supervisor as _, deterministic};
    use commonware_utils::probability;
    use futures::FutureExt as _;
    use std::{panic::AssertUnwindSafe, time::Duration};

    #[test]
    fn receipt_sync_failure_is_fatal() {
        deterministic::Runner::default().start(|context| async move {
            let (store, receipt) =
                FinalizedReceiptStore::open(context.child("receipt"), "failed-sync").await;
            assert!(receipt.is_none());
            store.persist(capture_receipt(1, 2, 2)).await;

            context.storage_fault_config().write().sync_rate = Some(probability!(1.0));
            let persist = AssertUnwindSafe(store.persist(capture_receipt(2, 3, 3))).catch_unwind();
            let panic = tokio::select! {
                result = persist => result.expect_err("receipt sync failure must panic"),
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("receipt sync failure must not retry");
                }
            };
            let message = panic.downcast_ref::<String>().expect("panic has a message");
            assert!(message.contains("failed to persist finalized capture receipt"));
        });
    }

    #[test]
    fn queue_record_round_trips() {
        let record = FinalizedQueueRecord {
            receipt: capture_receipt(7, 11, 13),
            payload: PayloadDescriptor {
                len: 31_000_000,
                crc: 0xdead_beef,
            },
        };
        let encoded = record.encode();
        assert_eq!(encoded.len(), FinalizedQueueRecord::SIZE);
        assert_eq!(
            FinalizedQueueRecord::decode(encoded).expect("record decodes"),
            record
        );
    }

    #[test]
    fn pruned_record_boundary_rounds_down_to_a_section() {
        let section = FINALIZED_QUEUE_ITEMS_PER_SECTION.get();
        assert_eq!(pruned_record_boundary(0), 0);
        assert_eq!(pruned_record_boundary(section - 1), 0);
        assert_eq!(pruned_record_boundary(section), section);
        assert_eq!(pruned_record_boundary(3 * section + 5), 3 * section);
    }

    #[test]
    fn queue_tail_repairs_an_older_capture_receipt() {
        let metadata = capture_receipt(7, 11, 13);
        let queue = capture_receipt(8, 14, 17);

        assert_eq!(
            recover_capture_receipt(Some(metadata), Some(queue)),
            Some(queue)
        );
        assert_eq!(recover_capture_receipt(None, Some(queue)), Some(queue));
        assert_eq!(
            recover_capture_receipt(Some(metadata), None),
            Some(metadata)
        );
    }

    #[test]
    #[should_panic(expected = "capture receipt is ahead of the durable queue tail")]
    fn capture_receipt_cannot_advance_past_a_nonempty_queue() {
        let metadata = capture_receipt(8, 14, 17);
        let queue = capture_receipt(7, 11, 13);

        let _ = recover_capture_receipt(Some(metadata), Some(queue));
    }

    #[test]
    #[should_panic(expected = "capture receipt conflicts with queue tail")]
    fn capture_receipt_must_match_the_queue_tail() {
        let metadata = capture_receipt(7, 11, 13);
        let queue = capture_receipt(7, 12, 13);

        let _ = recover_capture_receipt(Some(metadata), Some(queue));
    }
}
