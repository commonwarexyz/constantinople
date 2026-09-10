//! Durable payload blobs for the finalized index queue.
//!
//! The finalized index queue holds one small record per block. The encoded
//! upload lives here as one blob per block. Keeping payloads out of the queue
//! journal lets the consumer read a payload with a single blob read outside the
//! shared queue lock, and lets a restart recover the queue from records alone.

use bytes::Bytes;
use commonware_cryptography::crc32::Crc32;
use commonware_formatting::hex;
use commonware_runtime::{
    Blob as _, Clock, Error, Handle, Metrics, ReadOptions, Spawner, Storage, WriteOptions,
    telemetry::metrics::{Gauge, Histogram, MetricsExt as _},
};
use std::{
    collections::BTreeSet,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tracing::warn;

const CLEANUP_CAPACITY: usize = 64;

const DURATION_BUCKETS: [f64; 12] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

/// Length and checksum of a durable payload.
///
/// The queue record carries this so a later read rejects a truncated or
/// corrupted blob before decoding it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PayloadDescriptor {
    pub(crate) len: u64,
    pub(crate) crc: u32,
}

/// Why a payload read did not produce the recorded bytes.
#[derive(Debug)]
pub(crate) enum PayloadReadError {
    Storage(Error),
    Length { expected: u64, actual: u64 },
    Checksum { expected: u32, actual: u32 },
}

impl fmt::Display for PayloadReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "storage error: {error}"),
            Self::Length { expected, actual } => {
                write!(
                    f,
                    "payload length {actual} does not match record {expected}"
                )
            }
            Self::Checksum { expected, actual } => write!(
                f,
                "payload checksum {actual:#010x} does not match record {expected:#010x}"
            ),
        }
    }
}

impl From<Error> for PayloadReadError {
    fn from(error: Error) -> Self {
        Self::Storage(error)
    }
}

#[derive(Clone)]
struct PayloadMetrics {
    retained: Gauge,
    retained_bytes: Gauge,
    write_duration: Histogram,
    sync_duration: Histogram,
    read_duration: Histogram,
}

impl PayloadMetrics {
    fn new(context: &impl Metrics) -> Self {
        Self {
            retained: context.gauge("retained", "Finalized payload blobs on disk"),
            retained_bytes: context.gauge("retained_bytes", "Finalized payload bytes on disk"),
            write_duration: context.histogram(
                "write_duration",
                "Finalized payload write time before sync (s)",
                DURATION_BUCKETS,
            ),
            sync_duration: context.histogram(
                "sync_duration",
                "Finalized payload sync time (s)",
                DURATION_BUCKETS,
            ),
            read_duration: context.histogram(
                "read_duration",
                "Finalized payload read and verify time (s)",
                DURATION_BUCKETS,
            ),
        }
    }
}

/// One payload blob per finalized block, named by height.
///
/// Runtime contexts are not `Clone`, so the producer and consumer share one
/// store through an `Arc`. Rust-ism: deriving `Clone` would add an `E: Clone`
/// bound, so the impl is written by hand and only bumps the reference count.
pub(crate) struct PayloadStore<E: Storage> {
    inner: Arc<Inner<E>>,
}

struct Inner<E: Storage> {
    context: E,
    partition: String,
    metrics: PayloadMetrics,
}

pub(crate) struct PayloadCleanup {
    sender: mpsc::Sender<(u64, u64)>,
    pending: Gauge,
}

impl PayloadCleanup {
    pub(crate) async fn enqueue(&self, height: u64, len: u64) {
        let permit = self
            .sender
            .reserve()
            .await
            .expect("payload cleanup task stopped");
        self.pending.inc();
        permit.send((height, len));
    }
}

impl<E: Storage> Clone for PayloadStore<E> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<E: Storage> PayloadStore<E> {
    pub(crate) fn new(context: E, partition: String) -> Self
    where
        E: Metrics,
    {
        let metrics = PayloadMetrics::new(&context);
        Self {
            inner: Arc::new(Inner {
                context,
                partition,
                metrics,
            }),
        }
    }

    pub(crate) fn start_cleanup(
        &self,
        context: impl Spawner + Metrics + Clock,
    ) -> (PayloadCleanup, Handle<()>) {
        let pending = context.gauge("pending", "Finalized payloads awaiting removal");
        let duration = context.histogram(
            "remove_duration",
            "Finalized payload removal time including retries (s)",
            DURATION_BUCKETS,
        );
        let (sender, mut receiver) = mpsc::channel(CLEANUP_CAPACITY);
        let cleanup = PayloadCleanup {
            sender,
            pending: pending.clone(),
        };
        let payloads = self.clone();
        let task = context.spawn(move |context| async move {
            while let Some((height, len)) = receiver.recv().await {
                let started = Instant::now();
                loop {
                    match payloads.remove(height, len).await {
                        Ok(()) => break,
                        Err(error) => {
                            warn!(error = %error, height, "failed to remove finalized index payload, retrying");
                            context.sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
                duration.observe(started.elapsed().as_secs_f64());
                pending.dec();
            }
        });
        (cleanup, task)
    }

    /// Persist `payload` for `height` and return its descriptor.
    ///
    /// The blob is synced before this returns, so a queue record committed
    /// afterwards never points at bytes a crash could lose. A blob left behind
    /// by an earlier crash never reached a committed record, so it is truncated
    /// before the new bytes land.
    pub(crate) async fn write(
        &self,
        height: u64,
        payload: Bytes,
    ) -> Result<PayloadDescriptor, Error> {
        let descriptor = PayloadDescriptor {
            len: payload.len() as u64,
            crc: Crc32::checksum(&payload),
        };
        let (blob, existing) = self
            .inner
            .context
            .open(&self.inner.partition, &blob_name(height))
            .await?;
        if existing != 0 {
            blob.resize(0).await?;
        }
        let write_started = Instant::now();
        blob.write_at(0, payload, WriteOptions::default()).await?;
        self.inner
            .metrics
            .write_duration
            .observe(write_started.elapsed().as_secs_f64());
        let sync_started = Instant::now();
        blob.sync().await?;
        self.inner
            .metrics
            .sync_duration
            .observe(sync_started.elapsed().as_secs_f64());
        self.inner.metrics.retained.inc();
        self.inner
            .metrics
            .retained_bytes
            .inc_by(metric_i64(descriptor.len));
        Ok(descriptor)
    }

    /// Read the payload for `height`, rejecting any disagreement with `descriptor`.
    pub(crate) async fn read(
        &self,
        height: u64,
        descriptor: PayloadDescriptor,
    ) -> Result<Bytes, PayloadReadError> {
        let started = Instant::now();
        let (blob, actual) = self
            .inner
            .context
            .open(&self.inner.partition, &blob_name(height))
            .await?;
        if actual != descriptor.len {
            return Err(PayloadReadError::Length {
                expected: descriptor.len,
                actual,
            });
        }
        let len = usize::try_from(descriptor.len).expect("payload length fits usize");
        let bytes: Bytes = blob
            .read_at(0, len, ReadOptions::default())
            .await?
            .coalesce()
            .freeze()
            .into();
        let crc = Crc32::checksum(&bytes);
        if crc != descriptor.crc {
            return Err(PayloadReadError::Checksum {
                expected: descriptor.crc,
                actual: crc,
            });
        }
        self.inner
            .metrics
            .read_duration
            .observe(started.elapsed().as_secs_f64());
        Ok(bytes)
    }

    /// Size on disk of the payload for `height`.
    ///
    /// Only call this for heights returned by [Self::heights]. Opening a blob
    /// that does not exist creates it.
    pub(crate) async fn len(&self, height: u64) -> Result<u64, Error> {
        let (_, len) = self
            .inner
            .context
            .open(&self.inner.partition, &blob_name(height))
            .await?;
        Ok(len)
    }

    /// Remove the payload for `height`. A payload that is already gone is not an error.
    pub(crate) async fn remove(&self, height: u64, len: u64) -> Result<(), Error> {
        match self
            .inner
            .context
            .remove(&self.inner.partition, Some(&blob_name(height)))
            .await
        {
            Ok(()) => {
                self.inner.metrics.retained.dec();
                self.inner.metrics.retained_bytes.dec_by(metric_i64(len));
                Ok(())
            }
            Err(Error::BlobMissing(..)) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Heights with a payload on disk. A partition never written to is empty.
    pub(crate) async fn heights(&self) -> Result<BTreeSet<u64>, Error> {
        let names = match self.inner.context.scan(&self.inner.partition).await {
            Ok(names) => names,
            Err(Error::PartitionMissing(_)) => return Ok(BTreeSet::new()),
            Err(error) => return Err(error),
        };
        Ok(names.iter().map(|name| parse_height(name)).collect())
    }

    /// Reset the retained gauges to what a startup sweep found on disk.
    pub(crate) fn set_retained(&self, count: usize, bytes: u64) {
        self.inner
            .metrics
            .retained
            .set(i64::try_from(count).unwrap_or(i64::MAX));
        self.inner.metrics.retained_bytes.set(metric_i64(bytes));
    }
}

const fn blob_name(height: u64) -> [u8; 8] {
    height.to_be_bytes()
}

fn parse_height(name: &[u8]) -> u64 {
    <[u8; 8]>::try_from(name)
        .map(u64::from_be_bytes)
        .unwrap_or_else(|_| {
            panic!(
                "unexpected blob {} in the finalized payload partition",
                hex(name)
            )
        })
}

fn metric_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{
        CLEANUP_CAPACITY, Inner, PayloadDescriptor, PayloadMetrics, PayloadReadError, PayloadStore,
    };
    use bytes::Bytes;
    use commonware_runtime::{
        BlobVersion, Error, Runner as _, Storage, Supervisor as _, deterministic,
    };
    use std::{
        ops::RangeInclusive,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::sync::{Notify, Semaphore};

    const PARTITION: &str = "finalized-payloads-test";

    fn store(context: &deterministic::Context) -> PayloadStore<deterministic::Context> {
        PayloadStore::new(context.child("finalized_payloads"), PARTITION.into())
    }

    struct GatedStorage<E> {
        inner: E,
        started: Arc<Notify>,
        release: Arc<Semaphore>,
        attempts: Arc<AtomicUsize>,
    }

    impl<E: Storage> Storage for GatedStorage<E> {
        type Blob = E::Blob;

        async fn open_versioned(
            &self,
            partition: &str,
            name: &[u8],
            versions: RangeInclusive<BlobVersion>,
        ) -> Result<(Self::Blob, u64, BlobVersion), Error> {
            self.inner.open_versioned(partition, name, versions).await
        }

        async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
            self.started.notify_one();
            self.release.acquire().await.unwrap().forget();
            if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(Error::WriteFailed);
            }
            self.inner.remove(partition, name).await
        }

        async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
            self.inner.scan(partition).await
        }
    }

    #[test]
    fn cleanup_is_bounded_retries_and_drains_without_blocking_payload_io() {
        deterministic::Runner::default().start(|context| async move {
            let started = Arc::new(Notify::new());
            let release = Arc::new(Semaphore::new(0));
            let attempts = Arc::new(AtomicUsize::new(0));
            let store = PayloadStore {
                inner: Arc::new(Inner {
                    context: GatedStorage {
                        inner: context.child("storage"),
                        started: started.clone(),
                        release: release.clone(),
                        attempts: attempts.clone(),
                    },
                    partition: PARTITION.into(),
                    metrics: PayloadMetrics::new(&context.child("payloads")),
                }),
            };
            let count = CLEANUP_CAPACITY as u64 + 2;
            for height in 1..=count {
                store.write(height, Bytes::from_static(b"x")).await.unwrap();
            }
            let (cleanup, task) = store.start_cleanup(context.child("cleanup"));
            let pending = cleanup.pending.clone();
            cleanup.enqueue(1, 1).await;
            started.notified().await;
            for height in 2..count {
                cleanup.enqueue(height, 1).await;
            }
            let mut blocked = Box::pin(cleanup.enqueue(count, 1));
            assert!(futures::poll!(blocked.as_mut()).is_pending());
            assert_eq!(pending.get(), count as i64 - 1);
            assert_eq!(store.inner.metrics.retained.get(), count as i64);

            let descriptor = store
                .write(count + 1, Bytes::from_static(b"new"))
                .await
                .unwrap();
            assert_eq!(store.read(count + 1, descriptor).await.unwrap(), b"new"[..]);
            assert_eq!(store.len(1).await.unwrap(), 1);
            release.add_permits(1);
            started.notified().await;
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
            assert_eq!(pending.get(), count as i64 - 1);
            assert_eq!(store.len(1).await.unwrap(), 1);

            release.add_permits(count as usize);
            blocked.await;
            drop(cleanup);
            task.await.expect("cleanup drains after channel closure");
            assert_eq!(pending.get(), 0);
            assert_eq!(attempts.load(Ordering::SeqCst), count as usize + 1);
            assert_eq!(store.heights().await.unwrap(), [count + 1].into());
            assert_eq!(store.inner.metrics.retained.get(), 1);
            assert_eq!(store.inner.metrics.retained_bytes.get(), 3);
        });
    }

    #[test]
    fn payload_round_trips_and_is_removed() {
        deterministic::Runner::default().start(|context| async move {
            let store = store(&context);
            assert!(store.heights().await.unwrap().is_empty());

            let payload = Bytes::from(vec![7u8; 4096]);
            let descriptor = store.write(3, payload.clone()).await.unwrap();
            assert_eq!(descriptor.len, 4096);
            assert_eq!(
                store
                    .heights()
                    .await
                    .unwrap()
                    .into_iter()
                    .collect::<Vec<_>>(),
                vec![3]
            );
            assert_eq!(store.len(3).await.unwrap(), 4096);
            assert_eq!(store.read(3, descriptor).await.unwrap(), payload);
            assert_eq!(store.inner.metrics.retained.get(), 1);
            assert_eq!(store.inner.metrics.retained_bytes.get(), 4096);

            store.remove(3, descriptor.len).await.unwrap();
            assert!(store.heights().await.unwrap().is_empty());
            assert_eq!(store.inner.metrics.retained.get(), 0);
            assert_eq!(store.inner.metrics.retained_bytes.get(), 0);

            // Removing an absent payload is idempotent.
            store.remove(3, descriptor.len).await.unwrap();
        });
    }

    #[test]
    fn read_rejects_length_and_checksum_mismatches() {
        deterministic::Runner::default().start(|context| async move {
            let store = store(&context);
            let descriptor = store
                .write(9, Bytes::from_static(b"payload"))
                .await
                .unwrap();

            let longer = PayloadDescriptor {
                len: descriptor.len + 1,
                ..descriptor
            };
            assert!(matches!(
                store.read(9, longer).await,
                Err(PayloadReadError::Length {
                    expected: 8,
                    actual: 7
                })
            ));

            let corrupted = PayloadDescriptor {
                crc: descriptor.crc ^ 1,
                ..descriptor
            };
            assert!(matches!(
                store.read(9, corrupted).await,
                Err(PayloadReadError::Checksum { .. })
            ));

            assert!(matches!(
                store.read(10, descriptor).await,
                Err(PayloadReadError::Length { actual: 0, .. })
            ));
        });
    }

    #[test]
    fn rewrite_truncates_a_stale_payload() {
        deterministic::Runner::default().start(|context| async move {
            let store = store(&context);
            store.write(5, Bytes::from(vec![1u8; 1024])).await.unwrap();

            let replacement = Bytes::from(vec![2u8; 16]);
            let descriptor = store.write(5, replacement.clone()).await.unwrap();
            assert_eq!(descriptor.len, 16);
            assert_eq!(store.len(5).await.unwrap(), 16);
            assert_eq!(store.read(5, descriptor).await.unwrap(), replacement);
        });
    }

    #[test]
    fn heights_are_ordered() {
        deterministic::Runner::default().start(|context| async move {
            let store = store(&context);
            for height in [12u64, 3, 7] {
                store.write(height, Bytes::from_static(b"x")).await.unwrap();
            }
            assert_eq!(
                store
                    .heights()
                    .await
                    .unwrap()
                    .into_iter()
                    .collect::<Vec<_>>(),
                vec![3, 7, 12]
            );
        });
    }
}
