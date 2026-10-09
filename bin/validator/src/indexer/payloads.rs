//! Durable payload blobs for the finalized index queue.
//!
//! The finalized index queue holds one small record per block. The encoded
//! upload lives here as one blob per block. Records stay small so restart scans
//! the queue without reading payloads, and payload I/O starts only after byte
//! admission.

use super::{DURATION_BUCKETS, metric_i64};
use bytes::Bytes;
use commonware_cryptography::crc32::Crc32;
use commonware_formatting::hex;
use commonware_runtime::{
    Blob as _, Error, Metrics, ReadOptions, Storage, WriteOptions,
    telemetry::metrics::{Gauge, GaugeExt as _, Histogram, MetricsExt as _},
};
use std::{collections::BTreeSet, sync::Arc, time::Instant};
use tracing::{Instrument as _, info_span};

/// Length and checksum of a durable payload.
///
/// The queue record carries this so a later read rejects a truncated or
/// corrupted blob before decoding it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PayloadDescriptor {
    pub(super) len: u64,
    pub(super) crc: u32,
}

/// Why a payload read did not produce the recorded bytes.
#[derive(Debug, thiserror::Error)]
pub(super) enum PayloadReadError {
    #[error("storage error: {0}")]
    Storage(#[from] Error),
    #[error("payload length {actual} does not match record {expected}")]
    Length { expected: u64, actual: u64 },
    #[error("payload checksum {actual:#010x} does not match record {expected:#010x}")]
    Checksum { expected: u32, actual: u32 },
}

#[derive(Clone)]
struct PayloadMetrics {
    retained: Gauge,
    retained_bytes: Gauge,
    write_open_duration: Histogram,
    read_open_duration: Histogram,
    write_duration: Histogram,
    sync_duration: Histogram,
    read_duration: Histogram,
}

impl PayloadMetrics {
    fn new(context: &impl Metrics) -> Self {
        Self {
            retained: context.gauge("retained", "Finalized payload blobs on disk"),
            retained_bytes: context.gauge("retained_bytes", "Finalized payload bytes on disk"),
            write_open_duration: context.histogram(
                "write_open_duration",
                "Finalized payload blob open time for writes (s)",
                DURATION_BUCKETS,
            ),
            read_open_duration: context.histogram(
                "read_open_duration",
                "Finalized payload blob open time for reads (s)",
                DURATION_BUCKETS,
            ),
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
/// store through an `Arc`. The manual `Clone` impl avoids the `E: Clone`
/// bound that a derive would add.
pub(super) struct PayloadStore<E: Storage> {
    inner: Arc<Inner<E>>,
}

struct Inner<E: Storage> {
    context: E,
    partition: String,
    metrics: PayloadMetrics,
}

impl<E: Storage> Clone for PayloadStore<E> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<E: Storage> PayloadStore<E> {
    pub(super) fn new(context: E, partition: String) -> Self
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

    /// Persist `payload` for `height` and return its descriptor.
    ///
    /// The blob is synced before this returns, so a queue record committed
    /// afterwards never points at bytes a crash could lose.
    pub(super) async fn write(
        &self,
        height: u64,
        payload: Bytes,
    ) -> Result<PayloadDescriptor, Error> {
        let descriptor = PayloadDescriptor {
            len: payload.len() as u64,
            crc: info_span!("indexer.payload.checksum", height, bytes = payload.len())
                .in_scope(|| Crc32::checksum(&payload)),
        };
        let open_started = Instant::now();
        let opened = self
            .inner
            .context
            .open(&self.inner.partition, &blob_name(height))
            .instrument(info_span!("indexer.payload.write_open", height))
            .await;
        self.inner
            .metrics
            .write_open_duration
            .observe(open_started.elapsed().as_secs_f64());
        let (blob, existing) = opened?;

        // Startup removes every blob without a record, and capture only
        // writes heights above the recovered receipt.
        assert_eq!(
            existing, 0,
            "finalized payload at height {height} already exists"
        );
        let write_started = Instant::now();
        blob.write_at(0, payload, WriteOptions::default())
            .instrument(info_span!(
                "indexer.payload.write",
                height,
                bytes = descriptor.len
            ))
            .await?;
        self.inner
            .metrics
            .write_duration
            .observe(write_started.elapsed().as_secs_f64());
        let sync_started = Instant::now();
        blob.sync()
            .instrument(info_span!("indexer.payload.sync", height))
            .await?;
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
    pub(super) async fn read(
        &self,
        height: u64,
        descriptor: PayloadDescriptor,
    ) -> Result<Bytes, PayloadReadError> {
        let started = Instant::now();
        let opened = self
            .inner
            .context
            .open(&self.inner.partition, &blob_name(height))
            .instrument(info_span!("indexer.payload.read_open", height))
            .await;
        self.inner
            .metrics
            .read_open_duration
            .observe(started.elapsed().as_secs_f64());
        let (blob, actual) = opened?;
        if actual != descriptor.len {
            return Err(PayloadReadError::Length {
                expected: descriptor.len,
                actual,
            });
        }
        let len = usize::try_from(descriptor.len).expect("payload length fits usize");
        let bytes: Bytes = blob
            .read_at(0, len, ReadOptions::default())
            .instrument(info_span!("indexer.payload.read", height, bytes = len))
            .await?
            .coalesce()
            .freeze()
            .into();
        let crc = info_span!("indexer.payload.checksum", height, bytes = len)
            .in_scope(|| Crc32::checksum(&bytes));
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

    /// Remove the payload for `height`. A payload that is already gone is not an error.
    pub(super) async fn remove(&self, height: u64, len: u64) -> Result<(), Error> {
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
    pub(super) async fn heights(&self) -> Result<BTreeSet<u64>, Error> {
        let names = match self.inner.context.scan(&self.inner.partition).await {
            Ok(names) => names,
            Err(Error::PartitionMissing(_)) => return Ok(BTreeSet::new()),
            Err(error) => return Err(error),
        };
        Ok(names.iter().map(|name| parse_height(name)).collect())
    }

    /// Reset the retained gauges to what a startup sweep found on disk.
    pub(super) fn set_retained(&self, count: usize, bytes: u64) {
        let _ = self.inner.metrics.retained.try_set(count);
        let _ = self.inner.metrics.retained_bytes.try_set(bytes);
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

#[cfg(test)]
mod tests {
    use super::{PayloadDescriptor, PayloadReadError, PayloadStore};
    use bytes::Bytes;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

    const PARTITION: &str = "finalized-payloads-test";

    fn store(context: &deterministic::Context) -> PayloadStore<deterministic::Context> {
        PayloadStore::new(context.child("finalized_payloads"), PARTITION.into())
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
}
