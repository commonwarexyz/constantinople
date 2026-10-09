//! Isolates finalized indexing so validator startup can wire it as one subsystem.

mod budget;
mod consumer;
mod payloads;
mod producer;
mod queue;
mod traces;

use crate::{config::IndexerConfig, run::CriticalTask};
use budget::{FINALIZED_UPLOAD_AMPLIFICATION, FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES, UploadBudget};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, ed25519::PublicKey, sha256::Sha256,
};
use commonware_parallel::Rayon;
use commonware_runtime::{
    Clock as _, Handle, Spawner as _, Strategizer as _, Supervisor as _,
    tokio::Context as RuntimeContext,
};
use constantinople_application::consensus::FinalizedHookFn;
use constantinople_engine::{
    ThresholdScheme,
    types::{EngineBlock, EngineCommitment, EngineMarshalMailbox},
};
use constantinople_indexer::{
    CertificateReporter, Publisher, StoreClientBuildError,
    namespaces::{
        PUBLICATION_TARGET_PREFIX_VALUE, SIMPLEX_PREFIX_VALUE, SQL_META_PREFIX_VALUE,
        STATE_QMDB_PREFIX_VALUE, TRANSACTIONS_QMDB_PREFIX_VALUE,
    },
    publisher::{
        PublisherMetrics,
        qmdb::{CapturedFinalizedUpload, PublishError, QueuedFinalizedUpload},
    },
};
use consumer::{FinalizedUploadConsumer, FinalizedUploadMetrics};
use payloads::PayloadStore;
use producer::{FinalizedCaptureMetrics, FinalizedUploadProducer};
use queue::{
    FinalizedQueueWriter, FinalizedReceiptStore, init_finalized_queue, recover_capture_receipt,
    scan_finalized_queue_records, sweep_finalized_payloads,
};
use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::sync::Mutex;
use traces::{CaptureTraces, block_span};
use tracing::{Instrument as _, error, info, info_span, warn};

const MAX_FINALIZED_QUEUE_UPLOADS: usize = 64;

const DURATION_BUCKETS: [f64; 27] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.0625, 0.08, 0.1, 0.125, 0.16, 0.2, 0.25, 0.315, 0.4,
    0.5, 0.63, 0.8, 1.0, 1.25, 1.6, 2.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];

type EngineCertReporter =
    CertificateReporter<Sha256, PublicKey, ThresholdScheme<PublicKey, MinSig>>;
type EnginePublisher = Publisher<Sha256, PublicKey>;
type EngineQueuedUpload = QueuedFinalizedUpload<Sha256, PublicKey, MinSig>;
type EngineCapturedUpload = CapturedFinalizedUpload<Sha256, PublicKey, MinSig>;
type FinalizedPayloads = PayloadStore<RuntimeContext>;
type EngineMarshal = EngineMarshalMailbox<Sha256, PublicKey, MinSig>;
type ValidatorFinalizedHook =
    FinalizedHookFn<EngineCommitment<Sha256, PublicKey>, Sha256, PublicKey>;

/// Saturating conversion for gauge increments and decrements.
fn metric_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Bundle of indexer state that needs to outlive engine startup.
pub(crate) struct IndexerHandle {
    pub(crate) finalized_hook: ValidatorFinalizedHook,
    pub(crate) marshal: Arc<OnceLock<EngineMarshal>>,
    pub(crate) critical_task: CriticalTask,
}

/// Connects the indexer publisher once and shares it across uploads.
struct LazyPublisher {
    context: RuntimeContext,
    store_url: String,
    api_key: Option<String>,
    buffer: usize,
    metrics: PublisherMetrics,
    strategy: Rayon,
    require_fresh: bool,
    publisher: Mutex<Option<Arc<EnginePublisher>>>,
}

impl LazyPublisher {
    fn new(
        context: RuntimeContext,
        store_url: String,
        api_key: Option<String>,
        buffer: usize,
        strategy: Rayon,
        require_fresh: bool,
    ) -> Self {
        // Connection retries must reuse the registered metrics.
        let metrics = PublisherMetrics::new(&context);
        Self {
            context,
            store_url,
            api_key,
            buffer,
            metrics,
            strategy,
            require_fresh,
            publisher: Mutex::new(None),
        }
    }

    /// Connect on first use. The slot lock is held across the connect so
    /// concurrent callers share one publisher instead of racing to create two.
    async fn publisher(&self) -> Arc<EnginePublisher> {
        let mut slot = self.publisher.lock().await;
        if let Some(publisher) = slot.as_ref() {
            return publisher.clone();
        }
        loop {
            let connect = EnginePublisher::connect(
                self.context.child("publisher"),
                &self.store_url,
                self.api_key.as_deref(),
                self.buffer,
                self.metrics.clone(),
                self.strategy.clone(),
                self.require_fresh,
            )
            .await;
            match connect {
                Ok((publisher, _worker)) => {
                    let publisher = Arc::new(publisher);
                    *slot = Some(publisher.clone());
                    return publisher;
                }
                Err(error @ PublishError::NonFreshNamespace { .. }) => {
                    panic!("fresh namespace validation failed. {error}")
                }
                Err(error) => {
                    warn!(
                        error = %error,
                        "indexer publisher connection failed, retrying",
                    );
                    self.context.sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
}

// A panic in either task already fails the runtime. This also fails it when a
// task returns or is aborted, which would otherwise stop indexing without a
// restart.
pub(crate) fn indexer_critical_task(
    cert_join: Handle<()>,
    finalized_join: Handle<()>,
) -> CriticalTask {
    Box::pin(async move {
        let (task, result) = tokio::select! {
            result = cert_join => ("Simplex certificate uploader", result),
            result = finalized_join => ("finalized index uploader", result),
        };
        match result {
            Ok(()) => error!(task, "critical indexer task exited"),
            Err(error) => error!(task, %error, "critical indexer task failed"),
        }
    })
}

/// Build the indexer wiring iff the secondary validator opted in.
pub(crate) async fn maybe_build_indexer(
    context: RuntimeContext,
    is_primary: bool,
    indexer: Option<IndexerConfig>,
    partition_prefix: &str,
) -> Result<Option<IndexerHandle>, StoreClientBuildError> {
    let Some(cfg) = indexer else {
        return Ok(None);
    };
    if is_primary {
        return Ok(None);
    }

    let max_active_uploads = cfg
        .upload_max_in_flight
        .clamp(1, MAX_FINALIZED_QUEUE_UPLOADS);
    info!(
        store_url = %cfg.store_url,
        upload_budget_bytes = cfg.upload_budget_bytes,
        upload_max_in_flight = max_active_uploads,
        configured_upload_max_in_flight = cfg.upload_max_in_flight,
        publisher_rayon_threads = cfg.publisher_rayon_threads.get(),
        upload_amplification = FINALIZED_UPLOAD_AMPLIFICATION,
        upload_budget_quantum_bytes = FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
        "starting full indexer uploaders",
    );
    info!(
        state_qmdb_prefix = %format_args!("0x{STATE_QMDB_PREFIX_VALUE:02x}"),
        transactions_qmdb_prefix = %format_args!("0x{TRANSACTIONS_QMDB_PREFIX_VALUE:02x}"),
        simplex_prefix = %format_args!("0x{SIMPLEX_PREFIX_VALUE:02x}"),
        sql_meta_prefix = %format_args!("0x{SQL_META_PREFIX_VALUE:02x}"),
        publication_target_prefix = %format_args!("0x{PUBLICATION_TARGET_PREFIX_VALUE:02x}"),
        "indexer Store layout",
    );
    let budget = UploadBudget::new(
        &context.child("finalized_upload_budget"),
        cfg.upload_budget_bytes,
    );
    let upload_metrics = FinalizedUploadMetrics::new(&context.child("finalized_upload"));
    let capture_metrics = FinalizedCaptureMetrics::new(&context.child("finalized_capture"));
    let (cert_reporter, cert_join) = EngineCertReporter::connect(
        context.child("simplex_upload"),
        &cfg.store_url,
        cfg.api_key.as_deref(),
        max_active_uploads,
    )?;
    let (queue, mut queue_reader) =
        init_finalized_queue(context.child("finalized_queue"), partition_prefix).await;
    let queue_writer = FinalizedQueueWriter::new(queue);
    let payloads = PayloadStore::new(
        context.child("finalized_payloads"),
        format!("{partition_prefix}-finalized-index-payloads"),
    );
    let (receipt_store, stored_receipt) =
        FinalizedReceiptStore::open(context.child("finalized_capture_receipt"), partition_prefix)
            .await;
    let records = scan_finalized_queue_records(&mut queue_reader).await;
    let payload_floor = queue_reader.ack_floor();
    sweep_finalized_payloads(&payloads, &records).await;
    let queue_tail = records.last().map(|(_, record)| record.receipt);
    let receipt = recover_capture_receipt(stored_receipt, queue_tail);

    // Records exist only after a capture, and a captured block may already be
    // uploaded, so the remote namespaces are validated as fresh only when
    // nothing was ever captured. That validation completes before the engine
    // can deliver a block to capture.
    let require_fresh = receipt.is_none();
    let strategy = context.strategy(cfg.publisher_rayon_threads);
    let publisher = Arc::new(LazyPublisher::new(
        context.child("publisher"),
        cfg.store_url,
        cfg.api_key,
        max_active_uploads,
        strategy,
        require_fresh,
    ));
    if require_fresh {
        publisher
            .publisher()
            .instrument(info_span!("indexer.publisher.connect"))
            .await;
    }

    let consumer_context = context.child("finalized_upload_consumer");
    let marshal = Arc::new(OnceLock::new());
    let traces = CaptureTraces::default();
    let finalized_producer = FinalizedUploadProducer {
        writer: queue_writer.clone(),
        payloads: payloads.clone(),
        receipt: Arc::new(Mutex::new(receipt)),
        capture_metrics,
        marshal: marshal.clone(),
        traces: traces.clone(),
    };
    let consumer = FinalizedUploadConsumer {
        publisher,
        cert_reporter,
        writer: queue_writer,
        reader: queue_reader,
        payloads,
        receipt_store,
        max_active: max_active_uploads,
        budget,
        metrics: upload_metrics,
        payload_floor,
        traces,
        replay_through: queue_tail.map_or(0, |receipt| receipt.height),
    };
    let finalized_join = consumer_context.spawn(move |context| consumer.run(context));
    Ok(Some(IndexerHandle {
        finalized_hook: indexer_finalized_hook(finalized_producer),
        marshal,
        critical_task: indexer_critical_task(cert_join, finalized_join),
    }))
}

fn indexer_finalized_hook(finalized_producer: FinalizedUploadProducer) -> ValidatorFinalizedHook {
    Arc::new(move |block, artifacts| {
        let height = block.header.height;
        let trace = block_span(height, "finalization");
        trace.record("block_digest", tracing::field::display(block.seal()));
        let capture = info_span!(parent: &trace, "indexer.capture", height);
        let block = EngineBlock::from(block.clone());
        let finalized_producer = finalized_producer.clone();
        Box::pin(
            async move { finalized_producer.enqueue(&block, artifacts, trace).await }
                .instrument(capture),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{
        FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES, IndexerConfig, StoreClientBuildError,
        maybe_build_indexer,
        queue::{FinalizedReceiptStore, capture_receipt},
    };
    use commonware_runtime::{Runner as _, Supervisor as _};
    use commonware_utils::NZUsize;
    use std::time::Duration;

    #[test]
    fn only_fresh_startup_waits_for_the_publisher_connection() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let indexer = IndexerConfig {
                store_url: "http://127.0.0.1:1".to_string(),
                api_key: None,
                publisher_rayon_threads: NZUsize!(2),
                upload_max_in_flight: 1,
                upload_budget_bytes: FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
            };

            // Remote namespaces must be validated as fresh before the first capture.
            let fresh = tokio::time::timeout(
                Duration::from_millis(500),
                maybe_build_indexer(
                    context.child("fresh"),
                    false,
                    Some(indexer.clone()),
                    "fresh",
                ),
            )
            .await;
            assert!(fresh.is_err(), "fresh startup must wait for validation");

            // A durable capture receipt means validation already happened.
            let (store, _) = FinalizedReceiptStore::open(context.child("seed"), "restart").await;
            store.persist(capture_receipt(1, 2, 2)).await;
            drop(store);
            tokio::time::timeout(
                Duration::from_secs(2),
                maybe_build_indexer(context.child("restart"), false, Some(indexer), "restart"),
            )
            .await
            .expect("publisher connection should not block restart")
            .expect("indexer Store client should build")
            .expect("secondary should keep indexer wiring");
        });
    }

    #[test]
    fn invalid_indexer_url_fails_secondary_startup() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let indexer = IndexerConfig {
                store_url: "http://invalid host".to_string(),
                api_key: None,
                publisher_rayon_threads: NZUsize!(2),
                upload_max_in_flight: 1,
                upload_budget_bytes: FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
            };
            let error = tokio::time::timeout(
                Duration::from_secs(2),
                maybe_build_indexer(context, false, Some(indexer), "test"),
            )
            .await
            .expect("invalid URL must not enter the connection retry loop")
            .err()
            .expect("invalid URL should fail startup");

            assert!(matches!(error, StoreClientBuildError::InvalidUrl { .. }));
        });
    }

    #[test]
    fn invalid_indexer_api_key_fails_secondary_startup() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let indexer = IndexerConfig {
                store_url: "http://127.0.0.1:1".to_string(),
                api_key: Some("invalid\nkey".to_string()),
                publisher_rayon_threads: NZUsize!(2),
                upload_max_in_flight: 1,
                upload_budget_bytes: FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
            };
            let error = tokio::time::timeout(
                Duration::from_secs(2),
                maybe_build_indexer(context, false, Some(indexer), "test"),
            )
            .await
            .expect("invalid API key must not enter the connection retry loop")
            .err()
            .expect("invalid API key should fail startup");

            assert!(matches!(error, StoreClientBuildError::InvalidApiKey));
        });
    }
}
