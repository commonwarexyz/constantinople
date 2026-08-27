//! Telemetry initialization for the io_uring validator runtime.
//!
//! Mirrors `commonware_runtime::tokio::telemetry::init`, with one structural
//! difference: the `/metrics` endpoint is served by the sidecar tokio runtime
//! (axum needs a tokio reactor), while metric encoding happens on the
//! consensus runtime through a channel bridge. The bridge keeps metric
//! collection with the runtime that owns the registry and sends only encoded
//! text to the HTTP sidecar.

use axum::{
    Router,
    body::Body,
    http::{Response, StatusCode, header},
    routing::get,
    serve,
};
use commonware_runtime::{
    Metrics, Spawner, Supervisor,
    tokio::{
        telemetry::Logs,
        tracing::{Config as TracesConfig, export},
    },
};
use std::net::SocketAddr;
use tokio::sync::{mpsc, oneshot};
use tracing_subscriber::{Layer, Registry, filter::filter_fn, layer::SubscriberExt};

/// Buffered `/metrics` scrapes; excess scrapes see 503 instead of queueing.
///
/// Kept minimal: each buffered scrape is a full registry encode executed on
/// the consensus thread, so a scrape burst must shed load rather than queue
/// consecutive encodes there.
const METRICS_SCRAPE_BUFFER: usize = 1;

/// Initialize telemetry with the given configuration.
///
/// `context` must be a child of the consensus runtime's context; a task
/// spawned on it answers metric-encoding requests. `sidecar` hosts the
/// metrics HTTP server and the OTLP trace exporter.
///
/// If `metrics` is provided, serves metrics at the given address at
/// `/metrics`. If `traces` is provided, enables OpenTelemetry trace export.
pub fn init<C>(
    context: C,
    sidecar: tokio::runtime::Handle,
    logs: Logs,
    metrics: Option<SocketAddr>,
    traces: Option<TracesConfig>,
) where
    C: Spawner + Supervisor + Metrics,
{
    // Create fmt layer for logging
    let log_layer = tracing_subscriber::fmt::layer()
        .with_line_number(true)
        .with_thread_ids(true)
        .with_file(true);

    // Set the format to JSON (if specified)
    let log_layer = if logs.json {
        log_layer.json().boxed()
    } else {
        log_layer.compact().boxed()
    };
    let log_layer = match &traces {
        None => log_layer
            .with_filter(filter_fn(move |metadata| {
                metadata.is_event() && *metadata.level() <= logs.level
            }))
            .boxed(),
        Some(_) => log_layer
            .with_filter(tracing_subscriber::EnvFilter::new(logs.level.to_string()))
            .boxed(),
    };

    // Create OpenTelemetry layer for tracing. The exporter is built inside the
    // sidecar runtime so any tokio facilities it needs are available.
    let trace_layer = traces.map(|cfg| {
        let _guard = sidecar.enter();
        let tracer = export(cfg).expect("Failed to initialize tracer");
        tracing_opentelemetry::layer()
            .with_tracer(tracer)
            .with_filter(tracing_subscriber::EnvFilter::new(logs.level.to_string()))
    });

    // Set the global subscriber
    let registry = Registry::default().with(log_layer).with(trace_layer);
    tracing::subscriber::set_global_default(registry).expect("Failed to set subscriber");

    // Expose metrics over HTTP
    let Some(cfg) = metrics else {
        return;
    };

    // Encoding runs on the consensus runtime, which owns the context; the
    // sidecar only ever sees the encoded string.
    let (encode_tx, mut encode_rx) =
        mpsc::channel::<oneshot::Sender<String>>(METRICS_SCRAPE_BUFFER);
    let watcher = context.child("watch");
    context.spawn(move |context| async move {
        while let Some(reply) = encode_rx.recv().await {
            let _ = reply.send(context.encode());
        }
    });

    let server = sidecar.spawn(async move {
        let listener = tokio::net::TcpListener::bind(cfg)
            .await
            .expect("Failed to bind metrics server");

        let app = Router::new().route(
            "/metrics",
            get(move || {
                let encode_tx = encode_tx.clone();
                async move {
                    let (reply_tx, reply_rx) = oneshot::channel();
                    if encode_tx.try_send(reply_tx).is_err() {
                        return Err(StatusCode::SERVICE_UNAVAILABLE);
                    }
                    let Ok(encoded) = reply_rx.await else {
                        return Err(StatusCode::SERVICE_UNAVAILABLE);
                    };
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
                        .body(Body::from(encoded))
                        .expect("Failed to create response"))
                }
            }),
        );

        serve(listener, app.into_make_service())
            .await
            .expect("Could not serve metrics");
    });

    // The sidecar swallows panics in its tasks; watching the server's join
    // handle from the consensus runtime restores fail-fast behavior (a bind
    // failure or server exit takes the validator down, as it did when the
    // server was a supervised runtime task).
    watcher.spawn(move |_| async move {
        let exit = server.await;
        panic!("metrics server exited: {exit:?}");
    });
}
