//! Shared HTTP metrics for the read adapters.

use axum::{
    body::Body,
    extract::{Request, State},
    http::header::CONTENT_TYPE,
    middleware::Next,
    response::Response,
};
use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use prometheus_client::{
    encoding::text::encode,
    metrics::{counter::Counter, gauge::Gauge, histogram::Histogram},
    registry::Registry,
};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

const RESPONSE_START_BUCKETS: [f64; 10] =
    [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1.0, 5.0, 30.0];
const METRICS_CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// HTTP metrics shared by the metadata and QMDB adapters.
#[derive(Clone, Debug)]
pub struct AdapterMetrics {
    registry: Arc<Registry>,
    requests: Counter,
    non_success_responses: Counter,
    response_start: Histogram,
    in_flight: Gauge,
}

impl AdapterMetrics {
    /// Creates an independent registry for one adapter process.
    pub fn new() -> Self {
        let requests = Counter::default();
        let non_success_responses = Counter::default();
        let response_start = Histogram::new(RESPONSE_START_BUCKETS);
        let in_flight = Gauge::default();
        let mut registry = Registry::default();

        registry.register(
            "adapter_requests",
            "Adapter HTTP requests received",
            requests.clone(),
        );
        registry.register(
            "adapter_non_success_responses",
            "Adapter HTTP responses outside the 2xx range",
            non_success_responses.clone(),
        );
        registry.register(
            "adapter_response_start_seconds",
            "Time until adapter response headers are available",
            response_start.clone(),
        );
        registry.register(
            "adapter_requests_in_flight",
            "Adapter HTTP requests whose bodies are still open",
            in_flight.clone(),
        );

        Self {
            registry: Arc::new(registry),
            requests,
            non_success_responses,
            response_start,
            in_flight,
        }
    }
}

impl Default for AdapterMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Encodes this adapter's metrics in OpenMetrics text format.
pub async fn serve_metrics(State(metrics): State<AdapterMetrics>) -> Response {
    let mut output = String::new();
    encode(&mut output, &metrics.registry).expect("metrics encoding cannot fail");

    Response::builder()
        .header(CONTENT_TYPE, METRICS_CONTENT_TYPE)
        .body(Body::from(output))
        .expect("static metrics response should build")
}

fn excluded(path: &str) -> bool {
    matches!(path, "/health" | "/ready" | "/metrics")
}

/// Records request metrics while leaving operational endpoints untracked.
pub async fn track_requests(
    State(metrics): State<AdapterMetrics>,
    request: Request,
    next: Next,
) -> Response {
    if excluded(request.uri().path()) {
        return next.run(request).await;
    }

    metrics.requests.inc();
    metrics.in_flight.inc();
    let guard = InFlightGuard(metrics.in_flight.clone());
    let started = Instant::now();
    let response = next.run(request).await;

    metrics
        .response_start
        .observe(started.elapsed().as_secs_f64());
    if !response.status().is_success() {
        metrics.non_success_responses.inc();
    }

    let (parts, body) = response.into_parts();
    Response::from_parts(parts, Body::new(TrackedBody::new(body, guard)))
}

#[derive(Debug)]
struct InFlightGuard(Gauge);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.dec();
    }
}

#[derive(Debug)]
struct TrackedBody {
    inner: Body,
    guard: Option<InFlightGuard>,
}

impl TrackedBody {
    const fn new(inner: Body, guard: InFlightGuard) -> Self {
        Self {
            inner,
            guard: Some(guard),
        }
    }
}

impl HttpBody for TrackedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let poll = Pin::new(&mut self.inner).poll_frame(context);
        if poll.is_ready() && matches!(poll, Poll::Ready(None)) {
            self.guard.take();
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::{AdapterMetrics, serve_metrics, track_requests};
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode, header::CONTENT_TYPE},
        middleware,
        response::Response,
        routing::get,
    };
    use bytes::Bytes;
    use futures::{StreamExt, stream};
    use std::convert::Infallible;
    use tower::ServiceExt;

    async fn streaming_body() -> Response {
        let body = stream::iter([Ok::<_, Infallible>(Bytes::from_static(b"chunk"))]);
        Response::new(Body::from_stream(body))
    }

    async fn pending_body() -> Response {
        let body = stream::pending::<Result<Bytes, Infallible>>();
        Response::new(Body::from_stream(body))
    }

    fn app(metrics: AdapterMetrics) -> Router {
        Router::new()
            .route("/health", get(|| async { "ok" }))
            .route("/ready", get(|| async { "ok" }))
            .route("/metrics", get(serve_metrics))
            .route("/error", get(|| async { StatusCode::BAD_GATEWAY }))
            .route("/stream", get(streaming_body))
            .route("/pending", get(pending_body))
            .layer(middleware::from_fn_with_state(
                metrics.clone(),
                track_requests,
            ))
            .with_state(metrics)
    }

    async fn send_get(app: Router, path: &str) -> Response {
        app.oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should succeed")
    }

    async fn metrics_text(app: Router) -> String {
        let response = send_get(app, "/metrics").await;
        assert_eq!(
            response.headers().get(CONTENT_TYPE).expect("content type"),
            "application/openmetrics-text; version=1.0.0; charset=utf-8"
        );
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("metrics body should read");
        String::from_utf8(body.to_vec()).expect("metrics should be UTF-8")
    }

    #[tokio::test]
    async fn operational_paths_are_excluded_exactly() {
        let metrics = AdapterMetrics::new();
        let app = app(metrics);

        for path in ["/health", "/ready", "/metrics"] {
            let response = send_get(app.clone(), path).await;
            assert_eq!(response.status(), StatusCode::OK);
        }

        let output = metrics_text(app.clone()).await;
        assert!(output.contains("adapter_requests_total 0"));
        assert!(output.contains("adapter_non_success_responses_total 0"));
        assert!(output.contains("adapter_response_start_seconds_count 0"));
        assert!(output.contains("adapter_requests_in_flight 0"));

        let response = send_get(app.clone(), "/health/").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        drop(response);

        let output = metrics_text(app).await;
        assert!(output.contains("adapter_requests_total 1"));
        assert!(output.contains("adapter_non_success_responses_total 1"));
    }

    #[tokio::test]
    async fn non_success_response_records_request_error_and_latency() {
        let metrics = AdapterMetrics::new();
        let app = app(metrics);

        let response = send_get(app.clone(), "/error").await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        drop(response);

        let output = metrics_text(app).await;
        assert!(output.contains("adapter_requests_total 1"));
        assert!(output.contains("adapter_non_success_responses_total 1"));
        assert!(output.contains("adapter_response_start_seconds_count 1"));
        assert!(output.contains("adapter_requests_in_flight 0"));
    }

    #[tokio::test]
    async fn in_flight_follows_stream_until_eof_or_drop() {
        let metrics = AdapterMetrics::new();
        let app = app(metrics.clone());

        let response = send_get(app.clone(), "/stream").await;
        assert_eq!(metrics.in_flight.get(), 1);
        let mut body = response.into_body().into_data_stream();
        assert_eq!(
            body.next().await.expect("first frame").expect("data frame"),
            Bytes::from_static(b"chunk")
        );
        assert_eq!(metrics.in_flight.get(), 1);
        assert!(body.next().await.is_none());
        assert_eq!(metrics.in_flight.get(), 0);

        let response = send_get(app, "/pending").await;
        assert_eq!(metrics.in_flight.get(), 1);
        drop(response);
        assert_eq!(metrics.in_flight.get(), 0);
    }
}
