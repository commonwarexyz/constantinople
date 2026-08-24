use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderValue, header::AUTHORIZATION},
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use exoware_simulator::{AppState, RocksStore, connect_stack};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;

static STORE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub(crate) struct RequestObservation {
    pub path: String,
    pub authorized: bool,
}

#[derive(Clone)]
struct ObservationState {
    expected: HeaderValue,
    requests: Arc<Mutex<Vec<RequestObservation>>>,
}

pub(crate) struct ObservedStore {
    pub url: String,
    requests: Arc<Mutex<Vec<RequestObservation>>>,
    server: tokio::task::JoinHandle<()>,
}

impl ObservedStore {
    pub async fn open(
        expected_key: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let directory = TestDirectory::new()?;
        let engine = RocksStore::open_owned(directory, None).map_err(std::io::Error::other)?;
        let connect = connect_stack(AppState::new(Arc::new(engine)));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let expected = format!("Bearer {expected_key}").parse()?;
        let state = ObservationState {
            expected,
            requests: requests.clone(),
        };
        let app = Router::new()
            .route("/health", get(|| async { "ok" }))
            .fallback_service(connect)
            .layer(middleware::from_fn_with_state(state, observe_authorization));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Ok(Self {
            url,
            requests,
            server,
        })
    }

    pub fn requests(&self) -> Vec<RequestObservation> {
        self.requests.lock().expect("request lock poisoned").clone()
    }

    pub async fn shutdown(self) {
        self.server.abort();
        let _ = self.server.await;
    }
}

#[derive(Clone)]
struct IngestGateState {
    ingests: Arc<AtomicUsize>,
    first_ingest: Arc<Notify>,
    later_ingest: Arc<Notify>,
    release_first: Arc<Notify>,
}

pub(crate) struct GatedIngestStore {
    pub url: String,
    first_ingest: Arc<Notify>,
    later_ingest: Arc<Notify>,
    release_first: Arc<Notify>,
    server: tokio::task::JoinHandle<()>,
}

impl GatedIngestStore {
    pub async fn open() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let directory = TestDirectory::new()?;
        let engine = RocksStore::open_owned(directory, None).map_err(std::io::Error::other)?;
        let connect = connect_stack(AppState::new(Arc::new(engine)));
        let first_ingest = Arc::new(Notify::new());
        let later_ingest = Arc::new(Notify::new());
        let release_first = Arc::new(Notify::new());
        let state = IngestGateState {
            ingests: Arc::new(AtomicUsize::new(0)),
            first_ingest: first_ingest.clone(),
            later_ingest: later_ingest.clone(),
            release_first: release_first.clone(),
        };
        let app = Router::new()
            .route("/health", get(|| async { "ok" }))
            .fallback_service(connect)
            .layer(middleware::from_fn_with_state(state, gate_first_ingest));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Ok(Self {
            url,
            first_ingest,
            later_ingest,
            release_first,
            server,
        })
    }

    pub async fn wait_for_first_ingest(&self) {
        self.first_ingest.notified().await;
    }

    pub async fn later_ingest_arrives_within(&self, duration: Duration) -> bool {
        tokio::time::timeout(duration, self.later_ingest.notified())
            .await
            .is_ok()
    }

    pub fn release_first_ingest(&self) {
        self.release_first.notify_one();
    }

    pub async fn shutdown(self) {
        self.server.abort();
        let _ = self.server.await;
    }
}

async fn observe_authorization(
    State(state): State<ObservationState>,
    request: Request,
    next: Next,
) -> Response {
    let observation = RequestObservation {
        path: request.uri().path().to_string(),
        authorized: request.headers().get(AUTHORIZATION) == Some(&state.expected),
    };
    state
        .requests
        .lock()
        .expect("request lock poisoned")
        .push(observation);
    next.run(request).await
}

async fn gate_first_ingest(
    State(state): State<IngestGateState>,
    request: Request,
    next: Next,
) -> Response {
    if request.uri().path().starts_with("/log.ingest.v1.Service/") {
        let index = state.ingests.fetch_add(1, Ordering::SeqCst);
        if index == 0 {
            state.first_ingest.notify_one();
            state.release_first.notified().await;
        } else {
            state.later_ingest.notify_one();
        }
    }
    next.run(request).await
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> std::io::Result<Self> {
        let id = STORE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "constantinople-observed-store-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl AsRef<Path> for TestDirectory {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
