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
    ops::Range,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Notify, Semaphore};

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
    gated_indices: Range<usize>,
    ingest_arrived: Arc<Notify>,
    first_ingest: Arc<Notify>,
    later_ingest: Arc<Notify>,
    release_ingest: Arc<Semaphore>,
}

pub(crate) struct GatedIngestStore {
    pub url: String,
    ingests: Arc<AtomicUsize>,
    ingest_arrived: Arc<Notify>,
    first_ingest: Arc<Notify>,
    later_ingest: Arc<Notify>,
    release_ingest: Arc<Semaphore>,
    server: tokio::task::JoinHandle<()>,
}

impl GatedIngestStore {
    pub async fn open() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::open_gating_ingest(0).await
    }

    pub async fn open_gating_ingest(
        gated_index: usize,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::open_gating_ingests(gated_index..gated_index + 1).await
    }

    pub async fn open_gating_ingests(
        gated_indices: Range<usize>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let directory = TestDirectory::new()?;
        let engine = RocksStore::open_owned(directory, None).map_err(std::io::Error::other)?;
        let connect = connect_stack(AppState::new(Arc::new(engine)));
        let first_ingest = Arc::new(Notify::new());
        let later_ingest = Arc::new(Notify::new());
        let ingests = Arc::new(AtomicUsize::new(0));
        let ingest_arrived = Arc::new(Notify::new());
        let release_ingest = Arc::new(Semaphore::new(0));
        let state = IngestGateState {
            ingests: ingests.clone(),
            gated_indices,
            ingest_arrived: ingest_arrived.clone(),
            first_ingest: first_ingest.clone(),
            later_ingest: later_ingest.clone(),
            release_ingest: release_ingest.clone(),
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
            ingests,
            ingest_arrived,
            first_ingest,
            later_ingest,
            release_ingest,
            server,
        })
    }

    pub async fn wait_for_first_ingest(&self) {
        self.first_ingest.notified().await;
    }

    pub async fn wait_for_ingests(&self, count: usize) {
        while self.ingests.load(Ordering::SeqCst) < count {
            self.ingest_arrived.notified().await;
        }
    }

    pub async fn later_ingest_arrives_within(&self, duration: Duration) -> bool {
        tokio::time::timeout(duration, self.later_ingest.notified())
            .await
            .is_ok()
    }

    pub fn release_first_ingest(&self) {
        self.release_ingest.add_permits(1);
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
        state.ingest_arrived.notify_one();
        if index == state.gated_indices.start {
            state.first_ingest.notify_one();
        } else if index > state.gated_indices.start {
            state.later_ingest.notify_one();
        }
        if state.gated_indices.contains(&index) {
            state.release_ingest.acquire().await.unwrap().forget();
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
