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
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    sync::{Notify, Semaphore},
    task::JoinHandle,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

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
    server: JoinHandle<()>,
}

impl ObservedStore {
    pub async fn open(expected_key: &str) -> Result<Self, BoxError> {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let state = ObservationState {
            expected: format!("Bearer {expected_key}").parse()?,
            requests: requests.clone(),
        };
        let (url, server) =
            serve(|app| app.layer(middleware::from_fn_with_state(state, observe_authorization)))
                .await?;
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
struct IngestGate {
    gated: Range<usize>,
    ingests: Arc<AtomicUsize>,
    arrived: Arc<Notify>,
    release: Arc<Semaphore>,
}

/// Holds Store ingests whose zero-based arrival index is in the gated range.
pub(crate) struct GatedIngestStore {
    pub url: String,
    gate: IngestGate,
    server: JoinHandle<()>,
}

impl GatedIngestStore {
    pub async fn open(gated: Range<usize>) -> Result<Self, BoxError> {
        let gate = IngestGate {
            gated,
            ingests: Arc::default(),
            arrived: Arc::default(),
            release: Arc::new(Semaphore::new(0)),
        };
        let state = gate.clone();
        let (url, server) =
            serve(|app| app.layer(middleware::from_fn_with_state(state, gate_ingest))).await?;
        Ok(Self { url, gate, server })
    }

    /// Wait until at least `count` ingests have arrived, gated or not.
    pub async fn wait_for_ingests(&self, count: usize) {
        while self.gate.ingests.load(Ordering::SeqCst) < count {
            self.gate.arrived.notified().await;
        }
    }

    /// Let one held ingest proceed.
    pub fn release_ingest(&self) {
        self.gate.release.add_permits(1);
    }

    pub async fn shutdown(self) {
        self.server.abort();
        let _ = self.server.await;
    }
}

async fn serve(wrap: impl FnOnce(Router) -> Router) -> Result<(String, JoinHandle<()>), BoxError> {
    let engine =
        RocksStore::open_owned(tempfile::tempdir()?, None).map_err(std::io::Error::other)?;
    let app = wrap(
        Router::new()
            .route("/health", get(|| async { "ok" }))
            .fallback_service(connect_stack(AppState::new(Arc::new(engine)))),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((url, server))
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

async fn gate_ingest(State(gate): State<IngestGate>, request: Request, next: Next) -> Response {
    if request.uri().path().starts_with("/log.ingest.v1.Service/") {
        let index = gate.ingests.fetch_add(1, Ordering::SeqCst);
        gate.arrived.notify_one();
        if gate.gated.contains(&index) {
            gate.release.acquire().await.unwrap().forget();
        }
    }
    next.run(request).await
}
