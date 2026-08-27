pub use exoware_sdk::ClientBuildError as StoreClientBuildError;
use exoware_sdk::{
    ClientError, ConnectRequestCompression, StoreClient, StoreClientBuilder,
    transport::BalancedHttp2Config,
};

/// Failure from the adapter's startup readiness check.
#[derive(Debug, thiserror::Error)]
pub enum StoreReadinessError {
    /// The Store answered the probe but did not report readiness.
    #[error("Store readiness probe returned a non-success response")]
    NotReady,
    /// The Store could not answer the probe.
    #[error("Store readiness probe failed")]
    Probe(#[source] ClientError),
}

/// Builds a Store client whose explicit key takes precedence over the SDK environment fallback.
pub fn store_client(
    url: &str,
    api_key: Option<&str>,
) -> Result<StoreClient, StoreClientBuildError> {
    store_client_builder(url, api_key).build()
}

/// Gives uploads path diversity so one slow connection does not serialize the
/// indexer, and compresses request bodies because writer commits carry multi-MB
/// row batches that would otherwise transit the wire raw. Read clients keep the
/// SDK default because their request bodies are small.
pub(crate) fn writer_store_client(
    url: &str,
    api_key: Option<&str>,
) -> Result<StoreClient, StoreClientBuildError> {
    store_client_builder(url, api_key)
        .balanced_http2_transport(BalancedHttp2Config::default())
        .connect_request_compression(ConnectRequestCompression::Zstd)
        .build()
}

pub(crate) fn writer_store_clients(
    url: &str,
    api_key: Option<&str>,
) -> Result<(StoreClient, StoreClient), StoreClientBuildError> {
    Ok((
        writer_store_client(url, api_key)?,
        writer_store_client(url, api_key)?,
    ))
}

fn store_client_builder(url: &str, api_key: Option<&str>) -> StoreClientBuilder {
    let builder = StoreClient::builder().url(url);
    match api_key {
        Some(api_key) => builder.api_key(api_key),
        None => builder,
    }
}

/// Requires one successful Store readiness response.
pub async fn require_store_ready(client: &StoreClient) -> Result<(), StoreReadinessError> {
    match client.ready().await {
        Ok(true) => Ok(()),
        Ok(false) => Err(StoreReadinessError::NotReady),
        Err(error) => Err(StoreReadinessError::Probe(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        StoreClientBuildError, StoreReadinessError, require_store_ready, store_client,
        writer_store_client, writer_store_clients,
    };
    use axum::{
        Router,
        extract::{ConnectInfo, State},
        http::{
            HeaderMap, StatusCode,
            header::{AUTHORIZATION, CONTENT_ENCODING},
        },
        routing::get,
    };
    use bytes::Bytes;
    use exoware_sdk::{API_KEY_ENV, PrefixedStoreClient, StoreClient};
    use std::{
        collections::HashSet,
        net::SocketAddr,
        process::{Command, Output},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::sync::mpsc;

    async fn readiness(
        State((status, requests)): State<(StatusCode, Arc<AtomicUsize>)>,
    ) -> StatusCode {
        requests.fetch_add(1, Ordering::SeqCst);
        status
    }

    async fn readiness_server(
        status: StatusCode,
    ) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let requests = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/ready", get(readiness))
            .with_state((status, requests.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("readiness listener should bind");
        let address = listener
            .local_addr()
            .expect("readiness listener should have an address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("readiness server should run");
        });

        (format!("http://{address}"), requests, task)
    }

    async fn capture_authorization(
        State(sender): State<mpsc::UnboundedSender<Option<String>>>,
        headers: HeaderMap,
    ) -> StatusCode {
        let authorization = headers.get(AUTHORIZATION).map(|value| {
            value
                .to_str()
                .expect("authorization should be ASCII")
                .to_string()
        });
        sender
            .send(authorization)
            .expect("authorization receiver should remain open");
        StatusCode::UNAUTHORIZED
    }

    async fn capture_content_encoding(
        State(sender): State<mpsc::UnboundedSender<Option<String>>>,
        headers: HeaderMap,
    ) -> StatusCode {
        let content_encoding = headers.get(CONTENT_ENCODING).map(|value| {
            value
                .to_str()
                .expect("content-encoding should be ASCII")
                .to_string()
        });
        sender
            .send(content_encoding)
            .expect("content-encoding receiver should remain open");
        StatusCode::UNAUTHORIZED
    }

    async fn capture_connection(
        ConnectInfo(address): ConnectInfo<SocketAddr>,
        State(connections): State<Arc<Mutex<HashSet<SocketAddr>>>>,
    ) -> StatusCode {
        connections
            .lock()
            .expect("connection set lock poisoned")
            .insert(address);
        tokio::time::sleep(Duration::from_millis(25)).await;
        StatusCode::UNAUTHORIZED
    }

    async fn send_concurrent_queries(client: StoreClient, marker: u8) {
        let queries = (0..64).map(|index| {
            let client = PrefixedStoreClient::empty(client.clone());
            async move {
                let key = Bytes::from(vec![marker, index]);
                let _ = client.query().get(&key).await;
            }
        });
        futures::future::join_all(queries).await;
    }

    async fn content_encoding_sent() -> Option<String> {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let app = Router::new()
            .fallback(capture_content_encoding)
            .with_state(sender);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("content-encoding listener should bind");
        let address = listener
            .local_addr()
            .expect("content-encoding listener should have an address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("content-encoding server should run");
        });
        let client = writer_store_client(&format!("http://{address}"), None)
            .expect("writer client should build");
        let client = PrefixedStoreClient::empty(client);
        // Stay above connectrpc's minimum-size compression policy (1 KiB) so
        // the header reflects a body that was actually compressed.
        let value = vec![0u8; 8192];
        let _ = client
            .ingest()
            .put(&[(&Bytes::from_static(b"key"), value.as_slice())])
            .await;
        let content_encoding = receiver
            .recv()
            .await
            .expect("content-encoding request should arrive");
        task.abort();
        content_encoding
    }

    async fn authorization_sent(api_key: Option<&str>) -> Option<String> {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let app = Router::new()
            .fallback(capture_authorization)
            .with_state(sender);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("authorization listener should bind");
        let address = listener
            .local_addr()
            .expect("authorization listener should have an address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("authorization server should run");
        });
        let client = store_client(&format!("http://{address}"), api_key)
            .expect("authorization client should build");
        let client = PrefixedStoreClient::empty(client);
        let _ = client.query().get(&Bytes::from_static(b"key")).await;
        let authorization = receiver
            .recv()
            .await
            .expect("authorization request should arrive");
        task.abort();
        authorization
    }

    fn run_in_child(case: &str, environment_key: Option<&str>) -> Output {
        let mut command = Command::new(std::env::current_exe().expect("test binary path"));
        command.args([case, "--exact", "--ignored", "--nocapture"]);
        match environment_key {
            Some(key) => {
                command.env(API_KEY_ENV, key);
            }
            None => {
                command.env_remove(API_KEY_ENV);
            }
        }
        command.output().expect("child test process should run")
    }

    fn assert_child_passes(case: &str, environment_key: Option<&str>) {
        let output = run_in_child(case, environment_key);
        assert!(
            output.status.success(),
            "{case} failed in a child process\nstdout\n{}\nstderr\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn builds_with_explicit_key() {
        store_client("https://store.example.com", Some("read-key"))
            .expect("explicit key should build");
    }

    #[test]
    fn rejects_invalid_explicit_key() {
        let error = store_client("https://store.example.com", Some("invalid\nkey"))
            .expect_err("invalid key should fail");

        assert!(matches!(error, StoreClientBuildError::InvalidApiKey));
    }

    #[tokio::test]
    async fn writer_client_builds_in_runtime() {
        writer_store_client("https://store.example.com", Some("write-key"))
            .expect("writer client should build");
    }

    #[tokio::test]
    async fn writer_client_compresses_put_bodies_on_the_wire() {
        assert_eq!(content_encoding_sent().await.as_deref(), Some("zstd"));
    }

    #[tokio::test]
    async fn writer_client_pair_uses_independent_connection_pools() {
        let connections = Arc::new(Mutex::new(HashSet::new()));
        let app = Router::new()
            .fallback(capture_connection)
            .with_state(connections.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("connection listener should bind");
        let address = listener
            .local_addr()
            .expect("connection listener should have an address");
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("connection server should run");
        });
        let (bulk, metadata) = writer_store_clients(&format!("http://{address}"), None)
            .expect("writer clients should build");

        tokio::join!(
            send_concurrent_queries(bulk, 0),
            send_concurrent_queries(metadata, 1)
        );
        let connection_count = connections
            .lock()
            .expect("connection set lock poisoned")
            .len();
        task.abort();
        assert!(connection_count > 4);
    }

    #[test]
    fn explicit_key_wins_over_environment_on_the_wire() {
        assert_child_passes(
            "store::tests::child_explicit_key_wins_over_environment_on_the_wire",
            Some("environment-key"),
        );
    }

    #[test]
    fn absent_key_sends_no_authorization_on_the_wire() {
        assert_child_passes(
            "store::tests::child_absent_key_sends_no_authorization_on_the_wire",
            None,
        );
    }

    #[tokio::test]
    #[ignore = "run by explicit_key_wins_over_environment_on_the_wire in a child process"]
    async fn child_explicit_key_wins_over_environment_on_the_wire() {
        assert_eq!(
            authorization_sent(Some("read-key")).await.as_deref(),
            Some("Bearer read-key")
        );
    }

    #[tokio::test]
    #[ignore = "run by absent_key_sends_no_authorization_on_the_wire in a child process"]
    async fn child_absent_key_sends_no_authorization_on_the_wire() {
        assert_eq!(authorization_sent(None).await, None);
    }

    #[tokio::test]
    async fn readiness_succeeds_after_exactly_one_probe() {
        let (url, requests, task) = readiness_server(StatusCode::OK).await;
        let client = store_client(&url, None).expect("client should build");

        require_store_ready(&client)
            .await
            .expect("Store should be ready");

        assert_eq!(requests.load(Ordering::SeqCst), 1);
        task.abort();
    }

    #[tokio::test]
    async fn readiness_rejects_non_success_after_exactly_one_probe() {
        let (url, requests, task) = readiness_server(StatusCode::SERVICE_UNAVAILABLE).await;
        let client = store_client(&url, None).expect("client should build");

        let error = require_store_ready(&client)
            .await
            .expect_err("Store should not be ready");

        assert!(matches!(error, StoreReadinessError::NotReady));
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        task.abort();
    }

    #[tokio::test]
    async fn readiness_rejects_transport_errors() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("temporary listener should bind");
        let address = listener
            .local_addr()
            .expect("temporary listener should have an address");
        drop(listener);
        let client = store_client(&format!("http://{address}"), None)
            .expect("client should build for a closed address");

        let error = require_store_ready(&client)
            .await
            .expect_err("closed address should fail");

        assert!(matches!(error, StoreReadinessError::Probe(_)));
    }
}
