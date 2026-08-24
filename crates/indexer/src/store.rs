pub use exoware_sdk::ClientBuildError as StoreClientBuildError;
use exoware_sdk::{ClientError, StoreClient};

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
    let builder = StoreClient::builder().url(url);
    match api_key {
        Some(api_key) => builder.api_key(api_key).build(),
        None => builder.build(),
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
    use super::{StoreClientBuildError, StoreReadinessError, require_store_ready, store_client};
    use axum::{
        Router,
        extract::State,
        http::{HeaderMap, StatusCode, header::AUTHORIZATION},
        routing::get,
    };
    use bytes::Bytes;
    use exoware_sdk::{API_KEY_ENV, PrefixedStoreClient};
    use std::{
        process::{Command, Output},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
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
