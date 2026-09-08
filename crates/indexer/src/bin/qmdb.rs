//! QMDB query facade for the shared indexer store.
//!
//! `qmdb-indexer` exposes the Store-backed QMDB indexes written by
//! validators. It serves the account-state operation log under `/state` and
//! transaction-hash history under `/transactions`.

use axum::{Router, middleware, routing::get};
use clap::Parser;
use commonware_codec::FixedSize;
use commonware_cryptography::sha256::Sha256;
use commonware_storage::{merkle::mmr, qmdb::any::value::FixedEncoding};
use commonware_utils::sequence::FixedBytes;
use constantinople_indexer::{
    adapter_metrics::{AdapterMetrics, serve_metrics, track_requests},
    namespaces::{state_qmdb_client, transactions_qmdb_client},
    require_store_ready, store_client,
};
use constantinople_primitives::{Account, AccountKey};
use exoware_qmdb::{
    KeylessClient, UnorderedClient, keyless_operation_log_connect_stack,
    unordered_operation_log_connect_stack,
};
use exoware_sdk::StoreClient;
use std::{net::SocketAddr, sync::Arc};
use tracing::info;

mod adapter_settings;

use adapter_settings::{AdapterArgs, Environment, Profile, Settings, load_settings};

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

const PROFILE: Profile = Profile {
    name: "qmdb-indexer",
    default_port: 8092,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type AccountValue = FixedBytes<{ Account::SIZE }>;
type StateClient =
    UnorderedClient<mmr::Family, Sha256, AccountKey, AccountValue, FixedEncoding<AccountValue>>;
type TransactionClient = KeylessClient<
    mmr::Family,
    Sha256,
    commonware_cryptography::sha256::Digest,
    FixedEncoding<commonware_cryptography::sha256::Digest>,
>;

#[derive(Parser, Debug)]
#[command(
    name = "qmdb-indexer",
    version,
    about = "QMDB service over Constantinople state and transaction indexes"
)]
struct Cli {
    #[command(flatten)]
    adapter: AdapterArgs,
}

async fn health() -> &'static str {
    "ok"
}

fn build_app(client: &StoreClient) -> Result<Router, BoxError> {
    let metrics = AdapterMetrics::new();
    let state = Arc::new(StateClient::new(state_qmdb_client(client)?, ()));
    let transactions = Arc::new(TransactionClient::new(
        transactions_qmdb_client(client)?,
        (),
    ));

    Ok(Router::new()
        .route("/health", get(health))
        .route("/ready", get(health))
        .route("/metrics", get(serve_metrics))
        .nest_service("/state", unordered_operation_log_connect_stack(state))
        .nest_service(
            "/transactions",
            keyless_operation_log_connect_stack(transactions),
        )
        .layer(tower_http::cors::CorsLayer::very_permissive())
        .layer(middleware::from_fn_with_state(
            metrics.clone(),
            track_requests,
        ))
        .with_state(metrics))
}

async fn run(settings: Settings) -> Result<(), BoxError> {
    let client = store_client(&settings.store_url, settings.api_key.as_deref())?;
    require_store_ready(&client).await?;
    let app = build_app(&client)?;
    let addr = SocketAddr::from((settings.host, settings.port));
    info!(%addr, store_url = settings.store_url, "constantinople QMDB server listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    init_tracing();
    let result = match load_settings(PROFILE, Cli::parse().adapter, Environment::read()) {
        Ok(settings) => run(settings).await,
        Err(error) => Err(Box::new(error).into()),
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("qmdb-indexer failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, build_app, store_client};
    use axum::{
        body::{Body, to_bytes},
        http::{Method, Request, StatusCode, header::CONTENT_TYPE},
    };
    use clap::Parser;
    use tower::ServiceExt;

    #[test]
    fn rejects_incomplete_deployer_pair() {
        assert!(Cli::try_parse_from(["qmdb-indexer", "--hosts", "hosts.yaml"]).is_err());
        assert!(Cli::try_parse_from(["qmdb-indexer", "--config", "config.yaml"]).is_err());
    }

    #[tokio::test]
    async fn app_serves_operational_routes_and_preserves_qmdb_routes() {
        let client = store_client("http://127.0.0.1:1", None).expect("client should build");
        let app = build_app(&client).expect("app should build");

        for path in ["/health", "/ready"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .body(Body::empty())
                        .expect("operational request"),
                )
                .await
                .expect("operational response");
            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), 16)
                .await
                .expect("operational body");
            assert_eq!(&body[..], b"ok");
        }

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .expect("metrics request"),
            )
            .await
            .expect("metrics response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).expect("content type"),
            "application/openmetrics-text; version=1.0.0; charset=utf-8"
        );

        for path in [
            "/state/qmdb.v1.OperationLogService/GetOperationRange",
            "/transactions/qmdb.v1.OperationLogService/GetOperationRange",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri(path)
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .expect("QMDB request"),
                )
                .await
                .expect("QMDB response");
            assert_ne!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }
}
