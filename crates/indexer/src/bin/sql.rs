//! Metadata query/stream service for the shared indexer store.
//!
//! `metadata-indexer` exposes Constantinople's SQL metadata schema
//! (`block_meta`, `tx_meta`, `tx_activity`, `account_meta`, and
//! `tx_proof_meta`) over
//! `sql.v1.Service`. It supports both
//! direct local invocations (`--store-url`, `--port`) and commonware-deployer's
//! `--hosts ... --config ...` convention for remote bundles.

use axum::{Router, middleware, routing::get};
use clap::Parser;
use constantinople_indexer::{
    adapter_metrics::{AdapterMetrics, serve_metrics, track_requests},
    namespaces::sql_meta_client,
    require_store_ready,
    sql_schema::build_meta_schema,
    store_client,
};
use exoware_sdk::StoreClient;
use exoware_sql::{SqlServer, sql_connect_stack};
use std::{net::SocketAddr, sync::Arc};
use tracing::info;

mod adapter_settings;

use adapter_settings::{AdapterArgs, Environment, Profile, Settings, load_settings};

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

const PROFILE: Profile = Profile {
    name: "metadata-indexer",
    default_port: 8091,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Parser, Debug)]
#[command(
    name = "metadata-indexer",
    version,
    about = "SQL service over Constantinople metadata tables"
)]
struct Cli {
    #[command(flatten)]
    adapter: AdapterArgs,
}

async fn health() -> &'static str {
    "ok"
}

fn build_server(client: &StoreClient) -> Result<Arc<SqlServer>, BoxError> {
    let client = sql_meta_client(client)?;
    let schema = build_meta_schema(client).map_err(|error| format!("configure schema: {error}"))?;
    let server = SqlServer::new(schema)?;
    Ok(Arc::new(server))
}

fn build_app(client: &StoreClient) -> Result<Router, BoxError> {
    let metrics = AdapterMetrics::new();
    let server = build_server(client)?;

    Ok(Router::new()
        .route("/health", get(health))
        .route("/ready", get(health))
        .route("/metrics", get(serve_metrics))
        .fallback_service(sql_connect_stack(server))
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
    info!(%addr, store_url = settings.store_url, "constantinople sql server listening");
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
            eprintln!("metadata-indexer failed: {error}");
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
        assert!(Cli::try_parse_from(["metadata-indexer", "--hosts", "hosts.yaml"]).is_err());
        assert!(Cli::try_parse_from(["metadata-indexer", "--config", "config.yaml"]).is_err());
    }

    #[tokio::test]
    async fn app_serves_operational_routes_and_preserves_sql_routes() {
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

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/sql.v1.Service/Tables")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("SQL request"),
            )
            .await
            .expect("SQL response");
        assert_ne!(response.status(), StatusCode::NOT_FOUND);
    }
}
