//! Metadata query/stream service for the shared indexer store.
//!
//! `metadata-indexer` exposes Constantinople's SQL metadata schema
//! (`block_meta`, `tx_meta`, `tx_activity`, and `account_meta`) over
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

fn build_app(
    client: &StoreClient,
    metrics: AdapterMetrics,
    shared_metrics: bool,
) -> Result<Router, BoxError> {
    let server = build_server(client)?;

    let mut app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(health))
        .fallback_service(sql_connect_stack(server));
    if shared_metrics {
        app = app.route("/metrics", get(serve_metrics));
    }

    Ok(app
        .layer(middleware::from_fn_with_state(
            metrics.clone(),
            track_requests,
        ))
        .layer(tower_http::cors::CorsLayer::very_permissive())
        .with_state(metrics))
}

async fn run(settings: Settings) -> Result<(), BoxError> {
    let client = store_client(&settings.store_url, settings.api_key.as_deref())?;
    require_store_ready(&client).await?;
    let metrics = AdapterMetrics::new();
    let app = build_app(&client, metrics.clone(), settings.metrics_port.is_none())?;
    let addr = SocketAddr::from((settings.host, settings.port));
    info!(%addr, store_url = settings.store_url, "constantinople sql server listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    if let Some(port) = settings.metrics_port {
        let metrics_listener =
            tokio::net::TcpListener::bind(SocketAddr::from((settings.host, port))).await?;
        let metrics_app = Router::new()
            .route("/metrics", get(serve_metrics))
            .with_state(metrics);
        tokio::try_join!(async { axum::serve(listener, app).await }, async {
            axum::serve(metrics_listener, metrics_app).await
        },)?;
    } else {
        axum::serve(listener, app).await?;
    }
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
    use super::{AdapterMetrics, Cli, build_app, store_client};
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
        let app = build_app(&client, AdapterMetrics::new(), true).expect("app should build");

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
    #[tokio::test]
    async fn separate_metrics_and_cors_preserve_request_counts() {
        let client = store_client("http://127.0.0.1:1", None).expect("client should build");
        let metrics = AdapterMetrics::new();
        let app = build_app(&client, metrics.clone(), false).expect("app should build");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/query")
                    .header("origin", "https://explorer.example.com")
                    .header("access-control-request-method", "POST")
                    .body(Body::empty())
                    .expect("preflight request"),
            )
            .await
            .expect("preflight response");
        assert!(response.status().is_success());

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
        assert!(!response.status().is_success());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/missing")
                    .body(Body::empty())
                    .expect("missing request"),
            )
            .await
            .expect("missing response");
        drop(response);

        let response = super::serve_metrics(axum::extract::State(metrics)).await;
        let body = to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("metrics body");
        let body = String::from_utf8(body.to_vec()).expect("metrics text");
        assert!(body.contains("adapter_requests_total 1\n"), "{body}");
        assert!(body.contains("adapter_requests_in_flight 0\n"), "{body}");
    }
}
