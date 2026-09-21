//! Shared startup and HTTP serving for Store-backed read adapters.

use crate::{
    adapter_metrics::{AdapterMetrics, serve_metrics, track_requests},
    require_store_ready, store_client,
};
use axum::{Router, middleware, routing::get};
use clap::{CommandFactory, FromArgMatches, Parser};
use exoware_sdk::StoreClient;
use settings::{AdapterArgs, Environment, Settings, load_settings};
use std::{net::SocketAddr, process::ExitCode};
use tracing::info;

mod settings;

/// Errors from adapter configuration, startup, or serving.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// CLI identity and defaults for an adapter binary.
#[derive(Clone, Copy)]
pub struct Profile {
    /// Command name displayed in help and errors.
    pub name: &'static str,
    /// Command description displayed in help.
    pub about: &'static str,
    /// Listen port when no configured value is available.
    pub default_port: u16,
}

#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    #[command(flatten)]
    adapter: AdapterArgs,
}

fn command(profile: Profile) -> clap::Command {
    Cli::command().name(profile.name).about(profile.about)
}

async fn health() -> &'static str {
    "ok"
}

fn metrics_app(metrics: AdapterMetrics) -> Router {
    Router::new()
        .route("/metrics", get(serve_metrics))
        .with_state(metrics)
}

fn build_app(routes: Router, metrics: AdapterMetrics, shared_metrics: bool) -> Router {
    // Readiness records successful startup, even if Store later becomes unavailable.
    let mut app = routes
        .route("/health", get(health))
        .route("/ready", get(health));
    if shared_metrics {
        app = app.merge(metrics_app(metrics.clone()));
    }

    // CORS must be outermost so preflight requests bypass request accounting.
    app.layer(middleware::from_fn_with_state(metrics, track_requests))
        .layer(tower_http::cors::CorsLayer::very_permissive())
}

async fn serve(
    profile: Profile,
    settings: Settings,
    routes: impl FnOnce(&StoreClient) -> Result<Router, BoxError>,
) -> Result<(), BoxError> {
    let client = store_client(&settings.store_url, settings.api_key.as_deref())?;
    require_store_ready(&client).await?;
    let metrics = AdapterMetrics::new();
    let app = build_app(
        routes(&client)?,
        metrics.clone(),
        settings.metrics_port.is_none(),
    );
    let addr = SocketAddr::from((settings.host, settings.port));
    info!(adapter = profile.name, %addr, store_url = settings.store_url, "constantinople adapter listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    if let Some(port) = settings.metrics_port {
        let metrics_listener =
            tokio::net::TcpListener::bind(SocketAddr::from((settings.host, port))).await?;
        let metrics_app = metrics_app(metrics);
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

/// Parses adapter arguments and serves the supplied routes after Store is ready.
pub async fn main(
    profile: Profile,
    routes: impl FnOnce(&StoreClient) -> Result<Router, BoxError>,
) -> ExitCode {
    init_tracing();
    let args = Cli::from_arg_matches(&command(profile).get_matches())
        .unwrap_or_else(|error| error.exit())
        .adapter;
    let result = match load_settings(profile, args, Environment::read()) {
        Ok(settings) => serve(profile, settings, routes).await,
        Err(error) => Err(Box::new(error).into()),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{} failed: {error}", profile.name);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AdapterMetrics, Profile, build_app, command, metrics_app};
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Method, Request, StatusCode, header::CONTENT_TYPE},
        response::Response,
        routing::get,
    };
    use tower::ServiceExt;

    const PROFILE: Profile = Profile {
        name: "test-adapter",
        about: "Test adapter service",
        default_port: 8091,
    };

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
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).expect("content type"),
            "application/openmetrics-text; version=1.0.0; charset=utf-8"
        );
        let body = to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("metrics body");
        String::from_utf8(body.to_vec()).expect("metrics text")
    }

    #[test]
    fn cli_preserves_profile_identity_and_defaults() {
        let mut command = command(PROFILE);
        assert_eq!(command.get_name(), PROFILE.name);
        assert_eq!(command.get_version(), Some(env!("CARGO_PKG_VERSION")));
        assert_eq!(
            command.get_about().expect("about").to_string(),
            PROFILE.about
        );
        let help = command.render_help().to_string();
        assert!(help.contains("Usage: test-adapter [OPTIONS]"), "{help}");
        assert!(help.contains("[default: 0.0.0.0]"), "{help}");
    }

    #[test]
    fn rejects_incomplete_deployer_pair() {
        for flag in ["--hosts", "--config"] {
            assert!(
                command(PROFILE)
                    .try_get_matches_from([PROFILE.name, flag, "file.yaml"])
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn operational_routes_preserve_fallback_and_exclude_metrics() {
        let routes = Router::new().fallback(|| async { StatusCode::IM_A_TEAPOT });
        let app = build_app(routes, AdapterMetrics::new(), true);
        for path in ["/health", "/ready"] {
            let response = send_get(app.clone(), path).await;
            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), 16)
                .await
                .expect("operational body");
            assert_eq!(&body[..], b"ok");
        }
        let output = metrics_text(app.clone()).await;
        assert!(output.contains("adapter_requests_total 0\n"), "{output}");

        let response = send_get(app.clone(), "/fallback").await;
        assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
        drop(response);
        let output = metrics_text(app).await;
        assert!(output.contains("adapter_requests_total 1\n"), "{output}");
    }

    #[tokio::test]
    async fn separate_metrics_and_cors_preserve_request_counts() {
        let metrics = AdapterMetrics::new();
        let routes = Router::new().route("/query", get(|| async { "response" }));
        let app = build_app(routes, metrics.clone(), false);
        let metrics_app = metrics_app(metrics);
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
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            "https://explorer.example.com"
        );
        drop(response);

        let response = send_get(app.clone(), "/metrics").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        drop(response);
        let response = send_get(metrics_app.clone(), "/query").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        drop(response);

        let response = send_get(app, "/query").await;
        let output = metrics_text(metrics_app.clone()).await;
        assert!(output.contains("adapter_requests_total 1\n"), "{output}");
        assert!(
            output.contains("adapter_requests_in_flight 1\n"),
            "{output}"
        );
        drop(response);

        let output = metrics_text(metrics_app).await;
        assert!(output.contains("adapter_requests_total 1\n"), "{output}");
        assert!(
            output.contains("adapter_requests_in_flight 0\n"),
            "{output}"
        );
    }
}
