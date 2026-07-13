//! Metadata query/stream service for the shared indexer store.
//!
//! `metadata-indexer` exposes Constantinople's SQL metadata schema
//! (`block_meta`, `tx_meta`, `tx_activity`, and `account_meta`) over
//! `store.sql.v1.Service`. It supports both
//! direct local invocations (`--store-url`, `--port`) and commonware-deployer's
//! `--hosts ... --config ...` convention for remote bundles.

use axum::{Router, routing::get};
use clap::{ArgGroup, Parser};
use constantinople_indexer::{facade, sql_schema::build_meta_schema};
use exoware_sdk::StoreClient;
use exoware_sql::{SqlServer, sql_connect_stack};
use std::sync::Arc;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser, Debug)]
#[command(
    name = "metadata-indexer",
    version,
    about = "SQL service over Constantinople metadata tables"
)]
#[command(group(
    ArgGroup::new("mode")
        .required(true)
        .args(["store_url", "hosts"])
))]
struct Cli {
    #[command(flatten)]
    facade: facade::Args,
    /// Listen port.
    #[arg(long, default_value_t = 8091)]
    port: u16,
}

fn build_server(store_url: &str) -> Result<Arc<SqlServer>, facade::Error> {
    let client = StoreClient::new(store_url);
    let schema = build_meta_schema(client).map_err(|e| format!("configure schema: {e}"))?;
    let server = SqlServer::new(schema)?;
    Ok(Arc::new(server))
}

fn build_app(store_url: &str) -> Result<Router, facade::Error> {
    let server = build_server(store_url)?;
    // The explorer hits this server from a browser; allow any origin so
    // local dev (Vite on a different port) can connect without a proxy.
    Ok(Router::new()
        .route("/health", get(facade::health))
        .fallback_service(sql_connect_stack(server))
        .layer(tower_http::cors::CorsLayer::very_permissive()))
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    facade::init_tracing();
    let cli = Cli::parse();
    let settings = facade::load_settings(cli.facade, cli.port);
    let result = match build_app(&settings.store_url) {
        Ok(app) => facade::serve(app, &settings, "metadata-indexer").await,
        Err(err) => Err(err),
    };
    facade::exit(result, "metadata-indexer")
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::Parser;

    #[test]
    fn uses_metadata_default_port() {
        let cli = Cli::try_parse_from(["metadata-indexer", "--store-url", "http://localhost"])
            .expect("local invocation should parse");

        assert_eq!(cli.port, 8_091);
    }
}
