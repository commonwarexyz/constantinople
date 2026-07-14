//! Metadata query/stream service for the shared indexer store.
//!
//! `metadata-indexer` exposes Constantinople's SQL metadata schema
//! (`block_meta`, `tx_meta`, `tx_activity`, and `account_meta`) over
//! `store.sql.v1.Service`. It supports both
//! direct local invocations (`--store-url`, `--port`) and commonware-deployer's
//! `--hosts ... --config ...` convention for remote bundles.

use axum::{Router, routing::get};
use clap::Parser;
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
struct Cli {
    #[command(flatten)]
    facade: facade::Args,
    /// Listen port.
    #[arg(long, default_value_t = 8091)]
    port: u16,
}

fn build_app(store_url: &str) -> Result<Router, facade::Error> {
    let client = StoreClient::new(store_url);
    let schema = build_meta_schema(client).map_err(|e| format!("configure schema: {e}"))?;
    let server = Arc::new(SqlServer::new(schema)?);
    // The explorer hits this server from a browser; allow any origin so
    // local dev (Vite on a different port) can connect without a proxy.
    Ok(Router::new()
        .route("/health", get(facade::health))
        .fallback_service(sql_connect_stack(server))
        .layer(tower_http::cors::CorsLayer::very_permissive()))
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    facade::run(cli.facade, cli.port, "metadata-indexer", build_app).await
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
