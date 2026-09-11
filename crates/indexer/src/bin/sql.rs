//! Metadata query/stream service for the shared indexer store.
//!
//! `metadata-indexer` exposes Constantinople's SQL metadata schema
//! (`block_meta`, `tx_meta`, `tx_activity`, and `account_meta`) over
//! `sql.v1.Service`. It supports both
//! direct local invocations (`--store-url`, `--port`) and commonware-deployer's
//! `--hosts ... --config ...` convention for remote bundles.

use axum::Router;
use constantinople_indexer::{
    adapter::{self, BoxError, Profile},
    namespaces::sql_meta_client,
    sql_schema::build_meta_schema,
};
use exoware_sdk::StoreClient;
use exoware_sql::{SqlServer, sql_connect_stack};
use std::sync::Arc;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

const PROFILE: Profile = Profile {
    name: "metadata-indexer",
    about: "SQL service over Constantinople metadata tables",
    default_port: 8091,
};

fn build_routes(client: &StoreClient) -> Result<Router, BoxError> {
    let client = sql_meta_client(client)?;
    let schema = build_meta_schema(client).map_err(|error| format!("configure schema: {error}"))?;
    let server = Arc::new(SqlServer::new(schema)?);
    Ok(Router::new().fallback_service(sql_connect_stack(server)))
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    adapter::main(PROFILE, build_routes).await
}

#[cfg(test)]
mod tests {
    use super::build_routes;
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use constantinople_indexer::store_client;
    use tower::ServiceExt;

    #[tokio::test]
    async fn serves_sql_routes() {
        let client = store_client("http://127.0.0.1:1", None).expect("client should build");
        let app = build_routes(&client).expect("routes should build");
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
