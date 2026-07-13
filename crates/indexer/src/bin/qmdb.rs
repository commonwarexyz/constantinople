//! QMDB query facade for the shared indexer store.
//!
//! `qmdb-indexer` exposes the Store-backed QMDB indexes written by
//! validators. It serves the account-state operation log under `/state` and
//! transaction-hash history under `/transactions`.

use axum::{Router, routing::get};
use clap::Parser;
use commonware_codec::FixedSize;
use commonware_cryptography::sha256::Sha256;
use commonware_storage::{merkle::mmr, qmdb::any::value::FixedEncoding};
use commonware_utils::sequence::FixedBytes;
use constantinople_indexer::{
    facade,
    publisher::qmdb::{state_qmdb_client, transactions_qmdb_client},
};
use constantinople_primitives::{Account, AccountKey};
use exoware_qmdb::{
    KeylessClient, UnorderedClient, keyless_operation_log_connect_stack,
    unordered_operation_log_connect_stack,
};
use exoware_sdk::StoreClient;
use std::sync::Arc;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

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
    facade: facade::Args,
    /// Listen port.
    #[arg(long, default_value_t = 8092)]
    port: u16,
}

fn build_app(store_url: &str) -> Result<Router, facade::Error> {
    let base = StoreClient::new(store_url);
    let state = Arc::new(StateClient::from_client(state_qmdb_client(&base)?, ()));
    let transactions = Arc::new(TransactionClient::from_client(
        transactions_qmdb_client(&base)?,
        (),
    ));

    Ok(Router::new()
        .route("/health", get(facade::health))
        .nest_service(
            constantinople_indexer::QMDB_STATE_ROUTE,
            unordered_operation_log_connect_stack(state),
        )
        .nest_service(
            constantinople_indexer::QMDB_TRANSACTIONS_ROUTE,
            keyless_operation_log_connect_stack(transactions),
        )
        .layer(tower_http::cors::CorsLayer::very_permissive()))
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    facade::run(cli.facade, cli.port, "qmdb-indexer", build_app).await
}

#[cfg(test)]
mod tests {
    use super::{Cli, build_app};
    use axum::{
        body::{Body, to_bytes},
        http::{Method, Request, StatusCode},
    };
    use clap::Parser;
    use tower::ServiceExt;

    #[test]
    fn uses_qmdb_default_port() {
        let cli = Cli::try_parse_from(["qmdb-indexer", "--store-url", "http://localhost"])
            .expect("local invocation should parse");

        assert_eq!(cli.port, 8_092);
    }

    #[tokio::test]
    async fn app_serves_health_and_mounts_distinct_qmdb_routes() {
        let app = build_app("http://127.0.0.1:1").expect("app should build");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("health request"),
            )
            .await
            .expect("health response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 16)
            .await
            .expect("health body");
        assert_eq!(&body[..], b"ok");

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
