//! QMDB query facade for the shared indexer store.
//!
//! `qmdb-indexer` exposes the Store-backed QMDB indexes written by
//! validators. It serves the account-state operation log under `/state` and
//! transaction-hash history under `/transactions`.

use axum::Router;
use commonware_codec::FixedSize;
use commonware_cryptography::sha256::Sha256;
use commonware_storage::{merkle::mmr, qmdb::any::value::FixedEncoding};
use commonware_utils::sequence::FixedBytes;
use constantinople_indexer::{
    adapter::{self, BoxError, Profile},
    namespaces::{state_qmdb_client, transactions_qmdb_client},
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

const PROFILE: Profile = Profile {
    name: "qmdb-indexer",
    about: "QMDB service over Constantinople state and transaction indexes",
    default_port: 8092,
};

type AccountValue = FixedBytes<{ Account::SIZE }>;
type StateClient =
    UnorderedClient<mmr::Family, Sha256, AccountKey, AccountValue, FixedEncoding<AccountValue>>;
type TransactionClient = KeylessClient<
    mmr::Family,
    Sha256,
    commonware_cryptography::sha256::Digest,
    FixedEncoding<commonware_cryptography::sha256::Digest>,
>;

fn build_routes(client: &StoreClient) -> Result<Router, BoxError> {
    let state = Arc::new(StateClient::new(state_qmdb_client(client)?, ()));
    let transactions = Arc::new(TransactionClient::new(
        transactions_qmdb_client(client)?,
        (),
    ));

    Ok(Router::new()
        .nest_service("/state", unordered_operation_log_connect_stack(state))
        .nest_service(
            "/transactions",
            keyless_operation_log_connect_stack(transactions),
        ))
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
    async fn serves_qmdb_routes() {
        let client = store_client("http://127.0.0.1:1", None).expect("client should build");
        let app = build_routes(&client).expect("routes should build");

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
