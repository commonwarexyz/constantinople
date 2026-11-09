//! Generated service bindings over the explorer's validated reads.

#![allow(refining_impl_trait)]

use super::*;
use crate::submission::Submission;
use connectrpc::{
    ConnectRpcService, DeadlinePolicy, Limits, RequestContext, ServiceRequest, ServiceResult,
    ServiceStream,
};
use std::time::Duration;

struct Service {
    explorer: Arc<Explorer>,
    submission: Submission,
}

pub(super) fn router(
    explorer: Arc<Explorer>,
    relayer_url: Option<&str>,
) -> Result<Router, BoxError> {
    let service = Service {
        explorer,
        submission: Submission::new(relayer_url)?,
    };
    let transport = ConnectRpcService::new(proto::ExplorerServiceServer::new(service))
        .with_limits(
            Limits::default()
                .with_max_request_body_size(MAX_RESPONSE_BYTES)
                .with_max_message_size(MAX_RESPONSE_BYTES)
                .with_element_memory_limit(256 * 1024),
        )
        .with_deadline_policy(
            DeadlinePolicy::new()
                .with_max(Duration::from_secs(11))
                .with_default_timeout(Duration::from_secs(11)),
        );
    Ok(Router::new().fallback_service(transport))
}

impl proto::ExplorerService for Service {
    async fn get_account(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, proto::GetAccountRequest>,
    ) -> ServiceResult<proto::ProofBundle> {
        connectrpc::Response::ok(account(&self.explorer, request.to_owned_message()).await?)
    }

    async fn get_block(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, proto::GetBlockRequest>,
    ) -> ServiceResult<proto::ProofBundle> {
        connectrpc::Response::ok(block(&self.explorer, request.to_owned_message()).await?)
    }

    async fn get_transaction(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, proto::GetTransactionRequest>,
    ) -> ServiceResult<proto::ProofBundle> {
        connectrpc::Response::ok(transaction(&self.explorer, request.to_owned_message()).await?)
    }

    async fn search(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, proto::SearchRequest>,
    ) -> ServiceResult<proto::SearchResponse> {
        let value = fixed_bytes::<32>(&request.value)?;
        connectrpc::Response::ok(self.explorer.search(value).await?)
    }

    async fn watch_blocks(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, proto::WatchBlocksRequest>,
    ) -> ServiceResult<ServiceStream<proto::WatchBlocksResponse>> {
        Ok(connectrpc::Response::stream(browse::events(
            self.explorer.clone(),
            request.after,
        )))
    }

    async fn submit_transaction(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, proto::SubmitTransactionRequest>,
    ) -> ServiceResult<proto::SubmitTransactionResponse> {
        connectrpc::Response::ok(
            self.submission
                .submit(Bytes::copy_from_slice(&request.batch))
                .await?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use futures::stream;
    use tower::ServiceExt;

    fn app() -> Router {
        let store = crate::store_client("http://127.0.0.1:1", None).unwrap();
        super::super::router(&store, None).unwrap()
    }

    #[tokio::test]
    async fn generated_submission_enforces_batch_size_and_requires_a_relayer() {
        let client = proto::ExplorerServiceClient::new(
            connectrpc::client::ServiceTransport::new(app()),
            connectrpc::client::ClientConfig::new("http://localhost".parse().unwrap()),
        );
        let unavailable = client
            .submit_transaction(proto::SubmitTransactionRequest::default())
            .await
            .unwrap_err();
        assert_eq!(unavailable.code, ErrorCode::Unavailable);
        let oversized = client
            .submit_transaction(proto::SubmitTransactionRequest {
                batch: vec![0; 4 * 1024 * 1024 + 6],
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(oversized.code, ErrorCode::ResourceExhausted);
    }

    async fn assert_error(body: Body, expected: &str) {
        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/constantinople.explorer.v1.ExplorerService/SubmitTransaction")
                    .header("content-type", "application/proto")
                    .header("connect-protocol-version", "1")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
        let error: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(error["code"], expected);
    }

    #[tokio::test]
    async fn encoded_ingress_is_bounded_before_message_decoding() {
        assert_error(
            Body::from(vec![0; MAX_RESPONSE_BYTES + 1]),
            "resource_exhausted",
        )
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_request_receipt_expires_before_submission() {
        let body = Body::from_stream(stream::pending::<Result<Bytes, std::io::Error>>());
        assert_error(body, "deadline_exceeded").await;
    }

    #[tokio::test]
    async fn application_service_does_not_expose_raw_protocols_or_rest_routes() {
        for path in [
            "/sql.v1.Service/Query",
            "/store.query.v1.Service/Range",
            "/log.stream.v1.Service/Subscribe",
            "/state/qmdb.v1.OperationLogService/GetOperationRange",
            "/transactions/qmdb.v1.OperationLogService/GetOperationRange",
            "/explorer/blocks/stream",
            "/explorer/transactions",
        ] {
            let response = app()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(!response.status().is_success(), "{path}");
        }
    }
}
