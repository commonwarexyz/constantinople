use std::future::Future;
use std::time::Duration;

use exoware_sdk::transport::BalancedHttp2Config;
use exoware_sdk::{ClientError, ErrorCode, Key, RetryConfig, StoreClient, StoreKeyPrefix};

async fn timeout_code<T>(future: impl Future<Output = Result<T, ClientError>>) -> ErrorCode {
    match tokio::time::timeout(Duration::from_millis(400), future)
        .await
        .expect("the SDK must bound response header waits")
    {
        Err(ClientError::Rpc(error)) => error.code,
        Err(error) => panic!("expected an RPC error, got {error}"),
        Ok(_) => panic!("the stalled server must not return a response"),
    }
}

#[tokio::test]
async fn balanced_transport_classifies_response_header_timeouts_consistently() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let mut sockets = Vec::new();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            sockets.push(socket);
        }
    });

    let client = StoreClient::builder()
        .url(&url)
        .retry_config(RetryConfig::disabled())
        .balanced_http2_transport(
            BalancedHttp2Config::default().with_request_timeout(Duration::from_millis(100)),
        )
        .build()
        .unwrap()
        .prefixed(StoreKeyPrefix::new("timeout/").unwrap());
    let stream_code = timeout_code(client.query().range_stream(
        &Key::from(b"a".to_vec()),
        &Key::from(b"z".to_vec()),
        10,
        1,
    ))
    .await;
    let unary_code = timeout_code(client.query().get(&Key::from(b"key".to_vec()))).await;
    server.abort();

    assert_eq!(stream_code, ErrorCode::DeadlineExceeded);
    assert_eq!(unary_code, stream_code);
}
