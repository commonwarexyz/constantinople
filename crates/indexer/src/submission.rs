//! Bounded transaction submission to the operator's configured relayer.

use crate::{
    adapter::BoxError,
    explorer::MAX_EVIDENCE_BYTES,
    proto::{
        AmbiguousSubmission, CompletedSubmission, Empty, Finalized, PartiallyFinalized,
        ProofBundle, SubmitTransactionResponse, completed_submission::Result as SubmissionResult,
        submit_transaction_response::Outcome,
    },
};
use buffa::Message;
use bytes::{Bytes, BytesMut};
use commonware_formatting::from_hex;
use connectrpc::ConnectError;
use reqwest::{StatusCode, header::CONTENT_TYPE};
use serde::Deserialize;
use std::time::Duration;

// The proxy allows 4 MiB of transaction data plus a u32 vector-length varint.
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024 + 5;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_CONTENT_TYPE_BYTES: usize = 256;
const SUBMISSION_TIMEOUT: Duration = Duration::from_secs(11);

struct Relayer {
    client: reqwest::Client,
    endpoint: reqwest::Url,
}

pub(crate) struct Submission {
    relayer: Option<Relayer>,
}

fn endpoint(base: &str) -> Result<reqwest::Url, BoxError> {
    let mut url = reqwest::Url::parse(base)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("relayer URL must be HTTP(S) without credentials, query, or fragment".into());
    }
    url.path_segments_mut()
        .map_err(|_| "relayer URL must support path segments")?
        .pop_if_empty()
        .push("transactions");
    Ok(url)
}

impl Submission {
    pub(crate) fn new(relayer_url: Option<&str>) -> Result<Self, BoxError> {
        let relayer = relayer_url
            .map(|base| {
                Ok::<_, BoxError>(Relayer {
                    endpoint: endpoint(base)?,
                    client: reqwest::Client::builder()
                        .redirect(reqwest::redirect::Policy::none())
                        .retry(reqwest::retry::never())
                        .no_proxy()
                        .no_gzip()
                        .no_brotli()
                        .no_deflate()
                        .no_zstd()
                        .build()?,
                })
            })
            .transpose()?;
        Ok(Self { relayer })
    }

    pub(crate) async fn submit(
        &self,
        batch: Bytes,
    ) -> Result<SubmitTransactionResponse, ConnectError> {
        if batch.len() > MAX_REQUEST_BYTES {
            return Err(ConnectError::resource_exhausted(
                "submission body is too large",
            ));
        }
        let relayer = self
            .relayer
            .as_ref()
            .ok_or_else(|| ConnectError::unavailable("relayer is not configured"))?;
        let mut status = None;
        Ok(
            match tokio::time::timeout(SUBMISSION_TIMEOUT, forward(relayer, batch, &mut status))
                .await
            {
                Ok(response) => response,
                Err(_) => ambiguous(
                    "submission timed out; transaction outcome is unknown",
                    status,
                ),
            },
        )
    }
}

fn ambiguous(reason: &str, status: Option<u16>) -> SubmitTransactionResponse {
    SubmitTransactionResponse {
        outcome: Some(Outcome::Ambiguous(
            AmbiguousSubmission {
                reason: reason.to_owned(),
                http_status: status.map(u32::from),
                ..Default::default()
            }
            .into(),
        )),
        ..Default::default()
    }
}

async fn forward(
    relayer: &Relayer,
    batch: Bytes,
    observed_status: &mut Option<u16>,
) -> SubmitTransactionResponse {
    let response = relayer
        .client
        .post(relayer.endpoint.clone())
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(batch)
        .send()
        .await;
    let mut response = match response {
        Ok(response) => response,
        Err(_) => {
            return ambiguous(
                "could not complete submission; transaction outcome is unknown",
                None,
            );
        }
    };
    let status = response.status();
    *observed_status = Some(status.as_u16());
    let content_type = response.headers().get(CONTENT_TYPE);
    if content_type.is_some_and(|value| value.as_bytes().len() > MAX_CONTENT_TYPE_BYTES) {
        return ambiguous(
            "relayer content type is too large; transaction outcome is unknown",
            *observed_status,
        );
    }
    let content_type = content_type
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return ambiguous(
            "relayer response is too large; transaction outcome is unknown",
            *observed_status,
        );
    }
    let mut body = BytesMut::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if chunk.len() > MAX_RESPONSE_BYTES - body.len() {
                    return ambiguous(
                        "relayer response is too large; transaction outcome is unknown",
                        *observed_status,
                    );
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => {
                return ambiguous(
                    "could not read complete relayer response; transaction outcome is unknown",
                    *observed_status,
                );
            }
        }
    }
    SubmitTransactionResponse {
        outcome: Some(Outcome::Completed(
            CompletedSubmission {
                http_status: u32::from(status.as_u16()),
                result: result(status, &body),
                body: body.to_vec(),
                content_type,
                ..Default::default()
            }
            .into(),
        )),
        ..Default::default()
    }
}

// Foreground status returned by the relayer's HTTP endpoint.
#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum TxStatus {
    Finalized {
        height: u64,
        /// Hex-encoded transaction evidence bundle.
        #[serde(default)]
        evidence: Option<String>,
    },
    PartiallyFinalized {
        height: u64,
        included: u64,
        filtered: u64,
    },
    Dropped,
}

/// Decodes the evidence a relayer attached to a finalization report.
///
/// The evidence is forwarded for the client to verify and is never checked here. Evidence that is
/// malformed, or that would push the response past the relayer response bound, is omitted so the
/// report itself is still delivered.
fn evidence(encoded: &str, body_bytes: usize) -> Option<ProofBundle> {
    if encoded.len() > 2 * MAX_EVIDENCE_BYTES || body_bytes + encoded.len() / 2 > MAX_RESPONSE_BYTES
    {
        return None;
    }
    ProofBundle::decode_from_slice(&from_hex(encoded)?).ok()
}

fn result(status: StatusCode, body: &[u8]) -> Option<SubmissionResult> {
    match status {
        StatusCode::OK => match serde_json::from_slice::<TxStatus>(body).ok()? {
            TxStatus::Finalized {
                height,
                evidence: encoded,
            } => Some(SubmissionResult::Finalized(
                Finalized {
                    height,
                    evidence: encoded
                        .and_then(|encoded| evidence(&encoded, body.len()))
                        .into(),
                    ..Default::default()
                }
                .into(),
            )),
            TxStatus::PartiallyFinalized {
                height,
                included,
                filtered,
            } => Some(SubmissionResult::PartiallyFinalized(
                PartiallyFinalized {
                    height,
                    included,
                    filtered,
                    ..Default::default()
                }
                .into(),
            )),
            TxStatus::Dropped => Some(SubmissionResult::Dropped(Empty::default().into())),
        },
        StatusCode::ACCEPTED => Some(SubmissionResult::Pending(Empty::default().into())),
        StatusCode::BAD_REQUEST | StatusCode::PAYLOAD_TOO_LARGE => {
            Some(SubmissionResult::Rejected(Empty::default().into()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_formatting::hex;
    use connectrpc::ErrorCode;
    use constantinople_mempool::webserver::TxStatus as RelayerStatus;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::mpsc,
        task::JoinHandle,
    };

    struct WireRequest {
        headers: String,
        body: Vec<u8>,
    }

    struct TestRelayer {
        url: String,
        requests: mpsc::UnboundedReceiver<WireRequest>,
        task: JoinHandle<()>,
    }

    impl Drop for TestRelayer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn read_request(socket: &mut TcpStream) -> WireRequest {
        let mut data = Vec::new();
        let header_end = loop {
            let mut chunk = [0; 8192];
            let read = socket.read(&mut chunk).await.expect("request read");
            assert_ne!(read, 0);
            data.extend_from_slice(&chunk[..read]);
            if let Some(end) = data.windows(4).position(|window| window == b"\r\n\r\n") {
                break end + 4;
            }
        };
        let headers = String::from_utf8(data[..header_end].to_vec()).expect("HTTP headers");
        let length = headers
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("body length"))
            })
            .expect("content length");
        let received = data.len();
        data.resize(header_end + length, 0);
        socket
            .read_exact(&mut data[received..])
            .await
            .expect("request body");
        WireRequest {
            headers,
            body: data[header_end..].to_vec(),
        }
    }

    async fn relayer(response: Vec<u8>, keep_open: bool) -> TestRelayer {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let url = format!("http://{}", listener.local_addr().expect("address"));
        let (sender, requests) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.expect("relayer connection");
                let request = read_request(&mut socket).await;
                if sender.send(request).is_err() {
                    return;
                }
                let _ = socket.write_all(&response).await;
                if keep_open {
                    std::future::pending::<()>().await;
                }
            }
        });
        TestRelayer {
            url,
            requests,
            task,
        }
    }

    fn wire_response(status: u16, body: &[u8]) -> Vec<u8> {
        let mut wire = format!(
            "HTTP/1.1 {status} Upstream\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
            body.len(),
        ).into_bytes();
        wire.extend_from_slice(body);
        wire
    }

    fn completed(response: SubmitTransactionResponse) -> CompletedSubmission {
        match response.outcome.expect("outcome") {
            Outcome::Completed(completed) => *completed,
            Outcome::Ambiguous(_) => panic!("expected complete upstream response"),
        }
    }

    fn uncertain(response: SubmitTransactionResponse) -> AmbiguousSubmission {
        match response.outcome.expect("outcome") {
            Outcome::Ambiguous(ambiguous) => *ambiguous,
            Outcome::Completed(_) => panic!("expected ambiguous outcome"),
        }
    }

    #[test]
    fn validates_and_appends_the_fixed_destination() {
        for (base, expected) in [
            (
                "http://localhost:8080",
                "http://localhost:8080/transactions",
            ),
            (
                "https://example.com/base",
                "https://example.com/base/transactions",
            ),
            (
                "https://example.com/base/",
                "https://example.com/base/transactions",
            ),
            (
                "http://[::1]:8080/a%20b",
                "http://[::1]:8080/a%20b/transactions",
            ),
        ] {
            assert_eq!(
                endpoint(base).expect("valid destination").as_str(),
                expected
            );
        }
        for base in [
            "file:///transactions",
            "ftp://example.com",
            "http://user@example.com",
            "http://user:password@example.com",
            "http://:password@example.com",
            "http://example.com?key=value",
            "http://example.com?",
            "http://example.com#fragment",
            "http://example.com#",
            "invalid",
        ] {
            assert!(Submission::new(Some(base)).is_err(), "{base}");
        }
    }

    #[tokio::test]
    async fn maps_the_relayers_actual_foreground_status_encoding() {
        for status in [
            RelayerStatus::Finalized { height: u64::MAX },
            RelayerStatus::PartiallyFinalized {
                height: 7,
                included: 3,
                filtered: 2,
            },
            RelayerStatus::Dropped,
        ] {
            let body = serde_json::to_vec(&status).expect("relayer status");
            let mut upstream = relayer(wire_response(200, &body), false).await;
            let submission = Submission::new(Some(&upstream.url)).expect("submission");
            let response = completed(
                submission
                    .submit(Bytes::from_static(b"batch"))
                    .await
                    .unwrap(),
            );
            assert_eq!(response.http_status, 200);
            assert_eq!(response.body.as_slice(), body.as_slice());
            match (status, response.result.expect("typed status")) {
                (RelayerStatus::Finalized { height }, SubmissionResult::Finalized(value)) => {
                    assert_eq!(value.height, height);
                }
                (
                    RelayerStatus::PartiallyFinalized {
                        height,
                        included,
                        filtered,
                    },
                    SubmissionResult::PartiallyFinalized(value),
                ) => {
                    assert_eq!(
                        (value.height, value.included, value.filtered),
                        (height, included, filtered)
                    );
                }
                (RelayerStatus::Dropped, SubmissionResult::Dropped(_)) => {}
                _ => panic!("incorrect status mapping"),
            }
            upstream.requests.recv().await.expect("forwarded request");
            assert!(upstream.requests.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn forwards_bounded_evidence_and_keeps_a_report_whose_evidence_is_unusable() {
        let bundle = ProofBundle {
            certificate: vec![7; 64],
            sequence_number: 3,
            ..Default::default()
        };
        let oversized = ProofBundle {
            certificate: vec![7; MAX_EVIDENCE_BYTES],
            ..Default::default()
        };
        let report = |evidence: String| {
            format!(r#"{{"status":"finalized","height":7,"evidence":"{evidence}"}}"#).into_bytes()
        };

        // Evidence fills the response bound together with the body it arrived in.
        let encoded = hex(&bundle.encode_to_vec());
        let mut padded = report(encoded.clone());
        padded.pop();
        padded.extend_from_slice(br#","padding":""#);
        padded.resize(MAX_RESPONSE_BYTES - encoded.len() / 2 - 2, b'x');
        padded.extend_from_slice(br#""}"#);
        let mut overfull = padded.clone();
        overfull.insert(overfull.len() - 2, b'x');

        for (name, body, expected) in [
            ("valid", report(encoded), Some(&bundle)),
            ("fits the bound", padded, Some(&bundle)),
            ("exceeds the bound", overfull, None),
            ("not hex", report("zz".to_owned()), None),
            ("not a bundle", report("ff".to_owned()), None),
            ("oversized", report(hex(&oversized.encode_to_vec())), None),
        ] {
            let upstream = relayer(wire_response(200, &body), false).await;
            let submission = Submission::new(Some(&upstream.url)).expect("submission");
            let response = submission
                .submit(Bytes::from_static(b"batch"))
                .await
                .unwrap();
            assert!((response.encoded_len() as usize) < 65 * 1024, "{name}");
            let response = completed(response);
            assert_eq!(response.body.as_slice(), body.as_slice(), "{name}");
            let Some(SubmissionResult::Finalized(finalized)) = response.result else {
                panic!("{name} must stay a finalization report");
            };
            assert_eq!(finalized.height, 7, "{name}");
            assert_eq!(finalized.evidence.as_option(), expected, "{name}");
        }
    }

    #[tokio::test]
    async fn preserves_complete_replies_and_forwards_only_the_fixed_binary_request() {
        let batch = Bytes::from_static(&[0, 255, 0, 128, 42]);
        for (status, body) in [
            (202, &b"pending"[..]),
            (400, &b"invalid\0\xff"[..]),
            (413, &b"too big"[..]),
            (200, &b"invalid status"[..]),
            (503, &b"busy"[..]),
            (500, &b"failure"[..]),
        ] {
            let mut upstream = relayer(wire_response(status, body), false).await;
            let submission = Submission::new(Some(&format!("{}/base/", upstream.url))).unwrap();
            let response = completed(submission.submit(batch.clone()).await.unwrap());
            assert_eq!(response.http_status, u32::from(status));
            assert_eq!(response.body.as_slice(), body);
            assert_eq!(response.content_type, "application/json; charset=utf-8");
            match status {
                202 => assert!(matches!(
                    response.result,
                    Some(SubmissionResult::Pending(_))
                )),
                400 | 413 => assert!(matches!(
                    response.result,
                    Some(SubmissionResult::Rejected(_))
                )),
                _ => assert!(response.result.is_none()),
            }
            let request = upstream.requests.recv().await.expect("request");
            assert!(
                request
                    .headers
                    .starts_with("POST /base/transactions HTTP/1.1\r\n")
            );
            let headers = request.headers.to_ascii_lowercase();
            assert!(headers.contains("content-type: application/octet-stream\r\n"));
            for forbidden in [
                "authorization:",
                "cookie:",
                "x-api-key:",
                "proxy-authorization:",
            ] {
                assert!(!headers.contains(forbidden), "{headers}");
            }
            assert_eq!(request.body.as_slice(), batch.as_ref());
            assert!(upstream.requests.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn complete_redirect_is_preserved_without_following_or_retrying() {
        let mut upstream = relayer(
            b"HTTP/1.1 307 Redirect\r\nLocation: /redirected\r\nContent-Length: 8\r\n\r\nredirect"
                .to_vec(),
            false,
        )
        .await;
        let response = completed(
            Submission::new(Some(&upstream.url))
                .unwrap()
                .submit(Bytes::from_static(b"batch"))
                .await
                .unwrap(),
        );
        assert_eq!(response.http_status, 307);
        assert_eq!(response.body.as_slice(), b"redirect");
        assert!(response.content_type.is_empty());
        assert!(response.result.is_none());
        upstream.requests.recv().await.expect("first request");
        assert!(upstream.requests.try_recv().is_err());
    }

    #[tokio::test]
    async fn maximum_content_type_is_preserved_within_the_encoded_response_cap() {
        let prefix = "application/octet-stream; note=";
        let content_type = format!(
            "{prefix}{}",
            "x".repeat(MAX_CONTENT_TYPE_BYTES - prefix.len())
        );
        let mut wire = format!(
            "HTTP/1.1 202 Accepted\r\nContent-Type: {content_type}\r\nContent-Length: {MAX_RESPONSE_BYTES}\r\n\r\n"
        ).into_bytes();
        wire.resize(wire.len() + MAX_RESPONSE_BYTES, b'x');
        let mut upstream = relayer(wire, false).await;
        let response = Submission::new(Some(&upstream.url))
            .unwrap()
            .submit(Bytes::from_static(b"batch"))
            .await
            .unwrap();
        assert!((response.encoded_len() as usize) < 65 * 1024);
        let response = completed(response);
        assert_eq!(response.content_type, content_type);
        assert_eq!(response.body, vec![b'x'; MAX_RESPONSE_BYTES]);
        upstream.requests.recv().await.expect("first request");
        assert!(upstream.requests.try_recv().is_err());
    }

    #[tokio::test]
    async fn oversized_content_type_is_ambiguous_before_reading_the_body() {
        let content_type = "x".repeat(MAX_CONTENT_TYPE_BYTES + 1);
        let wire = format!(
            "HTTP/1.1 400 Rejected\r\nContent-Type: {content_type}\r\nContent-Length: 1\r\n\r\n"
        )
        .into_bytes();
        let mut upstream = relayer(wire, true).await;
        let submission = Submission::new(Some(&upstream.url)).unwrap();
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            submission.submit(Bytes::from_static(b"batch")),
        )
        .await
        .expect("header limit must not wait for the response body")
        .unwrap();
        let response = uncertain(response);
        assert_eq!(response.http_status, Some(400));
        assert!(response.reason.contains("content type"));
        upstream.requests.recv().await.expect("first request");
        assert!(upstream.requests.try_recv().is_err());
    }

    #[tokio::test]
    async fn incomplete_replies_are_ambiguous_even_with_a_rejection_status() {
        for (wire, expected_status) in [
            (Vec::new(), None),
            (
                b"HTTP/1.1 400 Rejected\r\nContent-Length: 20\r\n\r\nshort".to_vec(),
                Some(400),
            ),
        ] {
            let mut upstream = relayer(wire, false).await;
            let response = uncertain(
                Submission::new(Some(&upstream.url))
                    .unwrap()
                    .submit(Bytes::from_static(b"batch"))
                    .await
                    .unwrap(),
            );
            assert_eq!(response.http_status, expected_status);
            assert!(response.reason.contains("outcome is unknown"));
            upstream.requests.recv().await.expect("first request");
            assert!(upstream.requests.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn oversized_upstream_replies_are_ambiguous_with_and_without_a_length() {
        for declared in [true, false] {
            let mut wire = if declared {
                format!(
                    "HTTP/1.1 400 Rejected\r\nContent-Length: {}\r\n\r\n",
                    MAX_RESPONSE_BYTES + 1
                )
                .into_bytes()
            } else {
                b"HTTP/1.1 400 Rejected\r\nConnection: close\r\n\r\n".to_vec()
            };
            wire.resize(wire.len() + MAX_RESPONSE_BYTES + 1, b'x');
            let upstream = relayer(wire, false).await;
            let response = uncertain(
                Submission::new(Some(&upstream.url))
                    .unwrap()
                    .submit(Bytes::from_static(b"batch"))
                    .await
                    .unwrap(),
            );
            assert_eq!(response.http_status, Some(400));
        }
    }

    #[tokio::test]
    async fn rejects_oversized_input_before_dispatch_and_allows_exact_limits() {
        let body = vec![b'x'; MAX_RESPONSE_BYTES];
        let mut upstream = relayer(wire_response(202, &body), false).await;
        let submission = Submission::new(Some(&upstream.url)).unwrap();
        let error = submission
            .submit(Bytes::from(vec![7; MAX_REQUEST_BYTES + 1]))
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ResourceExhausted);
        assert!(upstream.requests.try_recv().is_err());
        let response = completed(
            submission
                .submit(Bytes::from(vec![7; MAX_REQUEST_BYTES]))
                .await
                .unwrap(),
        );
        assert_eq!(response.body.as_slice(), body.as_slice());
        assert!(matches!(
            response.result,
            Some(SubmissionResult::Pending(_))
        ));
        assert_eq!(
            upstream.requests.recv().await.unwrap().body,
            vec![7; MAX_REQUEST_BYTES]
        );
        assert!(upstream.requests.try_recv().is_err());
        let error = Submission::new(None)
            .unwrap()
            .submit(Bytes::new())
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Unavailable);
    }

    #[tokio::test]
    async fn header_and_body_stalls_have_one_total_deadline() {
        for response in [
            Vec::new(),
            b"HTTP/1.1 400 Rejected\r\nContent-Length: 4\r\n\r\n".to_vec(),
        ] {
            let mut upstream = relayer(response, true).await;
            let submission = Submission::new(Some(&upstream.url)).unwrap();
            let pending =
                tokio::spawn(async move { submission.submit(Bytes::from_static(b"batch")).await });
            upstream.requests.recv().await.expect("request");
            tokio::time::pause();
            tokio::time::advance(SUBMISSION_TIMEOUT).await;
            let response = uncertain(pending.await.unwrap().unwrap());
            assert!(response.reason.contains("timed out"));
            tokio::time::resume();
            assert!(upstream.requests.try_recv().is_err());
        }
    }
}
