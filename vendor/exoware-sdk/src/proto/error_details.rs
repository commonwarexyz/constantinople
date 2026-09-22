use base64::Engine;
use buffa::Message;
use buffa_types::google::protobuf::Any;
use connectrpc::error::ErrorDetail;
use connectrpc::{ConnectError, ErrorCode};

use crate::google::rpc::{BadRequest, ErrorInfo, RetryInfo};
use crate::query::Detail;

#[derive(Debug, Clone, PartialEq)]
pub struct DecodedConnectError {
    pub code: ErrorCode,
    pub message: Option<String>,
    pub bad_request: Option<BadRequest>,
    pub error_info: Option<ErrorInfo>,
    pub retry_info: Option<RetryInfo>,
    pub query_detail: Option<Detail>,
    pub other_details: Vec<Any>,
}

pub fn with_bad_request_detail(err: ConnectError, detail: BadRequest) -> ConnectError {
    err.with_detail(pack_detail(&detail, BadRequest::TYPE_URL))
}

pub fn with_error_info_detail(err: ConnectError, detail: ErrorInfo) -> ConnectError {
    err.with_detail(pack_detail(&detail, ErrorInfo::TYPE_URL))
}

pub fn with_retry_info_detail(err: ConnectError, detail: RetryInfo) -> ConnectError {
    err.with_detail(pack_detail(&detail, RetryInfo::TYPE_URL))
}

/// Attaches [`Detail`] (`store.query.v1.Detail`) for query RPC error responses.
pub fn with_query_detail(err: ConnectError, detail: Detail) -> ConnectError {
    err.with_detail(pack_detail(&detail, Detail::TYPE_URL))
}

pub fn decode_connect_error(err: &ConnectError) -> Result<DecodedConnectError, buffa::DecodeError> {
    let mut decoded = DecodedConnectError {
        code: err.code,
        message: err.message.clone(),
        bad_request: None,
        error_info: None,
        retry_info: None,
        query_detail: None,
        other_details: Vec::new(),
    };

    for detail in &err.details {
        let any = decode_detail(detail)?;
        if let Some(msg) = any.unpack_if::<BadRequest>(BadRequest::TYPE_URL)? {
            decoded.bad_request = Some(msg);
            continue;
        }
        if let Some(msg) = any.unpack_if::<ErrorInfo>(ErrorInfo::TYPE_URL)? {
            decoded.error_info = Some(msg);
            continue;
        }
        if let Some(msg) = any.unpack_if::<RetryInfo>(RetryInfo::TYPE_URL)? {
            decoded.retry_info = Some(msg);
            continue;
        }
        if let Some(msg) = any.unpack_if::<Detail>(Detail::TYPE_URL)? {
            decoded.query_detail = Some(msg);
            continue;
        }
        decoded.other_details.push(any);
    }

    Ok(decoded)
}

fn pack_detail<M: Message>(message: &M, type_url: &str) -> ErrorDetail {
    let any = Any::pack(message, type_url.to_string());
    ErrorDetail {
        type_url: any.type_url,
        value: Some(base64::engine::general_purpose::STANDARD_NO_PAD.encode(any.value)),
        debug: None,
    }
}

fn decode_detail(detail: &ErrorDetail) -> Result<Any, buffa::DecodeError> {
    // InvalidUtf8 is the closest available variant for base64 decode failures
    // (buffa::DecodeError has no generic/catch-all variant).
    let value = detail
        .value
        .as_deref()
        .map(|encoded| {
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(encoded)
                .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))
        })
        .transpose()
        .map_err(|_| buffa::DecodeError::InvalidUtf8)?
        .unwrap_or_default();
    Ok(Any {
        type_url: detail.type_url.clone(),
        value: value.into(),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::google::rpc::{bad_request::FieldViolation, ErrorInfo};
    use crate::query::Detail;

    #[test]
    fn round_trips_query_detail() {
        let err = with_query_detail(
            ConnectError::invalid_argument("bad"),
            Detail {
                sequence_number: 42,
                ..Default::default()
            },
        );
        let decoded = decode_connect_error(&err).expect("decode details");
        assert_eq!(decoded.query_detail.unwrap().sequence_number, 42);
    }

    #[test]
    fn round_trips_typed_details() {
        let err = with_error_info_detail(
            with_bad_request_detail(
                ConnectError::invalid_argument("invalid request"),
                BadRequest {
                    field_violations: vec![FieldViolation {
                        field: "key".to_string(),
                        description: "too long".to_string(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ),
            ErrorInfo {
                reason: "INVALID_KEY".to_string(),
                domain: "log.ingest".to_string(),
                metadata: [("max_key_len".to_string(), "254".to_string())]
                    .into_iter()
                    .collect(),
                ..Default::default()
            },
        );

        let decoded = decode_connect_error(&err).expect("decode details");
        assert_eq!(decoded.code, ErrorCode::InvalidArgument);
        assert_eq!(
            decoded
                .bad_request
                .unwrap()
                .field_violations
                .first()
                .expect("field violation")
                .field,
            "key"
        );
        assert_eq!(
            decoded
                .error_info
                .unwrap()
                .metadata
                .get("max_key_len")
                .map(String::as_str),
            Some("254")
        );
    }
}
