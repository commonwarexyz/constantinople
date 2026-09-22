//! Parse protobuf retention messages into `retention` domain types.
//!
//! Parsing checks only protobuf shape. Call the validation helper on the parsed
//! output before applying retention effects (the handler is authoritative;
//! `buf.validate` annotations on the proto are documentation).

use crate::log::retention::v1::{
    retention_policy, RetentionGreaterThan, RetentionGreaterThanOrEqual, RetentionKeepLatest,
    RetentionPolicy as ProtoRetentionPolicy, SetRetentionRequestView,
};
use crate::retention::RetentionPolicy;
use buffa::MessageView;

pub fn parse_retention_policy_from_proto(
    p: &ProtoRetentionPolicy,
) -> Result<RetentionPolicy, String> {
    let Some(kind) = p.kind.as_ref() else {
        return Err("retention policy kind is required".to_string());
    };
    let policy = match kind {
        retention_policy::Kind::KeepLatest(k) => RetentionPolicy::KeepLatest { count: k.count },
        retention_policy::Kind::GreaterThan(g) => RetentionPolicy::GreaterThan {
            threshold: g.threshold,
        },
        retention_policy::Kind::GreaterThanOrEqual(g) => RetentionPolicy::GreaterThanOrEqual {
            threshold: g.threshold,
        },
        retention_policy::Kind::DropAll(_) => RetentionPolicy::DropAll,
    };
    Ok(policy)
}

pub fn retention_policy_to_proto(policy: &RetentionPolicy) -> ProtoRetentionPolicy {
    let kind = match policy {
        RetentionPolicy::KeepLatest { count } => {
            retention_policy::Kind::KeepLatest(Box::new(RetentionKeepLatest {
                count: *count,
                ..Default::default()
            }))
        }
        RetentionPolicy::GreaterThan { threshold } => {
            retention_policy::Kind::GreaterThan(Box::new(RetentionGreaterThan {
                threshold: *threshold,
                ..Default::default()
            }))
        }
        RetentionPolicy::GreaterThanOrEqual { threshold } => {
            retention_policy::Kind::GreaterThanOrEqual(Box::new(RetentionGreaterThanOrEqual {
                threshold: *threshold,
                ..Default::default()
            }))
        }
        RetentionPolicy::DropAll => retention_policy::Kind::DropAll(Box::default()),
    };
    ProtoRetentionPolicy {
        kind: Some(kind),
        ..Default::default()
    }
}

/// Parses a `SetRetention` RPC request. An absent `policy` clears the rule and
/// maps to `Ok(None)`.
pub fn parse_set_retention_request_view(
    req: &SetRetentionRequestView<'_>,
) -> Result<Option<RetentionPolicy>, String> {
    let Some(policy_view) = req.policy.as_option() else {
        return Ok(None);
    };
    let policy = policy_view
        .to_owned_message()
        .map_err(|error| error.to_string())?;
    Ok(Some(parse_retention_policy_from_proto(&policy)?))
}

pub fn validate_retention_policy(policy: &RetentionPolicy) -> Result<(), String> {
    crate::retention::validate_retention_policy(policy).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use buffa::Message as _;

    #[test]
    fn owned_proto_round_trips_to_domain() {
        for expected in [
            RetentionPolicy::KeepLatest { count: 3 },
            RetentionPolicy::GreaterThan { threshold: 9 },
            RetentionPolicy::GreaterThanOrEqual { threshold: 4 },
            RetentionPolicy::DropAll,
        ] {
            let proto = retention_policy_to_proto(&expected);
            let actual = parse_retention_policy_from_proto(&proto).expect("from proto");
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn set_retention_view_with_policy_parses() {
        let request = crate::log::retention::v1::SetRetentionRequest {
            policy: Some(retention_policy_to_proto(&RetentionPolicy::KeepLatest {
                count: 2,
            }))
            .into(),
            ..Default::default()
        };
        let bytes = request.encode_to_vec();
        let view = SetRetentionRequestView::decode_view(&bytes).expect("decode view");

        let parsed = parse_set_retention_request_view(&view).expect("parse");
        assert_eq!(parsed, Some(RetentionPolicy::KeepLatest { count: 2 }));
    }

    #[test]
    fn set_retention_view_absent_policy_clears() {
        let request = crate::log::retention::v1::SetRetentionRequest::default();
        let bytes = request.encode_to_vec();
        let view = SetRetentionRequestView::decode_view(&bytes).expect("decode view");

        let parsed = parse_set_retention_request_view(&view).expect("parse");
        assert_eq!(parsed, None);
    }
}
