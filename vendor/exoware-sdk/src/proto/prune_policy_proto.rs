//! Parse protobuf prune-policy messages into `prune_policy` domain types.
//!
//! Parsing checks only protobuf shape and numeric width conversions. Call the
//! validation helpers on the parsed output before applying policy effects.

use crate::common::kv::v1::Selector as ProtoSelector;
use crate::kv_codec::Utf8;
use crate::prune_policy::{
    GroupBy, KeysScope, OrderBy, OrderEncoding, PrunePolicy, PrunePolicyDocument, RetainPolicy,
    PRUNE_POLICY_DOCUMENT_VERSION,
};
use crate::selector::Selector;
use crate::store::prune::v1::{
    policy_retain, KeysScope as ProtoKeysScope, Policy as ProtoPolicy, PolicyOrderBy,
    PolicyOrderEncoding, PruneRequestView,
};
use buffa::MessageView;

fn usize_from_u64(field: &str, v: u64) -> Result<usize, String> {
    usize::try_from(v).map_err(|_| format!("{field} does not fit in usize (got {v})"))
}

fn order_encoding_from_proto(
    enc: &buffa::EnumValue<PolicyOrderEncoding>,
) -> Result<OrderEncoding, String> {
    let Some(known) = enc.as_known() else {
        return Err("order_by.encoding must be a known PolicyOrderEncoding value".to_string());
    };
    match known {
        PolicyOrderEncoding::POLICY_ORDER_ENCODING_BYTES_ASC => Ok(OrderEncoding::BytesAsc),
        PolicyOrderEncoding::POLICY_ORDER_ENCODING_U64_BE => Ok(OrderEncoding::U64Be),
        PolicyOrderEncoding::POLICY_ORDER_ENCODING_I64_BE => Ok(OrderEncoding::I64Be),
    }
}

fn retain_from_proto(kind: &policy_retain::Kind) -> Result<RetainPolicy, String> {
    match kind {
        policy_retain::Kind::KeepLatest(k) => Ok(RetainPolicy::KeepLatest {
            count: usize_from_u64("keep_latest.count", k.count)?,
        }),
        policy_retain::Kind::GreaterThan(g) => Ok(RetainPolicy::GreaterThan {
            threshold: g.threshold,
        }),
        policy_retain::Kind::GreaterThanOrEqual(g) => Ok(RetainPolicy::GreaterThanOrEqual {
            threshold: g.threshold,
        }),
        policy_retain::Kind::DropAll(_) => Ok(RetainPolicy::DropAll),
    }
}

fn selector_from_proto(mk: &ProtoSelector) -> Result<Selector, String> {
    Ok(Selector {
        prefix: mk.prefix.clone(),
        payload_regex: Utf8::from(mk.payload_regex.clone()),
    })
}

fn order_by_from_proto(o: &PolicyOrderBy) -> Result<OrderBy, String> {
    Ok(OrderBy {
        capture_group: Utf8::from(o.capture_group.clone()),
        encoding: order_encoding_from_proto(&o.encoding)?,
    })
}

fn keys_scope_from_proto(s: &ProtoKeysScope) -> Result<KeysScope, String> {
    let Some(mk) = s.selector.as_option() else {
        return Err("keys scope selector is required".to_string());
    };
    let selector = selector_from_proto(mk)?;

    let group_by = if let Some(group_by) = s.group_by.as_option() {
        GroupBy {
            capture_groups: group_by
                .capture_groups
                .iter()
                .map(|g| Utf8::from(g.clone()))
                .collect(),
        }
    } else {
        GroupBy::default()
    };

    let order_by = s
        .order_by
        .as_option()
        .map(order_by_from_proto)
        .transpose()?;

    Ok(KeysScope {
        selector,
        group_by,
        order_by,
    })
}

pub fn parse_prune_policy_from_proto(p: &ProtoPolicy) -> Result<PrunePolicy, String> {
    let Some(keys) = p.keys.as_option() else {
        return Err("prune policy keys scope is required".to_string());
    };
    let scope = keys_scope_from_proto(keys)?;

    let Some(retain_proto) = p.retain.as_option() else {
        return Err("prune policy retain is required".to_string());
    };
    let Some(kind) = retain_proto.kind.as_ref() else {
        return Err("prune policy retain.kind is required".to_string());
    };
    let retain = retain_from_proto(kind)?;

    Ok(PrunePolicy { scope, retain })
}

pub fn validate_prune_policy(policy: &PrunePolicy) -> Result<(), String> {
    crate::prune_policy::validate_policy(policy).map_err(|e| e.to_string())
}

pub fn validate_prune_policy_document(document: &PrunePolicyDocument) -> Result<(), String> {
    crate::prune_policy::validate_policy_document(document).map_err(|e| e.to_string())
}

pub fn prune_policies_to_proto(policies: &[PrunePolicy]) -> Vec<crate::store::prune::v1::Policy> {
    policies.iter().map(prune_policy_to_proto).collect()
}

fn selector_to_proto(mk: &Selector) -> ProtoSelector {
    ProtoSelector {
        prefix: mk.prefix.clone(),
        payload_regex: mk.payload_regex.0.clone(),
        ..Default::default()
    }
}

fn keys_scope_to_proto(s: &KeysScope) -> ProtoKeysScope {
    use crate::store::prune::v1::{PolicyGroupBy, PolicyOrderBy};

    let selector = selector_to_proto(&s.selector);
    let group_by = PolicyGroupBy {
        capture_groups: s
            .group_by
            .capture_groups
            .iter()
            .map(|s| s.0.clone())
            .collect(),
        ..Default::default()
    };
    let order_by = s.order_by.as_ref().map(|o| PolicyOrderBy {
        capture_group: o.capture_group.0.clone(),
        encoding: order_encoding_to_proto(&o.encoding).into(),
        ..Default::default()
    });
    ProtoKeysScope {
        selector: Some(selector).into(),
        group_by: Some(group_by).into(),
        order_by: order_by.into(),
        ..Default::default()
    }
}

fn prune_policy_to_proto(p: &PrunePolicy) -> crate::store::prune::v1::Policy {
    use crate::store::prune::v1::{
        policy_retain, Policy, PolicyRetain, RetainGreaterThan, RetainGreaterThanOrEqual,
        RetainKeepLatest,
    };

    let retain_kind = match &p.retain {
        RetainPolicy::KeepLatest { count } => {
            policy_retain::Kind::KeepLatest(Box::new(RetainKeepLatest {
                count: *count as u64,
                ..Default::default()
            }))
        }
        RetainPolicy::GreaterThan { threshold } => {
            policy_retain::Kind::GreaterThan(Box::new(RetainGreaterThan {
                threshold: *threshold,
                ..Default::default()
            }))
        }
        RetainPolicy::GreaterThanOrEqual { threshold } => {
            policy_retain::Kind::GreaterThanOrEqual(Box::new(RetainGreaterThanOrEqual {
                threshold: *threshold,
                ..Default::default()
            }))
        }
        RetainPolicy::DropAll => policy_retain::Kind::DropAll(Box::default()),
    };

    Policy {
        retain: Some(PolicyRetain {
            kind: Some(retain_kind),
            ..Default::default()
        })
        .into(),
        keys: Some(keys_scope_to_proto(&p.scope)).into(),
        ..Default::default()
    }
}

fn order_encoding_to_proto(enc: &OrderEncoding) -> PolicyOrderEncoding {
    match enc {
        OrderEncoding::BytesAsc => PolicyOrderEncoding::POLICY_ORDER_ENCODING_BYTES_ASC,
        OrderEncoding::U64Be => PolicyOrderEncoding::POLICY_ORDER_ENCODING_U64_BE,
        OrderEncoding::I64Be => PolicyOrderEncoding::POLICY_ORDER_ENCODING_I64_BE,
    }
}

/// Parses a `Prune` RPC request into the shared Rust document model (fixed document version).
pub fn parse_prune_policy_document_from_prune_request_view(
    req: &PruneRequestView<'_>,
) -> Result<PrunePolicyDocument, String> {
    let mut policies = Vec::with_capacity(req.policies.len());
    for p in req.policies.iter() {
        let policy = p.to_owned_message().map_err(|error| error.to_string())?;
        policies.push(parse_prune_policy_from_proto(&policy)?);
    }
    Ok(PrunePolicyDocument {
        version: PRUNE_POLICY_DOCUMENT_VERSION,
        policies,
    })
}

/// Parses a `Prune` RPC request and validates the resulting domain document.
pub fn parse_and_validate_policy_document(
    req: &PruneRequestView<'_>,
) -> Result<PrunePolicyDocument, String> {
    let document = parse_prune_policy_document_from_prune_request_view(req)?;
    validate_prune_policy_document(&document)?;
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::kv_codec::Utf8;
    use crate::prune_policy::{GroupBy, KeysScope, OrderBy, PrunePolicy, RetainPolicy};
    use crate::selector::Selector;

    #[test]
    fn owned_proto_policy_round_trips_to_domain_policy() {
        let expected = PrunePolicy {
            scope: KeysScope {
                selector: Selector {
                    prefix: bytes::Bytes::copy_from_slice(&[1]),
                    payload_regex: Utf8::from("(?s)^(?P<logical>.*)-(?P<version>.{8})$"),
                },
                group_by: GroupBy {
                    capture_groups: vec![Utf8::from("logical")],
                },
                order_by: Some(OrderBy {
                    capture_group: Utf8::from("version"),
                    encoding: OrderEncoding::U64Be,
                }),
            },
            retain: RetainPolicy::KeepLatest { count: 2 },
        };
        let proto = prune_policies_to_proto(std::slice::from_ref(&expected))
            .pop()
            .expect("policy");

        let actual = parse_prune_policy_from_proto(&proto).expect("from proto");

        assert_eq!(actual, expected);
    }

    #[test]
    fn parse_and_validate_rejects_invalid_policy_document() {
        use buffa::view::MessageView as _;
        use buffa::Message as _;

        let invalid = PrunePolicy {
            scope: KeysScope {
                selector: Selector {
                    prefix: bytes::Bytes::copy_from_slice(&[1]),
                    payload_regex: Utf8::from("(?s)^(?P<logical>.*)-(?P<version>.{8})$"),
                },
                group_by: GroupBy {
                    capture_groups: vec![Utf8::from("logical")],
                },
                order_by: Some(OrderBy {
                    capture_group: Utf8::from("version"),
                    encoding: OrderEncoding::U64Be,
                }),
            },
            retain: RetainPolicy::KeepLatest { count: 0 },
        };
        let request = crate::store::prune::v1::PruneRequest {
            policies: prune_policies_to_proto(&[invalid]),
            ..Default::default()
        };
        let bytes = request.encode_to_vec();
        let view = PruneRequestView::decode_view(&bytes).expect("decode view");

        let err = parse_and_validate_policy_document(&view).expect_err("invalid policy");

        assert!(err.contains("keep_latest count must be > 0"));
    }
}
