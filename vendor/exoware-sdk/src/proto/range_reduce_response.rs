use super::to_domain_reduced_value_from_view;
use crate::query;
use crate::{RangeReduceGroup, RangeReduceResponse, RangeReduceResult};

/// Converts a borrowed wire response into the domain reduction model.
pub fn to_domain_reduce_response(
    response: &query::ReduceResponseView<'_>,
) -> Result<RangeReduceResponse, String> {
    let results = response
        .results
        .iter()
        .map(|result| {
            let value = result
                .value
                .as_option()
                .map(to_domain_reduced_value_from_view)
                .transpose()?;
            Ok(RangeReduceResult { value })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let groups = response
        .groups
        .iter()
        .map(|group| {
            let mut group_values = Vec::with_capacity(group.group_values_present.len());
            let mut dense = group.group_values.iter();
            for &present in &group.group_values_present {
                if present {
                    let value = dense.next().ok_or_else(|| {
                        "group_values shorter than group_values_present true count".to_string()
                    })?;
                    group_values.push(Some(to_domain_reduced_value_from_view(value)?));
                } else {
                    group_values.push(None);
                }
            }
            if dense.next().is_some() {
                return Err("group_values longer than group_values_present true count".to_string());
            }
            let results = group
                .results
                .iter()
                .map(|result| {
                    let value = result
                        .value
                        .as_option()
                        .map(to_domain_reduced_value_from_view)
                        .transpose()?;
                    Ok(RangeReduceResult { value })
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(RangeReduceGroup {
                group_values,
                results,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(RangeReduceResponse { results, groups })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::{self, kv_reduced_value};
    use crate::{to_proto_reduce_response, KvReducedValue};

    #[test]
    fn domain_round_trip_preserves_sparse_group_keys() {
        let original = RangeReduceResponse {
            results: vec![RangeReduceResult {
                value: Some(KvReducedValue::Int64(9)),
            }],
            groups: vec![RangeReduceGroup {
                group_values: vec![
                    Some(KvReducedValue::Int64(1)),
                    None,
                    Some(KvReducedValue::Int64(3)),
                ],
                results: vec![RangeReduceResult {
                    value: Some(KvReducedValue::Int64(7)),
                }],
            }],
        };

        let (proto_results, proto_groups) = to_proto_reduce_response(original.clone());
        let wire = query::ReduceResponse {
            results: proto_results,
            groups: proto_groups,
            ..Default::default()
        };
        let frame = connectrpc::StreamMessage::from_message(&wire);
        let decoded = to_domain_reduce_response(frame.view()).expect("decode");

        assert_eq!(decoded, original);
        assert_eq!(
            decoded.groups[0].group_values,
            vec![
                Some(KvReducedValue::Int64(1)),
                None,
                Some(KvReducedValue::Int64(3)),
            ]
        );
    }

    #[test]
    fn decode_errors_on_mismatched_dense_length() {
        let bad = query::ReduceResponse {
            groups: vec![query::RangeReduceGroup {
                group_values: vec![query::KvReducedValue {
                    value: Some(kv_reduced_value::Value::Int64Value(1)),
                    ..Default::default()
                }],
                group_values_present: vec![true, true],
                ..Default::default()
            }],
            ..Default::default()
        };
        let frame = connectrpc::StreamMessage::from_message(&bad);
        let err = to_domain_reduce_response(frame.view()).unwrap_err();
        assert!(err.contains("shorter"), "unexpected message: {err}");
    }
}
