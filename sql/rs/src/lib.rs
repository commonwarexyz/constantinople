pub mod proto;
pub mod prune;
pub mod server;

mod aggregate;
mod builder;
mod codec;
mod diagnostics;
mod filter;
mod predicate;
mod scan;
mod schema;
mod types;
mod writer;

pub use schema::KvSchema;
pub use server::{sql_connect_stack, SqlConnect, SqlServer};
pub use types::default_orders_index_specs;
pub use types::{
    CellValue, IndexBackfillEvent, IndexBackfillOptions, IndexBackfillReport, IndexLayout,
    IndexSpec, TableColumnConfig,
};
pub use writer::{BatchReceipt, BatchWriter, PreparedBatch, TableWriter};

#[cfg(test)]
mod tests {
    #![allow(refining_impl_trait)]

    use super::aggregate::*;
    use super::builder::*;
    use super::codec::*;
    use super::diagnostics::*;
    use super::filter::*;
    use super::predicate::*;
    use super::scan::*;
    use super::types::*;
    use super::writer::*;
    use super::*;
    use commonware_codec::Encode;
    use datafusion::arrow::array::{Float64Array, Int64Array, LargeStringArray, StringViewArray};
    use datafusion::arrow::datatypes::{i256, DataType, TimeUnit};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::common::{config::ConfigOptions, ScalarValue};
    use datafusion::logical_expr::{Expr, Operator};
    use datafusion::physical_optimizer::limit_pushdown::LimitPushdown;
    use datafusion::physical_optimizer::PhysicalOptimizerRule;
    use datafusion::physical_plan::limit::GlobalLimitExec;
    use datafusion::physical_plan::ExecutionPlan;
    use datafusion::prelude::SessionContext;
    use exoware_sdk::keys::{Key, KeyCodec};
    use exoware_sdk::kv_codec::{
        canonicalize_reduced_group_values, decode_stored_row, encode_reduced_group_key,
        eval_predicate, KvReducedValue, StoredRow,
    };
    use exoware_sdk::{RangeReduceOp, RangeReduceRequest, StoreBatchUpload, StoreClient};
    use std::collections::{BTreeMap, HashSet};
    use std::ops::Bound::{Included, Unbounded};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axum::Router;
    use bytes::Bytes;
    use connectrpc::{Chain, ConnectError, ConnectRpcService, RequestContext as Context};
    use exoware_sdk::connect_compression_registry;
    use exoware_sdk::kv_codec::{eval_expr, expr_needs_value};
    use exoware_sdk::store::common::v1::KvEntry as ProtoKvEntry;
    use exoware_sdk::store::ingest::v1::{
        PutResponse as ProtoPutResponse, Service as IngestService,
        ServiceServer as IngestServiceServer,
    };
    use exoware_sdk::store::query::v1::{
        GetManyEntry as ProtoGetManyEntry, GetManyFrame as ProtoGetManyFrame,
        GetResponse as ProtoGetResponse, RangeFrame as ProtoRangeFrame,
        ReduceResponse as ProtoReduceResponse, Service as QueryService,
        ServiceServer as QueryServiceServer,
    };
    use exoware_sdk::RangeMode;
    use exoware_sdk::{
        parse_range_traversal_direction, to_domain_reduce_request, to_proto_optional_reduced_value,
        to_proto_reduced_value, RangeTraversalDirection, RangeTraversalModeError,
    };
    use exoware_sdk::{RangeReduceGroup, RangeReduceResponse, RangeReduceResult};
    use futures::{stream, TryStreamExt};
    use tokio::sync::{mpsc, oneshot, Notify};

    /// Assert EXPLAIN text includes the same `query_stats=...` suffix as [`format_query_stats_explain`].
    fn assert_explain_includes_query_stats_surface(
        explain: &str,
        surface: QueryStatsExplainSurface,
    ) {
        let expected = format!("query_stats={}", format_query_stats_explain(surface));
        assert!(
            explain.contains(&expected),
            "expected EXPLAIN output to include `{expected}`\n{explain}"
        );
    }

    fn simple_int64_model(prefix: u8) -> TableModel {
        let config = KvTableConfig::new(
            prefix,
            vec![TableColumnConfig::new("id", DataType::Int64, false)],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        TableModel::from_config(&config).unwrap()
    }

    fn codec_payload(codec: KeyCodec, key: &Key, offset: usize, len: usize) -> Vec<u8> {
        codec.read_payload(key, offset, len).expect("codec payload")
    }

    fn primary_payload(model: &TableModel, key: &Key, offset: usize, len: usize) -> Vec<u8> {
        codec_payload(model.primary_key_codec, key, offset, len)
    }

    fn index_payload(spec: &ResolvedIndexSpec, key: &Key, offset: usize, len: usize) -> Vec<u8> {
        codec_payload(spec.codec, key, offset, len)
    }

    fn matches_primary_key(table_prefix: u8, key: &Key) -> bool {
        primary_key_codec(table_prefix)
            .expect("primary codec")
            .matches(key)
    }

    fn matches_secondary_index_key(table_prefix: u8, index_id: u8, key: &Key) -> bool {
        secondary_index_codec(table_prefix, index_id)
            .expect("secondary codec")
            .matches(key)
    }

    fn test_model() -> (TableModel, Vec<ResolvedIndexSpec>) {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("region", DataType::Utf8, false),
                TableColumnConfig::new("customer_id", DataType::Int64, false),
                TableColumnConfig::new("order_id", DataType::Int64, false),
                TableColumnConfig::new("amount_cents", DataType::Int64, false),
                TableColumnConfig::new("status", DataType::Utf8, false),
            ],
            vec!["order_id".to_string()],
            vec![
                IndexSpec::new(
                    "region_customer",
                    vec!["region".to_string(), "customer_id".to_string()],
                )
                .expect("valid"),
                IndexSpec::new(
                    "status_customer",
                    vec!["status".to_string(), "customer_id".to_string()],
                )
                .expect("valid"),
            ],
        )
        .expect("valid config");
        let model = TableModel::from_config(&config).expect("model");
        let specs = model
            .resolve_index_specs(&config.index_specs)
            .expect("specs");
        (model, specs)
    }

    fn zorder_test_model() -> (TableModel, Vec<ResolvedIndexSpec>) {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("x", DataType::Int64, false),
                TableColumnConfig::new("y", DataType::Int64, false),
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("value", DataType::Int64, false),
            ],
            vec!["id".to_string()],
            vec![
                IndexSpec::new("xy_lex", vec!["x".to_string(), "y".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["value".to_string()]),
                IndexSpec::z_order("xy_z", vec!["x".to_string(), "y".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["value".to_string()]),
            ],
        )
        .expect("valid config");
        let model = TableModel::from_config(&config).expect("model");
        let specs = model
            .resolve_index_specs(&config.index_specs)
            .expect("specs");
        (model, specs)
    }

    #[derive(Clone)]
    struct MockState {
        kv: Arc<Mutex<BTreeMap<Key, Bytes>>>,
        range_calls: Arc<AtomicUsize>,
        range_reduce_calls: Arc<AtomicUsize>,
        sequence_number: Arc<AtomicU64>,
    }

    #[derive(Debug)]
    struct MockGroupedReduceState {
        group_values: Vec<Option<KvReducedValue>>,
        states: Vec<PartialAggregateState>,
    }

    type MockReduceRow = (Vec<Option<KvReducedValue>>, Vec<Option<KvReducedValue>>);

    fn extract_mock_reduce_row(
        key: &Key,
        value: &Bytes,
        request: &RangeReduceRequest,
    ) -> Option<MockReduceRow> {
        let needs_value = request
            .group_by
            .iter()
            .chain(
                request
                    .reducers
                    .iter()
                    .filter_map(|reducer| reducer.expr.as_ref()),
            )
            .any(expr_needs_value)
            || request
                .filter
                .as_ref()
                .is_some_and(exoware_sdk::kv_codec::predicate_needs_value);
        let archived = if needs_value {
            decode_stored_row(value.as_ref()).ok()
        } else {
            None
        };

        if let Some(filter) = &request.filter {
            if !eval_predicate(key, archived.as_ref(), filter).ok()? {
                return None;
            }
        }

        let mut group_values = Vec::with_capacity(request.group_by.len());
        for expr in &request.group_by {
            let extracted_value = eval_expr(key, archived.as_ref(), expr).ok()?;
            group_values.push(extracted_value);
        }
        canonicalize_reduced_group_values(&mut group_values);

        let mut reducer_values = Vec::with_capacity(request.reducers.len());
        for reducer in &request.reducers {
            let extracted_value = match (&reducer.expr, archived.as_ref()) {
                (None, _) => None,
                (Some(expr), _) => eval_expr(key, archived.as_ref(), expr).ok()?,
            };
            reducer_values.push(extracted_value);
        }

        Some((group_values, reducer_values))
    }

    #[allow(clippy::result_large_err)]
    fn ensure_min_sequence_number(
        token: &Arc<AtomicU64>,
        required: Option<u64>,
    ) -> Result<(), ConnectError> {
        let current = token.load(AtomicOrdering::Relaxed);
        if let Some(required) = required {
            if current < required {
                return Err(ConnectError::aborted(format!(
                    "consistency_not_ready: required={required}, current={current}"
                )));
            }
        }
        Ok(())
    }

    fn proto_range_entries_frame(results: Vec<(Key, Vec<u8>)>) -> ProtoRangeFrame {
        ProtoRangeFrame {
            results: results
                .into_iter()
                .map(|(key, value)| ProtoKvEntry {
                    key: key.to_vec(),
                    value: value.into(),
                    ..Default::default()
                })
                .collect(),
            detail: Some(query_detail(7)).into(),
            ..Default::default()
        }
    }

    fn query_detail(sequence_number: u64) -> exoware_sdk::store::query::v1::Detail {
        exoware_sdk::store::query::v1::Detail {
            sequence_number,
            extra: Default::default(),
            ..Default::default()
        }
    }

    fn final_range_detail_frame(sequence_number: u64) -> ProtoRangeFrame {
        ProtoRangeFrame {
            detail: Some(query_detail(sequence_number)).into(),
            ..Default::default()
        }
    }

    fn final_get_many_detail_frame(sequence_number: u64) -> ProtoGetManyFrame {
        ProtoGetManyFrame {
            detail: Some(query_detail(sequence_number)).into(),
            ..Default::default()
        }
    }

    #[derive(Clone)]
    struct MockIngestConnect {
        state: MockState,
    }

    impl IngestService for MockIngestConnect {
        async fn put(
            &self,
            _ctx: Context,
            request: buffa::view::OwnedView<
                exoware_sdk::store::ingest::v1::PutRequestView<'static>,
            >,
        ) -> connectrpc::ServiceResult<ProtoPutResponse> {
            let mut parsed = Vec::<(Key, Bytes)>::new();
            let wire = request.bytes();
            for kv in request.kvs.iter() {
                parsed.push((wire.slice_ref(kv.key), wire.slice_ref(kv.value)));
            }
            let mut guard = self.state.kv.lock().expect("kv mutex poisoned");
            for (key, value) in parsed.iter() {
                guard.insert(key.clone(), value.clone());
            }
            let seq = self
                .state
                .sequence_number
                .fetch_add(1, AtomicOrdering::SeqCst)
                + 1;
            connectrpc::Response::ok(ProtoPutResponse {
                sequence_number: seq,
                ..Default::default()
            })
        }
    }

    #[derive(Clone)]
    struct MockQueryConnect {
        state: MockState,
    }

    impl QueryService for MockQueryConnect {
        async fn get(
            &self,
            _ctx: Context,
            request: buffa::view::OwnedView<exoware_sdk::store::query::v1::GetRequestView<'static>>,
        ) -> connectrpc::ServiceResult<ProtoGetResponse> {
            ensure_min_sequence_number(&self.state.sequence_number, request.min_sequence_number)?;
            let key: Key = request.bytes().slice_ref(request.key);
            let guard = self.state.kv.lock().expect("kv mutex poisoned");
            let value = guard.get(&key).cloned();
            let token = self.state.sequence_number.load(AtomicOrdering::Relaxed);
            connectrpc::Response::ok(ProtoGetResponse {
                value,
                detail: Some(query_detail(token)).into(),
                ..Default::default()
            })
        }

        async fn range(
            &self,
            _ctx: Context,
            request: buffa::view::OwnedView<
                exoware_sdk::store::query::v1::RangeRequestView<'static>,
            >,
        ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<ProtoRangeFrame>> {
            ensure_min_sequence_number(&self.state.sequence_number, request.min_sequence_number)?;
            self.state.range_calls.fetch_add(1, AtomicOrdering::SeqCst);

            let wire = request.bytes();
            let start_key: Key = wire.slice_ref(request.start);
            let end_key: Key = wire.slice_ref(request.end);
            let limit = request.limit.map(|v| v as usize).unwrap_or(usize::MAX);
            let batch_size = usize::try_from(request.batch_size).unwrap_or(usize::MAX);
            if batch_size == 0 {
                return Err(ConnectError::invalid_argument(
                    "invalid batch_size: expected positive integer",
                ));
            }

            let mode = match parse_range_traversal_direction(request.mode) {
                Ok(RangeTraversalDirection::Forward) => RangeMode::Forward,
                Ok(RangeTraversalDirection::Reverse) => RangeMode::Reverse,
                Err(RangeTraversalModeError::UnknownWireValue(v)) => {
                    return Err(ConnectError::invalid_argument(format!(
                        "unknown TraversalMode enum value {v}"
                    )));
                }
            };

            let state = self.state.clone();
            let guard = state.kv.lock().expect("kv mutex poisoned");
            // Match `StoreEngine::range_scan`: inclusive [start, end]; empty end = unbounded.
            let range: (std::ops::Bound<&Key>, std::ops::Bound<&Key>) = (
                Included(&start_key),
                if end_key.is_empty() {
                    Unbounded
                } else {
                    Included(&end_key)
                },
            );
            let range_iter = guard.range::<Key, _>(range);
            let iter: Box<dyn Iterator<Item = (&Key, &Bytes)> + Send> = match mode {
                RangeMode::Forward => Box::new(range_iter),
                RangeMode::Reverse => Box::new(range_iter.rev()),
            };
            let mut results: Vec<ProtoKvEntry> = Vec::new();
            for (key, value) in iter.take(limit) {
                results.push(ProtoKvEntry {
                    key: key.to_vec(),
                    value: value.clone(),
                    ..Default::default()
                });
            }
            drop(guard);
            let token = state.sequence_number.load(AtomicOrdering::Relaxed);
            let batch = batch_size.max(1);
            let mut frames: Vec<Result<ProtoRangeFrame, ConnectError>> = Vec::new();
            let mut emitted_frame = false;
            for chunk in results.chunks(batch) {
                frames.push(Ok(ProtoRangeFrame {
                    results: chunk.to_vec(),
                    detail: Some(query_detail(token)).into(),
                    ..Default::default()
                }));
                emitted_frame = true;
            }
            if !emitted_frame {
                frames.push(Ok(final_range_detail_frame(token)));
            }
            Ok(connectrpc::Response::stream(stream::iter(frames)))
        }

        async fn get_many(
            &self,
            _ctx: Context,
            request: buffa::view::OwnedView<
                exoware_sdk::store::query::v1::GetManyRequestView<'static>,
            >,
        ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<ProtoGetManyFrame>> {
            ensure_min_sequence_number(&self.state.sequence_number, request.min_sequence_number)?;
            let batch_size = usize::try_from(request.batch_size)
                .unwrap_or(usize::MAX)
                .max(1);
            let guard = self.state.kv.lock().expect("kv mutex poisoned");
            let mut entries: Vec<ProtoGetManyEntry> = Vec::new();
            let wire = request.bytes();
            for key_bytes in request.keys.iter() {
                let key: Key = wire.slice_ref(key_bytes);
                let value = guard.get(&key).cloned();
                entries.push(ProtoGetManyEntry {
                    key: key.to_vec(),
                    value,
                    ..Default::default()
                });
            }
            drop(guard);
            let token = self.state.sequence_number.load(AtomicOrdering::Relaxed);
            let mut frames: Vec<Result<ProtoGetManyFrame, ConnectError>> = Vec::new();
            let mut emitted_frame = false;
            for chunk in entries.chunks(batch_size) {
                frames.push(Ok(ProtoGetManyFrame {
                    results: chunk.to_vec(),
                    detail: Some(query_detail(token)).into(),
                    ..Default::default()
                }));
                emitted_frame = true;
            }
            if !emitted_frame {
                frames.push(Ok(final_get_many_detail_frame(token)));
            }
            Ok(connectrpc::Response::stream(stream::iter(frames)))
        }

        async fn reduce(
            &self,
            _ctx: Context,
            request: buffa::view::OwnedView<
                exoware_sdk::store::query::v1::ReduceRequestView<'static>,
            >,
        ) -> connectrpc::ServiceResult<ProtoReduceResponse> {
            ensure_min_sequence_number(&self.state.sequence_number, request.min_sequence_number)?;
            self.state
                .range_reduce_calls
                .fetch_add(1, AtomicOrdering::SeqCst);
            let owned = request.to_owned_message();
            let start_key: Key = owned.start.clone().into();
            let end_key: Key = owned.end.clone().into();
            let reduce_req = owned
                .params
                .as_option()
                .ok_or_else(|| ConnectError::invalid_argument("missing range reduce params"))?;
            let domain_request =
                to_domain_reduce_request(reduce_req).map_err(ConnectError::invalid_argument)?;

            let state = self.state.clone();
            let guard = state.kv.lock().expect("kv mutex poisoned");
            let mut states = domain_request.group_by.is_empty().then(|| {
                domain_request
                    .reducers
                    .iter()
                    .map(|reducer| PartialAggregateState::from_op(reducer.op))
                    .collect::<Vec<_>>()
            });
            let mut grouped = BTreeMap::<Vec<u8>, MockGroupedReduceState>::new();

            let range: (std::ops::Bound<&Key>, std::ops::Bound<&Key>) = (
                Included(&start_key),
                if end_key.is_empty() {
                    Unbounded
                } else {
                    Included(&end_key)
                },
            );
            for (key, value) in guard.range::<Key, _>(range) {
                let Some((group_values, reducer_values)) =
                    extract_mock_reduce_row(key, value, &domain_request)
                else {
                    continue;
                };
                if domain_request.group_by.is_empty() {
                    let states = states.as_mut().expect("scalar states");
                    for ((state, reducer), value) in states
                        .iter_mut()
                        .zip(domain_request.reducers.iter())
                        .zip(reducer_values)
                    {
                        match reducer.op {
                            RangeReduceOp::CountAll => state
                                .merge_partial(reducer.op, Some(&KvReducedValue::UInt64(1)))
                                .map_err(|e| ConnectError::internal(e.to_string()))?,
                            RangeReduceOp::CountField => {
                                let partial =
                                    KvReducedValue::UInt64(if value.is_some() { 1 } else { 0 });
                                state
                                    .merge_partial(reducer.op, Some(&partial))
                                    .map_err(|e| ConnectError::internal(e.to_string()))?
                            }
                            _ => state
                                .merge_partial(reducer.op, value.as_ref())
                                .map_err(|e| ConnectError::internal(e.to_string()))?,
                        }
                    }
                } else {
                    let group_key = encode_reduced_group_key(&group_values);
                    let group =
                        grouped
                            .entry(group_key)
                            .or_insert_with(|| MockGroupedReduceState {
                                group_values: group_values.clone(),
                                states: domain_request
                                    .reducers
                                    .iter()
                                    .map(|reducer| PartialAggregateState::from_op(reducer.op))
                                    .collect(),
                            });
                    for ((state, reducer), value) in group
                        .states
                        .iter_mut()
                        .zip(domain_request.reducers.iter())
                        .zip(reducer_values)
                    {
                        match reducer.op {
                            RangeReduceOp::CountAll => state
                                .merge_partial(reducer.op, Some(&KvReducedValue::UInt64(1)))
                                .map_err(|e| ConnectError::internal(e.to_string()))?,
                            RangeReduceOp::CountField => {
                                let partial =
                                    KvReducedValue::UInt64(if value.is_some() { 1 } else { 0 });
                                state
                                    .merge_partial(reducer.op, Some(&partial))
                                    .map_err(|e| ConnectError::internal(e.to_string()))?
                            }
                            _ => state
                                .merge_partial(reducer.op, value.as_ref())
                                .map_err(|e| ConnectError::internal(e.to_string()))?,
                        }
                    }
                }
            }

            let response = if let Some(states) = states {
                RangeReduceResponse {
                    results: states
                        .iter()
                        .map(|state| RangeReduceResult {
                            value: match state {
                                PartialAggregateState::Count(count) => {
                                    Some(KvReducedValue::UInt64(*count))
                                }
                                PartialAggregateState::Sum(value)
                                | PartialAggregateState::Min(value)
                                | PartialAggregateState::Max(value) => value.clone(),
                            },
                        })
                        .collect(),
                    groups: Vec::new(),
                }
            } else {
                RangeReduceResponse {
                    results: Vec::new(),
                    groups: grouped
                        .into_values()
                        .map(|group| RangeReduceGroup {
                            group_values: group.group_values,
                            results: group
                                .states
                                .into_iter()
                                .map(|state| RangeReduceResult {
                                    value: match state {
                                        PartialAggregateState::Count(count) => {
                                            Some(KvReducedValue::UInt64(count))
                                        }
                                        PartialAggregateState::Sum(value)
                                        | PartialAggregateState::Min(value)
                                        | PartialAggregateState::Max(value) => value,
                                    },
                                })
                                .collect(),
                        })
                        .collect(),
                }
            };
            drop(guard);
            let token = state.sequence_number.load(AtomicOrdering::Relaxed);
            connectrpc::Response::ok(ProtoReduceResponse {
                results: response
                    .results
                    .into_iter()
                    .map(|result| exoware_sdk::store::query::v1::RangeReduceResult {
                        value: result.value.map(to_proto_reduced_value).into(),
                        ..Default::default()
                    })
                    .collect(),
                groups: response
                    .groups
                    .into_iter()
                    .map(|group| {
                        let group_values_present: Vec<bool> =
                            group.group_values.iter().map(|v| v.is_some()).collect();
                        exoware_sdk::store::query::v1::RangeReduceGroup {
                            group_values: group
                                .group_values
                                .into_iter()
                                .map(to_proto_optional_reduced_value)
                                .collect(),
                            group_values_present,
                            results: group
                                .results
                                .into_iter()
                                .map(|result| exoware_sdk::store::query::v1::RangeReduceResult {
                                    value: result.value.map(to_proto_reduced_value).into(),
                                    ..Default::default()
                                })
                                .collect(),
                            ..Default::default()
                        }
                    })
                    .collect(),
                detail: Some(query_detail(token)).into(),
                ..Default::default()
            })
        }
    }

    async fn spawn_mock_server(state: MockState) -> (String, oneshot::Sender<()>) {
        let connect = ConnectRpcService::new(Chain(
            IngestServiceServer::new(MockIngestConnect {
                state: state.clone(),
            }),
            QueryServiceServer::new(MockQueryConnect { state }),
        ))
        .with_compression(connect_compression_registry());
        let app = Router::new().fallback_service(connect);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock server");
        let addr = listener.local_addr().expect("local addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("mock server should run");
        });
        (format!("http://{addr}"), shutdown_tx)
    }

    fn assert_count_scalar(batch: &RecordBatch, col_idx: usize, row_idx: usize, expected: u64) {
        let scalar = ScalarValue::try_from_array(batch.column(col_idx), row_idx)
            .expect("count scalar should decode");
        match scalar {
            ScalarValue::UInt64(Some(value)) => assert_eq!(value, expected),
            ScalarValue::Int64(Some(value)) => assert_eq!(value, expected as i64),
            other => panic!("unexpected count scalar: {other:?}"),
        }
    }

    fn collect_i64_column(batches: &[RecordBatch], col_idx: usize) -> Vec<i64> {
        let mut values = Vec::new();
        for batch in batches {
            for row_idx in 0..batch.num_rows() {
                match ScalarValue::try_from_array(batch.column(col_idx), row_idx)
                    .expect("int64 scalar should decode")
                {
                    ScalarValue::Int64(Some(value)) => values.push(value),
                    other => panic!("unexpected int64 scalar: {other:?}"),
                }
            }
        }
        values
    }

    async fn explain_plan_rows(ctx: &SessionContext, sql: &str) -> Vec<(String, String)> {
        let batches = ctx
            .sql(&format!("EXPLAIN {sql}"))
            .await
            .expect("explain query")
            .collect()
            .await
            .expect("explain collect");
        let mut rows = Vec::new();
        for batch in batches {
            for row_idx in 0..batch.num_rows() {
                let plan_type = scalar_to_string(
                    &ScalarValue::try_from_array(batch.column(0), row_idx).expect("plan type"),
                )
                .expect("plan type string");
                let plan = scalar_to_string(
                    &ScalarValue::try_from_array(batch.column(1), row_idx).expect("plan"),
                )
                .expect("plan string");
                rows.push((plan_type, plan));
            }
        }
        rows
    }

    fn physical_plan_text(rows: &[(String, String)]) -> String {
        rows.iter()
            .filter(|(plan_type, _)| plan_type.contains("physical_plan"))
            .map(|(_, plan)| plan.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[tokio::test]
    async fn explain_reports_full_scan_like_primary_key_scan() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");
        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        let explain =
            physical_plan_text(&explain_plan_rows(&ctx, "SELECT id, status FROM orders").await);
        assert!(explain.contains("KvScanExec:"));
        assert!(explain.contains("mode=primary_key"));
        assert!(explain.contains("predicate=<none>"));
        assert!(explain.contains("row_recheck=false"));
        assert!(explain.contains("full_scan_like=true"));
        assert_explain_includes_query_stats_surface(
            &explain,
            QueryStatsExplainSurface::StreamedRangeDetail,
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn explain_reports_secondary_index_scan_and_row_recheck() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");
        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        let explain = physical_plan_text(
            &explain_plan_rows(
                &ctx,
                "SELECT id, status, amount_cents FROM orders \
                 WHERE status = 'open' AND amount_cents >= 5",
            )
            .await,
        );
        assert!(explain.contains("KvScanExec:"));
        assert!(explain.contains("mode=secondary_index(status_idx, lexicographic)"));
        assert!(explain.contains("predicate=status = 'open' AND amount_cents >= 5"));
        assert!(explain.contains("exact=false"));
        assert!(explain.contains("row_recheck=true"));
        assert!(explain.contains("full_scan_like=false"));
        assert_explain_includes_query_stats_surface(
            &explain,
            QueryStatsExplainSurface::StreamedRangeDetail,
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn explain_reports_zorder_secondary_index_scan() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "points",
                vec![
                    TableColumnConfig::new("x", DataType::Int64, false),
                    TableColumnConfig::new("y", DataType::Int64, false),
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("value", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![
                    IndexSpec::z_order("xy_z", vec!["x".to_string(), "y".to_string()])
                        .expect("valid")
                        .with_cover_columns(vec!["value".to_string()]),
                ],
            )
            .expect("schema");
        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        let explain = physical_plan_text(
            &explain_plan_rows(
                &ctx,
                "SELECT id, value FROM points \
                 WHERE x >= 1 AND x <= 2 AND y >= 1 AND y <= 2",
            )
            .await,
        );
        assert!(explain.contains("KvScanExec:"));
        assert!(explain.contains("mode=secondary_index(xy_z, z_order)"));
        assert!(explain.contains("exact=false"));
        assert!(explain.contains("row_recheck=true"));

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn explain_reports_aggregate_pushdown_access_path_details() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");
        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        let explain = physical_plan_text(
            &explain_plan_rows(
                &ctx,
                "SELECT status, SUM(amount_cents) AS total_cents \
                 FROM orders WHERE status = 'open' GROUP BY status",
            )
            .await,
        );
        assert!(explain.contains("KvAggregateExec:"));
        assert!(explain.contains("grouped=true"));
        assert!(explain.contains("job0{mode=secondary_index(status_idx, lexicographic)"));
        assert!(explain.contains("predicate=status = 'open'"));
        assert!(explain.contains("exact=true"));
        assert!(explain.contains("row_recheck=false"));
        assert_explain_includes_query_stats_surface(
            &explain,
            QueryStatsExplainSurface::RangeReduceDetail,
        );

        let _ = shutdown_tx.send(());
    }

    #[test]
    fn index_spec_constructor_sets_name_and_keys() {
        let spec = IndexSpec::new(
            "status_customer",
            vec!["status".to_string(), "customer_id".to_string()],
        )
        .expect("valid index spec");
        assert_eq!(spec.name(), "status_customer");
        assert_eq!(spec.key_columns(), &["status", "customer_id"]);
        assert!(spec.cover_columns().is_empty());
    }

    #[test]
    fn index_spec_cover_columns_are_configurable_in_code() {
        let spec = IndexSpec::new("status_customer", vec!["status".to_string()])
            .expect("valid")
            .with_cover_columns(vec!["amount_cents".to_string()]);
        assert_eq!(spec.key_columns(), &["status"]);
        assert_eq!(spec.cover_columns(), &["amount_cents"]);
    }

    #[test]
    fn describe_in_list_places_truncation_ellipsis_inside_parentheses() {
        let rendered = describe_in_list((1..=6).map(|v| v.to_string()));
        assert_eq!(rendered, "IN (1, 2, 3, 4, 5, ...)");
    }

    #[test]
    fn normalize_sum_case_then_one_uses_countall_optimization() {
        let (model, _) = test_model();
        let argument = normalize_case_then_expr(
            AggregatePushdownFunction::Sum,
            &Expr::Literal(ScalarValue::Int64(Some(1)), None),
            &model,
        )
        .expect("normalize");
        assert_eq!(argument, AggregatePushdownArgument::CountAll);
    }

    #[test]
    fn normalize_count_case_then_literal_uses_countall_optimization() {
        use datafusion::logical_expr::col;

        let (model, _) = test_model();
        let case_expr = Expr::Case(datafusion::logical_expr::expr::Case {
            expr: None,
            when_then_expr: vec![(
                Box::new(col("status").eq(Expr::Literal(
                    ScalarValue::Utf8(Some("open".to_string())),
                    None,
                ))),
                Box::new(Expr::Literal(
                    ScalarValue::Utf8(Some("yes".to_string())),
                    None,
                )),
            )],
            else_expr: Some(Box::new(Expr::Literal(ScalarValue::Utf8(None), None))),
        });

        let (func, argument, filter) =
            normalize_count_aggregate_argument(&case_expr, &model).expect("normalize");
        assert_eq!(func, AggregatePushdownFunction::Count);
        assert_eq!(argument, AggregatePushdownArgument::CountAll);
        assert!(filter.is_some());
    }

    #[test]
    fn reduced_value_to_scalar_preserves_timestamp_timezone_label() {
        let tz: Arc<str> = Arc::from("America/New_York");
        let scalar = reduced_value_to_scalar(
            Some(KvReducedValue::Timestamp(1_700_000_000_000_000)),
            &DataType::Timestamp(TimeUnit::Microsecond, Some(tz.clone())),
        )
        .expect("timestamp scalar");
        assert_eq!(
            scalar,
            ScalarValue::TimestampMicrosecond(Some(1_700_000_000_000_000), Some(tz))
        );
    }

    #[test]
    fn index_spec_cover_pk_column_is_rejected() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("status", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                .expect("valid")
                .with_cover_columns(vec!["id".to_string()])],
        )
        .expect("valid config");
        let model = TableModel::from_config(&config).expect("model");
        let err = model
            .resolve_index_specs(&config.index_specs)
            .expect_err("covering a PK column must be rejected");
        assert!(err.contains("primary key column"));
    }

    #[test]
    fn access_plan_requires_cover_columns_for_index_scan() {
        let (model, _) = test_model();
        let predicate = QueryPredicate::default();
        let projection = Some(vec![
            *model.columns_by_name.get("order_id").unwrap(),
            *model.columns_by_name.get("amount_cents").unwrap(),
        ]);
        let plan = ScanAccessPlan::new(&model, &projection, &predicate);

        let no_cover = IndexSpec::new("status_idx", vec!["status".to_string()]).unwrap();
        let with_cover = IndexSpec::new("status_idx", vec!["status".to_string()])
            .unwrap()
            .with_cover_columns(vec!["amount_cents".to_string()]);
        let no_cover_resolved = model.resolve_index_specs(&[no_cover]).unwrap();
        let with_cover_resolved = model.resolve_index_specs(&[with_cover]).unwrap();

        assert!(!plan.index_covers_required_non_pk(&no_cover_resolved[0]));
        assert!(plan.index_covers_required_non_pk(&with_cover_resolved[0]));
    }

    #[test]
    fn choose_index_plan_prefers_longer_prefix() {
        let (model, specs) = test_model();
        let region_idx = *model.columns_by_name.get("region").unwrap();
        let customer_idx = *model.columns_by_name.get("customer_id").unwrap();
        let mut predicate = QueryPredicate::default();
        predicate.constraints.insert(
            region_idx,
            PredicateConstraint::StringEq("us-east".to_string()),
        );
        predicate.constraints.insert(
            customer_idx,
            PredicateConstraint::IntRange {
                min: Some(10),
                max: Some(20),
            },
        );
        let plan = predicate
            .choose_index_plan(&model, &specs)
            .expect("plan")
            .expect("exists");
        assert_eq!(plan.spec_idx, 0);
        assert_eq!(plan.constrained_prefix_len, 2);
    }

    #[test]
    fn choose_index_plan_prefers_covering_index_when_prefix_strength_ties() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("status", DataType::Utf8, false),
                TableColumnConfig::new("amount_cents", DataType::Int64, false),
            ],
            vec!["id".to_string()],
            vec![
                IndexSpec::new("status_plain", vec!["status".to_string()]).expect("valid"),
                IndexSpec::new("status_covering", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()]),
            ],
        )
        .expect("config");
        let model = TableModel::from_config(&config).expect("model");
        let specs = model
            .resolve_index_specs(&config.index_specs)
            .expect("specs");
        let status_idx = *model.columns_by_name.get("status").unwrap();
        let amount_idx = *model.columns_by_name.get("amount_cents").unwrap();
        let mut predicate = QueryPredicate::default();
        predicate.constraints.insert(
            status_idx,
            PredicateConstraint::StringEq("open".to_string()),
        );
        predicate.constraints.insert(
            amount_idx,
            PredicateConstraint::IntRange {
                min: Some(10),
                max: None,
            },
        );

        let plan = predicate
            .choose_index_plan(&model, &specs)
            .expect("plan")
            .expect("exists");
        assert_eq!(specs[plan.spec_idx].name, "status_covering");
    }

    #[test]
    fn choose_index_plan_prefers_zorder_for_multi_column_box_constraints() {
        let (model, specs) = zorder_test_model();
        let x_idx = *model.columns_by_name.get("x").unwrap();
        let y_idx = *model.columns_by_name.get("y").unwrap();
        let mut predicate = QueryPredicate::default();
        predicate.constraints.insert(
            x_idx,
            PredicateConstraint::IntRange {
                min: Some(1),
                max: Some(2),
            },
        );
        predicate.constraints.insert(
            y_idx,
            PredicateConstraint::IntRange {
                min: Some(1),
                max: Some(2),
            },
        );

        let plan = predicate
            .choose_index_plan(&model, &specs)
            .expect("plan")
            .expect("exists");
        assert_eq!(specs[plan.spec_idx].name, "xy_z");
        assert_eq!(specs[plan.spec_idx].layout, IndexLayout::ZOrder);
        assert_eq!(plan.constrained_column_count, 2);
    }

    #[test]
    fn secondary_index_key_round_trip() {
        let (model, specs) = test_model();
        let row = KvRow {
            values: vec![
                CellValue::Utf8("us-east".to_string()),
                CellValue::Int64(42),
                CellValue::Int64(9001),
                CellValue::Int64(1500),
                CellValue::Utf8("open".to_string()),
            ],
        };
        let key = encode_secondary_index_key(model.table_prefix, &specs[0], &model, &row)
            .expect("encode");
        let decoded = decode_secondary_index_key(model.table_prefix, &specs[0], &model, &key)
            .expect("decode");
        let region_idx = *model.columns_by_name.get("region").unwrap();
        let customer_idx = *model.columns_by_name.get("customer_id").unwrap();
        assert!(matches!(
            decoded.values.get(&region_idx),
            Some(CellValue::Utf8(v)) if v == "us-east"
        ));
        assert!(matches!(
            decoded.values.get(&customer_idx),
            Some(CellValue::Int64(v)) if *v == 42
        ));
        assert!(matches!(
            &decoded.primary_key_values[0],
            CellValue::Int64(9001)
        ));
        let expected_pk = encode_primary_key_from_row(model.table_prefix, &row, &model)
            .expect("primary key should encode");
        assert_eq!(decoded.primary_key, expected_pk);
    }

    #[test]
    fn zorder_secondary_index_key_round_trip() {
        let (model, specs) = zorder_test_model();
        let row = KvRow {
            values: vec![
                CellValue::Int64(2),
                CellValue::Int64(1),
                CellValue::Int64(42),
                CellValue::Int64(900),
            ],
        };
        let key = encode_secondary_index_key(model.table_prefix, &specs[1], &model, &row)
            .expect("encode");
        let decoded = decode_secondary_index_key(model.table_prefix, &specs[1], &model, &key)
            .expect("decode");
        let x_idx = *model.columns_by_name.get("x").unwrap();
        let y_idx = *model.columns_by_name.get("y").unwrap();
        assert!(matches!(
            decoded.values.get(&x_idx),
            Some(CellValue::Int64(v)) if *v == 2
        ));
        assert!(matches!(
            decoded.values.get(&y_idx),
            Some(CellValue::Int64(v)) if *v == 1
        ));
        assert!(matches!(
            &decoded.primary_key_values[0],
            CellValue::Int64(42)
        ));
    }

    #[test]
    fn table_config_supports_non_orders_schema() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("tenant", DataType::Utf8, false),
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("score", DataType::Int64, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new(
                "tenant_score",
                vec!["tenant".to_string(), "score".to_string()],
            )
            .expect("valid")],
        )
        .expect("schema agnostic config should be valid");
        assert_eq!(config.primary_key_columns, vec!["id".to_string()]);
        assert_eq!(config.columns.len(), 3);
    }

    #[test]
    fn table_config_accepts_float64_column() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("price", DataType::Float64, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("Float64 column should be accepted");
        assert_eq!(config.columns.len(), 2);
    }

    #[test]
    fn table_config_accepts_boolean_column() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("active", DataType::Boolean, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("Boolean column should be accepted");
        assert_eq!(config.columns.len(), 2);
    }

    #[test]
    fn build_projected_batch_uses_large_utf8_type() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("name", DataType::LargeUtf8, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let rows = vec![KvRow {
            values: vec![CellValue::Int64(1), CellValue::Utf8("hello".to_string())],
        }];
        let batch = build_projected_batch(&rows, &model, &model.schema, &None).unwrap();
        assert_eq!(batch.column(1).data_type(), &DataType::LargeUtf8);
        let values = batch
            .column(1)
            .as_any()
            .downcast_ref::<LargeStringArray>()
            .expect("must build LargeStringArray");
        assert_eq!(values.value(0), "hello");
    }

    #[test]
    fn build_projected_batch_uses_utf8_view_type() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("name", DataType::Utf8View, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let rows = vec![KvRow {
            values: vec![CellValue::Int64(1), CellValue::Utf8("hello".to_string())],
        }];
        let batch = build_projected_batch(&rows, &model, &model.schema, &None).unwrap();
        assert_eq!(batch.column(1).data_type(), &DataType::Utf8View);
        let values = batch
            .column(1)
            .as_any()
            .downcast_ref::<StringViewArray>()
            .expect("must build StringViewArray");
        assert_eq!(values.value(0), "hello");
    }

    #[test]
    fn f64_ordered_encoding_preserves_order() {
        let values = [
            f64::NEG_INFINITY,
            f64::MIN,
            -1000.0,
            -1.0,
            -0.001,
            0.0,
            0.001,
            1.0,
            1000.0,
            f64::MAX,
            f64::INFINITY,
        ];
        let encoded: Vec<[u8; 8]> = values.iter().map(|v| encode_f64_ordered(*v)).collect();
        for i in 0..encoded.len() - 1 {
            assert!(
                encoded[i] < encoded[i + 1],
                "encode_f64_ordered({}) >= encode_f64_ordered({})",
                values[i],
                values[i + 1]
            );
        }
    }

    #[test]
    fn f64_ordered_encoding_round_trip() {
        let values = [
            f64::MIN,
            -42.5,
            -0.0,
            0.0,
            3.125,
            f64::MAX,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ];
        for v in values {
            let encoded = encode_f64_ordered(v);
            let decoded = decode_f64_ordered(encoded);
            assert!(
                v.to_bits() == decoded.to_bits(),
                "round-trip failed for {v}: got {decoded}"
            );
        }
    }

    fn mixed_model() -> (TableModel, Vec<ResolvedIndexSpec>) {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("label", DataType::Utf8, false),
                TableColumnConfig::new("score", DataType::Float64, false),
                TableColumnConfig::new("active", DataType::Boolean, false),
            ],
            vec!["id".to_string()],
            vec![
                IndexSpec::new(
                    "active_score",
                    vec!["active".to_string(), "score".to_string()],
                )
                .expect("valid"),
                IndexSpec::new("label_idx", vec!["label".to_string()]).expect("valid"),
            ],
        )
        .expect("valid config");
        let model = TableModel::from_config(&config).expect("model");
        let specs = model
            .resolve_index_specs(&config.index_specs)
            .expect("specs");
        (model, specs)
    }

    #[test]
    fn secondary_index_key_round_trip_with_float64_and_boolean() {
        let (model, specs) = mixed_model();
        let row = KvRow {
            values: vec![
                CellValue::Int64(100),
                CellValue::Utf8("hello".to_string()),
                CellValue::Float64(3.125),
                CellValue::Boolean(true),
            ],
        };
        let key = encode_secondary_index_key(model.table_prefix, &specs[0], &model, &row)
            .expect("encode");
        let decoded = decode_secondary_index_key(model.table_prefix, &specs[0], &model, &key)
            .expect("decode");
        let active_idx = *model.columns_by_name.get("active").unwrap();
        let score_idx = *model.columns_by_name.get("score").unwrap();
        assert!(matches!(
            decoded.values.get(&active_idx),
            Some(CellValue::Boolean(true))
        ));
        assert!(
            matches!(decoded.values.get(&score_idx), Some(CellValue::Float64(v)) if (*v - 3.125).abs() < f64::EPSILON)
        );
        assert!(matches!(
            &decoded.primary_key_values[0],
            CellValue::Int64(100)
        ));
    }

    #[test]
    fn base_row_round_trip_with_float64_and_boolean() {
        let (model, _specs) = mixed_model();
        let row = KvRow {
            values: vec![
                CellValue::Int64(42),
                CellValue::Utf8("world".to_string()),
                CellValue::Float64(-99.5),
                CellValue::Boolean(false),
            ],
        };
        let encoded = encode_base_row_value(&row, &model).expect("encode");
        let decoded =
            decode_base_row(vec![CellValue::Int64(42)], &encoded, &model).expect("decode");
        assert!(matches!(&decoded.values[0], CellValue::Int64(42)));
        assert!(matches!(&decoded.values[1], CellValue::Utf8(v) if v == "world"));
        assert!(
            matches!(&decoded.values[2], CellValue::Float64(v) if (*v - (-99.5)).abs() < f64::EPSILON)
        );
        assert!(matches!(&decoded.values[3], CellValue::Boolean(false)));
    }

    #[test]
    fn predicate_bool_eq_matches() {
        let (model, _specs) = mixed_model();
        let active_idx = *model.columns_by_name.get("active").unwrap();
        let mut pred = QueryPredicate::default();
        pred.constraints
            .insert(active_idx, PredicateConstraint::BoolEq(true));
        let row_true = KvRow {
            values: vec![
                CellValue::Int64(1),
                CellValue::Utf8("a".to_string()),
                CellValue::Float64(1.0),
                CellValue::Boolean(true),
            ],
        };
        let row_false = KvRow {
            values: vec![
                CellValue::Int64(2),
                CellValue::Utf8("b".to_string()),
                CellValue::Float64(2.0),
                CellValue::Boolean(false),
            ],
        };
        assert!(pred.matches_row(&row_true));
        assert!(!pred.matches_row(&row_false));
    }

    #[test]
    fn predicate_float_range_matches() {
        let (model, _specs) = mixed_model();
        let score_idx = *model.columns_by_name.get("score").unwrap();
        let mut pred = QueryPredicate::default();
        pred.constraints.insert(
            score_idx,
            PredicateConstraint::FloatRange {
                min: Some((2.0, true)),
                max: Some((5.0, false)),
            },
        );
        let make_row = |score: f64| KvRow {
            values: vec![
                CellValue::Int64(1),
                CellValue::Utf8("a".to_string()),
                CellValue::Float64(score),
                CellValue::Boolean(true),
            ],
        };
        assert!(!pred.matches_row(&make_row(1.99)));
        assert!(pred.matches_row(&make_row(2.0)));
        assert!(pred.matches_row(&make_row(3.5)));
        assert!(pred.matches_row(&make_row(4.99)));
        assert!(!pred.matches_row(&make_row(5.0)));
        assert!(!pred.matches_row(&make_row(5.01)));
    }

    #[test]
    fn float_range_rejects_nan_row_value() {
        let constraint = PredicateConstraint::FloatRange {
            min: Some((0.0, true)),
            max: Some((10.0, true)),
        };
        assert!(!matches_constraint(
            &CellValue::Float64(f64::NAN),
            &constraint
        ));
    }

    #[test]
    fn index_plan_with_boolean_prefix() {
        let (model, specs) = mixed_model();
        let active_idx = *model.columns_by_name.get("active").unwrap();
        let mut pred = QueryPredicate::default();
        pred.constraints
            .insert(active_idx, PredicateConstraint::BoolEq(true));
        let plan = pred
            .choose_index_plan(&model, &specs)
            .expect("plan")
            .expect("should find index");
        assert_eq!(plan.spec_idx, 0);
        assert_eq!(plan.constrained_prefix_len, 1);
    }

    #[test]
    fn float_constraint_contradiction() {
        let mut lo: Option<(f64, bool)> = None;
        let mut hi: Option<(f64, bool)> = None;
        let mut contradiction = false;
        apply_float_constraint(&mut lo, &mut hi, Operator::Gt, 10.0, &mut contradiction);
        assert!(!contradiction);
        apply_float_constraint(&mut lo, &mut hi, Operator::Lt, 5.0, &mut contradiction);
        assert!(contradiction);
    }

    #[test]
    fn float_constraint_eq_then_range_contradicts() {
        let mut lo: Option<(f64, bool)> = None;
        let mut hi: Option<(f64, bool)> = None;
        let mut contradiction = false;
        apply_float_constraint(&mut lo, &mut hi, Operator::Eq, 5.0, &mut contradiction);
        assert!(!contradiction);
        apply_float_constraint(&mut lo, &mut hi, Operator::Gt, 5.0, &mut contradiction);
        assert!(contradiction);
    }

    #[test]
    fn float_nan_literal_comparison_marks_contradiction() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("score", DataType::Float64, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        use datafusion::logical_expr::col;
        let filter = col("score").gt(Expr::Literal(ScalarValue::Float64(Some(f64::NAN)), None));
        assert!(QueryPredicate::supports_filter(&filter, &model));

        let pred = QueryPredicate::from_filters(&[filter], &model);
        assert!(
            pred.contradiction,
            "comparison with NaN literal must produce contradiction"
        );
    }

    #[test]
    fn null_predicate_merges_are_order_independent() {
        use datafusion::logical_expr::col;
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("label", DataType::Utf8, true),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let label_idx = *model.columns_by_name.get("label").unwrap();
        let eq_foo = col("label").eq(Expr::Literal(
            ScalarValue::Utf8(Some("foo".to_string())),
            None,
        ));
        let is_null = col("label").is_null();
        let is_not_null = col("label").is_not_null();
        let row_foo = KvRow {
            values: vec![CellValue::Int64(1), CellValue::Utf8("foo".to_string())],
        };

        // (label = 'foo') AND (label IS NOT NULL) — IS NOT NULL is implied;
        // predicate must reduce to StringEq('foo') in either order.
        for filters in [[&eq_foo, &is_not_null], [&is_not_null, &eq_foo]] {
            let owned: Vec<Expr> = filters.iter().map(|e| (*e).clone()).collect();
            let pred = QueryPredicate::from_filters(&owned, &model);
            assert!(!pred.contradiction);
            assert!(matches!(
                pred.constraints.get(&label_idx),
                Some(PredicateConstraint::StringEq(s)) if s == "foo"
            ));
            assert!(pred.matches_row(&row_foo));
        }

        // (label = 'foo') AND (label IS NULL) — must contradict in either order.
        for filters in [[&eq_foo, &is_null], [&is_null, &eq_foo]] {
            let owned: Vec<Expr> = filters.iter().map(|e| (*e).clone()).collect();
            assert!(QueryPredicate::from_filters(&owned, &model).contradiction);
        }
    }

    #[test]
    fn non_nullable_null_predicates_simplify() {
        use datafusion::logical_expr::col;
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("label", DataType::Utf8, true),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        let is_null = col("id").is_null();
        assert!(QueryPredicate::supports_filter(&is_null, &model));
        assert!(QueryPredicate::from_filters(&[is_null], &model).contradiction);

        let is_not_null = col("id").is_not_null();
        assert!(QueryPredicate::supports_filter(&is_not_null, &model));
        let pred = QueryPredicate::from_filters(&[is_not_null], &model);
        assert!(!pred.contradiction);
        assert!(pred.constraints.is_empty());
    }

    #[test]
    fn null_literal_comparisons_are_contradictions() {
        use datafusion::logical_expr::col;
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("label", DataType::Utf8, true),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        for filter in [
            col("label").eq(Expr::Literal(ScalarValue::Utf8(None), None)),
            col("id").gt(Expr::Literal(ScalarValue::Int64(None), None)),
        ] {
            assert!(QueryPredicate::supports_filter(&filter, &model));
            assert!(QueryPredicate::from_filters(&[filter], &model).contradiction);
        }
    }

    #[test]
    fn in_predicate_merges_with_comparisons_order_independent() {
        use datafusion::logical_expr::{col, in_list};
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("label", DataType::Utf8, true),
                TableColumnConfig::new("score", DataType::Int64, true),
                TableColumnConfig::new("version", DataType::UInt64, true),
                TableColumnConfig::new("hash", DataType::FixedSizeBinary(2), true),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let label_idx = *model.columns_by_name.get("label").unwrap();
        let score_idx = *model.columns_by_name.get("score").unwrap();
        let version_idx = *model.columns_by_name.get("version").unwrap();
        let hash_idx = *model.columns_by_name.get("hash").unwrap();

        let label_in = in_list(
            col("label"),
            vec![
                Expr::Literal(ScalarValue::Utf8(Some("foo".to_string())), None),
                Expr::Literal(ScalarValue::Utf8(Some("bar".to_string())), None),
            ],
            false,
        );
        let label_eq = col("label").eq(Expr::Literal(
            ScalarValue::Utf8(Some("foo".to_string())),
            None,
        ));
        for filters in [[&label_in, &label_eq], [&label_eq, &label_in]] {
            let owned: Vec<Expr> = filters.iter().map(|e| (*e).clone()).collect();
            let pred = QueryPredicate::from_filters(&owned, &model);
            assert!(!pred.contradiction);
            assert!(matches!(
                pred.constraints.get(&label_idx),
                Some(PredicateConstraint::StringEq(v)) if v == "foo"
            ));
        }

        let label_miss = col("label").eq(Expr::Literal(
            ScalarValue::Utf8(Some("baz".to_string())),
            None,
        ));
        for filters in [[&label_in, &label_miss], [&label_miss, &label_in]] {
            let owned: Vec<Expr> = filters.iter().map(|e| (*e).clone()).collect();
            assert!(QueryPredicate::from_filters(&owned, &model).contradiction);
        }

        let score_in = in_list(
            col("score"),
            vec![
                Expr::Literal(ScalarValue::Int64(Some(1)), None),
                Expr::Literal(ScalarValue::Int64(Some(2)), None),
                Expr::Literal(ScalarValue::Int64(Some(3)), None),
            ],
            false,
        );
        let score_gt = col("score").gt(Expr::Literal(ScalarValue::Int64(Some(1)), None));
        for filters in [[&score_in, &score_gt], [&score_gt, &score_in]] {
            let owned: Vec<Expr> = filters.iter().map(|e| (*e).clone()).collect();
            let pred = QueryPredicate::from_filters(&owned, &model);
            assert!(!pred.contradiction);
            assert!(matches!(
                pred.constraints.get(&score_idx),
                Some(PredicateConstraint::IntIn(v)) if v == &vec![2, 3]
            ));
        }

        let version_in = in_list(
            col("version"),
            vec![
                Expr::Literal(ScalarValue::UInt64(Some(1)), None),
                Expr::Literal(ScalarValue::UInt64(Some(2)), None),
                Expr::Literal(ScalarValue::UInt64(Some(3)), None),
            ],
            false,
        );
        let version_lt = col("version").lt(Expr::Literal(ScalarValue::UInt64(Some(3)), None));
        for filters in [[&version_in, &version_lt], [&version_lt, &version_in]] {
            let owned: Vec<Expr> = filters.iter().map(|e| (*e).clone()).collect();
            let pred = QueryPredicate::from_filters(&owned, &model);
            assert!(!pred.contradiction);
            assert!(matches!(
                pred.constraints.get(&version_idx),
                Some(PredicateConstraint::UInt64In(v)) if v == &vec![1, 2]
            ));
        }

        let hash_in = in_list(
            col("hash"),
            vec![
                Expr::Literal(
                    ScalarValue::FixedSizeBinary(2, Some(vec![0xAA, 0xAA])),
                    None,
                ),
                Expr::Literal(
                    ScalarValue::FixedSizeBinary(2, Some(vec![0xBB, 0xBB])),
                    None,
                ),
            ],
            false,
        );
        let hash_eq = col("hash").eq(Expr::Literal(
            ScalarValue::FixedSizeBinary(2, Some(vec![0xAA, 0xAA])),
            None,
        ));
        for filters in [[&hash_in, &hash_eq], [&hash_eq, &hash_in]] {
            let owned: Vec<Expr> = filters.iter().map(|e| (*e).clone()).collect();
            let pred = QueryPredicate::from_filters(&owned, &model);
            assert!(!pred.contradiction);
            assert!(matches!(
                pred.constraints.get(&hash_idx),
                Some(PredicateConstraint::FixedBinaryEq(v)) if v == &vec![0xAA, 0xAA]
            ));
        }
    }

    #[test]
    fn empty_and_null_in_lists_are_exact() {
        use datafusion::logical_expr::{col, in_list};
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("label", DataType::Utf8, true),
                TableColumnConfig::new("score", DataType::Float64, true),
                TableColumnConfig::new("version", DataType::UInt64, true),
                TableColumnConfig::new("hash", DataType::FixedSizeBinary(2), true),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let id_idx = *model.columns_by_name.get("id").unwrap();

        for filter in [
            in_list(col("id"), vec![], false),
            in_list(
                col("id"),
                vec![Expr::Literal(ScalarValue::Int64(None), None)],
                false,
            ),
            in_list(
                col("label"),
                vec![Expr::Literal(ScalarValue::Utf8(None), None)],
                false,
            ),
            in_list(
                col("score"),
                vec![Expr::Literal(ScalarValue::Float64(None), None)],
                false,
            ),
            in_list(
                col("version"),
                vec![Expr::Literal(ScalarValue::UInt64(None), None)],
                false,
            ),
            in_list(
                col("hash"),
                vec![Expr::Literal(ScalarValue::FixedSizeBinary(2, None), None)],
                false,
            ),
        ] {
            assert!(QueryPredicate::supports_filter(&filter, &model));
            assert!(QueryPredicate::from_filters(&[filter], &model).contradiction);
        }

        let filter = in_list(
            col("id"),
            vec![
                Expr::Literal(ScalarValue::Int64(Some(7)), None),
                Expr::Literal(ScalarValue::Int64(None), None),
            ],
            false,
        );
        assert!(QueryPredicate::supports_filter(&filter, &model));
        let pred = QueryPredicate::from_filters(&[filter], &model);
        assert!(!pred.contradiction);
        assert!(matches!(
            pred.constraints.get(&id_idx),
            Some(PredicateConstraint::IntRange {
                min: Some(7),
                max: Some(7)
            })
        ));
    }

    #[test]
    fn table_config_accepts_date32_column() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("created", DataType::Date32, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("Date32 column should be accepted");
        assert_eq!(config.columns.len(), 2);
    }

    #[test]
    fn table_config_accepts_timestamp_column() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new(
                    "ts",
                    DataType::Timestamp(TimeUnit::Microsecond, None),
                    false,
                ),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("Timestamp column should be accepted");
        let schema = config.to_schema();
        assert!(matches!(
            schema.field(1).data_type(),
            DataType::Timestamp(TimeUnit::Microsecond, _)
        ));
    }

    #[test]
    fn table_config_normalizes_timestamp_to_microsecond() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new(
                    "ts",
                    DataType::Timestamp(TimeUnit::Nanosecond, None),
                    false,
                ),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("Nanosecond timestamp should be accepted");
        let schema = config.to_schema();
        assert!(matches!(
            schema.field(1).data_type(),
            DataType::Timestamp(TimeUnit::Microsecond, _)
        ));
    }

    #[test]
    fn table_config_accepts_decimal128_column() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("price", DataType::Decimal128(10, 2), false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("Decimal128 column should be accepted");
        assert_eq!(config.columns.len(), 2);
    }

    #[test]
    fn table_config_accepts_list_column() {
        use datafusion::arrow::datatypes::Field;

        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new(
                    "tags",
                    DataType::List(Arc::new(Field::new("item", DataType::Utf8, false))),
                    false,
                ),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("List<Utf8> column should be accepted");
        assert_eq!(config.columns.len(), 2);
    }

    #[test]
    fn list_column_rejected_in_index() {
        use datafusion::arrow::datatypes::Field;

        let result = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new(
                    "tags",
                    DataType::List(Arc::new(Field::new("item", DataType::Utf8, false))),
                    false,
                ),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("tags_idx", vec!["tags".to_string()]).unwrap()],
        );
        assert!(
            result.is_err() || {
                let config = result.unwrap();
                let model = TableModel::from_config(&config).unwrap();
                model.resolve_index_specs(&config.index_specs).is_err()
            }
        );
    }

    #[test]
    fn i32_ordered_encoding_round_trip() {
        let values = [i32::MIN, -1000, -1, 0, 1, 1000, i32::MAX];
        for v in values {
            assert_eq!(decode_i32_ordered(encode_i32_ordered(v)), v);
        }
        let encoded: Vec<[u8; 4]> = values.iter().map(|v| encode_i32_ordered(*v)).collect();
        for i in 0..encoded.len() - 1 {
            assert!(encoded[i] < encoded[i + 1]);
        }
    }

    #[test]
    fn i128_ordered_encoding_round_trip() {
        let values = [i128::MIN, -1, 0, 1, 1234567890123456789, i128::MAX];
        for v in values {
            assert_eq!(decode_i128_ordered(encode_i128_ordered(v)), v);
        }
        let encoded: Vec<[u8; 16]> = values.iter().map(|v| encode_i128_ordered(*v)).collect();
        for i in 0..encoded.len() - 1 {
            assert!(encoded[i] < encoded[i + 1]);
        }
    }

    fn extended_model() -> (TableModel, Vec<ResolvedIndexSpec>) {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("created", DataType::Date32, false),
                TableColumnConfig::new(
                    "ts",
                    DataType::Timestamp(TimeUnit::Microsecond, None),
                    false,
                ),
                TableColumnConfig::new("price", DataType::Decimal128(10, 2), false),
                TableColumnConfig::new("label", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![
                IndexSpec::new(
                    "date_label",
                    vec!["created".to_string(), "label".to_string()],
                )
                .expect("valid"),
                IndexSpec::new("price_idx", vec!["price".to_string()]).expect("valid"),
            ],
        )
        .expect("valid config");
        let model = TableModel::from_config(&config).expect("model");
        let specs = model
            .resolve_index_specs(&config.index_specs)
            .expect("specs");
        (model, specs)
    }

    #[test]
    fn secondary_index_key_round_trip_date32_and_decimal128() {
        let (model, specs) = extended_model();
        let row = KvRow {
            values: vec![
                CellValue::Int64(42),
                CellValue::Date32(19000),
                CellValue::Timestamp(1_700_000_000_000_000),
                CellValue::Decimal128(123456),
                CellValue::Utf8("hello".to_string()),
            ],
        };
        let key = encode_secondary_index_key(model.table_prefix, &specs[0], &model, &row)
            .expect("encode");
        let decoded = decode_secondary_index_key(model.table_prefix, &specs[0], &model, &key)
            .expect("decode");
        let created_idx = *model.columns_by_name.get("created").unwrap();
        let label_idx = *model.columns_by_name.get("label").unwrap();
        assert!(matches!(
            decoded.values.get(&created_idx),
            Some(CellValue::Date32(19000))
        ));
        assert!(matches!(
            decoded.values.get(&label_idx),
            Some(CellValue::Utf8(v)) if v == "hello"
        ));
        assert!(matches!(
            &decoded.primary_key_values[0],
            CellValue::Int64(42)
        ));

        let key2 = encode_secondary_index_key(model.table_prefix, &specs[1], &model, &row)
            .expect("encode");
        let decoded2 = decode_secondary_index_key(model.table_prefix, &specs[1], &model, &key2)
            .expect("decode");
        let price_idx = *model.columns_by_name.get("price").unwrap();
        assert!(matches!(
            decoded2.values.get(&price_idx),
            Some(CellValue::Decimal128(123456))
        ));
        assert!(matches!(
            &decoded2.primary_key_values[0],
            CellValue::Int64(42)
        ));
    }

    #[test]
    fn base_row_round_trip_with_date32_timestamp_decimal128() {
        let (model, _specs) = extended_model();
        let row = KvRow {
            values: vec![
                CellValue::Int64(7),
                CellValue::Date32(19500),
                CellValue::Timestamp(1_700_000_000_000_000),
                CellValue::Decimal128(-9876543),
                CellValue::Utf8("world".to_string()),
            ],
        };
        let encoded = encode_base_row_value(&row, &model).expect("encode");
        let decoded = decode_base_row(vec![CellValue::Int64(7)], &encoded, &model).expect("decode");
        assert!(matches!(&decoded.values[0], CellValue::Int64(7)));
        assert!(matches!(&decoded.values[1], CellValue::Date32(19500)));
        assert!(matches!(
            &decoded.values[2],
            CellValue::Timestamp(1_700_000_000_000_000)
        ));
        assert!(matches!(
            &decoded.values[3],
            CellValue::Decimal128(-9876543)
        ));
        assert!(matches!(&decoded.values[4], CellValue::Utf8(v) if v == "world"));
    }

    #[test]
    fn base_row_round_trip_with_list() {
        use datafusion::arrow::datatypes::Field;

        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new(
                    "tags",
                    DataType::List(Arc::new(Field::new("item", DataType::Utf8, false))),
                    false,
                ),
                TableColumnConfig::new(
                    "scores",
                    DataType::List(Arc::new(Field::new("item", DataType::Int64, false))),
                    false,
                ),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("valid");
        let model = TableModel::from_config(&config).expect("model");
        let row = KvRow {
            values: vec![
                CellValue::Int64(1),
                CellValue::List(vec![
                    CellValue::Utf8("a".to_string()),
                    CellValue::Utf8("b".to_string()),
                ]),
                CellValue::List(vec![CellValue::Int64(10), CellValue::Int64(20)]),
            ],
        };
        let encoded = encode_base_row_value(&row, &model).expect("encode");
        let decoded = decode_base_row(vec![CellValue::Int64(1)], &encoded, &model).expect("decode");
        assert!(matches!(&decoded.values[0], CellValue::Int64(1)));
        match &decoded.values[1] {
            CellValue::List(items) => {
                assert_eq!(items.len(), 2);
                assert!(matches!(&items[0], CellValue::Utf8(v) if v == "a"));
                assert!(matches!(&items[1], CellValue::Utf8(v) if v == "b"));
            }
            _ => panic!("expected List"),
        }
        match &decoded.values[2] {
            CellValue::List(items) => {
                assert_eq!(items.len(), 2);
                assert!(matches!(&items[0], CellValue::Int64(10)));
                assert!(matches!(&items[1], CellValue::Int64(20)));
            }
            _ => panic!("expected List"),
        }
    }

    #[test]
    fn decimal128_constraint_range() {
        let mut min: Option<i128> = None;
        let mut max: Option<i128> = None;
        let mut contradiction = false;
        apply_decimal128_constraint(&mut min, &mut max, Operator::GtEq, 100, &mut contradiction);
        assert!(!contradiction);
        apply_decimal128_constraint(&mut min, &mut max, Operator::LtEq, 200, &mut contradiction);
        assert!(!contradiction);
        assert_eq!(min, Some(100));
        assert_eq!(max, Some(200));
        assert!(in_i128_bounds(150, min, max));
        assert!(!in_i128_bounds(99, min, max));
        assert!(!in_i128_bounds(201, min, max));
    }

    #[test]
    fn decimal256_gt_max_is_contradiction() {
        let mut min: Option<i256> = None;
        let mut max: Option<i256> = None;
        let mut contradiction = false;
        apply_i256_constraint(
            &mut min,
            &mut max,
            Operator::Gt,
            i256::MAX,
            &mut contradiction,
        );
        assert!(contradiction);
        assert_eq!(min, None);
        assert_eq!(max, None);
    }

    #[test]
    fn decimal256_lt_min_is_contradiction() {
        let mut min: Option<i256> = None;
        let mut max: Option<i256> = None;
        let mut contradiction = false;
        apply_i256_constraint(
            &mut min,
            &mut max,
            Operator::Lt,
            i256::MIN,
            &mut contradiction,
        );
        assert!(contradiction);
        assert_eq!(min, None);
        assert_eq!(max, None);
    }

    #[test]
    fn date32_index_bound_clamps_on_i64_overflow() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("created", DataType::Date32, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("created_idx", vec!["created".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();

        let created_idx = *model.columns_by_name.get("created").unwrap();
        let mut pred = QueryPredicate::default();
        pred.constraints.insert(
            created_idx,
            PredicateConstraint::IntRange {
                min: Some(i32::MAX as i64 + 1),
                max: None,
            },
        );

        let start = pred
            .encode_index_bound_key(model.table_prefix, &model, &specs[0], 1, false)
            .unwrap();
        let end = pred
            .encode_index_bound_key(model.table_prefix, &model, &specs[0], 1, true)
            .unwrap();

        assert!(
            start <= end,
            "lower bound must not exceed upper bound (was wrapping via as i32)"
        );

        let encoded_lower = specs[0].codec.read_payload_exact::<4>(&start, 0).unwrap();
        let decoded_lower = decode_i32_ordered(encoded_lower);
        assert_eq!(
            decoded_lower,
            i32::MAX,
            "out-of-range i64 must clamp to i32::MAX, not wrap"
        );
    }

    #[test]
    fn timestamp_nanos_gt_uses_floor_division() {
        let micros = timestamp_scalar_to_micros_for_op(
            &ScalarValue::TimestampNanosecond(Some(-1500), None),
            Operator::Gt,
        )
        .unwrap();
        assert_eq!(micros, -2, "Gt on -1500ns should floor to -2us");

        let mut min: Option<i64> = None;
        let mut max: Option<i64> = None;
        let mut contradiction = false;
        apply_int_constraint(&mut min, &mut max, Operator::Gt, micros, &mut contradiction);
        assert_eq!(min, Some(-1), "Gt(-2us) + 1 = min -1us");

        let row_at_minus_1 = CellValue::Timestamp(-1);
        assert!(matches_constraint(
            &row_at_minus_1,
            &PredicateConstraint::IntRange { min, max }
        ));
    }

    #[test]
    fn timestamp_nanos_lteq_uses_floor_division() {
        let micros = timestamp_scalar_to_micros_for_op(
            &ScalarValue::TimestampNanosecond(Some(-1500), None),
            Operator::LtEq,
        )
        .unwrap();
        assert_eq!(micros, -2, "LtEq on -1500ns should floor to -2us");

        let row_at_minus_1 = CellValue::Timestamp(-1);
        assert!(
            !matches_constraint(
                &row_at_minus_1,
                &PredicateConstraint::IntRange {
                    min: None,
                    max: Some(micros)
                }
            ),
            "-1us (-1000ns) > -1500ns, must not satisfy <= -1500ns"
        );
    }

    #[test]
    fn timestamp_nanos_gteq_uses_ceil_division() {
        let micros = timestamp_scalar_to_micros_for_op(
            &ScalarValue::TimestampNanosecond(Some(-1500), None),
            Operator::GtEq,
        )
        .unwrap();
        assert_eq!(micros, -1, "GtEq on -1500ns should ceil to -1us");
    }

    #[test]
    fn timestamp_nanos_lt_uses_ceil_division() {
        let micros = timestamp_scalar_to_micros_for_op(
            &ScalarValue::TimestampNanosecond(Some(-1500), None),
            Operator::Lt,
        )
        .unwrap();
        assert_eq!(micros, -1, "Lt on -1500ns should ceil to -1us");

        let mut min: Option<i64> = None;
        let mut max: Option<i64> = None;
        let mut contradiction = false;
        apply_int_constraint(&mut min, &mut max, Operator::Lt, micros, &mut contradiction);
        assert_eq!(max, Some(-2), "Lt(-1us) - 1 = max -2us");
    }

    #[test]
    fn timestamp_nanos_eq_non_aligned_is_contradiction() {
        let result = timestamp_scalar_to_micros_for_op(
            &ScalarValue::TimestampNanosecond(Some(-1500), None),
            Operator::Eq,
        );
        assert!(
            result.is_none(),
            "non-aligned ns Eq must produce contradiction"
        );
    }

    #[test]
    fn timestamp_nanos_exact_multiple_is_unchanged() {
        for op in [
            Operator::Eq,
            Operator::Gt,
            Operator::GtEq,
            Operator::Lt,
            Operator::LtEq,
        ] {
            let micros = timestamp_scalar_to_micros_for_op(
                &ScalarValue::TimestampNanosecond(Some(-2000), None),
                op,
            )
            .unwrap();
            assert_eq!(micros, -2, "exact multiple -2000ns = -2us for {op:?}");
        }
    }

    #[test]
    fn float64_index_bounds_include_infinity() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("val", DataType::Float64, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("val_idx", vec!["val".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();

        let pred = QueryPredicate::default();
        let start = pred
            .encode_index_bound_key(model.table_prefix, &model, &specs[0], 0, false)
            .unwrap();
        let end = pred
            .encode_index_bound_key(model.table_prefix, &model, &specs[0], 0, true)
            .unwrap();

        let neg_inf_row = KvRow {
            values: vec![CellValue::Int64(1), CellValue::Float64(f64::NEG_INFINITY)],
        };
        let pos_inf_row = KvRow {
            values: vec![CellValue::Int64(2), CellValue::Float64(f64::INFINITY)],
        };

        let neg_inf_key =
            encode_secondary_index_key(model.table_prefix, &specs[0], &model, &neg_inf_row)
                .unwrap();
        let pos_inf_key =
            encode_secondary_index_key(model.table_prefix, &specs[0], &model, &pos_inf_row)
                .unwrap();

        assert!(
            neg_inf_key >= start,
            "NEG_INFINITY row key must be within scan start bound"
        );
        assert!(
            pos_inf_key <= end,
            "INFINITY row key must be within scan end bound"
        );
    }

    #[test]
    fn distinct_table_prefixes_produce_non_overlapping_pk_ranges() {
        let range_a = primary_key_prefix_range(1);
        let range_b = primary_key_prefix_range(2);
        assert!(
            range_a.end < range_b.start,
            "table prefix 1 pk range must be entirely below table prefix 2"
        );
    }

    #[test]
    fn distinct_table_prefixes_isolate_primary_keys() {
        let model_1 = simple_int64_model(1);
        let model_2 = simple_int64_model(2);
        let pk = CellValue::Int64(42);
        let key_a = encode_primary_key(1, &[&pk], &model_1).expect("pk key encodes");
        let key_b = encode_primary_key(2, &[&pk], &model_2).expect("pk key encodes");
        assert_ne!(key_a, key_b, "same PK under different prefixes must differ");
        assert!(
            decode_primary_key(1, &key_a, &model_1).is_some(),
            "key_a must decode under prefix 1"
        );
        assert!(
            decode_primary_key(2, &key_a, &model_2).is_none(),
            "key_a must NOT decode under prefix 2"
        );
        assert!(
            decode_primary_key(2, &key_b, &model_2).is_some(),
            "key_b must decode under prefix 2"
        );
    }

    #[test]
    fn distinct_table_prefixes_isolate_secondary_keys() {
        let config_a = KvTableConfig::new(
            10,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("name", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("name_idx", vec!["name".to_string()]).unwrap()],
        )
        .unwrap();
        let config_b = KvTableConfig::new(
            11,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("name", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("name_idx", vec!["name".to_string()]).unwrap()],
        )
        .unwrap();

        let model_a = TableModel::from_config(&config_a).unwrap();
        let specs_a = model_a.resolve_index_specs(&config_a.index_specs).unwrap();
        let model_b = TableModel::from_config(&config_b).unwrap();
        let specs_b = model_b.resolve_index_specs(&config_b.index_specs).unwrap();

        let row = KvRow {
            values: vec![CellValue::Int64(1), CellValue::Utf8("alice".to_string())],
        };
        let key_a =
            encode_secondary_index_key(model_a.table_prefix, &specs_a[0], &model_a, &row).unwrap();
        let key_b =
            encode_secondary_index_key(model_b.table_prefix, &specs_b[0], &model_b, &row).unwrap();

        assert_ne!(
            key_a, key_b,
            "same row under different prefixes must differ"
        );
        assert!(
            decode_secondary_index_key(model_a.table_prefix, &specs_a[0], &model_a, &key_a)
                .is_some()
        );
        assert!(
            decode_secondary_index_key(model_a.table_prefix, &specs_a[0], &model_a, &key_b)
                .is_none(),
            "key from table B must not decode under table A's prefix"
        );
    }

    #[test]
    fn table_prefix_stored_in_model() {
        let config = KvTableConfig::new(
            12,
            vec![TableColumnConfig::new("id", DataType::Int64, false)],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        assert_eq!(model.table_prefix, 12);
    }

    #[test]
    fn codec_layout_exposes_payload_bits_under_reserved_family_bits() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("bucket", DataType::FixedSizeBinary(16), false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("bucket_idx", vec!["bucket".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let spec = model
            .resolve_index_specs(&config.index_specs)
            .unwrap()
            .remove(0);

        let mut current_primary = HashSet::new();
        let mut current_secondary = HashSet::new();

        fn first_twelve_bits_of_key(key: &[u8]) -> u16 {
            let first = u16::from(*key.first().unwrap_or(&0));
            let second = u16::from(*key.get(1).unwrap_or(&0));
            (first << 4) | (second >> 4)
        }

        for first_byte in 0u8..=255 {
            let mut id = vec![0u8; 16];
            id[0] = first_byte;
            let mut bucket = vec![0u8; 16];
            bucket[0] = first_byte;

            let pk = CellValue::FixedBinary(id.clone());
            let current_pk = encode_primary_key(model.table_prefix, &[&pk], &model).unwrap();
            current_primary.insert(first_twelve_bits_of_key(&current_pk));

            let row = KvRow {
                values: vec![
                    CellValue::FixedBinary(id),
                    CellValue::FixedBinary(bucket.clone()),
                ],
            };
            let current_index =
                encode_secondary_index_key(model.table_prefix, &spec, &model, &row).unwrap();
            current_secondary.insert(first_twelve_bits_of_key(&current_index));
        }

        // Primary keys reserve 5 high bits for family, leaving 7 payload bits in the first
        // 12 bits of the physical key. Varying one payload byte therefore spans 2^7 values.
        assert_eq!(current_primary.len(), 128);

        // Secondary index keys reserve 9 high bits for family, leaving 3 payload bits in the
        // first 12 bits. Varying one payload byte therefore spans 2^3 values.
        assert_eq!(current_secondary.len(), 8);
    }

    #[test]
    fn kv_schema_auto_assigns_sequential_prefixes() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .table(
                "alpha",
                vec![TableColumnConfig::new("id", DataType::Int64, false)],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap()
            .table(
                "beta",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("name", DataType::Utf8, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap()
            .table(
                "gamma",
                vec![TableColumnConfig::new("id", DataType::Int64, false)],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap();

        assert_eq!(schema.table_count(), 3);
    }

    #[test]
    fn kv_schema_allows_max_codec_table_count_and_rejects_overflow() {
        let client = StoreClient::new("http://localhost:10000");
        let mut schema = KvSchema::new(client);
        for idx in 0..MAX_TABLES {
            schema = schema
                .table(
                    format!("t{idx}"),
                    vec![TableColumnConfig::new("id", DataType::Int64, false)],
                    vec!["id".to_string()],
                    vec![],
                )
                .expect("tables up to codec capacity should be accepted");
        }
        assert_eq!(schema.table_count(), MAX_TABLES);

        let overflow = schema.table(
            "overflow",
            vec![TableColumnConfig::new("id", DataType::Int64, false)],
            vec!["id".to_string()],
            vec![],
        );
        match overflow {
            Ok(_) => panic!("overflow table should be rejected"),
            Err(err) => assert!(
                err.contains(&format!(
                    "too many tables for codec layout (max {MAX_TABLES})"
                )),
                "overflow table should be rejected with codec-capacity error"
            ),
        }
    }

    #[test]
    fn sequential_prefixes_produce_non_overlapping_pk_ranges() {
        let range_a = primary_key_prefix_range(0);
        let range_b = primary_key_prefix_range(1);
        let range_c = primary_key_prefix_range(2);
        assert!(range_a.end < range_b.start);
        assert!(range_b.end < range_c.start);
    }

    #[test]
    fn sequential_prefixes_isolate_primary_keys() {
        let model_0 = simple_int64_model(0);
        let model_1 = simple_int64_model(1);
        let pk = CellValue::Int64(42);
        let key_a = encode_primary_key(0, &[&pk], &model_0).expect("pk key encodes");
        let key_b = encode_primary_key(1, &[&pk], &model_1).expect("pk key encodes");
        assert_ne!(key_a, key_b);
        assert!(decode_primary_key(0, &key_a, &model_0).is_some());
        assert!(decode_primary_key(1, &key_a, &model_1).is_none());
        assert!(decode_primary_key(0, &key_b, &model_0).is_none());
        assert!(decode_primary_key(1, &key_b, &model_1).is_some());
    }

    #[test]
    fn sequential_prefixes_isolate_secondary_keys() {
        let config_a = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("name", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("name_idx", vec!["name".to_string()]).unwrap()],
        )
        .unwrap();
        let config_b = KvTableConfig::new(
            1,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("name", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("name_idx", vec!["name".to_string()]).unwrap()],
        )
        .unwrap();

        let model_a = TableModel::from_config(&config_a).unwrap();
        let specs_a = model_a.resolve_index_specs(&config_a.index_specs).unwrap();
        let model_b = TableModel::from_config(&config_b).unwrap();
        let specs_b = model_b.resolve_index_specs(&config_b.index_specs).unwrap();

        let row = KvRow {
            values: vec![CellValue::Int64(1), CellValue::Utf8("alice".to_string())],
        };
        let key_a =
            encode_secondary_index_key(model_a.table_prefix, &specs_a[0], &model_a, &row).unwrap();
        let key_b =
            encode_secondary_index_key(model_b.table_prefix, &specs_b[0], &model_b, &row).unwrap();
        assert_ne!(key_a, key_b);
        assert!(
            decode_secondary_index_key(model_a.table_prefix, &specs_a[0], &model_a, &key_b)
                .is_none(),
            "key from prefix 1 must not decode under prefix 0"
        );
    }

    #[tokio::test]
    async fn kv_schema_register_all_enables_join() {
        let ctx = SessionContext::new();
        let client = StoreClient::new("http://localhost:10000");

        let result = KvSchema::new(client)
            .table(
                "customers",
                vec![
                    TableColumnConfig::new("customer_id", DataType::Int64, false),
                    TableColumnConfig::new("name", DataType::Utf8, false),
                ],
                vec!["customer_id".to_string()],
                vec![],
            )
            .unwrap()
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("order_id", DataType::Int64, false),
                    TableColumnConfig::new("customer_id", DataType::Int64, false),
                    TableColumnConfig::new("amount", DataType::Int64, false),
                ],
                vec!["order_id".to_string()],
                vec![IndexSpec::new("cust_idx", vec!["customer_id".to_string()]).unwrap()],
            )
            .unwrap()
            .register_all(&ctx);

        assert!(
            result.is_ok(),
            "register_all must succeed: {:?}",
            result.err()
        );

        let plan = ctx
            .sql(
                "SELECT c.name, o.order_id, o.amount \
                 FROM orders o \
                 JOIN customers c ON o.customer_id = c.customer_id",
            )
            .await;
        assert!(
            plan.is_ok(),
            "JOIN query must plan successfully: {:?}",
            plan.err()
        );
    }

    #[tokio::test]
    async fn kv_schema_three_way_join() {
        let ctx = SessionContext::new();
        let client = StoreClient::new("http://localhost:10000");

        KvSchema::new(client)
            .table(
                "products",
                vec![
                    TableColumnConfig::new("product_id", DataType::Int64, false),
                    TableColumnConfig::new("name", DataType::Utf8, false),
                    TableColumnConfig::new("price", DataType::Int64, false),
                ],
                vec!["product_id".to_string()],
                vec![],
            )
            .unwrap()
            .table(
                "line_items",
                vec![
                    TableColumnConfig::new("item_id", DataType::Int64, false),
                    TableColumnConfig::new("order_id", DataType::Int64, false),
                    TableColumnConfig::new("product_id", DataType::Int64, false),
                    TableColumnConfig::new("qty", DataType::Int64, false),
                ],
                vec!["item_id".to_string()],
                vec![
                    IndexSpec::new("prod_idx", vec!["product_id".to_string()]).unwrap(),
                    IndexSpec::new("order_idx", vec!["order_id".to_string()]).unwrap(),
                ],
            )
            .unwrap()
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("order_id", DataType::Int64, false),
                    TableColumnConfig::new("customer", DataType::Utf8, false),
                ],
                vec!["order_id".to_string()],
                vec![],
            )
            .unwrap()
            .register_all(&ctx)
            .unwrap();

        let plan = ctx
            .sql(
                "SELECT o.customer, p.name, li.qty \
                 FROM line_items li \
                 JOIN products p ON li.product_id = p.product_id \
                 JOIN orders o ON li.order_id = o.order_id",
            )
            .await;
        assert!(plan.is_ok(), "three-way JOIN must plan: {:?}", plan.err());
    }

    #[test]
    fn kv_schema_orders_table_convenience() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .orders_table(
                "my_orders",
                vec![IndexSpec::new(
                    "region_customer",
                    vec!["region".to_string(), "customer_id".to_string()],
                )
                .unwrap()],
            )
            .unwrap();
        assert_eq!(schema.table_count(), 1);
    }

    #[test]
    fn nullable_column_accepted_in_config() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("name", DataType::Utf8, true),
            ],
            vec!["id".to_string()],
            vec![],
        );
        assert!(config.is_ok());
    }

    #[test]
    fn nullable_column_rejected_in_index() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("name", DataType::Utf8, true),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("name_idx", vec!["name".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let result = model.resolve_index_specs(&config.index_specs);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("nullable"));
    }

    #[test]
    fn base_row_round_trip_with_null() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("label", DataType::Utf8, true),
                TableColumnConfig::new("score", DataType::Int64, true),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let row = KvRow {
            values: vec![CellValue::Int64(1), CellValue::Null, CellValue::Int64(42)],
        };
        let encoded = encode_base_row_value(&row, &model).unwrap();
        let decoded = decode_base_row(vec![CellValue::Int64(1)], &encoded, &model).unwrap();
        assert!(matches!(&decoded.values[0], CellValue::Int64(1)));
        assert!(matches!(&decoded.values[1], CellValue::Null));
        assert!(matches!(&decoded.values[2], CellValue::Int64(42)));
    }

    #[test]
    fn null_does_not_match_equality_constraint() {
        assert!(!matches_constraint(
            &CellValue::Null,
            &PredicateConstraint::StringEq("x".to_string())
        ));
        assert!(!matches_constraint(
            &CellValue::Null,
            &PredicateConstraint::IntRange {
                min: Some(0),
                max: Some(10)
            }
        ));
    }

    #[test]
    fn is_null_constraint_matches() {
        assert!(matches_constraint(
            &CellValue::Null,
            &PredicateConstraint::IsNull
        ));
        assert!(!matches_constraint(
            &CellValue::Utf8("x".to_string()),
            &PredicateConstraint::IsNull
        ));
        assert!(!matches_constraint(
            &CellValue::Null,
            &PredicateConstraint::IsNotNull
        ));
        assert!(matches_constraint(
            &CellValue::Int64(5),
            &PredicateConstraint::IsNotNull
        ));
    }

    #[test]
    fn string_in_constraint_matches() {
        let constraint =
            PredicateConstraint::StringIn(vec!["us-east".to_string(), "us-west".to_string()]);
        assert!(matches_constraint(
            &CellValue::Utf8("us-east".to_string()),
            &constraint,
        ));
        assert!(matches_constraint(
            &CellValue::Utf8("us-west".to_string()),
            &constraint,
        ));
        assert!(!matches_constraint(
            &CellValue::Utf8("eu-central".to_string()),
            &constraint,
        ));
    }

    #[test]
    fn int_in_constraint_matches() {
        let constraint = PredicateConstraint::IntIn(vec![1, 2, 3]);
        assert!(matches_constraint(&CellValue::Int64(1), &constraint));
        assert!(matches_constraint(&CellValue::Int64(3), &constraint));
        assert!(!matches_constraint(&CellValue::Int64(4), &constraint));
    }

    #[test]
    fn oversized_utf8_primary_key_constraint_is_empty_terminal_range() {
        let too_large = "a".repeat(exoware_sdk::keys::MAX_KEY_LEN + 1);
        match primary_key_range_constraint(
            ColumnKind::Utf8,
            &PredicateConstraint::StringEq(too_large),
        ) {
            PrimaryKeyRangeConstraint::Terminal(spans) => assert!(
                spans.is_empty(),
                "unencodable UTF-8 PK equality should be impossible"
            ),
            other => panic!("unexpected oversized UTF-8 PK constraint: {other:?}"),
        }
    }

    #[test]
    fn in_predicate_generates_multiple_index_ranges() {
        let (model, specs) = test_model();
        let region_idx = *model.columns_by_name.get("region").unwrap();
        let mut pred = QueryPredicate::default();
        pred.constraints.insert(
            region_idx,
            PredicateConstraint::StringIn(vec!["us-east".to_string(), "us-west".to_string()]),
        );
        let plan = pred
            .choose_index_plan(&model, &specs)
            .expect("plan")
            .expect("should find index");
        assert_eq!(plan.ranges.len(), 2);
    }

    #[test]
    fn int_in_generates_multiple_pk_ranges() {
        let (model, _specs) = test_model();
        let mut pred = QueryPredicate::default();
        pred.constraints.insert(
            model.primary_key_indices[0],
            PredicateConstraint::IntIn(vec![200, 100, 300]),
        );
        let ranges = pred.primary_key_ranges(&model).unwrap();
        assert_eq!(ranges.len(), 3);
        let expected_starts = [100, 200, 300]
            .into_iter()
            .map(|id| {
                let value = CellValue::Int64(id);
                encode_primary_key_bound(model.table_prefix, &[&value], &model, false)
                    .expect("primary key lower bound")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            ranges
                .iter()
                .map(|range| range.start.clone())
                .collect::<Vec<_>>(),
            expected_starts,
            "primary_key_ranges should sort terminal IN ranges by encoded start key"
        );
    }

    #[test]
    fn duplicate_int_in_values_deduplicated() {
        let (model, _specs) = test_model();
        // Use the PK column "order_id" for the IN list
        let filter = Expr::InList(datafusion::logical_expr::expr::InList {
            expr: Box::new(Expr::Column(datafusion::common::Column::new_unqualified(
                "order_id",
            ))),
            list: vec![
                Expr::Literal(ScalarValue::Int64(Some(5)), None),
                Expr::Literal(ScalarValue::Int64(Some(5)), None),
                Expr::Literal(ScalarValue::Int64(Some(10)), None),
            ],
            negated: false,
        });
        let pred = QueryPredicate::from_filters(&[filter], &model);
        let ranges = pred.primary_key_ranges(&model).unwrap();
        assert_eq!(
            ranges.len(),
            2,
            "duplicate IN values must be deduped, producing 2 ranges not 3"
        );
    }

    #[test]
    fn duplicate_uint64_in_values_deduplicated() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::UInt64, false),
                TableColumnConfig::new("name", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let filter = Expr::InList(datafusion::logical_expr::expr::InList {
            expr: Box::new(Expr::Column(datafusion::common::Column::new_unqualified(
                "id",
            ))),
            list: vec![
                Expr::Literal(ScalarValue::UInt64(Some(100)), None),
                Expr::Literal(ScalarValue::UInt64(Some(100)), None),
                Expr::Literal(ScalarValue::UInt64(Some(200)), None),
            ],
            negated: false,
        });
        let pred = QueryPredicate::from_filters(&[filter], &model);
        let ranges = pred.primary_key_ranges(&model).unwrap();
        assert_eq!(
            ranges.len(),
            2,
            "duplicate UInt64 IN values must be deduped"
        );
    }

    #[test]
    fn duplicate_fixed_binary_in_values_deduplicated() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("hash", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("val", DataType::Int64, false),
            ],
            vec!["hash".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let dup_val = vec![0xAA; 16];
        let other_val = vec![0xBB; 16];
        let filter = Expr::InList(datafusion::logical_expr::expr::InList {
            expr: Box::new(Expr::Column(datafusion::common::Column::new_unqualified(
                "hash",
            ))),
            list: vec![
                Expr::Literal(
                    ScalarValue::FixedSizeBinary(16, Some(dup_val.clone())),
                    None,
                ),
                Expr::Literal(ScalarValue::FixedSizeBinary(16, Some(dup_val)), None),
                Expr::Literal(ScalarValue::FixedSizeBinary(16, Some(other_val)), None),
            ],
            negated: false,
        });
        let pred = QueryPredicate::from_filters(&[filter], &model);
        let ranges = pred.primary_key_ranges(&model).unwrap();
        assert_eq!(
            ranges.len(),
            2,
            "duplicate FixedBinary IN values must be deduped"
        );
    }

    #[test]
    fn composite_utf8_primary_key_prefix_overflow_produces_no_ranges() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("a", DataType::Utf8, false),
                TableColumnConfig::new("b", DataType::Utf8, false),
            ],
            vec!["a".to_string(), "b".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let capacity = model.primary_key_codec.payload_capacity_bytes();
        let a = "a".repeat(capacity - 10);
        let b = "b".repeat(10);
        let a_width = encode_string_variable(&a).expect("a should encode").len();
        let b_width = encode_string_variable(&b).expect("b should encode").len();
        assert!(a_width <= capacity, "first component should fit alone");
        assert!(
            a_width + b_width > capacity,
            "composite UTF-8 prefix should overflow"
        );

        let mut pred = QueryPredicate::default();
        pred.constraints.insert(0, PredicateConstraint::StringEq(a));
        pred.constraints.insert(1, PredicateConstraint::StringEq(b));

        let ranges = pred.primary_key_ranges(&model).unwrap();
        assert!(
            ranges.is_empty(),
            "overflowing composite UTF-8 PK equality can never match"
        );
    }

    #[test]
    fn or_equalities_extracted_as_in_list() {
        let (model, _) = test_model();
        let expr = Expr::BinaryExpr(datafusion::logical_expr::BinaryExpr {
            left: Box::new(Expr::BinaryExpr(datafusion::logical_expr::BinaryExpr {
                left: Box::new(Expr::Column(datafusion::common::Column::new_unqualified(
                    "region",
                ))),
                op: Operator::Eq,
                right: Box::new(Expr::Literal(
                    ScalarValue::Utf8(Some("us-east".to_string())),
                    None,
                )),
            })),
            op: Operator::Or,
            right: Box::new(Expr::BinaryExpr(datafusion::logical_expr::BinaryExpr {
                left: Box::new(Expr::Column(datafusion::common::Column::new_unqualified(
                    "region",
                ))),
                op: Operator::Eq,
                right: Box::new(Expr::Literal(
                    ScalarValue::Utf8(Some("us-west".to_string())),
                    None,
                )),
            })),
        });
        let result = extract_or_in_column(&expr, &model);
        assert!(result.is_some());
        let (col, vals) = result.unwrap();
        assert_eq!(col, "region");
        assert_eq!(vals.len(), 2);
    }

    #[test]
    fn or_equalities_on_float64_are_not_pushdown_supported() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("score", DataType::Float64, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        use datafusion::logical_expr::col;
        let filter = col("score")
            .eq(Expr::Literal(ScalarValue::Float64(Some(1.0)), None))
            .or(col("score").eq(Expr::Literal(ScalarValue::Float64(Some(2.0)), None)));

        assert!(
            !QueryPredicate::supports_filter(&filter, &model),
            "OR-equality pushdown should be disabled for Float64 because apply_in_list cannot enforce it"
        );

        let pred = QueryPredicate::from_filters(&[filter], &model);
        assert!(!pred.contradiction);
        assert!(
            pred.constraints.is_empty(),
            "unsupported OR predicate must not contribute pushdown constraints"
        );
    }

    #[test]
    fn batch_writer_encodes_rows_across_tables() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .table(
                "customers",
                vec![
                    TableColumnConfig::new("customer_id", DataType::Int64, false),
                    TableColumnConfig::new("name", DataType::Utf8, false),
                ],
                vec!["customer_id".to_string()],
                vec![],
            )
            .unwrap()
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("order_id", DataType::Int64, false),
                    TableColumnConfig::new("customer_id", DataType::Int64, false),
                    TableColumnConfig::new("amount", DataType::Int64, false),
                ],
                vec!["order_id".to_string()],
                vec![IndexSpec::new("cust_idx", vec!["customer_id".to_string()]).unwrap()],
            )
            .unwrap();

        let mut batch = schema.batch_writer();
        batch
            .insert(
                "customers",
                vec![CellValue::Int64(1), CellValue::Utf8("Alice".to_string())],
            )
            .unwrap();
        batch
            .insert(
                "orders",
                vec![
                    CellValue::Int64(100),
                    CellValue::Int64(1),
                    CellValue::Int64(4999),
                ],
            )
            .unwrap();
        batch
            .insert(
                "orders",
                vec![
                    CellValue::Int64(101),
                    CellValue::Int64(1),
                    CellValue::Int64(2999),
                ],
            )
            .unwrap();

        // 1 customer base row + 2 order base rows + 2 order index rows = 5
        assert_eq!(batch.pending_count(), 5);
    }

    #[test]
    fn batch_writer_rejects_unknown_table() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .table(
                "t1",
                vec![TableColumnConfig::new("id", DataType::Int64, false)],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap();

        let mut batch = schema.batch_writer();
        let result = batch.insert("nonexistent", vec![CellValue::Int64(1)]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown table"));
    }

    #[test]
    fn batch_writer_rejects_wrong_column_count() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .table(
                "t1",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("name", DataType::Utf8, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap();

        let mut batch = schema.batch_writer();
        let result = batch.insert("t1", vec![CellValue::Int64(1)]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected 2"));
    }

    #[test]
    fn batch_writer_rejects_non_pk_type_mismatch() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .table(
                "t1",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("amount", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap();

        let mut batch = schema.batch_writer();
        let result = batch.insert(
            "t1",
            vec![CellValue::Int64(1), CellValue::Utf8("bad".to_string())],
        );
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("type mismatch"),
            "non-PK schema-invalid values must be rejected at insert-time"
        );
    }

    #[test]
    fn batch_writer_entries_use_distinct_table_prefixes() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .table(
                "a",
                vec![TableColumnConfig::new("id", DataType::Int64, false)],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap()
            .table(
                "b",
                vec![TableColumnConfig::new("id", DataType::Int64, false)],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap();

        let mut batch = schema.batch_writer();
        batch.insert("a", vec![CellValue::Int64(42)]).unwrap();
        batch.insert("b", vec![CellValue::Int64(42)]).unwrap();

        assert_eq!(batch.pending_count(), 2);
        assert_ne!(
            batch.pending_keys[0], batch.pending_keys[1],
            "same PK in different tables must produce different keys"
        );
        assert_ne!(
            batch.pending_keys[0][0], batch.pending_keys[1][0],
            "table prefix byte must differ"
        );
    }

    #[tokio::test]
    async fn batch_writer_trait_failure_requeues_prepared_before_new_pending() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .table(
                "t",
                vec![TableColumnConfig::new("id", DataType::Int64, false)],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap();

        let mut batch = schema.batch_writer();
        batch.insert("t", vec![CellValue::Int64(1)]).unwrap();
        let prepared = batch.prepare_flush().unwrap().expect("prepared row");
        assert_eq!(prepared.request_id(), 0);
        assert_eq!(prepared.entry_count(), 1);

        batch.insert("t", vec![CellValue::Int64(2)]).unwrap();
        StoreBatchUpload::mark_upload_failed(&batch, prepared, "commit failed".to_string()).await;
        assert_eq!(batch.pending_count(), 2);

        let retry = batch.prepare_flush().unwrap().expect("retry row");
        assert_eq!(retry.request_id(), 0);
        assert_eq!(retry.entry_count(), 1);
        let next = batch.prepare_flush().unwrap().expect("new pending row");
        assert_eq!(next.request_id(), 1);
        assert_eq!(next.entry_count(), 1);
    }

    #[test]
    fn batch_writer_supports_nullable_columns() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .table(
                "t",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("note", DataType::Utf8, true),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap();

        let mut batch = schema.batch_writer();
        batch
            .insert("t", vec![CellValue::Int64(1), CellValue::Null])
            .unwrap();
        assert_eq!(batch.pending_count(), 1);
    }

    #[test]
    fn non_nullable_column_rejects_null_in_batch_writer() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .table(
                "t",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("name", DataType::Utf8, false),
                    TableColumnConfig::new("note", DataType::Utf8, true),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap();

        // NULL in non-nullable column "name" must fail
        let mut batch = schema.batch_writer();
        let result = batch.insert(
            "t",
            vec![
                CellValue::Int64(1),
                CellValue::Null,
                CellValue::Utf8("ok".to_string()),
            ],
        );
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("not nullable"),
            "error should mention non-nullable constraint"
        );

        // NULL in nullable column "note" must succeed
        let mut batch = schema.batch_writer();
        batch
            .insert(
                "t",
                vec![
                    CellValue::Int64(1),
                    CellValue::Utf8("Alice".to_string()),
                    CellValue::Null,
                ],
            )
            .unwrap();
        assert_eq!(batch.pending_count(), 1);

        // All non-null values must succeed
        let mut batch = schema.batch_writer();
        batch
            .insert(
                "t",
                vec![
                    CellValue::Int64(1),
                    CellValue::Utf8("Alice".to_string()),
                    CellValue::Utf8("hello".to_string()),
                ],
            )
            .unwrap();
        assert_eq!(batch.pending_count(), 1);
    }

    #[test]
    fn uint64_column_accepted() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::UInt64, false),
                TableColumnConfig::new("name", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![],
        );
        assert!(config.is_ok());
    }

    #[test]
    fn uint64_primary_key_round_trip() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::UInt64, false),
                TableColumnConfig::new("label", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let row = KvRow {
            values: vec![
                CellValue::UInt64(u64::MAX),
                CellValue::Utf8("max".to_string()),
            ],
        };
        let encoded = encode_base_row_value(&row, &model).unwrap();
        let pk = row
            .primary_key_values(&model)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let decoded = decode_base_row(pk, &encoded, &model).unwrap();
        assert!(matches!(&decoded.values[0], CellValue::UInt64(v) if *v == u64::MAX));
        assert!(matches!(&decoded.values[1], CellValue::Utf8(v) if v == "max"));
    }

    #[test]
    fn string_primary_key_accepted() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("code", DataType::Utf8, false),
                TableColumnConfig::new("value", DataType::Int64, false),
            ],
            vec!["code".to_string()],
            vec![],
        );
        assert!(config.is_ok());
    }

    #[test]
    fn fixed_binary_primary_key_round_trip() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("hash", DataType::FixedSizeBinary(32), false),
                TableColumnConfig::new("amount", DataType::Int64, false),
            ],
            vec!["hash".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let hash_val = vec![0xABu8; 32];
        let row = KvRow {
            values: vec![
                CellValue::FixedBinary(hash_val.clone()),
                CellValue::Int64(100),
            ],
        };
        let encoded = encode_base_row_value(&row, &model).unwrap();
        let pk = row
            .primary_key_values(&model)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let decoded = decode_base_row(pk, &encoded, &model).unwrap();
        assert!(matches!(&decoded.values[0], CellValue::FixedBinary(v) if *v == hash_val));
    }

    #[test]
    fn fixed_binary_key_rejects_wrong_length() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("hash", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("amount", DataType::Int64, false),
            ],
            vec!["hash".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        // Too short (10 bytes for a 16-byte column)
        let short_row = KvRow {
            values: vec![CellValue::FixedBinary(vec![0xAB; 10]), CellValue::Int64(1)],
        };
        let result = encode_primary_key_from_row(model.table_prefix, &short_row, &model);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("requires exactly 16 bytes"),
            "should mention exact width requirement"
        );

        // Too long (20 bytes for a 16-byte column)
        let long_row = KvRow {
            values: vec![CellValue::FixedBinary(vec![0xCD; 20]), CellValue::Int64(2)],
        };
        let result = encode_primary_key_from_row(model.table_prefix, &long_row, &model);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("requires exactly 16 bytes"));

        // Exact length (16 bytes) — must succeed
        let ok_row = KvRow {
            values: vec![CellValue::FixedBinary(vec![0xEF; 16]), CellValue::Int64(3)],
        };
        assert!(encode_primary_key_from_row(model.table_prefix, &ok_row, &model).is_ok());
    }

    #[test]
    fn fixed_binary_index_key_rejects_wrong_length() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("tag", DataType::FixedSizeBinary(8), false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("tag_idx", vec!["tag".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();

        // Wrong length (4 bytes for an 8-byte column)
        let bad_row = KvRow {
            values: vec![CellValue::Int64(1), CellValue::FixedBinary(vec![0x01; 4])],
        };
        let result = encode_secondary_index_key(model.table_prefix, &specs[0], &model, &bad_row);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("requires exactly 8 bytes"));

        // Correct length (8 bytes)
        let ok_row = KvRow {
            values: vec![CellValue::Int64(1), CellValue::FixedBinary(vec![0x02; 8])],
        };
        assert!(encode_secondary_index_key(model.table_prefix, &specs[0], &model, &ok_row).is_ok());
    }

    #[test]
    fn decimal256_column_round_trip() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("balance", DataType::Decimal256(76, 0), false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let big_val = i256::from(123456789012345i64);
        let row = KvRow {
            values: vec![CellValue::Int64(1), CellValue::Decimal256(big_val)],
        };
        let encoded = encode_base_row_value(&row, &model).unwrap();
        let pk = row
            .primary_key_values(&model)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let decoded = decode_base_row(pk, &encoded, &model).unwrap();
        assert!(matches!(&decoded.values[1], CellValue::Decimal256(v) if *v == big_val));
    }

    #[test]
    fn float64_primary_key_rejected() {
        let config = KvTableConfig::new(
            0,
            vec![TableColumnConfig::new("id", DataType::Float64, false)],
            vec!["id".to_string()],
            vec![],
        );
        assert!(config.is_err());
    }

    #[test]
    fn i256_ordered_encoding_round_trip() {
        let values = [
            i256::from_i128(i128::MIN),
            i256::from(-1i64),
            i256::from(0i64),
            i256::from(1i64),
            i256::from_i128(i128::MAX),
        ];
        for v in values {
            assert_eq!(decode_i256_ordered(encode_i256_ordered(v)), v);
        }
        let encoded: Vec<[u8; 32]> = values.iter().map(|v| encode_i256_ordered(*v)).collect();
        for i in 0..encoded.len() - 1 {
            assert!(encoded[i] < encoded[i + 1]);
        }
    }

    #[test]
    fn uint64_primary_key_encode_decode() {
        let config = KvTableConfig::new(
            5,
            vec![
                TableColumnConfig::new("id", DataType::UInt64, false),
                TableColumnConfig::new("name", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let pk = CellValue::UInt64(12345);
        let key = encode_primary_key(5, &[&pk], &model).expect("pk key encodes");
        let decoded = decode_primary_key(5, &key, &model).unwrap();
        assert!(matches!(&decoded[0], CellValue::UInt64(12345)));
    }

    #[test]
    fn utf8_primary_key_encode_decode() {
        let config = KvTableConfig::new(
            3,
            vec![
                TableColumnConfig::new("code", DataType::Utf8, false),
                TableColumnConfig::new("val", DataType::Int64, false),
            ],
            vec!["code".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let pk = CellValue::Utf8("HELLO".to_string());
        let key = encode_primary_key(3, &[&pk], &model).expect("pk key encodes");
        let decoded = decode_primary_key(3, &key, &model).unwrap();
        assert!(matches!(&decoded[0], CellValue::Utf8(v) if v == "HELLO"));
    }

    #[test]
    fn fixed_binary_primary_key_encode_decode() {
        let config = KvTableConfig::new(
            7,
            vec![
                TableColumnConfig::new("hash", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("val", DataType::Int64, false),
            ],
            vec!["hash".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let pk = CellValue::FixedBinary(data.clone());
        let key = encode_primary_key(7, &[&pk], &model).expect("pk key encodes");
        let decoded = decode_primary_key(7, &key, &model).unwrap();
        assert!(matches!(&decoded[0], CellValue::FixedBinary(v) if *v == data));
    }

    #[test]
    fn secondary_index_with_uint64_column() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("counter", DataType::UInt64, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("counter_idx", vec!["counter".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();
        let row = KvRow {
            values: vec![CellValue::Int64(1), CellValue::UInt64(999)],
        };
        let key = encode_secondary_index_key(model.table_prefix, &specs[0], &model, &row).unwrap();
        let decoded =
            decode_secondary_index_key(model.table_prefix, &specs[0], &model, &key).unwrap();
        let counter_idx = *model.columns_by_name.get("counter").unwrap();
        assert!(matches!(
            decoded.values.get(&counter_idx),
            Some(CellValue::UInt64(999))
        ));
        assert!(matches!(
            &decoded.primary_key_values[0],
            CellValue::Int64(1)
        ));
    }

    #[test]
    fn secondary_index_with_decimal256_column() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("big_val", DataType::Decimal256(76, 0), false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("big_idx", vec!["big_val".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();
        let val = i256::from(42i64);
        let row = KvRow {
            values: vec![CellValue::Int64(1), CellValue::Decimal256(val)],
        };
        let key = encode_secondary_index_key(model.table_prefix, &specs[0], &model, &row).unwrap();
        let decoded =
            decode_secondary_index_key(model.table_prefix, &specs[0], &model, &key).unwrap();
        let big_idx = *model.columns_by_name.get("big_val").unwrap();
        assert!(matches!(
            decoded.values.get(&big_idx),
            Some(CellValue::Decimal256(v)) if *v == val
        ));
    }

    // -----------------------------------------------------------------------
    // Composite primary key tests
    // -----------------------------------------------------------------------

    #[test]
    fn composite_pk_config_accepted() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(32), false),
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("data", DataType::Utf8, true),
            ],
            vec!["entity".to_string(), "version".to_string()],
            vec![],
        );
        assert!(config.is_ok());
        let c = config.unwrap();
        assert_eq!(c.primary_key_columns, vec!["entity", "version"]);
    }

    #[test]
    fn composite_pk_rejects_unsupported_type() {
        let result = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(32), false),
                TableColumnConfig::new("score", DataType::Float64, false),
            ],
            vec!["entity".to_string(), "score".to_string()],
            vec![],
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("must be Int64") || err.contains("must be"),
            "expected PK type error, got: {err}"
        );
    }

    #[test]
    fn composite_pk_rejects_too_wide() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("big", DataType::FixedSizeBinary(60), false),
                TableColumnConfig::new("ver", DataType::UInt64, false),
            ],
            vec!["big".to_string(), "ver".to_string()],
            vec![],
        )
        .expect("variable-length keys should allow wider composite PKs");
        let model = TableModel::from_config(&config).expect("model");
        assert_eq!(model.primary_key_width, 68);
    }

    #[test]
    fn composite_pk_encode_decode_round_trip() {
        let config = KvTableConfig::new(
            1,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(32), false),
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("title", DataType::Utf8, true),
            ],
            vec!["entity".to_string(), "version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        let entity = vec![0xAA; 32];
        let pk_entity = CellValue::FixedBinary(entity.clone());
        let pk_version = CellValue::UInt64(42);
        let key =
            encode_primary_key(1, &[&pk_entity, &pk_version], &model).expect("pk key encodes");

        let decoded = decode_primary_key(1, &key, &model).unwrap();
        assert_eq!(decoded.len(), 2);
        assert!(matches!(&decoded[0], CellValue::FixedBinary(v) if *v == entity));
        assert!(matches!(&decoded[1], CellValue::UInt64(42)));
    }

    #[test]
    fn composite_pk_version_sort_order() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(32), false),
                TableColumnConfig::new("version", DataType::UInt64, false),
            ],
            vec!["entity".to_string(), "version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        let entity = vec![0xBB; 32];
        let pk_entity = CellValue::FixedBinary(entity.clone());

        let key_v1 = encode_primary_key(0, &[&pk_entity, &CellValue::UInt64(1)], &model)
            .expect("pk key encodes");
        let key_v10 = encode_primary_key(0, &[&pk_entity, &CellValue::UInt64(10)], &model)
            .expect("pk key encodes");
        let key_v100 = encode_primary_key(0, &[&pk_entity, &CellValue::UInt64(100)], &model)
            .expect("pk key encodes");

        // Versions must sort numerically (big-endian U64)
        assert!(key_v1 < key_v10);
        assert!(key_v10 < key_v100);
    }

    #[test]
    fn composite_pk_value_excludes_all_pk_columns() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("data", DataType::Utf8, true),
            ],
            vec!["entity".to_string(), "version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        let row = KvRow {
            values: vec![
                CellValue::FixedBinary(vec![0xCC; 16]),
                CellValue::UInt64(7),
                CellValue::Utf8("hello".to_string()),
            ],
        };
        let encoded = encode_base_row_value(&row, &model).unwrap();
        // Both PK columns should be None in stored value
        let decoded = decode_base_row(
            vec![CellValue::FixedBinary(vec![0xCC; 16]), CellValue::UInt64(7)],
            &encoded,
            &model,
        )
        .unwrap();
        assert!(matches!(&decoded.values[0], CellValue::FixedBinary(v) if v.len() == 16));
        assert!(matches!(&decoded.values[1], CellValue::UInt64(7)));
        assert!(matches!(&decoded.values[2], CellValue::Utf8(v) if v == "hello"));
    }

    #[test]
    fn composite_pk_secondary_index_appends_all_pk_columns() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("tag", DataType::Int64, false),
            ],
            vec!["entity".to_string(), "version".to_string()],
            vec![IndexSpec::new("tag_idx", vec!["tag".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();

        let entity_data = vec![0xDD; 16];
        let row = KvRow {
            values: vec![
                CellValue::FixedBinary(entity_data.clone()),
                CellValue::UInt64(99),
                CellValue::Int64(42),
            ],
        };
        let key = encode_secondary_index_key(model.table_prefix, &specs[0], &model, &row).unwrap();
        let decoded =
            decode_secondary_index_key(model.table_prefix, &specs[0], &model, &key).unwrap();

        assert_eq!(decoded.primary_key_values.len(), 2);
        assert!(matches!(
            &decoded.primary_key_values[0],
            CellValue::FixedBinary(v) if *v == entity_data
        ));
        assert!(matches!(
            &decoded.primary_key_values[1],
            CellValue::UInt64(99)
        ));
        let tag_idx = *model.columns_by_name.get("tag").unwrap();
        assert!(matches!(
            decoded.values.get(&tag_idx),
            Some(CellValue::Int64(42))
        ));
    }

    #[test]
    fn table_versioned_convenience() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .table_versioned(
                "documents",
                vec![
                    TableColumnConfig::new("doc_id", DataType::FixedSizeBinary(32), false),
                    TableColumnConfig::new("version", DataType::UInt64, false),
                    TableColumnConfig::new("title", DataType::Utf8, false),
                ],
                "doc_id",
                "version",
                vec![],
            )
            .unwrap();
        assert_eq!(schema.table_count(), 1);
    }

    #[test]
    fn single_column_pk_backward_compat() {
        // Ensure single-column PK still works identically
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("name", DataType::Utf8, true),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        assert_eq!(model.primary_key_indices.len(), 1);
        assert_eq!(model.primary_key_indices[0], 0);
        assert_eq!(model.primary_key_width, 8);

        let pk = CellValue::Int64(42);
        let key = encode_primary_key(0, &[&pk], &model).expect("pk key encodes");
        let decoded = decode_primary_key(0, &key, &model).unwrap();
        assert_eq!(decoded.len(), 1);
        assert!(matches!(&decoded[0], CellValue::Int64(42)));
    }

    #[test]
    fn partial_prefix_upper_bound_fills_trailing_pk_bytes() {
        // Regression: encode_primary_key_bound with partial prefix must
        // fill 0xFF from the end of the encoded prefix, not from the
        // end of the full PK width. Otherwise trailing PK column bytes
        // stay 0x00, producing an end key that's too low.
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("version", DataType::UInt64, false),
            ],
            vec!["entity".to_string(), "version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        assert_eq!(model.primary_key_width, 24); // 16 + 8

        let entity = CellValue::FixedBinary(vec![0xAA; 16]);
        // Partial prefix: only entity, no version
        let upper =
            encode_primary_key_bound(0, &[&entity], &model, true).expect("pk bound encodes");

        // Entity bytes must be encoded
        assert_eq!(primary_payload(&model, &upper, 0, 16), vec![0xAA; 16]);
        // Version bytes (8 bytes after entity) MUST be 0xFF, not 0x00
        assert_eq!(
            primary_payload(&model, &upper, 16, 8),
            vec![0xFF; 8],
            "trailing PK column (version) must be 0xFF for upper bound"
        );
        // Everything after PK region also 0xFF
        assert!(primary_payload(
            &model,
            &upper,
            24,
            model.primary_key_codec.payload_capacity_bytes() - 24
        )
        .iter()
        .all(|&b| b == 0xFF));

        // Lower bound: trailing bytes should be 0x00
        let lower =
            encode_primary_key_bound(0, &[&entity], &model, false).expect("pk bound encodes");
        assert_eq!(primary_payload(&model, &lower, 0, 16), vec![0xAA; 16]);
        assert_eq!(
            primary_payload(&model, &lower, 16, 8),
            vec![0x00; 8],
            "trailing PK column (version) must be 0x00 for lower bound"
        );
    }

    // -----------------------------------------------------------------------
    // Composite PK filter pushdown tests
    // -----------------------------------------------------------------------

    #[test]
    fn composite_pk_range_pushdown_entity_eq_version_lte() {
        // PK = (entity: FixedSizeBinary(16), version: UInt64)
        // Query: entity = X'CC..CC' AND version <= 42
        // Should produce a TIGHT range, not a full table scan.
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("data", DataType::Utf8, true),
            ],
            vec!["entity".to_string(), "version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        // Simulate predicate: entity = X'CC..CC' AND version <= 42
        let mut pred = QueryPredicate::default();
        pred.constraints
            .insert(0, PredicateConstraint::FixedBinaryEq(vec![0xCC; 16]));
        pred.constraints.insert(
            1,
            PredicateConstraint::UInt64Range {
                min: None,
                max: Some(42),
            },
        );

        let ranges = pred.primary_key_ranges(&model).unwrap();
        assert_eq!(ranges.len(), 1, "should produce exactly one range");

        let range = &ranges[0];

        // The start key should encode entity=CC..CC, version=0
        let expected_start = encode_primary_key(
            0,
            &[
                &CellValue::FixedBinary(vec![0xCC; 16]),
                &CellValue::UInt64(0),
            ],
            &model,
        )
        .expect("pk key encodes");
        assert_eq!(
            range.start, expected_start,
            "start should be entity=CC..CC, version=0"
        );

        // The end key should encode entity=CC..CC, version=42, then 0xFF tail
        let expected_end_prefix = encode_primary_key(
            0,
            &[
                &CellValue::FixedBinary(vec![0xCC; 16]),
                &CellValue::UInt64(42),
            ],
            &model,
        )
        .expect("pk key encodes");
        // The end key has 0xFF-filled tail after the PK portion
        assert_eq!(
            primary_payload(&model, &range.end, 0, model.primary_key_width),
            primary_payload(&model, &expected_end_prefix, 0, model.primary_key_width),
            "end prefix should be entity=CC..CC, version=42"
        );
        // Trailing bytes after PK should be 0xFF
        assert!(
            primary_payload(
                &model,
                &range.end,
                model.primary_key_width,
                model.primary_key_codec.payload_capacity_bytes() - model.primary_key_width
            )
            .iter()
            .all(|&b| b == 0xFF),
            "end trailing bytes should be 0xFF"
        );

        // Crucially, the range must NOT be a full table scan
        let full_range = primary_key_prefix_range(0);
        assert_ne!(
            range.start, full_range.start,
            "range must not be a full table scan"
        );
    }

    #[test]
    fn composite_pk_range_pushdown_entity_eq_only() {
        // PK = (entity: FixedSizeBinary(16), version: UInt64)
        // Query: entity = X'DD..DD' (no version constraint)
        // Should still produce a tight entity-prefix range.
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("version", DataType::UInt64, false),
            ],
            vec!["entity".to_string(), "version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        let mut pred = QueryPredicate::default();
        pred.constraints
            .insert(0, PredicateConstraint::FixedBinaryEq(vec![0xDD; 16]));

        let ranges = pred.primary_key_ranges(&model).unwrap();
        assert_eq!(ranges.len(), 1);

        let range = &ranges[0];
        // Start should have entity=DD..DD, version=0x00..00
        assert_eq!(primary_payload(&model, &range.start, 0, 16), vec![0xDD; 16]);
        // End should have entity=DD..DD, then 0xFF for version + tail
        assert_eq!(primary_payload(&model, &range.end, 0, 16), vec![0xDD; 16]);
        assert!(
            primary_payload(
                &model,
                &range.end,
                16,
                model.primary_key_codec.payload_capacity_bytes() - 16
            )
            .iter()
            .all(|&b| b == 0xFF),
            "after entity bytes, everything should be 0xFF"
        );
    }

    #[test]
    fn fixed_binary_eq_constraint_extracted() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("version", DataType::UInt64, false),
            ],
            vec!["entity".to_string(), "version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        // Build an equality expression: entity = X'AA..AA'
        use datafusion::logical_expr::col;
        let entity_literal =
            Expr::Literal(ScalarValue::FixedSizeBinary(16, Some(vec![0xAA; 16])), None);
        let filter = col("entity").eq(entity_literal);

        assert!(
            QueryPredicate::supports_filter(&filter, &model),
            "FixedSizeBinary equality should be supported"
        );

        let pred = QueryPredicate::from_filters(&[filter], &model);
        assert!(
            matches!(
                pred.constraints.get(&0),
                Some(PredicateConstraint::FixedBinaryEq(v)) if *v == vec![0xAA; 16]
            ),
            "should extract FixedBinaryEq constraint"
        );
    }

    #[test]
    fn uint64_range_constraint_extracted() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("data", DataType::Utf8, true),
            ],
            vec!["version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        use datafusion::logical_expr::col;
        let filter = col("version").lt_eq(Expr::Literal(ScalarValue::UInt64(Some(42)), None));

        assert!(
            QueryPredicate::supports_filter(&filter, &model),
            "UInt64 range should be supported"
        );

        let pred = QueryPredicate::from_filters(&[filter], &model);
        assert!(
            matches!(
                pred.constraints.get(&0),
                Some(PredicateConstraint::UInt64Range {
                    min: None,
                    max: Some(42)
                })
            ),
            "should extract UInt64Range with max=42"
        );
    }

    #[test]
    fn uint64_range_constraint_supports_values_above_i64_max() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("data", DataType::Utf8, true),
            ],
            vec!["version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        let threshold = (1u64 << 63) + 5;
        use datafusion::logical_expr::col;
        let filter =
            col("version").gt_eq(Expr::Literal(ScalarValue::UInt64(Some(threshold)), None));

        assert!(QueryPredicate::supports_filter(&filter, &model));

        let pred = QueryPredicate::from_filters(&[filter], &model);
        assert!(matches!(
            pred.constraints.get(&0),
            Some(PredicateConstraint::UInt64Range {
                min: Some(v),
                max: None
            }) if *v == threshold
        ));
    }

    #[test]
    fn unsupported_uint64_comparison_does_not_force_contradiction() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("data", DataType::Utf8, true),
            ],
            vec!["version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        use datafusion::logical_expr::col;
        let unsupported = col("version").gt(Expr::Literal(ScalarValue::Int64(Some(-1)), None));

        assert!(
            !QueryPredicate::supports_filter(&unsupported, &model),
            "negative Int64 literal on UInt64 column should not be pushdown-supported"
        );

        let pred = QueryPredicate::from_filters(&[unsupported], &model);
        assert!(
            !pred.contradiction,
            "unsupported filter must not collapse scan to empty result"
        );
        assert!(
            pred.constraints.is_empty(),
            "unsupported filter must not contribute pushed constraints"
        );
    }

    #[test]
    fn unsupported_uint64_comparison_in_and_keeps_supported_sibling() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("data", DataType::Utf8, true),
            ],
            vec!["version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        use datafusion::logical_expr::col;
        let supported = col("version").gt_eq(Expr::Literal(ScalarValue::UInt64(Some(10)), None));
        let unsupported = col("version").gt(Expr::Literal(ScalarValue::Int64(Some(-1)), None));
        let filter = supported.and(unsupported);

        assert!(
            !QueryPredicate::supports_filter(&filter, &model),
            "mixed AND should not be marked fully pushdown-supported"
        );

        let pred = QueryPredicate::from_filters(&[filter], &model);
        assert!(!pred.contradiction);
        assert!(matches!(
            pred.constraints.get(&0),
            Some(PredicateConstraint::UInt64Range {
                min: Some(10),
                max: None
            })
        ));
    }

    #[test]
    fn uint64_in_list_pushdown() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("data", DataType::Utf8, true),
            ],
            vec!["version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        use datafusion::logical_expr::{col, in_list};
        let filter = in_list(
            col("version"),
            vec![
                Expr::Literal(ScalarValue::UInt64(Some(1)), None),
                Expr::Literal(ScalarValue::UInt64(Some(5)), None),
                Expr::Literal(ScalarValue::UInt64(Some(10)), None),
            ],
            false,
        );

        assert!(QueryPredicate::supports_filter(&filter, &model));
        let pred = QueryPredicate::from_filters(&[filter], &model);
        assert!(
            matches!(pred.constraints.get(&0), Some(PredicateConstraint::UInt64In(v)) if v.len() == 3),
            "should extract UInt64In with 3 values"
        );
    }

    #[test]
    fn uint64_in_list_pushdown_supports_values_above_i64_max() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("data", DataType::Utf8, true),
            ],
            vec!["version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        let huge = 1u64 << 63;
        use datafusion::logical_expr::{col, in_list};
        let filter = in_list(
            col("version"),
            vec![
                Expr::Literal(ScalarValue::UInt64(Some(1)), None),
                Expr::Literal(ScalarValue::UInt64(Some(huge)), None),
            ],
            false,
        );

        assert!(QueryPredicate::supports_filter(&filter, &model));
        let pred = QueryPredicate::from_filters(&[filter], &model);
        assert!(matches!(
            pred.constraints.get(&0),
            Some(PredicateConstraint::UInt64In(v)) if v.contains(&huge) && v.len() == 2
        ));
    }

    #[test]
    fn fixed_binary_in_list_pushdown() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("data", DataType::Utf8, true),
            ],
            vec!["entity".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        use datafusion::logical_expr::{col, in_list};
        let filter = in_list(
            col("entity"),
            vec![
                Expr::Literal(ScalarValue::FixedSizeBinary(16, Some(vec![0xAA; 16])), None),
                Expr::Literal(ScalarValue::FixedSizeBinary(16, Some(vec![0xBB; 16])), None),
            ],
            false,
        );

        assert!(QueryPredicate::supports_filter(&filter, &model));
        let pred = QueryPredicate::from_filters(&[filter], &model);
        assert!(
            matches!(
                pred.constraints.get(&0),
                Some(PredicateConstraint::FixedBinaryIn(v)) if v.len() == 2
            ),
            "should extract FixedBinaryIn with 2 values"
        );

        // Verify range generation produces 2 ranges (one per entity)
        let ranges = pred.primary_key_ranges(&model).unwrap();
        assert_eq!(ranges.len(), 2, "should produce one range per entity");
    }

    #[test]
    fn decimal256_range_pushdown() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("big_val", DataType::Decimal256(76, 0), false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("big_idx", vec!["big_val".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        use datafusion::logical_expr::col;
        let filter = col("big_val").gt_eq(Expr::Literal(
            ScalarValue::Decimal256(Some(i256::from(100i64)), 76, 0),
            None,
        ));

        assert!(
            QueryPredicate::supports_filter(&filter, &model),
            "Decimal256 range should be supported"
        );

        let pred = QueryPredicate::from_filters(&[filter], &model);
        let big_idx = *model.columns_by_name.get("big_val").unwrap();
        assert!(
            matches!(
                pred.constraints.get(&big_idx),
                Some(PredicateConstraint::Decimal256Range {
                    min: Some(_),
                    max: None
                })
            ),
            "should extract Decimal256Range with min=100, no max"
        );

        // Verify constraint matching
        let val_in = CellValue::Decimal256(i256::from(200i64));
        let val_out = CellValue::Decimal256(i256::from(50i64));
        let constraint = pred.constraints.get(&big_idx).unwrap();
        assert!(matches_constraint(&val_in, constraint));
        assert!(!matches_constraint(&val_out, constraint));
    }

    #[test]
    fn uint64_constraint_matching_does_not_wrap_large_values() {
        let gt_zero = PredicateConstraint::UInt64Range {
            min: Some(1),
            max: None,
        };
        assert!(matches_constraint(&CellValue::UInt64(1u64 << 63), &gt_zero));
        assert!(!matches_constraint(&CellValue::UInt64(0), &gt_zero));

        let in_list = PredicateConstraint::UInt64In(vec![1, 2, 3]);
        assert!(matches_constraint(&CellValue::UInt64(2), &in_list));
        assert!(!matches_constraint(
            &CellValue::UInt64(1u64 << 63),
            &in_list
        ));
    }

    #[test]
    fn uint64_empty_range_produces_no_pk_ranges() {
        let config = KvTableConfig::new(
            0,
            vec![TableColumnConfig::new("version", DataType::UInt64, false)],
            vec!["version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let mut pred = QueryPredicate::default();
        pred.constraints.insert(
            0,
            PredicateConstraint::UInt64Range {
                min: Some(10),
                max: Some(9),
            },
        );

        let ranges = pred.primary_key_ranges(&model).unwrap();
        assert!(ranges.is_empty());
    }

    #[test]
    fn utf8_primary_key_encoding_supports_unicode_and_long_values() {
        let config = KvTableConfig::new(
            0,
            vec![TableColumnConfig::new("id", DataType::Utf8, false)],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        let row_non_ascii = KvRow {
            values: vec![CellValue::Utf8("naive-cafe-e9".replace("e9", "\u{00E9}"))],
        };
        let key_non_ascii = encode_primary_key_from_row(model.table_prefix, &row_non_ascii, &model)
            .expect("non-ascii PK should encode");
        let decoded_non_ascii = decode_primary_key(model.table_prefix, &key_non_ascii, &model)
            .expect("non-ascii PK should decode");
        assert!(matches!(
            decoded_non_ascii.as_slice(),
            [CellValue::Utf8(value)] if value == "naive-cafe-\u{00E9}"
        ));

        let row_too_long = KvRow {
            values: vec![CellValue::Utf8("abcdefghijklmnopq".to_string())],
        };
        let key_too_long = encode_primary_key_from_row(model.table_prefix, &row_too_long, &model)
            .expect("long UTF-8 PK should encode");
        let decoded_too_long = decode_primary_key(model.table_prefix, &key_too_long, &model)
            .expect("long UTF-8 PK should decode");
        assert!(matches!(
            decoded_too_long.as_slice(),
            [CellValue::Utf8(value)] if value == "abcdefghijklmnopq"
        ));
    }

    #[test]
    fn utf8_primary_key_encodes_at_max_codec_payload_and_rejects_overflow() {
        let config = KvTableConfig::new(
            0,
            vec![TableColumnConfig::new("id", DataType::Utf8, false)],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let max_payload = model.primary_key_codec.payload_capacity_bytes();
        let max_value = "a".repeat(max_payload - 1);
        let overflow_value = "a".repeat(max_payload);

        let key = encode_primary_key_from_row(
            model.table_prefix,
            &KvRow {
                values: vec![CellValue::Utf8(max_value.clone())],
            },
            &model,
        )
        .expect("max-length UTF-8 PK should encode");
        assert_eq!(key.len(), exoware_sdk::keys::MAX_KEY_LEN);
        let decoded = decode_primary_key(model.table_prefix, &key, &model)
            .expect("max-length PK should decode");
        assert!(matches!(
            decoded.as_slice(),
            [CellValue::Utf8(value)] if value == &max_value
        ));

        let err = encode_primary_key_from_row(
            model.table_prefix,
            &KvRow {
                values: vec![CellValue::Utf8(overflow_value)],
            },
            &model,
        )
        .expect_err("UTF-8 PK exceeding codec payload should be rejected");
        assert!(err.contains("primary key payload exceeds codec payload capacity 253 bytes"));
    }

    #[test]
    fn utf8_primary_key_round_trips_embedded_nul() {
        let config = KvTableConfig::new(
            0,
            vec![TableColumnConfig::new("id", DataType::Utf8, false)],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let row = KvRow {
            values: vec![CellValue::Utf8("AB\0CD".to_string())],
        };

        let key = encode_primary_key_from_row(model.table_prefix, &row, &model)
            .expect("embedded NUL in key text must encode");
        let decoded =
            decode_primary_key(model.table_prefix, &key, &model).expect("embedded NUL must decode");
        assert!(matches!(
            decoded.as_slice(),
            [CellValue::Utf8(value)] if value == "AB\0CD"
        ));
    }

    #[test]
    fn utf8_index_key_round_trips_embedded_nul() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("tag", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("tag_idx", vec!["tag".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();
        let row = KvRow {
            values: vec![CellValue::Int64(1), CellValue::Utf8("AB\0CD".to_string())],
        };

        let key = encode_secondary_index_key(model.table_prefix, &specs[0], &model, &row)
            .expect("embedded NUL in index key text must encode");
        let decoded = decode_secondary_index_key(model.table_prefix, &specs[0], &model, &key)
            .expect("embedded NUL index key must decode");
        assert!(matches!(
            decoded.values.get(&1),
            Some(CellValue::Utf8(value)) if value == "AB\0CD"
        ));
    }

    #[test]
    fn secondary_index_with_long_utf8_primary_key_encodes_at_max_payload_and_rejects_overflow() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Utf8, false),
                TableColumnConfig::new("tag", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("tag_idx", vec!["tag".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();
        let spec = &specs[0];
        let max_payload = spec.codec.payload_capacity_bytes();
        let max_tag = "t".to_string();
        let max_id = "i".repeat(max_payload - encode_string_variable(&max_tag).unwrap().len() - 1);
        let overflow_id = format!("{max_id}x");

        let key = encode_secondary_index_key(
            model.table_prefix,
            spec,
            &model,
            &KvRow {
                values: vec![
                    CellValue::Utf8(max_id.clone()),
                    CellValue::Utf8(max_tag.clone()),
                ],
            },
        )
        .expect("secondary key at max payload should encode");
        assert_eq!(key.len(), exoware_sdk::keys::MAX_KEY_LEN);
        let decoded =
            decode_secondary_index_key(model.table_prefix, spec, &model, &key).expect("decode");
        assert!(matches!(
            decoded.values.get(&1),
            Some(CellValue::Utf8(value)) if value == &max_tag
        ));
        assert!(matches!(
            decoded.primary_key_values.as_slice(),
            [CellValue::Utf8(value)] if value == &max_id
        ));

        let err = encode_secondary_index_key(
            model.table_prefix,
            spec,
            &model,
            &KvRow {
                values: vec![CellValue::Utf8(overflow_id), CellValue::Utf8(max_tag)],
            },
        )
        .expect_err("secondary key exceeding max payload should be rejected");
        assert!(err.contains("index 'tag_idx' payload exceeds codec payload capacity 252 bytes"));
    }

    #[test]
    fn secondary_index_from_parts_with_long_utf8_primary_key_rejects_overflow() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Utf8, false),
                TableColumnConfig::new("tag", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("tag_idx", vec!["tag".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();
        let spec = &specs[0];
        let max_payload = spec.codec.payload_capacity_bytes();
        let max_tag = "t".to_string();
        let max_id = "i".repeat(max_payload - encode_string_variable(&max_tag).unwrap().len() - 1);
        let overflow_id = format!("{max_id}x");
        let max_row = KvRow {
            values: vec![
                CellValue::Utf8(max_id.clone()),
                CellValue::Utf8(max_tag.clone()),
            ],
        };
        let encoded_row = encode_base_row_value(&max_row, &model).expect("encode row");
        let archived = decode_stored_row(&encoded_row).expect("archive row");

        let key = encode_secondary_index_key_from_parts(
            model.table_prefix,
            spec,
            &model,
            &[CellValue::Utf8(max_id.clone())],
            &archived,
        )
        .expect("backfill path should encode max payload");
        assert_eq!(key.len(), exoware_sdk::keys::MAX_KEY_LEN);

        let err = encode_secondary_index_key_from_parts(
            model.table_prefix,
            spec,
            &model,
            &[CellValue::Utf8(overflow_id)],
            &archived,
        )
        .expect_err("backfill path overflow should be rejected");
        assert!(err
            .to_string()
            .contains("index 'tag_idx' payload exceeds codec payload capacity 252 bytes"));
    }

    #[test]
    fn primary_key_type_mismatch_returns_error_instead_of_panicking() {
        let config = KvTableConfig::new(
            0,
            vec![TableColumnConfig::new("id", DataType::UInt64, false)],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let row = KvRow {
            values: vec![CellValue::Int64(7)],
        };

        let err = encode_primary_key_from_row(model.table_prefix, &row, &model)
            .expect_err("mismatched PK type should return an error");
        assert!(err.contains("type mismatch while encoding key value"));
    }

    #[test]
    fn choose_index_plan_uses_fixed_binary_leading_constraint() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(16), false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("entity_idx", vec!["entity".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();

        use datafusion::logical_expr::col;
        let filter = col("entity").eq(Expr::Literal(
            ScalarValue::FixedSizeBinary(16, Some(vec![0xAB; 16])),
            None,
        ));
        let pred = QueryPredicate::from_filters(&[filter], &model);
        let plan = pred
            .choose_index_plan(&model, &specs)
            .unwrap()
            .expect("fixed-binary equality should choose an index");

        assert_eq!(plan.constrained_prefix_len, 1);
        assert_eq!(plan.ranges.len(), 1);
        let range = &plan.ranges[0];
        assert_eq!(
            index_payload(&specs[0], &range.start, 0, 16),
            vec![0xAB; 16]
        );
        assert_eq!(index_payload(&specs[0], &range.end, 0, 16), vec![0xAB; 16]);
    }

    #[test]
    fn choose_index_plan_uses_decimal256_leading_constraint() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("big_val", DataType::Decimal256(76, 0), false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("big_idx", vec!["big_val".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();

        use datafusion::logical_expr::col;
        let filter = col("big_val").gt_eq(Expr::Literal(
            ScalarValue::Decimal256(Some(i256::from(100i64)), 76, 0),
            None,
        ));
        let pred = QueryPredicate::from_filters(&[filter], &model);
        let plan = pred
            .choose_index_plan(&model, &specs)
            .unwrap()
            .expect("decimal256 range should choose an index");

        assert_eq!(plan.constrained_prefix_len, 1);
        assert_eq!(plan.ranges.len(), 1);
        let range = &plan.ranges[0];
        assert_eq!(
            index_payload(&specs[0], &range.start, 0, 32),
            encode_i256_ordered(i256::from(100i64)).to_vec()
        );
    }

    #[tokio::test]
    async fn backfill_added_indexes_writes_entries_for_existing_rows() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let seed_schema = KvSchema::unprefixed(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("seed schema");
        let mut writer = seed_schema.batch_writer();
        for i in 0..6i64 {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(i),
                        CellValue::Utf8(if i % 2 == 0 { "open" } else { "closed" }.to_string()),
                        CellValue::Int64(i * 10),
                    ],
                )
                .expect("seed row");
        }
        writer.flush().await.expect("seed flush");

        {
            let guard = state.kv.lock().expect("kv mutex poisoned");
            let base_rows = guard
                .keys()
                .filter(|key| matches_primary_key(0, key))
                .count();
            let index_rows = guard
                .keys()
                .filter(|key| matches_secondary_index_key(0, 1, key))
                .count();
            assert_eq!(base_rows, 6);
            assert_eq!(index_rows, 0);
        }

        let backfill_schema = KvSchema::unprefixed(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid index")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("backfill schema");
        let report = backfill_schema
            .backfill_added_indexes_with_options(
                "orders",
                &[],
                IndexBackfillOptions {
                    row_batch_size: 2,
                    start_from_primary_key: None,
                },
            )
            .await
            .expect("backfill should succeed");
        assert_eq!(report.scanned_rows, 6);
        assert_eq!(report.indexes_backfilled, 1);
        assert_eq!(report.index_entries_written, 6);

        {
            let guard = state.kv.lock().expect("kv mutex poisoned");
            let index_rows = guard
                .keys()
                .filter(|key| matches_secondary_index_key(0, 1, key))
                .count();
            assert_eq!(index_rows, 6);
            let (_, sample_value) = guard
                .iter()
                .find(|(key, _)| matches_secondary_index_key(0, 1, key))
                .expect("backfill should create index entry");
            let archived = decode_stored_row(sample_value.as_ref())
                .expect("covering value must be valid codec");
            assert_eq!(archived.values.len(), 3);
        }

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn backfill_added_indexes_writes_zorder_entries_for_existing_rows() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let seed_schema = KvSchema::unprefixed(client.clone())
            .table(
                "points",
                vec![
                    TableColumnConfig::new("x", DataType::Int64, false),
                    TableColumnConfig::new("y", DataType::Int64, false),
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("value", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("seed schema");
        let mut writer = seed_schema.batch_writer();
        for (x, y, id, value) in [(1, 1, 11, 110), (1, 2, 12, 120), (2, 1, 21, 210)] {
            writer
                .insert(
                    "points",
                    vec![
                        CellValue::Int64(x),
                        CellValue::Int64(y),
                        CellValue::Int64(id),
                        CellValue::Int64(value),
                    ],
                )
                .expect("seed row");
        }
        writer.flush().await.expect("seed flush");

        let backfill_schema = KvSchema::unprefixed(client.clone())
            .table(
                "points",
                vec![
                    TableColumnConfig::new("x", DataType::Int64, false),
                    TableColumnConfig::new("y", DataType::Int64, false),
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("value", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![
                    IndexSpec::z_order("xy_z", vec!["x".to_string(), "y".to_string()])
                        .expect("valid index")
                        .with_cover_columns(vec!["value".to_string()]),
                ],
            )
            .expect("backfill schema");
        let report = backfill_schema
            .backfill_added_indexes_with_options(
                "points",
                &[],
                IndexBackfillOptions {
                    row_batch_size: 2,
                    start_from_primary_key: None,
                },
            )
            .await
            .expect("backfill should succeed");
        assert_eq!(report.scanned_rows, 3);
        assert_eq!(report.index_entries_written, 3);

        let guard = state.kv.lock().expect("kv mutex poisoned");
        let index_entry = guard
            .keys()
            .find(|key| matches_secondary_index_key(0, 1, key))
            .cloned()
            .expect("z-order backfill should create index entry");
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("x", DataType::Int64, false),
                TableColumnConfig::new("y", DataType::Int64, false),
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("value", DataType::Int64, false),
            ],
            vec!["id".to_string()],
            vec![
                IndexSpec::z_order("xy_z", vec!["x".to_string(), "y".to_string()]).expect("valid"),
            ],
        )
        .expect("config");
        let model = TableModel::from_config(&config).expect("model");
        let spec = model
            .resolve_index_specs(&config.index_specs)
            .expect("specs")
            .remove(0);
        let decoded = decode_secondary_index_key(model.table_prefix, &spec, &model, &index_entry)
            .expect("decode z-order key");
        let x_idx = *model.columns_by_name.get("x").unwrap();
        let y_idx = *model.columns_by_name.get("y").unwrap();
        assert!(matches!(
            decoded.values.get(&x_idx),
            Some(CellValue::Int64(_))
        ));
        assert!(matches!(
            decoded.values.get(&y_idx),
            Some(CellValue::Int64(_))
        ));

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn backfill_added_indexes_requires_append_only_index_evolution() {
        let client = StoreClient::new("http://127.0.0.1:1");
        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![
                    IndexSpec::new("status_idx", vec!["status".to_string()]).expect("valid"),
                    IndexSpec::new("amount_idx", vec!["amount_cents".to_string()]).expect("valid"),
                ],
            )
            .expect("schema");

        let previous_specs =
            vec![IndexSpec::new("amount_idx", vec!["amount_cents".to_string()]).expect("valid")];
        let err = schema
            .backfill_added_indexes("orders", &previous_specs)
            .await
            .expect_err("non-append-only evolution should be rejected");
        assert!(err
            .to_string()
            .contains("index evolution must be append-only"));
    }

    #[tokio::test]
    async fn backfill_added_indexes_is_noop_when_no_new_indexes() {
        let client = StoreClient::new("http://127.0.0.1:1");
        let existing = IndexSpec::new("status_idx", vec!["status".to_string()])
            .expect("valid")
            .with_cover_columns(vec!["amount_cents".to_string()]);
        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![existing.clone()],
            )
            .expect("schema");

        let report = schema
            .backfill_added_indexes("orders", &[existing])
            .await
            .expect("no-op backfill should succeed");
        assert_eq!(report, IndexBackfillReport::default());
    }

    #[tokio::test]
    async fn backfill_added_indexes_rejects_zero_row_batch_size() {
        let client = StoreClient::new("http://127.0.0.1:1");
        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()]).expect("valid")],
            )
            .expect("schema");
        let err = schema
            .backfill_added_indexes_with_options(
                "orders",
                &[],
                IndexBackfillOptions {
                    row_batch_size: 0,
                    start_from_primary_key: None,
                },
            )
            .await
            .expect_err("row_batch_size=0 should fail");
        assert!(err.to_string().contains("row_batch_size must be > 0"));
    }

    #[tokio::test]
    async fn backfill_added_indexes_emits_progress_events() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let seed_schema = KvSchema::new(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("seed schema");
        let mut writer = seed_schema.batch_writer();
        for i in 0..5i64 {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(i),
                        CellValue::Utf8("open".to_string()),
                        CellValue::Int64(i * 10),
                    ],
                )
                .expect("seed row");
        }
        writer.flush().await.expect("seed flush");

        let backfill_schema = KvSchema::new(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()]).expect("valid")],
            )
            .expect("backfill schema");

        let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
        let report = backfill_schema
            .backfill_added_indexes_with_options_and_progress(
                "orders",
                &[],
                IndexBackfillOptions {
                    row_batch_size: 2,
                    start_from_primary_key: None,
                },
                Some(&progress_tx),
            )
            .await
            .expect("backfill should succeed");
        drop(progress_tx);

        let mut saw_started = false;
        let mut saw_completed = false;
        let mut progress_events = 0usize;
        while let Some(event) = progress_rx.recv().await {
            match event {
                IndexBackfillEvent::Started {
                    table_name,
                    indexes_backfilled,
                    row_batch_size,
                    ..
                } => {
                    saw_started = true;
                    assert_eq!(table_name, "orders");
                    assert_eq!(indexes_backfilled, 1);
                    assert_eq!(row_batch_size, 2);
                }
                IndexBackfillEvent::Progress {
                    scanned_rows,
                    index_entries_written,
                    ..
                } => {
                    progress_events += 1;
                    assert!(scanned_rows >= 1);
                    assert_eq!(scanned_rows, index_entries_written);
                }
                IndexBackfillEvent::Completed {
                    report: completed_report,
                } => {
                    saw_completed = true;
                    assert_eq!(completed_report, report);
                }
            }
        }
        assert!(saw_started);
        assert!(saw_completed);
        assert!(progress_events >= 1);

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn backfill_added_indexes_can_resume_from_primary_key() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let seed_schema = KvSchema::unprefixed(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("seed schema");
        let mut writer = seed_schema.batch_writer();
        for i in 0..6i64 {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(i),
                        CellValue::Utf8("open".to_string()),
                        CellValue::Int64(i * 10),
                    ],
                )
                .expect("seed row");
        }
        writer.flush().await.expect("seed flush");

        let backfill_schema = KvSchema::unprefixed(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()]).expect("valid")],
            )
            .expect("backfill schema");

        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("status", DataType::Utf8, false),
                TableColumnConfig::new("amount_cents", DataType::Int64, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("valid config");
        let model = TableModel::from_config(&config).expect("model");
        let resume_value = CellValue::Int64(3);
        let resume_key =
            encode_primary_key(model.table_prefix, &[&resume_value], &model).expect("resume key");

        let report = backfill_schema
            .backfill_added_indexes_with_options(
                "orders",
                &[],
                IndexBackfillOptions {
                    row_batch_size: 2,
                    start_from_primary_key: Some(resume_key.clone()),
                },
            )
            .await
            .expect("resume backfill should succeed");
        assert_eq!(report.scanned_rows, 3);
        assert_eq!(report.index_entries_written, 3);

        {
            let guard = state.kv.lock().expect("kv mutex poisoned");
            let index_rows = guard
                .keys()
                .filter(|key| matches_secondary_index_key(0, 1, key))
                .count();
            assert_eq!(index_rows, 3);
        }

        let resume_payload = model
            .primary_key_codec
            .read_payload(&resume_key, 0, model.primary_key_width)
            .expect("resume payload");
        let wrong_prefix = secondary_index_codec(model.table_prefix, 1)
            .expect("secondary codec")
            .encode(&resume_payload)
            .expect("wrong prefix key");
        let err = backfill_schema
            .backfill_added_indexes_with_options(
                "orders",
                &[],
                IndexBackfillOptions {
                    row_batch_size: 2,
                    start_from_primary_key: Some(wrong_prefix),
                },
            )
            .await
            .expect_err("wrong key prefix must be rejected");
        assert!(err.to_string().contains("primary-key prefix"));

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn covering_index_scan_fails_closed_when_covering_payload_missing() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::unprefixed(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");
        let mut writer = schema.batch_writer();
        for id in 0..4i64 {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8("open".to_string()),
                        CellValue::Int64(id * 10),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        {
            let mut guard = state.kv.lock().expect("kv mutex poisoned");
            let key = guard
                .keys()
                .find(|key| matches_secondary_index_key(0, 1, key))
                .expect("index row should exist")
                .clone();
            guard.insert(key, Bytes::new());
        }

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");
        let df = ctx
            .sql("SELECT amount_cents FROM orders WHERE status = 'open'")
            .await
            .expect("query should plan");
        let err = df
            .collect()
            .await
            .expect_err("missing covering payload must fail closed");
        assert!(err
            .to_string()
            .contains("secondary index entry missing covering payload"));

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn covering_index_scan_fails_closed_when_covering_payload_is_corrupt() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::unprefixed(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");
        let mut writer = schema.batch_writer();
        for id in 0..4i64 {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8("open".to_string()),
                        CellValue::Int64(id * 10),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        {
            let mut guard = state.kv.lock().expect("kv mutex poisoned");
            let key = guard
                .keys()
                .find(|key| matches_secondary_index_key(0, 1, key))
                .expect("index row should exist")
                .clone();
            guard.insert(key, Bytes::from_static(b"not-codec"));
        }

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");
        let df = ctx
            .sql("SELECT amount_cents FROM orders WHERE status = 'open'")
            .await
            .expect("query should plan");
        let err = df
            .collect()
            .await
            .expect_err("corrupt covering payload must fail closed");
        assert!(err.to_string().contains("invalid covering index payload"));

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn non_covering_index_uses_point_lookup_instead_of_full_scan() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                    TableColumnConfig::new("notes", DataType::Utf8, true),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()]).expect("valid")],
            )
            .expect("schema");
        let mut writer = schema.batch_writer();
        writer
            .insert(
                "orders",
                vec![
                    CellValue::Int64(1),
                    CellValue::Utf8("open".to_string()),
                    CellValue::Int64(100),
                    CellValue::Utf8("first".to_string()),
                ],
            )
            .expect("row");
        writer
            .insert(
                "orders",
                vec![
                    CellValue::Int64(2),
                    CellValue::Utf8("closed".to_string()),
                    CellValue::Int64(200),
                    CellValue::Utf8("second".to_string()),
                ],
            )
            .expect("row");
        writer
            .insert(
                "orders",
                vec![
                    CellValue::Int64(3),
                    CellValue::Utf8("open".to_string()),
                    CellValue::Int64(300),
                    CellValue::Utf8("third".to_string()),
                ],
            )
            .expect("row");
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        let df = ctx
            .sql("SELECT id, notes FROM orders WHERE status = 'open' ORDER BY id")
            .await
            .expect("plan");
        let batches = df.collect().await.expect("non-covering index lookup");
        let ids: Vec<i64> = batches
            .iter()
            .flat_map(|b| {
                b.column(0)
                    .as_any()
                    .downcast_ref::<datafusion::arrow::array::Int64Array>()
                    .unwrap()
                    .iter()
                    .map(|v| v.unwrap())
            })
            .collect();
        let notes: Vec<String> = batches
            .iter()
            .flat_map(|b| {
                b.column(1)
                    .as_any()
                    .downcast_ref::<datafusion::arrow::array::StringArray>()
                    .unwrap()
                    .iter()
                    .map(|v| v.unwrap().to_string())
            })
            .collect();
        assert_eq!(ids, vec![1, 3]);
        assert_eq!(notes, vec!["first", "third"]);

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn backfill_resume_cursor_can_continue_without_skips_or_duplicates() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let seed_schema = KvSchema::unprefixed(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("seed schema");
        let mut writer = seed_schema.batch_writer();
        for i in 0..8i64 {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(i),
                        CellValue::Utf8("open".to_string()),
                        CellValue::Int64(i * 10),
                    ],
                )
                .expect("seed row");
        }
        writer.flush().await.expect("seed flush");

        let backfill_schema = KvSchema::unprefixed(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()]).expect("valid")],
            )
            .expect("backfill schema");

        let task_schema = KvSchema::unprefixed(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()]).expect("valid")],
            )
            .expect("task schema");
        let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
        let handle = tokio::spawn(async move {
            task_schema
                .backfill_added_indexes_with_options_and_progress(
                    "orders",
                    &[],
                    IndexBackfillOptions {
                        row_batch_size: 2,
                        start_from_primary_key: None,
                    },
                    Some(&progress_tx),
                )
                .await
        });

        let mut resume_cursor = None;
        while let Some(event) = progress_rx.recv().await {
            if let IndexBackfillEvent::Progress { next_cursor, .. } = event {
                resume_cursor = next_cursor;
                break;
            }
        }
        handle.abort();
        let resume_cursor =
            resume_cursor.expect("first progress event should provide resume cursor");

        let report = backfill_schema
            .backfill_added_indexes_with_options(
                "orders",
                &[],
                IndexBackfillOptions {
                    row_batch_size: 2,
                    start_from_primary_key: Some(resume_cursor),
                },
            )
            .await
            .expect("resume backfill should succeed");
        assert_eq!(report.scanned_rows, 6);

        let guard = state.kv.lock().expect("kv mutex poisoned");
        let base_rows = guard
            .keys()
            .filter(|key| matches_primary_key(0, key))
            .count();
        let index_rows = guard
            .keys()
            .filter(|key| matches_secondary_index_key(0, 1, key))
            .count();
        assert_eq!(base_rows, 8);
        assert_eq!(
            index_rows, 8,
            "resume should backfill each row exactly once"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn concurrent_writes_during_backfill_preserve_index_correctness() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let seed_schema = KvSchema::unprefixed(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("seed schema");
        let mut seed_writer = seed_schema.batch_writer();
        for i in 0..40i64 {
            seed_writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(i),
                        CellValue::Utf8(if i % 2 == 0 { "open" } else { "closed" }.to_string()),
                        CellValue::Int64(i * 10),
                    ],
                )
                .expect("seed row");
        }
        seed_writer.flush().await.expect("seed flush");

        let backfill_schema = KvSchema::unprefixed(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("backfill schema");

        let task_schema = KvSchema::unprefixed(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("task schema");
        let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
        let handle = tokio::spawn(async move {
            task_schema
                .backfill_added_indexes_with_options_and_progress(
                    "orders",
                    &[],
                    IndexBackfillOptions {
                        row_batch_size: 5,
                        start_from_primary_key: None,
                    },
                    Some(&progress_tx),
                )
                .await
        });

        while let Some(event) = progress_rx.recv().await {
            if matches!(event, IndexBackfillEvent::Progress { .. }) {
                break;
            }
        }

        let mut concurrent_writer = backfill_schema.batch_writer();
        for id in [100i64, 101i64] {
            concurrent_writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8("open".to_string()),
                        CellValue::Int64(id * 10),
                    ],
                )
                .expect("concurrent row");
        }
        concurrent_writer.flush().await.expect("concurrent flush");

        let report = handle
            .await
            .expect("backfill task join")
            .expect("backfill result");
        assert!(
            report.scanned_rows >= 40,
            "backfill should at least scan the original historical rows"
        );

        let guard = state.kv.lock().expect("kv mutex poisoned");
        let base_rows = guard
            .keys()
            .filter(|key| matches_primary_key(0, key))
            .count();
        let index_rows = guard
            .keys()
            .filter(|key| matches_secondary_index_key(0, 1, key))
            .count();
        assert_eq!(base_rows, 42);
        assert_eq!(
            index_rows, 42,
            "historical backfill plus concurrent indexed writes should leave one index row per base row"
        );

        let _ = shutdown_tx.send(());
    }

    #[derive(Clone)]
    struct DeferredChunkRangeHarness {
        first_chunk_sent: Arc<Notify>,
        release_second_chunk: Arc<Notify>,
        first_frame: ProtoRangeFrame,
        second_frame: ProtoRangeFrame,
    }

    impl QueryService for DeferredChunkRangeHarness {
        async fn get(
            &self,
            _ctx: Context,
            _request: buffa::view::OwnedView<
                exoware_sdk::store::query::v1::GetRequestView<'static>,
            >,
        ) -> connectrpc::ServiceResult<ProtoGetResponse> {
            Err(ConnectError::unimplemented("test harness"))
        }

        async fn get_many(
            &self,
            _ctx: Context,
            _request: buffa::view::OwnedView<
                exoware_sdk::store::query::v1::GetManyRequestView<'static>,
            >,
        ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<ProtoGetManyFrame>> {
            Err(ConnectError::unimplemented("test harness"))
        }

        async fn range(
            &self,
            _ctx: Context,
            _request: buffa::view::OwnedView<
                exoware_sdk::store::query::v1::RangeRequestView<'static>,
            >,
        ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<ProtoRangeFrame>> {
            let first_chunk_sent = self.first_chunk_sent.clone();
            let release_second_chunk = self.release_second_chunk.clone();
            let first_frame = self.first_frame.clone();
            let second_frame = self.second_frame.clone();
            let stream = stream::try_unfold(0u8, move |state| {
                let first_chunk_sent = first_chunk_sent.clone();
                let release_second_chunk = release_second_chunk.clone();
                let first_frame = first_frame.clone();
                let second_frame = second_frame.clone();
                async move {
                    match state {
                        0 => {
                            first_chunk_sent.notify_one();
                            Ok(Some((first_frame, 1)))
                        }
                        1 => {
                            release_second_chunk.notified().await;
                            Ok(Some((second_frame, 2)))
                        }
                        _ => Ok(None),
                    }
                }
            });
            Ok(connectrpc::Response::stream(stream))
        }

        async fn reduce(
            &self,
            _ctx: Context,
            _request: buffa::view::OwnedView<
                exoware_sdk::store::query::v1::ReduceRequestView<'static>,
            >,
        ) -> connectrpc::ServiceResult<ProtoReduceResponse> {
            Err(ConnectError::unimplemented("test harness"))
        }
    }

    #[derive(Clone)]
    struct ObservedLimitRangeHarness {
        release_second_chunk: Arc<Notify>,
        observed_limit: Arc<AtomicUsize>,
        observed_mode: Arc<AtomicUsize>,
        first_frame: ProtoRangeFrame,
        second_frame: ProtoRangeFrame,
    }

    impl QueryService for ObservedLimitRangeHarness {
        async fn get(
            &self,
            _ctx: Context,
            _request: buffa::view::OwnedView<
                exoware_sdk::store::query::v1::GetRequestView<'static>,
            >,
        ) -> connectrpc::ServiceResult<ProtoGetResponse> {
            Err(ConnectError::unimplemented("test harness"))
        }

        async fn get_many(
            &self,
            _ctx: Context,
            _request: buffa::view::OwnedView<
                exoware_sdk::store::query::v1::GetManyRequestView<'static>,
            >,
        ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<ProtoGetManyFrame>> {
            Err(ConnectError::unimplemented("test harness"))
        }

        async fn range(
            &self,
            _ctx: Context,
            request: buffa::view::OwnedView<
                exoware_sdk::store::query::v1::RangeRequestView<'static>,
            >,
        ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<ProtoRangeFrame>> {
            let limit = request.limit.map(|v| v as usize).unwrap_or(usize::MAX);
            self.observed_limit.store(limit, AtomicOrdering::SeqCst);
            let mode = match parse_range_traversal_direction(request.mode) {
                Ok(RangeTraversalDirection::Forward) => 0,
                Ok(RangeTraversalDirection::Reverse) => 1,
                Err(_) => usize::MAX,
            };
            self.observed_mode.store(mode, AtomicOrdering::SeqCst);
            let release_second_chunk = self.release_second_chunk.clone();
            let first_frame = self.first_frame.clone();
            let second_frame = self.second_frame.clone();
            let stream = stream::try_unfold(0u8, move |state| {
                let release_second_chunk = release_second_chunk.clone();
                let first_frame = first_frame.clone();
                let second_frame = second_frame.clone();
                async move {
                    match state {
                        0 => Ok(Some((first_frame, 1))),
                        1 => {
                            if limit > 1 {
                                release_second_chunk.notified().await;
                                Ok(Some((second_frame, 2)))
                            } else {
                                Ok(None)
                            }
                        }
                        _ => Ok(None),
                    }
                }
            });
            Ok(connectrpc::Response::stream(stream))
        }

        async fn reduce(
            &self,
            _ctx: Context,
            _request: buffa::view::OwnedView<
                exoware_sdk::store::query::v1::ReduceRequestView<'static>,
            >,
        ) -> connectrpc::ServiceResult<ProtoReduceResponse> {
            Err(ConnectError::unimplemented("test harness"))
        }
    }

    #[derive(Clone)]
    struct ObservedLimitIndexRangeHarness {
        observed_limit: Arc<AtomicUsize>,
        entries_frame: ProtoRangeFrame,
    }

    impl QueryService for ObservedLimitIndexRangeHarness {
        async fn get(
            &self,
            _ctx: Context,
            _request: buffa::view::OwnedView<
                exoware_sdk::store::query::v1::GetRequestView<'static>,
            >,
        ) -> connectrpc::ServiceResult<ProtoGetResponse> {
            Err(ConnectError::unimplemented("test harness"))
        }

        async fn get_many(
            &self,
            _ctx: Context,
            _request: buffa::view::OwnedView<
                exoware_sdk::store::query::v1::GetManyRequestView<'static>,
            >,
        ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<ProtoGetManyFrame>> {
            Err(ConnectError::unimplemented("test harness"))
        }

        async fn range(
            &self,
            _ctx: Context,
            request: buffa::view::OwnedView<
                exoware_sdk::store::query::v1::RangeRequestView<'static>,
            >,
        ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<ProtoRangeFrame>> {
            let limit = request
                .limit
                .map(|v| {
                    if v == u32::MAX {
                        usize::MAX
                    } else {
                        v as usize
                    }
                })
                .unwrap_or(usize::MAX);
            self.observed_limit.store(limit, AtomicOrdering::SeqCst);
            let entries_frame = self.entries_frame.clone();
            Ok(connectrpc::Response::stream(stream::iter(vec![Ok(
                entries_frame,
            )])))
        }

        async fn reduce(
            &self,
            _ctx: Context,
            _request: buffa::view::OwnedView<
                exoware_sdk::store::query::v1::ReduceRequestView<'static>,
            >,
        ) -> connectrpc::ServiceResult<ProtoReduceResponse> {
            Err(ConnectError::unimplemented("test harness"))
        }
    }

    #[tokio::test]
    async fn kv_scan_streaming_range_reads_emit_first_batch_before_full_range_completes() {
        let model = Arc::new(simple_int64_model(0));
        let first_chunk_sent = Arc::new(Notify::new());
        let release_second_chunk = Arc::new(Notify::new());

        let encoded_row = (StoredRow { values: vec![None] }).encode().to_vec();

        let first_results = {
            let mut results = Vec::with_capacity(BATCH_FLUSH_ROWS);
            for id in 0..BATCH_FLUSH_ROWS {
                let key =
                    encode_primary_key(model.table_prefix, &[&CellValue::Int64(id as i64)], &model)
                        .expect("primary key");
                results.push((key, encoded_row.clone()));
            }
            results
        };
        let first_frame = proto_range_entries_frame(first_results);

        let second_results = {
            let key = encode_primary_key(
                model.table_prefix,
                &[&CellValue::Int64(BATCH_FLUSH_ROWS as i64)],
                &model,
            )
            .expect("primary key");
            vec![(key, encoded_row)]
        };
        let second_frame = proto_range_entries_frame(second_results);

        let harness = DeferredChunkRangeHarness {
            first_chunk_sent: first_chunk_sent.clone(),
            release_second_chunk: release_second_chunk.clone(),
            first_frame,
            second_frame,
        };
        let connect = ConnectRpcService::new(QueryServiceServer::new(harness))
            .with_compression(connect_compression_registry());
        let app = Router::new().fallback_service(connect);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let url = format!("http://{}", listener.local_addr().expect("listener addr"));
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });

        let client = StoreClient::new(&url);
        let scan = KvScanExec::new(
            client,
            model.clone(),
            Arc::new(Vec::new()),
            QueryPredicate::default(),
            None,
            model.schema.clone(),
            None,
        );

        let session_ctx = SessionContext::new();
        let mut stream = scan
            .execute(0, session_ctx.task_ctx())
            .expect("scan execute should start");

        tokio::time::timeout(Duration::from_secs(1), first_chunk_sent.notified())
            .await
            .expect("server should send first range frame");
        let first_batch = tokio::time::timeout(Duration::from_millis(200), stream.try_next())
            .await
            .expect("first record batch should arrive before the second stream chunk is released")
            .expect("stream poll should succeed")
            .expect("expected first record batch");
        assert_eq!(first_batch.num_rows(), BATCH_FLUSH_ROWS);

        release_second_chunk.notify_one();

        let second_batch = stream
            .try_next()
            .await
            .expect("second poll should succeed")
            .expect("expected second record batch");
        assert_eq!(second_batch.num_rows(), 1);
        assert!(
            stream
                .try_next()
                .await
                .expect("stream completion poll")
                .is_none(),
            "stream should finish after the second batch"
        );
    }

    #[tokio::test]
    async fn kv_scan_sql_limit_is_pushed_upstream_on_exact_streaming_scan() {
        let release_second_chunk = Arc::new(Notify::new());
        let observed_limit = Arc::new(AtomicUsize::new(0));
        let observed_mode = Arc::new(AtomicUsize::new(usize::MAX));
        let model = simple_int64_model(0);

        let encoded_row = (StoredRow { values: vec![None] }).encode().to_vec();

        let first_key = encode_primary_key(model.table_prefix, &[&CellValue::Int64(1)], &model)
            .expect("first primary key");
        let second_key = encode_primary_key(model.table_prefix, &[&CellValue::Int64(2)], &model)
            .expect("second primary key");

        let first_frame = proto_range_entries_frame(vec![(first_key, encoded_row.clone())]);
        let second_frame = proto_range_entries_frame(vec![(second_key, encoded_row)]);

        let harness = ObservedLimitRangeHarness {
            release_second_chunk: release_second_chunk.clone(),
            observed_limit: observed_limit.clone(),
            observed_mode,
            first_frame,
            second_frame,
        };
        let connect = ConnectRpcService::new(QueryServiceServer::new(harness))
            .with_compression(connect_compression_registry());
        let app = Router::new().fallback_service(connect);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let url = format!("http://{}", listener.local_addr().expect("listener addr"));
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });

        let client = StoreClient::new(&url);
        let schema = KvSchema::unprefixed(client)
            .table(
                "items",
                vec![TableColumnConfig::new("id", DataType::Int64, false)],
                vec!["id".to_string()],
                vec![],
            )
            .expect("schema");
        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");
        let batches = tokio::time::timeout(Duration::from_millis(200), async {
            ctx.sql("SELECT id FROM items LIMIT 1")
                .await
                .expect("query")
                .collect()
                .await
                .expect("collect")
        })
        .await
        .expect("query with LIMIT 1 should finish without waiting for a delayed second chunk");

        assert_eq!(
            batches.iter().map(|batch| batch.num_rows()).sum::<usize>(),
            1
        );
        assert_eq!(
            observed_limit.load(AtomicOrdering::SeqCst),
            1,
            "exact streaming scan should push SQL LIMIT upstream"
        );
        release_second_chunk.notify_one();
    }

    #[test]
    fn kv_scan_physical_limit_pushdown_sets_leaf_fetch() {
        let model = Arc::new(simple_int64_model(0));
        let scan = Arc::new(KvScanExec::new(
            StoreClient::new("http://127.0.0.1:0"),
            model.clone(),
            Arc::new(Vec::new()),
            QueryPredicate::default(),
            None,
            model.schema.clone(),
            None,
        ));
        let limited: Arc<dyn ExecutionPlan> = Arc::new(GlobalLimitExec::new(scan, 0, Some(1)));

        let optimized = LimitPushdown::new()
            .optimize(limited, &ConfigOptions::new())
            .expect("limit pushdown");

        let scan = optimized
            .as_any()
            .downcast_ref::<KvScanExec>()
            .expect("physical limit should be converted to a scan fetch");
        assert_eq!(scan.fetch(), Some(1));
    }

    #[tokio::test]
    async fn kv_scan_activity_desc_order_pushes_reverse_range_limit() {
        let release_second_chunk = Arc::new(Notify::new());
        let observed_limit = Arc::new(AtomicUsize::new(0));
        let observed_mode = Arc::new(AtomicUsize::new(usize::MAX));
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("account", DataType::UInt64, false),
                TableColumnConfig::new("height", DataType::UInt64, false),
                TableColumnConfig::new("index", DataType::UInt64, false),
                TableColumnConfig::new("role", DataType::UInt64, false),
            ],
            vec![
                "account".to_string(),
                "height".to_string(),
                "index".to_string(),
                "role".to_string(),
            ],
            vec![],
        )
        .expect("config");
        let model = TableModel::from_config(&config).expect("model");
        let encoded_row = (StoredRow {
            values: vec![None, None, None, None],
        })
        .encode()
        .to_vec();

        let receiver_key = encode_primary_key(
            model.table_prefix,
            &[
                &CellValue::UInt64(7),
                &CellValue::UInt64(9),
                &CellValue::UInt64(4),
                &CellValue::UInt64(1),
            ],
            &model,
        )
        .expect("receiver primary key");
        let sender_key = encode_primary_key(
            model.table_prefix,
            &[
                &CellValue::UInt64(7),
                &CellValue::UInt64(9),
                &CellValue::UInt64(4),
                &CellValue::UInt64(0),
            ],
            &model,
        )
        .expect("sender primary key");

        let first_frame = proto_range_entries_frame(vec![(receiver_key, encoded_row.clone())]);
        let second_frame = proto_range_entries_frame(vec![(sender_key, encoded_row)]);

        let harness = ObservedLimitRangeHarness {
            release_second_chunk: release_second_chunk.clone(),
            observed_limit: observed_limit.clone(),
            observed_mode: observed_mode.clone(),
            first_frame,
            second_frame,
        };
        let connect = ConnectRpcService::new(QueryServiceServer::new(harness))
            .with_compression(connect_compression_registry());
        let app = Router::new().fallback_service(connect);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let url = format!("http://{}", listener.local_addr().expect("listener addr"));
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });

        let client = StoreClient::new(&url);
        let schema = KvSchema::unprefixed(client)
            .table(
                "tx_activity",
                vec![
                    TableColumnConfig::new("account", DataType::UInt64, false),
                    TableColumnConfig::new("height", DataType::UInt64, false),
                    TableColumnConfig::new("index", DataType::UInt64, false),
                    TableColumnConfig::new("role", DataType::UInt64, false),
                ],
                vec![
                    "account".to_string(),
                    "height".to_string(),
                    "index".to_string(),
                    "role".to_string(),
                ],
                vec![],
            )
            .expect("schema");
        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        let batches = tokio::time::timeout(Duration::from_millis(200), async {
            ctx.sql(
                "SELECT height, index, role \
                 FROM tx_activity \
                 WHERE account = 7 \
                 ORDER BY height DESC, index DESC, role DESC \
                 LIMIT 1",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect")
        })
        .await
        .expect("activity DESC LIMIT query should not wait for a delayed second chunk");

        assert_eq!(
            batches.iter().map(|batch| batch.num_rows()).sum::<usize>(),
            1
        );
        assert_eq!(
            observed_mode.load(AtomicOrdering::SeqCst),
            1,
            "activity DESC primary-key order should use reverse range traversal"
        );
        assert_eq!(
            observed_limit.load(AtomicOrdering::SeqCst),
            1,
            "activity DESC LIMIT should push the top-K limit to the range request"
        );
        release_second_chunk.notify_one();
    }

    #[tokio::test]
    async fn kv_scan_activity_mixed_order_does_not_push_range_limit() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "tx_activity",
                vec![
                    TableColumnConfig::new("account", DataType::UInt64, false),
                    TableColumnConfig::new("height", DataType::UInt64, false),
                    TableColumnConfig::new("index", DataType::UInt64, false),
                    TableColumnConfig::new("role", DataType::UInt64, false),
                ],
                vec![
                    "account".to_string(),
                    "height".to_string(),
                    "index".to_string(),
                    "role".to_string(),
                ],
                vec![],
            )
            .expect("schema");
        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        let explain = physical_plan_text(
            &explain_plan_rows(
                &ctx,
                "SELECT height, index, role \
                 FROM tx_activity \
                 WHERE account = 7 \
                 ORDER BY height DESC, index DESC, role ASC \
                 LIMIT 1",
            )
            .await,
        );
        assert!(explain.contains("KvScanExec:"));
        assert!(
            explain.contains("KvScanExec: limit=None"),
            "mixed direction order cannot be a bounded key-order scan:\n{explain}"
        );
        assert!(
            !explain.contains("KvScanExec: limit=Some(1)"),
            "mixed direction order incorrectly pushed top-K into the scan:\n{explain}"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn kv_topk_sort_pushdown_stops_at_filter_exec() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "tx_activity",
                vec![
                    TableColumnConfig::new("account", DataType::UInt64, false),
                    TableColumnConfig::new("height", DataType::UInt64, false),
                    TableColumnConfig::new("index", DataType::UInt64, false),
                    TableColumnConfig::new("role", DataType::UInt64, false),
                ],
                vec![
                    "account".to_string(),
                    "height".to_string(),
                    "index".to_string(),
                    "role".to_string(),
                ],
                vec![],
            )
            .expect("schema");
        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        let explain = physical_plan_text(
            &explain_plan_rows(
                &ctx,
                "SELECT height, index, role \
                 FROM tx_activity \
                 WHERE account = 7 AND height + 0 > 1 \
                 ORDER BY height DESC, index DESC, role DESC \
                 LIMIT 1",
            )
            .await,
        );
        assert!(
            explain.contains("FilterExec"),
            "unsupported filter should remain above scan:\n{explain}"
        );
        assert!(
            explain.contains("KvScanExec: limit=None"),
            "top-K fetch must not cross a row-dropping filter:\n{explain}"
        );
        assert!(
            !explain.contains("KvScanExec: limit=Some(1)"),
            "top-K fetch crossed a filter into the scan:\n{explain}"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn kv_topk_reverse_scan_keeps_reading_after_later_pk_filter_rejects_first_key() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client.clone())
            .table(
                "tx_activity",
                vec![
                    TableColumnConfig::new("account", DataType::UInt64, false),
                    TableColumnConfig::new("height", DataType::UInt64, false),
                    TableColumnConfig::new("index", DataType::UInt64, false),
                    TableColumnConfig::new("role", DataType::UInt64, false),
                ],
                vec![
                    "account".to_string(),
                    "height".to_string(),
                    "index".to_string(),
                    "role".to_string(),
                ],
                vec![],
            )
            .expect("schema");
        let mut writer = schema.batch_writer();
        writer
            .insert(
                "tx_activity",
                vec![
                    CellValue::UInt64(8),
                    CellValue::UInt64(0),
                    CellValue::UInt64(0),
                    CellValue::UInt64(0),
                ],
            )
            .expect("non-matching higher key");
        writer
            .insert(
                "tx_activity",
                vec![
                    CellValue::UInt64(7),
                    CellValue::UInt64(9),
                    CellValue::UInt64(4),
                    CellValue::UInt64(1),
                ],
            )
            .expect("matching lower key");
        writer.flush().await.expect("seed rows");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");
        let sql = "SELECT account, height \
                   FROM tx_activity \
                   WHERE account >= 7 AND height = 9 \
                   ORDER BY account DESC \
                   LIMIT 1";
        let explain = physical_plan_text(&explain_plan_rows(&ctx, sql).await);
        assert!(
            explain.contains("KvScanExec: limit=Some(1), direction=Reverse"),
            "test must exercise reverse top-K scan pushdown:\n{explain}"
        );

        let batches = ctx
            .sql(sql)
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");
        assert_eq!(
            batches.iter().map(|batch| batch.num_rows()).sum::<usize>(),
            1
        );
        let batch = batches
            .iter()
            .find(|batch| batch.num_rows() > 0)
            .expect("non-empty result batch");
        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 0).expect("account scalar"),
            ScalarValue::UInt64(Some(7))
        );
        assert_eq!(
            ScalarValue::try_from_array(batch.column(1), 0).expect("height scalar"),
            ScalarValue::UInt64(Some(9))
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn kv_topk_reverse_scan_orders_multiple_primary_key_ranges() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client.clone())
            .table(
                "events",
                vec![TableColumnConfig::new("id", DataType::Int64, false)],
                vec!["id".to_string()],
                vec![],
            )
            .expect("schema");
        let mut writer = schema.batch_writer();
        for id in [1, 3, 10, 20] {
            writer
                .insert("events", vec![CellValue::Int64(id)])
                .expect("row");
        }
        writer.flush().await.expect("seed rows");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");
        let sql = "SELECT id \
                   FROM events \
                   WHERE id IN (3, 20, 1, 10) \
                   ORDER BY id DESC \
                   LIMIT 3";
        let explain = physical_plan_text(&explain_plan_rows(&ctx, sql).await);
        assert!(
            explain.contains("KvScanExec: limit=Some(3), direction=Reverse"),
            "test must exercise reverse top-K scan pushdown over IN ranges:\n{explain}"
        );

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        let batches = ctx
            .sql(sql)
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");
        assert_eq!(collect_i64_column(&batches, 0), vec![20, 10, 3]);
        assert_eq!(
            state.range_calls.load(AtomicOrdering::SeqCst),
            3,
            "reverse scan should stop after the three highest IN ranges"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn kv_topk_reverse_scan_applies_offset_over_multiple_primary_key_ranges() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client.clone())
            .table(
                "events",
                vec![TableColumnConfig::new("id", DataType::Int64, false)],
                vec!["id".to_string()],
                vec![],
            )
            .expect("schema");
        let mut writer = schema.batch_writer();
        for id in [1, 3, 10, 20] {
            writer
                .insert("events", vec![CellValue::Int64(id)])
                .expect("row");
        }
        writer.flush().await.expect("seed rows");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");
        let sql = "SELECT id \
                   FROM events \
                   WHERE id IN (3, 20, 1, 10) \
                   ORDER BY id DESC \
                   LIMIT 2 OFFSET 1";
        let explain = physical_plan_text(&explain_plan_rows(&ctx, sql).await);
        assert!(
            explain.contains("KvScanExec: limit=Some(3), direction=Reverse"),
            "OFFSET requires fetching offset + limit rows from the reverse scan:\n{explain}"
        );

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        let batches = ctx
            .sql(sql)
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");
        assert_eq!(collect_i64_column(&batches, 0), vec![10, 3]);
        assert_eq!(
            state.range_calls.load(AtomicOrdering::SeqCst),
            3,
            "reverse OFFSET scan should fetch only offset + limit IN ranges"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn kv_scan_impossible_utf8_primary_key_equality_skips_scan() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client.clone())
            .table(
                "items",
                vec![TableColumnConfig::new("id", DataType::Utf8, false)],
                vec!["id".to_string()],
                vec![],
            )
            .expect("schema");
        let mut writer = schema.batch_writer();
        writer
            .insert("items", vec![CellValue::Utf8("present".to_string())])
            .expect("row");
        writer.flush().await.expect("seed rows");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        let oversized = "a".repeat(
            primary_key_codec(0)
                .expect("primary-key codec")
                .payload_capacity_bytes(),
        );
        let sql = format!("SELECT id FROM items WHERE id = '{oversized}'");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        let batches = ctx
            .sql(&sql)
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");
        assert_eq!(
            batches.iter().map(|batch| batch.num_rows()).sum::<usize>(),
            0,
            "an unencodable PK equality can never match any row"
        );
        assert_eq!(
            state.range_calls.load(AtomicOrdering::SeqCst),
            0,
            "an impossible PK equality must not issue a range scan"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn kv_scan_index_limit_does_not_push_upstream_when_seen_dedup_can_drop_entries() {
        let observed_limit = Arc::new(AtomicUsize::new(0));
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("status", DataType::Utf8, false),
                TableColumnConfig::new("amount_cents", DataType::Int64, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                .expect("valid")
                .with_cover_columns(vec!["status".to_string(), "amount_cents".to_string()])],
        )
        .expect("config");
        let model = TableModel::from_config(&config).expect("model");
        let spec = model
            .resolve_index_specs(&config.index_specs)
            .expect("specs")
            .into_iter()
            .next()
            .expect("status index spec");
        let stale_row = KvRow {
            values: vec![
                CellValue::Int64(7),
                CellValue::Utf8("closed".to_string()),
                CellValue::Int64(10),
            ],
        };
        let current_row = KvRow {
            values: vec![
                CellValue::Int64(7),
                CellValue::Utf8("open".to_string()),
                CellValue::Int64(10),
            ],
        };
        let unique_row = KvRow {
            values: vec![
                CellValue::Int64(8),
                CellValue::Utf8("open".to_string()),
                CellValue::Int64(20),
            ],
        };
        let stale_key = encode_secondary_index_key(model.table_prefix, &spec, &model, &stale_row)
            .expect("stale index key");
        let current_key =
            encode_secondary_index_key(model.table_prefix, &spec, &model, &current_row)
                .expect("current index key");
        let unique_key = encode_secondary_index_key(model.table_prefix, &spec, &model, &unique_row)
            .expect("unique index key");
        let stale_payload =
            encode_secondary_index_value(&stale_row, &model, &spec).expect("stale payload");
        let current_payload =
            encode_secondary_index_value(&current_row, &model, &spec).expect("current payload");
        let unique_payload =
            encode_secondary_index_value(&unique_row, &model, &spec).expect("unique payload");

        let entries_frame = proto_range_entries_frame(vec![
            (stale_key, stale_payload),
            (current_key, current_payload),
            (unique_key, unique_payload),
        ]);
        let harness = ObservedLimitIndexRangeHarness {
            observed_limit: observed_limit.clone(),
            entries_frame,
        };
        let connect = ConnectRpcService::new(QueryServiceServer::new(harness))
            .with_compression(connect_compression_registry());
        let app = Router::new().fallback_service(connect);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let url = format!("http://{}", listener.local_addr().expect("listener addr"));
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });

        let client = StoreClient::new(&url);
        let schema = KvSchema::unprefixed(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["status".to_string(), "amount_cents".to_string()])],
            )
            .expect("schema");
        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        let batches = ctx
            .sql(
                "SELECT id, amount_cents \
                 FROM orders \
                 WHERE status IN ('open', 'closed') \
                 LIMIT 2",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(
            batches.iter().map(|batch| batch.num_rows()).sum::<usize>(),
            2
        );
        assert_eq!(
            observed_limit.load(AtomicOrdering::SeqCst),
            usize::MAX,
            "index streaming scans should not push SQL LIMIT upstream while seen-dedup can drop duplicate primary keys"
        );
    }

    #[tokio::test]
    async fn zorder_covering_index_scan_filters_false_positive_morton_span_rows() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "points",
                vec![
                    TableColumnConfig::new("x", DataType::Int64, false),
                    TableColumnConfig::new("y", DataType::Int64, false),
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("value", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![
                    IndexSpec::z_order("xy_z", vec!["x".to_string(), "y".to_string()])
                        .expect("valid")
                        .with_cover_columns(vec!["value".to_string()]),
                ],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (x, y, id, value) in [
            (0, 2, 2, 20),
            (1, 1, 11, 110),
            (1, 2, 12, 120),
            (2, 1, 21, 210),
            (2, 2, 22, 220),
            (3, 0, 30, 300),
        ] {
            writer
                .insert(
                    "points",
                    vec![
                        CellValue::Int64(x),
                        CellValue::Int64(y),
                        CellValue::Int64(id),
                        CellValue::Int64(value),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        let batches = ctx
            .sql(
                "SELECT id, value FROM points \
                 WHERE x >= 1 AND x <= 2 AND y >= 1 AND y <= 2 \
                 ORDER BY id",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        let mut rows = Vec::new();
        for batch in &batches {
            let ids = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int64Array>()
                .expect("id int64");
            let values = batch
                .column(1)
                .as_any()
                .downcast_ref::<Int64Array>()
                .expect("value int64");
            for row_idx in 0..batch.num_rows() {
                rows.push((ids.value(row_idx), values.value(row_idx)));
            }
        }
        assert_eq!(rows, vec![(11, 110), (12, 120), (21, 210), (22, 220)]);

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_uses_range_reduce_for_supported_global_aggregates() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, status, amount) in [
            (1, "open", 10),
            (2, "closed", 15),
            (3, "open", 30),
            (4, "closed", 40),
        ] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8(status.to_string()),
                        CellValue::Int64(amount),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let df = ctx
            .sql(
                "SELECT COUNT(*) AS row_count, SUM(amount_cents) AS total_cents, \
                 AVG(amount_cents) AS avg_cents \
                 FROM orders WHERE status = 'open'",
            )
            .await
            .expect("query");
        let batches = df.collect().await.expect("collect");

        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        let row_count = ScalarValue::try_from_array(batch.column(0), 0).expect("row_count scalar");
        let total = batch
            .column(1)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("sum int64")
            .value(0);
        let avg = batch
            .column(2)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("avg float64")
            .value(0);
        assert!(matches!(
            row_count,
            ScalarValue::UInt64(Some(2)) | ScalarValue::Int64(Some(2))
        ));
        assert_eq!(total, 40);
        assert_eq!(avg, 20.0);
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 1,
            "supported aggregate should use range reduction path"
        );

        let _ = shutdown_tx.send(());
    }

    /// Store `/v1/range` is inclusive on both ends; `id <= N` and `BETWEEN` must include the end key.
    #[tokio::test]
    async fn primary_key_inclusive_upper_bound_streaming_scan_uses_range() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "inc_pk",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("amount", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for id in 1i64..=5i64 {
            writer
                .insert(
                    "inc_pk",
                    vec![CellValue::Int64(id), CellValue::Int64(id * 100)],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql("SELECT id FROM inc_pk WHERE id <= 3 ORDER BY id")
            .await
            .expect("lte query")
            .collect()
            .await
            .expect("collect");
        let mut ids = Vec::new();
        for batch in &batches {
            let col = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int64Array>()
                .expect("id");
            for i in 0..batch.num_rows() {
                ids.push(col.value(i));
            }
        }
        assert_eq!(ids, vec![1, 2, 3], "id <= 3 must include id 3");
        assert!(
            state.range_calls.load(AtomicOrdering::SeqCst) >= 1,
            "PK bounded scan should call range"
        );
        assert_eq!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst),
            0,
            "streaming scan must not use range_reduce"
        );

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql("SELECT id FROM inc_pk WHERE id BETWEEN 2 AND 4 ORDER BY id")
            .await
            .expect("between query")
            .collect()
            .await
            .expect("collect");
        ids.clear();
        for batch in &batches {
            let col = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int64Array>()
                .expect("id");
            for i in 0..batch.num_rows() {
                ids.push(col.value(i));
            }
        }
        assert_eq!(ids, vec![2, 3, 4], "BETWEEN must include both endpoints");
        assert!(state.range_calls.load(AtomicOrdering::SeqCst) >= 1);
        assert_eq!(state.range_reduce_calls.load(AtomicOrdering::SeqCst), 0);

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn primary_key_inclusive_upper_bound_scalar_aggregates_use_range_reduce() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "inc_pk",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("amount", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for id in 1i64..=5i64 {
            writer
                .insert(
                    "inc_pk",
                    vec![CellValue::Int64(id), CellValue::Int64(id * 100)],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql("SELECT COUNT(*) AS c, SUM(amount) AS s FROM inc_pk WHERE id <= 3")
            .await
            .expect("lte agg")
            .collect()
            .await
            .expect("collect");
        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        let c = ScalarValue::try_from_array(batch.column(0), 0).expect("count");
        assert!(
            matches!(
                c,
                ScalarValue::UInt64(Some(3)) | ScalarValue::Int64(Some(3))
            ),
            "count should include id=3"
        );
        assert_eq!(
            batch
                .column(1)
                .as_any()
                .downcast_ref::<Int64Array>()
                .expect("sum")
                .value(0),
            100 + 200 + 300
        );
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 1,
            "scalar aggregate on PK range should use range_reduce"
        );

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql("SELECT SUM(amount) AS s FROM inc_pk WHERE id BETWEEN 2 AND 4")
            .await
            .expect("between agg")
            .collect()
            .await
            .expect("collect");
        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_eq!(
            batch
                .column(0)
                .as_any()
                .downcast_ref::<Int64Array>()
                .expect("sum")
                .value(0),
            200 + 300 + 400
        );
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 1,
            "BETWEEN aggregate should use range_reduce"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_uses_zorder_index_with_worker_filter() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "points",
                vec![
                    TableColumnConfig::new("x", DataType::Int64, false),
                    TableColumnConfig::new("y", DataType::Int64, false),
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("value", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![
                    IndexSpec::z_order("xy_z", vec!["x".to_string(), "y".to_string()])
                        .expect("valid")
                        .with_cover_columns(vec!["value".to_string()]),
                ],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (x, y, id, value) in [
            (0, 2, 2, 20),
            (1, 1, 11, 110),
            (1, 2, 12, 120),
            (2, 1, 21, 210),
            (2, 2, 22, 220),
            (3, 0, 30, 300),
        ] {
            writer
                .insert(
                    "points",
                    vec![
                        CellValue::Int64(x),
                        CellValue::Int64(y),
                        CellValue::Int64(id),
                        CellValue::Int64(value),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT COUNT(*) AS row_count, SUM(value) AS total_value \
                 FROM points \
                 WHERE x >= 1 AND x <= 2 AND y >= 1 AND y <= 2",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        let row_count = ScalarValue::try_from_array(batch.column(0), 0).expect("row_count scalar");
        let total = batch
            .column(1)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("sum int64")
            .value(0);
        assert!(matches!(
            row_count,
            ScalarValue::UInt64(Some(4)) | ScalarValue::Int64(Some(4))
        ));
        assert_eq!(total, 660);
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 1,
            "z-order aggregate should use range reduction path"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_avg_merges_sum_and_count_across_multiple_ranges() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, status, amount) in [
            (1, "open", 10),
            (2, "open", 20),
            (3, "closed", 100),
            (4, "pending", 1_000),
        ] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8(status.to_string()),
                        CellValue::Int64(amount),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT AVG(amount_cents) AS avg_cents \
                 FROM orders \
                 WHERE status IN ('open', 'closed')",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        let avg = batch
            .column(0)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("avg float64")
            .value(0);
        let expected = 130.0 / 3.0;
        assert!(
            (avg - expected).abs() < 1e-12,
            "AVG should merge SUM+COUNT across unequal-count ranges: got {avg}, expected {expected}"
        );
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst),
            2,
            "status IN (...) should expand to two pushed reduction ranges"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_supports_filtered_global_aggregates() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, status, amount) in [
            (1, "open", 10),
            (2, "closed", 15),
            (3, "open", 30),
            (4, "closed", 40),
        ] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8(status.to_string()),
                        CellValue::Int64(amount),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let query = "SELECT COUNT(*) FILTER (WHERE status = 'open') AS open_count, \
                            COUNT(*) FILTER (WHERE status = 'closed') AS closed_count, \
                            AVG(amount_cents) FILTER (WHERE status = 'closed') AS closed_avg \
                     FROM orders";
        let batches = ctx
            .sql(query)
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_count_scalar(batch, 0, 0, 2);
        assert_count_scalar(batch, 1, 0, 2);
        let closed_avg = batch
            .column(2)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("avg float64")
            .value(0);
        assert_eq!(closed_avg, 27.5);
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 3,
            "filtered aggregate pushdown should use dedicated reduction jobs"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_supports_case_filtered_global_aggregates() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, status, amount) in [
            (1, "open", 10),
            (2, "closed", 15),
            (3, "open", 30),
            (4, "closed", 40),
        ] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8(status.to_string()),
                        CellValue::Int64(amount),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let query = "SELECT SUM(CASE status WHEN 'open' THEN amount_cents END) AS open_total, \
                            COUNT(CASE status WHEN 'closed' THEN 1 END) AS closed_count, \
                            AVG(CASE WHEN status = 'closed' THEN amount_cents END) AS closed_avg \
                     FROM orders";
        let batches = ctx
            .sql(query)
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 0).expect("sum scalar"),
            ScalarValue::Int64(Some(40))
        );
        assert_count_scalar(batch, 1, 0, 2);
        let closed_avg = batch
            .column(2)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("avg float64")
            .value(0);
        assert_eq!(closed_avg, 27.5);
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 3,
            "case-based conditional aggregates should use reduction jobs"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_supports_casted_group_and_aggregate_expressions() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, status, amount) in [
            (1, "open", 10),
            (2, "open", 30),
            (3, "closed", 15),
            (4, "closed", 40),
        ] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8(status.to_string()),
                        CellValue::Int64(amount),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT CAST(status AS VARCHAR) AS status_text, \
                        SUM(CAST(amount_cents AS DOUBLE)) AS total_cents \
                 FROM orders \
                 GROUP BY CAST(status AS VARCHAR) \
                 ORDER BY status_text",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.iter().map(|b| b.num_rows()).sum::<usize>(), 2);
        let batch = &batches[0];
        let status = ScalarValue::try_from_array(batch.column(0), 0).expect("status scalar");
        assert_eq!(scalar_to_string(&status).as_deref(), Some("closed"));
        let closed_total = batch
            .column(1)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("sum float64")
            .value(0);
        let open_total = batch
            .column(1)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("sum float64")
            .value(1);
        assert_eq!(closed_total, 55.0);
        assert_eq!(open_total, 40.0);
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 1,
            "casted grouped aggregates should stay on the reduction path"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_supports_computed_aggregate_inputs() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("price_cents", DataType::Int64, false),
                    TableColumnConfig::new("qty", DataType::Int64, false),
                    TableColumnConfig::new("duration_ms", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, price, qty, duration_ms) in [(1, 10, 2, 500), (2, 15, 3, 2500), (3, 7, 4, 1000)] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Int64(price),
                        CellValue::Int64(qty),
                        CellValue::Int64(duration_ms),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT SUM(price_cents * qty) AS total_revenue, \
                        AVG(duration_ms / 1e3) AS avg_seconds \
                 FROM orders",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 0).expect("sum scalar"),
            ScalarValue::Int64(Some(93))
        );
        let avg_seconds = batch
            .column(1)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("avg float64")
            .value(0);
        assert!((avg_seconds - (4.0 / 3.0)).abs() < 1e-12);
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 2,
            "computed aggregate inputs should use reduction jobs"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_supports_add_and_subtract_inputs() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("price_cents", DataType::Int64, false),
                    TableColumnConfig::new("fee_cents", DataType::Int64, false),
                    TableColumnConfig::new("discount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, price, fee, discount) in [(1, 10, 2, 1), (2, 15, 3, 4), (3, 7, 1, 2)] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Int64(price),
                        CellValue::Int64(fee),
                        CellValue::Int64(discount),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT SUM(price_cents + fee_cents) AS gross_plus_fee, \
                        SUM(price_cents - discount_cents) AS net_total \
                 FROM orders",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 0).expect("sum scalar"),
            ScalarValue::Int64(Some(38))
        );
        assert_eq!(
            ScalarValue::try_from_array(batch.column(1), 0).expect("sum scalar"),
            ScalarValue::Int64(Some(25))
        );
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 2,
            "add/sub aggregate inputs should use reduction jobs"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_supports_case_filtered_computed_aggregates() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("price_cents", DataType::Int64, false),
                    TableColumnConfig::new("qty", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["price_cents".to_string(), "qty".to_string()])],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, status, price, qty) in [
            (1, "open", 10, 2),
            (2, "closed", 99, 1),
            (3, "open", 15, 3),
            (4, "closed", 7, 4),
        ] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8(status.to_string()),
                        CellValue::Int64(price),
                        CellValue::Int64(qty),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT SUM(CASE WHEN status = 'open' THEN price_cents * qty END) \
                 AS open_revenue \
                 FROM orders",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 0).expect("sum scalar"),
            ScalarValue::Int64(Some(65))
        );
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 1,
            "case-filtered computed aggregate should use reduction jobs"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_does_not_rewrite_sum_case_else_zero_semantics() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("region", DataType::Utf8, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["region".to_string(), "amount_cents".to_string()])],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, region, status, amount) in [
            (1, "east", "open", 10),
            (2, "east", "closed", 20),
            (3, "west", "closed", 30),
        ] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8(region.to_string()),
                        CellValue::Utf8(status.to_string()),
                        CellValue::Int64(amount),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT region, \
                        SUM(CASE WHEN status = 'open' THEN amount_cents ELSE 0 END) AS open_total \
                 FROM orders \
                 GROUP BY region \
                 ORDER BY region",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.iter().map(|b| b.num_rows()).sum::<usize>(), 2);
        let batch = &batches[0];
        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 0).expect("region scalar"),
            ScalarValue::Utf8(Some("east".to_string()))
        );
        assert_eq!(
            ScalarValue::try_from_array(batch.column(1), 0).expect("sum scalar"),
            ScalarValue::Int64(Some(10))
        );
        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 1).expect("region scalar"),
            ScalarValue::Utf8(Some("west".to_string()))
        );
        assert_eq!(
            ScalarValue::try_from_array(batch.column(1), 1).expect("sum scalar"),
            ScalarValue::Int64(Some(0))
        );
        assert_eq!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst),
            0,
            "SUM(CASE ... ELSE 0 END) must not push down because FILTER rewrite changes semantics"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_supports_computed_group_keys() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "events",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("country", DataType::Utf8, false),
                    TableColumnConfig::new(
                        "occurred_at",
                        DataType::Timestamp(TimeUnit::Microsecond, None),
                        false,
                    ),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("schema");

        let day_micros = 86_400_000_000i64;
        let day0 = 1_700_000_000_000_000i64;
        let day1 = day0 + day_micros;
        let day0_bucket = day0.div_euclid(day_micros) * day_micros;
        let day1_bucket = day1.div_euclid(day_micros) * day_micros;
        let mut writer = schema.batch_writer();
        for (id, country, occurred_at, amount) in [
            (1, "East", day0 + 111, 10),
            (2, "east", day0 + 222, 30),
            (3, "West", day1 + 333, 7),
        ] {
            writer
                .insert(
                    "events",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8(country.to_string()),
                        CellValue::Timestamp(occurred_at),
                        CellValue::Int64(amount),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT lower(country) AS country_norm, \
                        date_trunc('day', occurred_at) AS day_bucket, \
                        SUM(amount_cents) AS total_cents \
                 FROM events \
                 GROUP BY lower(country), date_trunc('day', occurred_at) \
                 ORDER BY country_norm, day_bucket",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.iter().map(|b| b.num_rows()).sum::<usize>(), 2);
        let batch = &batches[0];
        assert_eq!(
            scalar_to_string(
                &ScalarValue::try_from_array(batch.column(0), 0).expect("country scalar")
            )
            .as_deref(),
            Some("east")
        );
        assert_eq!(
            ScalarValue::try_from_array(batch.column(1), 0).expect("day scalar"),
            ScalarValue::TimestampMicrosecond(Some(day0_bucket), None)
        );
        assert_eq!(
            ScalarValue::try_from_array(batch.column(2), 0).expect("sum scalar"),
            ScalarValue::Int64(Some(40))
        );
        assert_eq!(
            scalar_to_string(
                &ScalarValue::try_from_array(batch.column(0), 1).expect("country scalar")
            )
            .as_deref(),
            Some("west")
        );
        assert_eq!(
            ScalarValue::try_from_array(batch.column(1), 1).expect("day scalar"),
            ScalarValue::TimestampMicrosecond(Some(day1_bucket), None)
        );
        assert_eq!(
            ScalarValue::try_from_array(batch.column(2), 1).expect("sum scalar"),
            ScalarValue::Int64(Some(7))
        );
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 1,
            "computed group keys should use grouped reduction path"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_supports_group_by_queries() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, status, amount) in [
            (1, "open", 10),
            (2, "open", 30),
            (3, "closed", 15),
            (4, "closed", 40),
        ] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8(status.to_string()),
                        CellValue::Int64(amount),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT status, COUNT(*) AS row_count, SUM(amount_cents) AS total_cents \
                 FROM orders GROUP BY status ORDER BY status",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.iter().map(|b| b.num_rows()).sum::<usize>(), 2);
        let batch = &batches[0];
        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 0).expect("status scalar"),
            ScalarValue::Utf8(Some("closed".to_string()))
        );
        assert_count_scalar(batch, 1, 0, 2);
        assert_eq!(
            ScalarValue::try_from_array(batch.column(2), 0).expect("sum scalar"),
            ScalarValue::Int64(Some(55))
        );
        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 1).expect("status scalar"),
            ScalarValue::Utf8(Some("open".to_string()))
        );
        assert_count_scalar(batch, 1, 1, 2);
        assert_eq!(
            ScalarValue::try_from_array(batch.column(2), 1).expect("sum scalar"),
            ScalarValue::Int64(Some(40))
        );
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 2,
            "group-by aggregate should use grouped range reduction path"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_group_by_float_canonicalizes_signed_zero() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "metrics",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("score", DataType::Float64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, score) in [(1, -0.0), (2, 0.0), (3, 1.5)] {
            writer
                .insert(
                    "metrics",
                    vec![CellValue::Int64(id), CellValue::Float64(score)],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT score, COUNT(*) AS row_count \
                 FROM metrics GROUP BY score ORDER BY row_count DESC, score",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.iter().map(|b| b.num_rows()).sum::<usize>(), 2);
        let batch = &batches[0];
        let top_score = batch
            .column(0)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("score float64")
            .value(0);
        assert_eq!(top_score.to_bits(), 0.0f64.to_bits());
        assert_count_scalar(batch, 1, 0, 2);
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 1,
            "float group-by aggregate should stay on grouped reduction path"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_supports_filtered_group_by_queries() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("region", DataType::Utf8, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["region".to_string(), "amount_cents".to_string()])],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, region, status, amount) in [
            (1, "east", "open", 10),
            (2, "east", "closed", 20),
            (3, "west", "open", 30),
            (4, "north", "closed", 40),
        ] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8(region.to_string()),
                        CellValue::Utf8(status.to_string()),
                        CellValue::Int64(amount),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT region, \
                        COUNT(*) FILTER (WHERE status = 'open') AS open_count, \
                        SUM(amount_cents) FILTER (WHERE status = 'closed') AS closed_total \
                 FROM orders \
                 GROUP BY region \
                 ORDER BY region",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.iter().map(|b| b.num_rows()).sum::<usize>(), 3);
        let batch = &batches[0];

        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 0).expect("region scalar"),
            ScalarValue::Utf8(Some("east".to_string()))
        );
        assert_count_scalar(batch, 1, 0, 1);
        assert_eq!(
            ScalarValue::try_from_array(batch.column(2), 0).expect("sum scalar"),
            ScalarValue::Int64(Some(20))
        );

        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 1).expect("region scalar"),
            ScalarValue::Utf8(Some("north".to_string()))
        );
        assert_count_scalar(batch, 1, 1, 0);
        assert_eq!(
            ScalarValue::try_from_array(batch.column(2), 1).expect("sum scalar"),
            ScalarValue::Int64(Some(40))
        );

        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 2).expect("region scalar"),
            ScalarValue::Utf8(Some("west".to_string()))
        );
        assert_count_scalar(batch, 1, 2, 1);
        assert_eq!(
            ScalarValue::try_from_array(batch.column(2), 2).expect("sum scalar"),
            ScalarValue::Int64(None)
        );

        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 3,
            "filtered group-by aggregate should use grouped reduction plus seed job"
        );

        let _ = shutdown_tx.send(());
    }

    mod e2e {
        use super::*;
        use axum::{routing::get, Router};
        use datafusion::prelude::SessionContext;
        use exoware_sdk::StoreClient;
        use exoware_server::{connect_stack, AppState};
        use exoware_simulator::RocksStore;
        use tempfile::tempdir;

        struct TestServers {
            ingest_url: String,
            query_url: String,
        }

        impl TestServers {
            fn client(&self) -> StoreClient {
                StoreClient::builder()
                    .health_url(&self.query_url)
                    .ingest_url(&self.ingest_url)
                    .query_url(&self.query_url)
                    .compact_url(&self.ingest_url)
                    .stream_url(&self.query_url)
                    .build()
                    .expect("test server URLs are set")
            }
        }

        async fn spawn_e2e_servers() -> TestServers {
            let dir = tempdir().expect("tempdir");
            let db = RocksStore::open(dir.path(), None).expect("db");
            let state = AppState::new(std::sync::Arc::new(db));
            let connect = connect_stack(state);
            let app = Router::new()
                .route("/health", get(|| async { "ok" }))
                .fallback_service(connect);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let url = format!("http://{}", listener.local_addr().unwrap());
            tokio::spawn(async move {
                axum::serve(listener, app).await.expect("serve");
            });
            for _ in 0..200 {
                if reqwest::get(format!("{url}/health"))
                    .await
                    .ok()
                    .is_some_and(|r| r.status().is_success())
                {
                    return TestServers {
                        ingest_url: url.clone(),
                        query_url: url,
                    };
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            panic!("e2e simulator did not become ready");
        }

        #[tokio::test]
        async fn sql_insert_and_select_through_real_ingest_query_workers() {
            let servers = spawn_e2e_servers().await;
            let client = servers.client();

            let schema = KvSchema::new(client)
                .table(
                    "orders",
                    vec![
                        TableColumnConfig::new("id", DataType::Int64, false),
                        TableColumnConfig::new("status", DataType::Utf8, false),
                        TableColumnConfig::new("amount_cents", DataType::Int64, false),
                    ],
                    vec!["id".to_string()],
                    vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                        .expect("valid")
                        .with_cover_columns(vec!["amount_cents".to_string()])],
                )
                .expect("schema");

            let mut writer = schema.batch_writer();
            for (id, status, amount) in [
                (1i64, "open", 100i64),
                (2, "closed", 200),
                (3, "open", 300),
                (4, "closed", 400),
                (5, "open", 500),
            ] {
                writer
                    .insert(
                        "orders",
                        vec![
                            CellValue::Int64(id),
                            CellValue::Utf8(status.to_string()),
                            CellValue::Int64(amount),
                        ],
                    )
                    .expect("insert row");
            }
            writer.flush().await.expect("flush batch");

            let ctx = SessionContext::new();
            schema.register_all(&ctx).expect("register tables");

            let batches = ctx
                .sql("SELECT id, amount_cents FROM orders ORDER BY id")
                .await
                .expect("full scan query")
                .collect()
                .await
                .expect("collect full scan");
            let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
            assert_eq!(total_rows, 5, "all 5 rows returned from full scan");

            let mut ids = Vec::new();
            let mut amounts = Vec::new();
            for batch in &batches {
                let id_col = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .expect("id column");
                let amt_col = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .expect("amount column");
                for i in 0..batch.num_rows() {
                    ids.push(id_col.value(i));
                    amounts.push(amt_col.value(i));
                }
            }
            assert_eq!(ids, vec![1, 2, 3, 4, 5]);
            assert_eq!(amounts, vec![100, 200, 300, 400, 500]);

            let filtered = ctx
                .sql(
                    "SELECT id, amount_cents FROM orders \
                     WHERE status = 'open' ORDER BY id",
                )
                .await
                .expect("filtered query")
                .collect()
                .await
                .expect("collect filtered");
            let mut filtered_ids = Vec::new();
            let mut filtered_amounts = Vec::new();
            for batch in &filtered {
                let id_col = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .expect("id column");
                let amt_col = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .expect("amount column");
                for i in 0..batch.num_rows() {
                    filtered_ids.push(id_col.value(i));
                    filtered_amounts.push(amt_col.value(i));
                }
            }
            assert_eq!(filtered_ids, vec![1, 3, 5]);
            assert_eq!(filtered_amounts, vec![100, 300, 500]);

            let agg = ctx
                .sql(
                    "SELECT COUNT(*) AS cnt, SUM(amount_cents) AS total \
                     FROM orders WHERE status = 'open'",
                )
                .await
                .expect("aggregate query")
                .collect()
                .await
                .expect("collect aggregate");
            assert_eq!(agg.len(), 1);
            let batch = &agg[0];
            assert_eq!(batch.num_rows(), 1);
            assert_count_scalar(batch, 0, 0, 3);
            let total = ScalarValue::try_from_array(batch.column(1), 0).expect("sum scalar");
            match total {
                ScalarValue::Int64(Some(v)) => assert_eq!(v, 900),
                other => panic!("unexpected sum type: {other:?}"),
            }
        }
    }
}
