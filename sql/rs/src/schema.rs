use std::any::Any;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use datafusion::arrow::datatypes::{DataType, SchemaRef};
use datafusion::catalog::Session;
use datafusion::common::{DataFusionError, Result as DataFusionResult, SchemaExt};
use datafusion::datasource::sink::DataSinkExec;
use datafusion::datasource::TableProvider;
use datafusion::execution::SessionStateBuilder;
use datafusion::logical_expr::dml::InsertOp;
use datafusion::logical_expr::{Expr, TableProviderFilterPushDown, TableType};
use datafusion::physical_plan::ExecutionPlan;
use datafusion::prelude::SessionContext;
use exoware_sdk::kv_codec::decode_stored_row;
use exoware_sdk::{Namespace, PrefixedStoreClient, StoreClient};

use crate::aggregate::KvAggregatePushdownRule;
use crate::codec::*;
use crate::predicate::*;
use crate::scan::*;
use crate::types::*;
use crate::writer::*;

pub(crate) fn register_kv_table(
    ctx: &SessionContext,
    table_name: &str,
    client: StoreClient,
    config: KvTableConfig,
) -> DataFusionResult<()> {
    let table = Arc::new(
        KvTable::new(client, config)
            .map_err(|e| DataFusionError::Execution(format!("invalid table config: {e}")))?,
    );
    let _ = ctx.register_table(table_name, table)?;
    Ok(())
}

pub struct KvSchema {
    client: StoreClient,
    tables: Vec<(String, KvTableConfig)>,
    next_prefix: u8,
}

impl KvSchema {
    /// Build a schema over the canonical [`Namespace::Sql`] keyspace — the safe
    /// default when the Store is co-tenanted with simplex/qmdb, so SQL's
    /// prefix-bounded scans can't observe foreign keys. Use [`Self::unprefixed`]
    /// only for a Store SQL owns exclusively.
    pub fn new(client: StoreClient) -> Self {
        Self::prefixed(client.for_namespace(Namespace::Sql))
    }

    /// Build a schema over a caller-chosen namespace (e.g. multiple `KvSchema`
    /// instances in one Store). The caller must pick a slot disjoint from every
    /// co-tenant.
    pub fn prefixed(client: PrefixedStoreClient) -> Self {
        Self::unprefixed(client.into_client())
    }

    /// Build a schema over a raw, un-namespaced client — escape hatch for a
    /// single-tenant Store. `grep` for `unprefixed` to audit such call sites.
    pub fn unprefixed(client: StoreClient) -> Self {
        Self {
            client,
            tables: Vec::new(),
            next_prefix: 0,
        }
    }

    pub fn table(
        mut self,
        name: impl Into<String>,
        columns: Vec<TableColumnConfig>,
        primary_key_columns: Vec<String>,
        index_specs: Vec<IndexSpec>,
    ) -> Result<Self, String> {
        if self.tables.len() >= MAX_TABLES {
            return Err(format!(
                "too many tables for codec layout (max {MAX_TABLES})"
            ));
        }
        let prefix = self.next_prefix;
        let config = KvTableConfig::new(prefix, columns, primary_key_columns, index_specs)?;
        self.tables.push((name.into(), config));
        self.next_prefix = self.next_prefix.wrapping_add(1);
        Ok(self)
    }

    pub fn orders_table(
        self,
        table_name: impl Into<String>,
        index_specs: Vec<IndexSpec>,
    ) -> Result<Self, String> {
        self.table(
            table_name,
            vec![
                TableColumnConfig::new("region", DataType::Utf8, false),
                TableColumnConfig::new("customer_id", DataType::Int64, false),
                TableColumnConfig::new("order_id", DataType::Int64, false),
                TableColumnConfig::new("amount_cents", DataType::Int64, false),
                TableColumnConfig::new("status", DataType::Utf8, false),
            ],
            vec!["order_id".to_string()],
            index_specs,
        )
    }

    /// Create a table with a versioned composite primary key.
    ///
    /// The entity column and version column (UInt64) together form the
    /// composite primary key. The entity can be any supported primary-key
    /// type, including variable-length logical keys encoded through the
    /// crate's ordered variable-length `Utf8` mapping.
    ///
    /// Versions sort
    /// numerically via big-endian encoding, so a reverse range scan
    /// from `(entity, V)` downward with LIMIT 1 yields the latest
    /// version <= V. See `examples/versioned_kv.rs` for the basic
    /// query pattern plus an immutable-friendly companion watermark
    /// table pattern for out-of-order batch uploads.
    pub fn table_versioned(
        self,
        name: impl Into<String>,
        columns: Vec<TableColumnConfig>,
        entity_column: impl Into<String>,
        version_column: impl Into<String>,
        index_specs: Vec<IndexSpec>,
    ) -> Result<Self, String> {
        let entity = entity_column.into();
        let version = version_column.into();
        self.table(name, columns, vec![entity, version], index_specs)
    }

    pub fn table_count(&self) -> usize {
        self.tables.len()
    }

    pub(crate) fn client(&self) -> &StoreClient {
        &self.client
    }

    pub(crate) fn tables(&self) -> &[(String, KvTableConfig)] {
        &self.tables
    }

    pub fn register_all(self, ctx: &SessionContext) -> DataFusionResult<()> {
        register_kv_optimizers(ctx);
        for (name, config) in &self.tables {
            register_kv_table(ctx, name, self.client.clone(), config.clone())?;
        }
        Ok(())
    }

    pub fn batch_writer(&self) -> BatchWriter {
        BatchWriter::new(self.client.clone(), &self.tables)
    }

    /// Backfill secondary index entries after adding new index specs.
    ///
    /// `previous_index_specs` must represent the index list used when existing
    /// rows were written. The current schema's index list must be an append-only
    /// extension of that list (same order/layout for existing indexes, with new
    /// indexes only added at the tail).
    ///
    /// Operational ordering requirement: start writing new rows with the new
    /// index specs before backfilling historical rows, or rows written during
    /// the backfill window may be missing from the new index.
    pub async fn backfill_added_indexes(
        &self,
        table_name: &str,
        previous_index_specs: &[IndexSpec],
    ) -> DataFusionResult<IndexBackfillReport> {
        self.backfill_added_indexes_with_options(
            table_name,
            previous_index_specs,
            IndexBackfillOptions::default(),
        )
        .await
    }

    /// Backfill secondary index entries after adding new index specs, with
    /// configurable row page size for the full-scan read.
    pub async fn backfill_added_indexes_with_options(
        &self,
        table_name: &str,
        previous_index_specs: &[IndexSpec],
        options: IndexBackfillOptions,
    ) -> DataFusionResult<IndexBackfillReport> {
        self.backfill_added_indexes_with_options_and_progress(
            table_name,
            previous_index_specs,
            options,
            None,
        )
        .await
    }

    /// Backfill secondary index entries after adding new index specs, with
    /// configurable row page size for the full-scan read and an optional
    /// progress event channel.
    ///
    /// Progress events are emitted only after buffered ingest writes for the
    /// reported cursor are flushed, so `Progress.next_cursor` can be persisted
    /// and used to resume later.
    pub async fn backfill_added_indexes_with_options_and_progress(
        &self,
        table_name: &str,
        previous_index_specs: &[IndexSpec],
        options: IndexBackfillOptions,
        progress_tx: Option<&tokio::sync::mpsc::UnboundedSender<IndexBackfillEvent>>,
    ) -> DataFusionResult<IndexBackfillReport> {
        if options.row_batch_size == 0 {
            return Err(DataFusionError::Execution(
                "index backfill row_batch_size must be > 0".to_string(),
            ));
        }

        let config = self
            .tables
            .iter()
            .find(|(name, _)| name == table_name)
            .map(|(_, config)| config.clone())
            .ok_or_else(|| {
                DataFusionError::Execution(format!(
                    "unknown table '{table_name}' for index backfill"
                ))
            })?;

        let model = TableModel::from_config(&config)
            .map_err(|e| DataFusionError::Execution(format!("invalid table config: {e}")))?;
        let current_specs = model
            .resolve_index_specs(&config.index_specs)
            .map_err(|e| DataFusionError::Execution(format!("invalid index specs: {e}")))?;
        let previous_specs = model
            .resolve_index_specs(previous_index_specs)
            .map_err(|e| {
                DataFusionError::Execution(format!("invalid previous index specs: {e}"))
            })?;

        if previous_specs.len() > current_specs.len() {
            return Err(DataFusionError::Execution(format!(
                "table '{table_name}' previous index count ({}) exceeds current index count ({})",
                previous_specs.len(),
                current_specs.len()
            )));
        }
        for (idx, previous) in previous_specs.iter().enumerate() {
            let current = &current_specs[idx];
            if !resolved_index_layout_matches(previous, current) {
                return Err(DataFusionError::Execution(format!(
                    "table '{table_name}' index evolution must be append-only; index at position {} changed",
                    idx + 1
                )));
            }
        }

        let full_range = primary_key_prefix_range(model.table_prefix);
        let mut cursor = options
            .start_from_primary_key
            .unwrap_or_else(|| full_range.start.clone());
        if !model.primary_key_codec.matches(&cursor) {
            return Err(DataFusionError::Execution(
                "index backfill start_from_primary_key must use this table's primary-key prefix"
                    .to_string(),
            ));
        }
        if cursor < full_range.start || cursor > full_range.end {
            return Err(DataFusionError::Execution(
                "index backfill start_from_primary_key is outside table key range".to_string(),
            ));
        }

        let new_specs = current_specs[previous_specs.len()..].to_vec();
        if new_specs.is_empty() {
            let report = IndexBackfillReport::default();
            send_backfill_event(
                progress_tx,
                IndexBackfillEvent::Started {
                    table_name: table_name.to_string(),
                    indexes_backfilled: 0,
                    row_batch_size: options.row_batch_size,
                    start_cursor: cursor.clone(),
                },
            );
            send_backfill_event(progress_tx, IndexBackfillEvent::Completed { report });
            return Ok(report);
        }

        let mut report = IndexBackfillReport {
            scanned_rows: 0,
            indexes_backfilled: new_specs.len(),
            index_entries_written: 0,
        };
        let mut pending_keys = Vec::new();
        let mut pending_values: Vec<Bytes> = Vec::new();
        let session = self.client.create_session();
        let decode_pk_mask = vec![true; model.primary_key_kinds.len()];
        send_backfill_event(
            progress_tx,
            IndexBackfillEvent::Started {
                table_name: table_name.to_string(),
                indexes_backfilled: new_specs.len(),
                row_batch_size: options.row_batch_size,
                start_cursor: cursor.clone(),
            },
        );

        loop {
            let mut stream = session
                .range_stream(
                    &cursor,
                    &full_range.end,
                    options.row_batch_size,
                    options.row_batch_size,
                )
                .await
                .map_err(|e| DataFusionError::External(Box::new(e)))?;
            let mut last_key = None;
            while let Some(chunk) = stream
                .next_chunk()
                .await
                .map_err(|e| DataFusionError::External(Box::new(e)))?
            {
                for (base_key, base_value) in &chunk.rows {
                    last_key = Some(base_key.clone());
                    let Some(pk_values) = decode_primary_key_selected(
                        model.table_prefix,
                        base_key,
                        &model,
                        &decode_pk_mask,
                    ) else {
                        return Err(DataFusionError::Execution(format!(
                            "invalid primary key while backfilling index (key={})",
                            hex::encode(base_key)
                        )));
                    };
                    let archived = decode_stored_row(base_value).map_err(|e| {
                        DataFusionError::Execution(format!(
                            "invalid base row payload while backfilling index (key={}): {e}",
                            hex::encode(base_key)
                        ))
                    })?;
                    if archived.values.len() != model.columns.len() {
                        return Err(DataFusionError::Execution(format!(
                            "invalid base row payload while backfilling index (key={})",
                            hex::encode(base_key)
                        )));
                    }
                    report.scanned_rows += 1;

                    for spec in &new_specs {
                        let index_key = encode_secondary_index_key_from_parts(
                            model.table_prefix,
                            spec,
                            &model,
                            &pk_values,
                            &archived,
                        )?;
                        let index_value =
                            encode_secondary_index_value_from_archived(&archived, &model, spec)?;
                        pending_keys.push(index_key);
                        pending_values.push(index_value.into());
                        report.index_entries_written += 1;
                    }

                    if pending_keys.len() >= INDEX_BACKFILL_FLUSH_ENTRIES {
                        flush_ingest_batch(&self.client, &mut pending_keys, &mut pending_values)
                            .await?;
                    }
                }
            }
            let Some(last_key) = last_key else {
                break;
            };

            let next_cursor = if last_key >= full_range.end {
                None
            } else {
                next_key(&last_key)
            };
            if !pending_keys.is_empty() {
                flush_ingest_batch(&self.client, &mut pending_keys, &mut pending_values).await?;
            }
            send_backfill_event(
                progress_tx,
                IndexBackfillEvent::Progress {
                    scanned_rows: report.scanned_rows,
                    index_entries_written: report.index_entries_written,
                    last_scanned_primary_key: last_key,
                    next_cursor: next_cursor.clone(),
                },
            );

            if let Some(next) = next_cursor {
                cursor = next;
            } else {
                break;
            }
        }

        if !pending_keys.is_empty() {
            flush_ingest_batch(&self.client, &mut pending_keys, &mut pending_values).await?;
        }
        send_backfill_event(progress_tx, IndexBackfillEvent::Completed { report });
        Ok(report)
    }
}

fn register_kv_optimizers(ctx: &SessionContext) {
    let _ = ctx.remove_optimizer_rule("kv_aggregate_pushdown");
    ctx.add_optimizer_rule(Arc::new(KvAggregatePushdownRule::new()));

    let state_ref = ctx.state_ref();
    let mut state = state_ref.write();
    let mut rules = state
        .physical_optimizers()
        .iter()
        .filter(|rule| rule.name() != "kv_topk_sort_pushdown")
        .cloned()
        .collect::<Vec<_>>();
    let insert_at = rules
        .iter()
        .position(|rule| rule.name() == "SanityCheckPlan")
        .unwrap_or(rules.len());
    rules.insert(insert_at, Arc::new(KvTopKSortPushdownRule::new()));
    let new_state = SessionStateBuilder::new_from_existing(state.clone())
        .with_physical_optimizer_rules(rules)
        .build();
    *state = new_state;
}

pub(crate) fn send_backfill_event(
    progress_tx: Option<&tokio::sync::mpsc::UnboundedSender<IndexBackfillEvent>>,
    event: IndexBackfillEvent,
) {
    if let Some(tx) = progress_tx {
        let _ = tx.send(event);
    }
}

pub(crate) fn resolved_index_layout_matches(
    previous: &ResolvedIndexSpec,
    current: &ResolvedIndexSpec,
) -> bool {
    previous.id == current.id
        && previous.name == current.name
        && previous.layout == current.layout
        && previous.key_columns == current.key_columns
        && previous.value_column_mask == current.value_column_mask
        && previous.key_columns_width == current.key_columns_width
}

#[async_trait]
impl TableProvider for KvTable {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        self.model.schema.clone()
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    fn supports_filters_pushdown(
        &self,
        filters: &[&Expr],
    ) -> DataFusionResult<Vec<TableProviderFilterPushDown>> {
        Ok(filters
            .iter()
            .map(|expr| {
                if QueryPredicate::supports_filter(expr, &self.model) {
                    TableProviderFilterPushDown::Exact
                } else {
                    TableProviderFilterPushDown::Unsupported
                }
            })
            .collect())
    }

    async fn scan(
        &self,
        _state: &dyn Session,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        let predicate = QueryPredicate::from_filters(filters, &self.model);
        let projected_schema = match projection {
            Some(proj) => Arc::new(self.model.schema.project(proj)?),
            None => self.model.schema.clone(),
        };
        Ok(Arc::new(KvScanExec::new(
            self.client.clone(),
            self.model.clone(),
            self.index_specs.clone(),
            predicate,
            limit,
            projected_schema,
            projection.cloned(),
        )))
    }

    async fn insert_into(
        &self,
        _state: &dyn Session,
        input: Arc<dyn ExecutionPlan>,
        insert_op: InsertOp,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        self.schema()
            .logically_equivalent_names_and_types(&input.schema())?;
        if insert_op != InsertOp::Append {
            return Err(DataFusionError::NotImplemented(format!(
                "{insert_op} not implemented for kv table"
            )));
        }

        let sink = KvIngestSink::new(
            self.client.clone(),
            self.model.schema.clone(),
            self.model.clone(),
            self.index_specs.clone(),
        );
        Ok(Arc::new(DataSinkExec::new(input, Arc::new(sink), None)))
    }
}
