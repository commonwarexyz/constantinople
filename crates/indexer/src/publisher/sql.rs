//! SQL metadata row encoding shared by the combined publisher.

use crate::sql_schema::BLOCK_META_TABLE;
use exoware_sql::CellValue;

/// One row destined for a SQL metadata table.
///
/// `table` identifies the destination by name (one of the constants in
/// [`crate::sql_schema`]); `values` is the column-ordered cell list that
/// matches the schema declared by [`crate::sql_schema::build_meta_schema`].
pub struct SqlRow {
    pub table: &'static str,
    pub values: Vec<CellValue>,
}

/// Block-level metadata needed to build the `block_meta` row.
pub(crate) struct BlockMetaRow {
    pub height: u64,
    pub digest: [u8; 32],
    pub tx_count: u64,
    pub transactions_root: [u8; 32],
    pub transactions_tip: u64,
    pub view: u64,
    pub finalized_ts_micros: i64,
}

/// Encode the SQL rows for a finalized block.
///
/// Returns one `block_meta` row.
/// The `finalized_ts_micros` is captured at the moment the
/// block is delivered (wall-clock on this validator).
///
/// The `view` column is currently always `0` because the finalized hook does
/// not see consensus rounds. A future enrichment can pipe round/view metadata
/// through either by joining tables or by extending [`SqlRow`] with an update
/// path.
pub(crate) fn encode_sql_rows(block: BlockMetaRow) -> Vec<SqlRow> {
    vec![SqlRow {
        table: BLOCK_META_TABLE,
        values: vec![
            CellValue::UInt64(block.height),
            CellValue::FixedBinary(block.digest.to_vec()),
            CellValue::UInt64(block.tx_count),
            CellValue::FixedBinary(block.transactions_root.to_vec()),
            CellValue::UInt64(block.transactions_tip),
            CellValue::UInt64(block.view),
            CellValue::Timestamp(block.finalized_ts_micros),
        ],
    }]
}
