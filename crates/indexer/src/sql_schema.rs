//! Metadata-store schema for the SQL streaming path.
//!
//! Constantinople fans every finalized block out across two storage paths:
//!
//! - **Full storage (KV)** — `BLOCK`, `BLOCK_BY_H`, `TX`, `TX_BY_H`,
//!   `FINALIZED`, `NOTARIZED` rows in the existing exoware Stores. Anyone
//!   can fetch a `SignedTransaction` body or a QMDB proof by digest from
//!   this path.
//! - **Metadata streaming (SQL)** — two columnar tables registered onto
//!   the same `StoreClient` via [`KvSchema`]. The `block_meta` table is
//!   what the explorer subscribes to over the `store.sql.v1.Service`
//!   `Subscribe` RPC; the `tx_meta` table is written for future
//!   drill-down but has no consumer yet.
//!
//! The string constants in this module are intentionally `pub` so that
//! external consumers (the explorer and the SQL CLI) can hard-code the
//! exact same identifiers without an out-of-band agreement.

use datafusion::arrow::datatypes::{DataType, TimeUnit};
use exoware_sdk::StoreClient;
use exoware_sql::{IndexSpec, KvSchema, TableColumnConfig};

/// Name of the SQL table that the explorer subscribes to.
pub const BLOCK_META_TABLE: &str = "block_meta";

/// Name of the SQL table that records one row per finalized transaction.
pub const TX_META_TABLE: &str = "tx_meta";

// ---------- block_meta columns ----------

/// `block_meta`: finalized block height (primary key, big-endian sortable).
pub const BLOCK_META_HEIGHT: &str = "height";
/// `block_meta`: 32-byte block digest, fixed-size binary.
pub const BLOCK_META_DIGEST: &str = "digest";
/// `block_meta`: number of transactions contained in the block.
pub const BLOCK_META_TX_COUNT: &str = "tx_count";
/// `block_meta`: root of the transaction-hash QMDB operation log at this block.
pub const BLOCK_META_TRANSACTIONS_ROOT: &str = "transactions_root";
/// `block_meta`: latest transaction-hash QMDB operation location at this block.
pub const BLOCK_META_TRANSACTIONS_TIP: &str = "transactions_tip";
/// `block_meta`: simplex consensus view that finalized the block.
pub const BLOCK_META_VIEW: &str = "view";
/// `block_meta`: finalization timestamp in microseconds since the Unix epoch.
pub const BLOCK_META_FINALIZED_TS: &str = "finalized_ts";

// ---------- tx_meta columns ----------

/// `tx_meta`: containing block height (composite primary key, first column).
pub const TX_META_HEIGHT: &str = "height";
/// `tx_meta`: per-block transaction index (composite primary key, second column).
pub const TX_META_INDEX: &str = "index";
/// `tx_meta`: 32-byte transaction digest, fixed-size binary.
pub const TX_META_DIGEST: &str = "tx_digest";
/// `tx_meta`: transaction-hash QMDB operation location for this digest.
pub const TX_META_QMDB_LOCATION: &str = "qmdb_location";
/// `tx_meta`: secondary index used to resolve proof metadata by digest.
pub const TX_META_DIGEST_INDEX: &str = "tx_meta_by_digest";

/// Build the metadata-store [`KvSchema`] used by the SQL streaming path.
///
/// The returned schema declares both [`BLOCK_META_TABLE`] and
/// [`TX_META_TABLE`] on top of the supplied [`StoreClient`]. Callers can
/// either:
///
/// - Hand the schema to a fresh [`SessionContext`] via
///   [`KvSchema::register_all`] (the `exoware-sql` SQL server does this),
///   or
/// - Build a [`BatchWriter`] from it via [`KvSchema::batch_writer`] and
///   stream rows through `BatchWriter::insert` + `flush().await` (this is
///   what `crate::publisher::sql` does on every finalized block).
///
/// [`BatchWriter`]: exoware_sql::BatchWriter
/// [`SessionContext`]: datafusion::prelude::SessionContext
pub fn build_meta_schema(client: StoreClient) -> Result<KvSchema, String> {
    KvSchema::new(client)
        .table(
            BLOCK_META_TABLE,
            vec![
                TableColumnConfig::new(BLOCK_META_HEIGHT, DataType::UInt64, false),
                TableColumnConfig::new(BLOCK_META_DIGEST, DataType::FixedSizeBinary(32), false),
                TableColumnConfig::new(BLOCK_META_TX_COUNT, DataType::UInt64, false),
                TableColumnConfig::new(
                    BLOCK_META_TRANSACTIONS_ROOT,
                    DataType::FixedSizeBinary(32),
                    false,
                ),
                TableColumnConfig::new(BLOCK_META_TRANSACTIONS_TIP, DataType::UInt64, false),
                TableColumnConfig::new(BLOCK_META_VIEW, DataType::UInt64, false),
                TableColumnConfig::new(
                    BLOCK_META_FINALIZED_TS,
                    DataType::Timestamp(TimeUnit::Microsecond, None),
                    false,
                ),
            ],
            vec![BLOCK_META_HEIGHT.to_string()],
            vec![],
        )?
        .table(
            TX_META_TABLE,
            vec![
                TableColumnConfig::new(TX_META_HEIGHT, DataType::UInt64, false),
                TableColumnConfig::new(TX_META_INDEX, DataType::UInt64, false),
                TableColumnConfig::new(TX_META_DIGEST, DataType::FixedSizeBinary(32), false),
                TableColumnConfig::new(TX_META_QMDB_LOCATION, DataType::UInt64, false),
            ],
            vec![TX_META_HEIGHT.to_string(), TX_META_INDEX.to_string()],
            vec![
                IndexSpec::lexicographic(TX_META_DIGEST_INDEX, vec![TX_META_DIGEST.to_string()])?
                    .with_cover_columns(vec![TX_META_QMDB_LOCATION.to_string()]),
            ],
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::prelude::SessionContext;

    /// `build_meta_schema` must register both tables onto a fresh
    /// `SessionContext` without error.
    #[tokio::test]
    async fn schema_registers_into_session_context() {
        let client = StoreClient::new("http://127.0.0.1:0");
        let schema = build_meta_schema(client).expect("build schema");
        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        // Both tables must be visible to the catalog after registration.
        let tables = ctx
            .catalog("datafusion")
            .expect("default catalog")
            .schema("public")
            .expect("default schema")
            .table_names();
        assert!(
            tables.iter().any(|t| t == BLOCK_META_TABLE),
            "block_meta missing: {tables:?}"
        );
        assert!(
            tables.iter().any(|t| t == TX_META_TABLE),
            "tx_meta missing: {tables:?}"
        );
    }

    /// The string constants must remain stable so the explorer can rely on
    /// them without an out-of-band agreement.
    #[test]
    fn table_and_column_names_are_stable() {
        assert_eq!(BLOCK_META_TABLE, "block_meta");
        assert_eq!(TX_META_TABLE, "tx_meta");
        assert_eq!(BLOCK_META_HEIGHT, "height");
        assert_eq!(BLOCK_META_DIGEST, "digest");
        assert_eq!(BLOCK_META_TX_COUNT, "tx_count");
        assert_eq!(BLOCK_META_TRANSACTIONS_ROOT, "transactions_root");
        assert_eq!(BLOCK_META_TRANSACTIONS_TIP, "transactions_tip");
        assert_eq!(BLOCK_META_VIEW, "view");
        assert_eq!(BLOCK_META_FINALIZED_TS, "finalized_ts");
        assert_eq!(TX_META_HEIGHT, "height");
        assert_eq!(TX_META_INDEX, "index");
        assert_eq!(TX_META_DIGEST, "tx_digest");
        assert_eq!(TX_META_QMDB_LOCATION, "qmdb_location");
        assert_eq!(TX_META_DIGEST_INDEX, "tx_meta_by_digest");
    }
}
