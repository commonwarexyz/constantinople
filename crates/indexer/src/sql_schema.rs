//! Metadata-store schema for the SQL streaming path.
//!
//! Constantinople fans every finalized block out across complementary storage
//! paths:
//!
//! - **Simplex block/certificate storage** — certified headers, full
//!   `{ header, body }` block envelopes by digest, and finalization indexes.
//!   Height/latest block reads start with a certified header and only fetch the
//!   body when needed.
//! - **Metadata and lookup storage (SQL)** — columnar tables registered onto
//!   the same `StoreClient` via [`KvSchema`]. The `block_meta` table is what
//!   the explorer subscribes to over the `store.sql.v1.Service` `Subscribe`
//!   RPC. `tx_meta` stores one row per finalized transaction with proof and
//!   body data. `tx_activity` stores one account-ordered row for each sender
//!   and receiver side of a transaction. `account_meta` stores the latest
//!   indexed account state plus its QMDB operation location.
//!
//! The string constants in this module are intentionally `pub` so that
//! external consumers (the explorer and the SQL CLI) can hard-code the
//! exact same identifiers without an out-of-band agreement.

use datafusion::arrow::datatypes::{DataType, TimeUnit};
use exoware_sdk::StoreClient;
use exoware_sql::{KvSchema, TableColumnConfig};

/// Name of the SQL table that the explorer subscribes to.
pub const BLOCK_META_TABLE: &str = "block_meta";

/// Name of the SQL table that records one row per finalized transaction.
pub const TX_META_TABLE: &str = "tx_meta";
/// Name of the SQL table that indexes account transaction activity.
pub const TX_ACTIVITY_TABLE: &str = "tx_activity";
/// Name of the SQL table that records the latest indexed account state.
pub const ACCOUNT_META_TABLE: &str = "account_meta";

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

/// `tx_meta`: 32-byte transaction digest, fixed-size binary.
pub const TX_META_DIGEST: &str = "tx_digest";
/// `tx_meta`: transaction-hash QMDB operation location for this digest.
pub const TX_META_QMDB_LOCATION: &str = "qmdb_location";
/// `tx_meta`: encoded signed transaction bytes as lowercase hex.
pub const TX_META_BODY_HEX: &str = "body_hex";

// ---------- tx_activity columns ----------

/// `tx_activity`: active account key (primary key first column).
pub const TX_ACTIVITY_ACCOUNT: &str = "account";
/// `tx_activity`: finalized block height.
pub const TX_ACTIVITY_HEIGHT: &str = "height";
/// `tx_activity`: transaction index within the finalized block.
pub const TX_ACTIVITY_INDEX: &str = "index";
/// `tx_activity`: role of this account in the transaction (`0` sender, `1` receiver).
pub const TX_ACTIVITY_ROLE: &str = "role";
/// `tx_activity`: 32-byte transaction digest, fixed-size binary.
pub const TX_ACTIVITY_DIGEST: &str = "tx_digest";
/// `tx_activity`: other account involved in the transfer.
pub const TX_ACTIVITY_COUNTERPARTY: &str = "counterparty";
/// `tx_activity`: transfer value.
pub const TX_ACTIVITY_VALUE: &str = "value";
/// `tx_activity`: sender nonce.
pub const TX_ACTIVITY_NONCE: &str = "nonce";

// ---------- account_meta columns ----------

/// `account_meta`: account key (primary key), fixed-size binary.
pub const ACCOUNT_META_ACCOUNT: &str = "account";
/// `account_meta`: indexed account balance.
pub const ACCOUNT_META_BALANCE: &str = "balance";
/// `account_meta`: indexed account nonce.
pub const ACCOUNT_META_NONCE: &str = "nonce";
/// `account_meta`: account-state QMDB operation location.
pub const ACCOUNT_META_QMDB_LOCATION: &str = "qmdb_location";

/// Build the metadata-store [`KvSchema`] used by the SQL streaming path.
///
/// The returned schema declares all metadata tables on top of the supplied
/// [`StoreClient`]. Callers can either:
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
                TableColumnConfig::new(TX_META_DIGEST, DataType::FixedSizeBinary(32), false),
                TableColumnConfig::new(TX_META_QMDB_LOCATION, DataType::UInt64, false),
                TableColumnConfig::new(TX_META_BODY_HEX, DataType::Utf8, false),
            ],
            vec![TX_META_DIGEST.to_string()],
            vec![],
        )
        .and_then(|schema| {
            schema.table(
                TX_ACTIVITY_TABLE,
                vec![
                    TableColumnConfig::new(
                        TX_ACTIVITY_ACCOUNT,
                        DataType::FixedSizeBinary(32),
                        false,
                    ),
                    TableColumnConfig::new(TX_ACTIVITY_HEIGHT, DataType::UInt64, false),
                    TableColumnConfig::new(TX_ACTIVITY_INDEX, DataType::UInt64, false),
                    TableColumnConfig::new(TX_ACTIVITY_ROLE, DataType::UInt64, false),
                    TableColumnConfig::new(
                        TX_ACTIVITY_DIGEST,
                        DataType::FixedSizeBinary(32),
                        false,
                    ),
                    TableColumnConfig::new(
                        TX_ACTIVITY_COUNTERPARTY,
                        DataType::FixedSizeBinary(32),
                        false,
                    ),
                    TableColumnConfig::new(TX_ACTIVITY_VALUE, DataType::UInt64, false),
                    TableColumnConfig::new(TX_ACTIVITY_NONCE, DataType::UInt64, false),
                ],
                vec![
                    TX_ACTIVITY_ACCOUNT.to_string(),
                    TX_ACTIVITY_HEIGHT.to_string(),
                    TX_ACTIVITY_INDEX.to_string(),
                    TX_ACTIVITY_ROLE.to_string(),
                ],
                vec![],
            )
        })
        .and_then(|schema| {
            schema.table(
                ACCOUNT_META_TABLE,
                vec![
                    TableColumnConfig::new(
                        ACCOUNT_META_ACCOUNT,
                        DataType::FixedSizeBinary(32),
                        false,
                    ),
                    TableColumnConfig::new(ACCOUNT_META_BALANCE, DataType::UInt64, false),
                    TableColumnConfig::new(ACCOUNT_META_NONCE, DataType::UInt64, false),
                    TableColumnConfig::new(ACCOUNT_META_QMDB_LOCATION, DataType::UInt64, false),
                ],
                vec![ACCOUNT_META_ACCOUNT.to_string()],
                vec![],
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::prelude::SessionContext;

    /// `build_meta_schema` must register all metadata tables onto a fresh
    /// `SessionContext` without error.
    #[tokio::test]
    async fn schema_registers_into_session_context() {
        let client = StoreClient::new("http://127.0.0.1:0");
        let schema = build_meta_schema(client).expect("build schema");
        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        // All tables must be visible to the catalog after registration.
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
        assert!(
            tables.iter().any(|t| t == TX_ACTIVITY_TABLE),
            "tx_activity missing: {tables:?}"
        );
        assert!(
            tables.iter().any(|t| t == ACCOUNT_META_TABLE),
            "account_meta missing: {tables:?}"
        );
    }

    /// The string constants must remain stable so the explorer can rely on
    /// them without an out-of-band agreement.
    #[test]
    fn table_and_column_names_are_stable() {
        assert_eq!(BLOCK_META_TABLE, "block_meta");
        assert_eq!(TX_META_TABLE, "tx_meta");
        assert_eq!(TX_ACTIVITY_TABLE, "tx_activity");
        assert_eq!(ACCOUNT_META_TABLE, "account_meta");
        assert_eq!(BLOCK_META_HEIGHT, "height");
        assert_eq!(BLOCK_META_DIGEST, "digest");
        assert_eq!(BLOCK_META_TX_COUNT, "tx_count");
        assert_eq!(BLOCK_META_TRANSACTIONS_ROOT, "transactions_root");
        assert_eq!(BLOCK_META_TRANSACTIONS_TIP, "transactions_tip");
        assert_eq!(BLOCK_META_VIEW, "view");
        assert_eq!(BLOCK_META_FINALIZED_TS, "finalized_ts");
        assert_eq!(TX_META_DIGEST, "tx_digest");
        assert_eq!(TX_META_QMDB_LOCATION, "qmdb_location");
        assert_eq!(TX_META_BODY_HEX, "body_hex");
        assert_eq!(TX_ACTIVITY_ACCOUNT, "account");
        assert_eq!(TX_ACTIVITY_HEIGHT, "height");
        assert_eq!(TX_ACTIVITY_INDEX, "index");
        assert_eq!(TX_ACTIVITY_ROLE, "role");
        assert_eq!(TX_ACTIVITY_DIGEST, "tx_digest");
        assert_eq!(TX_ACTIVITY_COUNTERPARTY, "counterparty");
        assert_eq!(TX_ACTIVITY_VALUE, "value");
        assert_eq!(TX_ACTIVITY_NONCE, "nonce");
        assert_eq!(ACCOUNT_META_ACCOUNT, "account");
        assert_eq!(ACCOUNT_META_BALANCE, "balance");
        assert_eq!(ACCOUNT_META_NONCE, "nonce");
        assert_eq!(ACCOUNT_META_QMDB_LOCATION, "qmdb_location");
    }
}
