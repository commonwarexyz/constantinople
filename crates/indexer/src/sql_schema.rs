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
//!   the SQL metadata namespace (see [`crate::namespaces`]) via [`KvSchema`].
//!   The `block_meta` table is what
//!   the explorer subscribes to over the `sql.v1.Service` `Subscribe`
//!   RPC. `tx_meta` stores one row per finalized transaction with its proof
//!   location and body data. `tx_activity` stores one account-ordered row for
//!   each sender and receiver side of a transaction. `account_meta` stores one
//!   row per account-state QMDB operation, keyed by account and operation
//!   location. Readers take the highest location for an account. Store keys
//!   are immutable, so a latest-value table keyed by account alone would
//!   rewrite keys with new values and readers would observe stale rows.
//!   A transaction's finalized height is derived from `block_meta`, which
//!   keeps the bulk Store commit at three SQL rows per transaction.
//!
//! The string constants in this module are intentionally `pub` so that
//! external consumers (the explorer and the SQL CLI) can hard-code the
//! exact same identifiers without an out-of-band agreement.

use commonware_cryptography::{Hasher as _, sha256::Sha256};
use datafusion::arrow::datatypes::{DataType, TimeUnit};
use exoware_sdk::PrefixedStoreClient;
use exoware_sql::{KvSchema, TableColumnConfig};

/// Name of the SQL table that the explorer subscribes to.
pub const BLOCK_META_TABLE: &str = "block_meta";

/// Name of the SQL table that records one row per finalized transaction.
pub const TX_META_TABLE: &str = "tx_meta";
/// Name of the SQL table that indexes account transaction activity.
pub const TX_ACTIVITY_TABLE: &str = "tx_activity";
/// Name of the SQL table that records one row per account-state QMDB operation.
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
/// `tx_meta`: encoded signed transaction bytes.
pub const TX_META_BODY: &str = "body";

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

/// `account_meta`: account key (primary key first column), fixed-size binary.
pub const ACCOUNT_META_ACCOUNT: &str = "account";
/// `account_meta`: indexed account balance.
pub const ACCOUNT_META_BALANCE: &str = "balance";
/// `account_meta`: indexed account nonce base.
pub const ACCOUNT_META_NONCE_BASE: &str = "nonce_base";
/// `account_meta`: indexed account run-ahead nonce bitmap.
pub const ACCOUNT_META_NONCE_BITMAP: &str = "nonce_bitmap";
/// `account_meta`: account-state QMDB operation location (primary key second column).
pub const ACCOUNT_META_QMDB_LOCATION: &str = "qmdb_location";

#[derive(Clone, Copy)]
enum SchemaDataType {
    UInt64,
    FixedBinary32,
    Binary,
    TimestampMicros,
}

impl SchemaDataType {
    const fn arrow(self) -> DataType {
        match self {
            Self::UInt64 => DataType::UInt64,
            Self::FixedBinary32 => DataType::FixedSizeBinary(32),
            Self::Binary => DataType::Binary,
            Self::TimestampMicros => DataType::Timestamp(TimeUnit::Microsecond, None),
        }
    }

    const fn fingerprint(self) -> &'static [u8] {
        match self {
            Self::UInt64 => b"uint64",
            Self::FixedBinary32 => b"fixed-binary-32",
            Self::Binary => b"binary",
            Self::TimestampMicros => b"timestamp-micros",
        }
    }
}

struct SchemaColumn {
    name: &'static str,
    data_type: SchemaDataType,
    nullable: bool,
}

struct SchemaTable {
    name: &'static str,
    columns: &'static [SchemaColumn],
    primary_key: &'static [&'static str],
}

const BLOCK_META_COLUMNS: &[SchemaColumn] = &[
    SchemaColumn {
        name: BLOCK_META_HEIGHT,
        data_type: SchemaDataType::UInt64,
        nullable: false,
    },
    SchemaColumn {
        name: BLOCK_META_DIGEST,
        data_type: SchemaDataType::FixedBinary32,
        nullable: false,
    },
    SchemaColumn {
        name: BLOCK_META_TX_COUNT,
        data_type: SchemaDataType::UInt64,
        nullable: false,
    },
    SchemaColumn {
        name: BLOCK_META_TRANSACTIONS_ROOT,
        data_type: SchemaDataType::FixedBinary32,
        nullable: false,
    },
    SchemaColumn {
        name: BLOCK_META_TRANSACTIONS_TIP,
        data_type: SchemaDataType::UInt64,
        nullable: false,
    },
    SchemaColumn {
        name: BLOCK_META_VIEW,
        data_type: SchemaDataType::UInt64,
        nullable: false,
    },
    SchemaColumn {
        name: BLOCK_META_FINALIZED_TS,
        data_type: SchemaDataType::TimestampMicros,
        nullable: false,
    },
];

const TX_META_COLUMNS: &[SchemaColumn] = &[
    SchemaColumn {
        name: TX_META_DIGEST,
        data_type: SchemaDataType::FixedBinary32,
        nullable: false,
    },
    SchemaColumn {
        name: TX_META_QMDB_LOCATION,
        data_type: SchemaDataType::UInt64,
        nullable: false,
    },
    SchemaColumn {
        name: TX_META_BODY,
        data_type: SchemaDataType::Binary,
        nullable: false,
    },
];

const TX_ACTIVITY_COLUMNS: &[SchemaColumn] = &[
    SchemaColumn {
        name: TX_ACTIVITY_ACCOUNT,
        data_type: SchemaDataType::FixedBinary32,
        nullable: false,
    },
    SchemaColumn {
        name: TX_ACTIVITY_HEIGHT,
        data_type: SchemaDataType::UInt64,
        nullable: false,
    },
    SchemaColumn {
        name: TX_ACTIVITY_INDEX,
        data_type: SchemaDataType::UInt64,
        nullable: false,
    },
    SchemaColumn {
        name: TX_ACTIVITY_ROLE,
        data_type: SchemaDataType::UInt64,
        nullable: false,
    },
    SchemaColumn {
        name: TX_ACTIVITY_DIGEST,
        data_type: SchemaDataType::FixedBinary32,
        nullable: false,
    },
    SchemaColumn {
        name: TX_ACTIVITY_COUNTERPARTY,
        data_type: SchemaDataType::FixedBinary32,
        nullable: false,
    },
    SchemaColumn {
        name: TX_ACTIVITY_VALUE,
        data_type: SchemaDataType::UInt64,
        nullable: false,
    },
    SchemaColumn {
        name: TX_ACTIVITY_NONCE,
        data_type: SchemaDataType::UInt64,
        nullable: false,
    },
];

const ACCOUNT_META_COLUMNS: &[SchemaColumn] = &[
    SchemaColumn {
        name: ACCOUNT_META_ACCOUNT,
        data_type: SchemaDataType::FixedBinary32,
        nullable: false,
    },
    SchemaColumn {
        name: ACCOUNT_META_BALANCE,
        data_type: SchemaDataType::UInt64,
        nullable: false,
    },
    SchemaColumn {
        name: ACCOUNT_META_NONCE_BASE,
        data_type: SchemaDataType::UInt64,
        nullable: false,
    },
    SchemaColumn {
        name: ACCOUNT_META_NONCE_BITMAP,
        data_type: SchemaDataType::UInt64,
        nullable: false,
    },
    SchemaColumn {
        name: ACCOUNT_META_QMDB_LOCATION,
        data_type: SchemaDataType::UInt64,
        nullable: false,
    },
];

const META_SCHEMA_TABLES: &[SchemaTable] = &[
    SchemaTable {
        name: BLOCK_META_TABLE,
        columns: BLOCK_META_COLUMNS,
        primary_key: &[BLOCK_META_HEIGHT],
    },
    SchemaTable {
        name: TX_META_TABLE,
        columns: TX_META_COLUMNS,
        primary_key: &[TX_META_DIGEST],
    },
    SchemaTable {
        name: TX_ACTIVITY_TABLE,
        columns: TX_ACTIVITY_COLUMNS,
        primary_key: &[
            TX_ACTIVITY_ACCOUNT,
            TX_ACTIVITY_HEIGHT,
            TX_ACTIVITY_INDEX,
            TX_ACTIVITY_ROLE,
        ],
    },
    SchemaTable {
        name: ACCOUNT_META_TABLE,
        columns: ACCOUNT_META_COLUMNS,
        primary_key: &[ACCOUNT_META_ACCOUNT, ACCOUNT_META_QMDB_LOCATION],
    },
];

/// Return the fingerprint of the metadata schema built by [`build_meta_schema`].
pub fn meta_schema_fingerprint() -> String {
    let mut hasher = Sha256::default();
    hasher.update(b"constantinople-indexer-meta-schema\0");
    for table in META_SCHEMA_TABLES {
        hasher.update(b"table\0");
        hasher.update(table.name.as_bytes());
        hasher.update(b"\0");
        for column in table.columns {
            hasher.update(b"column\0");
            hasher.update(column.name.as_bytes());
            hasher.update(b"\0");
            hasher.update(column.data_type.fingerprint());
            hasher.update(b"\0");
            hasher.update(&[u8::from(column.nullable)]);
        }
        for primary_key in table.primary_key {
            hasher.update(b"primary-key\0");
            hasher.update(primary_key.as_bytes());
            hasher.update(b"\0");
        }
    }
    let (_, fingerprint) = hasher.finalize();
    fingerprint.to_string()
}

/// Build the metadata-store [`KvSchema`] used by the SQL streaming path.
///
/// The returned schema declares all metadata tables on top of the supplied
/// [`PrefixedStoreClient`]. Callers can either:
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
pub fn build_meta_schema(client: PrefixedStoreClient) -> Result<KvSchema, String> {
    META_SCHEMA_TABLES
        .iter()
        .try_fold(KvSchema::new(client), |schema, table| {
            schema.table(
                table.name,
                table
                    .columns
                    .iter()
                    .map(|column| {
                        TableColumnConfig::new(
                            column.name,
                            column.data_type.arrow(),
                            column.nullable,
                        )
                    })
                    .collect(),
                table
                    .primary_key
                    .iter()
                    .map(|column| (*column).to_string())
                    .collect(),
                vec![],
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::prelude::SessionContext;

    #[test]
    fn schema_fingerprint_is_stable_hex() {
        let fingerprint = meta_schema_fingerprint();
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(fingerprint, meta_schema_fingerprint());
    }

    /// `build_meta_schema` must register all metadata tables onto a fresh
    /// `SessionContext` without error.
    #[tokio::test]
    async fn schema_registers_into_session_context() {
        let client = crate::namespaces::sql_meta_client(&exoware_sdk::StoreClient::new(
            "http://127.0.0.1:0",
        ))
        .expect("sql metadata client");
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

        let table = ctx.table(TX_META_TABLE).await.expect("tx_meta table");
        let fields = table.schema().fields();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].name(), TX_META_DIGEST);
        assert_eq!(fields[0].data_type(), &DataType::FixedSizeBinary(32));
        assert!(!fields[0].is_nullable());
        assert_eq!(fields[1].name(), TX_META_QMDB_LOCATION);
        assert_eq!(fields[1].data_type(), &DataType::UInt64);
        assert!(!fields[1].is_nullable());
        assert_eq!(fields[2].name(), TX_META_BODY);
        assert_eq!(fields[2].data_type(), &DataType::Binary);
        assert!(!fields[2].is_nullable());
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
        assert_eq!(TX_META_BODY, "body");
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
        assert_eq!(ACCOUNT_META_NONCE_BASE, "nonce_base");
        assert_eq!(ACCOUNT_META_NONCE_BITMAP, "nonce_bitmap");
        assert_eq!(ACCOUNT_META_QMDB_LOCATION, "qmdb_location");
    }
}
