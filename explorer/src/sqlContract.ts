// The explorer's copy of the indexer's SQL and route contract
// (crates/indexer/src/sql_schema.rs and crates/indexer/src/lib.rs).
// tests/sqlFixtures.test.ts asserts everything here against the golden
// fixture the Rust side generates (crates/indexer/tests/sql_fixtures.rs), so
// renaming or renumbering on either side fails CI instead of breaking
// explorer queries at runtime.

// Routes the qmdb-indexer facade serves its operation logs under.
export const QMDB_STATE_ROUTE = '/state';
export const QMDB_TRANSACTIONS_ROUTE = '/transactions';

// Table names.
export const BLOCK_META_TABLE = 'block_meta';
export const TX_META_TABLE = 'tx_meta';
export const TX_ACTIVITY_TABLE = 'tx_activity';
export const ACCOUNT_META_TABLE = 'account_meta';

// block_meta columns (the subset the explorer reads).
export const BLOCK_META_HEIGHT = 'height';
export const BLOCK_META_DIGEST = 'digest';
export const BLOCK_META_TX_COUNT = 'tx_count';
export const BLOCK_META_TRANSFERS = 'transfers';
export const BLOCK_META_CHANNEL_OPENS = 'channel_opens';
export const BLOCK_META_CHANNEL_CLOSES = 'channel_closes';
export const BLOCK_META_CHANNEL_TIMEOUTS = 'channel_timeouts';
export const BLOCK_META_MINTS = 'mints';

// tx_meta columns.
export const TX_META_DIGEST = 'tx_digest';
export const TX_META_QMDB_LOCATION = 'qmdb_location';
export const TX_META_BODY_HEX = 'body_hex';

// tx_activity columns.
export const TX_ACTIVITY_ACCOUNT = 'account';
export const TX_ACTIVITY_HEIGHT = 'height';
export const TX_ACTIVITY_INDEX = 'index';
export const TX_ACTIVITY_ROLE = 'role';
export const TX_ACTIVITY_DIGEST = 'tx_digest';
export const TX_ACTIVITY_COUNTERPARTY = 'counterparty';
export const TX_ACTIVITY_VALUE = 'value';
export const TX_ACTIVITY_NONCE = 'nonce';
export const TX_ACTIVITY_KIND = 'kind';

// account_meta columns.
export const ACCOUNT_META_ACCOUNT = 'account';
export const ACCOUNT_META_BALANCE = 'balance';
export const ACCOUNT_META_NONCE_BASE = 'nonce_base';
export const ACCOUNT_META_NONCE_BITMAP = 'nonce_bitmap';
export const ACCOUNT_META_QMDB_LOCATION = 'qmdb_location';
export const ACCOUNT_META_DELETED = 'deleted';

// Numeric tx_activity values.
export const TX_ACTIVITY_ROLES = {
    sender: 0n,
    receiver: 1n,
} as const;
export const TX_ACTIVITY_KINDS = {
    transfer: 0n,
    channelOpen: 1n,
    channelClose: 2n,
    channelTimeout: 3n,
    mint: 4n,
} as const;
