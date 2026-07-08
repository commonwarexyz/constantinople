//! Registry of chain Store key namespaces.
//!
//! Every family of rows the indexer writes to the chain Store lives under its
//! own [`StoreKeyPrefix`], so families cannot collide even though they share
//! one physical Store. All prefix assignments live in this module: adding a
//! new family means claiming an unused value here.

use exoware_sdk::{PrefixedStoreClient, StoreClient, StoreKeyPrefix, StoreKeyPrefixError};

/// Number of high-order Store key bits reserved for namespace prefixes.
pub const STORE_PREFIX_RESERVED_BITS: u8 = 4;

/// Store namespace for QMDB account-state rows.
pub const STATE_QMDB_PREFIX_VALUE: u16 = 0x8;
/// Store namespace for QMDB transaction-hash rows.
pub const TRANSACTIONS_QMDB_PREFIX_VALUE: u16 = 0x9;
/// Store namespace for Simplex block and certificate rows.
pub const SIMPLEX_PREFIX_VALUE: u16 = 0xA;
/// Store namespace for SQL metadata rows.
pub const SQL_META_PREFIX_VALUE: u16 = 0xB;

/// Store namespace prefix for account-state QMDB rows.
pub fn state_qmdb_prefix() -> Result<StoreKeyPrefix, StoreKeyPrefixError> {
    StoreKeyPrefix::new(STORE_PREFIX_RESERVED_BITS, STATE_QMDB_PREFIX_VALUE)
}

/// Store namespace prefix for transaction-history QMDB rows.
pub fn transactions_qmdb_prefix() -> Result<StoreKeyPrefix, StoreKeyPrefixError> {
    StoreKeyPrefix::new(STORE_PREFIX_RESERVED_BITS, TRANSACTIONS_QMDB_PREFIX_VALUE)
}

/// Store namespace prefix for Simplex block and certificate rows.
pub fn simplex_prefix() -> Result<StoreKeyPrefix, StoreKeyPrefixError> {
    StoreKeyPrefix::new(STORE_PREFIX_RESERVED_BITS, SIMPLEX_PREFIX_VALUE)
}

/// Store namespace prefix for SQL metadata rows.
pub fn sql_meta_prefix() -> Result<StoreKeyPrefix, StoreKeyPrefixError> {
    StoreKeyPrefix::new(STORE_PREFIX_RESERVED_BITS, SQL_META_PREFIX_VALUE)
}

/// Clone `client` into the account-state QMDB namespace.
pub fn state_qmdb_client(client: &StoreClient) -> Result<PrefixedStoreClient, StoreKeyPrefixError> {
    Ok(PrefixedStoreClient::new(
        client.clone(),
        state_qmdb_prefix()?,
    ))
}

/// Clone `client` into the transaction-history QMDB namespace.
pub fn transactions_qmdb_client(
    client: &StoreClient,
) -> Result<PrefixedStoreClient, StoreKeyPrefixError> {
    Ok(PrefixedStoreClient::new(
        client.clone(),
        transactions_qmdb_prefix()?,
    ))
}

/// Clone `client` into the Simplex block and certificate namespace.
pub fn simplex_client(client: &StoreClient) -> Result<PrefixedStoreClient, StoreKeyPrefixError> {
    Ok(PrefixedStoreClient::new(client.clone(), simplex_prefix()?))
}

/// Clone `client` into the SQL metadata namespace.
pub fn sql_meta_client(client: &StoreClient) -> Result<PrefixedStoreClient, StoreKeyPrefixError> {
    Ok(PrefixedStoreClient::new(client.clone(), sql_meta_prefix()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every Store family must live under its own namespace prefix.
    #[test]
    fn store_namespaces_are_distinct() {
        let prefixes = [
            state_qmdb_prefix().expect("state prefix"),
            transactions_qmdb_prefix().expect("transaction prefix"),
            simplex_prefix().expect("simplex prefix"),
            sql_meta_prefix().expect("sql metadata prefix"),
        ];

        for prefix in &prefixes {
            assert_eq!(prefix.reserved_bits(), STORE_PREFIX_RESERVED_BITS);
        }
        for (i, a) in prefixes.iter().enumerate() {
            for b in &prefixes[i + 1..] {
                assert_ne!(a.prefix(), b.prefix());
            }
        }
    }
}
