//! Key-prefix allocation for the single Store the indexer shares across all of
//! its subsystems.
//!
//! Every subsystem co-located in that Store carves a distinct key prefix from
//! this table. This module is the single source of truth for the partition:
//! keeping all prefixes in one place lets the disjointness invariant be checked
//! at a glance (and in the test below). A uniform reserved width paired with
//! distinct slot values is pairwise disjoint by construction — no prefix is a
//! bit-prefix of another, so one subsystem's range scan can never observe
//! another's keys.
//!
//! Adding a co-located index means adding one entry here with a fresh value;
//! never reuse or change a slot.

use exoware_sdk::StoreKeyPrefix;

/// Reserved width shared by every prefix below. Uniform width plus distinct
/// slot values is what makes the prefixes pairwise disjoint.
const RESERVED_BITS: u8 = 4;

/// SQL metadata tables (`exoware-sql`).
pub const SQL_META: u16 = 0;
/// Simplex block and certificate artifacts (`exoware-simplex`).
pub const SIMPLEX_BLOCKS: u16 = 1;
/// Account-state QMDB operation log.
pub const QMDB_STATE: u16 = 4;
/// Transaction-history QMDB operation log.
pub const QMDB_TRANSACTIONS: u16 = 5;

fn prefix(slot: u16) -> StoreKeyPrefix {
    StoreKeyPrefix::new(RESERVED_BITS, slot).expect("slot value fits the reserved width")
}

/// Prefix for the SQL metadata tables.
pub fn sql_meta() -> StoreKeyPrefix {
    prefix(SQL_META)
}

/// Prefix for the Simplex block and certificate artifacts.
pub fn simplex_blocks() -> StoreKeyPrefix {
    prefix(SIMPLEX_BLOCKS)
}

/// Prefix for the account-state QMDB log.
pub fn qmdb_state() -> StoreKeyPrefix {
    prefix(QMDB_STATE)
}

/// Prefix for the transaction-history QMDB log.
pub fn qmdb_transactions() -> StoreKeyPrefix {
    prefix(QMDB_TRANSACTIONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_prefixes_are_pairwise_disjoint() {
        let all = [
            sql_meta(),
            simplex_blocks(),
            qmdb_state(),
            qmdb_transactions(),
        ];
        // Uniform reserved width + distinct slot values ⇒ pairwise disjoint.
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i == j {
                    continue;
                }
                assert_eq!(
                    a.reserved_bits(),
                    b.reserved_bits(),
                    "all prefixes must share one reserved width",
                );
                assert_ne!(a.prefix(), b.prefix(), "slots {i} and {j} collide");
            }
        }
    }
}
