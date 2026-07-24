//! SQL row encoding shared by the combined publisher.

use crate::sql_schema::{
    ACCOUNT_META_TABLE, BLOCK_META_TABLE, COMMITTEE_META_TABLE, ELIGIBLE_PEER_TABLE,
    TX_ACTIVITY_TABLE, TX_META_TABLE,
};
use bytes::Bytes;
use commonware_consensus::types::Round;
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
    pub round: Round,
    pub finalized_ts_micros: i64,
}

/// Transaction row fields stored in `tx_meta`.
pub(crate) struct TxMetaRow {
    pub digest: [u8; 32],
    pub qmdb_location: u64,
    pub body: Bytes,
}

/// Transaction activity role stored in `tx_activity`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TxActivityRole {
    Sender,
    Receiver,
}

impl TxActivityRole {
    const fn as_u64(self) -> u64 {
        match self {
            Self::Sender => 0,
            Self::Receiver => 1,
        }
    }
}

/// Account-ordered transaction activity row.
pub(crate) struct TxActivityRow {
    pub account: [u8; 32],
    pub role: TxActivityRole,
    pub height: u64,
    pub index: u32,
    pub digest: [u8; 32],
    pub counterparty: [u8; 32],
    pub value: u64,
    pub nonce: u64,
}

/// Latest account row stored in `account_meta`.
pub(crate) struct AccountMetaRow {
    pub account: [u8; 32],
    pub balance: u64,
    pub nonce_base: u64,
    pub nonce_bitmap: u64,
    pub qmdb_location: u64,
}

/// Immutable eligible-peer catalog entry supplied by validator configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EligiblePeer {
    /// Raw 32-byte Ed25519 public key.
    pub public_key: [u8; 32],
    /// Configured network ingress address.
    pub address: String,
}

/// Materialized committee membership for one epoch.
pub(crate) struct CommitteeMetaRow {
    pub epoch: u64,
    pub members: Vec<u8>,
}

/// Encode the SQL rows for a finalized block.
///
/// Returns one `block_meta` row.
/// The `finalized_ts_micros` is captured at the moment the
/// block is delivered (wall-clock on this validator).
///
pub(crate) fn encode_block_meta_row(block: BlockMetaRow) -> SqlRow {
    SqlRow {
        table: BLOCK_META_TABLE,
        values: vec![
            CellValue::UInt64(block.height),
            CellValue::FixedBinary(block.digest.to_vec()),
            CellValue::UInt64(block.tx_count),
            CellValue::FixedBinary(block.transactions_root.to_vec()),
            CellValue::UInt64(block.transactions_tip),
            CellValue::UInt64(block.round.epoch().get()),
            CellValue::UInt64(block.round.view().get()),
            CellValue::Timestamp(block.finalized_ts_micros),
        ],
    }
}

/// Encode one finalized transaction row.
pub(crate) fn encode_tx_meta_row(tx: TxMetaRow) -> SqlRow {
    SqlRow {
        table: TX_META_TABLE,
        values: vec![
            CellValue::FixedBinary(tx.digest.to_vec()),
            CellValue::UInt64(tx.qmdb_location),
            CellValue::Binary(tx.body.to_vec()),
        ],
    }
}

/// Encode one account transaction activity row.
pub(crate) fn encode_tx_activity_row(tx: TxActivityRow) -> SqlRow {
    SqlRow {
        table: TX_ACTIVITY_TABLE,
        values: vec![
            CellValue::FixedBinary(tx.account.to_vec()),
            CellValue::UInt64(tx.height),
            CellValue::UInt64(u64::from(tx.index)),
            CellValue::UInt64(tx.role.as_u64()),
            CellValue::FixedBinary(tx.digest.to_vec()),
            CellValue::FixedBinary(tx.counterparty.to_vec()),
            CellValue::UInt64(tx.value),
            CellValue::UInt64(tx.nonce),
        ],
    }
}

/// Encode one latest account row.
pub(crate) fn encode_account_meta_row(account: AccountMetaRow) -> SqlRow {
    SqlRow {
        table: ACCOUNT_META_TABLE,
        values: vec![
            CellValue::FixedBinary(account.account.to_vec()),
            CellValue::UInt64(account.balance),
            CellValue::UInt64(account.nonce_base),
            CellValue::UInt64(account.nonce_bitmap),
            CellValue::UInt64(account.qmdb_location),
        ],
    }
}

/// Encode one materialized epoch committee row.
pub(crate) fn encode_committee_meta_row(committee: CommitteeMetaRow) -> SqlRow {
    SqlRow {
        table: COMMITTEE_META_TABLE,
        values: vec![
            CellValue::UInt64(committee.epoch),
            CellValue::Binary(committee.members),
        ],
    }
}

/// Encode one immutable eligible-peer catalog row.
pub(crate) fn encode_eligible_peer_row(peer: &EligiblePeer) -> SqlRow {
    SqlRow {
        table: ELIGIBLE_PEER_TABLE,
        values: vec![
            CellValue::FixedBinary(peer.public_key.to_vec()),
            CellValue::Utf8(peer.address.clone()),
        ],
    }
}
