//! Block access list types.
//!
//! A [`BlockAccessList`] records:
//!
//! - the declared accesses for each transaction in the block
//! - the final persistent account and storage writes after block execution
//!
//! This lets verifiers preload state and schedule execution from the declared
//! per-transaction accesses, while also letting certified apply write the final
//! state directly without re-executing the block.
//!
//! Verification is intentionally strict:
//!
//! - each transaction slice in the BAL must exactly match the canonical
//!   observed access list for that transaction
//! - the final account and storage write vectors must exactly match the final
//!   committed state after execution

use crate::{Access, AccessList, Account, Address, Slot};
use commonware_codec::{EncodeSize, Error, RangeCfg, Read, ReadExt, Write};

/// Final account value written by block execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(any(feature = "arbitrary", test), derive(arbitrary::Arbitrary))]
pub struct AccountWrite {
    /// The written account.
    pub address: Address,
    /// The final account value.
    pub account: Account,
}

impl Write for AccountWrite {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.address.write(buf);
        self.account.write(buf);
    }
}

impl EncodeSize for AccountWrite {
    fn encode_size(&self) -> usize {
        self.address.encode_size() + self.account.encode_size()
    }
}

impl Read for AccountWrite {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            address: Address::read(buf)?,
            account: Account::read(buf)?,
        })
    }
}

/// Final storage value written by block execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(any(feature = "arbitrary", test), derive(arbitrary::Arbitrary))]
pub struct StorageWrite {
    /// The account that owns the slot.
    pub address: Address,
    /// The written storage slot key.
    pub slot: Slot,
    /// The final storage value.
    pub value: Slot,
}

impl Write for StorageWrite {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.address.write(buf);
        self.slot.write(buf);
        self.value.write(buf);
    }
}

impl EncodeSize for StorageWrite {
    fn encode_size(&self) -> usize {
        self.address.encode_size() + self.slot.encode_size() + self.value.encode_size()
    }
}

impl Read for StorageWrite {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            address: Address::read(buf)?,
            slot: Slot::read(buf)?,
            value: Slot::read(buf)?,
        })
    }
}

/// Codec configuration for decoding a [`BlockAccessList`].
#[derive(Debug, Clone)]
pub struct BlockAccessListCfg {
    /// Maximum number of per-transaction offsets.
    pub max_tx_offsets: RangeCfg<usize>,
    /// Maximum number of declared transaction accesses.
    pub max_tx_accesses: RangeCfg<usize>,
    /// Maximum number of final account writes.
    pub max_account_writes: RangeCfg<usize>,
    /// Maximum number of final storage writes.
    pub max_storage_writes: RangeCfg<usize>,
}

impl Default for BlockAccessListCfg {
    fn default() -> Self {
        Self {
            max_tx_offsets: RangeCfg::new(0..=usize::MAX),
            max_tx_accesses: RangeCfg::new(0..=usize::MAX),
            max_account_writes: RangeCfg::new(0..=usize::MAX),
            max_storage_writes: RangeCfg::new(0..=usize::MAX),
        }
    }
}

/// Declared accesses and final writes for one block.
///
/// `tx_offsets` partitions `tx_accesses` into one contiguous access slice per
/// transaction. Each slice is expected to use the same canonical ordering
/// produced by execution: account accesses first, then storage accesses, both
/// in lexicographic key order, with duplicate accesses collapsed to the
/// strongest observed mode.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockAccessList {
    /// Start offsets in `tx_accesses` for each transaction plus a trailing end.
    pub tx_offsets: Vec<u32>,
    /// Flattened declared accesses for all transactions.
    pub tx_accesses: Vec<Access>,
    /// Final account writes after the block commits.
    pub account_writes: Vec<AccountWrite>,
    /// Final storage writes after the block commits.
    pub storage_writes: Vec<StorageWrite>,
}

impl BlockAccessList {
    /// Creates a BAL from per-transaction accesses and final writes.
    ///
    /// Transaction accesses are flattened into `tx_accesses` and partitioned by
    /// `tx_offsets`.
    ///
    /// # Panics
    ///
    /// Panics if the flattened access list length exceeds `u32::MAX`.
    pub fn from_transactions(
        transaction_accesses: impl IntoIterator<Item = AccessList>,
        account_writes: Vec<AccountWrite>,
        storage_writes: Vec<StorageWrite>,
    ) -> Self {
        let mut tx_offsets = Vec::new();
        let mut tx_accesses = Vec::new();

        for accesses in transaction_accesses {
            if tx_offsets.is_empty() {
                tx_offsets.push(0);
            }

            tx_accesses.extend(accesses);
            tx_offsets.push(
                u32::try_from(tx_accesses.len()).expect("block access list exceeded u32::MAX"),
            );
        }

        Self {
            tx_offsets,
            tx_accesses,
            account_writes,
            storage_writes,
        }
    }

    /// Returns the number of transactions covered by this BAL.
    pub const fn transaction_count(&self) -> usize {
        self.tx_offsets.len().saturating_sub(1)
    }

    /// Returns whether the transaction access layout is internally consistent.
    ///
    /// This validates only the BAL's structural shape. It does not validate
    /// that the declared accesses or final writes are semantically correct for
    /// a given block.
    pub fn is_well_formed(&self, transaction_count: usize) -> bool {
        if transaction_count == 0 {
            return self.tx_offsets.is_empty() && self.tx_accesses.is_empty();
        }

        if self.tx_offsets.len() != transaction_count + 1 {
            return false;
        }

        if self.tx_offsets[0] != 0 {
            return false;
        }

        for window in self.tx_offsets.windows(2) {
            if window[0] > window[1] {
                return false;
            }
        }

        self.tx_offsets
            .last()
            .is_some_and(|last| usize::try_from(*last).ok() == Some(self.tx_accesses.len()))
    }

    /// Returns the declared accesses for `transaction_index`.
    ///
    /// # Panics
    ///
    /// Panics if the BAL is malformed.
    pub fn accesses_for_transaction(&self, transaction_index: usize) -> &[Access] {
        let start = usize::try_from(self.tx_offsets[transaction_index])
            .expect("tx offset must fit into usize");
        let end = usize::try_from(self.tx_offsets[transaction_index + 1])
            .expect("tx offset must fit into usize");
        &self.tx_accesses[start..end]
    }

    /// Iterates the declared accesses for each transaction.
    ///
    /// # Panics
    ///
    /// Panics if the BAL is malformed.
    pub fn transaction_accesses(&self) -> impl Iterator<Item = &[Access]> + '_ {
        self.tx_offsets.windows(2).map(|window| {
            let start = usize::try_from(window[0]).expect("tx offset must fit into usize");
            let end = usize::try_from(window[1]).expect("tx offset must fit into usize");
            &self.tx_accesses[start..end]
        })
    }
}

impl EncodeSize for BlockAccessList {
    fn encode_size(&self) -> usize {
        self.tx_offsets.encode_size()
            + self.tx_accesses.encode_size()
            + self.account_writes.encode_size()
            + self.storage_writes.encode_size()
    }
}

impl Write for BlockAccessList {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.tx_offsets.write(buf);
        self.tx_accesses.write(buf);
        self.account_writes.write(buf);
        self.storage_writes.write(buf);
    }
}

impl Read for BlockAccessList {
    type Cfg = BlockAccessListCfg;

    fn read_cfg(buf: &mut impl bytes::Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let tx_offsets_cfg = (cfg.max_tx_offsets, ());
        let tx_accesses_cfg = (cfg.max_tx_accesses, ());
        let account_writes_cfg = (cfg.max_account_writes, ());
        let storage_writes_cfg = (cfg.max_storage_writes, ());
        Ok(Self {
            tx_offsets: Vec::read_cfg(buf, &tx_offsets_cfg)?,
            tx_accesses: Vec::read_cfg(buf, &tx_accesses_cfg)?,
            account_writes: Vec::read_cfg(buf, &account_writes_cfg)?,
            storage_writes: Vec::read_cfg(buf, &storage_writes_cfg)?,
        })
    }
}

#[cfg(any(feature = "arbitrary", test))]
impl arbitrary::Arbitrary<'_> for BlockAccessList {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            tx_offsets: u.arbitrary()?,
            tx_accesses: u.arbitrary()?,
            account_writes: u.arbitrary()?,
            storage_writes: u.arbitrary()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, Encode, FixedSize};
    use commonware_cryptography::Digest;

    #[test]
    fn block_access_list_codec_roundtrip() {
        let bal = BlockAccessList {
            tx_offsets: vec![0, 2],
            tx_accesses: vec![
                Access::Account(Address::EMPTY, crate::AccessMode::Read),
                Access::Storage(
                    Address::EMPTY,
                    Slot::from([3; Slot::SIZE]),
                    crate::AccessMode::Write,
                ),
            ],
            account_writes: vec![AccountWrite {
                address: Address::EMPTY,
                account: Account {
                    balance: 7,
                    nonce: 9,
                },
            }],
            storage_writes: vec![StorageWrite {
                address: Address::EMPTY,
                slot: Slot::from([5; Slot::SIZE]),
                value: Slot::from([6; Slot::SIZE]),
            }],
        };

        let encoded = bal.encode();
        let decoded = BlockAccessList::decode_cfg(encoded.as_ref(), &BlockAccessListCfg::default())
            .expect("bal should decode");
        assert_eq!(decoded, bal);
    }

    #[test]
    fn well_formed_bal_requires_matching_offsets() {
        let bal = BlockAccessList {
            tx_offsets: vec![0, 2, 3],
            tx_accesses: vec![
                Access::Account(Address::EMPTY, crate::AccessMode::Read),
                Access::Account(Address::EMPTY, crate::AccessMode::Write),
                Access::Storage(
                    Address::EMPTY,
                    Slot::from([1; Slot::SIZE]),
                    crate::AccessMode::Read,
                ),
            ],
            ..BlockAccessList::default()
        };

        assert!(bal.is_well_formed(2));
        assert!(!bal.is_well_formed(1));
    }

    #[test]
    fn from_transactions_preserves_transaction_boundaries() {
        let first = vec![Access::Account(Address::EMPTY, crate::AccessMode::Read)];
        let second = vec![
            Access::Account(Address::EMPTY, crate::AccessMode::Write),
            Access::Storage(
                Address::EMPTY,
                Slot::from([1; Slot::SIZE]),
                crate::AccessMode::Read,
            ),
        ];

        let bal = BlockAccessList::from_transactions(
            vec![first.clone(), second.clone()],
            Vec::new(),
            Vec::new(),
        );

        assert_eq!(bal.tx_offsets, vec![0, 1, 3]);
        assert_eq!(bal.accesses_for_transaction(0), first.as_slice());
        assert_eq!(bal.accesses_for_transaction(1), second.as_slice());
        assert!(
            bal.transaction_accesses()
                .zip([first.as_slice(), second.as_slice()])
                .all(|(actual, expected)| actual == expected)
        );
    }
}
