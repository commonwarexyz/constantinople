//! Transfer settlement rules for the Constantinople account model.
//!
//! [`PreparedTransfer`] is the account-level view of one signed transaction. It implements
//! [`Transfer`], so a block body settles with [`commonware_glue::transfers`]: verifiers settle a
//! body as one batch with [`Plan`](transfers::Plan), and proposers choose a body with
//! [`Selection`](transfers::Selection). `consensus::execution` drives both against the state
//! database.
//!
//! A block settles against the accounts it starts from. Each sender consumes its transactions'
//! nonces in block order through [`Nonce::consume`](constantinople_primitives::Nonce::consume).
//! Every transfer debits its sender and credits its recipient by its value, even when they are the
//! same account. A sender's debits must fit the balance it held at the start of the block, so a
//! credit received in the block, including a self-transfer's, cannot fund a debit in the same
//! block. Every final balance must fit in a `u64`.
//!
//! An absent key reads as [`Account::default`], and settlement deletes a key whose account settles
//! to that default. No block settles a key to the default in a state that only settlement has
//! written since an empty genesis: a sender's consumed nonce differs from the default nonce, and
//! an account that has never sent holds at least the default balance, so its nonzero credits leave
//! it above that balance. Every key a block changes is therefore written, never deleted.

use commonware_cryptography::Hasher;
use commonware_glue::transfers::{self, Change, Transfer};
use commonware_storage::qmdb::any::batch::Slot;
use constantinople_primitives::{Account, AccountKey, SignedTransaction};

/// The account-level view of one transaction.
#[derive(Debug, Clone, Copy)]
pub struct PreparedTransfer {
    /// Sender account key.
    pub sender: AccountKey,
    /// Recipient account key.
    pub recipient: AccountKey,
    /// Amount transferred.
    pub value: u64,
    /// Sender nonce required by the transaction.
    pub nonce: u64,
}

/// Prepares one transaction for settlement, or returns `None` if its sender key does not decode.
pub fn prepare_transfer<H>(transaction: &SignedTransaction<H>) -> Option<PreparedTransfer>
where
    H: Hasher,
{
    let transfer = transaction.value();
    Some(PreparedTransfer {
        sender: AccountKey::from_public_key(transfer.sender_lazy().get()?),
        recipient: transfer.to,
        value: transfer.value.get(),
        nonce: transfer.nonce,
    })
}

/// A state account as [`commonware_glue::transfers`] settles it.
///
/// Settlement needs the account trait on the stored type, which this crate can only implement on
/// its own type. The wrapper has the layout of [`Account`], so converting staged reads and settled
/// slots reuses their buffers.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct TransferAccount(pub Account);

impl transfers::Account for TransferAccount {
    /// The nonce a transfer consumes.
    type Effect = u64;

    fn balance(&self) -> u64 {
        self.0.balance
    }

    fn set_balance(&mut self, balance: u64) {
        self.0.balance = balance;
    }

    fn apply(&mut self, nonce: u64) -> bool {
        self.0.nonce.consume(nonce)
    }
}

impl Transfer for PreparedTransfer {
    type Key = AccountKey;
    type Account = TransferAccount;

    /// The sender's change consumes the nonce and debits the value, and the recipient's change
    /// credits it. A self-transfer lists its sender twice, so both settle as one change that debits
    /// and credits the value.
    fn changes(&self) -> impl Iterator<Item = (&AccountKey, Change<u64>)> {
        [
            (
                &self.sender,
                Change::debit(self.value).with_effect(self.nonce),
            ),
            (&self.recipient, Change::credit(self.value)),
        ]
        .into_iter()
    }
}

/// Wraps staged account reads for settlement.
pub fn starting_accounts(reads: Vec<Option<Account>>) -> Vec<Option<TransferAccount>> {
    reads
        .into_iter()
        .map(|read| read.map(TransferAccount))
        .collect()
}

/// Unwraps settled slots for the state batch to merkleize.
pub fn account_slots(slots: Vec<Slot<TransferAccount>>) -> Vec<Slot<Account>> {
    slots
        .into_iter()
        .map(|slot| match slot {
            Slot::Keep => Slot::Keep,
            Slot::Put(TransferAccount(account)) => Slot::Put(account),
            Slot::Delete => Slot::Delete,
        })
        .collect()
}

#[cfg(test)]
mod tests;
