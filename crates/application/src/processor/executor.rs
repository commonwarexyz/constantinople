//! Transaction execution engine for simple transfers.

use super::state::{AccountEffect, State, TransferEffect, WorkingState};
use commonware_cryptography::{Hasher, PublicKey};
use constantinople_primitives::{Account, Address, VerifiedTransaction};
use std::collections::BTreeMap;

/// The final result of verifier-side execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutput {
    /// Persistent account writes produced by execution.
    pub changeset: BTreeMap<Address, Account>,
}

/// The final result of proposal-side filtering and execution.
#[derive(Debug)]
pub struct ProposalOutput<PK: PublicKey, H: Hasher> {
    /// Transactions that passed static validation and were included.
    pub valid: Vec<VerifiedTransaction<PK, H>>,
    /// Transactions that failed static validation and were excluded.
    pub invalid: Vec<VerifiedTransaction<PK, H>>,
    /// Persistent account writes produced by the included transactions.
    pub changeset: BTreeMap<Address, Account>,
}

/// Executes transfer-only transactions.
pub struct Processor;

impl core::fmt::Debug for Processor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Processor").finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct PreparedTransaction<Tx> {
    transaction: Tx,
    sender_index: usize,
    recipient_index: usize,
    value: u64,
    nonce: u64,
}

impl<'a, PK, H> PreparedTransaction<&'a VerifiedTransaction<PK, H>>
where
    PK: PublicKey,
    H: Hasher,
{
    fn from_borrowed(
        state: &WorkingState,
        transaction: &'a VerifiedTransaction<PK, H>,
    ) -> Option<Self> {
        Some(Self {
            transaction,
            sender_index: state.index(transaction.signer())?,
            recipient_index: state.index(transaction.value().to)?,
            value: transaction.value().value.get(),
            nonce: transaction.value().nonce,
        })
    }
}

impl<PK, H> PreparedTransaction<VerifiedTransaction<PK, H>>
where
    PK: PublicKey,
    H: Hasher,
{
    fn from_owned(state: &WorkingState, transaction: VerifiedTransaction<PK, H>) -> Option<Self> {
        Some(Self {
            sender_index: state.index(transaction.signer())?,
            recipient_index: state.index(transaction.value().to)?,
            value: transaction.value().value.get(),
            nonce: transaction.value().nonce,
            transaction,
        })
    }
}

impl Processor {
    /// Creates a processor.
    pub const fn new() -> Self {
        Self
    }

    /// Filters invalid proposal candidates and executes the valid transfers.
    pub fn propose<H, PK>(
        &self,
        state: State,
        transactions: Vec<VerifiedTransaction<PK, H>>,
    ) -> ProposalOutput<PK, H>
    where
        H: Hasher,
        PK: PublicKey,
    {
        let mut state = WorkingState::new(state);
        let mut valid = Vec::with_capacity(transactions.len());
        let mut invalid = Vec::new();

        for transaction in transactions {
            let prepared = PreparedTransaction::from_owned(&state, transaction)
                .expect("state must preload every sender and recipient before execution");

            let Some(effect) = self.execute_prepared_transaction(state.accounts(), &prepared)
            else {
                invalid.push(prepared.transaction);
                continue;
            };

            state.apply_transfer(effect);
            valid.push(prepared.transaction);
        }

        ProposalOutput {
            valid,
            invalid,
            changeset: state.changeset(),
        }
    }

    /// Executes block transactions and rejects the batch on the first invalid transfer.
    pub fn execute<H, PK>(
        &self,
        state: State,
        transactions: &[VerifiedTransaction<PK, H>],
    ) -> Option<ExecutionOutput>
    where
        H: Hasher,
        PK: PublicKey,
    {
        let mut executed = WorkingState::new(state);

        for transaction in transactions {
            let prepared = PreparedTransaction::from_borrowed(&executed, transaction)?;
            let effect = self.execute_prepared_transaction(executed.accounts(), &prepared)?;
            executed.apply_transfer(effect);
        }

        Some(ExecutionOutput {
            changeset: executed.changeset(),
        })
    }

    fn execute_prepared_transaction<Tx>(
        &self,
        accounts: &[Account],
        transaction: &PreparedTransaction<Tx>,
    ) -> Option<TransferEffect> {
        let sender_account = accounts[transaction.sender_index];
        if sender_account.nonce != transaction.nonce || sender_account.balance < transaction.value {
            return None;
        }

        let next_nonce = sender_account.nonce.checked_add(1)?;
        let sender = AccountEffect {
            index: transaction.sender_index,
            account: Account {
                balance: if transaction.sender_index == transaction.recipient_index {
                    sender_account.balance
                } else {
                    sender_account.balance - transaction.value
                },
                nonce: next_nonce,
            },
        };

        if transaction.sender_index == transaction.recipient_index {
            return Some(TransferEffect {
                sender,
                recipient: None,
            });
        }

        let recipient_account = accounts[transaction.recipient_index];
        let recipient_balance = recipient_account.balance.checked_add(transaction.value)?;

        Some(TransferEffect {
            sender,
            recipient: Some(AccountEffect {
                index: transaction.recipient_index,
                account: Account {
                    balance: recipient_balance,
                    nonce: recipient_account.nonce,
                },
            }),
        })
    }
}
