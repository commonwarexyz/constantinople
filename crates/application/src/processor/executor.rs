//! Transaction execution engine for simple transfers.

use super::state::{AccountEffect, State, TransferEffect, WorkingState};
use commonware_cryptography::{Hasher, PublicKey};
use constantinople_primitives::{Account, Address, VerifiedTransaction};

/// Deterministic account writes produced by execution.
pub type Changeset = Vec<(Address, Account)>;

/// The final result of proposal-side filtering and execution.
#[derive(Debug)]
pub struct ProposalOutput<PK: PublicKey, H: Hasher> {
    /// Transactions that passed static validation and were included.
    pub valid: Vec<VerifiedTransaction<PK, H>>,
    /// Transactions that failed static validation and were excluded.
    pub invalid: Vec<VerifiedTransaction<PK, H>>,
    /// Persistent account writes produced by the included transactions.
    pub changeset: Changeset,
}

/// Resolved indices and values needed to execute a single transfer.
struct PreparedTransaction {
    sender_index: usize,
    recipient_index: usize,
    value: u64,
    nonce: u64,
}

/// Resolves a transaction's sender and recipient to their working-state indices.
///
/// Returns `None` if either the sender or recipient is missing from the state.
fn prepare<H, PK>(
    state: &WorkingState,
    transaction: &VerifiedTransaction<PK, H>,
) -> Option<PreparedTransaction>
where
    H: Hasher,
    PK: PublicKey,
{
    Some(PreparedTransaction {
        sender_index: state.index(transaction.signer())?,
        recipient_index: state.index(transaction.value().to)?,
        value: transaction.value().value.get(),
        nonce: transaction.value().nonce,
    })
}

/// Filters invalid proposal candidates and executes the valid transfers.
pub fn propose<H, PK>(
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
        let prepared = prepare(&state, &transaction)
            .expect("state must preload every sender and recipient before execution");

        let Some(effect) = execute_transfer(state.accounts(), &prepared) else {
            invalid.push(transaction);
            continue;
        };

        state.apply_transfer(effect);
        valid.push(transaction);
    }

    ProposalOutput {
        valid,
        invalid,
        changeset: state.changeset(),
    }
}

/// Executes block transactions and rejects the batch on the first invalid transfer.
///
/// Returns `None` if any transaction in the batch fails validation.
pub fn execute<H, PK>(
    state: State,
    transactions: &[VerifiedTransaction<PK, H>],
) -> Option<Changeset>
where
    H: Hasher,
    PK: PublicKey,
{
    let mut executed = WorkingState::new(state);

    for transaction in transactions {
        let prepared = prepare(&executed, transaction)?;
        let effect = execute_transfer(executed.accounts(), &prepared)?;
        executed.apply_transfer(effect);
    }

    Some(executed.changeset())
}

/// Applies a single prepared transfer against the current account state.
///
/// Returns `None` if the sender has an incorrect nonce, insufficient balance,
/// or if the recipient balance would overflow.
fn execute_transfer(
    accounts: &[Account],
    transaction: &PreparedTransaction,
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
