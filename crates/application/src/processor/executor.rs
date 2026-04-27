//! Transaction execution engine for simple transfers.

use super::state::{Overlay, State};
use commonware_codec::types::lazy::Lazy;
use commonware_cryptography::{Hasher, PublicKey};
use constantinople_primitives::{Account, SignedTransaction};

/// Deterministic account writes produced by execution.
pub type Changeset<PK> = Vec<(PK, Account)>;

/// The final result of proposal-side filtering and execution.
#[derive(Debug)]
pub struct ProposalOutput<PK: PublicKey, H: Hasher> {
    /// Transactions that passed static validation and were included.
    pub valid: Vec<SignedTransaction<PK, H>>,
    /// Transactions that failed static validation and were excluded.
    pub invalid: Vec<SignedTransaction<PK, H>>,
    /// Persistent account writes produced by the included transactions.
    pub changeset: Changeset<PK>,
}

/// Filters invalid proposal candidates and executes the valid transfers.
pub fn propose<H, PK>(
    state: &State<PK>,
    transactions: Vec<SignedTransaction<PK, H>>,
) -> ProposalOutput<PK, H>
where
    H: Hasher,
    PK: PublicKey,
{
    let mut overlay = Overlay::new(state);
    let mut valid = Vec::with_capacity(transactions.len());
    let mut invalid = Vec::new();

    for transaction in transactions {
        if execute_transfer(&mut overlay, &transaction) {
            valid.push(transaction);
        } else {
            invalid.push(transaction);
        }
    }

    ProposalOutput {
        valid,
        invalid,
        changeset: overlay.into_changeset(),
    }
}

/// Executes block transactions and rejects the batch on the first invalid transfer.
///
/// Returns `None` if any transaction in the batch fails validation.
pub fn execute<H, PK>(
    state: &State<PK>,
    transactions: &[SignedTransaction<PK, H>],
) -> Option<Changeset<PK>>
where
    H: Hasher,
    PK: PublicKey,
{
    let mut overlay = Overlay::new(state);

    for transaction in transactions {
        if !execute_transfer(&mut overlay, transaction) {
            return None;
        }
    }

    Some(overlay.into_changeset())
}

/// Executes lazily decoded block transactions.
///
/// Returns `None` if any transaction fails to decode or execute.
pub fn execute_lazy<H, PK>(
    state: &State<PK>,
    transactions: &[Lazy<SignedTransaction<PK, H>>],
) -> Option<Changeset<PK>>
where
    H: Hasher,
    PK: PublicKey,
{
    let mut overlay = Overlay::new(state);

    for transaction in transactions {
        if !execute_transfer(&mut overlay, transaction.get()?) {
            return None;
        }
    }

    Some(overlay.into_changeset())
}

/// Applies a single transfer against the current account state.
///
/// Returns `false` if the sender has an incorrect nonce, insufficient balance,
/// or if the recipient balance would overflow.
fn execute_transfer<H, PK>(
    state: &mut Overlay<'_, PK>,
    transaction: &SignedTransaction<PK, H>,
) -> bool
where
    H: Hasher,
    PK: PublicKey,
{
    let Some(sender_key) = transaction.value().sender().cloned() else {
        return false;
    };
    let recipient_key = transaction.value().to.clone();
    let value = transaction.value().value.get();
    let nonce = transaction.value().nonce;

    let Some(sender) = state.get(&sender_key) else {
        return false;
    };
    if sender.nonce != nonce || sender.balance < value {
        return false;
    }
    let Some(next_nonce) = sender.nonce.checked_add(1) else {
        return false;
    };

    // Self-transfer: only bump the nonce.
    if sender_key == recipient_key {
        let sender = state.get_mut(&sender_key).expect("checked above");
        sender.nonce = next_nonce;
        return true;
    }

    let Some(recipient) = state.get(&recipient_key) else {
        return false;
    };
    let Some(recipient_balance) = recipient.balance.checked_add(value) else {
        return false;
    };

    let sender = state.get_mut(&sender_key).expect("checked above");
    sender.balance -= value;
    sender.nonce = next_nonce;

    let recipient = state.get_mut(&recipient_key).expect("checked above");
    recipient.balance = recipient_balance;

    true
}
