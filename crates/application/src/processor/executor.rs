//! Transaction execution engine for simple transfers.

use super::state::{Overlay, State};
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

/// Filters invalid proposal candidates and executes the valid transfers.
pub fn propose<H, PK>(
    state: &State,
    transactions: Vec<VerifiedTransaction<PK, H>>,
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
    state: &State,
    transactions: &[VerifiedTransaction<PK, H>],
) -> Option<Changeset>
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

/// Applies a single transfer against the current account state.
///
/// Returns `false` if the sender has an incorrect nonce, insufficient balance,
/// or if the recipient balance would overflow.
fn execute_transfer<H, PK>(
    state: &mut Overlay<'_>,
    transaction: &VerifiedTransaction<PK, H>,
) -> bool
where
    H: Hasher,
    PK: PublicKey,
{
    let sender_address = transaction.signer();
    let recipient_address = transaction.value().to;
    let value = transaction.value().value.get();
    let nonce = transaction.value().nonce;

    let Some(sender) = state.get(&sender_address) else {
        return false;
    };
    if sender.nonce != nonce || sender.balance < value {
        return false;
    }
    let Some(next_nonce) = sender.nonce.checked_add(1) else {
        return false;
    };

    // Self-transfer: only bump the nonce.
    if sender_address == recipient_address {
        let sender = state.get_mut(&sender_address).expect("checked above");
        sender.nonce = next_nonce;
        return true;
    }

    let Some(recipient) = state.get(&recipient_address) else {
        return false;
    };
    let Some(recipient_balance) = recipient.balance.checked_add(value) else {
        return false;
    };

    let sender = state.get_mut(&sender_address).expect("checked above");
    sender.balance -= value;
    sender.nonce = next_nonce;

    let recipient = state.get_mut(&recipient_address).expect("checked above");
    recipient.balance = recipient_balance;

    true
}
