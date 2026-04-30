//! Transaction execution engine for simple transfers.

use super::state::{Overlay, State};
use commonware_codec::types::lazy::Lazy;
use commonware_cryptography::{Hasher, PublicKey};
use constantinople_primitives::{Account, AccountKey, SignedTransaction};

/// Deterministic account writes produced by execution.
pub type Changeset<PK> = Vec<(AccountKey<PK>, Account)>;

/// Transfer data with account keys already prepared for execution.
pub struct Transfer<'a, PK: PublicKey> {
    /// Account sending funds and consuming a nonce.
    pub sender: &'a AccountKey<PK>,
    /// Account receiving funds.
    pub recipient: &'a AccountKey<PK>,
    /// Amount to move from sender to recipient.
    pub value: u64,
    /// Expected sender nonce.
    pub nonce: u64,
}

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
    let overlay_capacity = overlay_capacity(state, transactions.len());
    let mut overlay = Overlay::with_capacity(state, overlay_capacity);
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
    let mut overlay = Overlay::with_capacity(state, overlay_capacity(state, transactions.len()));

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
    signers: &[AccountKey<PK>],
) -> Option<Changeset<PK>>
where
    H: Hasher,
    PK: PublicKey,
{
    assert_eq!(
        transactions.len(),
        signers.len(),
        "transactions and cached signer keys must have the same length",
    );

    execute_transfers(
        state,
        transactions.len(),
        transactions
            .iter()
            .zip(signers)
            .map(|(transaction, signer)| {
                let transfer = transaction.get()?.value();
                Some(Transfer {
                    sender: signer,
                    recipient: &transfer.to,
                    value: transfer.value.get(),
                    nonce: transfer.nonce,
                })
            }),
    )
}

/// Executes transfers whose account keys and scalar fields are already prepared.
pub fn execute_transfers<'a, PK, I>(
    state: &State<PK>,
    transfer_count: usize,
    transfers: I,
) -> Option<Changeset<PK>>
where
    PK: PublicKey,
    I: IntoIterator<Item = Option<Transfer<'a, PK>>>,
{
    let mut overlay = Overlay::with_capacity(state, overlay_capacity(state, transfer_count));

    for transfer in transfers {
        let transfer = transfer?;
        if !execute_transfer_parts(
            &mut overlay,
            transfer.sender,
            transfer.recipient,
            transfer.value,
            transfer.nonce,
        ) {
            return None;
        }
    }

    Some(overlay.into_changeset())
}

/// Returns an upper bound for accounts modified by a batch.
fn overlay_capacity<PK>(state: &State<PK>, transaction_count: usize) -> usize
where
    PK: PublicKey,
{
    state.len().min(transaction_count.saturating_mul(2))
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
    let transfer = transaction.value();
    let Some(sender_key) = transfer.sender().map(AccountKey::from_public_key) else {
        return false;
    };
    execute_transfer_with_sender(state, transaction, &sender_key)
}

fn execute_transfer_with_sender<H, PK>(
    state: &mut Overlay<'_, PK>,
    transaction: &SignedTransaction<PK, H>,
    sender_key: &AccountKey<PK>,
) -> bool
where
    H: Hasher,
    PK: PublicKey,
{
    let transfer = transaction.value();
    execute_transfer_parts(
        state,
        sender_key,
        &transfer.to,
        transfer.value.get(),
        transfer.nonce,
    )
}

fn execute_transfer_parts<PK>(
    state: &mut Overlay<'_, PK>,
    sender_key: &AccountKey<PK>,
    recipient_key: &AccountKey<PK>,
    value: u64,
    nonce: u64,
) -> bool
where
    PK: PublicKey,
{
    let Some(mut sender) = state.get(sender_key) else {
        return false;
    };
    if sender.nonce != nonce || sender.balance < value {
        return false;
    }
    let Some(next_nonce) = sender.nonce.checked_add(1) else {
        return false;
    };

    sender.nonce = next_nonce;

    // Self-transfer: only bump the nonce.
    if sender_key == recipient_key {
        state.set(sender_key.clone(), sender);
        return true;
    }

    let Some(mut recipient) = state.get(recipient_key) else {
        return false;
    };
    let Some(recipient_balance) = recipient.balance.checked_add(value) else {
        return false;
    };

    sender.balance -= value;
    recipient.balance = recipient_balance;

    state.set(sender_key.clone(), sender);
    state.set(recipient_key.clone(), recipient);

    true
}
