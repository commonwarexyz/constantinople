//! Transfer execution for the Constantinople account model.

use bytes::BytesMut;
use commonware_codec::{FixedSize as _, Write as _};
use commonware_cryptography::Hasher;
use constantinople_primitives::{Account, AccountKey, SignedTransaction, TransactionPublicKey};
use hashbrown::HashMap;

/// Fully loaded account state for one execution batch.
pub type State = HashMap<AccountKey, Account>;

/// Deterministic account writes produced by execution.
pub type Changeset = Vec<(AccountKey, Account)>;

/// Transfer data used by the executor.
#[derive(Debug, Clone)]
pub struct PreparedTransfer<H>
where
    H: Hasher,
{
    /// Sender account key.
    pub sender: AccountKey,
    /// Recipient account key.
    pub recipient: AccountKey,
    /// Amount transferred.
    pub value: u64,
    /// Sender nonce required by the transaction.
    pub nonce: u64,
    /// Transaction digest written to the transaction history.
    pub digest: H::Digest,
}

/// Transaction paired with its prepared execution data.
#[derive(Debug, Clone)]
pub(crate) struct PreparedTransaction<H>
where
    H: Hasher,
{
    /// Original signed transaction.
    pub transaction: SignedTransaction<H>,
    /// Prepared transfer data.
    pub transfer: PreparedTransfer<H>,
}

/// Proposal-side transaction preparation.
#[derive(Debug)]
pub(crate) struct ProposalInput<H>
where
    H: Hasher,
{
    /// Transactions with decodable execution metadata.
    pub candidates: Vec<PreparedTransaction<H>>,
    /// Transactions rejected before account execution.
    pub invalid: Vec<SignedTransaction<H>>,
}

/// The result of proposal-side filtering and execution.
#[derive(Debug)]
pub struct ProposalOutput<H>
where
    H: Hasher,
{
    /// Transactions included in the proposed block.
    pub valid: Vec<SignedTransaction<H>>,
    /// Transactions excluded from the proposed block.
    pub invalid: Vec<SignedTransaction<H>>,
    /// Persistent account writes produced by included transactions.
    pub changeset: Changeset,
    pub(crate) transfers: Vec<PreparedTransfer<H>>,
}

/// Prepares transactions for proposal-side execution.
pub(crate) fn prepare_proposal<H>(transactions: Vec<SignedTransaction<H>>) -> ProposalInput<H>
where
    H: Hasher,
{
    let mut candidates = Vec::with_capacity(transactions.len());
    let mut invalid = Vec::new();

    for transaction in transactions {
        let Some(transfer) = prepare_transfer(&transaction) else {
            invalid.push(transaction);
            continue;
        };
        candidates.push(PreparedTransaction {
            transaction,
            transfer,
        });
    }

    ProposalInput {
        candidates,
        invalid,
    }
}

/// Executes proposal candidates and filters statically invalid transfers.
pub(crate) fn propose_prepared<H>(state: &State, input: ProposalInput<H>) -> ProposalOutput<H>
where
    H: Hasher,
{
    let mut overlay = Overlay::new(state, input.candidates.len());
    let mut valid = Vec::with_capacity(input.candidates.len());
    let mut transfers = Vec::with_capacity(input.candidates.len());
    let mut invalid = input.invalid;

    for candidate in input.candidates {
        if apply_transfer(&mut overlay, &candidate.transfer) {
            transfers.push(candidate.transfer);
            valid.push(candidate.transaction);
        } else {
            invalid.push(candidate.transaction);
        }
    }

    ProposalOutput {
        valid,
        invalid,
        changeset: overlay.into_changeset(),
        transfers,
    }
}

/// Prepares and executes proposal transactions.
pub fn propose<H>(state: &State, transactions: Vec<SignedTransaction<H>>) -> ProposalOutput<H>
where
    H: Hasher,
{
    propose_prepared(state, prepare_proposal(transactions))
}

/// Prepares one transaction for account execution.
pub fn prepare_transfer<H>(transaction: &SignedTransaction<H>) -> Option<PreparedTransfer<H>>
where
    H: Hasher,
{
    let transfer = transaction.value();
    Some(PreparedTransfer {
        sender: account_key_from_sender(transfer.sender_lazy())?,
        recipient: transfer.to.clone(),
        value: transfer.value.get(),
        nonce: transfer.nonce,
        digest: *transaction.message_digest(),
    })
}

/// Executes already prepared transfers.
pub fn execute<H>(state: &State, transfers: &[PreparedTransfer<H>]) -> Option<Changeset>
where
    H: Hasher,
{
    let mut overlay = Overlay::new(state, transfers.len());

    for transfer in transfers {
        if !apply_transfer(&mut overlay, transfer) {
            return None;
        }
    }

    Some(overlay.into_changeset())
}

pub(crate) fn execute_unique<H>(
    transfers: &[PreparedTransfer<H>],
    accounts: &[Account],
) -> Option<Changeset>
where
    H: Hasher,
{
    if accounts.len() != transfers.len().saturating_mul(2) {
        return None;
    }
    let mut changeset = Vec::with_capacity(transfers.len().saturating_mul(2));

    for (transfer, accounts) in transfers.iter().zip(accounts.chunks_exact(2)) {
        let mut sender = accounts[0];
        if sender.balance < transfer.value || !sender.use_nonce(transfer.nonce) {
            return None;
        }

        let mut recipient = accounts[1];
        let recipient_balance = recipient.balance.checked_add(transfer.value)?;

        sender.balance -= transfer.value;
        recipient.balance = recipient_balance;
        changeset.push((transfer.sender.clone(), sender));
        changeset.push((transfer.recipient.clone(), recipient));
    }

    changeset.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
    Some(changeset)
}

fn account_key_from_sender(
    sender: &commonware_codec::types::lazy::Lazy<TransactionPublicKey>,
) -> Option<AccountKey> {
    let mut bytes = BytesMut::with_capacity(TransactionPublicKey::SIZE);
    sender.write(&mut bytes);
    AccountKey::from_public_key_bytes(&bytes)
}

#[derive(Debug)]
struct Overlay<'a> {
    base: &'a State,
    writes: HashMap<AccountKey, Account>,
}

impl<'a> Overlay<'a> {
    fn new(base: &'a State, transaction_count: usize) -> Self {
        let capacity = base.len().min(transaction_count.saturating_mul(2));
        Self {
            base,
            writes: HashMap::with_capacity(capacity),
        }
    }

    fn get(&self, account_key: &AccountKey) -> Option<Account> {
        self.writes
            .get(account_key)
            .or_else(|| self.base.get(account_key))
            .copied()
    }

    fn set(&mut self, account_key: AccountKey, account: Account) {
        self.writes.insert(account_key, account);
    }

    fn into_changeset(self) -> Changeset {
        let mut changeset: Changeset = self.writes.into_iter().collect();
        changeset.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        changeset
    }
}

fn apply_transfer<H>(state: &mut Overlay<'_>, transfer: &PreparedTransfer<H>) -> bool
where
    H: Hasher,
{
    let Some(mut sender) = state.get(&transfer.sender) else {
        return false;
    };
    if sender.balance < transfer.value || !sender.use_nonce(transfer.nonce) {
        return false;
    }

    if transfer.sender == transfer.recipient {
        state.set(transfer.sender.clone(), sender);
        return true;
    }

    let Some(mut recipient) = state.get(&transfer.recipient) else {
        return false;
    };
    let Some(recipient_balance) = recipient.balance.checked_add(transfer.value) else {
        return false;
    };

    sender.balance -= transfer.value;
    recipient.balance = recipient_balance;
    state.set(transfer.sender.clone(), sender);
    state.set(transfer.recipient.clone(), recipient);

    true
}

#[cfg(test)]
mod tests;
