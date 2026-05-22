//! Transfer execution for the Constantinople account model.

use bytes::BytesMut;
use commonware_codec::Write as _;
use commonware_cryptography::{Hasher, PublicKey};
use constantinople_primitives::{Account, AccountKey, SignedTransaction};
use hashbrown::HashMap;

/// Fully loaded account state for one execution batch.
pub type State<P> = HashMap<AccountKey<P>, Account>;

/// Deterministic account writes produced by execution.
pub type Changeset<P> = Vec<(AccountKey<P>, Account)>;

/// Transfer data used by the executor.
#[derive(Debug, Clone)]
pub struct PreparedTransfer<P, H>
where
    H: Hasher,
    P: PublicKey,
{
    /// Sender account key.
    pub sender: AccountKey<P>,
    /// Recipient account key.
    pub recipient: AccountKey<P>,
    /// Amount transferred.
    pub value: u64,
    /// Sender nonce required by the transaction.
    pub nonce: u64,
    /// Transaction digest written to the transaction history.
    pub digest: H::Digest,
}

/// Transaction paired with its prepared execution data.
#[derive(Debug, Clone)]
pub(crate) struct PreparedTransaction<P, H>
where
    H: Hasher,
    P: PublicKey,
{
    /// Original signed transaction.
    pub transaction: SignedTransaction<P, H>,
    /// Prepared transfer data.
    pub transfer: PreparedTransfer<P, H>,
}

/// Proposal-side transaction preparation.
#[derive(Debug)]
pub(crate) struct ProposalInput<P, H>
where
    H: Hasher,
    P: PublicKey,
{
    /// Transactions with decodable execution metadata.
    pub candidates: Vec<PreparedTransaction<P, H>>,
    /// Transactions rejected before account execution.
    pub invalid: Vec<SignedTransaction<P, H>>,
}

/// The result of proposal-side filtering and execution.
#[derive(Debug)]
pub struct ProposalOutput<P, H>
where
    H: Hasher,
    P: PublicKey,
{
    /// Transactions included in the proposed block.
    pub valid: Vec<SignedTransaction<P, H>>,
    /// Transactions excluded from the proposed block.
    pub invalid: Vec<SignedTransaction<P, H>>,
    /// Persistent account writes produced by included transactions.
    pub changeset: Changeset<P>,
    pub(crate) transfers: Vec<PreparedTransfer<P, H>>,
}

/// Prepares transactions for proposal-side execution.
pub(crate) fn prepare_proposal<P, H>(
    transactions: Vec<SignedTransaction<P, H>>,
) -> ProposalInput<P, H>
where
    H: Hasher,
    P: PublicKey,
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
pub(crate) fn propose_prepared<P, H>(
    state: &State<P>,
    input: ProposalInput<P, H>,
) -> ProposalOutput<P, H>
where
    H: Hasher,
    P: PublicKey,
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
pub fn propose<P, H>(
    state: &State<P>,
    transactions: Vec<SignedTransaction<P, H>>,
) -> ProposalOutput<P, H>
where
    H: Hasher,
    P: PublicKey,
{
    propose_prepared(state, prepare_proposal(transactions))
}

/// Prepares one transaction for account execution.
pub fn prepare_transfer<P, H>(
    transaction: &SignedTransaction<P, H>,
) -> Option<PreparedTransfer<P, H>>
where
    H: Hasher,
    P: PublicKey,
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
pub fn execute<P, H>(state: &State<P>, transfers: &[PreparedTransfer<P, H>]) -> Option<Changeset<P>>
where
    H: Hasher,
    P: PublicKey,
{
    let mut overlay = Overlay::new(state, transfers.len());

    for transfer in transfers {
        if !apply_transfer(&mut overlay, transfer) {
            return None;
        }
    }

    Some(overlay.into_changeset())
}

pub(crate) fn execute_unique<P, H>(
    transfers: &[PreparedTransfer<P, H>],
    accounts: &[Account],
) -> Option<Changeset<P>>
where
    H: Hasher,
    P: PublicKey,
{
    if accounts.len() != transfers.len().saturating_mul(2) {
        return None;
    }
    let mut changeset = Vec::with_capacity(transfers.len().saturating_mul(2));

    for (transfer, accounts) in transfers.iter().zip(accounts.chunks_exact(2)) {
        let mut sender = accounts[0];
        if sender.nonce != transfer.nonce || sender.balance < transfer.value {
            return None;
        }
        let next_nonce = sender.nonce.checked_add(1)?;

        let mut recipient = accounts[1];
        let recipient_balance = recipient.balance.checked_add(transfer.value)?;

        sender.nonce = next_nonce;
        sender.balance -= transfer.value;
        recipient.balance = recipient_balance;
        changeset.push((transfer.sender.clone(), sender));
        changeset.push((transfer.recipient.clone(), recipient));
    }

    changeset.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
    Some(changeset)
}

fn account_key_from_sender<P>(
    sender: &commonware_codec::types::lazy::Lazy<P>,
) -> Option<AccountKey<P>>
where
    P: PublicKey,
{
    let mut bytes = BytesMut::with_capacity(P::SIZE);
    sender.write(&mut bytes);
    AccountKey::from_bytes(bytes.freeze())
}

#[derive(Debug)]
struct Overlay<'a, P>
where
    P: PublicKey,
{
    base: &'a State<P>,
    writes: HashMap<AccountKey<P>, Account>,
}

impl<'a, P> Overlay<'a, P>
where
    P: PublicKey,
{
    fn new(base: &'a State<P>, transaction_count: usize) -> Self {
        let capacity = base.len().min(transaction_count.saturating_mul(2));
        Self {
            base,
            writes: HashMap::with_capacity(capacity),
        }
    }

    fn get(&self, account_key: &AccountKey<P>) -> Option<Account> {
        self.writes
            .get(account_key)
            .or_else(|| self.base.get(account_key))
            .copied()
    }

    fn set(&mut self, account_key: AccountKey<P>, account: Account) {
        self.writes.insert(account_key, account);
    }

    fn into_changeset(self) -> Changeset<P> {
        let mut changeset: Changeset<P> = self.writes.into_iter().collect();
        changeset.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        changeset
    }
}

fn apply_transfer<P, H>(state: &mut Overlay<'_, P>, transfer: &PreparedTransfer<P, H>) -> bool
where
    H: Hasher,
    P: PublicKey,
{
    let Some(mut sender) = state.get(&transfer.sender) else {
        return false;
    };
    if sender.nonce != transfer.nonce || sender.balance < transfer.value {
        return false;
    }
    let Some(next_nonce) = sender.nonce.checked_add(1) else {
        return false;
    };

    sender.nonce = next_nonce;
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
