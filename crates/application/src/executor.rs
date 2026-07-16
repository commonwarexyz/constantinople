//! Transfer execution for the Constantinople account model.
//!
//! This module is the state-agnostic account engine used by consensus execution,
//! tests, and benchmarks. It decides which account keys must be loaded, builds
//! deterministic account effects from the transfer list, and applies those
//! effects to loaded block-start account state. DB-backed loading is handled by
//! `consensus::execution`; the in-memory entry points in this module read from
//! [`State`].
//!
//! Execution first builds an account-touch plan. The plan counts non-self
//! sender/recipient touches across the block. Transfers whose touched accounts
//! are unique stay on the discrete lane, where each loaded sender or recipient
//! produces one final write. Transfers that touch any contended account move to
//! the general lane.
//!
//! The general lane is account-owned. It aggregates every contended transfer
//! into one effect per account: sent nonces, non-self debit total,
//! self-transfer affordability floor, and recipient credit total. Account state
//! is loaded after these effects are known, then each loaded account is checked
//! and written once. A sender spends only the balance it held at the start of the
//! block, never funds credited to it within the same block.
//!
//! Verification is all or nothing: if any transfer fails its nonce or balance
//! check or overflows its recipient, the whole batch is rejected. Because a
//! successful batch has no failed debits, every loaded account effect produces
//! one final write. Proposal construction instead uses [`SelectiveExecutor`],
//! which applies the same per-account rules per transfer and drops what cannot
//! apply.

use ahash::AHashMap;
use commonware_cryptography::Hasher;
use constantinople_primitives::{Account, AccountKey, Nonce, SignedTransaction};

/// Fully loaded base account state for one in-memory execution batch.
pub type State = AHashMap<AccountKey, Account>;

/// Deterministic account writes produced by execution.
pub type Changeset = Vec<(AccountKey, Account)>;

/// Account execution plan for one batch.
pub(crate) struct ExecutionPlan {
    /// Transfers whose non-self account touches are unique in the block.
    pub(crate) discrete: DiscreteWorkload,
    /// Account-owned effects for the remaining transfers.
    pub(crate) general: GeneralWorkload,
}

/// Transfers that can produce direct sender and recipient writes.
pub(crate) struct DiscreteWorkload {
    /// Indices into the original transfer list, in block order.
    pub(crate) transfers: Vec<usize>,
    /// Sender account keys, in transfer order.
    pub(crate) sender_keys: Vec<AccountKey>,
    /// Non-self recipient account keys, in transfer order.
    pub(crate) recipient_keys: Vec<AccountKey>,
}

/// Account-owned effects for transfers that touch contended accounts.
pub(crate) struct GeneralWorkload {
    /// Account keys to load, deduplicated exactly.
    account_keys: Vec<AccountKey>,
    /// Effects to apply to each loaded account.
    effects: Vec<AccountEffect>,
}

impl GeneralWorkload {
    /// Whether the general lane has no account effects.
    pub(crate) const fn is_empty(&self) -> bool {
        self.account_keys.is_empty()
    }

    /// Account keys to load for the general lane.
    pub(crate) fn account_keys(&self) -> &[AccountKey] {
        &self.account_keys
    }
}

/// Transfer data used by the executor.
#[derive(Debug, Clone, Copy)]
pub struct PreparedTransfer {
    /// Sender account key.
    pub sender: AccountKey,
    /// Recipient account key.
    pub recipient: AccountKey,
    /// Sender key prefix used for routing and transient indexing.
    pub sender_prefix: u64,
    /// Recipient key prefix used for routing and transient indexing.
    pub recipient_prefix: u64,
    /// Amount transferred.
    pub value: u64,
    /// Sender nonce required by the transaction.
    pub nonce: u64,
}

/// Prepares one transaction for account execution.
pub fn prepare_transfer<H>(transaction: &SignedTransaction<H>) -> Option<PreparedTransfer>
where
    H: Hasher,
{
    let transfer = transaction.value();
    let sender = AccountKey::from_public_key(transfer.sender_lazy().get()?);
    let recipient = transfer.to;
    Some(PreparedTransfer {
        sender,
        recipient,
        sender_prefix: sender.prefix(),
        recipient_prefix: recipient.prefix(),
        value: transfer.value.get(),
        nonce: transfer.nonce,
    })
}

#[derive(Default)]
pub(crate) struct AccountEffect {
    /// Transfer indices sent by this account, in block order.
    sent: Vec<u32>,
    /// Total non-self debit to subtract from the account.
    debit: u64,
    /// Largest self-transfer value that must be affordable.
    self_transfer_floor: u64,
    /// Total credit to add to the account after debits.
    credit: u64,
}

struct AccountIndexTable {
    slots: Vec<AccountIndexSlot>,
    mask: usize,
    len: usize,
}

#[derive(Clone, Copy)]
struct AccountIndexSlot {
    key: Option<AccountKey>,
    index: u32,
}

impl AccountIndexTable {
    fn with_capacity(capacity: usize) -> Self {
        let slots = capacity.saturating_mul(2).next_power_of_two().max(16);
        Self {
            slots: vec![
                AccountIndexSlot {
                    key: None,
                    index: 0
                };
                slots
            ],
            mask: slots - 1,
            len: 0,
        }
    }

    /// Looks up a key without inserting.
    fn get(&self, prefix: u64, key: &AccountKey) -> Option<u32> {
        let mut slot = (prefix as usize) & self.mask;
        loop {
            let entry = self.slots[slot];
            entry.key?;
            if entry.key == Some(*key) {
                return Some(entry.index);
            }
            slot = (slot + 1) & self.mask;
        }
    }

    fn get_or_insert(&mut self, prefix: u64, key: AccountKey, index: u32) -> (u32, bool) {
        if self.len.saturating_mul(2) >= self.slots.len() {
            self.grow();
        }

        let mut slot = (prefix as usize) & self.mask;
        loop {
            let entry = self.slots[slot];
            if entry.key.is_none() {
                self.slots[slot] = AccountIndexSlot {
                    key: Some(key),
                    index,
                };
                self.len += 1;
                return (index, true);
            }
            if entry.key == Some(key) {
                return (entry.index, false);
            }
            slot = (slot + 1) & self.mask;
        }
    }

    fn grow(&mut self) {
        let new_slots = self.slots.len() * 2;
        let old_slots = core::mem::replace(
            &mut self.slots,
            vec![
                AccountIndexSlot {
                    key: None,
                    index: 0
                };
                new_slots
            ],
        );
        self.mask = new_slots - 1;
        self.len = 0;

        for slot in old_slots {
            if let Some(key) = slot.key {
                self.insert_unique(key, slot.index);
            }
        }
    }

    fn insert_unique(&mut self, key: AccountKey, index: u32) {
        let mut slot = (key.prefix() as usize) & self.mask;
        while self.slots[slot].key.is_some() {
            slot = (slot + 1) & self.mask;
        }
        self.slots[slot] = AccountIndexSlot {
            key: Some(key),
            index,
        };
        self.len += 1;
    }
}

/// Builder for the general lane's dense account-effect table.
///
/// Account keys are copied from the prepared transfer slice and deduplicated by
/// value. The prefix only seeds the probe position; equality still compares the
/// full account key, so equal keys from different transfer slots share one
/// effect.
struct GeneralBuilder {
    account_keys: Vec<AccountKey>,
    effects: Vec<AccountEffect>,
    indices: AccountIndexTable,
}

impl GeneralBuilder {
    fn new(transfers: usize) -> Self {
        let expected_accounts = transfers.saturating_mul(2).max(16);
        Self {
            account_keys: Vec::with_capacity(expected_accounts),
            effects: Vec::with_capacity(expected_accounts),
            indices: AccountIndexTable::with_capacity(expected_accounts),
        }
    }

    fn account(&mut self, prefix: u64, key: &AccountKey) -> &mut AccountEffect {
        let (account, inserted) =
            self.indices
                .get_or_insert(prefix, *key, self.account_keys.len() as u32);
        if inserted {
            self.account_keys.push(*key);
            self.effects.push(AccountEffect::default());
        }
        &mut self.effects[account as usize]
    }

    fn into_workload(self) -> GeneralWorkload {
        GeneralWorkload {
            account_keys: self.account_keys,
            effects: self.effects,
        }
    }
}

/// Builds the execution plan used by both DB-backed and in-memory execution.
pub(crate) fn execution_plan(transfers: &[PreparedTransfer]) -> Option<ExecutionPlan> {
    // Count account touches by each key's precomputed 64-bit prefix instead
    // of rehashing full 32-byte keys. A prefix collision between distinct
    // keys only merges their counts, which can only demote transfers to the
    // general lane; that lane deduplicates by full key and applies the same
    // per-account checks as the discrete lane, so routing stays
    // consensus-neutral.
    let mut touches: AHashMap<u64, u32> =
        AHashMap::with_capacity(transfers.len().saturating_mul(2));
    for transfer in transfers {
        *touches.entry(transfer.sender_prefix).or_default() += 1;
        if transfer.sender != transfer.recipient {
            *touches.entry(transfer.recipient_prefix).or_default() += 1;
        }
    }

    let mut general = None;
    let mut discrete = DiscreteWorkload {
        transfers: Vec::with_capacity(transfers.len()),
        sender_keys: Vec::with_capacity(transfers.len()),
        recipient_keys: Vec::with_capacity(transfers.len()),
    };

    for (index, transfer) in transfers.iter().enumerate() {
        let sender_is_unique = touches
            .get(&transfer.sender_prefix)
            .copied()
            .unwrap_or_default()
            == 1;
        let recipient_is_unique = transfer.sender == transfer.recipient
            || touches
                .get(&transfer.recipient_prefix)
                .copied()
                .unwrap_or_default()
                == 1;
        if sender_is_unique && recipient_is_unique {
            discrete.transfers.push(index);
            discrete.sender_keys.push(transfer.sender);
            if transfer.sender != transfer.recipient {
                discrete.recipient_keys.push(transfer.recipient);
            }
            continue;
        }

        let general = general.get_or_insert_with(|| GeneralBuilder::new(transfers.len()));
        let sender = general.account(transfer.sender_prefix, &transfer.sender);
        sender.sent.push(index as u32);
        if transfer.sender == transfer.recipient {
            sender.self_transfer_floor = sender.self_transfer_floor.max(transfer.value);
        } else {
            sender.debit = sender.debit.checked_add(transfer.value)?;
            let recipient = general.account(transfer.recipient_prefix, &transfer.recipient);
            recipient.credit = recipient.credit.checked_add(transfer.value)?;
        }
    }

    Some(ExecutionPlan {
        discrete,
        general: general.map_or_else(
            || GeneralWorkload {
                account_keys: Vec::new(),
                effects: Vec::new(),
            },
            GeneralBuilder::into_workload,
        ),
    })
}

/// Applies one credit to an account.
pub(crate) fn apply_credit(account: &mut Account, value: u64) -> Option<()> {
    account.balance = account.balance.checked_add(value)?;
    Some(())
}

/// Applies account-owned effects to loaded accounts.
///
/// Returns one final account per workload entry, in `account_keys` order.
pub(crate) fn apply_general_accounts(
    values: &[Option<Account>],
    workload: &GeneralWorkload,
    transfers: &[PreparedTransfer],
) -> Option<Vec<Account>> {
    assert_eq!(values.len(), workload.account_keys.len());
    assert_eq!(values.len(), workload.effects.len());

    let mut writes = Vec::with_capacity(workload.effects.len());
    for (effect, value) in workload.effects.iter().zip(values) {
        let mut account = value.unwrap_or_default();
        for index in &effect.sent {
            let transfer = &transfers[*index as usize];
            if !account.nonce.consume(transfer.nonce) {
                return None;
            }
        }
        if account.balance < effect.self_transfer_floor || account.balance < effect.debit {
            return None;
        }
        account.balance -= effect.debit;
        apply_credit(&mut account, effect.credit)?;
        writes.push(account);
    }
    Some(writes)
}

fn execute_discrete(
    state: &State,
    plan: &DiscreteWorkload,
    transfers: &[PreparedTransfer],
) -> Option<Changeset> {
    assert_eq!(plan.sender_keys.len(), plan.transfers.len());
    let mut changeset =
        Changeset::with_capacity(plan.sender_keys.len() + plan.recipient_keys.len());
    for (sender_key, transfer_index) in plan.sender_keys.iter().zip(&plan.transfers) {
        let transfer = &transfers[*transfer_index];
        let mut sender = state.get(&transfer.sender).copied().unwrap_or_default();
        if sender.balance < transfer.value || !sender.nonce.consume(transfer.nonce) {
            return None;
        }
        if transfer.sender != transfer.recipient {
            sender.balance -= transfer.value;
        }
        changeset.push((*sender_key, sender));
    }

    for transfer_index in &plan.transfers {
        let transfer = &transfers[*transfer_index];
        if transfer.sender == transfer.recipient {
            continue;
        }
        let mut recipient = state.get(&transfer.recipient).copied().unwrap_or_default();
        apply_credit(&mut recipient, transfer.value)?;
        changeset.push((transfer.recipient, recipient));
    }

    Some(changeset)
}

/// Incremental best-effort executor for proposals.
///
/// Verification is all or nothing: a block containing an inapplicable
/// transfer is invalid. A proposer, however, chooses the block body, so it
/// applies candidate transfers in block order against block-start account
/// state and simply drops any transfer that cannot apply (stale nonce,
/// insufficient start balance, credit overflow) — typically a transaction
/// that already landed in another block on this chain. Candidates can be fed
/// in multiple rounds (the initial selection, then mempool refills), with
/// account state loaded incrementally per round.
///
/// The per-account bookkeeping mirrors `apply_general_accounts` exactly:
/// debits and self-transfer floors are checked against the block-start
/// balance only (credits never fund debits in the same block), nonces are
/// consumed in block order, and the final value is
/// `start - debits + credits`. Applied transfers therefore re-execute
/// cleanly, with identical account writes, under the all-or-nothing
/// verification path.
pub struct SelectiveExecutor {
    /// Prefix-seeded open-addressing map from account key to dense index.
    indices: AccountIndexTable,
    /// Touched account keys, in first-appearance (= staged read) order.
    keys: Vec<AccountKey>,
    /// Working state per key; the dense index doubles as the staged read
    /// index because keys are staged in exactly this order.
    accounts: Vec<WorkingAccount>,
}

#[derive(Clone, Copy)]
struct WorkingAccount {
    /// Block-start balance.
    start_balance: u64,
    /// Nonce state after the transfers applied so far.
    nonce: Nonce,
    /// Total non-self debits applied so far.
    debit: u64,
    /// Total credits applied so far.
    credit: u64,
    /// Whether any applied transfer touched this account.
    touched: bool,
}

impl Default for SelectiveExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl SelectiveExecutor {
    pub fn new() -> Self {
        Self {
            indices: AccountIndexTable::with_capacity(16),
            keys: Vec::new(),
            accounts: Vec::new(),
        }
    }

    /// Records the accounts a candidate round touches, returning the keys not
    /// seen in any earlier round, in the order their block-start values must
    /// be staged (their dense indices continue the staged read space).
    pub fn begin_round(&mut self, transfers: &[PreparedTransfer]) -> Vec<AccountKey> {
        let before = self.keys.len();
        for transfer in transfers {
            for (prefix, key) in [
                (transfer.sender_prefix, transfer.sender),
                (transfer.recipient_prefix, transfer.recipient),
            ] {
                let (_, inserted) = self
                    .indices
                    .get_or_insert(prefix, key, self.keys.len() as u32);
                if inserted {
                    self.keys.push(key);
                }
            }
        }
        self.keys[before..].to_vec()
    }

    /// Registers the staged block-start values for the keys the last
    /// [`begin_round`](Self::begin_round) returned, in the same order.
    pub fn register(&mut self, values: &[Option<Account>]) {
        assert_eq!(
            self.accounts.len() + values.len(),
            self.keys.len(),
            "registered values must cover exactly the unregistered keys"
        );
        for value in values {
            let start = value.unwrap_or_default();
            self.accounts.push(WorkingAccount {
                start_balance: start.balance,
                nonce: start.nonce,
                debit: 0,
                credit: 0,
                touched: false,
            });
        }
    }

    /// Applies `transfers` in order, returning one applied/dropped flag per
    /// transfer. Every touched account must be registered.
    pub fn apply(&mut self, transfers: &[PreparedTransfer]) -> Vec<bool> {
        let mut applied = Vec::with_capacity(transfers.len());
        for transfer in transfers {
            applied.push(self.apply_one(transfer));
        }
        applied
    }

    fn apply_one(&mut self, transfer: &PreparedTransfer) -> bool {
        let sender = self
            .indices
            .get(transfer.sender_prefix, &transfer.sender)
            .expect("touched account must be registered") as usize;

        if transfer.sender == transfer.recipient {
            let account = &mut self.accounts[sender];

            // Affordable from the start balance (self-transfers never debit),
            // with the nonce as the final, mutating gate.
            if account.start_balance < transfer.value || !account.nonce.consume(transfer.nonce) {
                return false;
            }
            account.touched = true;
            return true;
        }
        let recipient = self
            .indices
            .get(transfer.recipient_prefix, &transfer.recipient)
            .expect("touched account must be registered") as usize;

        // Check everything that could fail before consuming the nonce, so a
        // dropped transfer leaves no trace.
        let Some(debit) = self.accounts[sender].debit.checked_add(transfer.value) else {
            return false;
        };
        if self.accounts[sender].start_balance < debit {
            return false;
        }

        // The recipient's final value is `start - debits + credits`; its
        // debits only grow after this point, so checking against the current
        // debit total is conservative.
        let Some(credit) = self.accounts[recipient].credit.checked_add(transfer.value) else {
            return false;
        };
        if (self.accounts[recipient].start_balance - self.accounts[recipient].debit)
            .checked_add(credit)
            .is_none()
        {
            return false;
        }
        if !self.accounts[sender].nonce.consume(transfer.nonce) {
            return false;
        }

        self.accounts[sender].debit = debit;
        self.accounts[sender].touched = true;
        self.accounts[recipient].credit = credit;
        self.accounts[recipient].touched = true;
        true
    }

    /// Final values for every account touched by an applied transfer, as
    /// staged-index updates in staged order.
    pub fn into_updates(self) -> Vec<(usize, Option<Account>)> {
        self.accounts
            .into_iter()
            .enumerate()
            .filter(|(_, account)| account.touched)
            .map(|(index, account)| {
                let balance = account.start_balance - account.debit + account.credit;
                (
                    index,
                    Some(Account {
                        balance,
                        nonce: account.nonce,
                    }),
                )
            })
            .collect()
    }
}

/// Computes a batch changeset against an in-memory base state.
///
/// Returns the sorted changeset, or `None` if any transfer fails its nonce or
/// balance check or any recipient credit overflows.
pub fn compute(state: &State, transfers: &[PreparedTransfer]) -> Option<Changeset> {
    let plan = execution_plan(transfers)?;
    let mut changeset = execute_discrete(state, &plan.discrete, transfers)?;
    if !plan.general.is_empty() {
        let accounts: Vec<Option<Account>> = plan
            .general
            .account_keys()
            .iter()
            .map(|key| state.get(key).copied())
            .collect();
        let written = apply_general_accounts(&accounts, &plan.general, transfers)?;
        changeset.extend(plan.general.account_keys().iter().copied().zip(written));
    }
    changeset.sort_unstable_by_key(|(key, _)| *key);
    Some(changeset)
}

#[cfg(test)]
mod tests;
