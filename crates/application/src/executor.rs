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
//! Execution is all or nothing: if any transfer fails its nonce or balance check
//! or overflows its recipient, the whole batch is rejected. Because a successful
//! batch has no failed debits, every loaded account effect produces one final
//! write.

use ahash::AHashMap;
use commonware_cryptography::Hasher;
use constantinople_primitives::{Account, AccountKey, SignedTransaction};
use core::marker::PhantomData;

/// Fully loaded base account state for one in-memory execution batch.
pub type State = AHashMap<AccountKey, Account>;

/// Deterministic account writes produced by execution.
pub type Changeset = Vec<(AccountKey, Account)>;

/// One independently applicable group of account writes.
pub(crate) type ShardWrites = Vec<(AccountKey, Account)>;

/// Account execution plan for one batch.
pub(crate) struct ExecutionPlan<'a> {
    /// Transfers whose non-self account touches are unique in the block.
    pub(crate) discrete: DiscreteWorkload<'a>,
    /// Account-owned effects for the remaining transfers.
    pub(crate) general: GeneralWorkload<'a>,
}

/// Transfers that can produce direct sender and recipient writes.
pub(crate) struct DiscreteWorkload<'a> {
    /// Transfers, in block order.
    pub(crate) transfers: Vec<&'a PreparedTransfer>,
    /// Sender account keys, in transfer order.
    pub(crate) sender_keys: Vec<&'a AccountKey>,
    /// Non-self recipient account keys, in transfer order.
    pub(crate) recipient_keys: Vec<&'a AccountKey>,
}

/// Account-owned effects for transfers that touch contended accounts.
pub(crate) struct GeneralWorkload<'a> {
    /// Account keys to load, deduplicated exactly.
    account_keys: Vec<&'a AccountKey>,
    /// Effects to apply to each loaded account.
    effects: Vec<AccountEffect>,
}

impl<'a> GeneralWorkload<'a> {
    /// Whether the general lane has no account effects.
    pub(crate) const fn is_empty(&self) -> bool {
        self.account_keys.is_empty()
    }

    /// Account keys to load for the general lane.
    pub(crate) fn account_keys(&self) -> &[&'a AccountKey] {
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

struct AccountIndexTable<'a> {
    slots: Vec<AccountIndexSlot>,
    mask: usize,
    len: usize,
    _marker: PhantomData<&'a AccountKey>,
}

#[derive(Clone, Copy)]
struct AccountIndexSlot {
    key: *const AccountKey,
    index: u32,
}

impl<'a> AccountIndexTable<'a> {
    fn with_capacity(capacity: usize) -> Self {
        let slots = capacity.saturating_mul(2).next_power_of_two().max(16);
        Self {
            slots: vec![
                AccountIndexSlot {
                    key: core::ptr::null(),
                    index: 0,
                };
                slots
            ],
            mask: slots - 1,
            len: 0,
            _marker: PhantomData,
        }
    }

    fn get_or_insert(&mut self, prefix: u64, key: &'a AccountKey, index: u32) -> (u32, bool) {
        if self.len.saturating_mul(2) >= self.slots.len() {
            self.grow();
        }

        let mut slot = (prefix as usize) & self.mask;
        loop {
            let entry = self.slots[slot];
            if entry.key.is_null() {
                self.slots[slot] = AccountIndexSlot { key, index };
                self.len += 1;
                return (index, true);
            }
            // SAFETY: keys are pointers to accounts borrowed from `transfers`,
            // which outlive the table through `'a`.
            if unsafe { *entry.key == *key } {
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
                    key: core::ptr::null(),
                    index: 0,
                };
                new_slots
            ],
        );
        self.mask = new_slots - 1;
        self.len = 0;

        for slot in old_slots {
            if !slot.key.is_null() {
                // SAFETY: keys are pointers to accounts borrowed from `transfers`,
                // which outlive the table through `'a`.
                self.insert_unique(unsafe { &*slot.key }, slot.index);
            }
        }
    }

    fn insert_unique(&mut self, key: &'a AccountKey, index: u32) {
        let mut slot = (key.prefix() as usize) & self.mask;
        while !self.slots[slot].key.is_null() {
            slot = (slot + 1) & self.mask;
        }
        self.slots[slot] = AccountIndexSlot { key, index };
        self.len += 1;
    }
}

/// Builder for the general lane's dense account-effect table.
///
/// Account keys are borrowed from the prepared transfer slice and deduplicated by
/// value. The prefix only seeds the probe position; equality still compares the
/// full account key, so equal keys from different transfer slots share one
/// effect.
struct GeneralBuilder<'a> {
    account_keys: Vec<&'a AccountKey>,
    effects: Vec<AccountEffect>,
    indices: AccountIndexTable<'a>,
}

impl<'a> GeneralBuilder<'a> {
    fn new(transfers: usize) -> Self {
        let expected_accounts = transfers.saturating_mul(2).max(16);
        Self {
            account_keys: Vec::with_capacity(expected_accounts),
            effects: Vec::with_capacity(expected_accounts),
            indices: AccountIndexTable::with_capacity(expected_accounts),
        }
    }

    fn account(&mut self, prefix: u64, key: &'a AccountKey) -> &mut AccountEffect {
        let (account, inserted) =
            self.indices
                .get_or_insert(prefix, key, self.account_keys.len() as u32);
        if inserted {
            self.account_keys.push(key);
            self.effects.push(AccountEffect::default());
        }
        &mut self.effects[account as usize]
    }

    fn into_workload(self) -> GeneralWorkload<'a> {
        GeneralWorkload {
            account_keys: self.account_keys,
            effects: self.effects,
        }
    }
}

/// Builds the execution plan used by both DB-backed and in-memory execution.
pub(crate) fn execution_plan(transfers: &[PreparedTransfer]) -> Option<ExecutionPlan<'_>> {
    let mut touches: AHashMap<&AccountKey, usize> =
        AHashMap::with_capacity(transfers.len().saturating_mul(2));
    for transfer in transfers {
        *touches.entry(&transfer.sender).or_default() += 1;
        if transfer.sender != transfer.recipient {
            *touches.entry(&transfer.recipient).or_default() += 1;
        }
    }

    let mut general = None;
    let mut discrete = DiscreteWorkload {
        transfers: Vec::with_capacity(transfers.len()),
        sender_keys: Vec::with_capacity(transfers.len()),
        recipient_keys: Vec::with_capacity(transfers.len()),
    };

    for (index, transfer) in transfers.iter().enumerate() {
        let sender_is_unique = touches.get(&transfer.sender).copied().unwrap_or_default() == 1;
        let recipient_is_unique = transfer.sender == transfer.recipient
            || touches
                .get(&transfer.recipient)
                .copied()
                .unwrap_or_default()
                == 1;
        if sender_is_unique && recipient_is_unique {
            discrete.transfers.push(transfer);
            discrete.sender_keys.push(&transfer.sender);
            if transfer.sender != transfer.recipient {
                discrete.recipient_keys.push(&transfer.recipient);
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
pub(crate) fn apply_general_accounts(
    values: Vec<Option<Account>>,
    workload: &GeneralWorkload<'_>,
    transfers: &[PreparedTransfer],
) -> Option<ShardWrites> {
    assert_eq!(values.len(), workload.account_keys.len());
    assert_eq!(values.len(), workload.effects.len());

    let mut writes = ShardWrites::with_capacity(workload.account_keys.len());
    for ((key, effect), value) in workload
        .account_keys
        .iter()
        .zip(&workload.effects)
        .zip(values)
    {
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
        writes.push((**key, account));
    }
    Some(writes)
}

fn execute_discrete(state: &State, plan: &DiscreteWorkload<'_>) -> Option<Changeset> {
    assert_eq!(plan.sender_keys.len(), plan.transfers.len());
    let mut changeset =
        Changeset::with_capacity(plan.sender_keys.len() + plan.recipient_keys.len());
    for (sender_key, transfer) in plan.sender_keys.iter().zip(&plan.transfers) {
        let mut sender = state.get(&transfer.sender).copied().unwrap_or_default();
        if sender.balance < transfer.value || !sender.nonce.consume(transfer.nonce) {
            return None;
        }
        if transfer.sender != transfer.recipient {
            sender.balance -= transfer.value;
        }
        changeset.push((**sender_key, sender));
    }

    for transfer in &plan.transfers {
        if transfer.sender == transfer.recipient {
            continue;
        }
        let mut recipient = state.get(&transfer.recipient).copied().unwrap_or_default();
        apply_credit(&mut recipient, transfer.value)?;
        changeset.push((transfer.recipient, recipient));
    }

    Some(changeset)
}

/// Computes a batch changeset against an in-memory base state.
///
/// Returns the sorted changeset, or `None` if any transfer fails its nonce or
/// balance check or any recipient credit overflows.
pub fn compute(state: &State, transfers: &[PreparedTransfer]) -> Option<Changeset> {
    let plan = execution_plan(transfers)?;
    let mut changeset = execute_discrete(state, &plan.discrete)?;
    if !plan.general.is_empty() {
        let accounts = plan
            .general
            .account_keys()
            .iter()
            .map(|key| state.get(*key).copied())
            .collect();
        changeset.extend(apply_general_accounts(accounts, &plan.general, transfers)?);
    }
    changeset.sort_unstable_by_key(|(key, _)| *key);
    Some(changeset)
}

#[cfg(test)]
mod tests;
