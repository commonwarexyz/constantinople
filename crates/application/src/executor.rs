//! Transfer execution for the Constantinople account model.
//!
//! This module is the state-agnostic account engine used by consensus execution,
//! tests, and benchmarks. It decides which sender accounts must be loaded,
//! applies nonce/debit checks to those loaded sender accounts, routes credits to
//! loaded senders, and reports the recipient-only credits that must be swept by
//! the caller. DB-backed loading is handled by `consensus::execution`; the
//! in-memory entry points in this module read from [`State`].
//!
//! Execution first builds an account-touch plan. The plan counts non-self
//! sender/recipient touches across the block. Transfers whose touched accounts
//! are unique stay on the discrete lane, where each loaded sender or recipient
//! produces one final write. Transfers that touch any contended account move to
//! the general lane.
//!
//! The general lane is sharded by a prefix of the sender key. Each shard owns
//! only its sender accounts and applies debits and nonce advances. Recipient
//! accounts are not loaded or mutated by the shards. After all sender shards
//! finish, a final credit sweep routes credits back to the post-debit sender
//! shard maps first, then credits any remaining recipient-only accounts. A
//! sender spends only the balance it held at the start of the block, never funds
//! credited to it within the same block.
//!
//! Execution is all or nothing: if any transfer fails its nonce or balance check
//! or overflows its recipient, the whole batch is rejected. Because a successful
//! batch has no failed debits, every loaded sender account is mutated, and the
//! credit sweep produces the remaining recipient writes.

use ahash::RandomState;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use constantinople_primitives::{Account, AccountKey, SignedTransaction};
use core::marker::PhantomData;
use hashbrown::HashMap;

type FastMap<K, V> = HashMap<K, V, RandomState>;

/// Fully loaded base account state for one in-memory execution batch.
pub type State = HashMap<AccountKey, Account>;

/// Deterministic account writes produced by execution.
pub type Changeset = Vec<(AccountKey, Account)>;

/// One independently applicable group of account writes.
pub(crate) type ShardWrites = Vec<(AccountKey, Account)>;

/// One shard's loaded sender accounts, in the same order as its sender keys.
pub(crate) type ShardAccounts = Vec<Account>;

/// Aggregated recipient credits used by the final sweep.
pub(crate) type AggregatedCredits<'a> = Vec<(&'a AccountKey, u64)>;

/// Transfer indices whose recipients were not loaded as senders.
pub(crate) type MissingCredits = Vec<u32>;

/// Account execution plan for one batch.
pub(crate) struct ExecutionPlan<'a> {
    /// Transfers whose non-self account touches are unique in the block.
    pub(crate) discrete: DiscreteWorkload<'a>,
    /// Sender-sharded work for the remaining transfers.
    pub(crate) general: Vec<Shard<'a>>,
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

/// Sender-shard execution output.
pub(crate) struct ShardOutput {
    /// Post-debit sender accounts to write.
    pub(crate) senders: ShardAccounts,
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
        sender_prefix: key_prefix(&sender),
        recipient_prefix: key_prefix(&recipient),
        value: transfer.value.get(),
        nonce: transfer.nonce,
    })
}

/// One sender shard's work: the transfers it must debit, in block order.
pub(crate) struct Shard<'a> {
    /// Transfer indices to debit, in block order.
    senders: Vec<ShardSender>,
    /// Sender account keys this shard must load, deduplicated exactly.
    sender_keys: Vec<&'a AccountKey>,
    /// Sender key -> index in `sender_keys` and `ShardOutput::senders`.
    sender_indices: AccountIndexTable<'a>,
}

struct ShardSender {
    transfer: u32,
    account: u32,
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

// SAFETY: `AccountIndexTable` only stores immutable pointers to `AccountKey`
// values borrowed from the transfer slice for lifetime `'a`. Those keys are
// never mutated through the table, and `AccountKey` is `Sync`.
unsafe impl<'a> Send for AccountIndexTable<'a> {}
// SAFETY: see the `Send` impl above.
unsafe impl<'a> Sync for AccountIndexTable<'a> {}

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

    fn get(&self, prefix: u64, key: &AccountKey) -> Option<u32> {
        let mut slot = (prefix as usize) & self.mask;
        loop {
            let entry = self.slots[slot];
            if entry.key.is_null() {
                return None;
            }
            // SAFETY: keys are pointers to accounts borrowed from `transfers`,
            // which outlive the table through `'a`.
            if unsafe { *entry.key == *key } {
                return Some(entry.index);
            }
            slot = (slot + 1) & self.mask;
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
        let mut slot = (key_prefix(key) as usize) & self.mask;
        while !self.slots[slot].key.is_null() {
            slot = (slot + 1) & self.mask;
        }
        self.slots[slot] = AccountIndexSlot { key, index };
        self.len += 1;
    }
}

impl<'a> Shard<'a> {
    /// The sender account keys this shard must load, deduplicated exactly.
    pub(crate) fn sender_keys(&self) -> &[&'a AccountKey] {
        &self.sender_keys
    }
}

/// Builds the execution plan used by both DB-backed and in-memory execution.
pub(crate) fn execution_plan(transfers: &[PreparedTransfer], shards: usize) -> ExecutionPlan<'_> {
    let mut touches: FastMap<&AccountKey, usize> =
        FastMap::with_capacity_and_hasher(transfers.len().saturating_mul(2), RandomState::new());
    for transfer in transfers {
        *touches.entry(&transfer.sender).or_default() += 1;
        if transfer.sender != transfer.recipient {
            *touches.entry(&transfer.recipient).or_default() += 1;
        }
    }

    let shards = shards.max(1);
    let expected_shard_len = transfers.len().div_ceil(shards).clamp(16, 1024);
    let mut general = new_shards(shards, expected_shard_len);
    let mut has_general = false;
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

        has_general = true;
        push_sender(&mut general, index as u32, transfer);
    }

    if !has_general {
        general.clear();
    }

    ExecutionPlan { discrete, general }
}

fn new_shards<'a>(shards: usize, expected_shard_len: usize) -> Vec<Shard<'a>> {
    (0..shards)
        .map(|_| Shard {
            senders: Vec::new(),
            sender_keys: Vec::new(),
            sender_indices: AccountIndexTable::with_capacity(expected_shard_len),
        })
        .collect()
}

fn push_sender<'a>(shards: &mut [Shard<'a>], index: u32, transfer: &'a PreparedTransfer) {
    let shard = shard_of_prefix(transfer.sender_prefix, shards.len());
    let shard = &mut shards[shard];
    let (account, inserted) = shard.sender_indices.get_or_insert(
        transfer.sender_prefix,
        &transfer.sender,
        shard.sender_keys.len() as u32,
    );
    if inserted {
        shard.sender_keys.push(&transfer.sender);
    }
    shard.senders.push(ShardSender {
        transfer: index,
        account,
    });
}

/// Applies one sender shard's debits.
///
/// `accounts` must already hold every sender key this shard owns (loaded from
/// block-start state); each lookup is therefore infallible. Returns post-debit
/// sender writes, or `None` if any debit fails its nonce or balance check.
pub(crate) fn execute_shard(
    mut accounts: ShardAccounts,
    shard: &Shard<'_>,
    transfers: &[PreparedTransfer],
) -> Option<ShardOutput> {
    let mut debits = vec![0u64; accounts.len()];
    for sender in &shard.senders {
        let transfer = &transfers[sender.transfer as usize];
        let account = &mut accounts[sender.account as usize];
        if !account.nonce.consume(transfer.nonce) {
            return None;
        }
        if transfer.sender == transfer.recipient {
            if account.balance < transfer.value {
                return None;
            }
        } else {
            let debit = &mut debits[sender.account as usize];
            *debit = (*debit).checked_add(transfer.value)?;
        }
    }

    for (account, debit) in accounts.iter_mut().zip(debits) {
        if account.balance < debit {
            return None;
        }
        account.balance -= debit;
    }

    Some(ShardOutput { senders: accounts })
}

/// Applies credits to recipients already loaded as sender accounts.
///
/// Returns transfer indices whose recipients were not loaded by any sender
/// shard and therefore still need state fetched in the final sweep.
pub(crate) fn apply_loaded_credits(
    outputs: &mut [ShardOutput],
    shards: &[Shard<'_>],
    transfers: &[PreparedTransfer],
) -> Option<MissingCredits> {
    let shard_count = outputs.len();
    let mut missing = MissingCredits::new();
    for owner in shards {
        for sender in &owner.senders {
            let index = sender.transfer;
            let transfer = &transfers[index as usize];
            if transfer.sender == transfer.recipient {
                continue;
            }
            let recipient_shard = shard_of_prefix(transfer.recipient_prefix, shard_count);
            if let Some(account) = shards[recipient_shard]
                .sender_indices
                .get(transfer.recipient_prefix, &transfer.recipient)
            {
                apply_credit(
                    &mut outputs[recipient_shard].senders[account as usize],
                    transfer.value,
                )?;
            } else {
                missing.push(index);
            }
        }
    }
    Some(missing)
}

/// Converts a sender shard output into account writes.
pub(crate) fn shard_writes(shard: &Shard<'_>, output: ShardOutput) -> ShardWrites {
    shard
        .sender_keys
        .iter()
        .zip(output.senders)
        .map(|(key, account)| (**key, account))
        .collect()
}

/// Aggregates recipient-only credits for the final state fetch.
pub(crate) fn aggregate_credits<'a>(
    missing: MissingCredits,
    transfers: &'a [PreparedTransfer],
) -> Option<AggregatedCredits<'a>> {
    let mut aggregated: FastMap<&AccountKey, u64> =
        FastMap::with_capacity_and_hasher(missing.len(), RandomState::new());
    for index in missing {
        let transfer = &transfers[index as usize];
        let credit = aggregated.entry(&transfer.recipient).or_default();
        *credit = credit.checked_add(transfer.value)?;
    }
    Some(aggregated.into_iter().collect())
}

/// Applies aggregated recipient-only credits to fetched accounts.
pub(crate) fn apply_aggregated_credits<'a, I>(
    recipients: I,
    values: impl IntoIterator<Item = Option<Account>>,
) -> Option<ShardWrites>
where
    I: IntoIterator<Item = (&'a AccountKey, u64)>,
{
    let recipients = recipients.into_iter();
    let mut writes = ShardWrites::with_capacity(recipients.size_hint().0);
    for ((recipient, credit), value) in recipients.zip(values) {
        let mut account = value.unwrap_or_default();
        apply_credit(&mut account, credit)?;
        writes.push((*recipient, account));
    }
    Some(writes)
}

/// Applies aggregated recipient-only credits to the in-memory state.
pub(crate) fn apply_state_credits<'a, I>(state: &State, recipients: I) -> Option<ShardWrites>
where
    I: IntoIterator<Item = (&'a AccountKey, u64)>,
{
    let recipients = recipients.into_iter();
    let mut writes = ShardWrites::with_capacity(recipients.size_hint().0);
    for (recipient, credit) in recipients {
        let mut account = state.get(recipient).copied().unwrap_or_default();
        apply_credit(&mut account, credit)?;
        writes.push((*recipient, account));
    }
    Some(writes)
}

/// Applies one credit to an account.
pub(crate) fn apply_credit(account: &mut Account, value: u64) -> Option<()> {
    account.balance = account.balance.checked_add(value)?;
    Some(())
}

/// Executes a batch against an in-memory base state, sharding by `shards`.
///
/// Used by tests and benchmarks; the consensus path loads each shard's accounts
/// from the database instead (see `consensus::execution`). The result is
/// independent of the shard count.
pub(crate) fn execute_with_shards(
    state: &State,
    transfers: &[PreparedTransfer],
    shards: usize,
) -> Option<Changeset> {
    let plan = execution_plan(transfers, shards);
    let mut changeset = execute_discrete(state, &plan.discrete)?;
    if !plan.general.is_empty() {
        let mut outputs = Vec::with_capacity(plan.general.len());
        for shard in &plan.general {
            let accounts = shard
                .sender_keys()
                .iter()
                .map(|key| state.get(*key).copied().unwrap_or_default())
                .collect();
            outputs.push(execute_shard(accounts, shard, transfers)?);
        }
        let missing = apply_loaded_credits(&mut outputs, &plan.general, transfers)?;
        let mut recipient_writes = ShardWrites::new();
        if !missing.is_empty() {
            recipient_writes = apply_state_credits(state, aggregate_credits(missing, transfers)?)?;
        }

        changeset.extend(
            outputs
                .into_iter()
                .zip(&plan.general)
                .flat_map(|(output, shard)| shard_writes(shard, output))
                .chain(recipient_writes),
        );
    }
    changeset.sort_unstable_by_key(|(key, _)| *key);
    Some(changeset)
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

/// Executes a batch against an in-memory base state.
///
/// Returns the sorted changeset, or `None` if any transfer fails its nonce or
/// balance check or any recipient credit overflows.
pub fn execute<S>(strategy: &S, state: &State, transfers: &[PreparedTransfer]) -> Option<Changeset>
where
    S: Strategy,
{
    execute_with_shards(state, transfers, strategy.parallelism_hint())
}

/// The shard that owns an account, derived from a prefix of its key. Account
/// keys are uniformly distributed (public keys or hashes), so a key prefix
/// spreads accounts evenly across shards.
#[inline]
const fn shard_of_prefix(prefix: u64, shards: usize) -> usize {
    let value = prefix as usize;
    if shards.is_power_of_two() {
        value & (shards - 1)
    } else {
        value % shards
    }
}

#[inline]
pub(crate) fn key_prefix(key: &AccountKey) -> u64 {
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&key[..8]);
    u64::from_le_bytes(prefix)
}

#[cfg(test)]
mod tests;
