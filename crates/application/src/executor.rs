//! Transfer execution for the Constantinople account model.
//!
//! Execution shards transactions by a prefix of the sender key. Each shard loads
//! only its sender accounts and applies debits and nonce advances. Recipient
//! accounts are not loaded or mutated by the shards. After all sender shards
//! finish, a final credit sweep routes credits back to the post-debit sender
//! shard maps first, then loads and credits any remaining recipient-only
//! accounts. A sender spends only the balance it held at the start of the block,
//! never funds credited to it within the same block.
//!
//! Execution is all or nothing: if any transfer fails its nonce or balance check
//! or overflows its recipient, the whole batch is rejected. Because a successful
//! batch has no failed debits, every loaded sender account is mutated, and the
//! credit sweep produces the remaining recipient writes.

use ahash::RandomState;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use constantinople_primitives::{Account, AccountKey, SignedTransaction, TransactionPublicKey};
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

/// Account-touch proof and load keys for a batch proven to be disjoint.
pub(crate) struct DisjointAccountPlan<'a> {
    /// Sender account keys, in transfer order.
    pub(crate) sender_keys: Vec<&'a AccountKey>,
    /// Non-self recipient account keys, in transfer order.
    pub(crate) recipient_keys: Vec<&'a AccountKey>,
}

impl DisjointAccountPlan<'_> {
    /// Number of recipient accounts that are not also the sender in the same transfer.
    pub(crate) const fn recipient_count(&self) -> usize {
        self.recipient_keys.len()
    }

    /// Whether every transfer credits a distinct non-self recipient.
    pub(crate) const fn all_recipients_non_self(&self, transfers: &[PreparedTransfer]) -> bool {
        self.recipient_keys.len() == transfers.len()
    }
}

/// Sender-shard execution output.
pub(crate) struct ShardOutput {
    /// Post-debit sender accounts to write.
    pub(crate) senders: ShardAccounts,
}

/// One indexed batch output.
pub(crate) struct IndexedOutput {
    /// Post-debit and loaded-recipient-credit sender accounts to write.
    pub(crate) senders: ShardAccounts,
}

/// Indexed execution output plus recipient-only transfer indices.
pub(crate) struct IndexedExecution {
    /// Post-debit and post-credit sender accounts to write.
    pub(crate) output: IndexedOutput,
    /// Transfer indices whose recipients were not loaded as senders.
    pub(crate) missing: MissingCredits,
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
    let sender = account_key_from_sender(transfer.sender_lazy())?;
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

/// Sender-indexed transfer work for contended batches.
pub(crate) struct SenderIndex<'a> {
    /// Transfer sender indices, in block order.
    senders: Vec<IndexedSender>,
    /// Sender account keys to load, deduplicated exactly.
    sender_keys: Vec<&'a AccountKey>,
    /// Sender key -> index in `sender_keys` and `IndexedOutput::senders`.
    sender_indices: AccountIndexTable<'a>,
}

struct IndexedSender {
    account: u32,
}

#[derive(Clone, Copy, Default)]
struct AccountDelta {
    debit: u64,
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
        let mut slot = account_index_hash(prefix) & self.mask;
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

        let mut slot = account_index_hash(prefix) & self.mask;
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
        let mut slot = account_index_hash(key_prefix(key)) & self.mask;
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

impl<'a> SenderIndex<'a> {
    /// The sender account keys this batch must load, deduplicated exactly.
    pub(crate) fn sender_keys(&self) -> &[&'a AccountKey] {
        &self.sender_keys
    }

    /// Number of unique sender accounts.
    pub(crate) const fn sender_count(&self) -> usize {
        self.sender_keys.len()
    }
}

/// Routes transfers to sender shards by sender-key prefix.
///
/// Each transfer is assigned only to its sender's shard. Sender indices are
/// emitted in block order (the input is scanned in order), which is the order
/// nonce checks must see.
pub(crate) fn partition(transfers: &[PreparedTransfer], shards: usize) -> Vec<Shard<'_>> {
    let shards = shards.max(1);
    let expected_shard_len = transfers.len().div_ceil(shards).clamp(16, 1024);
    let mut result: Vec<Shard<'_>> = (0..shards)
        .map(|_| Shard {
            senders: Vec::new(),
            sender_keys: Vec::new(),
            sender_indices: AccountIndexTable::with_capacity(expected_shard_len),
        })
        .collect();

    for (index, transfer) in transfers.iter().enumerate() {
        let index = index as u32;
        let shard = shard_of_prefix(transfer.sender_prefix, shards);
        let shard = &mut result[shard];
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

    result
}

/// Builds a global sender index for contended batches.
///
/// This is still sender-only accounting: only senders are indexed and loaded.
/// The final sweep can use this index to credit recipients that were already
/// loaded as senders without re-hashing through per-shard maps.
pub(crate) fn index_senders(transfers: &[PreparedTransfer]) -> SenderIndex<'_> {
    let expected_senders = transfers.len().div_ceil(4).max(16);
    let mut sender_keys = Vec::with_capacity(expected_senders);
    let mut sender_indices = AccountIndexTable::with_capacity(expected_senders);
    let mut senders = Vec::with_capacity(transfers.len());

    for transfer in transfers {
        let (account, inserted) = sender_indices.get_or_insert(
            transfer.sender_prefix,
            &transfer.sender,
            sender_keys.len() as u32,
        );
        if inserted {
            sender_keys.push(&transfer.sender);
        }
        senders.push(IndexedSender { account });
    }

    SenderIndex {
        senders,
        sender_keys,
        sender_indices,
    }
}

/// Returns true when no account is touched by more than one non-self role.
///
/// This is a no-false-negative check: `true` proves disjointness; `false` means
/// there may be overlap, so callers must use the general path.
pub(crate) fn account_keys_are_disjoint(transfers: &[PreparedTransfer]) -> bool {
    let mut accounts = AccountDisjointTracker::new(transfers.len());
    for transfer in transfers {
        if !accounts.insert(transfer.sender_prefix, &transfer.sender) {
            return false;
        }
        if transfer.sender != transfer.recipient
            && !accounts.insert(transfer.recipient_prefix, &transfer.recipient)
        {
            return false;
        }
    }
    true
}

/// Returns load keys when no account is touched by more than one non-self role.
pub(crate) fn disjoint_account_plan(
    transfers: &[PreparedTransfer],
) -> Option<DisjointAccountPlan<'_>> {
    let mut accounts = AccountDisjointTracker::new(transfers.len());
    let mut sender_keys =
        Vec::with_capacity(transfers.len().min(AccountDisjointTracker::SMALL_KEYS));
    let mut recipient_keys =
        Vec::with_capacity(transfers.len().min(AccountDisjointTracker::SMALL_KEYS));
    let mut reserved_full = transfers.len() <= AccountDisjointTracker::SMALL_KEYS;

    for transfer in transfers {
        if !accounts.insert(transfer.sender_prefix, &transfer.sender) {
            return None;
        }
        if transfer.sender != transfer.recipient
            && !accounts.insert(transfer.recipient_prefix, &transfer.recipient)
        {
            return None;
        }

        if !reserved_full
            && sender_keys.len().saturating_add(recipient_keys.len())
                >= AccountDisjointTracker::SMALL_KEYS
        {
            sender_keys.reserve_exact(transfers.len().saturating_sub(sender_keys.len()));
            recipient_keys.reserve_exact(transfers.len().saturating_sub(recipient_keys.len()));
            reserved_full = true;
        }

        sender_keys.push(&transfer.sender);
        if transfer.sender != transfer.recipient {
            recipient_keys.push(&transfer.recipient);
        }
    }

    Some(DisjointAccountPlan {
        sender_keys,
        recipient_keys,
    })
}

/// Small-front account overlap detector with a no-false-negative fingerprint
/// table after the front fills.
struct AccountDisjointTracker {
    state: AccountDisjointState,
    transfers: usize,
}

enum AccountDisjointState {
    Small(Vec<AccountKey>),
    Dense(DisjointAccountFilter),
}

impl AccountDisjointTracker {
    const SMALL_KEYS: usize = 128;

    fn new(transfers: usize) -> Self {
        Self {
            state: AccountDisjointState::Small(Vec::with_capacity(Self::SMALL_KEYS)),
            transfers,
        }
    }

    fn insert(&mut self, prefix: u64, key: &AccountKey) -> bool {
        match &mut self.state {
            AccountDisjointState::Small(keys) => {
                if keys.contains(key) {
                    return false;
                }
                if keys.len() < Self::SMALL_KEYS {
                    keys.push(*key);
                    return true;
                }

                let existing = core::mem::take(keys);
                let mut dense = DisjointAccountFilter::new(self.transfers.saturating_mul(2));
                for key in &existing {
                    dense.insert(key_prefix(key), key);
                }
                let inserted = dense.insert(prefix, key);
                self.state = AccountDisjointState::Dense(dense);
                inserted
            }
            AccountDisjointState::Dense(filter) => filter.insert(prefix, key),
        }
    }
}

struct DisjointAccountFilter {
    slots: Vec<u64>,
    mask: usize,
}

impl DisjointAccountFilter {
    const MIN_SLOTS: usize = 256;

    fn new(accounts: usize) -> Self {
        let slots = accounts
            .saturating_mul(2)
            .next_power_of_two()
            .max(Self::MIN_SLOTS);
        Self {
            slots: vec![0; slots],
            mask: slots - 1,
        }
    }

    fn insert(&mut self, prefix: u64, key: &AccountKey) -> bool {
        let fingerprint = account_fingerprint(prefix, key);
        let mut slot = account_index_hash(prefix) & self.mask;
        loop {
            let entry = self.slots[slot];
            if entry == 0 {
                self.slots[slot] = fingerprint;
                return true;
            }
            if entry == fingerprint {
                return false;
            }
            slot = (slot + 1) & self.mask;
        }
    }
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

/// Applies indexed sender debits and credits to recipients loaded as senders.
///
/// `accounts` must hold every sender key in [`SenderIndex::sender_keys`].
pub(crate) fn execute_indexed(
    mut accounts: ShardAccounts,
    index: &SenderIndex<'_>,
    transfers: &[PreparedTransfer],
) -> Option<IndexedExecution> {
    let mut deltas = vec![AccountDelta::default(); accounts.len()];
    let mut missing = MissingCredits::new();
    for (transfer_index, (sender, transfer)) in index.senders.iter().zip(transfers).enumerate() {
        let account = &mut accounts[sender.account as usize];
        if !account.nonce.consume(transfer.nonce) {
            return None;
        }
        if transfer.sender == transfer.recipient {
            if account.balance < transfer.value {
                return None;
            }
        } else {
            let sender_delta = &mut deltas[sender.account as usize];
            sender_delta.debit = sender_delta.debit.checked_add(transfer.value)?;
            if let Some(recipient) = index
                .sender_indices
                .get(transfer.recipient_prefix, &transfer.recipient)
            {
                let recipient_delta = &mut deltas[recipient as usize];
                recipient_delta.credit = recipient_delta.credit.checked_add(transfer.value)?;
            } else {
                missing.push(transfer_index as u32);
            }
        }
    }

    for (account, delta) in accounts.iter_mut().zip(deltas) {
        if account.balance < delta.debit {
            return None;
        }
        account.balance -= delta.debit;
        apply_credit(account, delta.credit)?;
    }

    Some(IndexedExecution {
        output: IndexedOutput { senders: accounts },
        missing,
    })
}

/// Executes the indexed path with sender validation and recipient routing split
/// across the configured strategy.
pub(crate) fn execute_indexed_parallel<S>(
    strategy: &S,
    accounts: ShardAccounts,
    index: &SenderIndex<'_>,
    transfers: &[PreparedTransfer],
) -> Option<IndexedExecution>
where
    S: Strategy,
{
    let account_count = accounts.len();
    let (debits, credits) = strategy.join(
        || execute_indexed_debits(accounts, index, transfers),
        || route_indexed_credits(account_count, index, transfers),
    );
    let (mut accounts, debits) = debits?;
    let (credits, missing) = credits?;

    for ((account, debit), credit) in accounts.iter_mut().zip(debits).zip(credits) {
        if account.balance < debit {
            return None;
        }
        account.balance -= debit;
        apply_credit(account, credit)?;
    }

    Some(IndexedExecution {
        output: IndexedOutput { senders: accounts },
        missing,
    })
}

fn execute_indexed_debits(
    mut accounts: ShardAccounts,
    index: &SenderIndex<'_>,
    transfers: &[PreparedTransfer],
) -> Option<(ShardAccounts, Vec<u64>)> {
    let mut debits = vec![0u64; accounts.len()];
    for (sender, transfer) in index.senders.iter().zip(transfers) {
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
    Some((accounts, debits))
}

fn route_indexed_credits(
    account_count: usize,
    index: &SenderIndex<'_>,
    transfers: &[PreparedTransfer],
) -> Option<(Vec<u64>, MissingCredits)> {
    let mut credits = vec![0u64; account_count];
    let mut missing = MissingCredits::new();
    for (transfer_index, transfer) in transfers.iter().enumerate() {
        if transfer.sender == transfer.recipient {
            continue;
        }
        if let Some(recipient) = index
            .sender_indices
            .get(transfer.recipient_prefix, &transfer.recipient)
        {
            let credit = &mut credits[recipient as usize];
            *credit = credit.checked_add(transfer.value)?;
        } else {
            missing.push(transfer_index as u32);
        }
    }
    Some((credits, missing))
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
    for (index, transfer) in transfers.iter().enumerate() {
        if transfer.sender == transfer.recipient {
            continue;
        }
        let shard = shard_of_prefix(transfer.recipient_prefix, shard_count);
        if let Some(account) = shards[shard]
            .sender_indices
            .get(transfer.recipient_prefix, &transfer.recipient)
        {
            apply_credit(
                &mut outputs[shard].senders[account as usize],
                transfer.value,
            )?;
        } else {
            missing.push(index as u32);
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

/// Converts indexed sender output into account writes.
pub(crate) fn indexed_writes(index: &SenderIndex<'_>, output: IndexedOutput) -> ShardWrites {
    index
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
    if account_keys_are_disjoint(transfers) {
        return execute_disjoint(state, transfers);
    }

    let shards = partition(transfers, shards);
    let mut outputs = Vec::with_capacity(shards.len());
    for shard in &shards {
        let accounts = shard
            .sender_keys()
            .iter()
            .map(|key| state.get(*key).copied().unwrap_or_default())
            .collect();
        outputs.push(execute_shard(accounts, shard, transfers)?);
    }
    let missing = apply_loaded_credits(&mut outputs, &shards, transfers)?;
    let mut recipient_writes = ShardWrites::new();
    if !missing.is_empty() {
        recipient_writes = apply_state_credits(state, aggregate_credits(missing, transfers)?)?;
    }

    let mut changeset: Changeset = outputs
        .into_iter()
        .zip(&shards)
        .flat_map(|(output, shard)| shard_writes(shard, output))
        .chain(recipient_writes)
        .collect();
    changeset.sort_unstable_by_key(|(key, _)| *key);
    Some(changeset)
}

fn execute_disjoint(state: &State, transfers: &[PreparedTransfer]) -> Option<Changeset> {
    let mut changeset = Changeset::with_capacity(transfers.len().saturating_mul(2));
    for transfer in transfers {
        let mut sender = state.get(&transfer.sender).copied().unwrap_or_default();
        if sender.balance < transfer.value || !sender.nonce.consume(transfer.nonce) {
            return None;
        }
        if transfer.sender != transfer.recipient {
            sender.balance -= transfer.value;
        }
        changeset.push((transfer.sender, sender));
    }

    for transfer in transfers {
        if transfer.sender == transfer.recipient {
            continue;
        }
        let mut recipient = state.get(&transfer.recipient).copied().unwrap_or_default();
        apply_credit(&mut recipient, transfer.value)?;
        changeset.push((transfer.recipient, recipient));
    }

    changeset.sort_unstable_by_key(|(key, _)| *key);
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

fn account_key_from_sender(
    sender: &commonware_codec::types::lazy::Lazy<TransactionPublicKey>,
) -> Option<AccountKey> {
    Some(AccountKey::from_public_key(sender.get()?))
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

#[inline]
fn key_suffix(key: &AccountKey) -> u64 {
    let mut suffix = [0u8; 8];
    suffix.copy_from_slice(&key[8..16]);
    u64::from_le_bytes(suffix)
}

#[inline]
const fn account_index_hash(prefix: u64) -> usize {
    prefix as usize
}

#[inline]
fn account_fingerprint(prefix: u64, key: &AccountKey) -> u64 {
    let value = prefix ^ key_suffix(key).rotate_left(32);
    if value == 0 { 1 } else { value }
}

#[cfg(test)]
mod tests;
