//! Transfer execution for the Constantinople account model.
//!
//! Execution shards accounts by a prefix of their key. Each shard owns a
//! disjoint set of accounts and one map that holds its loaded block-start
//! accounts and, after execution, the mutated values to write. A transaction's
//! debit and nonce advance are applied in the shard that owns its sender; its
//! credit in the shard that owns its recipient. Because an account hashes to the
//! same shard whether it sends or receives, a single shard owns every write to
//! that account. A sender spends only the balance it held at the start of the
//! block, never funds credited to it within the same block.
//!
//! Execution is all or nothing: if any transfer fails its nonce or balance check
//! or overflows its recipient, the whole batch is rejected. Because a successful
//! batch has no failed debits, every loaded account is mutated, so a shard's map
//! is exactly its set of writes.

use bytes::BytesMut;
use commonware_codec::{FixedSize as _, Write as _};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use constantinople_primitives::{Account, AccountKey, SignedTransaction, TransactionPublicKey};
use hashbrown::HashMap;

/// Fully loaded base account state for one in-memory execution batch.
pub type State = HashMap<AccountKey, Account>;

/// Deterministic account writes produced by execution.
pub type Changeset = Vec<(AccountKey, Account)>;

/// One shard's working map: loaded block-start accounts, mutated in place into
/// the accounts to write. hashbrown's default hasher (foldhash) is a fast,
/// DoS-resistant choice and the workload is memory bound, so the hasher is not
/// the bottleneck.
pub(crate) type ShardMap = HashMap<AccountKey, Account>;

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

/// One shard's work: the transfers it must debit (sender owned) and credit
/// (recipient owned). The accounts it owns are derived from these indices via
/// [`Shard::account_keys`].
pub(crate) struct Shard {
    /// Transfer indices to debit, in block order.
    senders: Vec<u32>,
    /// Transfer indices to credit.
    recipients: Vec<u32>,
}

impl Shard {
    /// The account keys this shard owns, with possible duplicates (an account
    /// that both sends and receives appears twice). Loading and the base map both
    /// deduplicate, so callers need not.
    pub(crate) fn account_keys<'a, H>(
        &self,
        transfers: &'a [PreparedTransfer<H>],
    ) -> Vec<&'a AccountKey>
    where
        H: Hasher,
    {
        self.senders
            .iter()
            .map(|index| &transfers[*index as usize].sender)
            .chain(
                self.recipients
                    .iter()
                    .map(|index| &transfers[*index as usize].recipient),
            )
            .collect()
    }
}

/// Routes transfers to shards by account-key prefix.
///
/// Each transfer is assigned to its sender's shard for the debit and, unless it
/// is a self-transfer, to its recipient's shard for the credit. Sender indices
/// are emitted in block order (the input is scanned in order), which is the
/// order the nonce checks must see.
pub(crate) fn partition<H>(transfers: &[PreparedTransfer<H>], shards: usize) -> Vec<Shard>
where
    H: Hasher,
{
    let shards = shards.max(1);
    let mut result: Vec<Shard> = (0..shards)
        .map(|_| Shard {
            senders: Vec::new(),
            recipients: Vec::new(),
        })
        .collect();

    for (index, transfer) in transfers.iter().enumerate() {
        let index = index as u32;
        result[shard_of(&transfer.sender, shards)]
            .senders
            .push(index);
        if transfer.sender != transfer.recipient {
            result[shard_of(&transfer.recipient, shards)]
                .recipients
                .push(index);
        }
    }

    result
}

/// Applies one shard's debits then credits, in place, on its loaded accounts.
///
/// `accounts` must already hold every key this shard owns (loaded from
/// block-start state); each lookup is therefore infallible. Returns the mutated
/// map (the shard's writes), or `None` if any debit fails its nonce/balance
/// check or any credit overflows.
pub(crate) fn execute_shard<H>(
    mut accounts: ShardMap,
    shard: &Shard,
    transfers: &[PreparedTransfer<H>],
) -> Option<ShardMap>
where
    H: Hasher,
{
    for index in &shard.senders {
        let transfer = &transfers[*index as usize];
        let account = accounts
            .get_mut(&transfer.sender)
            .expect("sender is loaded by its shard");
        if account.balance < transfer.value || !account.nonce.consume(transfer.nonce) {
            return None;
        }
        if transfer.sender != transfer.recipient {
            account.balance -= transfer.value;
        }
    }

    for index in &shard.recipients {
        let transfer = &transfers[*index as usize];
        let account = accounts
            .get_mut(&transfer.recipient)
            .expect("recipient is loaded by its shard");
        match account.balance.checked_add(transfer.value) {
            Some(balance) => account.balance = balance,
            None => return None,
        }
    }

    Some(accounts)
}

/// Executes a batch against an in-memory base state, sharding by `shards`.
///
/// Used by tests and benchmarks; the consensus path loads each shard's accounts
/// from the database instead (see `consensus::execution`). The result is
/// independent of the shard count.
pub(crate) fn execute_with_shards<H>(
    state: &State,
    transfers: &[PreparedTransfer<H>],
    shards: usize,
) -> Option<Changeset>
where
    H: Hasher,
{
    let mut changeset = Changeset::new();
    for shard in &partition(transfers, shards) {
        let keys = shard.account_keys(transfers);
        let mut accounts = ShardMap::with_capacity(keys.len());
        for key in keys {
            accounts
                .entry(key.clone())
                .or_insert_with(|| state.get(key).copied().unwrap_or_default());
        }
        changeset.extend(execute_shard(accounts, shard, transfers)?);
    }
    changeset.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
    Some(changeset)
}

/// Executes a batch against an in-memory base state.
///
/// Returns the sorted changeset, or `None` if any transfer fails its nonce or
/// balance check or any recipient credit overflows.
pub fn execute<S, H>(
    strategy: &S,
    state: &State,
    transfers: &[PreparedTransfer<H>],
) -> Option<Changeset>
where
    S: Strategy,
    H: Hasher,
{
    execute_with_shards(state, transfers, strategy.parallelism_hint())
}

fn account_key_from_sender(
    sender: &commonware_codec::types::lazy::Lazy<TransactionPublicKey>,
) -> Option<AccountKey> {
    let mut bytes = BytesMut::with_capacity(TransactionPublicKey::SIZE);
    sender.write(&mut bytes);
    AccountKey::from_public_key_bytes(&bytes)
}

/// The shard that owns an account, derived from a prefix of its key. Account
/// keys are uniformly distributed (public keys or hashes), so a key prefix
/// spreads accounts evenly across shards.
#[inline]
fn shard_of(key: &AccountKey, shards: usize) -> usize {
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&key[..8]);
    (u64::from_le_bytes(prefix) % shards as u64) as usize
}

#[cfg(test)]
mod tests;
