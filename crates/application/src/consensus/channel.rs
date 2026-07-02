//! On-chain payment-channel execution.
//!
//! This is the second execution lane that runs beside the transfer executor.
//! The transfer fast path (see [`crate::executor`]) is untouched: a block body
//! is partitioned into transfers and channel operations, transfers run through
//! the optimized contention-lane executor, and the (rare) channel operations
//! run through the sequential logic here.
//!
//! Channels are ordinary accounts at a derived, unspendable address (see
//! [`constantinople_primitives::channel_address`]). Opening a channel debits the
//! payer and funds the channel account; closing it verifies the payer's voucher
//! and splits the escrow between receiver and payer; once the block height
//! exceeds the channel's expiry, a timeout lets the payer reclaim the whole
//! escrow unilaterally. A channel address can never sign a transaction, so the
//! channel account's nonce slot stores the expiry. Because a channel is just
//! an account, no new state value type, QMDB schema, or block-header field is
//! required.
//!
//! Channel-operation execution reads block-start state (like the transfer
//! lane), but applies its operations sequentially against a working set so that
//! two channel operations on the same account in one block compose. The caller
//! rejects any block where a channel operation and a transfer touch the same
//! account, so the two lanes never race on a write.
//!
//! The channel address is derived from the payer's `OpenChannel` nonce
//! (`H(domain || payer || receiver || open_nonce)`). Because account nonces are
//! monotonic and never reused, every open yields a unique address that no later
//! `OpenChannel` can recreate. That gives three properties: a settled channel
//! can be deleted, an old voucher can never be replayed against a *different*
//! channel (a new channel always has a new nonce, hence a new address), and no
//! per-channel counter has to be stored — the existing account nonce is the
//! monotonic counter.
//!
//! Replay caveat: deletion plus monotonic nonces stop a voucher being replayed
//! against a *new* channel, but not against the *same* settled address if it is
//! re-funded. The address is publicly derivable and lives in the ordinary
//! account key space, so a plain `Transfer` can credit it after settlement;
//! `channel_escrow` would then read that balance as live escrow and the old
//! (still validly signed) voucher would settle against it again. No
//! `OpenChannel` can trigger this (its nonce is consumed and never reused), so
//! it cannot arise in normal operation — only a deliberate transfer to a dead
//! channel address, where the funder is the only party that can lose. Closing
//! the gap entirely would need a durable closed-marker, which trades away the
//! no-residual-state property; see the limitations below. (A transfer-created
//! account carries a zero nonce, which reads as expiry 0, so the payer can at
//! least reclaim such stray escrow with a timeout.)
//!
//! Design choices and limitations (candidates for follow-up):
//! - A channel address is an ordinary account, so anyone may pay into it and an
//!   `OpenChannel` adds to (rather than replaces) the channel's escrow. A
//!   never-funded address contributes zero escrow, so opening mints nothing,
//!   and ordinary stray payments just become escrow returned to the payer on
//!   close. (The one exception is an adversary pre-funding the derived address
//!   so the open's escrow would overflow `u64`, which rejects the open; that
//!   needs a balance near `u64::MAX`, far above any real supply.)
//! - Channel vouchers are Ed25519, so `OpenChannel` rejects a non-Ed25519
//!   payer: it could never sign a settleable voucher, which would lock the
//!   deposit.
//! - Closing (or timing out) deletes the channel account, so a settled channel
//!   leaves no state. The flip side is the replay caveat above: with no
//!   residual marker, a re-funded dead address looks like a fresh, live
//!   channel. A durable closed-marker would close that gap at the cost of
//!   per-channel state.
//! - The channel's expiry is the receiver's settlement deadline: a close is
//!   valid at any height while the channel exists, a timeout only once
//!   `height > expiry`, and whichever lands first deletes the channel and
//!   invalidates the other. A receiver that misses the deadline forfeits its
//!   unsettled vouchers, so it must settle with margin (the operator stops
//!   serving vouchers as expiry approaches for exactly this reason).

use super::db::StateBatch;
use crate::executor::apply_credit;
use ahash::AHashMap;
use commonware_cryptography::{Hasher, ed25519};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::translator::EightCap;
use constantinople_primitives::{
    Account, AccountKey, Nonce, Operation, SignedTransaction, TransactionPublicKey,
    channel_address, verify_voucher,
};

/// Account writes a channel-operation batch produces, in no particular order.
///
/// `Some(account)` upserts; `None` deletes the account, which is how a settled
/// channel is removed so it leaves no state behind.
pub(super) type ChannelWrites = Vec<(AccountKey, Option<Account>)>;

/// A channel operation prepared for execution.
#[derive(Debug, Clone)]
pub struct PreparedChannelOp {
    /// The transaction sender's account key (payer for open, receiver for
    /// close).
    pub sender: AccountKey,
    /// The sender nonce this operation consumes. For an open it also derives
    /// the channel address.
    pub nonce: u64,
    /// Operation-specific payload.
    pub kind: PreparedChannelOpKind,
}

/// Operation-specific payload for a [`PreparedChannelOp`].
#[derive(Debug, Clone)]
pub enum PreparedChannelOpKind {
    /// Open a channel from the sender (payer) to `receiver`. The channel
    /// address is derived from the sender, receiver, and this operation's
    /// nonce.
    Open {
        /// Receiver account key.
        receiver: AccountKey,
        /// Amount escrowed.
        deposit: u64,
        /// Block height after which the payer may reclaim the escrow.
        expiry: u64,
    },
    /// Close a channel, settling the latest voucher.
    Close {
        /// Payer public key (used to verify the voucher).
        payer: TransactionPublicKey,
        /// Payer account key (used to derive the channel address).
        payer_key: AccountKey,
        /// Nonce of the `OpenChannel` that created the channel.
        open_nonce: u64,
        /// Cumulative amount claimed.
        cumulative: u64,
        /// Payer's voucher signature.
        voucher: ed25519::Signature,
    },
    /// Reclaim an expired channel's escrow for the sender (payer).
    Timeout {
        /// Receiver account key (used to derive the channel address).
        receiver: AccountKey,
        /// Nonce of the `OpenChannel` that created the channel.
        open_nonce: u64,
    },
}

/// Prepares a channel operation from a signed transaction.
///
/// Returns `None` if the sender public key fails to decode, the transaction is
/// a transfer (which belongs to the other lane), or the operation is statically
/// invalid (an `OpenChannel` from a non-Ed25519 payer; see below).
pub fn prepare_channel_op<H>(transaction: &SignedTransaction<H>) -> Option<PreparedChannelOp>
where
    H: Hasher,
{
    let tx = transaction.value();
    let sender_key = tx.sender_lazy().get()?;
    let sender = AccountKey::from_public_key(sender_key);
    let kind = match tx.op() {
        Operation::Transfer { .. } => return None,
        Operation::OpenChannel {
            receiver,
            deposit,
            expiry,
        } => {
            // Vouchers are Ed25519, so a non-Ed25519 payer could never sign a
            // voucher the chain accepts at settlement — the deposit would be
            // locked until withdrawal. Refuse to open such a channel.
            if !matches!(sender_key, TransactionPublicKey::Ed25519 { .. }) {
                return None;
            }
            PreparedChannelOpKind::Open {
                receiver: *receiver,
                deposit: deposit.get(),
                expiry: *expiry,
            }
        }
        Operation::CloseChannel {
            payer,
            open_nonce,
            cumulative,
            voucher,
        } => PreparedChannelOpKind::Close {
            payer: payer.clone(),
            payer_key: AccountKey::from_public_key(payer),
            open_nonce: *open_nonce,
            cumulative: *cumulative,
            voucher: voucher.clone(),
        },
        Operation::TimeoutChannel {
            receiver,
            open_nonce,
        } => PreparedChannelOpKind::Timeout {
            receiver: *receiver,
            open_nonce: *open_nonce,
        },
    };
    Some(PreparedChannelOp {
        sender,
        nonce: tx.nonce,
        kind,
    })
}

/// Pending writes accumulated while applying a channel-operation batch.
///
/// `Some(account)` is a live value; `None` marks the account for deletion.
type Pending = AHashMap<AccountKey, Option<Account>>;

/// Resolves an account's value, defaulting like the transfer lane: an unwritten
/// (or this-block-deleted) account reads as the funded default.
fn account_or_default(pending: &Pending, loaded: &Pending, key: &AccountKey) -> Account {
    match pending.get(key) {
        Some(Some(account)) => *account,
        Some(None) => Account::default(),
        None => loaded.get(key).copied().flatten().unwrap_or_default(),
    }
}

/// Returns the channel account at `key`, or `None` if no channel lives there.
///
/// Unlike [`account_or_default`], a never-funded address contributes nothing
/// (not the funded default account), so opening mints nothing and closing or
/// timing out a nonexistent channel is rejected. The account's balance is the
/// escrow; its (otherwise unusable) nonce base stores the channel's expiry.
fn channel_account(pending: &Pending, loaded: &Pending, key: &AccountKey) -> Option<Account> {
    match pending.get(key) {
        Some(Some(account)) => Some(*account),
        Some(None) => None,
        None => loaded.get(key).copied().flatten(),
    }
}

/// Returns a channel's current escrow, or `None` if no channel lives at `key`.
fn channel_escrow(pending: &Pending, loaded: &Pending, key: &AccountKey) -> Option<u64> {
    channel_account(pending, loaded, key).map(|account| account.balance)
}

/// Collects every account key a batch of channel operations reads or writes.
fn channel_op_keys(channel_ops: &[PreparedChannelOp]) -> Vec<AccountKey> {
    let mut keys = Vec::with_capacity(channel_ops.len() * 3);
    for op in channel_ops {
        keys.push(op.sender);
        match &op.kind {
            PreparedChannelOpKind::Open { receiver, .. } => {
                keys.push(channel_address(&op.sender, receiver, op.nonce));
            }
            PreparedChannelOpKind::Close {
                payer_key,
                open_nonce,
                ..
            } => {
                keys.push(*payer_key);
                keys.push(channel_address(payer_key, &op.sender, *open_nonce));
            }
            PreparedChannelOpKind::Timeout {
                receiver,
                open_nonce,
            } => {
                keys.push(channel_address(&op.sender, receiver, *open_nonce));
            }
        }
    }
    keys
}

/// Loads every account a batch of channel operations touches, keyed for the
/// working set.
async fn load_channel_state<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    channel_ops: &[PreparedChannelOp],
) -> Pending
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    // Deduplicate before loading: a block may contain several operations that
    // touch the same account (e.g. two opens from one payer), and `get_many`
    // expects unique keys, like the transfer lane's deduplicated plan.
    let mut keys = channel_op_keys(channel_ops);
    keys.sort_unstable();
    keys.dedup();
    let key_refs: Vec<&AccountKey> = keys.iter().collect();
    let values = batch
        .get_many(&key_refs)
        .await
        .expect("channel state loading must succeed");
    keys.iter().copied().zip(values).collect()
}

/// Applies one channel operation to the working set. `height` is the height of
/// the block being executed, which gates timeout eligibility.
///
/// Atomic: on any failure (bad nonce, insufficient balance, absent channel, an
/// unverifiable voucher, an unexpired timeout, or overflow) `pending` is left
/// untouched and `None` is returned, so a failed operation can be skipped
/// without unwinding.
fn apply_channel_op(
    pending: &mut Pending,
    loaded: &Pending,
    op: &PreparedChannelOp,
    height: u64,
) -> Option<()> {
    match &op.kind {
        PreparedChannelOpKind::Open {
            receiver,
            deposit,
            expiry,
        } => {
            let channel = channel_address(&op.sender, receiver, op.nonce);
            let mut payer = account_or_default(pending, loaded, &op.sender);
            if payer.balance < *deposit || !payer.nonce.consume(op.nonce) {
                return None;
            }
            payer.balance -= *deposit;
            // Add the deposit to the channel's escrow (zero for a fresh
            // address). Anyone may pay into a channel; those funds simply
            // become escrow returned to the payer on close.
            let escrow = channel_escrow(pending, loaded, &channel)
                .unwrap_or(0)
                .checked_add(*deposit)?;
            pending.insert(op.sender, Some(payer));
            // A channel address can never sign a transaction, so its nonce
            // slot is repurposed to store the expiry.
            pending.insert(
                channel,
                Some(Account {
                    balance: escrow,
                    nonce: Nonce::new(*expiry, 0),
                }),
            );
        }
        PreparedChannelOpKind::Close {
            payer,
            payer_key,
            open_nonce,
            cumulative,
            voucher,
        } => {
            let channel = channel_address(payer_key, &op.sender, *open_nonce);
            // The channel must exist (it was opened by a prior transaction).
            let balance = channel_escrow(pending, loaded, &channel)?;
            // Verify the payer's voucher over (channel, cumulative).
            if !verify_voucher(payer, &channel, *cumulative, voucher) {
                return None;
            }
            // Can never claim more than what is escrowed.
            if *cumulative > balance {
                return None;
            }
            let refund = balance - *cumulative;

            // Pay the receiver (the sender of this transaction) and consume
            // its nonce.
            let mut receiver = account_or_default(pending, loaded, &op.sender);
            if !receiver.nonce.consume(op.nonce) {
                return None;
            }
            apply_credit(&mut receiver, *cumulative)?;

            // Return the remainder to the payer. A self-channel's refund lands
            // on the receiver copy just credited, so the two credits compose;
            // nothing touches `pending` until every check has passed.
            if *payer_key == op.sender {
                apply_credit(&mut receiver, refund)?;
                pending.insert(op.sender, Some(receiver));
            } else {
                let mut payer_account = account_or_default(pending, loaded, payer_key);
                apply_credit(&mut payer_account, refund)?;
                pending.insert(op.sender, Some(receiver));
                pending.insert(*payer_key, Some(payer_account));
            }

            // Delete the settled channel so it leaves no state.
            pending.insert(channel, None);
        }
        PreparedChannelOpKind::Timeout {
            receiver,
            open_nonce,
        } => {
            let channel = channel_address(&op.sender, receiver, *open_nonce);
            // The channel must exist and its expiry (stored in the channel
            // account's nonce base) must have passed. A receiver close that
            // landed first deleted the channel, so first-to-land wins.
            let account = channel_account(pending, loaded, &channel)?;
            if height <= account.nonce.base {
                return None;
            }

            // Reclaim the entire escrow for the payer (the sender of this
            // transaction) and consume its nonce.
            let mut payer = account_or_default(pending, loaded, &op.sender);
            if !payer.nonce.consume(op.nonce) {
                return None;
            }
            apply_credit(&mut payer, account.balance)?;
            pending.insert(op.sender, Some(payer));

            // Delete the reclaimed channel so it leaves no state.
            pending.insert(channel, None);
        }
    }
    Some(())
}

/// Applies a batch of channel operations against block-start state.
///
/// Returns the resulting writes (deletions included), or `None` if any
/// operation is invalid. Like the transfer lane, verification is all or
/// nothing: a proposed block containing an invalid channel operation is
/// rejected. Proposers instead build blocks with
/// [`apply_channel_ops_skipping`], which never includes a failing operation.
pub(super) async fn apply_channel_ops<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    channel_ops: &[PreparedChannelOp],
    height: u64,
) -> Option<ChannelWrites>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    if channel_ops.is_empty() {
        return Some(Vec::new());
    }

    let loaded = load_channel_state(batch, channel_ops).await;
    let mut pending: Pending = AHashMap::new();
    for op in channel_ops {
        apply_channel_op(&mut pending, &loaded, op, height)?;
    }

    Some(pending.into_iter().collect())
}

/// Applies a batch of channel operations, skipping any operation that fails
/// instead of rejecting the whole batch.
///
/// A channel operation's validity can depend on execution-time state the
/// mempool cannot screen (a voucher is only checkable against live escrow), so
/// the proposer uses this variant to keep one bad operation from poisoning an
/// entire proposal. Returns the writes plus one applied/skipped flag per
/// operation; the proposer drops skipped operations from the body, so verifiers
/// re-execute exactly the applied sequence.
pub(super) async fn apply_channel_ops_skipping<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    channel_ops: &[PreparedChannelOp],
    height: u64,
) -> (ChannelWrites, Vec<bool>)
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    if channel_ops.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let loaded = load_channel_state(batch, channel_ops).await;
    let mut pending: Pending = AHashMap::new();
    let applied = channel_ops
        .iter()
        .map(|op| apply_channel_op(&mut pending, &loaded, op, height).is_some())
        .collect();

    (pending.into_iter().collect(), applied)
}
