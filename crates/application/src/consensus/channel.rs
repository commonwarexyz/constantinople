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
//! and splits the escrow between receiver and payer. Because a channel is just
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
//! no-residual-state property; see the limitations below.
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
//! - Closing deletes the channel account, so a settled channel leaves no state.
//!   The flip side is the replay caveat above: with no residual marker, a
//!   re-funded dead address looks like a fresh, live channel. A durable
//!   closed-marker would close that gap at the cost of per-channel state.
//! - There is no unilateral timed-withdraw escape yet; a payer relies on the
//!   receiver to settle. Adding it needs a `withdraw_deadline` on the channel
//!   account (its otherwise-unused nonce slot suffices, since a channel address
//!   can never sign a transaction).

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
        Operation::OpenChannel { receiver, deposit } => {
            // Vouchers are Ed25519, so a non-Ed25519 payer could never sign a
            // voucher the chain accepts at settlement — the deposit would be
            // locked until withdrawal. Refuse to open such a channel.
            if !matches!(sender_key, TransactionPublicKey::Ed25519 { .. }) {
                return None;
            }
            PreparedChannelOpKind::Open {
                receiver: *receiver,
                deposit: deposit.get(),
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

/// Returns a channel's current escrow, or `None` if no channel lives at `key`.
///
/// Unlike [`account_or_default`], a never-funded address contributes no escrow
/// (not the default account balance), so opening mints nothing and closing a
/// nonexistent channel is rejected.
fn channel_escrow(pending: &Pending, loaded: &Pending, key: &AccountKey) -> Option<u64> {
    match pending.get(key) {
        Some(Some(account)) => Some(account.balance),
        Some(None) => None,
        None => loaded
            .get(key)
            .copied()
            .flatten()
            .map(|account| account.balance),
    }
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
        }
    }
    keys
}

/// Applies a batch of channel operations against block-start state.
///
/// Returns the resulting writes (deletions included), or `None` if any
/// operation is invalid (bad nonce, insufficient balance, absent channel, or an
/// unverifiable voucher). Like the transfer lane, execution is all or nothing.
pub(super) async fn apply_channel_ops<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    channel_ops: &[PreparedChannelOp],
) -> Option<ChannelWrites>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    if channel_ops.is_empty() {
        return Some(Vec::new());
    }

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
    let loaded: Pending = keys.iter().copied().zip(values).collect();

    let mut pending: Pending = AHashMap::new();
    for op in channel_ops {
        match &op.kind {
            PreparedChannelOpKind::Open { receiver, deposit } => {
                let channel = channel_address(&op.sender, receiver, op.nonce);
                let mut payer = account_or_default(&pending, &loaded, &op.sender);
                if payer.balance < *deposit || !payer.nonce.consume(op.nonce) {
                    return None;
                }
                payer.balance -= *deposit;
                // Add the deposit to the channel's escrow (zero for a fresh
                // address). Anyone may pay into a channel; those funds simply
                // become escrow returned to the payer on close.
                let escrow = channel_escrow(&pending, &loaded, &channel)
                    .unwrap_or(0)
                    .checked_add(*deposit)?;
                pending.insert(op.sender, Some(payer));
                pending.insert(
                    channel,
                    Some(Account {
                        balance: escrow,
                        nonce: Nonce::default(),
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
                let balance = channel_escrow(&pending, &loaded, &channel)?;
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
                let mut receiver = account_or_default(&pending, &loaded, &op.sender);
                if !receiver.nonce.consume(op.nonce) {
                    return None;
                }
                apply_credit(&mut receiver, *cumulative)?;
                pending.insert(op.sender, Some(receiver));

                // Return the remainder to the payer (read after crediting the
                // receiver, so a self-channel composes correctly).
                let mut payer_account = account_or_default(&pending, &loaded, payer_key);
                apply_credit(&mut payer_account, refund)?;
                pending.insert(*payer_key, Some(payer_account));

                // Delete the settled channel so it leaves no state.
                pending.insert(channel, None);
            }
        }
    }

    Some(pending.into_iter().collect())
}
