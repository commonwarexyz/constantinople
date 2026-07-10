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
//! payer and funds the channel account; closing it verifies a voucher signed
//! by the channel's delegated voucher key and splits the escrow between
//! receiver and payer; once the block height
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
//! (`H(domain || payer || receiver || operator || voucher_key || open_nonce)`).
//! Because account nonces are
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
//! - Vouchers are signed by the delegated Ed25519 `voucher_key` an open
//!   names, so any account — including one whose own key cannot sign
//!   unattended (a WebAuthn passkey) — can be a payer. An open naming a key
//!   nobody controls locks its deposit until the expiry timeout; that is the
//!   payer's own mistake to make.
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
use crate::executor::saturating_credit;
use ahash::AHashMap;
use commonware_cryptography::{Hasher, ed25519};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::translator::EightCap;
use constantinople_primitives::{
    Account, AccountKey, Nonce, Operation, SignedTransaction, channel_address, verify_voucher,
};

/// Account writes a channel-operation batch produces, in no particular order.
///
/// `Some(account)` upserts; `None` deletes the account, which is how a settled
/// channel is removed so it leaves no state behind.
pub(super) type ChannelWrites = Vec<(AccountKey, Option<Account>)>;

/// A channel operation prepared for execution.
#[derive(Debug, Clone)]
pub struct PreparedChannelOp {
    /// The transaction sender's account key (payer for open and timeout,
    /// operator for close).
    pub sender: AccountKey,
    /// The sender nonce this operation consumes. For an open it also derives
    /// the channel address (stored on the kind at preparation time).
    pub nonce: u64,
    /// Operation-specific payload.
    pub kind: PreparedChannelOpKind,
}

/// Operation-specific payload for a [`PreparedChannelOp`].
///
/// Each variant keeps only what execution reads. The transaction fields
/// that merely feed the channel-address derivation (receiver, operator, and
/// the open nonce) are consumed at preparation time and travel on as the
/// derived `channel` — the address commits to all of them.
// The size skew (a close carries a key and a signature, a mint a u64) is
// accepted: prepared ops live in a short per-block scratch vec, so boxing
// the close would trade a few stack bytes for an allocation per operation.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum PreparedChannelOpKind {
    /// Open a channel from the sender (payer).
    Open {
        /// Amount escrowed.
        deposit: u64,
        /// Block height after which the payer may reclaim the escrow.
        expiry: u64,
        /// Derived channel address, computed once at preparation.
        channel: AccountKey,
    },
    /// Close a channel, settling the latest voucher. The sender is the
    /// operator; the cumulative is paid to `receiver`.
    Close {
        /// Payer account key (the refund destination).
        payer: AccountKey,
        /// Receiver (payee) account key the cumulative is paid to.
        receiver: AccountKey,
        /// Delegated voucher key the signature is verified against.
        voucher_key: ed25519::PublicKey,
        /// Cumulative amount claimed.
        cumulative: u64,
        /// Voucher key's signature.
        voucher: ed25519::Signature,
        /// Derived channel address, computed once at preparation.
        channel: AccountKey,
    },
    /// Reclaim an expired channel's escrow for the sender (payer).
    Timeout {
        /// Derived channel address, computed once at preparation.
        channel: AccountKey,
    },
    /// Mint new tokens to the sender (this lane also executes the chain's
    /// non-transfer bookkeeping operations).
    Mint {
        /// Amount credited to the sender.
        amount: u64,
    },
}

/// Prepares a channel operation from a signed transaction.
///
/// Returns `None` if the sender public key fails to decode or the transaction
/// is a transfer (which belongs to the other lane). Any account may open a
/// channel: vouchers are signed by the delegated `voucher_key` the open
/// names, not by the payer's own key.
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
            operator,
            voucher_key,
            deposit,
            expiry,
        } => PreparedChannelOpKind::Open {
            deposit: deposit.get(),
            expiry: *expiry,
            channel: channel_address(&sender, receiver, operator, voucher_key, tx.nonce),
        },
        Operation::CloseChannel {
            payer,
            receiver,
            voucher_key,
            open_nonce,
            cumulative,
            voucher,
        } => PreparedChannelOpKind::Close {
            payer: *payer,
            receiver: *receiver,
            voucher_key: voucher_key.clone(),
            cumulative: *cumulative,
            voucher: voucher.clone(),
            channel: channel_address(payer, receiver, &sender, voucher_key, *open_nonce),
        },
        Operation::TimeoutChannel {
            receiver,
            operator,
            voucher_key,
            open_nonce,
        } => PreparedChannelOpKind::Timeout {
            channel: channel_address(&sender, receiver, operator, voucher_key, *open_nonce),
        },
        Operation::Mint { amount } => PreparedChannelOpKind::Mint {
            amount: amount.get(),
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
/// (or this-block-deleted) account reads as empty.
fn account_or_default(pending: &Pending, loaded: &Pending, key: &AccountKey) -> Account {
    channel_account(pending, loaded, key).unwrap_or_default()
}

/// Returns the channel account at `key`, or `None` if no channel lives there.
///
/// Unlike [`account_or_default`], a never-written address reads as absent
/// rather than an empty account, so closing or timing out a nonexistent
/// channel is rejected. The account's balance is the escrow; its (otherwise
/// unusable) nonce base stores the channel's expiry.
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

impl PreparedChannelOp {
    /// Appends every account key this operation reads or writes — a static
    /// superset of its writes, so the proposer can drop operations that would
    /// conflict with the transfer lane without executing them.
    pub(super) fn touched_keys(&self, keys: &mut Vec<AccountKey>) {
        keys.push(self.sender);
        match &self.kind {
            PreparedChannelOpKind::Open { channel, .. } => {
                keys.push(*channel);
            }
            PreparedChannelOpKind::Close {
                payer,
                receiver,
                channel,
                ..
            } => {
                keys.push(*payer);
                keys.push(*receiver);
                keys.push(*channel);
            }
            PreparedChannelOpKind::Timeout { channel } => {
                keys.push(*channel);
            }
            // A mint touches only the sender, already pushed above.
            PreparedChannelOpKind::Mint { .. } => {}
        }
    }
}

/// Collects every account key a batch of channel operations reads or writes.
fn channel_op_keys(channel_ops: &[PreparedChannelOp]) -> Vec<AccountKey> {
    let mut keys = Vec::with_capacity(channel_ops.len() * 4);
    for op in channel_ops {
        op.touched_keys(&mut keys);
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
            deposit,
            expiry,
            channel,
            ..
        } => {
            let mut payer = account_or_default(pending, loaded, &op.sender);
            if payer.balance < *deposit || !payer.nonce.consume(op.nonce) {
                return None;
            }
            payer.balance -= *deposit;
            // Add the deposit to the channel's escrow (zero for a fresh
            // address). Anyone may pay into a channel; those funds simply
            // become escrow returned to the payer on close.
            let escrow = channel_escrow(pending, loaded, channel)
                .unwrap_or(0)
                .checked_add(*deposit)?;
            pending.insert(op.sender, Some(payer));
            // A channel address can never sign a transaction, so its nonce
            // slot is repurposed to store the expiry.
            pending.insert(
                *channel,
                Some(Account {
                    balance: escrow,
                    nonce: Nonce::new(*expiry, 0),
                }),
            );
        }
        PreparedChannelOpKind::Close {
            payer,
            receiver,
            voucher_key,
            cumulative,
            voucher,
            channel,
            ..
        } => {
            // The channel must exist (it was opened by a prior transaction).
            let balance = channel_escrow(pending, loaded, channel)?;
            // Verify the voucher over (channel, cumulative). The address
            // commits to (payer, receiver, operator, voucher_key, open_nonce),
            // so a valid voucher also proves this close's sender is the
            // channel's operator, its receiver field is the channel's payee,
            // and its voucher key is the one the payer delegated.
            if !verify_voucher(voucher_key, channel, *cumulative, voucher) {
                return None;
            }
            // Can never claim more than what is escrowed.
            if *cumulative > balance {
                return None;
            }
            let refund = balance - *cumulative;

            // Consume the operator's (sender's) nonce. Nothing touches
            // `pending` until every check has passed.
            let mut operator_account = account_or_default(pending, loaded, &op.sender);
            if !operator_account.nonce.consume(op.nonce) {
                return None;
            }
            pending.insert(op.sender, Some(operator_account));

            // Pay the receiver, then refund the payer. Each credit re-reads
            // through `pending`, so aliasing among operator, receiver, and
            // payer (a payee-run channel has operator == receiver; a
            // self-channel has payer == receiver) composes instead of one
            // write clobbering another.
            //
            // A zero-cumulative close (a cooperative early cancel) pays the
            // receiver nothing; skip the write so a never-funded receiver is
            // not materialized as an empty account (execution never writes
            // one — see `apply_channel_writes`).
            if *cumulative > 0 {
                let mut receiver_account = account_or_default(pending, loaded, receiver);
                saturating_credit(&mut receiver_account, *cumulative);
                pending.insert(*receiver, Some(receiver_account));
            }

            let mut payer_account = account_or_default(pending, loaded, payer);
            saturating_credit(&mut payer_account, refund);
            pending.insert(*payer, Some(payer_account));

            // Delete the settled channel so it leaves no state.
            pending.insert(*channel, None);
        }
        PreparedChannelOpKind::Timeout { channel } => {
            // The channel must exist and its expiry (stored in the channel
            // account's nonce base) must have passed. A receiver close that
            // landed first deleted the channel, so first-to-land wins.
            let account = channel_account(pending, loaded, channel)?;
            if height <= account.nonce.base {
                return None;
            }

            // Reclaim the entire escrow for the payer (the sender of this
            // transaction) and consume its nonce.
            let mut payer = account_or_default(pending, loaded, &op.sender);
            if !payer.nonce.consume(op.nonce) {
                return None;
            }
            saturating_credit(&mut payer, account.balance);
            pending.insert(op.sender, Some(payer));

            // Delete the reclaimed channel so it leaves no state.
            pending.insert(*channel, None);
        }
        PreparedChannelOpKind::Mint { amount } => {
            let mut account = account_or_default(pending, loaded, &op.sender);
            if !account.nonce.consume(op.nonce) {
                return None;
            }
            saturating_credit(&mut account, *amount);
            pending.insert(op.sender, Some(account));
        }
    }
    Some(())
}

/// Applies a batch of channel operations against block-start state, skipping
/// any operation that fails instead of rejecting the whole batch.
///
/// This is the single execution semantics for the channel lane; whether a
/// skipped operation is tolerated is the caller's policy. A channel
/// operation's validity can depend on execution-time state the mempool cannot
/// screen (a voucher is only checkable against live escrow), so the proposer
/// uses the flags to drop failing operations from the body — one bad operation
/// cannot poison an entire proposal — while verification rejects any block
/// whose flags are not all set (see `execution::execute_lanes`). Verifiers
/// therefore re-execute exactly the applied sequence the proposer kept.
///
/// Returns the resulting writes (deletions included) plus one applied/skipped
/// flag per operation.
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
