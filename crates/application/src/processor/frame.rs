//! Callframe execution surface for precompiles.
//!
//! A [`Frame`] is the interface precompiles use to interact with on-chain
//! state during execution. Each frame is scoped to an owner address and
//! provides a narrow set of operations:
//!
//! - **Read** any declared account or storage slot ([`inspect_account`],
//!   [`inspect_storage`], [`read_storage`]).
//! - **Write** the owner's storage slots ([`write_storage`]).
//! - **Transfer** value from the owner to another account ([`transfer`]).
//! - **Call** another precompile ([`call`]).
//!
//! All operations are validated against the transaction's declared access
//! list. Undeclared accesses return [`FrameError::AccessViolation`] and
//! writes through read-only declarations return
//! [`FrameError::WriteProtection`].
//!
//! [`inspect_account`]: Frame::inspect_account
//! [`inspect_storage`]: Frame::inspect_storage
//! [`read_storage`]: Frame::read_storage
//! [`write_storage`]: Frame::write_storage
//! [`transfer`]: Frame::transfer
//! [`call`]: Frame::call

use super::{Precompiles, executor::Processor};
use crate::processor::{
    access::{AccessListBuilder, AccessSet},
    state::{FrameDiff, StateReader},
};
use bytes::Bytes;
use commonware_parallel::Strategy;
use constantinople_primitives::{AccessMode, Account, Address, Slot};
use thiserror::Error;

/// An execution halt inside a frame.
///
/// `Revert` preserves the return payload from an explicit precompile revert.
/// The other variants represent hard execution halts that abort the active
/// frame.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FrameError {
    #[error("frame reverted")]
    Revert(Bytes),
    #[error("bad transaction nonce")]
    BadTransactionNonce,
    #[error("invalid transaction target")]
    InvalidTransactionTarget,
    #[error("access outside of the declared access list")]
    AccessViolation,
    #[error("attempted write through read-only access")]
    WriteProtection,
    #[error("balance underflow")]
    BalanceUnderflow,
    #[error("balance overflow")]
    BalanceOverflow,
    #[error("maximum call depth exceeded")]
    CallDepthExceeded,
    #[error("precompile panicked")]
    PrecompilePanic,
}

/// An in-memory callframe scoped to an owner address.
///
/// Precompiles receive a `&mut Frame` and use it to read state, write
/// owner-scoped storage, transfer value, and call other precompiles. All
/// access is validated against the transaction's declared access list.
///
/// Reads resolve through: local diff → parent diffs → committed state.
pub struct Frame<'a, R: StateReader> {
    owner: Address,
    depth: u16,
    value: u64,
    input: Bytes,
    state: &'a R,
    access: &'a AccessSet,
    access_list_builder: AccessListBuilder,
    parent: Option<&'a Self>,
    diff: FrameDiff,
}

impl<R: StateReader> core::fmt::Debug for Frame<'_, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Frame")
            .field("owner", &self.owner)
            .field("depth", &self.depth)
            .field("value", &self.value)
            .field("input_len", &self.input.len())
            .field("diff", &self.diff)
            .finish_non_exhaustive()
    }
}

impl<'a, R: StateReader> Frame<'a, R> {
    /// Creates a root frame for `owner`.
    pub(crate) fn new(
        owner: Address,
        state: &'a R,
        access: &'a AccessSet,
        access_list_builder: AccessListBuilder,
        depth: u16,
        value: u64,
        input: Bytes,
    ) -> Self {
        Self {
            owner,
            depth,
            value,
            input,
            state,
            access,
            access_list_builder,
            parent: None,
            diff: FrameDiff::default(),
        }
    }

    /// Returns the frame owner.
    pub const fn owner(&self) -> Address {
        self.owner
    }

    /// Returns the call value for this frame.
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// Returns the current call depth for this frame.
    pub const fn depth(&self) -> u16 {
        self.depth
    }

    /// Returns the input bytes for this frame.
    pub const fn input(&self) -> &Bytes {
        &self.input
    }

    /// Returns the visible account value for the frame owner.
    pub(super) fn owner_account(&mut self) -> Account {
        self.account(self.owner)
    }

    /// Records a new visible account value for the frame owner.
    pub(super) fn set_owner_account(&mut self, account: Account) {
        self.set_account(self.owner, account);
    }

    /// Applies the sender nonce bump outside the revertible transaction body.
    ///
    /// The nonce increment is recorded in the prelude frame and committed
    /// immediately so it survives root-frame reverts.
    pub(super) fn bump_sender_nonce(&mut self) -> Result<(), FrameError> {
        let mut account = self.owner_account();
        account.nonce = account
            .nonce
            .checked_add(1)
            .ok_or(FrameError::BadTransactionNonce)?;
        self.set_owner_account(account);
        Ok(())
    }

    /// Returns the visible account value for `address`.
    ///
    /// Reads walk the local diff first, then parent diffs, then the committed
    /// processor state.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::AccessViolation`] if the transaction did not
    /// declare account access for `address`.
    pub fn inspect_account(&mut self, address: Address) -> Result<Account, FrameError> {
        if !self.access.can_read_account(address) {
            return Err(FrameError::AccessViolation);
        }

        Ok(self.account(address))
    }

    /// Returns the visible storage value for `(address, slot)`.
    ///
    /// Reads walk the local diff first, then parent diffs, then the committed
    /// processor state.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::AccessViolation`] if the transaction did not
    /// declare storage access for `(address, slot)`.
    pub fn inspect_storage(&mut self, address: Address, slot: Slot) -> Result<Slot, FrameError> {
        if !self.access.can_read_storage(address, slot) {
            return Err(FrameError::AccessViolation);
        }

        Ok(self.storage(address, slot))
    }

    /// Returns the visible storage value for the frame owner.
    pub fn read_storage(&mut self, slot: Slot) -> Result<Slot, FrameError> {
        self.inspect_storage(self.owner, slot)
    }

    /// Records a new visible storage value for the frame owner.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::WriteProtection`] if the transaction only
    /// declared read access for the owner's slot.
    pub fn write_storage(&mut self, slot: Slot, value: Slot) -> Result<(), FrameError> {
        if !self.access.can_write_storage(self.owner, slot) {
            return Err(FrameError::WriteProtection);
        }

        self.set_storage(self.owner, slot, value);
        Ok(())
    }

    /// Transfers value from the frame owner to `to`.
    ///
    /// Both accounts are always validated against the access list. A
    /// zero-value transfer records Read access for both accounts; a non-zero
    /// transfer records Write and moves the balance.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::AccessViolation`] if either account is not
    /// declared, [`FrameError::WriteProtection`] if a non-zero transfer
    /// targets a read-only account, or a balance error if the transfer
    /// cannot be applied.
    pub fn transfer(&mut self, to: Address, value: u64) -> Result<(), FrameError> {
        self.transfer_between(self.owner, to, value)
    }

    /// Calls another precompile from this frame.
    ///
    /// The nested call executes in a child frame owned by `to`. On success,
    /// the child diff merges into this frame. On failure, the child diff is
    /// discarded and the error bubbles back to the caller.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::InvalidTransactionTarget`] if `to` is not a
    /// precompile, [`FrameError::CallDepthExceeded`] when the processor depth
    /// limit is reached, or any error raised while executing the child call.
    pub fn call<S, P>(
        &mut self,
        processor: &Processor<'_, S, P>,
        to: Address,
        value: u64,
        input: Bytes,
    ) -> Result<Bytes, FrameError>
    where
        S: Strategy,
        P: Precompiles,
    {
        processor.call_precompile(self, to, value, input)
    }

    /// Merges a successful child diff and observed accesses into this frame.
    pub(crate) fn merge(&mut self, child: FrameDiff, child_builder: AccessListBuilder) {
        self.diff.merge(child);
        self.access_list_builder.merge(child_builder);
    }

    /// Merges only the observed accesses from a failed child into this frame.
    pub(crate) fn merge_access_list_builder(&mut self, child_builder: AccessListBuilder) {
        self.access_list_builder.merge(child_builder);
    }

    /// Consumes the frame and returns its local diff and observed accesses.
    pub(crate) fn into_parts(self) -> (FrameDiff, AccessListBuilder) {
        (self.diff, self.access_list_builder)
    }

    /// Branches into a child frame owned by `owner` with `value`.
    ///
    /// The child sees the parent's visible state but starts with an empty local
    /// diff.
    pub(super) fn branch(&self, owner: Address, value: u64, input: Bytes) -> Frame<'_, R> {
        self.child_with_depth(owner, self.depth + 1, value, input)
    }

    /// Creates a child frame with an explicit depth.
    ///
    /// The child starts with an empty access list builder and empty diff. After
    /// execution the caller merges the child's builder back into the parent.
    pub(super) fn child_with_depth(
        &self,
        owner: Address,
        depth: u16,
        value: u64,
        input: Bytes,
    ) -> Frame<'_, R> {
        Frame {
            owner,
            depth,
            value,
            input,
            state: self.state,
            access: self.access,
            access_list_builder: AccessListBuilder::default(),
            parent: Some(self),
            diff: FrameDiff::default(),
        }
    }

    /// Transfers value between two accounts inside this frame.
    ///
    /// Both accounts are always validated against the access list so the
    /// scheduler sees the dependency. A zero-value transfer records Read
    /// access; a non-zero transfer records Write.
    pub(super) fn transfer_between(
        &mut self,
        from: Address,
        to: Address,
        value: u64,
    ) -> Result<(), FrameError> {
        if !self.access.can_read_account(from) || !self.access.can_read_account(to) {
            return Err(FrameError::AccessViolation);
        }

        if value == 0 {
            // Record Read access for both accounts so the access list and
            // scheduler see the dependency even when no balance moves.
            let _ = self.account(from);
            let _ = self.account(to);
            return Ok(());
        }

        if !self.access.can_write_account(from) || !self.access.can_write_account(to) {
            return Err(FrameError::WriteProtection);
        }

        // Record the full write dependency before applying balance math so
        // proposal-time discovery and verifier-side execution agree even when
        // the transfer later reverts on underflow or overflow.
        self.record_account_access(from, AccessMode::Write);
        self.record_account_access(to, AccessMode::Write);

        if from == to {
            // Read + write records Write access without modifying state.
            let account = self.account(from);
            self.set_account(from, account);
            return Ok(());
        }

        let mut from_account = self.account(from);
        from_account.balance = from_account
            .balance
            .checked_sub(value)
            .ok_or(FrameError::BalanceUnderflow)?;

        let mut to_account = self.account(to);
        to_account.balance = to_account
            .balance
            .checked_add(value)
            .ok_or(FrameError::BalanceOverflow)?;

        self.set_account(from, from_account);
        self.set_account(to, to_account);
        Ok(())
    }

    /// Reads the visible account value for `address` and records the access.
    ///
    /// This bypasses access-list validation. Callers must validate access
    /// before using it.
    fn account(&mut self, address: Address) -> Account {
        self.record_account_access(address, AccessMode::Read);

        if let Some(account) = self.diff.account(address) {
            return account;
        }

        let mut parent = self.parent;
        while let Some(frame) = parent {
            if let Some(account) = frame.diff.account(address) {
                return account;
            }

            parent = frame.parent;
        }

        self.state.account(address)
    }

    /// Records a new visible account value for `address`.
    ///
    /// This bypasses access-list validation. Callers must validate write
    /// permission before using it.
    fn set_account(&mut self, address: Address, account: Account) {
        self.record_account_access(address, AccessMode::Write);
        let original = self.account(address);
        self.diff.set_account(address, original, account);
    }

    /// Reads the visible storage value for `(address, slot)` and records the
    /// access.
    ///
    /// This bypasses access-list validation. Callers must validate access
    /// before using it.
    fn storage(&mut self, address: Address, slot: Slot) -> Slot {
        self.record_storage_access(address, slot, AccessMode::Read);

        if let Some(value) = self.diff.storage(address, slot) {
            return value;
        }

        let mut parent = self.parent;
        while let Some(frame) = parent {
            if let Some(value) = frame.diff.storage(address, slot) {
                return value;
            }

            parent = frame.parent;
        }

        self.state.storage(address, slot)
    }

    /// Records a new visible storage value for `(address, slot)`.
    ///
    /// This bypasses access-list validation. Callers must validate write
    /// permission before using it.
    fn set_storage(&mut self, address: Address, slot: Slot, value: Slot) {
        self.record_storage_access(address, slot, AccessMode::Write);
        let original = self.storage(address, slot);
        self.diff.set_storage(address, slot, original, value);
    }

    /// Records an observed account access.
    fn record_account_access(&mut self, address: Address, mode: AccessMode) {
        self.access_list_builder.record_account(address, mode);
    }

    /// Records an observed storage access.
    fn record_storage_access(&mut self, address: Address, slot: Slot, mode: AccessMode) {
        self.access_list_builder.record_storage(address, slot, mode);
    }
}

#[cfg(test)]
mod tests {
    use super::{Frame, FrameError};
    use crate::processor::{
        access::{AccessListBuilder, AccessSet},
        keys::{account_key, storage_key},
        state::State,
    };
    use bytes::Bytes;
    use commonware_codec::{DecodeExt, FixedSize};
    use commonware_cryptography::blake3;
    use commonware_parallel::Sequential;
    use constantinople_primitives::{Access, AccessMode, Account, Address, Slot, StateValue};
    use std::collections::{BTreeMap, HashMap};

    fn address(byte: u8) -> Address {
        Address::decode(&[byte; Address::SIZE][..]).expect("address bytes should decode")
    }

    fn slot(byte: u8) -> Slot {
        Slot::from([byte; Slot::SIZE])
    }

    fn access_set(
        owner: Address,
        recipient: Address,
        owner_slot: Slot,
        child_slot: Slot,
    ) -> AccessSet {
        AccessSet::new(&[
            Access::Account(owner, AccessMode::Write),
            Access::Account(recipient, AccessMode::Write),
            Access::Storage(owner, owner_slot, AccessMode::Write),
            Access::Storage(recipient, child_slot, AccessMode::Write),
        ])
    }

    #[test]
    fn nested_frames_merge_child_changes() {
        let root_address = address(0x11);
        let child_address = address(0x22);
        let root_slot = slot(0x33);
        let child_slot = slot(0x44);

        let mut accounts = HashMap::new();
        accounts.insert(
            root_address,
            Account {
                balance: 10,
                nonce: 1,
            },
        );

        let state = State::new(accounts, HashMap::new());
        let access = access_set(root_address, child_address, root_slot, child_slot);
        let mut root = Frame::new(
            root_address,
            &state,
            &access,
            AccessListBuilder::default(),
            0,
            7,
            Bytes::new(),
        );

        assert_eq!(root.value(), 7);
        root.transfer(child_address, 5)
            .expect("root transfer should succeed");
        root.write_storage(root_slot, slot(0x55))
            .expect("root write should succeed");

        let mut child = root.branch(child_address, 9, Bytes::from_static(b"child"));
        assert_eq!(child.value(), 9);
        assert_eq!(child.input().as_ref(), b"child");
        assert_eq!(
            child
                .inspect_account(root_address)
                .expect("root account should be visible")
                .balance,
            5
        );

        child
            .write_storage(child_slot, slot(0x66))
            .expect("child write should succeed");
        child
            .transfer(root_address, 1)
            .expect("child transfer should succeed");

        let (diff, access_list_builder) = child.into_parts();
        root.merge(diff, access_list_builder);

        assert_eq!(
            root.inspect_account(root_address)
                .expect("root account should be visible")
                .balance,
            6
        );
        assert_eq!(
            root.inspect_account(child_address)
                .expect("child account should be visible")
                .balance,
            4
        );
        assert_eq!(
            root.inspect_storage(child_address, child_slot)
                .expect("child storage should be visible"),
            slot(0x66)
        );
    }

    #[test]
    fn nested_frames_drop_unmerged_child_changes() {
        let root_address = address(0x11);
        let child_address = address(0x22);
        let root_slot = slot(0x33);
        let child_slot = slot(0x44);

        let state = State::new(HashMap::new(), HashMap::new());
        let access = access_set(root_address, child_address, root_slot, child_slot);
        let mut root = Frame::new(
            root_address,
            &state,
            &access,
            AccessListBuilder::default(),
            0,
            3,
            Bytes::new(),
        );

        root.write_storage(root_slot, slot(0x77))
            .expect("root write should succeed");

        let mut child = root.branch(child_address, 5, Bytes::new());
        child
            .write_storage(child_slot, slot(0x66))
            .expect("child write should succeed");
        drop(child);

        assert_eq!(
            root.inspect_storage(root_address, root_slot)
                .expect("root storage should be visible"),
            slot(0x77)
        );
        assert_eq!(
            root.inspect_storage(child_address, child_slot)
                .expect("child storage should be visible"),
            Slot::default()
        );
    }

    #[test]
    fn frame_changeset_only_includes_persistent_changes() {
        let root_address = address(0x11);
        let child_address = address(0x22);
        let root_slot = slot(0x33);
        let child_slot = slot(0x44);

        let mut accounts = HashMap::new();
        accounts.insert(
            root_address,
            Account {
                balance: 10,
                nonce: 1,
            },
        );

        let mut storage = HashMap::new();
        storage.insert((root_address, root_slot), slot(0x55));

        let state = State::new(accounts, storage);
        let access = access_set(root_address, child_address, root_slot, child_slot);
        let mut root = Frame::new(
            root_address,
            &state,
            &access,
            AccessListBuilder::default(),
            0,
            1,
            Bytes::new(),
        );

        root.transfer(child_address, 4)
            .expect("root transfer should succeed");
        root.write_storage(root_slot, slot(0x77))
            .expect("root write should succeed");
        root.write_storage(root_slot, slot(0x55))
            .expect("root restore should succeed");

        let mut child = root.branch(child_address, 2, Bytes::new());
        child
            .write_storage(child_slot, slot(0x88))
            .expect("child write should succeed");

        // Merge child into parent and export the changeset.
        let (child_diff, child_builder) = child.into_parts();
        root.merge(child_diff, child_builder);
        let (root_diff, _) = root.into_parts();
        let strategy = Sequential;
        let frame_changeset = root_diff.changeset::<blake3::Blake3>(&strategy);

        let mut expected = BTreeMap::new();
        expected.insert(
            account_key(root_address),
            StateValue::Account(Account {
                balance: 6,
                nonce: 1,
            }),
        );
        expected.insert(
            account_key(child_address),
            StateValue::Account(Account {
                balance: 4,
                nonce: 0,
            }),
        );
        expected.insert(
            storage_key(&mut blake3::Blake3::default(), child_address, child_slot),
            StateValue::Storage(slot(0x88)),
        );

        assert_eq!(frame_changeset, expected);
    }

    #[test]
    fn undeclared_access_reverts_reads_and_writes() {
        let owner = address(0x11);
        let recipient = address(0x22);
        let owner_slot = slot(0x33);
        let other_slot = slot(0x44);

        let access = AccessSet::new(&[Access::Storage(owner, owner_slot, AccessMode::Read)]);
        let state = State::new(HashMap::new(), HashMap::new());
        let mut frame = Frame::new(
            owner,
            &state,
            &access,
            AccessListBuilder::default(),
            0,
            0,
            Bytes::new(),
        );

        assert_eq!(
            frame.inspect_storage(recipient, other_slot),
            Err(FrameError::AccessViolation)
        );
        assert_eq!(
            frame.write_storage(owner_slot, slot(0x55)),
            Err(FrameError::WriteProtection)
        );
    }
}
