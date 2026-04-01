//! In-memory processor state for transfer-only execution.

use constantinople_primitives::{Account, Address};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

/// Reads visible state values for execution.
///
/// This trait is implemented by both the fully preloaded verifier state and
/// the proposer-side lazy discovery state. Missing accounts read as the
/// default account value.
pub trait StateReader {
    /// Returns the visible account value for `address`.
    fn account(&self, address: Address) -> Account;
}

/// Tracks one value that changed during execution.
///
/// The processor keeps both the original value and the latest visible value.
/// This lets execution merge later writes while omitting values that were
/// changed and then restored back to their original state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tracked<T> {
    original: T,
    current: T,
}

impl<T> Tracked<T>
where
    T: Copy + Eq,
{
    /// Creates a tracked entry from the original and current values.
    const fn new(original: T, current: T) -> Self {
        Self { original, current }
    }

    /// Returns the latest visible value.
    const fn current(&self) -> T {
        self.current
    }

    /// Returns whether the value still differs from its original value.
    fn is_changed(&self) -> bool {
        self.original != self.current
    }
}

/// Stores the account changes produced during execution.
///
/// Each entry records both its original and current value. A value disappears
/// from the diff once it is restored to its original state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AccountDiff {
    accounts: HashMap<Address, Tracked<Account>>,
}

impl AccountDiff {
    /// Returns the changed account value for `address`, if present.
    pub(crate) fn account(&self, address: Address) -> Option<Account> {
        self.accounts.get(&address).map(Tracked::current)
    }

    /// Records an account change.
    ///
    /// If the latest value equals the original value, the tracked entry is
    /// removed so the diff contains only persistent changes.
    pub(crate) fn set_account(&mut self, address: Address, original: Account, current: Account) {
        if let Some(tracked) = self.accounts.get_mut(&address) {
            tracked.current = current;

            if !tracked.is_changed() {
                self.accounts.remove(&address);
            }
            return;
        }

        if original == current {
            return;
        }

        self.accounts
            .insert(address, Tracked::new(original, current));
    }

    /// Merges another diff into this diff.
    pub(crate) fn merge(&mut self, child: Self) {
        for (address, tracked) in child.accounts {
            self.set_account(address, tracked.original, tracked.current);
        }
    }

    /// Produces a deterministic changeset for the changed accounts in this diff.
    pub(crate) fn changeset(&self) -> BTreeMap<Address, Account> {
        self.accounts
            .iter()
            .map(|(address, tracked)| (*address, tracked.current()))
            .collect()
    }
}

/// In-memory processor state.
///
/// `State` combines the loaded base state with the committed in-memory diff
/// accumulated during execution. Reads first consult the committed diff and
/// then fall back to the loaded base state.
///
/// The base maps are `Arc`-wrapped so that `State::clone()` is a cheap
/// reference-count bump rather than a deep copy. The base maps are read-only
/// during execution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    base_accounts: Arc<HashMap<Address, Account>>,
    diff: AccountDiff,
}

impl State {
    /// Creates in-memory processor state from loaded accounts.
    pub fn new(base_accounts: HashMap<Address, Account>) -> Self {
        Self {
            base_accounts: Arc::new(base_accounts),
            diff: AccountDiff::default(),
        }
    }

    /// Returns the visible account value for `address`.
    ///
    /// Missing accounts read as the default account value.
    pub(crate) fn account(&self, address: Address) -> Account {
        if let Some(account) = self.diff.account(address) {
            return account;
        }

        self.base_accounts
            .get(&address)
            .copied()
            .unwrap_or_default()
    }

    /// Commits an execution diff into the state.
    pub(crate) fn apply(&mut self, diff: AccountDiff) {
        self.diff.merge(diff);
    }

    /// Produces a deterministic changeset for the committed state diff.
    pub(crate) fn changeset(&self) -> BTreeMap<Address, Account> {
        self.diff.changeset()
    }
}

impl StateReader for State {
    fn account(&self, address: Address) -> Account {
        Self::account(self, address)
    }
}

/// Proposal-time state with lazy base reads.
///
/// `DiscoveryState` wraps another [`StateReader`] and caches every base read
/// on demand. The proposer executes sequentially over this state to build the
/// final account changeset without preloading the entire block footprint up
/// front.
#[derive(Debug)]
pub struct DiscoveryState<R: StateReader> {
    reader: R,
    base_accounts: RefCell<HashMap<Address, Account>>,
    diff: AccountDiff,
}

impl<R: StateReader> DiscoveryState<R> {
    /// Creates an empty lazy state backed by `reader`.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            base_accounts: RefCell::new(HashMap::new()),
            diff: AccountDiff::default(),
        }
    }

    /// Commits an execution diff into the state.
    pub(crate) fn apply(&mut self, diff: AccountDiff) {
        self.diff.merge(diff);
    }

    /// Produces a deterministic changeset for the committed state diff.
    pub(crate) fn changeset(&self) -> BTreeMap<Address, Account> {
        self.diff.changeset()
    }

    fn load_account(&self, address: Address) -> Account {
        if let Some(account) = self.diff.account(address) {
            return account;
        }

        if let Some(account) = self.base_accounts.borrow().get(&address).copied() {
            return account;
        }

        let loaded = self.reader.account(address);
        self.base_accounts.borrow_mut().insert(address, loaded);
        loaded
    }
}

impl<R: StateReader> StateReader for DiscoveryState<R> {
    fn account(&self, address: Address) -> Account {
        self.load_account(address)
    }
}
