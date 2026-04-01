//! In-memory processor state for transfer-only execution.

use super::executor::Changeset;
use constantinople_primitives::{Account, Address};
use std::{collections::HashMap, sync::Arc};

/// Fully loaded account state for one execution batch.
///
/// The loaded accounts are stored in deterministic address order so later
/// changeset export can walk a dense array instead of rebuilding order through
/// a tree or hash map.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    addresses: Arc<Vec<Address>>,
    accounts: Arc<Vec<Account>>,
    indices: Arc<HashMap<Address, usize>>,
}

impl State {
    /// Creates in-memory processor state from loaded accounts.
    pub fn new(base_accounts: HashMap<Address, Account>) -> Self {
        let loaded_addresses = base_accounts.keys().copied().collect::<Vec<_>>();
        Self::from_loaded(base_accounts, loaded_addresses)
    }

    /// Creates state from `loaded_addresses` and the known `base_accounts`.
    ///
    /// Any loaded address missing from `base_accounts` is treated as the
    /// default empty account.
    pub(crate) fn from_loaded(
        base_accounts: HashMap<Address, Account>,
        mut loaded_addresses: Vec<Address>,
    ) -> Self {
        loaded_addresses.sort_unstable();
        loaded_addresses.dedup();

        let mut accounts = Vec::with_capacity(loaded_addresses.len());
        let mut indices = HashMap::with_capacity(loaded_addresses.len());

        for (index, address) in loaded_addresses.iter().copied().enumerate() {
            indices.insert(address, index);
            accounts.push(base_accounts.get(&address).copied().unwrap_or_default());
        }

        Self {
            addresses: Arc::new(loaded_addresses),
            accounts: Arc::new(accounts),
            indices: Arc::new(indices),
        }
    }

    /// Returns the base account at `index`.
    pub(crate) fn account_at(&self, index: usize) -> Account {
        self.accounts[index]
    }

    /// Returns the dense account index for `address`, if loaded.
    pub(crate) fn index(&self, address: Address) -> Option<usize> {
        self.indices.get(&address).copied()
    }

    /// Returns the base account value for `address`.
    ///
    /// Missing accounts read as the default account value.
    #[cfg(test)]
    pub(crate) fn account(&self, address: Address) -> Account {
        self.indices
            .get(&address)
            .copied()
            .map(|index| self.account_at(index))
            .unwrap_or_default()
    }

    /// Returns the address at `index`.
    pub(crate) fn address_at(&self, index: usize) -> Address {
        self.addresses[index]
    }

    /// Returns the number of loaded accounts.
    pub(crate) fn len(&self) -> usize {
        self.accounts.len()
    }
}

/// Mutable account state used during one execution pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkingState {
    base: State,
    accounts: Vec<Account>,
    changed: Vec<bool>,
}

impl WorkingState {
    /// Creates mutable execution state from a loaded base snapshot.
    pub(crate) fn new(base: State) -> Self {
        let account_count = base.len();
        let accounts = base.accounts.as_ref().clone();

        Self {
            base,
            accounts,
            changed: vec![false; account_count],
        }
    }

    /// Returns the dense account index for `address`, if loaded.
    pub(crate) fn index(&self, address: Address) -> Option<usize> {
        self.base.index(address)
    }

    /// Returns the current account snapshot.
    pub(crate) fn accounts(&self) -> &[Account] {
        &self.accounts
    }

    /// Sets the current account at `index`.
    pub(crate) fn set_account(&mut self, index: usize, account: Account) {
        self.accounts[index] = account;
        self.changed[index] = account != self.base.account_at(index);
    }

    /// Applies one account update effect.
    pub(crate) fn apply_effect(&mut self, effect: AccountEffect) {
        self.set_account(effect.index, effect.account);
    }

    /// Applies a transfer effect.
    pub(crate) fn apply_transfer(&mut self, effect: TransferEffect) {
        self.apply_effect(effect.sender);

        if let Some(recipient) = effect.recipient {
            self.apply_effect(recipient);
        }
    }

    /// Exports the deterministic account changeset.
    pub(crate) fn changeset(&self) -> Changeset {
        let changed_accounts = self.changed.iter().filter(|changed| **changed).count();
        let mut changeset = Vec::with_capacity(changed_accounts);

        for (index, changed) in self.changed.iter().copied().enumerate() {
            if !changed {
                continue;
            }

            changeset.push((self.base.address_at(index), self.accounts[index]));
        }

        changeset
    }
}

/// One account update produced by transaction execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AccountEffect {
    pub(crate) index: usize,
    pub(crate) account: Account,
}

/// The account updates produced by one transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TransferEffect {
    pub(crate) sender: AccountEffect,
    pub(crate) recipient: Option<AccountEffect>,
}
