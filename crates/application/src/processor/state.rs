//! In-memory processor state.

use super::executor::Changeset;
use constantinople_primitives::{Account, Address};
use std::collections::BTreeMap;

/// Fully loaded account state for one execution batch.
pub type State = BTreeMap<Address, Account>;

/// Mutable overlay on top of a base [`State`] snapshot.
///
/// Reads fall through to the base when an address has not been modified.
/// Only modified accounts are stored, so the changeset is the overlay itself.
#[derive(Debug)]
pub(crate) struct Overlay<'a> {
    base: &'a State,
    overlay: BTreeMap<Address, Account>,
}

impl<'a> Overlay<'a> {
    /// Creates an overlay on top of the given base state.
    pub(crate) fn new(base: &'a State) -> Self {
        Self {
            base,
            overlay: BTreeMap::new(),
        }
    }

    /// Returns the current account for `address` (overlay first, then base).
    pub(crate) fn get(&self, address: &Address) -> Option<&Account> {
        self.overlay.get(address).or_else(|| self.base.get(address))
    }

    /// Returns a mutable reference to the account for `address`.
    ///
    /// Copies the account from base into the overlay on first mutation.
    pub(crate) fn get_mut(&mut self, address: &Address) -> Option<&mut Account> {
        if !self.overlay.contains_key(address) {
            let account = *self.base.get(address)?;
            self.overlay.insert(*address, account);
        }
        self.overlay.get_mut(address)
    }

    /// Returns the overlay as the changeset.
    pub(crate) fn into_changeset(self) -> Changeset {
        self.overlay.into_iter().collect()
    }
}
