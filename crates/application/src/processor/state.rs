//! In-memory processor state.

use super::executor::Changeset;
use commonware_cryptography::PublicKey;
use constantinople_primitives::{Account, AccountKey};
use hashbrown::HashMap;

/// Fully loaded account state for one execution batch.
pub type State<P> = HashMap<AccountKey<P>, Account>;

/// Mutable overlay on top of a base [`State`] snapshot.
///
/// Reads fall through to the base when an account key has not been modified.
/// Only modified accounts are stored, so the changeset is the overlay itself.
#[derive(Debug)]
pub(crate) struct Overlay<'a, P>
where
    P: PublicKey,
{
    base: &'a State<P>,
    overlay: HashMap<AccountKey<P>, Account>,
}

impl<'a, P> Overlay<'a, P>
where
    P: PublicKey,
{
    /// Creates an overlay on top of the given base state.
    pub(crate) fn with_capacity(base: &'a State<P>, capacity: usize) -> Self {
        Self {
            base,
            overlay: HashMap::with_capacity(capacity),
        }
    }

    /// Returns a copy of the current account for `account_key`.
    pub(crate) fn get(&self, account_key: &AccountKey<P>) -> Option<Account> {
        self.overlay
            .get(account_key)
            .or_else(|| self.base.get(account_key))
            .copied()
    }

    /// Stores the current account value for `account_key`.
    pub(crate) fn set(&mut self, account_key: AccountKey<P>, account: Account) {
        self.overlay.insert(account_key, account);
    }

    /// Returns the overlay as a deterministically ordered changeset.
    pub(crate) fn into_changeset(self) -> Changeset<P> {
        let mut changeset: Changeset<P> = self.overlay.into_iter().collect();
        changeset.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        changeset
    }
}
