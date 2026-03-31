//! In-memory transaction processing.
//!
//! This module owns the processor entrypoint that executes signed
//! transactions over a prebuilt in-memory [`State`] snapshot. Processing has
//! five stages:
//!
//! - load or otherwise construct the in-memory [`State`] snapshot
//! - statically validate each transaction against the visible in-memory state
//! - greedily schedule transactions into dependency rounds from the declared
//!   access lists
//! - execute those rounds and merge the results back into committed state in
//!   transaction order
//! - export the final persistent changeset for database application
//!
//! The processor does not mutate the backing store directly. Instead callers
//! first prepare a [`State`] from whatever source they have available, then
//! execute against that isolated in-memory overlay and export a deterministic
//! changeset once execution is complete.
//!
//! The processor itself is intentionally agnostic to where the state snapshot
//! came from.
//!
//! Nested precompile execution is modeled with [`Frame`]s. The frame and state
//! internals live in the sibling `frame` and `state` modules.
//!
//! The greedy round scheduler and adaptive execution policy live in the
//! sibling `schedule` module so the processor entrypoint can stay focused on
//! transaction semantics.

use bytes::Bytes;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use constantinople_primitives::{
    AccessList, Address, Receipt, ReceiptStatus, Slot, StateValue, VerifiedTransaction,
};
pub use frame::{Frame, FrameError};
use schedule::TransactionExecution;
#[cfg(feature = "bench")]
pub use schedule::{ExecutedPrepared, PreparedExecution};
pub use state::State;
use state::{AccessListBuilder, AccessSet, FrameDiff};
use std::{
    collections::BTreeMap,
    panic::{AssertUnwindSafe, catch_unwind},
};

mod frame;
mod schedule;
pub(crate) mod state;
#[cfg(test)]
mod tests;

const MAX_CALL_DEPTH: u16 = 64;

/// A precompile registry and executor.
pub trait Precompiles: Sync {
    /// Returns whether `address` is a precompile entrypoint.
    fn is_precompile(&self, address: Address) -> bool;

    /// Executes the precompile at `address` inside `frame`.
    fn execute<S>(
        &self,
        address: Address,
        frame: &mut Frame<'_>,
        processor: &Processor<'_, S, Self>,
    ) -> Result<Bytes, FrameError>
    where
        S: Strategy,
        Self: Sized;
}

/// The final result of processing a set of transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessorOutput<D: Digest> {
    /// Receipts in transaction order.
    pub receipts: Vec<Receipt<D>>,
    /// Persistent database writes produced by the processed transactions.
    pub changeset: BTreeMap<Slot, StateValue>,
    /// Optionally built access lists for the processed transactions.
    ///
    /// This field is `None` unless access-list building is enabled on the
    /// processor. When enabled, successful transactions produce
    /// `Some(access_list)` and reverted transactions produce `None`.
    pub access_lists: Option<Vec<Option<AccessList>>>,
}

/// Executes transactions against the in-memory processor state.
///
/// The processor uses the declared transaction access lists to build greedy
/// dependency rounds. Each round executes against the same committed state
/// snapshot, and the resulting receipts and diffs are merged back into the
/// processor state in the original transaction order.
pub struct Processor<'a, S, P>
where
    S: Strategy,
    P: Precompiles,
{
    strategy: &'a S,
    precompiles: &'a P,
    access_list_builder: bool,
}

impl<S, P> core::fmt::Debug for Processor<'_, S, P>
where
    S: Strategy,
    P: Precompiles,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Processor").finish_non_exhaustive()
    }
}

impl<'a, S, P> Processor<'a, S, P>
where
    S: Strategy,
    P: Precompiles + Sync,
{
    /// Creates a processor over a prebuilt in-memory state snapshot.
    ///
    /// State preparation is kept separate from the processor so callers can build
    /// [`State`] from a database batch, a proof witness, or any other source.
    /// The processor only needs the execution strategy and precompile registry.
    pub const fn new(strategy: &'a S, precompiles: &'a P) -> Self {
        Self {
            strategy,
            precompiles,
            access_list_builder: false,
        }
    }

    /// Enables access-list collection during execution.
    ///
    /// Successful transactions will return the observed access list in
    /// [`ProcessorOutput::access_lists`].
    pub const fn with_access_list_builder(mut self) -> Self {
        self.access_list_builder = true;
        self
    }

    /// Prepares `transactions` for repeated execution from `state`.
    ///
    /// This captures the loaded in-memory state snapshot and computes the
    /// greedy dependency schedule once so callers such as benchmarks can reuse
    /// the same preparation across repeated runs.
    #[cfg(feature = "bench")]
    pub fn prepare<H, PK>(
        &self,
        state: State,
        transactions: &[VerifiedTransaction<PK, H>],
    ) -> PreparedExecution
    where
        H: Hasher,
        PK: PublicKey,
    {
        self.prepare_inner(state, transactions)
    }

    /// Executes transactions from a previously prepared in-memory snapshot.
    #[cfg(feature = "bench")]
    pub fn process_prepared<H, PK>(
        &self,
        prepared: &PreparedExecution,
        transactions: &[VerifiedTransaction<PK, H>],
    ) -> ProcessorOutput<H::Digest>
    where
        H: Hasher,
        PK: PublicKey,
    {
        self.process_prepared_inner(prepared, transactions)
    }

    /// Executes transactions from a previously prepared in-memory snapshot
    /// without exporting a persistent changeset.
    ///
    /// This exists for benchmarking the execution path in isolation from final
    /// changeset hashing and export.
    #[cfg(feature = "bench")]
    pub fn execute_prepared<H, PK>(
        &self,
        prepared: &PreparedExecution,
        transactions: &[VerifiedTransaction<PK, H>],
    ) -> ExecutedPrepared<H::Digest>
    where
        H: Hasher,
        PK: PublicKey,
    {
        schedule::execute_prepared(
            self.strategy,
            prepared,
            transactions,
            self.access_list_builder,
            |state, transaction, access, access_list_builder| {
                self.execute_transaction(state, transaction, access, access_list_builder)
            },
        )
    }

    /// Processes `transactions` against `state` and returns receipts plus the
    /// final state diff.
    ///
    /// The processor greedily partitions the transactions into dependency
    /// rounds. Transactions inside one round execute through the configured
    /// [`Strategy`] against the same committed state snapshot.
    ///
    /// After each round finishes, the processor merges the round's local diffs
    /// back into committed state in the original transaction order, so receipt
    /// reporting and final state remain deterministic. Root frame reverts
    /// preserve the sender nonce bump but discard the rest of the transaction
    /// diff.
    pub fn process<H, PK>(
        &self,
        state: State,
        transactions: &[VerifiedTransaction<PK, H>],
    ) -> ProcessorOutput<H::Digest>
    where
        H: Hasher,
        PK: PublicKey,
    {
        let prepared = self.prepare_inner(state, transactions);
        self.process_prepared_inner(&prepared, transactions)
    }

    fn prepare_inner<H, PK>(
        &self,
        state: State,
        transactions: &[VerifiedTransaction<PK, H>],
    ) -> schedule::PreparedExecution
    where
        H: Hasher,
        PK: PublicKey,
    {
        schedule::prepare(state, transactions, transaction_access_set::<H, PK>)
    }

    fn process_prepared_inner<H, PK>(
        &self,
        prepared: &schedule::PreparedExecution,
        transactions: &[VerifiedTransaction<PK, H>],
    ) -> ProcessorOutput<H::Digest>
    where
        H: Hasher,
        PK: PublicKey,
    {
        schedule::execute(
            self.strategy,
            prepared,
            transactions,
            self.access_list_builder,
            |state, transaction, access, access_list_builder| {
                self.execute_transaction(state, transaction, access, access_list_builder)
            },
        )
    }

    /// Filters static-invalid transactions and executes the survivors.
    ///
    /// This path is intended for proposal. Transactions that fail static
    /// validation are dropped before block construction, while transactions
    /// that revert at runtime are retained. The execution results are returned
    /// alongside the filtered transactions so callers can skip a redundant
    /// re-execution pass.
    pub fn filter_and_execute<H, PK>(
        &self,
        mut state: State,
        transactions: &[VerifiedTransaction<PK, H>],
    ) -> (Vec<VerifiedTransaction<PK, H>>, ProcessorOutput<H::Digest>)
    where
        H: Hasher,
        PK: PublicKey,
        VerifiedTransaction<PK, H>: Clone,
    {
        let mut filtered = Vec::with_capacity(transactions.len());
        let mut receipts = Vec::with_capacity(transactions.len());

        for transaction in transactions {
            let access = transaction_access_set(transaction);
            if self
                .validate_transaction(&state, transaction, &access)
                .is_err()
            {
                continue;
            }

            let result = self.execute_validated_transaction(&state, transaction, &access, None);
            receipts.push(result.receipt);
            state.apply(result.diff);
            filtered.push(transaction.clone());
        }

        let changeset = state.changeset::<H>(self.strategy);
        let output = ProcessorOutput {
            receipts,
            changeset,
            access_lists: None,
        };
        (filtered, output)
    }

    /// Returns whether every transaction passes static validation.
    ///
    /// This path is intended for block verification. Later transactions are
    /// validated against the state produced by earlier statically valid
    /// transactions, including nonce bumps from runtime reverts.
    pub fn all_statically_valid<H, PK>(
        &self,
        mut state: State,
        transactions: &[VerifiedTransaction<PK, H>],
    ) -> bool
    where
        H: Hasher,
        PK: PublicKey,
    {
        for transaction in transactions {
            let access = transaction_access_set(transaction);
            if self
                .validate_transaction(&state, transaction, &access)
                .is_err()
            {
                return false;
            }

            let result = self.execute_validated_transaction(&state, transaction, &access, None);
            state.apply(result.diff);
        }

        true
    }

    /// Validates and executes one transaction, producing its receipt.
    ///
    /// This method performs static checks, applies the non-revertible sender
    /// nonce bump, executes the transaction body, and then converts the root
    /// result into a [`Receipt`].
    ///
    fn execute_transaction<H, PK>(
        &self,
        state: &State,
        transaction: &VerifiedTransaction<PK, H>,
        access: &AccessSet,
        access_list_builder: Option<AccessListBuilder>,
    ) -> TransactionExecution<H::Digest>
    where
        H: Hasher,
        PK: PublicKey,
    {
        if self
            .validate_transaction(state, transaction, access)
            .is_err()
        {
            return TransactionExecution {
                receipt: Receipt::revert(*transaction.message_digest(), Bytes::new()),
                diff: FrameDiff::default(),
                access_list: None,
            };
        }

        self.execute_validated_transaction(state, transaction, access, access_list_builder)
    }

    /// Executes one transaction after static validation has already succeeded.
    ///
    /// This helper assumes the transaction has passed static checks and only
    /// needs to handle nonce bumping, runtime execution, and receipt
    /// construction.
    fn execute_validated_transaction<H, PK>(
        &self,
        state: &State,
        transaction: &VerifiedTransaction<PK, H>,
        access: &AccessSet,
        access_list_builder: Option<AccessListBuilder>,
    ) -> TransactionExecution<H::Digest>
    where
        H: Hasher,
        PK: PublicKey,
    {
        let sender = transaction_sender::<H, PK>(transaction);
        let mut prelude = Frame::new(
            sender,
            state,
            access,
            access_list_builder,
            0,
            0,
            Bytes::new(),
        );
        if self.bump_sender_nonce(&mut prelude).is_err() {
            return TransactionExecution {
                receipt: Receipt::revert(*transaction.message_digest(), Bytes::new()),
                diff: FrameDiff::default(),
                access_list: None,
            };
        }

        let tx = transaction.value();
        let mut root = prelude.child_with_depth(sender, 0, 0, Bytes::new());
        let result = if self.precompiles.is_precompile(tx.to) {
            root.call(self, tx.to, tx.value, tx.input.clone())
        } else {
            root.transfer(tx.to, tx.value).map(|()| Bytes::new())
        };

        match result {
            Ok(return_data) => {
                let (diff, access_list_builder) = root.into_parts();
                prelude.merge(diff, access_list_builder);
                let (diff, access_list_builder) = prelude.into_parts();
                TransactionExecution {
                    receipt: Receipt::new(
                        *transaction.message_digest(),
                        ReceiptStatus::Success,
                        return_data,
                    ),
                    diff,
                    access_list: access_list_builder.map(AccessListBuilder::into_access_list),
                }
            }
            Err(err) => {
                let payload = match err {
                    FrameError::Revert(p) => p,
                    _ => Bytes::new(),
                };
                let (diff, _) = prelude.into_parts();
                TransactionExecution {
                    receipt: Receipt::revert(*transaction.message_digest(), payload),
                    diff,
                    access_list: None,
                }
            }
        }
    }

    /// Performs static transaction checks against the current visible state.
    ///
    /// Today this verifies the sender nonce, available balance for the call
    /// value, and that transactions with input target a registered precompile.
    ///
    fn validate_transaction<H, PK>(
        &self,
        state: &State,
        transaction: &VerifiedTransaction<PK, H>,
        access: &AccessSet,
    ) -> Result<(), FrameError>
    where
        H: Hasher,
        PK: PublicKey,
    {
        if !state.access_is_valid(access) {
            return Err(FrameError::AccessViolation);
        }

        let sender = transaction_sender::<H, PK>(transaction);
        let tx = transaction.value();
        let sender_account = state.account(sender);

        if sender_account.nonce != tx.nonce {
            return Err(FrameError::BadTransactionNonce);
        }

        if sender_account.nonce == u64::MAX {
            return Err(FrameError::BadTransactionNonce);
        }

        if sender_account.balance < tx.value {
            return Err(FrameError::BalanceUnderflow);
        }

        if !self.precompiles.is_precompile(tx.to) && !tx.input.is_empty() {
            return Err(FrameError::InvalidTransactionTarget);
        }

        Ok(())
    }

    /// Applies the sender nonce bump outside the revertible transaction body.
    ///
    /// The nonce increment is recorded in a small prelude frame and committed
    /// immediately into the in-memory state so it survives root-frame reverts.
    ///
    fn bump_sender_nonce(&self, prelude: &mut Frame<'_>) -> Result<(), FrameError> {
        let mut account = prelude.owner_account();
        account.nonce = account
            .nonce
            .checked_add(1)
            .ok_or(FrameError::BadTransactionNonce)?;
        prelude.set_owner_account(account);
        Ok(())
    }

    /// Executes a nested precompile call from `frame`.
    ///
    /// Successful child calls merge their diffs into the parent frame.
    /// Reverted or halted child calls discard their state diff but still
    /// propagate any observed accesses.
    fn call_precompile(
        &self,
        frame: &mut Frame<'_>,
        to: Address,
        value: u64,
        input: Bytes,
    ) -> Result<Bytes, FrameError> {
        if frame.depth() == MAX_CALL_DEPTH {
            return Err(FrameError::CallDepthExceeded);
        }

        if !self.precompiles.is_precompile(to) {
            return Err(FrameError::InvalidTransactionTarget);
        }

        let mut child = frame.branch(to, value, input);
        child.transfer_between(frame.owner(), to, value)?;
        let result = catch_unwind(AssertUnwindSafe(|| {
            self.precompiles.execute(to, &mut child, self)
        }))
        .unwrap_or(Err(FrameError::PrecompilePanic));

        let (diff, access_list_builder) = child.into_parts();
        if result.is_ok() {
            frame.merge(diff, access_list_builder);
        } else {
            frame.merge_access_list_builder(access_list_builder);
        }

        result
    }
}

/// Builds the effective declared access set for `transaction`.
///
/// The effective access set combines the explicit access list with the
/// processor's implicit sender and top-level recipient account writes.
fn transaction_access_set<H, PK>(transaction: &VerifiedTransaction<PK, H>) -> AccessSet
where
    H: Hasher,
    PK: PublicKey,
{
    let sender = transaction_sender::<H, PK>(transaction);
    let tx = transaction.value();
    AccessSet::new(sender, tx.to, &tx.access_list)
}

/// Derives the sender address for `transaction`.
const fn transaction_sender<H, PK>(transaction: &VerifiedTransaction<PK, H>) -> Address
where
    H: Hasher,
    PK: PublicKey,
{
    transaction.signer()
}
