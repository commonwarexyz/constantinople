//! Transaction execution engine.
//!
//! The [`Processor`] struct orchestrates transaction execution in two modes:
//!
//! 1. [`Processor::propose`] executes sequentially over a lazy state reader
//!    and builds the block access list (BAL) for proposal.
//! 2. [`Processor::verify`] executes against a preloaded in-memory [`State`]
//!    and validates the declared BAL during verification.

use super::{
    Precompiles,
    access::{AccessListBuilder, AccessSet},
    frame::{Frame, FrameError},
    schedule::{self, TransactionExecution},
    state::{DiscoveryState, State, StateReader},
};
use bytes::Bytes;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use constantinople_primitives::{
    Address, BlockAccessList, Receipt, ReceiptStatus, Slot, StateValue, VerifiedTransaction,
};
use std::{
    collections::{BTreeMap, HashMap},
    panic::{AssertUnwindSafe, catch_unwind},
};
use thiserror::Error;

const MAX_CALL_DEPTH: u16 = 64;

/// The final result of verifier-side execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutput<D: Digest> {
    /// Receipts in transaction order.
    pub receipts: Vec<Receipt<D>>,
    /// Persistent database writes produced by execution.
    pub changeset: BTreeMap<Slot, StateValue>,
}

/// The result of proposer-side execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalOutput<D: Digest> {
    /// Receipts in transaction order.
    pub receipts: Vec<Receipt<D>>,
    /// Persistent database writes produced by execution.
    pub changeset: BTreeMap<Slot, StateValue>,
    /// The discovered block access list.
    pub access_list: BlockAccessList,
}

/// The result of [`Processor::validate`].
#[derive(Debug)]
pub struct ValidationResult<PK: PublicKey, H: Hasher> {
    /// Transactions that passed static validation.
    pub valid: Vec<VerifiedTransaction<PK, H>>,
    /// Transactions that failed static validation.
    pub invalid: Vec<VerifiedTransaction<PK, H>>,
}

/// Errors raised while verifying a declared block access list.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VerificationError {
    #[error("block access list has an invalid transaction layout")]
    MalformedBlockAccessList,
    #[error("transaction {transaction_index} declared accesses do not exactly match execution")]
    AccessListMismatch { transaction_index: usize },
    #[error("block access list final writes do not match execution")]
    FinalStateMismatch,
}

/// Executes transactions for BAL proposal and verification.
pub struct Processor<'a, S, P>
where
    S: Strategy,
    P: Precompiles,
{
    strategy: &'a S,
    precompiles: &'a P,
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
    fn is_precompile(&self, address: Address) -> Result<bool, FrameError> {
        catch_unwind(AssertUnwindSafe(|| self.precompiles.is_precompile(address)))
            .map_err(|_| FrameError::PrecompilePanic)
    }

    /// Creates a processor with the given execution strategy and precompile
    /// registry.
    pub const fn new(strategy: &'a S, precompiles: &'a P) -> Self {
        Self {
            strategy,
            precompiles,
        }
    }

    /// Splits `transactions` into statically valid and invalid sets.
    pub fn validate<H, PK>(
        &self,
        state: &impl StateReader,
        transactions: Vec<VerifiedTransaction<PK, H>>,
    ) -> ValidationResult<PK, H>
    where
        H: Hasher,
        PK: PublicKey,
    {
        let mut pending_nonces = HashMap::with_capacity(transactions.len());
        let mut valid = Vec::with_capacity(transactions.len());
        let mut invalid = Vec::new();

        for transaction in transactions {
            let sender = transaction.signer();
            let tx = transaction.value();
            let base = state.account(sender);
            let nonce = pending_nonces.get(&sender).copied().unwrap_or(base.nonce);
            let is_precompile = matches!(self.is_precompile(tx.to), Ok(true));

            let is_valid = nonce == tx.nonce
                && nonce != u64::MAX
                && base.balance >= tx.value
                && (is_precompile || tx.input.is_empty());

            if !is_valid {
                invalid.push(transaction);
                continue;
            }

            pending_nonces.insert(sender, nonce + 1);
            valid.push(transaction);
        }

        ValidationResult { valid, invalid }
    }

    /// Sequentially executes `transactions` and builds the BAL for proposal.
    ///
    /// The discovered BAL uses the processor's canonical access ordering and
    /// deterministic final-write ordering so verifiers can later check it
    /// exactly.
    pub fn propose<H, PK, R>(
        &self,
        state: &mut DiscoveryState<R>,
        transactions: &[VerifiedTransaction<PK, H>],
    ) -> ProposalOutput<H::Digest>
    where
        H: Hasher,
        PK: PublicKey,
        R: StateReader,
    {
        let mut receipts = Vec::with_capacity(transactions.len());
        let mut transaction_accesses = Vec::with_capacity(transactions.len());
        let permissive_access = AccessSet::permissive();

        for transaction in transactions {
            let result = self.execute_for_proposal(state, transaction, &permissive_access);
            state.apply(result.diff);
            receipts.push(result.receipt);
            transaction_accesses.push(result.observed_accesses);
        }

        let (account_writes, storage_writes) = state.writes();
        let access_list = BlockAccessList::from_transactions(
            transaction_accesses,
            account_writes,
            storage_writes,
        );

        ProposalOutput {
            receipts,
            changeset: state.changeset::<H>(self.strategy),
            access_list,
        }
    }

    /// Verifies pre-validated transactions against `state`.
    ///
    /// This is the verifier path. Each transaction must access exactly the
    /// declared BAL slice, no more and no less, and the declared final writes
    /// must exactly match the final committed state.
    ///
    /// # Errors
    ///
    /// Returns [`VerificationError::MalformedBlockAccessList`] if the BAL layout is
    /// structurally invalid, [`VerificationError::AccessListMismatch`] if any
    /// transaction's declared access slice does not match execution exactly,
    /// or [`VerificationError::FinalStateMismatch`] if the declared final writes do
    /// not equal the final state after execution.
    pub fn verify<H, PK>(
        &self,
        state: State,
        transactions: &[VerifiedTransaction<PK, H>],
        access_list: &BlockAccessList,
    ) -> Result<ExecutionOutput<H::Digest>, VerificationError>
    where
        H: Hasher,
        PK: PublicKey,
    {
        if !access_list.is_well_formed(transactions.len()) {
            return Err(VerificationError::MalformedBlockAccessList);
        }

        let declared_accesses = access_list
            .transaction_accesses()
            .map(AccessSet::new)
            .collect();
        let executed = schedule::execute(
            self.strategy,
            state,
            declared_accesses,
            transactions,
            |state, transaction, access| self.execute_for_verification(state, transaction, access),
        )
        .map_err(|transaction_index| VerificationError::AccessListMismatch { transaction_index })?;

        for (transaction_index, (declared, observed_accesses)) in access_list
            .transaction_accesses()
            .zip(executed.observed_accesses.iter())
            .enumerate()
        {
            // Verification is intentionally strict: the declared BAL slice must
            // exactly match the canonical observed access list, including
            // duplicate-free normalization and deterministic ordering.
            if declared != observed_accesses.as_slice() {
                return Err(VerificationError::AccessListMismatch { transaction_index });
            }
        }

        let (account_writes, storage_writes) = executed.state.writes();
        if account_writes != access_list.account_writes
            || storage_writes != access_list.storage_writes
        {
            return Err(VerificationError::FinalStateMismatch);
        }

        Ok(ExecutionOutput {
            receipts: executed.receipts,
            changeset: executed.state.changeset::<H>(self.strategy),
        })
    }

    /// Executes one transaction during proposal.
    fn execute_for_proposal<H, PK, V>(
        &self,
        state: &V,
        transaction: &VerifiedTransaction<PK, H>,
        access: &AccessSet,
    ) -> TransactionExecution<H::Digest>
    where
        H: Hasher,
        PK: PublicKey,
        V: StateReader,
    {
        self.execute_transaction(state, transaction, access, false)
            .expect("permissive proposal execution must not fail access enforcement")
    }

    /// Executes one transaction during verification.
    fn execute_for_verification<H, PK, V>(
        &self,
        state: &V,
        transaction: &VerifiedTransaction<PK, H>,
        access: &AccessSet,
    ) -> Result<TransactionExecution<H::Digest>, ()>
    where
        H: Hasher,
        PK: PublicKey,
        V: StateReader,
    {
        self.execute_transaction(state, transaction, access, true)
    }

    /// Executes a single transaction against `state`.
    fn execute_transaction<H, PK, V>(
        &self,
        state: &V,
        transaction: &VerifiedTransaction<PK, H>,
        access: &AccessSet,
        fail_on_access_violation: bool,
    ) -> Result<TransactionExecution<H::Digest>, ()>
    where
        H: Hasher,
        PK: PublicKey,
        V: StateReader,
    {
        let sender = transaction.signer();
        let mut prelude = Frame::new(
            sender,
            state,
            access,
            AccessListBuilder::default(),
            0,
            0,
            Bytes::new(),
        );

        if prelude.bump_sender_nonce().is_err() {
            let (diff, observed_accesses) = prelude.into_parts();
            return Ok(TransactionExecution {
                receipt: Receipt::revert(*transaction.message_digest(), Bytes::new()),
                diff,
                observed_accesses: observed_accesses.into_access_list(),
            });
        }

        let tx = transaction.value();
        let is_precompile = match self.is_precompile(tx.to) {
            Ok(is_precompile) => is_precompile,
            Err(_) => {
                let (diff, observed_accesses) = prelude.into_parts();
                return Ok(TransactionExecution {
                    receipt: Receipt::revert(*transaction.message_digest(), Bytes::new()),
                    diff,
                    observed_accesses: observed_accesses.into_access_list(),
                });
            }
        };
        let mut root = prelude.child_with_depth(sender, 0, 0, Bytes::new());
        let result = if is_precompile {
            root.call(self, tx.to, tx.value, tx.input.clone())
        } else {
            root.transfer(tx.to, tx.value).map(|()| Bytes::new())
        };

        match result {
            Ok(return_data) => {
                let (diff, child_accesses) = root.into_parts();
                prelude.merge(diff, child_accesses);
                let (diff, observed_accesses) = prelude.into_parts();

                Ok(TransactionExecution {
                    receipt: Receipt::new(
                        *transaction.message_digest(),
                        ReceiptStatus::Success,
                        return_data,
                    ),
                    diff,
                    observed_accesses: observed_accesses.into_access_list(),
                })
            }
            Err(err) => {
                if fail_on_access_violation
                    && matches!(
                        err,
                        FrameError::AccessViolation | FrameError::WriteProtection
                    )
                {
                    return Err(());
                }

                let payload = match err {
                    FrameError::Revert(payload) => payload,
                    _ => Bytes::new(),
                };
                let (_, child_accesses) = root.into_parts();
                prelude.merge_access_list_builder(child_accesses);
                let (diff, observed_accesses) = prelude.into_parts();

                Ok(TransactionExecution {
                    receipt: Receipt::revert(*transaction.message_digest(), payload),
                    diff,
                    observed_accesses: observed_accesses.into_access_list(),
                })
            }
        }
    }

    /// Executes a nested precompile call from `frame`.
    pub(super) fn call_precompile<R: StateReader>(
        &self,
        frame: &mut Frame<'_, R>,
        to: constantinople_primitives::Address,
        value: u64,
        input: Bytes,
    ) -> Result<Bytes, FrameError> {
        if frame.depth() == MAX_CALL_DEPTH {
            return Err(FrameError::CallDepthExceeded);
        }

        if !self.is_precompile(to)? {
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
