//! Greedy scheduling for transfer-only execution.
//!
//! Every transaction writes exactly two logical accounts:
//!
//! - the sender
//! - the recipient
//!
//! Two transactions may run in parallel only when they do not touch either
//! address in common.

use super::state::{AccountDiff, State};
use commonware_cryptography::{Hasher, PublicKey};
use commonware_parallel::Strategy;
use constantinople_primitives::{Address, VerifiedTransaction};
use std::collections::HashMap;

/// Summary information about a greedy schedule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ScheduleStats {
    /// The number of dependency rounds in the schedule.
    total_rounds: usize,
    /// The number of rounds that contain exactly one transaction.
    singleton_rounds: usize,
    /// The widest round in the schedule.
    max_width: usize,
    /// The number of transactions that appear in non-singleton rounds.
    parallel_transactions: usize,
}

/// A flat round layout for contiguous per-round transaction slices.
#[derive(Debug)]
struct MaterializedRounds {
    /// The start index of each round in `transaction_indices`.
    offsets: Vec<usize>,
    /// Transaction indices laid out contiguously by round.
    transaction_indices: Vec<usize>,
}

impl MaterializedRounds {
    /// Builds contiguous round slices from per-transaction round assignments.
    fn new(round_for_transaction: &[usize], total_rounds: usize) -> Self {
        let mut offsets = vec![0; total_rounds + 1];
        for &round in round_for_transaction {
            offsets[round + 1] += 1;
        }

        for round in 0..total_rounds {
            offsets[round + 1] += offsets[round];
        }

        let mut transaction_indices = vec![0; round_for_transaction.len()];
        let mut next_slot = offsets[..total_rounds].to_vec();
        for (transaction_index, &round) in round_for_transaction.iter().enumerate() {
            transaction_indices[next_slot[round]] = transaction_index;
            next_slot[round] += 1;
        }

        Self {
            offsets,
            transaction_indices,
        }
    }

    /// Returns the transaction indices for one dependency round.
    fn round(&self, round: usize) -> &[usize] {
        let start = self.offsets[round];
        let end = self.offsets[round + 1];
        &self.transaction_indices[start..end]
    }
}

impl ScheduleStats {
    /// Records that one transaction was placed into `round`.
    fn record_round_assignment(&mut self, round_widths: &mut Vec<usize>, round: usize) {
        while round_widths.len() <= round {
            round_widths.push(0);
            self.total_rounds += 1;
        }

        round_widths[round] += 1;
        let width = round_widths[round];
        self.max_width = self.max_width.max(width);

        match width {
            1 => {
                self.singleton_rounds += 1;
            }
            2 => {
                self.singleton_rounds -= 1;
                self.parallel_transactions += 2;
            }
            _ => {
                self.parallel_transactions += 1;
            }
        }
    }
}

/// The inferred write set for one transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransactionWrites {
    sender: Address,
    recipient: Address,
}

impl TransactionWrites {
    fn new(sender: Address, recipient: Address) -> Self {
        Self { sender, recipient }
    }

    fn from_transaction<PK, H>(transaction: &VerifiedTransaction<PK, H>) -> Self
    where
        PK: PublicKey,
        H: Hasher,
    {
        Self::new(transaction.signer(), transaction.value().to)
    }

    fn addresses(self) -> impl Iterator<Item = Address> {
        [self.sender, self.recipient]
            .into_iter()
            .enumerate()
            .filter_map(move |(index, address)| {
                if index == 1 && address == self.sender {
                    return None;
                }

                Some(address)
            })
    }
}

/// Shared execution inputs for one transaction batch.
struct ExecutionContext<'a, PK, H, F>
where
    H: Hasher,
    PK: PublicKey,
{
    /// The original verified transactions in slice order.
    transactions: &'a [VerifiedTransaction<PK, H>],
    /// The processor callback used to execute one transaction.
    execute_transaction: F,
}

/// Parallel dispatch is usually a loss below roughly two chunks per worker.
const MIN_PARALLEL_ROUND_FACTOR: usize = 2;
/// Parallelizing fewer than this many transactions per worker is rarely worth it.
const MIN_PARALLEL_TXS_FACTOR: usize = 4;
/// Coarse chunks keep scheduler overhead small on wide independent rounds.
const MIN_PARALLEL_CHUNK_SIZE: usize = 32;

/// Executes transactions against one in-memory state snapshot.
///
/// Results are always merged back into committed state in original
/// transaction order, even when one dependency round ran in parallel.
pub(super) fn execute<H, PK, S, F>(
    strategy: &S,
    mut state: State,
    transactions: &[VerifiedTransaction<PK, H>],
    execute_transaction: F,
) -> State
where
    H: Hasher,
    PK: PublicKey,
    S: Strategy,
    F: Fn(&State, &VerifiedTransaction<PK, H>) -> AccountDiff + Sync,
{
    let writes = transactions
        .iter()
        .map(TransactionWrites::from_transaction)
        .collect::<Vec<_>>();
    let execution = ExecutionContext {
        transactions,
        execute_transaction,
    };

    if strategy.parallelism_hint().max(1) == 1 {
        execute_transactions_inline(&mut state, &execution);
        return state;
    }

    let (round_for_transaction, stats) = schedule_rounds(&writes);
    if should_execute_sequentially(strategy, stats) {
        execute_transactions_inline(&mut state, &execution);
    } else {
        let rounds = MaterializedRounds::new(&round_for_transaction, stats.total_rounds);
        for round_index in 0..stats.total_rounds {
            let round = rounds.round(round_index);
            if round.is_empty() {
                continue;
            }

            let results = execute_round(strategy, &state, &execution, round);

            for (transaction_index, result) in round.iter().copied().zip(results) {
                state.apply(result);
                let _ = transaction_index;
            }
        }
    }

    state
}

/// Executes one dependency round either inline or in coarse parallel chunks.
fn execute_round<H, PK, S, F>(
    strategy: &S,
    state: &State,
    execution: &ExecutionContext<'_, PK, H, F>,
    round: &[usize],
) -> Vec<AccountDiff>
where
    H: Hasher,
    PK: PublicKey,
    S: Strategy,
    F: Fn(&State, &VerifiedTransaction<PK, H>) -> AccountDiff + Sync,
{
    if should_execute_round_inline(strategy, round) {
        return execute_round_inline(state, execution, round);
    }

    let grain_size = parallel_grain_size(strategy, round.len());
    let chunk_results = strategy.map_collect_vec(round.chunks(grain_size), |chunk| {
        execute_round_inline(state, execution, chunk)
    });

    let mut results = Vec::with_capacity(round.len());
    for chunk in chunk_results {
        results.extend(chunk);
    }

    results
}

/// Executes a contiguous subset of one dependency round inline.
fn execute_round_inline<H, PK, F>(
    state: &State,
    execution: &ExecutionContext<'_, PK, H, F>,
    round: &[usize],
) -> Vec<AccountDiff>
where
    H: Hasher,
    PK: PublicKey,
    F: Fn(&State, &VerifiedTransaction<PK, H>) -> AccountDiff,
{
    let mut results = Vec::with_capacity(round.len());

    for &transaction_index in round {
        let transaction = &execution.transactions[transaction_index];
        results.push((execution.execute_transaction)(state, transaction));
    }

    results
}

/// Executes the entire batch inline without walking round boundaries.
fn execute_transactions_inline<H, PK, F>(
    state: &mut State,
    execution: &ExecutionContext<'_, PK, H, F>,
) where
    H: Hasher,
    PK: PublicKey,
    F: Fn(&State, &VerifiedTransaction<PK, H>) -> AccountDiff,
{
    for transaction in execution.transactions {
        let result = (execution.execute_transaction)(state, transaction);
        state.apply(result);
    }
}

/// Builds greedy dependency rounds from inferred sender/recipient writes.
fn schedule_rounds(writes: &[TransactionWrites]) -> (Vec<usize>, ScheduleStats) {
    const NONE: usize = usize::MAX;

    let mut touched = HashMap::with_capacity(writes.len().saturating_mul(2));
    let mut round_for_transaction = Vec::with_capacity(writes.len());
    let mut round_widths = Vec::new();
    let mut stats = ScheduleStats::default();

    for write_set in writes {
        let mut ready_round = 0;

        for address in write_set.addresses() {
            if let Some(&last_touch) = touched.get(&address)
                && last_touch != NONE
            {
                ready_round = ready_round.max(last_touch + 1);
            }
        }

        round_for_transaction.push(ready_round);
        stats.record_round_assignment(&mut round_widths, ready_round);

        for address in write_set.addresses() {
            touched.insert(address, ready_round);
        }
    }

    (round_for_transaction, stats)
}

/// Returns whether the whole schedule should run inline.
fn should_execute_sequentially(strategy: &impl Strategy, stats: ScheduleStats) -> bool {
    let parallelism = strategy.parallelism_hint().max(1);
    if parallelism == 1 {
        return true;
    }

    if stats.max_width < 2 {
        return true;
    }

    if stats.parallel_transactions < parallelism * MIN_PARALLEL_TXS_FACTOR {
        return true;
    }

    stats.singleton_rounds * 2 >= stats.total_rounds
}

/// Returns whether one round is too small to benefit from parallel dispatch.
fn should_execute_round_inline(strategy: &impl Strategy, round: &[usize]) -> bool {
    let parallelism = strategy.parallelism_hint().max(1);
    if parallelism == 1 {
        return true;
    }

    round.len() < parallelism * MIN_PARALLEL_ROUND_FACTOR
}

/// Returns the coarse chunk size for a wide parallel round.
fn parallel_grain_size(strategy: &impl Strategy, round_len: usize) -> usize {
    let parallelism = strategy.parallelism_hint().max(1);
    let target_chunks = parallelism * MIN_PARALLEL_ROUND_FACTOR;
    let evenly_split = round_len.div_ceil(target_chunks);
    evenly_split.max(MIN_PARALLEL_CHUNK_SIZE)
}

#[cfg(test)]
mod tests {
    use super::{MaterializedRounds, ScheduleStats, TransactionWrites, schedule_rounds};
    use commonware_codec::{DecodeExt, FixedSize};
    use constantinople_primitives::Address;

    #[test]
    fn schedule_rounds_groups_sender_and_recipient_conflicts() {
        let shared_sender = address(0xa0);
        let shared_recipient = address(0xb0);
        let other_a = address(0xc0);
        let other_b = address(0xd0);

        let (round_for_transaction, stats) = schedule_rounds(&[
            TransactionWrites::new(shared_sender, other_a),
            TransactionWrites::new(other_b, shared_recipient),
            TransactionWrites::new(shared_sender, shared_recipient),
            TransactionWrites::new(address(0xe0), address(0xf0)),
        ]);

        assert_eq!(round_for_transaction, vec![0, 0, 1, 0]);
        assert_eq!(
            stats,
            ScheduleStats {
                total_rounds: 2,
                singleton_rounds: 1,
                max_width: 3,
                parallel_transactions: 3,
            }
        );
    }

    #[test]
    fn materialized_rounds_preserve_transaction_order() {
        let rounds = MaterializedRounds::new(&[2, 0, 2, 1, 0], 3);

        assert_eq!(rounds.round(0), &[1, 4]);
        assert_eq!(rounds.round(1), &[3]);
        assert_eq!(rounds.round(2), &[0, 2]);
    }

    fn address(byte: u8) -> Address {
        Address::decode(&[byte; Address::SIZE][..]).expect("address bytes should decode")
    }
}
