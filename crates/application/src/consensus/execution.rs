//! Execution and commitment checks for consensus blocks.

use super::{
    MALFORMED_TRANSACTION, Result, STATIC_INVALID_TRANSACTION,
    body::PreparedBody,
    db::{self, StateBatch, TransactionBatch, apply_shard_maps, apply_transaction_digests},
    history::parent_transactions_inactivity_floor,
    reject_verify,
};
use crate::executor::{self, PreparedTransfer, ShardMap};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_glue::stateful::db::Merkleized as _;
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{merkle::Family, mmr, qmdb::batch_chain::Bounds, translator::EightCap};
use commonware_utils::non_empty_range;
use constantinople_primitives::{Header, SealedBlock, SignedTransaction};
use tracing::{Instrument as _, info_span};

pub(super) struct ProposalExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    pub(super) block: BlockExecution<E, H, S>,
    pub(super) body: Vec<SignedTransaction<H>>,
}

pub(super) struct BlockExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    pub(super) state: db::StateMerkleized<E, H, EightCap, S>,
    pub(super) transactions: db::TransactionMerkleized<E, H, S>,
    pub(super) state_sync_range: commonware_utils::range::NonEmptyRange<u64>,
    pub(super) transactions_range: commonware_utils::range::NonEmptyRange<u64>,
    pub(super) transaction_count: usize,
}

impl<E, H, S> BlockExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    pub(super) fn into_merkleized(self) -> db::MerkleizedDatabases<E, H, S> {
        (self.state, self.transactions)
    }
}

/// Loads and executes a batch as a per-shard pipeline.
///
/// Transfers are routed to shards by account-key prefix; each shard concurrently
/// loads only the accounts it owns from the state batch, then applies its debits
/// and credits in place. The returned per-shard maps are the accounts to write.
/// Returns `None` if any transfer fails its nonce or balance check or overflows
/// a recipient (the whole batch is rejected). The batch is only borrowed for the
/// concurrent reads, so the caller may move it afterward to apply the writes.
async fn load_and_execute<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    strategy: &S,
    transfers: &[PreparedTransfer<H>],
) -> Option<Vec<ShardMap>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    if transfers.is_empty() {
        return Some(Vec::new());
    }

    let shards = executor::partition(transfers, strategy.parallelism_hint());
    let loaded: Vec<Option<ShardMap>> =
        futures::future::try_join_all(shards.iter().map(|shard| async move {
            let keys = shard.account_keys(transfers);
            let values = batch.get_many(&keys).await?;
            let mut accounts = ShardMap::with_capacity(keys.len());
            for (key, value) in keys.iter().zip(values) {
                accounts
                    .entry((*key).clone())
                    .or_insert_with(|| value.unwrap_or_default());
            }
            Ok::<_, commonware_storage::qmdb::Error<mmr::Family>>(executor::execute_shard(
                accounts, shard, transfers,
            ))
        }))
        .await
        .expect("state loading must succeed");

    loaded.into_iter().collect()
}

/// Executes a proposal's candidate transactions all or nothing.
///
/// If every candidate executes cleanly the block includes them all. If any
/// candidate is malformed, fails its nonce or balance check, or overflows a
/// recipient, the whole batch is dropped and an empty block is proposed so the
/// chain still makes progress.
pub(super) async fn execute_proposal<E, C, P, H, S>(
    strategy: S,
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent: &SealedBlock<C, P, H>,
    transactions: Vec<SignedTransaction<H>>,
) -> ProposalExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    let prepared = transactions
        .iter()
        .map(executor::prepare_transfer)
        .collect::<Option<Vec<_>>>();

    let outcome = match prepared {
        Some(transfers) if !transfers.is_empty() => {
            load_and_execute(&state_batch, &strategy, &transfers)
                .instrument(info_span!("application.execute.load_execute"))
                .await
                .map(|shard_maps| (transactions, transfers, shard_maps))
        }
        _ => None,
    };

    let (body, transfers, state_batch) = match outcome {
        Some((body, transfers, shard_maps)) => {
            (body, transfers, apply_shard_maps(state_batch, shard_maps))
        }
        None => (Vec::new(), Vec::new(), state_batch),
    };

    let transaction_batch = info_span!("application.execute.apply")
        .in_scope(|| apply_transaction_digests(transaction_batch, &transfer_digests(&transfers)));

    ProposalExecution {
        block: finalize_child(
            state_batch,
            transaction_batch,
            parent,
            body.len(),
            "database merkleization must succeed",
        )
        .await,
        body,
    }
}

pub(super) async fn execute_body<E, C, P, H, S>(
    strategy: S,
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent: &SealedBlock<C, P, H>,
    body: PreparedBody<H>,
) -> Result<BlockExecution<E, H, S>>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    let transfers = info_span!("application.execute.prepare").in_scope(|| {
        body.iter()
            .map(|transaction| executor::prepare_transfer(transaction.get()?))
            .collect::<Option<Vec<_>>>()
            .ok_or(MALFORMED_TRANSACTION)
    })?;

    let shard_maps = load_and_execute(&state_batch, &strategy, &transfers)
        .instrument(info_span!("application.execute.load_execute"))
        .await
        .ok_or(STATIC_INVALID_TRANSACTION)?;

    let (state_batch, transaction_batch) = info_span!("application.execute.apply").in_scope(|| {
        let digests = transfer_digests(&transfers);
        let state_batch = apply_shard_maps(state_batch, shard_maps);
        let transaction_batch = apply_transaction_digests(transaction_batch, &digests);
        (state_batch, transaction_batch)
    });

    Ok(finalize_child(
        state_batch,
        transaction_batch,
        parent,
        transfers.len(),
        "database merkleization during verification must succeed",
    )
    .await)
}

pub(super) async fn apply_prepared_body<E, H, S>(
    strategy: S,
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    transaction_floor: mmr::Location,
    transfers: &[PreparedTransfer<H>],
) -> Result<db::MerkleizedDatabases<E, H, S>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let shard_maps = load_and_execute(&state_batch, &strategy, transfers)
        .instrument(info_span!("application.execute.load_execute"))
        .await
        .ok_or(STATIC_INVALID_TRANSACTION)?;

    let (state_batch, transaction_batch) = info_span!("application.execute.apply").in_scope(|| {
        let digests = transfer_digests(transfers);
        let state_batch = apply_shard_maps(state_batch, shard_maps);
        let transaction_batch = apply_transaction_digests(transaction_batch, &digests)
            .with_inactivity_floor(transaction_floor);
        (state_batch, transaction_batch)
    });

    db::finalize_execution(state_batch, transaction_batch)
        .await
        .map_err(|_| STATIC_INVALID_TRANSACTION)
}

pub(super) fn commitments_match<E, C, P, H, S>(
    header: &Header<C, H::Digest, P>,
    execution: &BlockExecution<E, H, S>,
) -> bool
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    if execution.state.root() != header.state_root {
        reject_verify(header.height, "state_root_mismatch");
        return false;
    }
    if execution.state_sync_range != header.state_range {
        reject_verify(header.height, "state_range_mismatch");
        return false;
    }
    if execution.transactions.root() != header.transactions_root {
        reject_verify(header.height, "transaction_root_mismatch");
        return false;
    }
    if execution.transactions_range != header.transactions_range {
        reject_verify(header.height, "transaction_range_mismatch");
        return false;
    }

    true
}

#[tracing::instrument(name = "application.execute.finalize", level = "info", skip_all)]
async fn finalize_child<E, C, P, H, S>(
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent: &SealedBlock<C, P, H>,
    transaction_count: usize,
    expect_message: &'static str,
) -> BlockExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    let transaction_batch =
        transaction_batch.with_inactivity_floor(parent_transactions_inactivity_floor(parent));
    let (state, transactions) = db::finalize_execution(state_batch, transaction_batch)
        .await
        .expect(expect_message);
    let state_sync_range = range_from_bounds(state.bounds());
    let transactions_range = range_from_bounds(transactions.bounds());

    BlockExecution {
        state,
        transactions,
        state_sync_range,
        transactions_range,
        transaction_count,
    }
}

fn range_from_bounds<F>(bounds: &Bounds<F>) -> commonware_utils::range::NonEmptyRange<u64>
where
    F: Family,
{
    non_empty_range!(*bounds.inactivity_floor, bounds.total_size)
}

fn transfer_digests<H>(transfers: &[PreparedTransfer<H>]) -> Vec<H::Digest>
where
    H: Hasher,
{
    transfers.iter().map(|transfer| transfer.digest).collect()
}

#[cfg(test)]
mod tests {
    use super::range_from_bounds;
    use commonware_storage::{mmr, qmdb::batch_chain::Bounds};
    use commonware_utils::non_empty_range;

    #[test]
    fn range_comes_from_qmdb_bounds() {
        let bounds = Bounds {
            base_size: 7,
            db_size: 9,
            total_size: 15,
            ancestors: Vec::new(),
            inactivity_floor: mmr::Location::new(11),
        };

        assert_eq!(range_from_bounds(&bounds), non_empty_range!(11, 15));
    }
}

/// DB-backed timing harness for the load + execute path against a real QMDB.
///
/// Run with: `cargo test -p constantinople-application --release -- --ignored
/// --nocapture bench_load_execute`. Seeds a committed state DB, then times the
/// new per-shard `load_and_execute` against the previous global-load + overlay
/// path. Note: the deterministic runtime serves reads from memory, so this
/// measures the load+execute CPU/memory path (single-map reuse vs global state +
/// separate changeset), not the per-shard I/O concurrency, which only helps on
/// cold disk misses.
#[cfg(test)]
mod db_bench {
    use crate::executor::{PreparedTransfer, State};
    use commonware_cryptography::{Hasher as _, Sha256};
    use commonware_glue::stateful::db::{DatabaseSet, Unmerkleized as _};
    use commonware_parallel::{Rayon, Strategy as _};
    use commonware_runtime::{Runner as _, buffer::paged::CacheRef, deterministic};
    use commonware_storage::{
        journal::contiguous::fixed::Config as FixedJournalConfig,
        merkle::full::Config as MmrConfig, qmdb::any::FixedConfig, translator::EightCap,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};
    use constantinople_primitives::{Account, AccountKey, Nonce};
    use hashbrown::HashSet;
    use std::{
        hint::black_box,
        time::{Duration, Instant},
    };

    type Bench = super::db::StateDatabase<deterministic::Context, Sha256, EightCap, Rayon>;

    const ACCOUNTS: u64 = 131_072;
    const TRANSACTIONS: usize = 65_536;
    const WARMUP: u32 = 3;
    const ITERS: u32 = 20;

    fn key(index: u64) -> AccountKey {
        AccountKey::from_bytes(bytes::Bytes::copy_from_slice(
            Sha256::hash(&index.to_le_bytes()).as_ref(),
        ))
        .expect("32-byte key")
    }

    fn config(strategy: Rayon, cache: CacheRef) -> FixedConfig<EightCap, Rayon> {
        FixedConfig {
            merkle_config: MmrConfig {
                journal_partition: "bench-state-journal".into(),
                metadata_partition: "bench-state-metadata".into(),
                items_per_blob: NZU64!(1 << 20),
                write_buffer: NZUsize!(1 << 20),
                strategy,
                page_cache: cache.clone(),
            },
            journal_config: FixedJournalConfig {
                partition: "bench-state-log".into(),
                items_per_blob: NZU64!(1 << 20),
                page_cache: cache,
                write_buffer: NZUsize!(1 << 20),
            },
            translator: EightCap,
        }
    }

    /// The previous path: one global `get_many` then an inline overlay execute.
    async fn legacy(
        batch: &super::StateBatch<deterministic::Context, Sha256, EightCap, Rayon>,
        transfers: &[PreparedTransfer<Sha256>],
    ) -> usize {
        let mut keys = HashSet::with_capacity(transfers.len() * 2);
        for transfer in transfers {
            keys.insert(transfer.sender.clone());
            keys.insert(transfer.recipient.clone());
        }
        let keys: Vec<AccountKey> = keys.into_iter().collect();
        let refs: Vec<&AccountKey> = keys.iter().collect();
        let values = batch.get_many(&refs).await.expect("load");
        let state: State = keys
            .into_iter()
            .zip(values)
            .map(|(k, v)| (k, v.unwrap_or_default()))
            .collect();

        let mut writes = State::with_capacity(transfers.len() * 2);
        for transfer in transfers {
            let mut sender = writes
                .get(&transfer.sender)
                .copied()
                .or_else(|| state.get(&transfer.sender).copied())
                .unwrap_or_default();
            sender.balance -= transfer.value;
            sender.nonce.consume(transfer.nonce);
            if transfer.sender == transfer.recipient {
                writes.insert(transfer.sender.clone(), sender);
                continue;
            }
            let mut recipient = writes
                .get(&transfer.recipient)
                .copied()
                .or_else(|| state.get(&transfer.recipient).copied())
                .unwrap_or_default();
            recipient.balance += transfer.value;
            writes.insert(transfer.sender.clone(), sender);
            writes.insert(transfer.recipient.clone(), recipient);
        }
        writes.len()
    }

    #[test]
    #[ignore = "timing harness; run explicitly with --ignored --nocapture --release"]
    fn bench_load_execute() {
        deterministic::Runner::default().start(|context| async move {
            let strategy = Rayon::new(NZUsize!(8)).expect("rayon pool");
            let cache = CacheRef::from_pooler(&context, NZU16!(8192), NZUsize!(65536));
            let db = <Bench as DatabaseSet<deterministic::Context>>::init(
                context,
                config(strategy.clone(), cache),
            )
            .await;

            // Seed a committed state of ACCOUNTS funded accounts.
            let mut batch = db.new_batches().await;
            for index in 0..ACCOUNTS {
                batch = batch.write(
                    key(index),
                    Some(Account {
                        balance: 1_000_000,
                        nonce: Nonce::default(),
                    }),
                );
            }
            let merkleized = batch.merkleize().await.expect("seed merkleize");
            db.finalize(merkleized).await;

            // Disjoint senders/recipients, each sender used once (nonce 0).
            let transfers: Vec<PreparedTransfer<Sha256>> = (0..TRANSACTIONS)
                .map(|i| PreparedTransfer {
                    sender: key(i as u64),
                    recipient: key(TRANSACTIONS as u64 + i as u64),
                    value: 1,
                    nonce: 0,
                    digest: Sha256::hash(&(i as u64).to_le_bytes()),
                })
                .collect();

            let mut new_total = Duration::ZERO;
            for iter in 0..(WARMUP + ITERS) {
                let batch = db.new_batches().await;
                let start = Instant::now();
                let maps = super::load_and_execute(&batch, &strategy, &transfers)
                    .await
                    .expect("new path");
                let elapsed = start.elapsed();
                black_box(&maps);
                if iter >= WARMUP {
                    new_total += elapsed;
                }
            }

            let mut old_total = Duration::ZERO;
            for iter in 0..(WARMUP + ITERS) {
                let batch = db.new_batches().await;
                let start = Instant::now();
                let count = legacy(&batch, &transfers).await;
                let elapsed = start.elapsed();
                black_box(count);
                if iter >= WARMUP {
                    old_total += elapsed;
                }
            }

            let new = new_total / ITERS;
            let old = old_total / ITERS;
            let tps = |d: Duration| TRANSACTIONS as f64 / d.as_secs_f64() / 1e6;
            println!(
                "load+execute  {TRANSACTIONS} txs / {ACCOUNTS} accounts, {} shards\n  new (per-shard): {new:?}  ({:.2} Melem/s)\n  old (global):    {old:?}  ({:.2} Melem/s)",
                strategy.parallelism_hint(),
                tps(new),
                tps(old),
            );
        });
    }
}
