//! Measures block settlement against a QMDB state database of one million accounts, by stage.
//!
//! Verification plans the body, stages its accounts, settles them, and merkleizes the slots.
//! Proposal selects the body over refill rounds, staging each round's new accounts, then settles
//! and merkleizes. Each stage reports its median over the timed iterations, and every iteration
//! starts from the same seeded state, so the roots of a fixture must not change.
//!
//! Environment:
//! - `CONSTANTINOPLE_BENCH_WORKERS` (8): Rayon workers and Tokio worker threads.
//! - `CONSTANTINOPLE_BENCH_COUNTS` (`32768,65536,131072`): transfers per block.
//! - `CONSTANTINOPLE_BENCH_FIXTURE`: run only this fixture (`ring`, `unique`, `shared`, `mixed`,
//!   `hot`).
//! - `CONSTANTINOPLE_BENCH_MODE`: run only `verify` or `propose`.
//! - `CONSTANTINOPLE_BENCH_ROUNDS` (4): candidate rounds per proposal.
//! - `CONSTANTINOPLE_BENCH_WARMUP` (2) and `CONSTANTINOPLE_BENCH_ITERS` (10).
//! - `CONSTANTINOPLE_BENCH_CACHE_PAGES`: page-cache size, in pages.

// The layout of the main future nests deeper than the compiler's default limit.
#![recursion_limit = "256"]

use commonware_allocator::mimalloc::{Config, MiMalloc, Purge, Reserve};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_glue::{
    stateful::db::{DatabaseSet, Merkleized as _, Unmerkleized as _},
    transfers::{Plan, Selection},
};
use commonware_parallel::{Rayon, Strategy as _};
use commonware_runtime::{
    BLOB_PAGE_SIZE, Runner as _,
    buffer::paged::{self, CacheRef},
    tokio,
};
use commonware_storage::{
    journal::contiguous::fixed::Config as FixedJournalConfig,
    merkle::full::Config as MmrConfig,
    qmdb::{any::batch::Slot, current::FixedConfig},
    translator::EightCap,
};
use commonware_utils::{NZU64, NZUsize};
use constantinople_application::{
    consensus::{StateBatch, StateDatabase},
    executor::{PreparedTransfer, TransferAccount, account_slots, starting_accounts},
};
use constantinople_primitives::{Account, AccountKey, Nonce};
use core::num::NonZeroUsize;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

#[global_allocator]
static ALLOC: MiMalloc = MiMalloc::new(Config {
    purge: Purge::After(Duration::from_secs(10)),
    reserve: Some(Reserve::pinned(2 << 30)),
    ..Config::DEFAULT
});

type Db = StateDatabase<tokio::Context, Sha256, EightCap, Rayon>;
type Batch = StateBatch<tokio::Context, Sha256, EightCap, Rayon>;

/// Funded accounts seeded into the state database.
const ACCOUNTS: u64 = 1_000_000;

/// Default page-cache size, in bytes.
const CACHE_BYTES: usize = 512 * 1024 * 1024;

/// Default transfers per block, as a comma-separated list.
const COUNTS: &str = "32768,65536,131072";

/// Transfers each account sends in the shared fixtures.
const SHARED_FANOUT: usize = 8;

/// Senders, and separately recipients, in the hot fixture.
const HOT_ACCOUNTS: usize = 64;

/// Default untimed warmup iterations.
const WARMUP: u32 = 2;

/// Default timed iterations.
const ITERS: u32 = 10;

/// A pattern of transfers between accounts.
#[derive(Clone, Copy)]
enum Fixture {
    /// Each account pays the next, as the spammer does: every account but the ends is touched
    /// twice.
    Ring,
    /// Every account is touched once.
    Unique,
    /// Each account sends and receives `SHARED_FANOUT` transfers.
    Shared,
    /// Half shared, half unique.
    Mixed,
    /// `HOT_ACCOUNTS` senders pay `HOT_ACCOUNTS` recipients.
    Hot,
}

impl Fixture {
    const ALL: [Self; 5] = [
        Self::Ring,
        Self::Unique,
        Self::Shared,
        Self::Mixed,
        Self::Hot,
    ];

    /// The fixture's name in reports and in `CONSTANTINOPLE_BENCH_FIXTURE`.
    const fn name(self) -> &'static str {
        match self {
            Self::Ring => "ring",
            Self::Unique => "unique",
            Self::Shared => "shared",
            Self::Mixed => "mixed",
            Self::Hot => "hot",
        }
    }
}

fn key(index: u64) -> AccountKey {
    AccountKey::try_from(Sha256::hash(&[&index.to_le_bytes()]).as_ref()).expect("32-byte key")
}

const fn transfer(sender: AccountKey, recipient: AccountKey, nonce: u64) -> PreparedTransfer {
    PreparedTransfer {
        sender,
        recipient,
        value: 1,
        nonce,
    }
}

/// Verification stages, in the order they run.
const VERIFY_STAGES: &[&str] = &["plan", "stage", "settle", "merkleize"];

/// Proposal stages, in the order they run.
const PROPOSE_STAGES: &[&str] = &["touch", "stage", "apply", "settle", "merkleize"];

/// Verifies `body` as `consensus::compute` does, timing each stage. Returns the stage times, the
/// number of written accounts, and the root.
async fn verify(
    batch: Batch,
    body: &Arc<Vec<PreparedTransfer>>,
    strategy: &Rayon,
) -> (Vec<Duration>, usize, String) {
    // Plan the body on the pool before reading any account.
    let start = Instant::now();
    let transfers = Arc::clone(body);
    let plan = strategy
        .spawn(transfers.len(), move |s: Rayon| {
            Plan::new(transfers.as_slice(), &s)
        })
        .await
        .expect("body must plan");

    // One staged read covers every account the plan touches.
    let planned = Instant::now();
    let (reads, staged) = {
        let keys: Vec<&AccountKey> = plan.keys().iter().collect();
        batch.stage(&keys).await.expect("staging must succeed")
    };

    // Settle on the pool and count the slots that change state.
    let read = Instant::now();
    let slots = strategy
        .spawn(plan.len(), move |s: Rayon| {
            plan.settle(&starting_accounts(reads), &s)
                .map(account_slots)
        })
        .await
        .expect("body must settle");
    let settled = Instant::now();
    let writes = slots
        .iter()
        .filter(|slot| !matches!(slot, Slot::Keep))
        .count();

    // Merkleizing resolves each slot to its staged key.
    let merkleized = staged
        .merkleize(slots, Vec::new())
        .await
        .expect("merkleize");

    // Each stage runs from the end of the previous one.
    let done = Instant::now();
    let times = vec![
        planned - start,
        read - planned,
        settled - read,
        done - settled,
    ];
    (times, writes, root_hex(merkleized.root()))
}

/// Proposes from `rounds` as `execute_proposal` does, timing each stage. Returns the stage times,
/// the number of accepted transfers, and the root.
async fn propose(
    batch: Batch,
    rounds: &[Arc<Vec<PreparedTransfer>>],
    strategy: &Rayon,
) -> (Vec<Duration>, usize, String) {
    let mut times = vec![Duration::ZERO; PROPOSE_STAGES.len()];
    let mut selection: Selection<AccountKey, TransferAccount> = Selection::new();
    let mut unstaged = Some(batch);
    let mut staged = None;
    let mut accepted = 0;

    // Each round touches its keys, stages only the new ones, and applies its candidates. Stage
    // times accumulate across rounds.
    for round in rounds {
        // The selection moves into the touch job and back.
        let start = Instant::now();
        let (back, touched) = {
            let round = Arc::clone(round);
            let mut selection = selection;
            strategy
                .spawn(round.len(), move |_: Rayon| {
                    let touched = selection.touch(&round);
                    (selection, touched)
                })
                .await
        };
        selection = back;

        // The first round stages a fresh batch, and later rounds expand it.
        let touched_at = Instant::now();
        if !touched.is_empty() {
            let keys: Vec<&AccountKey> = selection.keys()[touched].iter().collect();
            let reads = if let Some(batch) = unstaged.take() {
                let (reads, next) = batch.stage(&keys).await.expect("staging must succeed");
                staged = Some(next);
                reads
            } else {
                let (_, reads, next) = staged
                    .take()
                    .expect("a staged batch must exist after the first round")
                    .expand(&keys)
                    .await
                    .expect("expanding must succeed");
                staged = Some(next);
                reads
            };
            selection.register(starting_accounts(reads));
        }

        // Apply the round on the pool, counting the accepted candidates.
        let read = Instant::now();
        let (back, flags) = {
            let round = Arc::clone(round);
            let mut selection = selection;
            strategy
                .spawn(round.len(), move |_: Rayon| {
                    let flags = selection.apply(&round);
                    (selection, flags)
                })
                .await
        };
        selection = back;
        accepted += flags.iter().filter(|accepted| **accepted).count();
        let applied = Instant::now();
        times[0] += touched_at - start;
        times[1] += read - touched_at;
        times[2] += applied - read;
    }

    // Settle every touched key once, then merkleize the slots.
    let staged = staged.expect("at least one round must stage accounts");
    let start = Instant::now();
    let slots = strategy
        .spawn(selection.keys().len(), move |s: Rayon| {
            account_slots(selection.settle(&s))
        })
        .await;
    let settled = Instant::now();
    let merkleized = staged
        .merkleize(slots, Vec::new())
        .await
        .expect("merkleize");
    let done = Instant::now();
    times[3] = settled - start;
    times[4] = done - settled;
    (times, accepted, root_hex(merkleized.root()))
}

/// The state database configuration, with every journal on `cache`.
fn config(strategy: Rayon, cache: CacheRef) -> FixedConfig<EightCap, Rayon> {
    FixedConfig {
        merkle_config: MmrConfig {
            journal_partition: "bench-state-journal".into(),
            metadata_partition: "bench-state-metadata".into(),
            items_per_blob: NZU64!(1 << 20),
            write_buffer: NZUsize!(1 << 20),
            replay_buffer: NZUsize!(1 << 20),
            strategy,
            page_cache: cache.clone(),
        },
        journal_config: FixedJournalConfig {
            partition: "bench-state-log".into(),
            items_per_blob: NZU64!(1 << 20),
            page_cache: cache,
            write_buffer: NZUsize!(1 << 20),
            replay_buffer: NZUsize!(1 << 20),
        },
        grafted_metadata_partition: "compute-state-grafted-metadata".into(),
        translator: EightCap,
        init_cache: Some(NZUsize!(1 << 18)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

/// `n` transfers between accounts, each sender consuming its nonces in order.
fn transfers(fixture: Fixture, n: usize) -> Vec<PreparedTransfer> {
    let pairs: Vec<(u64, u64)> = match fixture {
        Fixture::Ring => (0..n as u64).map(|i| (i, (i + 1) % ACCOUNTS)).collect(),
        Fixture::Unique => (0..n as u64).map(|i| (i, n as u64 + i)).collect(),
        Fixture::Shared => {
            let accounts = (n / SHARED_FANOUT).max(1);
            (0..n)
                .map(|i| ((i % accounts) as u64, ((i * 7 + 3) % accounts) as u64))
                .collect()
        }
        Fixture::Mixed => {
            let shared = n / 2;
            let unique = n - shared;
            let accounts = (shared / SHARED_FANOUT).max(1);
            (0..shared)
                .map(|i| ((i % accounts) as u64, ((i * 7 + 3) % accounts) as u64))
                .chain((0..unique).map(|i| ((n + i) as u64, (n + unique + i) as u64)))
                .collect()
        }
        Fixture::Hot => (0..n)
            .map(|i| {
                let sender = (i % HOT_ACCOUNTS) as u64;
                let recipient = ACCOUNTS - 1 - ((i * 7 + 3) % HOT_ACCOUNTS) as u64;
                (sender, recipient)
            })
            .collect(),
    };

    // Every seeded account starts at nonce 0, so sequential nonces let every transfer apply.
    let mut nonces = vec![0u64; ACCOUNTS as usize];
    pairs
        .into_iter()
        .map(|(sender, recipient)| {
            let nonce = nonces[sender as usize];
            nonces[sender as usize] += 1;
            transfer(key(sender), key(recipient), nonce)
        })
        .collect()
}

/// Medians of each stage over the timed iterations.
struct Stages {
    /// Stage names, in the order they run.
    names: &'static [&'static str],

    /// Each stage's samples, one per timed iteration.
    samples: Vec<Vec<Duration>>,
}

impl Stages {
    fn new(names: &'static [&'static str]) -> Self {
        Self {
            names,
            samples: vec![Vec::new(); names.len()],
        }
    }

    /// Records one timed iteration, with one time per stage.
    fn record(&mut self, times: &[Duration]) {
        assert_eq!(times.len(), self.names.len());
        for (samples, time) in self.samples.iter_mut().zip(times) {
            samples.push(*time);
        }
    }

    fn median(samples: &[Duration]) -> Duration {
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        sorted[sorted.len() / 2]
    }

    /// Formats each stage's median and the median, minimum, and maximum per-iteration totals.
    fn report(&self) -> String {
        let mut line = String::new();
        for (name, samples) in self.names.iter().zip(&self.samples) {
            line += &format!(" {name} {:.3?}", Self::median(samples));
        }
        let totals: Vec<Duration> = (0..self.samples[0].len())
            .map(|iter| self.samples.iter().map(|samples| samples[iter]).sum())
            .collect();
        let (min, max) = (
            totals
                .iter()
                .min()
                .expect("at least one iteration must be timed"),
            totals
                .iter()
                .max()
                .expect("at least one iteration must be timed"),
        );
        line += &format!(
            " | total {:.3?} (min {min:.3?} max {max:.3?})",
            Self::median(&totals)
        );
        line
    }
}

fn root_hex(root: impl core::fmt::Debug) -> String {
    format!("{root:?}")
}

/// Reads `name` from the environment, or `default` when it is unset or does not parse.
fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(default)
}

/// Reads `name` from the environment, or `default` when it is unset or does not parse.
fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn main() {
    let workers = env_usize("CONSTANTINOPLE_BENCH_WORKERS", 8).max(1);
    tokio::Runner::new(tokio::Config::default().with_worker_threads(workers)).start(
        |context| async move {
            // Read the run's settings, open the state database, and keep one page cache for
            // every journal.
            let warmup = env_u32("CONSTANTINOPLE_BENCH_WARMUP", WARMUP);
            let iters = env_u32("CONSTANTINOPLE_BENCH_ITERS", ITERS).max(1);
            let rounds = env_usize("CONSTANTINOPLE_BENCH_ROUNDS", 4).max(1);
            let cache_pages = env_usize(
                "CONSTANTINOPLE_BENCH_CACHE_PAGES",
                CACHE_BYTES / BLOB_PAGE_SIZE as usize,
            )
            .max(1);
            let counts: Vec<usize> = std::env::var("CONSTANTINOPLE_BENCH_COUNTS")
                .unwrap_or_else(|_| COUNTS.into())
                .split(',')
                .map(|count| {
                    count
                        .trim()
                        .parse()
                        .expect("each transfer count must parse")
                })
                .collect();
            let fixture_filter = std::env::var("CONSTANTINOPLE_BENCH_FIXTURE").ok();
            let mode_filter = std::env::var("CONSTANTINOPLE_BENCH_MODE").ok();
            let strategy =
                Rayon::new(NonZeroUsize::new(workers).expect("worker count")).expect("rayon pool");
            let cache = CacheRef::new(
                paged::page_size(BLOB_PAGE_SIZE),
                NonZeroUsize::new(cache_pages).expect("cache pages"),
            );
            let db = <Db as DatabaseSet<tokio::Context>>::init(
                context,
                config(strategy.clone(), cache),
                None,
            )
            .await;

            // Seed and durably commit every account, so each iteration starts from the same
            // state.
            let mut batch = db.new_batches().await;
            for index in 0..ACCOUNTS {
                batch = batch.write(
                    key(index),
                    Some(Account {
                        balance: 1_000_000,
                        nonce: Nonce::default(),
                        tx_count: 0,
                    }),
                );
            }
            let merkleized = batch.merkleize().await.expect("seed merkleize");
            db.apply(merkleized).await;
            assert!(db.finalize().await.durable().await);

            for &n in &counts {
                for fixture in Fixture::ALL {
                    if fixture_filter
                        .as_deref()
                        .is_some_and(|filter| filter != fixture.name())
                    {
                        continue;
                    }
                    let body = Arc::new(transfers(fixture, n));
                    let label = format!("{} {n} txs / {workers} workers", fixture.name());

                    // Every verify iteration must reach the same writes and root, and only
                    // iterations after the warmup are timed.
                    if mode_filter.as_deref().is_none_or(|mode| mode == "verify") {
                        let mut stages = Stages::new(VERIFY_STAGES);
                        let mut outcome = None;
                        for iter in 0..(warmup + iters) {
                            let batch = db.new_batches().await;
                            let (times, writes, root) = verify(batch, &body, &strategy).await;
                            match &outcome {
                                None => outcome = Some((writes, root)),
                                Some(expected) => assert_eq!(expected, &(writes, root)),
                            }
                            if iter >= warmup {
                                stages.record(&times);
                            }
                        }
                        let (writes, root) = outcome.expect("at least one iteration must run");
                        println!(
                            "verify  {label} |{} | {writes} writes root {root}",
                            stages.report()
                        );
                    }

                    // Split the body into equal candidate rounds. Every candidate must apply, and
                    // every iteration must reach the same root.
                    if mode_filter.as_deref().is_none_or(|mode| mode == "propose") {
                        let per_round = n.div_ceil(rounds);
                        let candidates: Vec<Arc<Vec<PreparedTransfer>>> = body
                            .chunks(per_round)
                            .map(|round| Arc::new(round.to_vec()))
                            .collect();
                        let mut stages = Stages::new(PROPOSE_STAGES);
                        let mut outcome = None;
                        for iter in 0..(warmup + iters) {
                            let batch = db.new_batches().await;
                            let (times, accepted, root) =
                                propose(batch, &candidates, &strategy).await;
                            assert_eq!(accepted, n, "every candidate must apply");
                            match &outcome {
                                None => outcome = Some(root),
                                Some(expected) => assert_eq!(expected, &root),
                            }
                            if iter >= warmup {
                                stages.record(&times);
                            }
                        }
                        println!(
                            "propose {label} / {} rounds |{} | root {}",
                            candidates.len(),
                            stages.report(),
                            outcome.expect("at least one iteration must run")
                        );
                    }
                }
            }
        },
    );
}
