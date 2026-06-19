//! Timing harnesses for consensus execution benchmarks.

use super::{
    db::{StateBatch, StateDatabase},
    execution::{
        compute as compute_state, load_discrete, load_general, prepare_lazy, prepare_signed,
    },
};
use crate::executor::{PreparedTransfer, execution_plan};
use commonware_codec::{EncodeSize as _, ReadExt as _, Write as _};
use commonware_cryptography::{Hasher as _, Sha256, Signer as _, ed25519};
use commonware_glue::stateful::db::{DatabaseSet, Unmerkleized as _};
use commonware_parallel::{Rayon, Strategy as _};
use commonware_runtime::{Runner as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::contiguous::fixed::Config as FixedJournalConfig, merkle::full::Config as MmrConfig,
    qmdb::any::FixedConfig, translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use constantinople_primitives::{
    Account, AccountKey, LazySignedTransaction, Nonce, Transaction, TransactionPublicKey,
    VerifiedTransaction, preload_transaction_slice,
};
use core::num::NonZeroU64;
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

type Db = StateDatabase<deterministic::Context, Sha256, EightCap, Rayon>;
type TestTransaction = VerifiedTransaction<Sha256>;

const ACCOUNTS: u64 = 1_000_000;
const TRANSACTION_COUNTS: &[usize] = &[16_384, 32_768];
const MAX_SIGNED_ACCOUNTS: u64 = 65_536;
const NAMESPACE: &[u8] = b"compute-bench";
const SHARED_FANOUT: usize = 8;
const WARMUP: u32 = 2;
const ITERS: u32 = 10;

#[derive(Clone, Copy)]
enum Fixture {
    Unique,
    Shared,
}

impl Fixture {
    const fn name(self) -> &'static str {
        match self {
            Self::Unique => "unique",
            Self::Shared => "shared",
        }
    }
}

fn key(index: u64) -> AccountKey {
    AccountKey::try_from(Sha256::hash(&index.to_le_bytes()).as_ref()).expect("32-byte key")
}

fn signed_key(index: u64) -> AccountKey {
    AccountKey::from_public_key(&TransactionPublicKey::ed25519(
        ed25519::PrivateKey::from_seed(index).public_key(),
    ))
}

struct TestSigner {
    key: ed25519::PrivateKey,
    public_key: ed25519::PublicKey,
}

impl TestSigner {
    fn from_seed(seed: u64) -> Self {
        let key = ed25519::PrivateKey::from_seed(seed);
        let public_key = key.public_key();
        Self { key, public_key }
    }

    fn sign(&self, to: ed25519::PublicKey, value: u64, nonce: u64) -> TestTransaction {
        Transaction::new(
            TransactionPublicKey::ed25519(self.key.public_key()),
            TransactionPublicKey::ed25519(to),
            NonZeroU64::new(value).expect("bench value must be non-zero"),
            nonce,
        )
        .seal_and_sign(&self.key, NAMESPACE, &mut Sha256::default())
    }
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

fn transfers(fixture: Fixture, transaction_count: usize) -> Vec<PreparedTransfer> {
    match fixture {
        Fixture::Unique => (0..transaction_count)
            .map(|i| {
                let sender = key(i as u64);
                let recipient = key(transaction_count as u64 + i as u64);
                PreparedTransfer {
                    sender,
                    recipient,
                    sender_prefix: sender.prefix(),
                    recipient_prefix: recipient.prefix(),
                    value: 1,
                    nonce: 0,
                }
            })
            .collect(),
        Fixture::Shared => {
            let account_count = (transaction_count / SHARED_FANOUT).max(1);
            let mut nonces = vec![0u64; account_count];
            (0..transaction_count)
                .map(|i| {
                    let sender_index = i % account_count;
                    let recipient_index = (i * 7 + 3) % account_count;
                    let nonce = nonces[sender_index];
                    nonces[sender_index] += 1;
                    let sender = key(sender_index as u64);
                    let recipient = key(recipient_index as u64);
                    PreparedTransfer {
                        sender,
                        recipient,
                        sender_prefix: sender.prefix(),
                        recipient_prefix: recipient.prefix(),
                        value: 1,
                        nonce,
                    }
                })
                .collect()
        }
    }
}

fn signed_transactions(fixture: Fixture, transaction_count: usize) -> Vec<TestTransaction> {
    match fixture {
        Fixture::Unique => (0..transaction_count)
            .map(|i| {
                let sender = TestSigner::from_seed(i as u64);
                let recipient =
                    TestSigner::from_seed(transaction_count as u64 + i as u64).public_key;
                sender.sign(recipient, 1, 0)
            })
            .collect(),
        Fixture::Shared => {
            let account_count = (transaction_count / SHARED_FANOUT).max(1);
            let signers = (0..account_count)
                .map(|index| TestSigner::from_seed(index as u64))
                .collect::<Vec<_>>();
            let mut nonces = vec![0u64; account_count];
            (0..transaction_count)
                .map(|i| {
                    let sender_index = i % account_count;
                    let recipient_index = (i * 7 + 3) % account_count;
                    let nonce = nonces[sender_index];
                    nonces[sender_index] += 1;
                    signers[sender_index].sign(
                        signers[recipient_index].public_key.clone(),
                        1,
                        nonce,
                    )
                })
                .collect()
        }
    }
}

fn lazy_body(transactions: &[TestTransaction]) -> Vec<LazySignedTransaction<Sha256>> {
    transactions
        .iter()
        .map(|transaction| {
            let mut encoded_transaction = Vec::with_capacity(transaction.encode_size());
            transaction.write(&mut encoded_transaction);

            let mut encoded_lazy = Vec::with_capacity(
                encoded_transaction.len().encode_size() + encoded_transaction.len(),
            );
            encoded_transaction.len().write(&mut encoded_lazy);
            encoded_lazy.extend_from_slice(&encoded_transaction);

            LazySignedTransaction::<Sha256>::read(&mut encoded_lazy.as_slice())
                .expect("lazy transaction should decode")
        })
        .collect()
}

async fn time_compute(
    batch: &StateBatch<deterministic::Context, Sha256, EightCap, Rayon>,
    strategy: &Rayon,
    transfers: &[PreparedTransfer],
) -> (usize, Duration) {
    let start = Instant::now();
    let state_writes = compute_state(batch, strategy, transfers)
        .await
        .expect("compute path");
    let elapsed = start.elapsed();
    let count = state_writes.shards.iter().map(|map| map.len()).sum();
    black_box(&state_writes);
    (count, elapsed)
}

async fn time_prepare_compute(
    batch: &StateBatch<deterministic::Context, Sha256, EightCap, Rayon>,
    strategy: &Rayon,
    txs: &[TestTransaction],
) -> (usize, Duration) {
    let start = Instant::now();
    let (transfers, digests) = prepare_signed(strategy, txs).expect("prepare");
    let state_writes = compute_state(batch, strategy, &transfers)
        .await
        .expect("compute path");
    let elapsed = start.elapsed();
    let count = state_writes.shards.iter().map(|map| map.len()).sum();
    black_box((&transfers, &digests, &state_writes));
    (count, elapsed)
}

#[derive(Default)]
struct Breakdown {
    total: Duration,
    plan: Duration,
    discrete: Duration,
    general: Duration,
}

async fn time_breakdown(
    batch: &StateBatch<deterministic::Context, Sha256, EightCap, Rayon>,
    strategy: &Rayon,
    transfers: &[PreparedTransfer],
) -> (usize, Breakdown) {
    let total = Instant::now();
    let mut breakdown = Breakdown::default();

    let start = Instant::now();
    let plan = execution_plan(transfers).expect("execution plan");
    breakdown.plan = start.elapsed();

    let mut count = 0;
    let crate::executor::ExecutionPlan { discrete, general } = plan;
    if !discrete.transfers.is_empty() {
        let start = Instant::now();
        let state_writes = load_discrete(batch, strategy, discrete)
            .await
            .expect("discrete path should execute");
        breakdown.discrete = start.elapsed();
        count += state_writes
            .shards
            .iter()
            .map(|map| map.len())
            .sum::<usize>();
        black_box(&state_writes);
    }
    if !general.is_empty() {
        let start = Instant::now();
        let state_writes = load_general(batch, strategy, transfers, &general)
            .await
            .expect("general path should execute");
        breakdown.general = start.elapsed();
        count += state_writes
            .shards
            .iter()
            .map(|map| map.len())
            .sum::<usize>();
        black_box(&state_writes);
    }

    breakdown.total = total.elapsed();
    (count, breakdown)
}

fn time_lazy_preload(
    strategy: &Rayon,
    body: &[LazySignedTransaction<Sha256>],
) -> (usize, Duration) {
    let start = Instant::now();
    assert!(
        preload_transaction_slice(body, strategy),
        "lazy preload should succeed"
    );
    let elapsed = start.elapsed();
    black_box(body);
    (body.len(), elapsed)
}

fn time_lazy_prepare(
    strategy: &Rayon,
    body: &[LazySignedTransaction<Sha256>],
) -> (usize, Duration) {
    let start = Instant::now();
    let (transfers, digests) = prepare_lazy(strategy, body).expect("prepare lazy body");
    let elapsed = start.elapsed();
    let count = transfers.len();
    black_box((transfers, digests));
    (count, elapsed)
}

pub fn lazy_body_prepare() {
    let transaction_count = std::env::var("CONSTANTINOPLE_BENCH_COUNT")
        .ok()
        .and_then(|count| count.parse::<usize>().ok())
        .unwrap_or(32_768);
    let warmup = std::env::var("CONSTANTINOPLE_BENCH_WARMUP")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(WARMUP);
    let iters = std::env::var("CONSTANTINOPLE_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(ITERS)
        .max(1);
    let strategy = Rayon::new(NZUsize!(8)).expect("rayon pool");
    let transactions = signed_transactions(Fixture::Unique, transaction_count);
    let body = lazy_body(&transactions);

    assert!(
        preload_transaction_slice(&body, &strategy),
        "bench body should preload"
    );

    let mut preload_total = Duration::ZERO;
    let mut apply_total = Duration::ZERO;
    for iter in 0..(warmup + iters) {
        let (preload_count, preload_elapsed) = time_lazy_preload(&strategy, &body);
        assert_eq!(
            preload_count, transaction_count,
            "preload count should match"
        );

        let (apply_count, apply_elapsed) = time_lazy_prepare(&strategy, &body);
        assert_eq!(apply_count, transaction_count, "prepare count should match");

        if iter >= warmup {
            preload_total += preload_elapsed;
            apply_total += apply_elapsed;
        }
    }

    let preload = preload_total / iters;
    let apply = apply_total / iters;
    let tps = |d: Duration| transaction_count as f64 / d.as_secs_f64() / 1e6;
    println!(
        "lazy body prepare  {transaction_count} txs / unique / {} shards\n  verify preload: {preload:?}  ({:.2} Melem/s)\n  apply prepare:  {apply:?}  ({:.2} Melem/s)",
        strategy.parallelism_hint().max(1),
        tps(preload),
        tps(apply),
    );
}

pub fn compute() {
    deterministic::Runner::default().start(|context| async move {
        let bench_prepare = std::env::var_os("CONSTANTINOPLE_BENCH_PREPARE").is_some();
        let warmup = std::env::var("CONSTANTINOPLE_BENCH_WARMUP")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(WARMUP);
        let iters = std::env::var("CONSTANTINOPLE_BENCH_ITERS")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(ITERS)
            .max(1);
        let strategy = Rayon::new(NZUsize!(8)).expect("rayon pool");
        let cache = CacheRef::from_pooler(&context, NZU16!(8192), NZUsize!(65536));
        let db = <Db as DatabaseSet<deterministic::Context>>::init(
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
        if bench_prepare {
            for index in 0..MAX_SIGNED_ACCOUNTS {
                batch = batch.write(
                    signed_key(index),
                    Some(Account {
                        balance: 1_000_000,
                        nonce: Nonce::default(),
                    }),
                );
            }
        }
        let merkleized = batch.merkleize().await.expect("seed merkleize");
        db.finalize(merkleized).await;

        let fixture_filter = std::env::var("CONSTANTINOPLE_BENCH_FIXTURE").ok();
        let count_filter = std::env::var("CONSTANTINOPLE_BENCH_COUNT")
            .ok()
            .and_then(|count| count.parse::<usize>().ok());
        for &transaction_count in TRANSACTION_COUNTS {
            if count_filter.is_some_and(|filter| filter != transaction_count) {
                continue;
            }
            for fixture in [Fixture::Unique, Fixture::Shared] {
                if fixture_filter.as_deref().is_some_and(|filter| filter != fixture.name()) {
                    continue;
                }
                let transfers = transfers(fixture, transaction_count);

                let mut total = Duration::ZERO;
                let mut writes = 0usize;
                for iter in 0..(warmup + iters) {
                    let batch = db.new_batches().await;
                    let (count, elapsed) = time_compute(&batch, &strategy, &transfers).await;
                    writes = count;
                    if iter >= warmup {
                        total += elapsed;
                    }
                }
                let tps = |d: Duration| transaction_count as f64 / d.as_secs_f64() / 1e6;

                let avg = total / iters;
                println!(
                    "compute  {transaction_count} txs / {ACCOUNTS} accounts / {} / {} shards\n  compute: {avg:?}  ({:.2} Melem/s) / {writes} writes",
                    fixture.name(),
                    strategy.parallelism_hint().max(1),
                    tps(avg),
                );

                if std::env::var_os("CONSTANTINOPLE_BENCH_BREAKDOWN").is_some() {
                    let batch = db.new_batches().await;
                    let (count, breakdown) =
                        time_breakdown(&batch, &strategy, &transfers).await;
                    assert_eq!(count, writes, "breakdown write count should match");
                    println!(
                        "  breakdown: total={:?} plan={:?} discrete={:?} general={:?}",
                        breakdown.total,
                        breakdown.plan,
                        breakdown.discrete,
                        breakdown.general,
                    );
                }

                if bench_prepare {
                    let transactions = signed_transactions(fixture, transaction_count);
                    let mut total = Duration::ZERO;
                    let mut writes = 0usize;
                    for iter in 0..(warmup + iters) {
                        let batch = db.new_batches().await;
                        let (count, elapsed) =
                            time_prepare_compute(&batch, &strategy, &transactions).await;
                        writes = count;
                        if iter >= warmup {
                            total += elapsed;
                        }
                    }

                    let avg = total / iters;
                    println!(
                        "prepare+compute  {transaction_count} txs / {ACCOUNTS} accounts / {} / {} shards\n  compute: {avg:?}  ({:.2} Melem/s) / {writes} writes",
                        fixture.name(),
                        strategy.parallelism_hint().max(1),
                        tps(avg),
                    );
                }
            }
        }
    });
}
