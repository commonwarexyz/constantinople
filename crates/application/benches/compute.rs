use ahash::{AHashMap, AHashSet};
use commonware_cryptography::{Hasher as _, Sha256, Signer as _, ed25519};
use commonware_glue::stateful::db::{DatabaseSet, Merkleized as _, Unmerkleized as _};
use commonware_parallel::Rayon;
use commonware_runtime::{Runner as _, buffer::paged::CacheRef, tokio};
use commonware_storage::{
    journal::contiguous::fixed::Config as FixedJournalConfig, merkle::full::Config as MmrConfig,
    qmdb::any::FixedConfig, translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use constantinople_application::{
    consensus::{self, StateBatch, StateDatabase},
    executor::PreparedTransfer,
};
use constantinople_primitives::{
    Account, AccountKey, Nonce, Transaction, TransactionPublicKey, VerifiedTransaction,
};
use core::num::{NonZeroU64, NonZeroUsize};
use std::{
    hint::black_box,
    sync::Arc,
    time::{Duration, Instant},
};

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

type Db = StateDatabase<tokio::Context, Sha256, EightCap, Rayon>;
type Batch = StateBatch<tokio::Context, Sha256, EightCap, Rayon>;
type TestTx = VerifiedTransaction<Sha256>;

const ACCOUNTS: u64 = 1_000_000;
const COUNTS: &[usize] = &[16_384, 32_768];
const MAX_SIGNED_ACCOUNTS: u64 = 65_536;
const NAMESPACE: &[u8] = b"compute-bench";
const SHARED_FANOUT: usize = 8;
const WARMUP: u32 = 2;
const ITERS: u32 = 10;

#[derive(Clone, Copy)]
enum Fixture {
    Unique,
    Shared,
    Mixed,
}

impl Fixture {
    const fn name(self) -> &'static str {
        match self {
            Self::Unique => "unique",
            Self::Shared => "shared",
            Self::Mixed => "mixed",
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

    fn sign(&self, to: ed25519::PublicKey, value: u64, nonce: u64) -> TestTx {
        Transaction::new(
            TransactionPublicKey::ed25519(self.key.public_key()),
            TransactionPublicKey::ed25519(to),
            NonZeroU64::new(value).expect("bench value must be non-zero"),
            nonce,
        )
        .seal_and_sign(&self.key, NAMESPACE, &mut Sha256::default())
    }
}

struct LoadPlan<'a> {
    discrete_senders: Vec<&'a AccountKey>,
    discrete_recipients: Vec<&'a AccountKey>,
    general: Vec<&'a AccountKey>,
}

impl LoadPlan<'_> {
    const fn discrete(&self) -> bool {
        !self.discrete_senders.is_empty()
    }

    const fn general(&self) -> bool {
        !self.general.is_empty()
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
        init_cache_size: Some(NZUsize!(1 << 18)),
    }
}

fn load_plan(transfers: &[PreparedTransfer]) -> LoadPlan<'_> {
    let mut touches: AHashMap<&AccountKey, usize> =
        AHashMap::with_capacity(transfers.len().saturating_mul(2));
    for transfer in transfers {
        *touches.entry(&transfer.sender).or_default() += 1;
        if transfer.sender != transfer.recipient {
            *touches.entry(&transfer.recipient).or_default() += 1;
        }
    }

    let mut general_seen = AHashSet::with_capacity(transfers.len().saturating_mul(2));
    let mut plan = LoadPlan {
        discrete_senders: Vec::with_capacity(transfers.len()),
        discrete_recipients: Vec::with_capacity(transfers.len()),
        general: Vec::new(),
    };
    for transfer in transfers {
        let sender_unique = touches.get(&transfer.sender).copied().unwrap_or_default() == 1;
        let recipient_unique = transfer.sender == transfer.recipient
            || touches
                .get(&transfer.recipient)
                .copied()
                .unwrap_or_default()
                == 1;
        if sender_unique && recipient_unique {
            plan.discrete_senders.push(&transfer.sender);
            if transfer.sender != transfer.recipient {
                plan.discrete_recipients.push(&transfer.recipient);
            }
            continue;
        }

        if general_seen.insert(&transfer.sender) {
            plan.general.push(&transfer.sender);
        }
        if transfer.sender != transfer.recipient && general_seen.insert(&transfer.recipient) {
            plan.general.push(&transfer.recipient);
        }
    }
    plan
}

fn transfers(fixture: Fixture, n: usize) -> Vec<PreparedTransfer> {
    match fixture {
        Fixture::Unique => (0..n)
            .map(|i| {
                let sender = key(i as u64);
                let recipient = key(n as u64 + i as u64);
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
            let accounts = (n / SHARED_FANOUT).max(1);
            let mut nonces = vec![0u64; accounts];
            (0..n)
                .map(|i| {
                    let sender_index = i % accounts;
                    let recipient_index = (i * 7 + 3) % accounts;
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
        Fixture::Mixed => {
            let shared = n / 2;
            let unique = n - shared;
            let shared_accounts = (shared / SHARED_FANOUT).max(1);
            let mut nonces = vec![0u64; shared_accounts];
            let shared_transfers = (0..shared).map(|i| {
                let sender_index = i % shared_accounts;
                let recipient_index = (i * 7 + 3) % shared_accounts;
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
            });
            let unique_transfers = (0..unique).map(|i| {
                let sender = key(n as u64 + i as u64);
                let recipient = key(n as u64 + unique as u64 + i as u64);
                PreparedTransfer {
                    sender,
                    recipient,
                    sender_prefix: sender.prefix(),
                    recipient_prefix: recipient.prefix(),
                    value: 1,
                    nonce: 0,
                }
            });
            shared_transfers.chain(unique_transfers).collect()
        }
    }
}

fn signed_txs(fixture: Fixture, n: usize) -> Vec<TestTx> {
    match fixture {
        Fixture::Unique => (0..n)
            .map(|i| {
                let sender = TestSigner::from_seed(i as u64);
                let recipient = TestSigner::from_seed(n as u64 + i as u64).public_key;
                sender.sign(recipient, 1, 0)
            })
            .collect(),
        Fixture::Shared => {
            let accounts = (n / SHARED_FANOUT).max(1);
            let signers = (0..accounts)
                .map(|index| TestSigner::from_seed(index as u64))
                .collect::<Vec<_>>();
            let mut nonces = vec![0u64; accounts];
            (0..n)
                .map(|i| {
                    let sender_index = i % accounts;
                    let recipient_index = (i * 7 + 3) % accounts;
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
        Fixture::Mixed => {
            let shared = n / 2;
            let unique = n - shared;
            let shared_accounts = (shared / SHARED_FANOUT).max(1);
            let signers = (0..MAX_SIGNED_ACCOUNTS)
                .map(TestSigner::from_seed)
                .collect::<Vec<_>>();
            let mut nonces = vec![0u64; shared_accounts];
            let shared_txs = (0..shared).map(|i| {
                let sender_index = i % shared_accounts;
                let recipient_index = (i * 7 + 3) % shared_accounts;
                let nonce = nonces[sender_index];
                nonces[sender_index] += 1;
                signers[sender_index].sign(signers[recipient_index].public_key.clone(), 1, nonce)
            });
            let unique_txs = (0..unique).map(|i| {
                let sender_index = n + i;
                let recipient_index = n + unique + i;
                signers[sender_index].sign(signers[recipient_index].public_key.clone(), 1, 0)
            });
            shared_txs.chain(unique_txs).collect()
        }
    }
}

async fn time_compute(
    batch: Batch,
    transfers: Arc<Vec<PreparedTransfer>>,
    strategy: &Rayon,
) -> (usize, Duration, Duration, String) {
    let start = Instant::now();
    let (staged, updates) = consensus::compute(batch, transfers, strategy).await;
    let updates = updates.expect("compute path");
    let compute_elapsed = start.elapsed();
    let count = updates.len();
    let merkleized = staged
        .merkleize(updates, Vec::new())
        .await
        .expect("merkleize");
    let root = format!("{}", merkleized.root());
    black_box(&merkleized);
    let total = start.elapsed();
    (count, compute_elapsed, total - compute_elapsed, root)
}

async fn load_discrete(batch: &Batch, plan: &LoadPlan<'_>) {
    let values = batch
        .get_many(plan.discrete_senders.as_slice())
        .await
        .expect("sender loads");
    black_box(values);
    if !plan.discrete_recipients.is_empty() {
        let values = batch
            .get_many(plan.discrete_recipients.as_slice())
            .await
            .expect("recipient loads");
        black_box(values);
    }
}

async fn load_general(batch: &Batch, plan: &LoadPlan<'_>) {
    let values = batch
        .get_many(plan.general.as_slice())
        .await
        .expect("general loads");
    black_box(values);
}

async fn load_combined(batch: &Batch, plan: &LoadPlan<'_>) {
    let keys = plan
        .discrete_senders
        .iter()
        .chain(&plan.discrete_recipients)
        .chain(&plan.general)
        .copied()
        .collect::<Vec<_>>();
    let values = batch
        .get_many(keys.as_slice())
        .await
        .expect("account loads");
    black_box(values);
}

async fn time_loads(batch: &Batch, plan: &LoadPlan<'_>, overlap: bool) -> Duration {
    let start = Instant::now();
    match (plan.discrete(), plan.general(), overlap) {
        (true, true, true) => {
            futures::join!(load_discrete(batch, plan), load_general(batch, plan));
        }
        (true, true, false) => {
            load_discrete(batch, plan).await;
            load_general(batch, plan).await;
        }
        (true, _, _) => load_discrete(batch, plan).await,
        (_, true, _) => load_general(batch, plan).await,
        (false, false, _) => {}
    }
    start.elapsed()
}

async fn time_combined_load(batch: &Batch, plan: &LoadPlan<'_>) -> Duration {
    let start = Instant::now();
    load_combined(batch, plan).await;
    start.elapsed()
}

async fn time_prepare_compute(batch: Batch, strategy: &Rayon, txs: &[TestTx]) -> (usize, Duration) {
    let start = Instant::now();
    let (transfers, digests) = consensus::prepare_signed(strategy, txs).expect("prepare");
    let transfers = Arc::new(transfers);
    let (staged, updates) = consensus::compute(batch, transfers.clone(), strategy).await;
    let updates = updates.expect("compute path");
    let elapsed = start.elapsed();
    let count = updates.len();
    black_box((&transfers, &digests, &staged, &updates));
    (count, elapsed)
}

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(default)
}

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
        let bench_prepare = std::env::var_os("CONSTANTINOPLE_BENCH_PREPARE").is_some();
        let bench_loads = std::env::var_os("CONSTANTINOPLE_BENCH_LOADS").is_some();
        let warmup = env_u32("CONSTANTINOPLE_BENCH_WARMUP", WARMUP);
        let iters = env_u32("CONSTANTINOPLE_BENCH_ITERS", ITERS).max(1);
        let cache_pages = env_usize("CONSTANTINOPLE_BENCH_CACHE_PAGES", 65_536).max(1);
        let strategy =
            Rayon::new(NonZeroUsize::new(workers).expect("worker count")).expect("rayon pool");
        let cache = CacheRef::from_pooler(
            &context,
            NZU16!(8192),
            NonZeroUsize::new(cache_pages).expect("cache pages"),
        );
        let db = <Db as DatabaseSet<tokio::Context>>::init(
            context,
            config(strategy.clone(), cache),
        )
        .await;

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
        for &n in COUNTS {
            if count_filter.is_some_and(|filter| filter != n) {
                continue;
            }
            for fixture in [Fixture::Unique, Fixture::Shared, Fixture::Mixed] {
                if fixture_filter
                    .as_deref()
                    .is_some_and(|filter| filter != fixture.name())
                {
                    continue;
                }

                let transfers = Arc::new(transfers(fixture, n));
                if bench_loads {
                    let plan = load_plan(&transfers);
                    let mut seq_total = Duration::ZERO;
                    let mut overlap_total = Duration::ZERO;
                    let mut combined_total = Duration::ZERO;
                    for iter in 0..(warmup + iters) {
                        let seq_batch = db.new_batches().await;
                        let seq = time_loads(&seq_batch, &plan, false).await;
                        let overlap_batch = db.new_batches().await;
                        let overlap = time_loads(&overlap_batch, &plan, true).await;
                        let combined_batch = db.new_batches().await;
                        let combined = time_combined_load(&combined_batch, &plan).await;
                        if iter >= warmup {
                            seq_total += seq;
                            overlap_total += overlap;
                            combined_total += combined;
                        }
                    }

                    println!(
                        "loads    {n} txs / {ACCOUNTS} accounts / {} / {} workers\n  sequential: {:?}\n  overlap:    {:?}\n  combined:   {:?}",
                        fixture.name(),
                        workers,
                        seq_total / iters,
                        overlap_total / iters,
                        combined_total / iters,
                    );
                }

                let mut total = Duration::ZERO;
                let mut merk_total = Duration::ZERO;
                let mut writes = 0usize;
                let mut root = String::new();
                for iter in 0..(warmup + iters) {
                    let batch = db.new_batches().await;
                    let (count, compute_t, merk_t, r) =
                        time_compute(batch, Arc::clone(&transfers), &strategy).await;
                    writes = count;
                    root = r;
                    if iter >= warmup {
                        total += compute_t;
                        merk_total += merk_t;
                    }
                }

                let avg = total / iters;
                let merk_avg = merk_total / iters;
                let pipeline = avg + merk_avg;
                let tps = n as f64 / pipeline.as_secs_f64() / 1e6;
                println!(
                    "pipeline {n} txs / {ACCOUNTS} accounts / {} / {workers} workers\n  compute: {avg:?}  merkleize: {merk_avg:?}  total: {pipeline:?}  ({tps:.2} Melem/s) / {writes} writes\n  root: {root}",
                    fixture.name(),
                );

                if bench_prepare {
                    let txs = signed_txs(fixture, n);
                    let mut total = Duration::ZERO;
                    let mut writes = 0usize;
                    for iter in 0..(warmup + iters) {
                        let batch = db.new_batches().await;
                        let (count, elapsed) = time_prepare_compute(batch, &strategy, &txs).await;
                        writes = count;
                        if iter >= warmup {
                            total += elapsed;
                        }
                    }

                    let avg = total / iters;
                    let tps = n as f64 / avg.as_secs_f64() / 1e6;
                    println!(
                        "prepare+compute  {n} txs / {ACCOUNTS} accounts / {} / {} workers\n  compute: {avg:?}  ({tps:.2} Melem/s) / {writes} writes",
                        fixture.name(),
                        workers,
                    );
                }
            }
        }
    },
    );
}
