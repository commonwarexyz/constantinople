//! Production-shaped state/history cadence benchmark.
//!
//! This advances an evolving 1M-account state while one FIFO worker applies
//! finalized batches. Throughput mode waits for each apply and non-durable
//! flush before building the next block, matching the stateful actor's
//! finalized-block boundary. Pressure mode can queue a wider window to test
//! generation retirement and memory ownership independently. Every reported
//! rate includes draining the final apply.

mod cadence_acceptance;

use bytes::Bytes;
use cadence_acceptance::{env_flag, env_optional, env_or};
use commonware_codec::{EncodeSize as _, ReadExt as _, Write as _};
use commonware_cryptography::{Hasher as _, Sha256, Signer as _, ed25519};
use commonware_glue::stateful::db::{DatabaseSet, Unmerkleized as _};
use commonware_parallel::{Rayon, Strategy as _};
use commonware_runtime::{
    Metrics as _, Runner as _, Spawner as _, Supervisor as _,
    buffer::paged::{CacheRef, page_size as paged_page_size},
    tokio,
};
use commonware_storage::{
    journal::contiguous::{
        fixed::Config as FixedJournalConfig, variable::Config as VariableJournalConfig,
    },
    merkle::full::Config as MmrConfig,
    qmdb::{any::FixedConfig, keyless::fixed as keyless_fixed},
    translator::EightCap,
};
use commonware_utils::{NZU64, NZUsize, TestRng, channel::mpsc};
use constantinople_application::{
    consensus::{self, Databases},
    executor::PreparedTransfer,
};
use constantinople_primitives::{
    Account, AccountKey, LazySignedTransaction, Nonce, PublicKeyCache, TRANSACTION_NAMESPACE,
    Transaction, TransactionPublicKey, preload_transaction_slice, verify_transaction_batch,
};
use std::{
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

type Dbs = Databases<tokio::Context, Sha256, EightCap, Rayon>;
type MerkleizedDbs = <Dbs as DatabaseSet<tokio::Context>>::Merkleized;

const DEFAULT_ACCOUNTS: usize = 1_000_000;
const DEFAULT_TXS: usize = 170_000;
const DEFAULT_WARMUP_BLOCKS: usize = 3;
const DEFAULT_BLOCKS: usize = 20;
const DEFAULT_TOKIO_WORKERS: usize = 3;
const DEFAULT_ENGINE_WORKERS: usize = 20;
const DEFAULT_CACHE_PAGES: usize = 131_072;
const DEFAULT_MAX_PENDING_APPLIES: usize = 1;

struct PhaseResult {
    build: Vec<BuildTiming>,
    signatures: Vec<Duration>,
    combined: Vec<Duration>,
    apply: Vec<Duration>,
    elapsed: Duration,
    max_backlog: usize,
}

struct AncestorPhaseResult {
    ancestor_setup: Vec<Duration>,
    leaf: Vec<BuildTiming>,
    apply: Vec<Duration>,
    sample_wall: Vec<Duration>,
}

#[derive(Clone, Copy)]
struct BuildTiming {
    total: Duration,
    batches: Duration,
    workload: Duration,
    compute: Duration,
    history_append: Duration,
    merkle_wall: Duration,
    state_merkleize: Duration,
    history_merkleize: Duration,
}

struct ApplyJob {
    height: usize,
    batch: MerkleizedDbs,
}

struct Builder {
    keys: Vec<AccountKey>,
    nonces: Vec<u64>,
    cursor: usize,
    height: usize,
    tip: Option<MerkleizedDbs>,
}

struct SigningAccount {
    private_key: ed25519::PrivateKey,
    public_key: ed25519::PublicKey,
}

struct SignatureFixture {
    encoded: Vec<Bytes>,
    cache: PublicKeyCache,
}

impl SignatureFixture {
    fn new(context: tokio::Context, strategy: &Rayon, count: usize) -> Self {
        let accounts: Vec<_> = (0..count)
            .map(|index| {
                let private_key = ed25519::PrivateKey::from_seed(index as u64);
                let public_key = private_key.public_key();
                SigningAccount {
                    private_key,
                    public_key,
                }
            })
            .collect();
        let encoded = strategy.map_collect_vec(0..count, |index| {
            let sender = &accounts[index];
            let recipient = &accounts[(index + 1) % accounts.len()];
            let transaction = Transaction::new(
                TransactionPublicKey::ed25519(sender.public_key.clone()),
                TransactionPublicKey::ed25519(recipient.public_key.clone()),
                NZU64!(1),
                0,
            )
            .seal_and_sign(
                &sender.private_key,
                TRANSACTION_NAMESPACE,
                &mut Sha256::default(),
            );
            let mut bytes = Vec::with_capacity(
                transaction.encode_size().encode_size() + transaction.encode_size(),
            );
            transaction.encode_size().write(&mut bytes);
            transaction.write(&mut bytes);
            Bytes::from(bytes)
        });
        Self {
            encoded,
            cache: PublicKeyCache::new(
                context,
                NonZeroUsize::new(count.saturating_mul(2).max(1))
                    .expect("signature cache capacity is nonzero"),
            ),
        }
    }

    fn fresh_body(&self) -> Arc<Vec<LazySignedTransaction<Sha256>>> {
        Arc::new(
            self.encoded
                .iter()
                .map(|encoded| {
                    LazySignedTransaction::read(&mut encoded.clone())
                        .expect("benchmark transaction must decode lazily")
                })
                .collect(),
        )
    }

    fn start(
        &self,
        strategy: &Rayon,
        body: Arc<Vec<LazySignedTransaction<Sha256>>>,
        seed: u64,
    ) -> impl core::future::Future<Output = Duration> + Send + 'static {
        let cache = self.cache.clone();
        strategy.spawn(move |strategy| {
            let started = Instant::now();
            let mut rng = TestRng::new(seed);
            assert!(
                preload_transaction_slice(body.as_slice(), &strategy)
                    && verify_transaction_batch(
                        TRANSACTION_NAMESPACE,
                        &mut rng,
                        &cache,
                        body.as_slice(),
                        &strategy,
                    ),
                "production-shaped signatures must verify",
            );
            started.elapsed()
        })
    }
}

impl Builder {
    fn new(keys: Vec<AccountKey>) -> Self {
        let accounts = keys.len();
        Self {
            keys,
            nonces: vec![0; accounts],
            cursor: 0,
            height: 0,
            tip: None,
        }
    }

    async fn build_next(
        &mut self,
        txs: usize,
        dbs: &Dbs,
        strategy: &Rayon,
        applied_height: usize,
    ) -> (usize, MerkleizedDbs, BuildTiming) {
        let start = Instant::now();
        let batches_start = Instant::now();
        let batches = if applied_height == self.height {
            // Once physical state catches up, release the pending chain and root the next block
            // directly at the newly published database generation.
            drop(self.tip.take());
            dbs.new_batches().await
        } else {
            Dbs::fork_batches(
                self.tip
                    .as_ref()
                    .expect("an unapplied logical tip must remain forkable"),
            )
        };
        let batches_elapsed = batches_start.elapsed();

        let workload_start = Instant::now();
        let mut transfers = Vec::with_capacity(txs);
        let mut digests = Vec::with_capacity(txs);
        for offset in 0..txs {
            let sender_index = (self.cursor + offset) % self.keys.len();
            let recipient_index = (sender_index + 1) % self.keys.len();
            let nonce = self.nonces[sender_index];
            self.nonces[sender_index] = nonce.checked_add(1).expect("nonce overflow");
            let sender = self.keys[sender_index];
            let recipient = self.keys[recipient_index];
            transfers.push(PreparedTransfer {
                sender,
                recipient,
                sender_prefix: sender.prefix(),
                recipient_prefix: recipient.prefix(),
                value: 1,
                nonce,
            });

            let block_bytes = (self.height as u64 + 1).to_le_bytes();
            let offset_bytes = (offset as u64).to_le_bytes();
            digests.push(Sha256::hash(&[&block_bytes, &offset_bytes]));
        }
        self.cursor = (self.cursor + txs) % self.keys.len();
        let workload_elapsed = workload_start.elapsed();

        let (state_batch, mut transaction_batch) = batches;
        let compute_start = Instant::now();
        let (staged, updates) =
            consensus::compute(state_batch, Arc::new(transfers), strategy).await;
        let compute_elapsed = compute_start.elapsed();
        let updates = updates.expect("production-shaped transfers must execute");
        let history_append_start = Instant::now();
        for digest in digests {
            transaction_batch = transaction_batch.append(digest);
        }
        let history_append_elapsed = history_append_start.elapsed();
        let merkle_start = Instant::now();
        let (state, transactions) = futures::join!(
            async move {
                let start = Instant::now();
                (staged.merkleize(updates, Vec::new()).await, start.elapsed())
            },
            async move {
                let start = Instant::now();
                (transaction_batch.merkleize().await, start.elapsed())
            },
        );
        let merkle_wall = merkle_start.elapsed();
        let (state, state_merkleize) = state;
        let (transactions, history_merkleize) = transactions;
        let next = (
            state.expect("state merkleization"),
            transactions.expect("transaction-history merkleization"),
        );

        self.height += 1;
        self.tip = Some(next.clone());
        (
            self.height,
            next,
            BuildTiming {
                total: start.elapsed(),
                batches: batches_elapsed,
                workload: workload_elapsed,
                compute: compute_elapsed,
                history_append: history_append_elapsed,
                merkle_wall,
                state_merkleize,
                history_merkleize,
            },
        )
    }

    const fn tip(&self) -> &MerkleizedDbs {
        self.tip.as_ref().expect("at least one block was built")
    }
}

fn key(index: u64) -> AccountKey {
    AccountKey::try_from(Sha256::hash(&[&index.to_le_bytes()]).as_ref()).expect("32-byte key")
}

fn state_config(strategy: Rayon, cache: &CacheRef) -> FixedConfig<EightCap, Rayon, NonZeroUsize> {
    let init_concurrency = NonZeroUsize::new(strategy.manual().parallelism())
        .expect("strategy parallelism must be non-zero");
    FixedConfig {
        merkle_config: MmrConfig {
            journal_partition: "cadence-state-journal".into(),
            metadata_partition: "cadence-state-metadata".into(),
            items_per_blob: NZU64!(1_048_576 * 25),
            write_buffer: NZUsize!(8 * 1024 * 1024),
            strategy,
            page_cache: cache.clone(),
        },
        journal_config: FixedJournalConfig {
            partition: "cadence-state-log".into(),
            items_per_blob: NZU64!(1_048_576 * 25),
            page_cache: cache.clone(),
            write_buffer: NZUsize!(8 * 1024 * 1024),
        },
        translator: EightCap,
        init_cache_size: Some(NZUsize!(1 << 18)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency,
    }
}

fn transaction_config(strategy: Rayon, cache: &CacheRef) -> keyless_fixed::CompactConfig<Rayon> {
    keyless_fixed::CompactConfig {
        strategy,
        witness: VariableJournalConfig {
            partition: "cadence-transactions-witness".into(),
            items_per_section: NZU64!(64),
            compression: None,
            codec_config: (),
            page_cache: cache.clone(),
            write_buffer: NZUsize!(8 * 1024 * 1024),
        },
        commit_codec_config: (),
    }
}

fn sample_stats(samples: &[Duration]) -> (Duration, Duration, Duration, Duration) {
    assert!(!samples.is_empty(), "at least one sample is required");
    let mean = samples.iter().copied().sum::<Duration>() / samples.len() as u32;
    let mut ordered = samples.to_vec();
    ordered.sort_unstable();
    let p50 = ordered[(ordered.len() - 1) * 50 / 100];
    let p95 = ordered[(ordered.len() - 1) * 95 / 100];
    let max = *ordered.last().expect("samples are nonempty");
    (mean, p50, p95, max)
}

fn print_duration_stats(name: &str, samples: impl Iterator<Item = Duration>) {
    let samples: Vec<_> = samples.collect();
    let (mean, p50, p95, max) = sample_stats(&samples);
    println!("    {name}: mean {mean:?}, p50 {p50:?}, p95 {p95:?}, max {max:?}");
}

async fn receive_apply(
    completed: &mut mpsc::UnboundedReceiver<(usize, Duration)>,
    expected: usize,
    samples: &mut Vec<Duration>,
) {
    let (applied, elapsed) = completed
        .recv()
        .await
        .expect("continuous apply worker must report every batch");
    assert_eq!(applied, expected, "database applies must remain FIFO");
    samples.push(elapsed);
}

fn enqueue_apply(
    jobs: &mpsc::UnboundedSender<ApplyJob>,
    backlog: &AtomicUsize,
    max_backlog: &AtomicUsize,
    height: usize,
    batch: MerkleizedDbs,
) {
    let queued = backlog.fetch_add(1, Ordering::AcqRel) + 1;
    max_backlog.fetch_max(queued, Ordering::Relaxed);
    assert!(
        jobs.send(ApplyJob { height, batch }).is_ok(),
        "continuous apply worker must remain active"
    );
}

#[allow(clippy::too_many_arguments)]
async fn run_phase(
    blocks: usize,
    txs: usize,
    builder: &mut Builder,
    dbs: &Dbs,
    strategy: &Rayon,
    signature_strategy: &Rayon,
    signature_fixture: Option<&SignatureFixture>,
    jobs: &mpsc::UnboundedSender<ApplyJob>,
    completed: &mut mpsc::UnboundedReceiver<(usize, Duration)>,
    applied_height: &AtomicUsize,
    backlog: &AtomicUsize,
    max_backlog: &AtomicUsize,
    max_pending_applies: usize,
) -> PhaseResult {
    assert!(blocks > 0, "phase must contain at least one block");
    max_backlog.store(0, Ordering::Relaxed);
    let phase_start = Instant::now();
    let mut build = Vec::with_capacity(blocks);
    let mut signatures = Vec::with_capacity(blocks);
    let mut combined = Vec::with_capacity(blocks);
    let mut apply = Vec::with_capacity(blocks);
    let first_height = builder.height + 1;
    let mut next_completion = first_height;
    let mut outstanding = 0usize;

    for _ in 0..blocks {
        if outstanding == max_pending_applies {
            receive_apply(completed, next_completion, &mut apply).await;
            next_completion += 1;
            outstanding -= 1;
        }

        let signature_body = signature_fixture.map(SignatureFixture::fresh_body);
        let combined_start = Instant::now();
        let signature = signature_fixture
            .zip(signature_body)
            .map(|(fixture, body)| {
                fixture.start(signature_strategy, body, builder.height as u64 + 1)
            });
        let (height, next, elapsed) = builder
            .build_next(txs, dbs, strategy, applied_height.load(Ordering::Acquire))
            .await;
        build.push(elapsed);
        if let Some(signature) = signature {
            signatures.push(signature.await);
            combined.push(combined_start.elapsed());
        }
        enqueue_apply(jobs, backlog, max_backlog, height, next);
        outstanding += 1;
    }

    while next_completion <= builder.height {
        receive_apply(completed, next_completion, &mut apply).await;
        next_completion += 1;
    }

    PhaseResult {
        build,
        signatures,
        combined,
        apply,
        elapsed: phase_start.elapsed(),
        max_backlog: max_backlog.load(Ordering::Relaxed),
    }
}

async fn run_forced_ancestor_phase(
    samples: usize,
    depth: usize,
    txs: usize,
    builder: &mut Builder,
    dbs: &Dbs,
    strategy: &Rayon,
) -> AncestorPhaseResult {
    assert!(samples > 0, "phase must contain at least one sample");
    assert!(depth > 0, "forced ancestor depth must be nonzero");
    let mut ancestor_setup = Vec::with_capacity(samples);
    let mut leaf = Vec::with_capacity(samples);
    let mut apply = Vec::with_capacity(samples);
    let mut sample_wall = Vec::with_capacity(samples);

    for _ in 0..samples {
        let sample_start = Instant::now();
        let applied_height = builder.height;
        let setup_start = Instant::now();
        let mut retained = Vec::with_capacity(depth);
        for offset in 0..depth {
            let (height, ancestor, _) =
                builder.build_next(txs, dbs, strategy, applied_height).await;
            assert_eq!(
                height,
                applied_height + offset + 1,
                "forced ancestors must remain consecutive",
            );
            retained.push(ancestor);
        }
        ancestor_setup.push(setup_start.elapsed());

        let (height, tail, timing) = builder.build_next(txs, dbs, strategy, applied_height).await;
        assert_eq!(height, applied_height + depth + 1);
        assert_eq!(
            tail.0.bounds().ancestors.len(),
            depth,
            "timed state leaf must resolve through the requested pending depth",
        );
        leaf.push(timing);

        let apply_start = Instant::now();
        dbs.apply(tail).await;
        apply.push(apply_start.elapsed());
        sample_wall.push(sample_start.elapsed());
        drop(retained);

        let committed = dbs.committed_targets().await;
        assert!(
            Dbs::matches_sync_targets(builder.tip(), &committed),
            "applied state and history must match the forced-depth logical tip",
        );
    }

    AncestorPhaseResult {
        ancestor_setup,
        leaf,
        apply,
        sample_wall,
    }
}

fn main() {
    let accounts = env_or("CONSTANTINOPLE_BENCH_ACCOUNTS", DEFAULT_ACCOUNTS);
    let txs = env_or("CONSTANTINOPLE_BENCH_TXS", DEFAULT_TXS);
    let warmup = env_or("CONSTANTINOPLE_BENCH_WARMUP_BLOCKS", DEFAULT_WARMUP_BLOCKS);
    let blocks = env_or("CONSTANTINOPLE_BENCH_BLOCKS", DEFAULT_BLOCKS);
    let required_tps = env_optional::<f64>("CONSTANTINOPLE_BENCH_REQUIRE_TPS");
    let verify_signatures = env_flag("CONSTANTINOPLE_BENCH_VERIFY_SIGNATURES");
    let forced_ancestor_depth = env_optional::<usize>("CONSTANTINOPLE_BENCH_FORCED_ANCESTOR_DEPTH");
    let tokio_workers = env_or("CONSTANTINOPLE_BENCH_TOKIO_WORKERS", DEFAULT_TOKIO_WORKERS).max(1);
    let engine_workers = env_or(
        "CONSTANTINOPLE_BENCH_ENGINE_WORKERS",
        DEFAULT_ENGINE_WORKERS,
    )
    .max(1);
    let signature_workers = env_optional("CONSTANTINOPLE_BENCH_SIGNATURE_WORKERS");
    assert!(
        signature_workers.is_none_or(|workers| workers > 0),
        "a dedicated signature pool must contain at least one worker"
    );
    let cache_pages = env_or("CONSTANTINOPLE_BENCH_CACHE_PAGES", DEFAULT_CACHE_PAGES).max(1);
    let max_pending_applies = env_or(
        "CONSTANTINOPLE_BENCH_MAX_PENDING_APPLIES",
        DEFAULT_MAX_PENDING_APPLIES,
    )
    .max(1);
    assert!(
        accounts > 1,
        "account universe must contain at least two accounts"
    );
    assert!(txs > 0 && txs < accounts, "txs must be in 1..accounts");
    assert!(
        warmup > 0 && blocks > 0,
        "warmup and measured blocks must be nonzero"
    );
    assert!(
        required_tps.is_none_or(|required| required.is_finite() && required > 0.0),
        "required TPS must be finite and positive",
    );
    assert!(
        forced_ancestor_depth.is_none_or(|depth| depth > 0),
        "forced ancestor depth must be positive",
    );
    assert!(
        forced_ancestor_depth.is_none() || !verify_signatures,
        "forced ancestor mode isolates the state/history path and does not verify signatures",
    );
    assert!(
        forced_ancestor_depth.is_none() || required_tps.is_none(),
        "forced ancestor mode reports path latency rather than a TPS acceptance rate",
    );

    tokio::Runner::new(tokio::Config::default().with_worker_threads(tokio_workers)).start(
        move |context| async move {
            let strategy = Rayon::new(NonZeroUsize::new(engine_workers).expect("workers"))
                .expect("rayon pool");
            let signature_strategy = signature_workers.map_or_else(
                || strategy.clone(),
                |workers| {
                    Rayon::new(NonZeroUsize::new(workers).expect("signature workers"))
                        .expect("signature rayon pool")
                },
            );
            let page_size = paged_page_size(4_096);
            let state_cache = CacheRef::from_pooler(
                &context,
                page_size,
                NonZeroUsize::new(cache_pages).expect("state cache pages"),
            );
            let other_cache = CacheRef::from_pooler(
                &context,
                page_size,
                NonZeroUsize::new(cache_pages).expect("history cache pages"),
            );
            let dbs = Dbs::init(
                context.child("cadence_dbs"),
                (
                    state_config(strategy.clone(), &state_cache),
                    transaction_config(strategy.clone(), &other_cache),
                ),
            )
            .await;

            let keys = (0..accounts as u64).map(key).collect::<Vec<_>>();
            let (mut state, transactions) = dbs.new_batches().await;
            for account_key in &keys {
                state = state.write(
                    *account_key,
                    Some(Account {
                        balance: 1_000_000,
                        nonce: Nonce::default(),
                    }),
                );
            }
            let (state, transactions) = futures::join!(state.merkleize(), transactions.merkleize());
            dbs.apply((
                state.expect("seed state merkleization"),
                transactions.expect("seed history merkleization"),
            ))
            .await;
            assert!(dbs.finalize().await.durable().await, "seed must be durable");
            eprintln!("seeded and durably initialized {accounts} accounts");

            let signature_fixture = verify_signatures.then(|| {
                SignatureFixture::new(
                    context.child("cadence_signatures"),
                    &signature_strategy,
                    txs,
                )
            });
            if signature_fixture.is_some() {
                eprintln!("prepared {txs} fresh-decode signature fixtures");
            }

            if let Some(depth) = forced_ancestor_depth {
                let mut builder = Builder::new(keys);
                let warmup_result = run_forced_ancestor_phase(
                    warmup,
                    depth,
                    txs,
                    &mut builder,
                    &dbs,
                    &strategy,
                )
                .await;
                drop(warmup_result);
                let measured = run_forced_ancestor_phase(
                    blocks,
                    depth,
                    txs,
                    &mut builder,
                    &dbs,
                    &strategy,
                )
                .await;

                let sync_start = Instant::now();
                assert!(
                    dbs.finalize().await.durable().await,
                    "forced-depth tail must become durable",
                );
                let sync_elapsed = sync_start.elapsed();
                println!(
                    "forced ancestor state path: {accounts} accounts, {txs} tx/block, depth {depth}, \
                     {tokio_workers} tokio + {engine_workers} engine workers, {cache_pages} cache pages/db",
                );
                print_duration_stats(
                    "ancestor setup",
                    measured.ancestor_setup.iter().copied(),
                );
                print_duration_stats("leaf build", measured.leaf.iter().map(|timing| timing.total));
                print_duration_stats(
                    "leaf compute",
                    measured.leaf.iter().map(|timing| timing.compute),
                );
                print_duration_stats(
                    "leaf state merkleize",
                    measured.leaf.iter().map(|timing| timing.state_merkleize),
                );
                print_duration_stats(
                    "leaf history merkleize",
                    measured.leaf.iter().map(|timing| timing.history_merkleize),
                );
                print_duration_stats("tail apply/flush", measured.apply.iter().copied());
                print_duration_stats(
                    "full sample wall",
                    measured.sample_wall.iter().copied(),
                );
                println!("  prune-boundary durability: {sync_elapsed:?}");
                for metric in context.encode().lines().filter(|line| {
                    line.contains("rebuilds") || line.contains("folds")
                }) {
                    println!("  {metric}");
                }
                return;
            }

            let (jobs, mut job_receiver) = mpsc::unbounded_channel::<ApplyJob>();
            let (completion_sender, mut completions) = mpsc::unbounded_channel();
            let applied_height = Arc::new(AtomicUsize::new(0));
            let backlog = Arc::new(AtomicUsize::new(0));
            let max_backlog = Arc::new(AtomicUsize::new(0));
            let apply_dbs = dbs.clone();
            let apply_height = Arc::clone(&applied_height);
            let apply_backlog = Arc::clone(&backlog);
            let writer = context.child("cadence_writer").spawn(move |_| async move {
                while let Some(ApplyJob { height, batch }) = job_receiver.recv().await {
                    let start = Instant::now();
                    apply_dbs.apply(batch).await;
                    apply_height.store(height, Ordering::Release);
                    apply_backlog.fetch_sub(1, Ordering::AcqRel);
                    if completion_sender.send((height, start.elapsed())).is_err() {
                        return;
                    }
                }
            });
            let mut builder = Builder::new(keys);
            let warmup_result = run_phase(
                warmup,
                txs,
                &mut builder,
                &dbs,
                &strategy,
                &signature_strategy,
                signature_fixture.as_ref(),
                &jobs,
                &mut completions,
                &applied_height,
                &backlog,
                &max_backlog,
                max_pending_applies,
            )
            .await;
            assert_eq!(backlog.load(Ordering::Acquire), 0, "warmup must drain");
            drop(warmup_result);

            let measured = run_phase(
                blocks,
                txs,
                &mut builder,
                &dbs,
                &strategy,
                &signature_strategy,
                signature_fixture.as_ref(),
                &jobs,
                &mut completions,
                &applied_height,
                &backlog,
                &max_backlog,
                max_pending_applies,
            )
            .await;
            assert_eq!(backlog.load(Ordering::Acquire), 0, "measured phase must drain");
            drop(jobs);
            writer.await.expect("continuous apply writer");
            if builder.tip.is_some() {
                let applied_targets = dbs.committed_targets().await;
                assert!(
                    Dbs::matches_sync_targets(builder.tip(), &applied_targets),
                    "both database targets must match the final logical tip"
                );
            }

            let sync_start = Instant::now();
            assert!(
                dbs.finalize().await.durable().await,
                "final prune-boundary sync must be durable"
            );
            let sync_elapsed = sync_start.elapsed();

            println!(
                "cadence: {accounts} accounts, {txs} tx/block, \
                 {tokio_workers} tokio + {engine_workers} engine workers + {} signature workers, {cache_pages} cache pages/db, \
                 {max_pending_applies} max pending applies, signatures {}",
                signature_workers.map_or_else(|| "shared".to_string(), |workers| workers.to_string()),
                if verify_signatures { "on" } else { "off" },
            );
            println!(
                "  acceptance: TPS {}",
                required_tps.map_or_else(|| "unbounded".to_string(), |value| value.to_string()),
            );
            let build_total: Vec<_> = measured
                .build
                .iter()
                .map(|timing| timing.total)
                .collect();
                    let (build_mean, build_p50, build_p95, build_max) =
                        sample_stats(&build_total);
                    let (apply_mean, apply_p50, apply_p95, apply_max) =
                        sample_stats(&measured.apply);
                    let total_txs = txs.checked_mul(blocks).expect("transaction count overflow");
                    let throughput = total_txs as f64 / measured.elapsed.as_secs_f64();
                    let cycle = measured.elapsed / blocks as u32;
                    println!(
                        "  build: mean {build_mean:?}, p50 {build_p50:?}, p95 {build_p95:?}, max {build_max:?}"
                    );
                    print_duration_stats(
                        "batches",
                        measured.build.iter().map(|timing| timing.batches),
                    );
                    print_duration_stats(
                        "workload",
                        measured.build.iter().map(|timing| timing.workload),
                    );
                    print_duration_stats(
                        "compute",
                        measured.build.iter().map(|timing| timing.compute),
                    );
                    print_duration_stats(
                        "history append",
                        measured
                            .build
                            .iter()
                            .map(|timing| timing.history_append),
                    );
                    print_duration_stats(
                        "merkle wall",
                        measured.build.iter().map(|timing| timing.merkle_wall),
                    );
                    print_duration_stats(
                        "state merkleize",
                        measured
                            .build
                            .iter()
                            .map(|timing| timing.state_merkleize),
                    );
                    print_duration_stats(
                        "history merkleize",
                        measured
                            .build
                            .iter()
                            .map(|timing| timing.history_merkleize),
                    );
                    if !measured.combined.is_empty() {
                        let (signature_mean, signature_p50, signature_p95, signature_max) =
                            sample_stats(&measured.signatures);
                        let (combined_mean, combined_p50, combined_p95, combined_max) =
                            sample_stats(&measured.combined);
                        println!(
                            "  signatures under contention: mean {signature_mean:?}, p50 {signature_p50:?}, p95 {signature_p95:?}, max {signature_max:?}"
                        );
                        println!(
                            "  verify wall (signatures || build): mean {combined_mean:?}, p50 {combined_p50:?}, p95 {combined_p95:?}, max {combined_max:?}"
                        );
                    }
                    println!(
                        "  apply: mean {apply_mean:?}, p50 {apply_p50:?}, p95 {apply_p95:?}, max {apply_max:?}"
                    );
                    println!(
                        "  drained cadence: {:?} total, {cycle:?}/block, {:.0} TPS, max apply backlog {}",
                        measured.elapsed, throughput, measured.max_backlog
                    );
                    if let Some(required) = required_tps {
                        assert!(
                            throughput >= required,
                            "drained throughput {throughput:.0} TPS is below required {required:.0} TPS"
                        );
                    }
            println!("  prune-boundary durability: {sync_elapsed:?}");
            for metric in context.encode().lines().filter(|line| {
                line.contains("rebuilds") || line.contains("folds")
            }) {
                println!("  {metric}");
            }

        },
    );
}
