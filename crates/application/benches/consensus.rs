use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_codec::{Decode as _, Encode as _, EncodeSize as _};
use commonware_consensus::{
    Reporter,
    marshal::Update,
    simplex::types::Context,
    types::{Round, View},
};
use commonware_cryptography::{
    Digest as _, Digestible as _, Signer as _,
    certificate::{Attestation, Scheme as CertificateScheme, Subject, Verifier},
    ed25519, sha256,
};
use commonware_glue::stateful::db::{DatabaseSet, Merkleized as _, Unmerkleized as _};
use commonware_parallel::Rayon;
use commonware_runtime::{
    Error as RuntimeError, Handle, Metrics as _, Storage as _, Supervisor, ThreadPooler,
    benchmarks::{context as bench_context, tokio as bench_tokio},
    buffer::paged::CacheRef,
    tokio::{Config as RuntimeConfig, Context as RuntimeContext},
};
use commonware_storage::{
    journal::contiguous::fixed::Config as FixedJournalConfig,
    merkle::{compact::Config as CompactMerkleConfig, full::Config as MmrConfig},
    mmr,
    qmdb::{
        any::{FixedConfig, unordered::fixed},
        keyless::fixed as keyless_fixed,
    },
    translator::EightCap,
};
use commonware_utils::{
    Acknowledgement, Faults, NZU16, NZU64, NZUsize, non_empty_range, sequence::U64,
    sync::AsyncRwLock,
};
use constantinople_application::consensus::{Application, TransactionHistoryDb};
use constantinople_mempool::{TransactionSource, webserver};
use constantinople_primitives::{
    Account, AccountKey, Block, BlockCfg, DEFAULT_ACCOUNT_BALANCE, Header, Nonce, Sealable,
    SealedBlock, TRANSACTION_NAMESPACE, Transaction, TransactionPublicKey, VerifiedTransaction,
};
use criterion::{
    BenchmarkId, Criterion, Throughput, async_executor::AsyncExecutor as _, criterion_group,
    criterion_main,
};
use std::{
    collections::VecDeque,
    future::{Future, ready},
    hint::black_box,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

type TestHasher = sha256::Sha256;
type TestCommitment = sha256::Digest;
type TestPublicKey = ed25519::PublicKey;
type TestTransaction = VerifiedTransaction<TestHasher>;
type TestTransactionSource = BenchTransactionSource;
type TestMempool = webserver::Mailbox<TestCommitment, TestPublicKey, TestHasher>;
type TestApplication = Application<
    RuntimeContext,
    TestHasher,
    TestCommitment,
    BenchScheme,
    TestPublicKey,
    TestTransactionSource,
    ed25519::Batch,
    Rayon,
    Rayon,
>;
type TestMempoolApplication = Application<
    RuntimeContext,
    TestHasher,
    TestCommitment,
    BenchScheme,
    TestPublicKey,
    TestMempool,
    ed25519::Batch,
    Rayon,
    Rayon,
>;
type TestStateDb =
    fixed::Db<mmr::Family, RuntimeContext, AccountKey, Account, TestHasher, EightCap, Rayon>;
type TestStateDatabase = Arc<AsyncRwLock<TestStateDb>>;
type TestTransactionDb = TransactionHistoryDb<RuntimeContext, TestHasher, Rayon>;
type TestTransactionDatabase = Arc<AsyncRwLock<TestTransactionDb>>;
type TestDatabases = (TestStateDatabase, TestTransactionDatabase);
type TestMerkleizedDatabases = <TestDatabases as DatabaseSet<RuntimeContext>>::Merkleized;
type TestUnmerkleizedDatabases = <TestDatabases as DatabaseSet<RuntimeContext>>::Unmerkleized;
type TestBlock = SealedBlock<TestCommitment, TestPublicKey, TestHasher>;
type TestConsensusContext = Context<TestCommitment, TestPublicKey>;

const PROD_LIKE_TRANSACTION_COUNT: usize = 16_384;
const PROD_LIKE_ACCOUNTS_PER_STREAM: usize = 16_384;
const PROD_LIKE_SUBMITTERS: usize = 50;
const PROD_LIKE_ACCOUNT_COUNT: usize = PROD_LIKE_ACCOUNTS_PER_STREAM * PROD_LIKE_SUBMITTERS;
const PROD_LIKE_ACCOUNT_SEED_OFFSET: u64 = 1_000;
const PROD_LIKE_WARMUP_BLOCKS: u64 = 256;
const PROD_LIKE_MAX_PROPOSE_BYTES: usize = 8 * 1024 * 1024;
const PROD_LIKE_MAX_POOL_BYTES: usize = 64 * 1024 * 1024;
const PROD_LIKE_RAYON_THREADS: usize = 2;
const BASELINE_RAYON_THREADS: usize = 8;
const BENCH_CASES: &[BenchCase] = &[
    BenchCase {
        transaction_count: PROD_LIKE_TRANSACTION_COUNT,
        workload: Workload::ProdLike,
        rayon_threads: PROD_LIKE_RAYON_THREADS,
    },
    BenchCase {
        transaction_count: 32_768,
        workload: Workload::Unique,
        rayon_threads: BASELINE_RAYON_THREADS,
    },
];
const STATE_ITEMS_PER_BLOB: NonZeroU64 = NZU64!(1_048_576 * 25);
const TRANSACTION_ITEMS_PER_SECTION: NonZeroU64 = NZU64!(4_096);
const WRITE_BUFFER: NonZeroUsize = NZUsize!(8 * 1024 * 1024);
const PAGE_CACHE_PAGE_SIZE: NonZeroU16 = NZU16!(8192);
const PAGE_CACHE_CAPACITY: NonZeroUsize = NZUsize!(65_536);

#[derive(Clone, Copy)]
struct BenchCase {
    transaction_count: usize,
    workload: Workload,
    rayon_threads: usize,
}

impl BenchCase {
    fn id(self) -> String {
        match self.workload {
            Workload::Unique => self.transaction_count.to_string(),
            Workload::ProdLike => format!("{}-prod-like", self.transaction_count),
        }
    }
}

#[derive(Clone, Copy)]
enum Workload {
    Unique,
    ProdLike,
}

#[derive(Clone, Default)]
struct BenchTransactionSource {
    proposals: VecDeque<BenchProposal>,
    proposed: VecDeque<(u64, Vec<TestCommitment>)>,
}

impl BenchTransactionSource {
    fn new(case: BenchCase, transactions: Vec<TestTransaction>) -> Self {
        match case.workload {
            Workload::Unique => Self::static_source(transactions),
            Workload::ProdLike => Self::mempool_like(transactions),
        }
    }

    fn static_source(transactions: Vec<TestTransaction>) -> Self {
        Self {
            proposals: VecDeque::from([BenchProposal::Static(transactions)]),
            proposed: VecDeque::new(),
        }
    }

    fn mempool_like(transactions: Vec<TestTransaction>) -> Self {
        let pool = transactions
            .chunks(PROD_LIKE_ACCOUNTS_PER_STREAM)
            .map(|chunk| {
                let transactions = chunk.to_vec();
                let total_bytes = total_bytes_for(&transactions);
                BenchPoolEntry {
                    transactions,
                    total_bytes,
                }
            })
            .collect();

        Self {
            proposals: VecDeque::from([BenchProposal::MempoolLike {
                pool,
                max_propose_bytes: PROD_LIKE_MAX_PROPOSE_BYTES,
            }]),
            proposed: VecDeque::new(),
        }
    }

    fn pop_proposal(&mut self, height: u64) -> Vec<TestTransaction> {
        let Some(proposal) = self.proposals.pop_front() else {
            return Vec::new();
        };

        match proposal {
            BenchProposal::Static(transactions) => transactions,
            BenchProposal::MempoolLike {
                mut pool,
                max_propose_bytes,
            } => {
                let transactions = self.drain_mempool_like(height, &mut pool, max_propose_bytes);
                if !pool.is_empty() {
                    self.proposals.push_front(BenchProposal::MempoolLike {
                        pool,
                        max_propose_bytes,
                    });
                }
                transactions
            }
        }
    }

    fn drain_mempool_like(
        &mut self,
        height: u64,
        pool: &mut VecDeque<BenchPoolEntry>,
        max_propose_bytes: usize,
    ) -> Vec<TestTransaction> {
        let mut batch_txs = Vec::new();
        let mut batch_bytes = 0;

        while let Some(entry) = pool.front() {
            if batch_bytes + entry.total_bytes > max_propose_bytes && !batch_txs.is_empty() {
                break;
            }
            let entry = pool.pop_front().expect("front was Some");
            batch_bytes += entry.total_bytes;

            let mut digests = Vec::with_capacity(entry.transactions.len());
            for transaction in &entry.transactions {
                digests.push(*transaction.message_digest());
            }
            self.proposed.push_back((height, digests));
            batch_txs.extend(entry.transactions);
        }

        black_box(batch_bytes);
        black_box(self.proposed.len());
        batch_txs
    }
}

#[derive(Clone)]
enum BenchProposal {
    Static(Vec<TestTransaction>),
    MempoolLike {
        pool: VecDeque<BenchPoolEntry>,
        max_propose_bytes: usize,
    },
}

#[derive(Clone)]
struct BenchPoolEntry {
    transactions: Vec<TestTransaction>,
    total_bytes: usize,
}

impl TransactionSource<TestCommitment, TestPublicKey, TestHasher> for BenchTransactionSource {
    fn propose(
        &mut self,
        parent: &Header<TestCommitment, TestCommitment, TestPublicKey>,
        _context: &Context<TestCommitment, TestPublicKey>,
    ) -> impl Future<Output = Vec<TestTransaction>> + Send {
        ready(self.pop_proposal(parent.height + 1))
    }
}

impl Reporter for BenchTransactionSource {
    type Activity = Update<TestBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Update::Block(_, acknowledgement) = activity {
            acknowledgement.acknowledge();
        }
        Feedback::Ok
    }
}

fn total_bytes_for(transactions: &[TestTransaction]) -> usize {
    transactions
        .iter()
        .map(|transaction| transaction.encode_size())
        .sum::<usize>()
}

#[derive(Clone, Copy, Debug)]
struct BenchSubject<'a> {
    message: &'a [u8],
}

impl Subject for BenchSubject<'_> {
    type Namespace = Vec<u8>;

    fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
        derived
    }

    fn message(&self) -> Bytes {
        Bytes::copy_from_slice(self.message)
    }
}

#[derive(Clone, Debug)]
struct BenchScheme;

impl Verifier for BenchScheme {
    type Subject<'a, D: commonware_cryptography::Digest> = BenchSubject<'a>;
    type PublicKey = TestPublicKey;
    type Certificate = U64;

    fn verify_certificate<R, D, M>(
        &self,
        _rng: &mut R,
        _subject: Self::Subject<'_, D>,
        _certificate: &Self::Certificate,
        _strategy: &impl commonware_parallel::Strategy,
    ) -> bool
    where
        R: rand_core::CryptoRngCore,
        D: commonware_cryptography::Digest,
        M: Faults,
    {
        unreachable!("benchmark scheme is never instantiated")
    }

    fn is_batchable() -> bool {
        true
    }

    fn certificate_codec_config(&self) {}

    fn certificate_codec_config_unbounded() {}
}

impl CertificateScheme for BenchScheme {
    type Signature = U64;

    fn me(&self) -> Option<commonware_utils::Participant> {
        unreachable!("benchmark scheme is never instantiated")
    }

    fn participants(&self) -> &commonware_utils::ordered::Set<Self::PublicKey> {
        unreachable!("benchmark scheme is never instantiated")
    }

    fn sign<D: commonware_cryptography::Digest>(
        &self,
        _subject: Self::Subject<'_, D>,
    ) -> Option<Attestation<Self>> {
        unreachable!("benchmark scheme is never instantiated")
    }

    fn verify_attestation<R, D>(
        &self,
        _rng: &mut R,
        _subject: Self::Subject<'_, D>,
        _attestation: &Attestation<Self>,
        _strategy: &impl commonware_parallel::Strategy,
    ) -> bool
    where
        R: rand_core::CryptoRngCore,
        D: commonware_cryptography::Digest,
    {
        unreachable!("benchmark scheme is never instantiated")
    }

    fn assemble<I, M>(
        &self,
        _attestations: I,
        _strategy: &impl commonware_parallel::Strategy,
    ) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = Attestation<Self>>,
        I::IntoIter: Send,
        M: Faults,
    {
        unreachable!("benchmark scheme is never instantiated")
    }

    fn is_attributable() -> bool {
        true
    }
}

#[derive(Clone, Copy)]
enum Operation {
    Propose,
    BuildAfterFinalize,
    BuildQueuedByFinalize,
    BuildWithMempool,
    Verify,
    VerifyDecoded,
    Apply,
}

impl Operation {
    const ALL: [Self; 7] = [
        Self::Propose,
        Self::BuildAfterFinalize,
        Self::BuildQueuedByFinalize,
        Self::BuildWithMempool,
        Self::Verify,
        Self::VerifyDecoded,
        Self::Apply,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Propose => "propose",
            Self::BuildAfterFinalize => "build-after-finalize",
            Self::BuildQueuedByFinalize => "build-queued-by-finalize",
            Self::BuildWithMempool => "build-with-mempool",
            Self::Verify => "verify",
            Self::VerifyDecoded => "verify-decoded",
            Self::Apply => "apply",
        }
    }

    async fn measure_once(
        self,
        runtime: &RuntimeContext,
        case: BenchCase,
        iteration: u64,
    ) -> Duration {
        let prefix = format!("consensus-bench-{}-{}-{iteration}", self.name(), case.id());
        cleanup_partitions(runtime, &prefix).await;

        let elapsed = match self {
            Self::Propose => propose_once(runtime, case, &prefix).await,
            Self::BuildAfterFinalize => build_after_finalize_once(runtime, case, &prefix).await,
            Self::BuildQueuedByFinalize => {
                build_queued_by_finalize_once(runtime, case, &prefix).await
            }
            Self::BuildWithMempool => build_with_mempool_once(runtime, case, &prefix).await,
            Self::Verify => verify_once(runtime, case, &prefix).await,
            Self::VerifyDecoded => verify_decoded_once(runtime, case, &prefix).await,
            Self::Apply => apply_once(runtime, case, &prefix).await,
        };

        cleanup_partitions(runtime, &prefix).await;
        elapsed
    }
}

fn consensus(c: &mut Criterion) {
    let runner = bench_tokio::Runner::new(RuntimeConfig::default());
    if std::env::var_os("CONSTANTINOPLE_PROFILE_CONSENSUS").is_some() {
        (&runner).block_on(profile_consensus());
        return;
    }

    let mut group = c.benchmark_group("consensus/block");

    for &case in BENCH_CASES {
        group.throughput(Throughput::Elements(case.transaction_count as u64));
        for operation in Operation::ALL {
            group.bench_with_input(
                BenchmarkId::new(operation.name(), case.id()),
                &case,
                |bencher, &case| {
                    bencher
                        .to_async(&runner)
                        .iter_custom(move |iterations| measure(operation, case, iterations));
                },
            );
        }
    }

    group.finish();
}

async fn measure(operation: Operation, case: BenchCase, iterations: u64) -> Duration {
    let runtime = bench_context::get::<RuntimeContext>();
    let mut total = Duration::ZERO;

    for iteration in 0..iterations {
        total += operation.measure_once(&runtime, case, iteration).await;
    }

    total
}

async fn propose_once(runtime: &RuntimeContext, case: BenchCase, prefix: &str) -> Duration {
    let Fixture {
        mut app,
        databases,
        parent,
        parent_merkleized,
        context,
        transactions,
    } = Fixture::new(runtime, case, prefix).await;
    let mut input = TestTransactionSource::new(case, transactions);
    let batches = parent_batches(&databases, parent_merkleized.as_ref()).await;

    let started_at = Instant::now();
    let proposed = app
        .propose_child(
            (runtime.child("propose"), context),
            &parent,
            batches,
            &mut input,
        )
        .await
        .expect("proposal should succeed");
    let elapsed = started_at.elapsed();

    black_box(proposed.block.body.len());
    black_box(proposed.block.digest());
    drop(proposed);
    drop(databases);
    elapsed
}

async fn build_after_finalize_once(
    runtime: &RuntimeContext,
    case: BenchCase,
    prefix: &str,
) -> Duration {
    let Fixture {
        mut app,
        databases,
        parent,
        parent_merkleized,
        context,
        transactions,
    } = Fixture::new(runtime, case, prefix).await;
    if let Some(parent_merkleized) = parent_merkleized {
        databases.finalize(parent_merkleized).await;
    }

    let mut input = TestTransactionSource::new(case, transactions);
    let started_at = Instant::now();
    let propose_batches = databases.new_batches().await;
    let proposed = app
        .propose_child(
            (runtime.child("build_after_finalize"), context),
            &parent,
            propose_batches,
            &mut input,
        )
        .await
        .expect("proposal after finalization should succeed");
    let elapsed = started_at.elapsed();

    black_box(proposed.block.body.len());
    black_box(proposed.block.digest());
    drop(proposed);
    drop(databases);
    elapsed
}

async fn build_queued_by_finalize_once(
    runtime: &RuntimeContext,
    case: BenchCase,
    prefix: &str,
) -> Duration {
    let Fixture {
        mut app,
        databases,
        parent,
        parent_merkleized,
        context,
        transactions,
    } = Fixture::new(runtime, case, prefix).await;
    let mut input = TestTransactionSource::new(case, transactions);

    let started_at = Instant::now();
    if let Some(parent_merkleized) = parent_merkleized {
        databases.finalize(parent_merkleized).await;
    }
    let propose_batches = databases.new_batches().await;
    let proposed = app
        .propose_child(
            (runtime.child("build_queued_by_finalize"), context),
            &parent,
            propose_batches,
            &mut input,
        )
        .await
        .expect("proposal queued by finalization should succeed");
    let elapsed = started_at.elapsed();

    black_box(proposed.block.body.len());
    black_box(proposed.block.digest());
    drop(proposed);
    drop(databases);
    elapsed
}

async fn build_with_mempool_once(
    runtime: &RuntimeContext,
    case: BenchCase,
    prefix: &str,
) -> Duration {
    let generated = GeneratedTransactions::new(case);
    let signature_strategy = bench_strategy(runtime, case.rayon_threads);
    let hash_strategy = bench_strategy(runtime, case.rayon_threads);
    let databases = init_databases(
        runtime,
        prefix,
        &generated.accounts,
        generated.committed_transactions,
        generated.state_history_blocks,
        case.transaction_count,
        hash_strategy.clone(),
    )
    .await;
    let leader = generated.leader.clone();
    let genesis_parent = parent_block(leader.clone(), generated.committed_height, &databases).await;
    let context = block_context(leader.clone());
    let mut setup_app: TestApplication = new_application(
        runtime,
        leader.clone(),
        &databases,
        signature_strategy.clone(),
        hash_strategy.clone(),
    )
    .await;
    let (parent, parent_merkleized) = if generated.warmup_transactions.is_empty() {
        (genesis_parent, None)
    } else {
        let mut input = TestTransactionSource::static_source(generated.warmup_transactions);
        let batches = databases.new_batches().await;
        let proposed = setup_app
            .propose_child(
                (runtime.child("mempool_pending_parent"), context.clone()),
                &genesis_parent,
                batches,
                &mut input,
            )
            .await
            .expect("pending parent proposal should succeed");
        (proposed.block, Some(proposed.merkleized))
    };
    let mut app: TestMempoolApplication = new_application(
        runtime,
        leader,
        &databases,
        signature_strategy,
        hash_strategy,
    )
    .await;
    let (mut mempool, mempool_handle) = start_mempool(runtime, case, generated.transactions).await;
    let batches = parent_batches(&databases, parent_merkleized.as_ref()).await;

    let started_at = Instant::now();
    let proposed = app
        .propose_child(
            (runtime.child("build_with_mempool"), context),
            &parent,
            batches,
            &mut mempool,
        )
        .await
        .expect("mempool-backed proposal should succeed");
    let elapsed = started_at.elapsed();

    black_box(proposed.block.body.len());
    black_box(proposed.block.digest());
    maybe_print_profile(runtime, "build_with_mempool", elapsed);
    drop(proposed);
    mempool_handle.abort();
    drop(databases);
    elapsed
}

async fn profile_consensus() {
    let runtime = bench_context::get::<RuntimeContext>();
    let case = BENCH_CASES
        .iter()
        .copied()
        .find(|case| matches!(case.workload, Workload::ProdLike))
        .expect("prod-like benchmark case should exist");
    let prefix = "consensus-profile-prod-like";
    cleanup_partitions(&runtime, prefix).await;
    let elapsed = build_with_mempool_once(&runtime, case, prefix).await;
    eprintln!(
        "profile_consensus operation=build-with-mempool case={} elapsed_ms={:.3}",
        case.id(),
        elapsed.as_secs_f64() * 1000.0
    );
    cleanup_partitions(&runtime, prefix).await;
}

fn maybe_print_profile(runtime: &RuntimeContext, operation: &str, elapsed: Duration) {
    if std::env::var_os("CONSTANTINOPLE_PROFILE_CONSENSUS").is_none() {
        return;
    }

    eprintln!(
        "profile_consensus operation={operation} elapsed_ms={:.3}",
        elapsed.as_secs_f64() * 1000.0
    );
    eprintln!("{}", runtime.encode());
}

async fn verify_once(runtime: &RuntimeContext, case: BenchCase, prefix: &str) -> Duration {
    let prepared = PreparedBlock::new(runtime, case, prefix).await;
    verify_prepared_once(
        runtime,
        prepared,
        "verification should accept the proposed block",
    )
    .await
}

async fn verify_decoded_once(runtime: &RuntimeContext, case: BenchCase, prefix: &str) -> Duration {
    let prepared = PreparedBlock::new_decoded(runtime, case, prefix).await;
    verify_prepared_once(
        runtime,
        prepared,
        "verification should accept the decoded block",
    )
    .await
}

async fn verify_prepared_once(
    runtime: &RuntimeContext,
    prepared: PreparedBlock,
    success: &str,
) -> Duration {
    let PreparedBlock {
        mut app,
        databases,
        parent,
        parent_merkleized,
        block,
    } = prepared;
    let batches = parent_batches(&databases, parent_merkleized.as_ref()).await;
    let context = block.header.context.clone();

    let started_at = Instant::now();
    let merkleized = app
        .verify_child((runtime.child("verify"), context), block, &parent, batches)
        .await
        .expect(success);
    let elapsed = started_at.elapsed();

    black_box(merkleized.0.root());
    black_box(merkleized.1.root());
    drop(merkleized);
    drop(databases);
    elapsed
}

async fn apply_once(runtime: &RuntimeContext, case: BenchCase, prefix: &str) -> Duration {
    let PreparedBlock {
        mut app,
        databases,
        parent: _,
        parent_merkleized,
        block,
    } = PreparedBlock::new(runtime, case, prefix).await;
    let batches = parent_batches(&databases, parent_merkleized.as_ref()).await;
    let context = block.header.context.clone();

    let started_at = Instant::now();
    let merkleized = app
        .apply_certified((runtime.child("apply"), context), &block, batches)
        .await;
    let elapsed = started_at.elapsed();

    black_box(merkleized.0.root());
    black_box(merkleized.1.root());
    drop(merkleized);
    drop(databases);
    elapsed
}

struct Fixture {
    app: TestApplication,
    databases: TestDatabases,
    parent: TestBlock,
    parent_merkleized: Option<TestMerkleizedDatabases>,
    context: TestConsensusContext,
    transactions: Vec<TestTransaction>,
}

impl Fixture {
    async fn new(runtime: &RuntimeContext, case: BenchCase, prefix: &str) -> Self {
        let generated = GeneratedTransactions::new(case);
        let signature_strategy = bench_strategy(runtime, case.rayon_threads);
        let hash_strategy = bench_strategy(runtime, case.rayon_threads);
        let databases = init_databases(
            runtime,
            prefix,
            &generated.accounts,
            generated.committed_transactions,
            generated.state_history_blocks,
            case.transaction_count,
            hash_strategy.clone(),
        )
        .await;
        let leader = generated.leader.clone();
        let genesis_parent =
            parent_block(leader.clone(), generated.committed_height, &databases).await;
        let context = block_context(leader.clone());
        let mut app = new_application(
            runtime,
            leader,
            &databases,
            signature_strategy,
            hash_strategy,
        )
        .await;
        let (parent, parent_merkleized) = if generated.warmup_transactions.is_empty() {
            (genesis_parent, None)
        } else {
            let mut input = TestTransactionSource::static_source(generated.warmup_transactions);
            let batches = databases.new_batches().await;
            let proposed = app
                .propose_child(
                    (runtime.child("pending_parent"), context.clone()),
                    &genesis_parent,
                    batches,
                    &mut input,
                )
                .await
                .expect("pending parent proposal should succeed");
            (proposed.block, Some(proposed.merkleized))
        };

        Self {
            app,
            databases,
            parent,
            parent_merkleized,
            context,
            transactions: generated.transactions,
        }
    }
}

struct PreparedBlock {
    app: TestApplication,
    databases: TestDatabases,
    parent: TestBlock,
    parent_merkleized: Option<TestMerkleizedDatabases>,
    block: TestBlock,
}

impl PreparedBlock {
    async fn new(runtime: &RuntimeContext, case: BenchCase, prefix: &str) -> Self {
        let Fixture {
            mut app,
            databases,
            parent,
            parent_merkleized,
            context,
            transactions,
        } = Fixture::new(runtime, case, prefix).await;
        let mut input = TestTransactionSource::new(case, transactions);
        let batches = parent_batches(&databases, parent_merkleized.as_ref()).await;
        let proposed = app
            .propose_child(
                (runtime.child("prepare_block"), context),
                &parent,
                batches,
                &mut input,
            )
            .await
            .expect("proposal should succeed");
        let block = proposed.block;
        drop(proposed.merkleized);

        Self {
            app,
            databases,
            parent,
            parent_merkleized,
            block,
        }
    }

    async fn new_decoded(runtime: &RuntimeContext, case: BenchCase, prefix: &str) -> Self {
        let mut prepared = Self::new(runtime, case, prefix).await;
        prepared.block = decode_block(prepared.block);
        prepared
    }
}

fn decode_block(block: TestBlock) -> TestBlock {
    TestBlock::decode_cfg(block.encode(), &BlockCfg::default()).expect("bench block should decode")
}

struct GeneratedTransactions {
    accounts: Vec<(AccountKey, Account)>,
    committed_height: u64,
    committed_transactions: usize,
    state_history_blocks: u64,
    warmup_transactions: Vec<TestTransaction>,
    transactions: Vec<TestTransaction>,
    leader: TestPublicKey,
}

impl GeneratedTransactions {
    fn new(case: BenchCase) -> Self {
        match case.workload {
            Workload::Unique => Self::unique(case.transaction_count),
            Workload::ProdLike => Self::prod_like(case.transaction_count),
        }
    }

    fn unique(transaction_count: usize) -> Self {
        let leader = TestSigner::new(u64::MAX).public_key;
        let mut accounts = Vec::with_capacity(transaction_count.saturating_mul(2));
        let mut transactions = Vec::with_capacity(transaction_count);

        for index in 0..transaction_count {
            let sender = TestSigner::new(index as u64);
            let recipient = TestSigner::new(index as u64 + transaction_count as u64).public_key;
            let sender_public_key = TransactionPublicKey::ed25519(sender.public_key.clone());
            let recipient_public_key = TransactionPublicKey::ed25519(recipient.clone());
            accounts.push((
                AccountKey::from_public_key(&sender_public_key),
                Account {
                    balance: 1,
                    nonce: Nonce::default(),
                },
            ));
            accounts.push((
                AccountKey::from_public_key(&recipient_public_key),
                Account::default(),
            ));
            transactions.push(sender.sign(recipient, 1, 0));
        }

        Self {
            accounts,
            committed_height: 0,
            committed_transactions: 0,
            state_history_blocks: 0,
            warmup_transactions: Vec::new(),
            transactions,
            leader,
        }
    }

    fn prod_like(transaction_count: usize) -> Self {
        let leader = TestSigner::new(u64::MAX).public_key;
        let state_history_blocks = prod_like_state_history_blocks();
        let committed_height = if state_history_blocks > 0 {
            state_history_blocks
        } else {
            PROD_LIKE_WARMUP_BLOCKS - 1
        };
        let committed_nonce = if state_history_blocks > 0 {
            stream_updates_before(state_history_blocks, 0)
        } else {
            committed_height / PROD_LIKE_SUBMITTERS as u64
        };
        let committed_transactions = if state_history_blocks > 0 {
            0
        } else {
            usize::try_from(committed_height)
                .expect("warmup block count must fit in usize")
                .saturating_mul(transaction_count)
        };
        let signers = (0..PROD_LIKE_ACCOUNT_COUNT)
            .map(|index| TestSigner::new(PROD_LIKE_ACCOUNT_SEED_OFFSET + index as u64))
            .collect::<Vec<_>>();
        let accounts = signers
            .iter()
            .map(|signer| {
                let public_key = TransactionPublicKey::ed25519(signer.public_key.clone());
                (
                    AccountKey::from_public_key(&public_key),
                    Account {
                        balance: DEFAULT_ACCOUNT_BALANCE,
                        nonce: Nonce::new(committed_nonce, 0),
                    },
                )
            })
            .collect();
        let proposal_signers = &signers[..PROD_LIKE_ACCOUNTS_PER_STREAM];
        let mut nonces = vec![committed_nonce; proposal_signers.len()];
        let mut cursor = 0;
        let warmup_transactions = ring_transactions(
            proposal_signers,
            transaction_count,
            &mut nonces,
            &mut cursor,
        );
        let transactions = ring_transactions(
            proposal_signers,
            transaction_count,
            &mut nonces,
            &mut cursor,
        );

        Self {
            accounts,
            committed_height,
            committed_transactions,
            state_history_blocks,
            warmup_transactions,
            transactions,
            leader,
        }
    }
}

fn prod_like_state_history_blocks() -> u64 {
    std::env::var("CONSTANTINOPLE_PROD_LIKE_STATE_HISTORY_BLOCKS")
        .ok()
        .map(|value| {
            value
                .parse()
                .expect("CONSTANTINOPLE_PROD_LIKE_STATE_HISTORY_BLOCKS must be a u64")
        })
        .unwrap_or(0)
}

const fn stream_updates_before(blocks: u64, stream: usize) -> u64 {
    let stream = stream as u64;
    if blocks <= stream {
        return 0;
    }

    ((blocks - 1 - stream) / PROD_LIKE_SUBMITTERS as u64) + 1
}

struct TestSigner {
    key: ed25519::PrivateKey,
    public_key: ed25519::PublicKey,
}

impl TestSigner {
    fn new(seed: u64) -> Self {
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
        .seal_and_sign(&self.key, TRANSACTION_NAMESPACE, &mut TestHasher::default())
    }
}

fn ring_transactions(
    signers: &[TestSigner],
    count: usize,
    nonces: &mut [u64],
    cursor: &mut usize,
) -> Vec<TestTransaction> {
    assert_eq!(signers.len(), nonces.len(), "nonces must match accounts");
    assert!(!signers.is_empty(), "need at least one signer");

    let mut transactions = Vec::with_capacity(count);
    for _ in 0..count {
        let sender_index = *cursor;
        let recipient_index = (sender_index + 1) % signers.len();
        let nonce = nonces[sender_index];
        nonces[sender_index] = nonce + 1;
        *cursor = recipient_index;

        transactions.push(signers[sender_index].sign(
            signers[recipient_index].public_key.clone(),
            1,
            nonce,
        ));
    }
    transactions
}

async fn parent_batches(
    databases: &TestDatabases,
    parent_merkleized: Option<&TestMerkleizedDatabases>,
) -> TestUnmerkleizedDatabases {
    match parent_merkleized {
        Some(merkleized) => {
            <TestDatabases as DatabaseSet<RuntimeContext>>::fork_batches(merkleized)
        }
        None => databases.new_batches().await,
    }
}

async fn start_mempool(
    runtime: &RuntimeContext,
    case: BenchCase,
    transactions: Vec<TestTransaction>,
) -> (TestMempool, Handle<()>) {
    let (mempool, receiver) = TestMempool::channel(65_536);
    enqueue_mempool_batches(&mempool, case, transactions);
    let actor = webserver::Actor::new(
        runtime.child("mempool"),
        webserver::Config {
            max_pool_bytes: PROD_LIKE_MAX_POOL_BYTES,
            max_propose_bytes: PROD_LIKE_MAX_PROPOSE_BYTES,
            namespace: TRANSACTION_NAMESPACE,
            drop_grace_blocks: 8,
            signature_strategy: bench_strategy(runtime, case.rayon_threads),
            hash_strategy: bench_strategy(runtime, case.rayon_threads),
        },
        mempool.clone(),
        receiver,
        Arc::new(OnceLock::new()),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mempool listener should bind");
    let handle = actor.start(listener);
    (mempool, handle)
}

fn enqueue_mempool_batches(
    mempool: &TestMempool,
    case: BenchCase,
    transactions: Vec<TestTransaction>,
) {
    let chunk_size = match case.workload {
        Workload::ProdLike => PROD_LIKE_ACCOUNTS_PER_STREAM,
        Workload::Unique => case.transaction_count,
    };
    for (batch, transactions) in transactions.chunks(chunk_size).enumerate() {
        let transactions = transactions.to_vec();
        let digests = transactions
            .iter()
            .map(|transaction| *transaction.message_digest())
            .collect();
        let total_bytes = total_bytes_for(&transactions);
        let status = mempool
            .try_submit(
                format!("bench-batch-{batch}"),
                digests,
                transactions,
                total_bytes,
            )
            .expect("mempool batch should enqueue");
        drop(status);
    }
}

async fn init_databases(
    runtime: &RuntimeContext,
    prefix: &str,
    accounts: &[(AccountKey, Account)],
    committed_transactions: usize,
    state_history_blocks: u64,
    transactions_per_block: usize,
    strategy: Rayon,
) -> TestDatabases {
    let databases = TestDatabases::init(
        runtime.child("databases"),
        (
            state_db_config(runtime, prefix, strategy.clone()),
            transaction_db_config(runtime, prefix, strategy),
        ),
    )
    .await;
    if state_history_blocks > 0 {
        seed_state_history(
            &databases,
            accounts,
            state_history_blocks,
            transactions_per_block,
        )
        .await;
        return databases;
    }

    let (state_batch, transaction_batch) = databases.new_batches().await;
    let state_batch = accounts
        .iter()
        .fold(state_batch, |batch, (account_key, account)| {
            batch.write(account_key.clone(), Some(*account))
        });
    let transaction_batch = (0..committed_transactions)
        .fold(transaction_batch, |batch, transaction| {
            batch.append(dummy_transaction_digest(transaction))
        });
    let (state_merkleized, transaction_merkleized) =
        futures::join!(state_batch.merkleize(), transaction_batch.merkleize());
    databases
        .finalize((
            state_merkleized.expect("state seed merkleization should succeed"),
            transaction_merkleized.expect("transaction seed merkleization should succeed"),
        ))
        .await;
    databases
}

async fn seed_state_history(
    databases: &TestDatabases,
    accounts: &[(AccountKey, Account)],
    blocks: u64,
    transactions_per_block: usize,
) {
    let mut stream_nonces = vec![0; PROD_LIKE_SUBMITTERS];

    for block in 0..blocks {
        let stream = (block as usize) % PROD_LIKE_SUBMITTERS;
        let stream_start = stream
            .checked_mul(PROD_LIKE_ACCOUNTS_PER_STREAM)
            .expect("stream account offset should fit in usize");
        let stream_end = stream_start
            .checked_add(PROD_LIKE_ACCOUNTS_PER_STREAM)
            .expect("stream account end should fit in usize");
        let next_nonce = stream_nonces[stream] + 1;
        stream_nonces[stream] = next_nonce;

        let (state_batch, transaction_batch) = databases.new_batches().await;
        let state_batch = accounts[stream_start..stream_end].iter().fold(
            state_batch,
            |batch, (account_key, _)| {
                batch.write(
                    account_key.clone(),
                    Some(Account {
                        balance: DEFAULT_ACCOUNT_BALANCE,
                        nonce: Nonce::new(next_nonce, 0),
                    }),
                )
            },
        );
        let transaction_offset = usize::try_from(block)
            .expect("state history block must fit in usize")
            .saturating_mul(transactions_per_block);
        let transaction_batch =
            (0..transactions_per_block).fold(transaction_batch, |batch, transaction| {
                batch.append(dummy_transaction_digest(transaction_offset + transaction))
            });
        let (state_merkleized, transaction_merkleized) =
            futures::join!(state_batch.merkleize(), transaction_batch.merkleize());
        databases
            .finalize((
                state_merkleized.expect("state history merkleization should succeed"),
                transaction_merkleized.expect("transaction history merkleization should succeed"),
            ))
            .await;
    }
}

fn dummy_transaction_digest(index: usize) -> TestCommitment {
    let mut bytes = [0; 32];
    bytes[..core::mem::size_of::<usize>()].copy_from_slice(&index.to_le_bytes());
    TestCommitment::from(bytes)
}

async fn new_application<I>(
    runtime: &RuntimeContext,
    leader: TestPublicKey,
    databases: &TestDatabases,
    signature_strategy: Rayon,
    hash_strategy: Rayon,
) -> Application<
    RuntimeContext,
    TestHasher,
    TestCommitment,
    BenchScheme,
    TestPublicKey,
    I,
    ed25519::Batch,
    Rayon,
    Rayon,
> {
    let (state_target, transaction_target) = databases.committed_targets().await;
    let genesis_transactions_target =
        constantinople_application::consensus::TransactionHistoryTarget {
            root: transaction_target.root,
            leaf_count: transaction_target.leaf_count,
        };

    Application::<
        RuntimeContext,
        TestHasher,
        TestCommitment,
        BenchScheme,
        TestPublicKey,
        I,
        ed25519::Batch,
        Rayon,
        Rayon,
    >::new(
        runtime.child("application"),
        signature_strategy,
        hash_strategy,
        leader,
        TestCommitment::EMPTY,
        TRANSACTION_NAMESPACE,
        state_target,
        genesis_transactions_target,
        None,
    )
}

fn bench_strategy(runtime: &RuntimeContext, threads: usize) -> Rayon {
    Rayon::with_pool(
        runtime
            .create_thread_pool(NonZeroUsize::new(threads).expect("rayon thread count is zero"))
            .unwrap(),
    )
}

async fn parent_block(leader: TestPublicKey, height: u64, databases: &TestDatabases) -> TestBlock {
    let (state_target, transaction_target) = databases.committed_targets().await;
    let header = Header {
        context: block_context(leader),
        parent: sha256::Digest::EMPTY,
        height,
        timestamp: 0,
        state_root: state_target.root,
        state_range: non_empty_range!(*state_target.range.start(), *state_target.range.end()),
        transactions_root: transaction_target.root,
        transactions_range: non_empty_range!(0, *transaction_target.leaf_count),
    };

    Block::new(header, Vec::new()).seal(&mut TestHasher::default())
}

const fn block_context(leader: TestPublicKey) -> TestConsensusContext {
    Context {
        round: Round::zero(),
        leader,
        parent: (View::zero(), TestCommitment::EMPTY),
    }
}

fn state_db_config(
    runtime: &RuntimeContext,
    prefix: &str,
    strategy: Rayon,
) -> FixedConfig<EightCap, Rayon> {
    let page_cache = CacheRef::from_pooler(
        &runtime.child("state_page_cache"),
        PAGE_CACHE_PAGE_SIZE,
        PAGE_CACHE_CAPACITY,
    );

    FixedConfig {
        merkle_config: MmrConfig {
            journal_partition: format!("{prefix}-state-journal"),
            metadata_partition: format!("{prefix}-state-metadata"),
            items_per_blob: STATE_ITEMS_PER_BLOB,
            write_buffer: WRITE_BUFFER,
            strategy,
            page_cache: page_cache.clone(),
        },
        journal_config: FixedJournalConfig {
            partition: format!("{prefix}-state-log"),
            items_per_blob: STATE_ITEMS_PER_BLOB,
            page_cache,
            write_buffer: WRITE_BUFFER,
        },
        translator: EightCap,
    }
}

fn transaction_db_config(
    runtime: &RuntimeContext,
    prefix: &str,
    strategy: Rayon,
) -> keyless_fixed::CompactConfig<Rayon> {
    let page_cache = CacheRef::from_pooler(
        &runtime.child("transactions_page_cache"),
        PAGE_CACHE_PAGE_SIZE,
        PAGE_CACHE_CAPACITY,
    );

    keyless_fixed::CompactConfig {
        merkle: CompactMerkleConfig {
            partition: format!("{prefix}-transactions-merkle"),
            items_per_section: TRANSACTION_ITEMS_PER_SECTION,
            page_cache,
            write_buffer: WRITE_BUFFER,
            strategy,
        },
        commit_codec_config: (),
    }
}

async fn cleanup_partitions(runtime: &RuntimeContext, prefix: &str) {
    for partition in partition_names(prefix) {
        match runtime.remove(&partition, None).await {
            Ok(()) | Err(RuntimeError::PartitionMissing(_)) => {}
            Err(error) => panic!("bench partition cleanup should succeed: {error}"),
        }
    }
}

fn partition_names(prefix: &str) -> [String; 4] {
    [
        format!("{prefix}-state-journal"),
        format!("{prefix}-state-metadata"),
        format!("{prefix}-state-log"),
        format!("{prefix}-transactions-merkle"),
    ]
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = consensus
}
criterion_main!(benches);
