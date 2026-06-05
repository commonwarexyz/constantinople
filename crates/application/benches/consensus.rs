use bytes::Bytes;
use commonware_codec::{Decode as _, Encode as _};
use commonware_consensus::{
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
    Error as RuntimeError, Storage as _, Supervisor, ThreadPooler,
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
    Faults, NZU16, NZU64, NZUsize, non_empty_range, sequence::U64, sync::AsyncRwLock,
};
use constantinople_application::consensus::{Application, TransactionHistoryDb};
use constantinople_mempool::mocks::StaticTransactionSource;
use constantinople_primitives::{
    Account, AccountKey, Block, BlockCfg, Header, Nonce, Sealable, SealedBlock,
    TRANSACTION_NAMESPACE, Transaction, TransactionPublicKey, VerifiedTransaction,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::{
    hint::black_box,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::{Duration, Instant},
};

type TestHasher = sha256::Sha256;
type TestCommitment = sha256::Digest;
type TestPublicKey = ed25519::PublicKey;
type TestTransaction = VerifiedTransaction<TestHasher>;
type TestTransactionSource = StaticTransactionSource<TestCommitment, TestPublicKey, TestHasher>;
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
type TestStateDb =
    fixed::Db<mmr::Family, RuntimeContext, AccountKey, Account, TestHasher, EightCap, Rayon>;
type TestStateDatabase = Arc<AsyncRwLock<TestStateDb>>;
type TestTransactionDb = TransactionHistoryDb<RuntimeContext, TestHasher, Rayon>;
type TestTransactionDatabase = Arc<AsyncRwLock<TestTransactionDb>>;
type TestDatabases = (TestStateDatabase, TestTransactionDatabase);
type TestBlock = SealedBlock<TestCommitment, TestPublicKey, TestHasher>;
type TestConsensusContext = Context<TestCommitment, TestPublicKey>;

const TRANSACTION_COUNTS: &[usize] = &[16384, 32768];
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(1_048_576);
const WRITE_BUFFER: NonZeroUsize = NZUsize!(1024 * 1024);
const PAGE_CACHE_PAGE_SIZE: NonZeroU16 = NZU16!(8192);
const PAGE_CACHE_CAPACITY: NonZeroUsize = NZUsize!(16_384);

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
    Verify,
    VerifyDecoded,
    Apply,
}

impl Operation {
    const ALL: [Self; 4] = [
        Self::Propose,
        Self::Verify,
        Self::VerifyDecoded,
        Self::Apply,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Propose => "propose",
            Self::Verify => "verify",
            Self::VerifyDecoded => "verify-decoded",
            Self::Apply => "apply",
        }
    }

    async fn measure_once(
        self,
        runtime: &RuntimeContext,
        transaction_count: usize,
        iteration: u64,
    ) -> Duration {
        let prefix = format!(
            "consensus-bench-{}-{transaction_count}-{iteration}",
            self.name()
        );
        cleanup_partitions(runtime, &prefix).await;

        let elapsed = match self {
            Self::Propose => propose_once(runtime, transaction_count, &prefix).await,
            Self::Verify => verify_once(runtime, transaction_count, &prefix).await,
            Self::VerifyDecoded => verify_decoded_once(runtime, transaction_count, &prefix).await,
            Self::Apply => apply_once(runtime, transaction_count, &prefix).await,
        };

        cleanup_partitions(runtime, &prefix).await;
        elapsed
    }
}

fn consensus(c: &mut Criterion) {
    let runner = bench_tokio::Runner::new(RuntimeConfig::default());
    let mut group = c.benchmark_group("consensus/block");

    for &transaction_count in TRANSACTION_COUNTS {
        group.throughput(Throughput::Elements(transaction_count as u64));
        for operation in Operation::ALL {
            group.bench_with_input(
                BenchmarkId::new(operation.name(), transaction_count),
                &transaction_count,
                |bencher, &transaction_count| {
                    bencher.to_async(&runner).iter_custom(move |iterations| {
                        measure(operation, transaction_count, iterations)
                    });
                },
            );
        }
    }

    group.finish();
}

async fn measure(operation: Operation, transaction_count: usize, iterations: u64) -> Duration {
    let runtime = bench_context::get::<RuntimeContext>();
    let mut total = Duration::ZERO;

    for iteration in 0..iterations {
        total += operation
            .measure_once(&runtime, transaction_count, iteration)
            .await;
    }

    total
}

async fn propose_once(
    runtime: &RuntimeContext,
    transaction_count: usize,
    prefix: &str,
) -> Duration {
    let Fixture {
        mut app,
        databases,
        parent,
        context,
        transactions,
    } = Fixture::new(runtime, transaction_count, prefix).await;
    let mut input = TestTransactionSource::new(vec![transactions]);
    let batches = databases.new_batches().await;

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

async fn verify_once(runtime: &RuntimeContext, transaction_count: usize, prefix: &str) -> Duration {
    let prepared = PreparedBlock::new(runtime, transaction_count, prefix).await;
    verify_prepared_once(
        runtime,
        prepared,
        "verification should accept the proposed block",
    )
    .await
}

async fn verify_decoded_once(
    runtime: &RuntimeContext,
    transaction_count: usize,
    prefix: &str,
) -> Duration {
    let prepared = PreparedBlock::new_decoded(runtime, transaction_count, prefix).await;
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
        block,
    } = prepared;
    let batches = databases.new_batches().await;
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

async fn apply_once(runtime: &RuntimeContext, transaction_count: usize, prefix: &str) -> Duration {
    let PreparedBlock {
        mut app,
        databases,
        parent: _,
        block,
    } = PreparedBlock::new(runtime, transaction_count, prefix).await;
    let batches = databases.new_batches().await;
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
    context: TestConsensusContext,
    transactions: Vec<TestTransaction>,
}

impl Fixture {
    async fn new(runtime: &RuntimeContext, transaction_count: usize, prefix: &str) -> Self {
        let generated = GeneratedTransactions::new(transaction_count);
        let signature_strategy = bench_strategy(runtime);
        let hash_strategy = bench_strategy(runtime);
        let databases =
            init_databases(runtime, prefix, &generated.accounts, hash_strategy.clone()).await;
        let leader = generated.leader.clone();
        let parent = parent_block(leader.clone(), &databases).await;
        let context = block_context(leader.clone());
        let app = new_application(
            runtime,
            leader,
            &databases,
            signature_strategy,
            hash_strategy,
        )
        .await;

        Self {
            app,
            databases,
            parent,
            context,
            transactions: generated.transactions,
        }
    }
}

struct PreparedBlock {
    app: TestApplication,
    databases: TestDatabases,
    parent: TestBlock,
    block: TestBlock,
}

impl PreparedBlock {
    async fn new(runtime: &RuntimeContext, transaction_count: usize, prefix: &str) -> Self {
        let Fixture {
            mut app,
            databases,
            parent,
            context,
            transactions,
        } = Fixture::new(runtime, transaction_count, prefix).await;
        let mut input = TestTransactionSource::new(vec![transactions]);
        let batches = databases.new_batches().await;
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
            block,
        }
    }

    async fn new_decoded(runtime: &RuntimeContext, transaction_count: usize, prefix: &str) -> Self {
        let mut prepared = Self::new(runtime, transaction_count, prefix).await;
        prepared.block = decode_block(prepared.block);
        prepared
    }
}

fn decode_block(block: TestBlock) -> TestBlock {
    TestBlock::decode_cfg(block.encode(), &BlockCfg::default()).expect("bench block should decode")
}

struct GeneratedTransactions {
    accounts: Vec<(AccountKey, Account)>,
    transactions: Vec<TestTransaction>,
    leader: TestPublicKey,
}

impl GeneratedTransactions {
    fn new(transaction_count: usize) -> Self {
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
            transactions,
            leader,
        }
    }
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

async fn init_databases(
    runtime: &RuntimeContext,
    prefix: &str,
    accounts: &[(AccountKey, Account)],
    strategy: Rayon,
) -> TestDatabases {
    let databases = TestDatabases::init(
        runtime.child("databases"),
        (
            state_db_config(runtime, prefix, strategy.clone()),
            transaction_db_config(prefix, strategy),
        ),
    )
    .await;
    let (state_batch, transaction_batch) = databases.new_batches().await;
    let state_batch = accounts
        .iter()
        .fold(state_batch, |batch, (account_key, account)| {
            batch.write(account_key.clone(), Some(*account))
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

async fn new_application(
    runtime: &RuntimeContext,
    leader: TestPublicKey,
    databases: &TestDatabases,
    signature_strategy: Rayon,
    hash_strategy: Rayon,
) -> TestApplication {
    let (state_target, transaction_target) = databases.committed_targets().await;
    let genesis_transactions_target =
        constantinople_application::consensus::TransactionHistoryTarget {
            root: transaction_target.root,
            leaf_count: transaction_target.leaf_count,
        };

    TestApplication::new(
        runtime.child("application"),
        signature_strategy,
        hash_strategy,
        leader,
        TestCommitment::EMPTY,
        TRANSACTION_NAMESPACE,
        state_target,
        genesis_transactions_target,
        NZU64!(1024),
        Arc::new(|_| Box::pin(async {})),
        None,
    )
}

fn bench_strategy(runtime: &RuntimeContext) -> Rayon {
    Rayon::with_pool(runtime.create_thread_pool(NZUsize!(8)).unwrap())
}

async fn parent_block(leader: TestPublicKey, databases: &TestDatabases) -> TestBlock {
    let (state_target, transaction_target) = databases.committed_targets().await;
    let header = Header {
        context: block_context(leader),
        parent: sha256::Digest::EMPTY,
        height: 0,
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
            items_per_blob: ITEMS_PER_BLOB,
            write_buffer: WRITE_BUFFER,
            strategy,
            page_cache: page_cache.clone(),
        },
        journal_config: FixedJournalConfig {
            partition: format!("{prefix}-state-log"),
            items_per_blob: ITEMS_PER_BLOB,
            page_cache,
            write_buffer: WRITE_BUFFER,
        },
        translator: EightCap,
    }
}

fn transaction_db_config(prefix: &str, strategy: Rayon) -> keyless_fixed::CompactConfig<Rayon> {
    keyless_fixed::CompactConfig {
        merkle: CompactMerkleConfig {
            partition: format!("{prefix}-transactions-merkle"),
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
