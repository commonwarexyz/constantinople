use bytes::Bytes;
use commonware_codec::{DecodeExt, FixedSize};
use commonware_cryptography::{Signer, blake3, secp256r1::recoverable};
use commonware_glue::stateful::db::ManagedDb;
use commonware_math::algebra::Random;
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_runtime::{Runner as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig,
    mmr,
    mmr::journaled::Config as MmrConfig,
    qmdb::any::{FixedConfig, unordered::fixed},
    translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, sync::AsyncRwLock};
use constantinople_application::{
    consensus::load_state,
    processor::{
        Precompiles,
        executor::Processor,
        frame::{Frame, FrameError},
        state::{DiscoveryState, State},
    },
};
use constantinople_primitives::{
    Account, Address, BlockAccessList, Slot, StateValue, Transaction, VerifiedTransaction,
};
use divan::Bencher;
use rand::{SeedableRng, rngs::StdRng};
use std::{
    collections::{BTreeMap, HashMap},
    hint::black_box,
    marker::PhantomData,
    num::NonZeroUsize,
    sync::{Arc, OnceLock},
};

type TestContext = deterministic::Context;
type TestHasher = blake3::Blake3;
type TestPublicKey = recoverable::PublicKey;
type TestSigned = VerifiedTransaction<TestPublicKey, TestHasher>;
type TestDb =
    Arc<AsyncRwLock<fixed::Db<mmr::Family, TestContext, Slot, StateValue, TestHasher, EightCap>>>;

const NAMESPACE: &[u8] = b"processor-bench";
const TRANSACTION_COUNTS: &[usize] = &[256, 1024, 8192, 16_384, 65_536];

static LOW_256: OnceLock<BenchFixture> = OnceLock::new();
static LOW_1024: OnceLock<BenchFixture> = OnceLock::new();
static LOW_8192: OnceLock<BenchFixture> = OnceLock::new();
static LOW_16384: OnceLock<BenchFixture> = OnceLock::new();
static LOW_65536: OnceLock<BenchFixture> = OnceLock::new();

static HIGH_256: OnceLock<BenchFixture> = OnceLock::new();
static HIGH_1024: OnceLock<BenchFixture> = OnceLock::new();
static HIGH_8192: OnceLock<BenchFixture> = OnceLock::new();
static HIGH_16384: OnceLock<BenchFixture> = OnceLock::new();
static HIGH_65536: OnceLock<BenchFixture> = OnceLock::new();

fn main() {
    divan::main();
}

#[divan::bench(args = TRANSACTION_COUNTS)]
fn sequential_execution_low_contention(bencher: Bencher<'_, '_>, transaction_count: usize) {
    let fixture = low_contention_fixture(transaction_count);
    bencher.bench_local(|| black_box(fixture.run(&Sequential)));
}

#[divan::bench(args = TRANSACTION_COUNTS)]
fn parallel_execution_low_contention(bencher: Bencher<'_, '_>, transaction_count: usize) {
    let fixture = low_contention_fixture(transaction_count);
    let strategy = parallel_strategy();
    bencher.bench_local(|| black_box(fixture.run(&strategy)));
}

#[divan::bench(args = TRANSACTION_COUNTS)]
fn sequential_execution_high_contention(bencher: Bencher<'_, '_>, transaction_count: usize) {
    let fixture = high_contention_fixture(transaction_count);
    bencher.bench_local(|| black_box(fixture.run(&Sequential)));
}

#[divan::bench(args = TRANSACTION_COUNTS)]
fn parallel_execution_high_contention(bencher: Bencher<'_, '_>, transaction_count: usize) {
    let fixture = high_contention_fixture(transaction_count);
    let strategy = parallel_strategy();
    bencher.bench_local(|| black_box(fixture.run(&strategy)));
}

struct BenchFixture {
    state: State,
    access_list: BlockAccessList,
    precompiles: BenchPrecompiles,
    transactions: Vec<TestSigned>,
}

impl BenchFixture {
    fn low_contention(transaction_count: usize) -> Self {
        let mut state_writes = Vec::with_capacity(transaction_count);
        let mut precompiles = BenchPrecompiles::default();
        let mut transactions = Vec::with_capacity(transaction_count);

        for index in 0..transaction_count {
            let signer = TestSigner::new(seed(index, 1));
            let precompile = address(index, 0x20);
            let storage_slot = slot(index, 0x40);
            let value = slot(index, 0x80);

            state_writes.push((
                signer.address,
                Account {
                    balance: 1,
                    nonce: 0,
                },
            ));
            precompiles.insert(
                precompile,
                vec![
                    BenchStep::ReadStorage(storage_slot),
                    BenchStep::WriteInputValue(storage_slot),
                ],
            );
            transactions.push(signer.sign(
                precompile,
                0,
                0,
                Bytes::copy_from_slice(value.as_ref()),
            ));
        }

        Self::load(state_writes, precompiles, transactions)
    }

    fn high_contention(transaction_count: usize) -> Self {
        let mut state_writes = Vec::with_capacity(transaction_count);
        let mut precompiles = BenchPrecompiles::default();
        let mut transactions = Vec::with_capacity(transaction_count);
        let precompile = address(0, 0x7a);
        let storage_slot = slot(0, 0x7b);

        precompiles.insert(
            precompile,
            vec![
                BenchStep::ReadStorage(storage_slot),
                BenchStep::WriteInputValue(storage_slot),
            ],
        );

        for index in 0..transaction_count {
            let signer = TestSigner::new(seed(index, 101));
            let value = slot(index, 0xaa);
            state_writes.push((
                signer.address,
                Account {
                    balance: 1,
                    nonce: 0,
                },
            ));
            transactions.push(signer.sign(
                precompile,
                0,
                0,
                Bytes::copy_from_slice(value.as_ref()),
            ));
        }

        Self::load(state_writes, precompiles, transactions)
    }

    /// Benchmarks validate + verify as the measured path.
    fn run<S>(&self, strategy: &S) -> usize
    where
        S: Strategy,
    {
        let processor = Processor::<S, BenchPrecompiles>::new(strategy, &self.precompiles);
        let result = processor.validate(&self.state, self.transactions.clone());
        processor
            .verify(self.state.clone(), &result.valid, &self.access_list)
            .expect("bench BAL should verify")
            .receipts
            .len()
    }

    /// Loads state from the database outside of the measured path.
    fn load(
        state_writes: Vec<(Address, Account)>,
        precompiles: BenchPrecompiles,
        transactions: Vec<TestSigned>,
    ) -> Self {
        deterministic::Runner::default().start(|context| async move {
            let suffix = format!(
                "processor-bench-{}-{}",
                transactions.len(),
                if precompiles.programs.len() == 1 {
                    "high"
                } else {
                    "low"
                }
            );

            let db = Arc::new(AsyncRwLock::new(open_state_db(context, &suffix).await));
            write_accounts(&db, &state_writes).await;

            let base_accounts = state_writes.iter().copied().collect::<HashMap<_, _>>();
            let base_state = State::new(base_accounts, HashMap::new());
            let processor = Processor::new(&Sequential, &precompiles);
            let mut discovery_state = DiscoveryState::new(base_state);
            let validation = processor.validate(&discovery_state, transactions.clone());
            let access_list = processor
                .propose(&mut discovery_state, &validation.valid)
                .access_list;

            let batch = ManagedDb::new_batch(&db).await;
            let state = load_state(&batch, &access_list)
                .await
                .expect("processor should preload state");

            Self {
                state,
                access_list,
                precompiles,
                transactions,
            }
        })
    }
}

#[derive(Debug, Clone)]
struct TestSigner {
    seed: [u8; 32],
    address: Address,
}

impl TestSigner {
    fn new(seed: [u8; 32]) -> Self {
        let key = private_key(seed);
        let public_key = key.public_key();
        let address = Address::from_public_key(&mut TestHasher::default(), &public_key);
        Self { seed, address }
    }

    fn sign(&self, to: Address, value: u64, nonce: u64, input: Bytes) -> TestSigned {
        let key = private_key(self.seed);
        Transaction {
            sender: key.public_key(),
            to,
            input,
            value,
            nonce,
            _digest: PhantomData,
        }
        .seal_and_sign_verified(&key, NAMESPACE, &mut TestHasher::default())
    }
}

#[derive(Debug, Clone)]
enum BenchStep {
    ReadStorage(Slot),
    WriteInputValue(Slot),
}

#[derive(Debug, Clone, Default)]
struct BenchPrecompiles {
    programs: BTreeMap<Address, Vec<BenchStep>>,
}

impl BenchPrecompiles {
    fn insert(&mut self, address: Address, program: Vec<BenchStep>) {
        self.programs.insert(address, program);
    }
}

impl Precompiles for BenchPrecompiles {
    fn is_precompile(&self, address: Address) -> bool {
        self.programs.contains_key(&address)
    }

    fn execute<S, R>(
        &self,
        address: Address,
        frame: &mut Frame<'_, R>,
        _processor: &Processor<'_, S, Self>,
    ) -> Result<Bytes, FrameError>
    where
        S: Strategy,
        R: constantinople_application::processor::state::StateReader,
        Self: Sized,
    {
        let Some(program) = self.programs.get(&address) else {
            return Ok(Bytes::new());
        };

        for step in program {
            match step {
                BenchStep::ReadStorage(slot) => {
                    let _ = frame.read_self_storage(*slot)?;
                }
                BenchStep::WriteInputValue(slot) => {
                    let value = Slot::decode(frame.input().as_ref())
                        .expect("bench input should encode a slot");
                    frame.write_storage(*slot, value)?;
                }
            }
        }

        Ok(Bytes::new())
    }
}

fn low_contention_fixture(transaction_count: usize) -> &'static BenchFixture {
    match transaction_count {
        256 => LOW_256.get_or_init(|| build_fixture(Contention::Low, 256)),
        1024 => LOW_1024.get_or_init(|| build_fixture(Contention::Low, 1024)),
        8192 => LOW_8192.get_or_init(|| build_fixture(Contention::Low, 8192)),
        16_384 => LOW_16384.get_or_init(|| build_fixture(Contention::Low, 16_384)),
        65_536 => LOW_65536.get_or_init(|| build_fixture(Contention::Low, 65_536)),
        _ => panic!("unsupported transaction count"),
    }
}

fn high_contention_fixture(transaction_count: usize) -> &'static BenchFixture {
    match transaction_count {
        256 => HIGH_256.get_or_init(|| build_fixture(Contention::High, 256)),
        1024 => HIGH_1024.get_or_init(|| build_fixture(Contention::High, 1024)),
        8192 => HIGH_8192.get_or_init(|| build_fixture(Contention::High, 8192)),
        16_384 => HIGH_16384.get_or_init(|| build_fixture(Contention::High, 16_384)),
        65_536 => HIGH_65536.get_or_init(|| build_fixture(Contention::High, 65_536)),
        _ => panic!("unsupported transaction count"),
    }
}

fn build_fixture(contention: Contention, transaction_count: usize) -> BenchFixture {
    match contention {
        Contention::Low => BenchFixture::low_contention(transaction_count),
        Contention::High => BenchFixture::high_contention(transaction_count),
    }
}

fn parallel_strategy() -> Rayon {
    Rayon::new(NonZeroUsize::new(4).expect("thread count must be non-zero"))
        .expect("rayon strategy should build")
}

fn address(index: usize, tag: u8) -> Address {
    let mut bytes = [0; Address::SIZE];
    bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
    bytes[Address::SIZE - 1] = tag;
    Address::decode(&bytes[..]).expect("address bytes should decode")
}

fn slot(index: usize, tag: u8) -> Slot {
    let mut bytes = [0; Slot::SIZE];
    bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
    bytes[Slot::SIZE - 1] = tag;
    Slot::from(bytes)
}

fn seed(index: usize, tag: u8) -> [u8; 32] {
    let mut seed = [0; 32];
    seed[..8].copy_from_slice(&(index as u64).to_be_bytes());
    seed[31] = tag;
    seed
}

fn private_key(seed: [u8; 32]) -> recoverable::PrivateKey {
    let mut rng = StdRng::from_seed(seed);
    recoverable::PrivateKey::random(&mut rng)
}

async fn write_accounts(db: &TestDb, accounts: &[(Address, Account)]) {
    let mut db = db.write().await;
    let mut batch = db.new_batch();
    for (address, account) in accounts {
        let key = account_key(*address);
        let value = StateValue::Account(*account);
        batch = batch.write(key, Some(value));
    }
    let finalized = batch
        .merkleize(None, &db)
        .await
        .expect("merkleization should succeed")
        .finalize();
    db.apply_batch(finalized)
        .await
        .expect("batch apply should succeed");
}

async fn open_state_db(
    context: TestContext,
    suffix: &str,
) -> fixed::Db<mmr::Family, TestContext, Slot, StateValue, TestHasher, EightCap> {
    let page_cache = CacheRef::from_pooler(&context, NZU16!(101), NZUsize!(11));
    let config = FixedConfig {
        merkle_config: MmrConfig {
            journal_partition: format!("bench-journal-{suffix}"),
            metadata_partition: format!("bench-metadata-{suffix}"),
            items_per_blob: NZU64!(11),
            write_buffer: NZUsize!(1024),
            thread_pool: None,
            page_cache: page_cache.clone(),
        },
        journal_config: JournalConfig {
            partition: format!("bench-log-{suffix}"),
            items_per_blob: NZU64!(7),
            page_cache,
            write_buffer: NZUsize!(1024),
        },
        translator: EightCap,
    };

    fixed::Db::init(context, config)
        .await
        .expect("db init should succeed")
}

fn account_key(address: Address) -> Slot {
    address.as_ref().into()
}

#[derive(Clone, Copy, Debug)]
enum Contention {
    Low,
    High,
}
