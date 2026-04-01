use commonware_codec::{DecodeExt, FixedSize};
use commonware_cryptography::{Signer, blake3, secp256r1::recoverable};
use commonware_math::algebra::Random;
use constantinople_application::processor::{executor::Processor, state::State};
use constantinople_primitives::{Account, Address, Transaction, VerifiedTransaction};
use core::{marker::PhantomData, num::NonZeroU64};
use divan::Bencher;
use rand::{SeedableRng, rngs::StdRng};
use std::{collections::HashMap, hint::black_box, sync::OnceLock};

type TestHasher = blake3::Blake3;
type TestPublicKey = recoverable::PublicKey;
type TestTransaction = VerifiedTransaction<TestPublicKey, TestHasher>;

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
fn execution_low_contention(bencher: Bencher<'_, '_>, transaction_count: usize) {
    let fixture = low_contention_fixture(transaction_count);
    bencher.bench_local(|| black_box(fixture.run()));
}

#[divan::bench(args = TRANSACTION_COUNTS)]
fn execution_high_contention(bencher: Bencher<'_, '_>, transaction_count: usize) {
    let fixture = high_contention_fixture(transaction_count);
    bencher.bench_local(|| black_box(fixture.run()));
}

#[derive(Debug)]
struct BenchFixture {
    state: State,
    transactions: Vec<TestTransaction>,
}

impl BenchFixture {
    fn low_contention(transaction_count: usize) -> Self {
        let mut accounts = HashMap::with_capacity(transaction_count * 2);
        let mut transactions = Vec::with_capacity(transaction_count);

        for index in 0..transaction_count {
            let signer = TestSigner::new(seed(index, 1));
            let recipient = address(index, 0x20);
            accounts.insert(
                signer.address,
                Account {
                    balance: 1,
                    nonce: 0,
                },
            );
            accounts.insert(recipient, Account::default());
            transactions.push(signer.sign(recipient, 1, 0));
        }

        let valid = valid_transactions(transactions, &accounts);
        Self {
            state: State::new(accounts),
            transactions: valid,
        }
    }

    fn high_contention(transaction_count: usize) -> Self {
        let mut accounts = HashMap::with_capacity(transaction_count + 1);
        let mut transactions = Vec::with_capacity(transaction_count);
        let recipient = address(0, 0x7a);

        accounts.insert(recipient, Account::default());

        for index in 0..transaction_count {
            let signer = TestSigner::new(seed(index, 101));
            accounts.insert(
                signer.address,
                Account {
                    balance: 1,
                    nonce: 0,
                },
            );
            transactions.push(signer.sign(recipient, 1, 0));
        }

        let valid = valid_transactions(transactions, &accounts);
        Self {
            state: State::new(accounts),
            transactions: valid,
        }
    }

    fn run(&self) -> usize {
        let processor = Processor::new();
        processor
            .execute(self.state.clone(), &self.transactions)
            .expect("bench proposal transactions should execute")
            .changeset
            .len()
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

    fn sign(&self, to: Address, value: u64, nonce: u64) -> TestTransaction {
        let key = private_key(self.seed);
        Transaction {
            sender: key.public_key(),
            to,
            value: NonZeroU64::new(value).expect("bench value must be non-zero"),
            nonce,
            _digest: PhantomData,
        }
        .seal_and_sign_verified(&key, NAMESPACE, &mut TestHasher::default())
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

fn valid_transactions(
    transactions: Vec<TestTransaction>,
    accounts: &HashMap<Address, Account>,
) -> Vec<TestTransaction> {
    Processor::new()
        .propose(State::new(accounts.clone()), transactions)
        .valid
}

fn address(index: usize, tag: u8) -> Address {
    let mut bytes = [0; Address::SIZE];
    bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
    bytes[Address::SIZE - 1] = tag;
    Address::decode(&bytes[..]).expect("address bytes should decode")
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

#[derive(Clone, Copy, Debug)]
enum Contention {
    Low,
    High,
}
