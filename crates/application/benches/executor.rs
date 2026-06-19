use commonware_cryptography::{Signer, ed25519, sha256};
use commonware_math::algebra::Random;
use constantinople_application::executor::{self, PreparedTransfer, State};
use constantinople_primitives::{
    Account, AccountKey, Nonce, Transaction, TransactionPublicKey, VerifiedTransaction,
};
use core::num::NonZeroU64;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::{SeedableRng, rngs::StdRng};
use std::hint::black_box;

type TestHasher = sha256::Sha256;
type TestTransaction = VerifiedTransaction<TestHasher>;
type Transfers = Vec<PreparedTransfer>;

const NAMESPACE: &[u8] = b"executor-bench";
const TRANSACTION_COUNTS: &[usize] = &[256, 1024, 8192, 16_384, 65_536];

/// Senders per transaction in the contended fixture (each sender signs this many).
const SHARED_FANOUT: usize = 8;

fn executor(c: &mut Criterion) {
    let mut group = c.benchmark_group("executor");

    for &transaction_count in TRANSACTION_COUNTS {
        group.throughput(Throughput::Elements(transaction_count as u64));

        // Unique senders and recipients (every account touched once).
        let (state, transfers) = build_unique_fixture(transaction_count);
        bench_compute(&mut group, "unique", transaction_count, &state, &transfers);

        // Contended accounts: each sender signs several transactions to shared
        // recipients, so senders and recipients overlap across the batch.
        let (state, transfers) = build_shared_fixture(transaction_count);
        bench_compute(&mut group, "shared", transaction_count, &state, &transfers);
    }

    group.finish();
}

/// Benchmarks only the in-memory CPU cost of the current compute kernel on
/// pre-loaded state. It does NOT measure the load, which is the part this
/// change restructures, so it is not a benchmark of the pipeline. For the real
/// load + compute measurement against a QMDB, run the `compute` bench target.
fn bench_compute(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    fixture: &str,
    transaction_count: usize,
    state: &State,
    transfers: &Transfers,
) {
    group.bench_with_input(
        BenchmarkId::new(fixture, transaction_count),
        &transaction_count,
        |bencher, _| {
            bencher.iter(|| {
                black_box(
                    executor::compute(black_box(state), black_box(transfers))
                        .expect("bench transfers should execute")
                        .len(),
                )
            });
        },
    );
}

fn build_unique_fixture(transaction_count: usize) -> (State, Transfers) {
    let mut accounts = State::new();
    let mut transactions = Vec::with_capacity(transaction_count);

    for index in 0..transaction_count {
        let signer = TestSigner::new(index as u64);
        let recipient = TestSigner::new(index as u64 + transaction_count as u64).public_key;
        let sender_public_key = TransactionPublicKey::ed25519(signer.public_key.clone());
        let recipient_public_key = TransactionPublicKey::ed25519(recipient.clone());
        accounts.insert(
            AccountKey::from_public_key(&sender_public_key),
            Account {
                balance: 1,
                nonce: Nonce::default(),
            },
        );
        accounts.insert(
            AccountKey::from_public_key(&recipient_public_key),
            Account::default(),
        );
        transactions.push(signer.sign(recipient, 1, 0));
    }

    finalize_fixture(accounts, transactions)
}

fn build_shared_fixture(transaction_count: usize) -> (State, Transfers) {
    let account_count = (transaction_count / SHARED_FANOUT).max(1);
    let signers: Vec<TestSigner> = (0..account_count)
        .map(|index| TestSigner::new(index as u64))
        .collect();

    let mut accounts = State::new();
    for signer in &signers {
        let public_key = TransactionPublicKey::ed25519(signer.public_key.clone());
        accounts.insert(
            AccountKey::from_public_key(&public_key),
            Account {
                balance: transaction_count as u64,
                nonce: Nonce::default(),
            },
        );
    }

    let mut nonces = vec![0u64; account_count];
    let mut transactions = Vec::with_capacity(transaction_count);
    for index in 0..transaction_count {
        let sender_index = index % account_count;
        let recipient_index = (index * 7 + 3) % account_count;
        let nonce = nonces[sender_index];
        nonces[sender_index] += 1;
        transactions.push(signers[sender_index].sign(
            signers[recipient_index].public_key.clone(),
            1,
            nonce,
        ));
    }

    finalize_fixture(accounts, transactions)
}

fn finalize_fixture(accounts: State, transactions: Vec<TestTransaction>) -> (State, Transfers) {
    let transfers = transactions
        .iter()
        .map(executor::prepare_transfer)
        .collect::<Option<Vec<_>>>()
        .expect("bench transactions should prepare");
    executor::compute(&accounts, &transfers).expect("bench fixtures must be valid");
    (accounts, transfers)
}

struct TestSigner {
    key: ed25519::PrivateKey,
    public_key: ed25519::PublicKey,
}

impl TestSigner {
    fn new(index: u64) -> Self {
        let key = ed25519::PrivateKey::random(&mut StdRng::seed_from_u64(index));
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
        .seal_and_sign(&self.key, NAMESPACE, &mut TestHasher::default())
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = executor
}
criterion_main!(benches);
