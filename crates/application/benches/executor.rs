use commonware_cryptography::{Signer, ed25519, sha256};
use commonware_math::algebra::Random;
use commonware_parallel::Sequential;
use constantinople_application::executor::{self, Changeset, PreparedTransfer, State};
use constantinople_primitives::{
    Account, AccountKey, Nonce, Transaction, TransactionPublicKey, VerifiedTransaction,
};
use core::num::NonZeroU64;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::{SeedableRng, rngs::StdRng};
use std::hint::black_box;

type TestHasher = sha256::Sha256;
type TestTransaction = VerifiedTransaction<TestHasher>;
type Transfers = Vec<PreparedTransfer<TestHasher>>;

/// The previous single-overlay execution, kept for a same-run baseline. Debits
/// and credits are applied inline against one map, so a recipient could spend
/// funds received earlier in the block.
fn legacy_execute(state: &State, transfers: &Transfers) -> Changeset {
    let mut writes = State::with_capacity(transfers.len() * 2);
    for transfer in transfers {
        let mut sender = writes
            .get(&transfer.sender)
            .copied()
            .or_else(|| state.get(&transfer.sender).copied())
            .unwrap_or_default();
        assert!(
            sender.balance >= transfer.value && sender.nonce.consume(transfer.nonce),
            "bench fixtures must be valid"
        );
        if transfer.sender == transfer.recipient {
            writes.insert(transfer.sender.clone(), sender);
            continue;
        }
        let mut recipient = writes
            .get(&transfer.recipient)
            .copied()
            .or_else(|| state.get(&transfer.recipient).copied())
            .unwrap_or_default();
        recipient.balance = recipient
            .balance
            .checked_add(transfer.value)
            .expect("bench fixtures must not overflow");
        sender.balance -= transfer.value;
        writes.insert(transfer.sender.clone(), sender);
        writes.insert(transfer.recipient.clone(), recipient);
    }
    let mut changeset: Changeset = writes.into_iter().collect();
    changeset.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
    changeset
}

const NAMESPACE: &[u8] = b"executor-bench";
const TRANSACTION_COUNTS: &[usize] = &[256, 1024, 8192, 16_384, 65_536];

/// Senders per transaction in the contended fixture (each sender signs this many).
const SHARED_FANOUT: usize = 8;

fn executor(c: &mut Criterion) {
    let mut group = c.benchmark_group("executor");

    for &transaction_count in TRANSACTION_COUNTS {
        group.throughput(Throughput::Elements(transaction_count as u64));

        // Disjoint senders and recipients (every account touched once).
        let (state, transfers) = build_unique_fixture(transaction_count);
        bench_execute(&mut group, "unique", transaction_count, &state, &transfers);

        // Contended accounts: each sender signs several transactions to shared
        // recipients, so senders and recipients overlap across the batch.
        let (state, transfers) = build_shared_fixture(transaction_count);
        bench_execute(&mut group, "shared", transaction_count, &state, &transfers);
    }

    group.finish();
}

/// Benchmarks only the in-memory CPU cost of the execute kernel (legacy
/// single-overlay vs the new sharded all-or-nothing pass) on pre-loaded state.
/// It does NOT measure the load, which is the part this change restructures, so
/// it is not a benchmark of the pipeline. For the real load + execute
/// measurement against a QMDB, see the `db_bench` harness in
/// `consensus::execution` (run with `--ignored --nocapture --release`).
fn bench_execute(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    fixture: &str,
    transaction_count: usize,
    state: &State,
    transfers: &Transfers,
) {
    group.bench_with_input(
        BenchmarkId::new(format!("{fixture}/legacy"), transaction_count),
        &transaction_count,
        |bencher, _| {
            bencher
                .iter(|| black_box(legacy_execute(black_box(state), black_box(transfers)).len()));
        },
    );
    group.bench_with_input(
        BenchmarkId::new(format!("{fixture}/new"), transaction_count),
        &transaction_count,
        |bencher, _| {
            bencher.iter(|| {
                black_box(
                    executor::execute(&Sequential, black_box(state), black_box(transfers))
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
    executor::execute(&Sequential, &accounts, &transfers).expect("bench fixtures must be valid");
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
