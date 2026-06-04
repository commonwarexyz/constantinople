use commonware_cryptography::{Signer, ed25519, sha256};
use commonware_math::algebra::Random;
use constantinople_application::executor::{self, State};
use constantinople_primitives::{
    Account, AccountKey, Transaction, TransactionPublicKey, VerifiedTransaction,
};
use core::num::NonZeroU64;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::{SeedableRng, rngs::StdRng};
use std::hint::black_box;

type TestHasher = sha256::Sha256;
type TestTransaction = VerifiedTransaction<TestHasher>;

const NAMESPACE: &[u8] = b"executor-bench";
const TRANSACTION_COUNTS: &[usize] = &[256, 1024, 8192, 16_384, 65_536];

fn executor(c: &mut Criterion) {
    let mut group = c.benchmark_group("executor");

    for &transaction_count in TRANSACTION_COUNTS {
        group.throughput(Throughput::Elements(transaction_count as u64));
        group.bench_with_input(
            BenchmarkId::new("execution", transaction_count),
            &transaction_count,
            |bencher, &transaction_count| {
                let (state, transactions) = build_fixture(transaction_count);
                let transfers = transactions
                    .iter()
                    .map(executor::prepare_transfer)
                    .collect::<Option<Vec<_>>>()
                    .expect("bench transactions should prepare");
                bencher.iter(|| {
                    black_box(
                        executor::execute(black_box(&state), black_box(&transfers))
                            .expect("bench transfers should execute")
                            .len(),
                    )
                });
            },
        );
    }

    group.finish();
}

fn build_fixture(transaction_count: usize) -> (State, Vec<TestTransaction>) {
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
                nonce: 0,
                nonce_bitmap: 0,
            },
        );
        accounts.insert(
            AccountKey::from_public_key(&recipient_public_key),
            Account::default(),
        );
        transactions.push(signer.sign(recipient, 1, 0));
    }

    let valid = executor::propose(&accounts, transactions).valid;
    (accounts, valid)
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
