use commonware_codec::{DecodeExt, FixedSize};
use commonware_cryptography::{Signer, ed25519, sha256};
use commonware_math::algebra::Random;
use constantinople_application::processor::{executor, state::State};
use constantinople_primitives::{Account, Address, Transaction, VerifiedTransaction};
use core::num::NonZeroU64;
use divan::Bencher;
use rand::{SeedableRng, rngs::StdRng};
use std::{collections::HashMap, hint::black_box};

type TestHasher = sha256::Sha256;
type TestTransaction = VerifiedTransaction<ed25519::PublicKey, TestHasher>;

const NAMESPACE: &[u8] = b"processor-bench";
const TRANSACTION_COUNTS: &[usize] = &[256, 1024, 8192, 16_384, 65_536];

fn main() {
    divan::main();
}

#[divan::bench(args = TRANSACTION_COUNTS)]
fn execution(bencher: Bencher<'_, '_>, transaction_count: usize) {
    let (state, transactions) = build_fixture(transaction_count);
    bencher.bench_local(|| {
        black_box(
            executor::execute(&state, &transactions)
                .expect("bench transactions should execute")
                .len(),
        )
    });
}

fn build_fixture(transaction_count: usize) -> (State, Vec<TestTransaction>) {
    let mut accounts = HashMap::new();
    let mut transactions = Vec::with_capacity(transaction_count);

    for index in 0..transaction_count {
        let signer = TestSigner::new(index as u64);
        let recipient = address(index as u64);
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

    let valid = executor::propose(&accounts, transactions).valid;
    (accounts, valid)
}

struct TestSigner {
    key: ed25519::PrivateKey,
    address: Address,
}

impl TestSigner {
    fn new(index: u64) -> Self {
        let key = ed25519::PrivateKey::random(&mut StdRng::seed_from_u64(index));
        let address = Address::from_public_key(&mut TestHasher::default(), &key.public_key());
        Self { key, address }
    }

    fn sign(&self, to: Address, value: u64, nonce: u64) -> TestTransaction {
        Transaction::new(
            self.key.public_key(),
            to,
            NonZeroU64::new(value).expect("bench value must be non-zero"),
            nonce,
        )
        .seal_and_sign_verified(&self.key, NAMESPACE, &mut TestHasher::default())
    }
}

fn address(index: u64) -> Address {
    let mut bytes = [0; Address::SIZE];
    bytes[..8].copy_from_slice(&index.to_be_bytes());
    Address::decode(&bytes[..]).expect("address bytes should decode")
}
