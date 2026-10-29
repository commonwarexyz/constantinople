//! Measures the in-memory CPU cost of settling a block body: planning it and settling it against
//! starting accounts already in memory. It does not read or merkleize a database; the `compute`
//! bench target measures the whole pipeline against QMDB.

use ahash::AHashMap;
use commonware_allocator::mimalloc::{Config, MiMalloc, Purge, Reserve};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_glue::transfers::Plan;
use commonware_parallel::{Rayon, Sequential, Strategy};
use constantinople_application::executor::{PreparedTransfer, account_slots, starting_accounts};
use constantinople_primitives::{Account, AccountKey, Nonce};
use core::num::NonZeroUsize;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::{hint::black_box, time::Duration};

#[global_allocator]
static ALLOC: MiMalloc = MiMalloc::new(Config {
    purge: Purge::After(Duration::from_secs(10)),
    reserve: Some(Reserve::pinned(2 << 30)),
    ..Config::DEFAULT
});

type State = AHashMap<AccountKey, Account>;

const TRANSACTION_COUNTS: &[usize] = &[256, 1024, 8192, 16_384, 65_536];

/// Transactions each sender signs in the contended fixture.
const SHARED_FANOUT: usize = 8;

/// Workers in the pool behind the parallel rows.
const WORKERS: usize = 8;

fn key(index: u64) -> AccountKey {
    AccountKey::try_from(Sha256::hash(&[&index.to_le_bytes()]).as_ref()).expect("32-byte key")
}

fn executor(c: &mut Criterion) {
    let pool = Rayon::new(NonZeroUsize::new(WORKERS).expect("workers")).expect("rayon pool");
    let mut group = c.benchmark_group("executor");
    for &transaction_count in TRANSACTION_COUNTS {
        group.throughput(Throughput::Elements(transaction_count as u64));

        // Unique senders and recipients (every account touched once).
        let (state, transfers) = unique_fixture(transaction_count);
        bench_settle(&mut group, "unique", &state, &transfers, &Sequential);
        bench_settle(&mut group, "unique/pool", &state, &transfers, &pool);

        // Contended accounts: each sender signs several transactions to shared
        // recipients, so senders and recipients overlap across the batch.
        let (state, transfers) = shared_fixture(transaction_count);
        bench_settle(&mut group, "shared", &state, &transfers, &Sequential);
        bench_settle(&mut group, "shared/pool", &state, &transfers, &pool);
    }
    group.finish();
}

fn settle(state: &State, transfers: &[PreparedTransfer], strategy: &impl Strategy) -> usize {
    let plan = Plan::new(transfers, strategy).expect("bench transfers plan");
    let reads = plan
        .keys()
        .iter()
        .map(|key| state.get(key).copied())
        .collect();
    let slots = plan
        .settle(&starting_accounts(reads), strategy)
        .expect("bench transfers settle");
    account_slots(slots).len()
}

fn bench_settle(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    fixture: &str,
    state: &State,
    transfers: &[PreparedTransfer],
    strategy: &impl Strategy,
) {
    group.bench_with_input(
        BenchmarkId::new(fixture, transfers.len()),
        &transfers.len(),
        |bencher, _| {
            bencher.iter(|| black_box(settle(black_box(state), black_box(transfers), strategy)));
        },
    );
}

fn unique_fixture(transaction_count: usize) -> (State, Vec<PreparedTransfer>) {
    let mut state = State::new();
    let transfers = (0..transaction_count as u64)
        .map(|index| {
            let sender = key(index);
            let recipient = key(index + transaction_count as u64);
            state.insert(
                sender,
                Account {
                    balance: 1,
                    nonce: Nonce::default(),
                },
            );
            state.insert(recipient, Account::default());
            PreparedTransfer {
                sender,
                recipient,
                value: 1,
                nonce: 0,
            }
        })
        .collect();
    (state, transfers)
}

fn shared_fixture(transaction_count: usize) -> (State, Vec<PreparedTransfer>) {
    let account_count = (transaction_count / SHARED_FANOUT).max(1);
    let state = (0..account_count as u64)
        .map(|index| {
            let account = Account {
                balance: transaction_count as u64,
                nonce: Nonce::default(),
            };
            (key(index), account)
        })
        .collect();
    let mut nonces = vec![0u64; account_count];
    let transfers = (0..transaction_count)
        .map(|index| {
            let sender = index % account_count;
            let recipient = (index * 7 + 3) % account_count;
            let nonce = nonces[sender];
            nonces[sender] += 1;
            PreparedTransfer {
                sender: key(sender as u64),
                recipient: key(recipient as u64),
                value: 1,
                nonce,
            }
        })
        .collect();
    (state, transfers)
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = executor
}
criterion_main!(benches);
