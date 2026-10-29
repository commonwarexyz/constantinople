//! Compares best-effort selection (the propose path) against settling the same body as one batch
//! (the verify path) on block-sized in-memory workloads.

use ahash::AHashMap;
use commonware_allocator::mimalloc::{Config, MiMalloc, Purge, Reserve};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_glue::transfers::{Plan, Selection};
use commonware_parallel::Sequential;
use commonware_storage::qmdb::any::batch::Slot;
use constantinople_application::executor::{
    PreparedTransfer, TransferAccount, account_slots, starting_accounts,
};
use constantinople_primitives::{Account, AccountKey, Nonce};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

#[global_allocator]
static ALLOC: MiMalloc = MiMalloc::new(Config {
    purge: Purge::After(Duration::from_secs(10)),
    reserve: Some(Reserve::pinned(2 << 30)),
    ..Config::DEFAULT
});

type State = AHashMap<AccountKey, Account>;

const COUNTS: &[usize] = &[16_384, 32_768];
const SHARED_FANOUT: u64 = 8;
const WARMUP: u32 = 3;
const ITERS: u32 = 30;

fn key(index: u64) -> AccountKey {
    AccountKey::try_from(Sha256::hash(&[&index.to_le_bytes()]).as_ref()).expect("32-byte key")
}

/// `n` transfers with unique senders, to unique or shared recipients. When `stale_every > 0`,
/// every `stale_every`-th transfer carries an already-consumed nonce, which only selection can
/// drop.
fn fixture(n: usize, shared: bool, stale_every: usize) -> (State, Vec<PreparedTransfer>) {
    let mut state = State::with_capacity(2 * n);
    let mut transfers = Vec::with_capacity(n);
    for i in 0..n as u64 {
        let sender = key(i);
        let recipient = if shared {
            key(u64::MAX - (i % SHARED_FANOUT))
        } else {
            key(u64::MAX - i)
        };
        let mut nonce = Nonce::default();
        if stale_every > 0 && (i as usize).is_multiple_of(stale_every) {
            assert!(nonce.consume(0));
        }
        state.insert(
            sender,
            Account {
                balance: 1_000_000,
                nonce,
            },
        );
        transfers.push(PreparedTransfer {
            sender,
            recipient,
            value: 1 + i % 97,
            nonce: 0,
        });
    }
    (state, transfers)
}

fn run<T>(label: &str, n: usize, mut op: impl FnMut() -> T) {
    let mut total = Duration::ZERO;
    for iter in 0..(WARMUP + ITERS) {
        let start = Instant::now();
        black_box(op());
        if iter >= WARMUP {
            total += start.elapsed();
        }
    }
    let avg = total / ITERS;
    let tps = n as f64 / avg.as_secs_f64() / 1e6;
    println!("  {label:28} {avg:>10.2?}  ({tps:.2} Melem/s)");
}

fn verify(state: &State, transfers: &[PreparedTransfer]) -> Vec<Slot<Account>> {
    let plan = Plan::new(transfers, &Sequential).expect("clean body plans");
    let reads = plan
        .keys()
        .iter()
        .map(|key| state.get(key).copied())
        .collect();
    let slots = plan
        .settle(&starting_accounts(reads), &Sequential)
        .expect("clean body settles");
    account_slots(slots)
}

fn select(state: &State, transfers: &[PreparedTransfer]) -> (usize, Vec<Slot<Account>>) {
    let mut selection: Selection<AccountKey, TransferAccount> = Selection::new();
    let touched = selection.touch(transfers);
    let reads = selection.keys()[touched]
        .iter()
        .map(|key| state.get(key).copied())
        .collect();
    selection.register(starting_accounts(reads));
    let accepted = selection.apply(transfers);
    let kept = accepted.iter().filter(|accepted| **accepted).count();
    (kept, account_slots(selection.settle(&Sequential)))
}

fn main() {
    for &n in COUNTS {
        for shared in [false, true] {
            let mix = if shared { "shared" } else { "unique" };
            println!("{n} txs / {mix} recipients");
            let (state, transfers) = fixture(n, shared, 0);
            run("verify", n, || verify(&state, &transfers));
            run("select clean", n, || {
                let (kept, slots) = select(&state, &transfers);
                assert_eq!(kept, n);
                slots
            });
            let (state, transfers) = fixture(n, shared, 20);
            run("select 5% stale", n, || select(&state, &transfers));
        }
    }
}
