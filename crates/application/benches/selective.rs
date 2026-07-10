//! Compares the best-effort selective executor (propose path) against the
//! all-or-nothing baseline (verify path) on block-sized in-memory workloads.

use commonware_cryptography::{Hasher as _, Sha256};
use constantinople_application::executor::{PreparedTransfer, SelectiveExecutor, State, compute};
use constantinople_primitives::{Account, AccountKey, Nonce};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

const COUNTS: &[usize] = &[16_384, 32_768];
const SHARED_FANOUT: u64 = 8;
const WARMUP: u32 = 3;
const ITERS: u32 = 30;

fn key(index: u64) -> AccountKey {
    AccountKey::try_from(Sha256::hash(&index.to_le_bytes()).as_ref()).expect("32-byte key")
}

fn transfer(sender: AccountKey, recipient: AccountKey, value: u64, nonce: u64) -> PreparedTransfer {
    PreparedTransfer {
        sender,
        recipient,
        sender_prefix: sender.prefix(),
        recipient_prefix: recipient.prefix(),
        value,
        nonce,
    }
}

/// `n` transfers with unique senders/recipients; when `stale_every > 0`,
/// every `stale_every`-th transfer carries an already-consumed nonce (only
/// the selective path can execute those bodies).
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
        state.insert(
            sender,
            Account {
                balance: 1_000_000,
                nonce: Nonce::default(),
            },
        );
        if stale_every > 0 && (i as usize).is_multiple_of(stale_every) {
            // Nonce 0 consumed at genesis: the selective pass must drop the
            // transfer below, which also carries nonce 0.
            let account = state.get_mut(&sender).expect("just inserted");
            assert!(account.nonce.consume(0));
        }
        transfers.push(transfer(sender, recipient, 1 + i % 97, 0));
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

fn selective(
    state: &State,
    transfers: &[PreparedTransfer],
) -> (usize, Vec<(usize, Option<Account>)>) {
    let mut executor = SelectiveExecutor::new();
    let keys = executor.begin_round(transfers);
    let values: Vec<Option<Account>> = keys.iter().map(|key| state.get(key).copied()).collect();
    executor.register(&values);
    let applied = executor.apply(transfers);
    let kept = applied.iter().filter(|applied| **applied).count();
    (kept, executor.into_updates())
}

fn main() {
    for &n in COUNTS {
        for shared in [false, true] {
            let mix = if shared { "shared" } else { "unique" };
            println!("{n} txs / {mix} recipients");
            let (state, transfers) = fixture(n, shared, 0);
            run("baseline all-or-nothing", n, || {
                compute(&state, &transfers).expect("clean batch")
            });
            run("selective clean", n, || {
                let (kept, updates) = selective(&state, &transfers);
                assert_eq!(kept, n);
                updates
            });
            let (state, transfers) = fixture(n, shared, 20);
            run("selective 5% stale", n, || selective(&state, &transfers));
        }
    }
}
