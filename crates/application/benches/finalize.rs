//! Measures the dual-merkleize scheduling in `finalize_execution`: sequential
//! awaits versus `futures::join!` versus spawning the transaction-history
//! merkleize on its own task. The spawned variant measures ~1ms faster at 32k
//! txs (the state merkleize has long single-threaded phases that leave pool
//! workers idle), but production joins both merkleizes on a single task: a
//! spawned child makes glue's verify cancellation observable mid-finalize,
//! and the gain is too small to carry that hazard. Asserts all three
//! schedules produce identical roots.

use commonware_cryptography::{Hasher as _, Sha256};
use commonware_glue::stateful::db::{DatabaseSet, Merkleized as _, Unmerkleized as _};
use commonware_parallel::Rayon;
use commonware_runtime::{
    Runner as _, Spawner as _, Supervisor as _, buffer::paged::CacheRef, tokio,
};
use commonware_storage::{
    journal::contiguous::{
        fixed::Config as FixedJournalConfig, variable::Config as VariableJournalConfig,
    },
    merkle::full::Config as MmrConfig,
    qmdb::{any::FixedConfig, keyless::fixed as keyless_fixed},
    translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use constantinople_application::{
    consensus::{self, Databases},
    executor::PreparedTransfer,
};
use constantinople_primitives::{Account, AccountKey, Nonce};
use core::num::NonZeroUsize;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

type Dbs = Databases<tokio::Context, Sha256, EightCap, Rayon>;

const ACCOUNTS: u64 = 1_000_000;
const TXS: usize = 32_768;
const WARMUP: usize = 3;
const ITERS: usize = 10;

fn key(index: u64) -> AccountKey {
    AccountKey::try_from(Sha256::hash(&index.to_le_bytes()).as_ref()).expect("32-byte key")
}

fn state_config(strategy: Rayon, cache: &CacheRef) -> FixedConfig<EightCap, Rayon> {
    FixedConfig {
        merkle_config: MmrConfig {
            journal_partition: "finalize-state-journal".into(),
            metadata_partition: "finalize-state-metadata".into(),
            items_per_blob: NZU64!(1 << 20),
            write_buffer: NZUsize!(1 << 20),
            strategy,
            page_cache: cache.clone(),
        },
        journal_config: FixedJournalConfig {
            partition: "finalize-state-log".into(),
            items_per_blob: NZU64!(1 << 20),
            page_cache: cache.clone(),
            write_buffer: NZUsize!(1 << 20),
        },
        translator: EightCap,
        init_cache_size: Some(NZUsize!(1 << 18)),
    }
}

fn transaction_config(strategy: Rayon, cache: &CacheRef) -> keyless_fixed::CompactConfig<Rayon> {
    keyless_fixed::CompactConfig {
        strategy,
        witness: VariableJournalConfig {
            partition: "finalize-transactions-witness".into(),
            items_per_section: NZU64!(1 << 16),
            compression: None,
            codec_config: (),
            page_cache: cache.clone(),
            write_buffer: NZUsize!(1 << 20),
        },
        commit_codec_config: (),
    }
}

fn transfers() -> Vec<PreparedTransfer> {
    (0..TXS)
        .map(|i| {
            let sender = key(i as u64);
            let recipient = key(TXS as u64 + i as u64);
            PreparedTransfer {
                sender,
                recipient,
                sender_prefix: sender.prefix(),
                recipient_prefix: recipient.prefix(),
                value: 1,
                nonce: 0,
            }
        })
        .collect()
}

fn main() {
    tokio::Runner::new(tokio::Config::default().with_worker_threads(8)).start(
        |context| async move {
            let strategy = Rayon::new(NonZeroUsize::new(8).expect("threads")).expect("rayon pool");
            let cache = CacheRef::from_pooler(&context, NZU16!(8192), NZUsize!(65_536));
            let dbs = Dbs::init(
                context.child("dbs"),
                (
                    state_config(strategy.clone(), &cache),
                    transaction_config(strategy.clone(), &cache),
                ),
            )
            .await;

            // Seed 1M accounts and finalize both databases once.
            let (mut state_batch, transaction_batch) = dbs.new_batches().await;
            for index in 0..ACCOUNTS {
                state_batch = state_batch.write(
                    key(index),
                    Some(Account {
                        balance: 1_000_000,
                        nonce: Nonce::default(),
                    }),
                );
            }
            let state = state_batch.merkleize().await.expect("seed state");
            let transactions = transaction_batch.merkleize().await.expect("seed txs");
            dbs.finalize((state, transactions)).await;

            let transfers = Arc::new(transfers());
            let digests: Vec<_> = (0..TXS as u64)
                .map(|i| Sha256::hash(&(u64::MAX - i).to_le_bytes()))
                .collect();

            let mut totals = [Duration::ZERO; 3];
            let mut roots: [Option<(String, String)>; 3] = [None, None, None];
            for iter in 0..(WARMUP + ITERS) {
                for variant in 0..3 {
                    let (state_batch, mut transaction_batch) = dbs.new_batches().await;
                    let (staged, updates) =
                        consensus::compute(state_batch, Arc::clone(&transfers), &strategy).await;
                    let updates = updates.expect("compute");
                    for digest in &digests {
                        transaction_batch = transaction_batch.append(*digest);
                    }

                    let start = Instant::now();
                    let (state, transactions) = match variant {
                        // Strictly sequential.
                        0 => {
                            let state = staged.merkleize(updates, Vec::new()).await.expect("state");
                            let transactions = transaction_batch.merkleize().await.expect("txs");
                            (state, transactions)
                        }
                        // futures::join! on one task (production's finalize_execution).
                        1 => {
                            let (state, transactions) = futures::join!(
                                staged.merkleize(updates, Vec::new()),
                                transaction_batch.merkleize()
                            );
                            (state.expect("state"), transactions.expect("txs"))
                        }
                        // Spawned concurrent (the rejected alternative; see module docs).
                        _ => {
                            let handle = context
                                .child("tx_merkleize")
                                .shared(true)
                                .spawn(move |_| async move { transaction_batch.merkleize().await });
                            let state = staged.merkleize(updates, Vec::new()).await.expect("state");
                            let transactions = handle.await.expect("task").expect("txs");
                            (state, transactions)
                        }
                    };
                    let elapsed = start.elapsed();

                    let pair = (
                        format!("{}", state.root()),
                        format!("{}", transactions.root()),
                    );
                    match &roots[variant] {
                        None => roots[variant] = Some(pair),
                        Some(existing) => {
                            assert_eq!(existing, &pair, "variant {variant} roots drifted")
                        }
                    }
                    if iter >= WARMUP {
                        totals[variant] += elapsed;
                    }
                }
            }

            assert_eq!(roots[0], roots[1], "sequential vs join roots");
            assert_eq!(roots[1], roots[2], "join vs spawned roots");
            for (name, total) in ["sequential", "join!", "spawned"].iter().zip(totals) {
                println!(
                    "{name:>10}: {:?} avg over {ITERS} iters",
                    total / ITERS as u32
                );
            }
            println!("roots: {:?}", roots[0].as_ref().expect("roots recorded"));
        },
    );
}
