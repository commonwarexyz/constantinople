//! Benchmarks the production transaction signature-verification helper.

use commonware_codec::{FixedSize as _, ReadExt as _};
use commonware_cryptography::{Sha256, Signer as _, ed25519};
use commonware_parallel::{Rayon, Strategy as _};
use commonware_runtime::{Runner as _, Strategizer as _, Supervisor as _, tokio};
use commonware_utils::TestRng;
use constantinople_curve25519::signing::{
    BatchVerifier as Ed25519BatchVerifier, Signature as Ed25519Signature,
    VerifyingKey as Ed25519VerifyingKey,
};
use constantinople_primitives::{
    LazySignedTransaction, PublicKeyCache, TRANSACTION_NAMESPACE, Transaction,
    TransactionBatchVerifier, TransactionPublicKey, verify_transaction_batch,
};
use core::num::{NonZeroU64, NonZeroUsize};
use std::{
    hint::black_box,
    sync::Arc,
    time::{Duration, Instant},
};

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

struct Account {
    private_key: ed25519::PrivateKey,
    public_key: ed25519::PublicKey,
}

fn argument(index: usize, default: usize) -> usize {
    std::env::args()
        .nth(index)
        .map(|value| value.parse().expect("arguments must be positive integers"))
        .unwrap_or(default)
}

fn transactions(
    strategy: &Rayon,
    accounts: &[Account],
    count: usize,
    block: u64,
) -> Vec<LazySignedTransaction<Sha256>> {
    let per_account = count.div_ceil(accounts.len()) as u64;
    strategy.map_collect_vec(0..count, |index| {
        let sender_index = index % accounts.len();
        let sender = &accounts[sender_index];
        let recipient = &accounts[(sender_index + 1) % accounts.len()];
        let nonce = block * per_account + (index / accounts.len()) as u64;
        let transaction = Transaction::new(
            TransactionPublicKey::ed25519(sender.public_key.clone()),
            TransactionPublicKey::ed25519(recipient.public_key.clone()),
            NonZeroU64::new(1).expect("benchmark value must be non-zero"),
            nonce,
        )
        .seal_and_sign(
            &sender.private_key,
            TRANSACTION_NAMESPACE,
            &mut Sha256::default(),
        );
        LazySignedTransaction::new(transaction)
    })
}

async fn verify(
    cache: &PublicKeyCache,
    transactions: Arc<Vec<LazySignedTransaction<Sha256>>>,
    strategy: &Rayon,
    seed: u64,
) -> Duration {
    let cache = cache.clone();
    strategy
        .spawn(move |strategy: Rayon| {
            let mut rng = TestRng::new(seed);
            let started = Instant::now();
            let valid = verify_transaction_batch(
                TRANSACTION_NAMESPACE,
                &mut rng,
                &cache,
                transactions.as_slice(),
                &strategy,
            );
            let elapsed = started.elapsed();
            assert!(valid, "benchmark transactions must verify");
            black_box(valid);
            elapsed
        })
        .await
}

async fn verify_prepared_cache(
    cache: &PublicKeyCache,
    transactions: Arc<Vec<LazySignedTransaction<Sha256>>>,
    strategy: &Rayon,
    seed: u64,
) -> Duration {
    let cache = cache.clone();
    strategy
        .spawn(move |strategy: Rayon| {
            let mut rng = TestRng::new(seed);
            let started = Instant::now();
            let senders: Vec<_> = transactions
                .iter()
                .map(|lazy| {
                    lazy.get()
                        .and_then(|transaction| transaction.value().sender())
                        .expect("benchmark transaction must have a sender")
                })
                .collect();
            let keys = cache
                .decompress(&senders, &strategy)
                .expect("benchmark sender must decompress");
            let mut verifier = TransactionBatchVerifier::new(transactions.len());
            for (lazy, key) in transactions.iter().zip(&keys) {
                let transaction = lazy.get().expect("benchmark transaction must decode");
                assert!(verifier.add(
                    TRANSACTION_NAMESPACE,
                    transaction.message_digest().as_ref(),
                    key,
                    transaction.signature(),
                ));
            }
            let valid = verifier.verify(&mut rng, &strategy);
            let elapsed = started.elapsed();
            assert!(valid, "benchmark transactions must verify");
            black_box(valid);
            elapsed
        })
        .await
}

async fn verify_backend_direct(
    transactions: Arc<Vec<LazySignedTransaction<Sha256>>>,
    strategy: &Rayon,
    seed: u64,
) -> Duration {
    strategy
        .spawn(move |strategy: Rayon| {
            let mut rng = TestRng::new(seed);
            let started = Instant::now();
            let mut verifier = Ed25519BatchVerifier::new(transactions.len());
            for lazy in transactions.iter() {
                let transaction = lazy.get().expect("benchmark transaction must decode");
                let sender = transaction
                    .value()
                    .sender()
                    .expect("benchmark transaction must have a sender");
                let bytes = &sender.as_ref()[1..1 + Ed25519VerifyingKey::SIZE];
                let key = Ed25519VerifyingKey::read(&mut &bytes[..])
                    .expect("benchmark sender must be Ed25519");
                let signature = Ed25519Signature::read(&mut &transaction.signature().as_ref()[1..])
                    .expect("benchmark signature must be Ed25519");
                verifier.add_owned(
                    TRANSACTION_NAMESPACE,
                    transaction.message_digest().as_ref(),
                    key,
                    &signature,
                );
            }
            let valid = verifier.verify(&mut rng, &strategy);
            let elapsed = started.elapsed();
            assert!(valid, "benchmark transactions must verify");
            black_box(valid);
            elapsed
        })
        .await
}

fn main() {
    let count = argument(1, 100_000);
    let unique_keys = argument(2, 50_000);
    let rounds = argument(3, 7);
    let threads = argument(4, 13);
    let cache_capacity = argument(5, unique_keys.saturating_mul(2));
    assert!(count > 0, "transaction count must be positive");
    assert!(unique_keys > 0, "key count must be positive");
    assert!(unique_keys <= count, "key count cannot exceed transactions");
    assert!(rounds > 0, "round count must be positive");
    assert!(
        cache_capacity >= unique_keys,
        "cache capacity must hold every benchmark key"
    );
    let threads = NonZeroUsize::new(threads).expect("thread count must be positive");
    println!(
        "backend={} generating two {count}-transaction blocks across {unique_keys} keys; rounds={rounds} tokio_threads=3 rayon_threads={threads} cache_capacity={cache_capacity}",
        constantinople_primitives::transaction_ed25519_backend(),
    );
    let runner = tokio::Runner::new(tokio::Config::default().with_worker_threads(3));
    runner.start(|context| async move {
        let strategy = context.strategy(threads);
        let accounts: Vec<_> = (0..unique_keys)
            .map(|index| {
                let private_key = ed25519::PrivateKey::from_seed(index as u64);
                let public_key = private_key.public_key();
                Account {
                    private_key,
                    public_key,
                }
            })
            .collect();
        let first = Arc::new(transactions(&strategy, &accounts, count, 0));
        let second = Arc::new(transactions(&strategy, &accounts, count, 1));
        drop(accounts);

        let warmup_cache = PublicKeyCache::new(
            context.child("warmup_cache"),
            NonZeroUsize::new(cache_capacity).expect("cache capacity must be positive"),
        );
        let _ = verify(&warmup_cache, Arc::clone(&first), &strategy, 0).await;
        let _ = verify(&warmup_cache, Arc::clone(&second), &strategy, 1).await;
        let _ = verify_backend_direct(Arc::clone(&first), &strategy, 2).await;
        drop(warmup_cache);

        let production_cache = PublicKeyCache::new(
            context.child("production_cache"),
            NonZeroUsize::new(cache_capacity).expect("cache capacity must be positive"),
        );
        let prepared_cache = PublicKeyCache::new(
            context.child("prepared_cache"),
            NonZeroUsize::new(cache_capacity).expect("cache capacity must be positive"),
        );
        let _ = verify(&production_cache, Arc::clone(&first), &strategy, 3).await;
        assert!(
            production_cache.is_empty(),
            "Ed25519 verification must bypass the cache"
        );
        let _ = verify_prepared_cache(&prepared_cache, Arc::clone(&first), &strategy, 4).await;
        let _ = verify_prepared_cache(&prepared_cache, Arc::clone(&second), &strategy, 5).await;
        assert_eq!(prepared_cache.len(), unique_keys);

        let mut production = Vec::with_capacity(rounds);
        let mut prepared = Vec::with_capacity(rounds);
        let mut direct_backend = Vec::with_capacity(rounds);
        for round in 0..rounds {
            let transactions = if round % 2 == 0 {
                Arc::clone(&first)
            } else {
                Arc::clone(&second)
            };
            direct_backend.push(
                verify_backend_direct(Arc::clone(&transactions), &strategy, round as u64 + 6)
                    .await,
            );
            prepared.push(
                verify_prepared_cache(
                    &prepared_cache,
                    Arc::clone(&transactions),
                    &strategy,
                    round as u64 + 6,
                )
                .await,
            );
            production.push(
                verify(
                    &production_cache,
                    transactions,
                    &strategy,
                    round as u64 + 6,
                )
                .await,
            );
        }
        production.sort_unstable();
        prepared.sort_unstable();
        direct_backend.sort_unstable();
        let production_median = production[production.len() / 2];
        let production_best = production[0];
        let prepared_median = prepared[prepared.len() / 2];
        let direct_backend_median = direct_backend[direct_backend.len() / 2];
        println!(
            "production_cache_entries={} prepared_cache_entries={} production_median_ms={:.3} production_best_ms={:.3} production_median_tps={:.0} prepared_median_ms={:.3} prepared_median_tps={:.0} direct_backend_median_ms={:.3} direct_backend_median_tps={:.0}",
            production_cache.len(),
            prepared_cache.len(),
            production_median.as_secs_f64() * 1_000.0,
            production_best.as_secs_f64() * 1_000.0,
            count as f64 / production_median.as_secs_f64(),
            prepared_median.as_secs_f64() * 1_000.0,
            count as f64 / prepared_median.as_secs_f64(),
            direct_backend_median.as_secs_f64() * 1_000.0,
            count as f64 / direct_backend_median.as_secs_f64(),
        );
    });
}
