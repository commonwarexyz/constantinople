//! Constantinople spam bot binary.
//!
//! Generates deterministic accounts and submits ring-transfer transactions to
//! the relayer in a continuous loop.
//!
//! Each target gets its own independent account set. A local signer keeps one
//! batch ready while the submitter has one batch in flight, hiding signing
//! latency without queueing multiple batches at a proposer.

mod accounts;
mod cli;
mod config;
mod signer;
mod submitter;

use accounts::{SpamAccount, generate_accounts};
use clap::Parser;
use cli::Cli;
use commonware_runtime::{Runner as _, Supervisor as _, ThreadPooler as _, tokio::telemetry};
use commonware_utils::NZUsize;
use constantinople_primitives::DEFAULT_ACCOUNT_BALANCE;
use core::num::NonZeroU64;
use signer::{Tx, sign_batch};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Instant,
};
use submitter::{RelayerSubmitter, Stats};
use tokio::sync::mpsc;
use tracing::info;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    let cli = Cli::parse();

    // Load config file if provided (deployer mode); CLI defaults are used otherwise.
    let (
        accounts_count,
        value,
        seed_offset,
        relayer_url,
        relayer_submitters,
        presigned_batches,
        primary_validators,
        rayon_threads,
        accounts_jitter,
    ) = if let Some(config_path) = &cli.config {
        let cfg = config::load_config(config_path);
        let relayer_submitters = if cfg.relayer_submitters == 0 {
            cfg.primary_validators.len().max(1)
        } else {
            cfg.relayer_submitters
        };
        (
            cfg.accounts,
            cfg.value,
            cfg.seed_offset,
            config::resolve_named_http_url(&cfg.relayer_url, cli.hosts.as_deref()),
            relayer_submitters,
            cfg.presigned_batches,
            if cfg.primary_validators.is_empty() {
                cli.relayer_targets.clone()
            } else {
                cfg.primary_validators
            },
            cfg.rayon_threads,
            cfg.accounts_jitter,
        )
    } else {
        (
            cli.accounts,
            cli.value,
            cli.seed_offset,
            cli.relayer_url
                .clone()
                .expect("provide --relayer-url or --config"),
            cli.relayer_submitters.max(1),
            cli.presigned_batches,
            cli.relayer_targets.clone(),
            cli.rayon_threads,
            cli.accounts_jitter,
        )
    };
    assert!(
        (0.0..=1.0).contains(&accounts_jitter),
        "--accounts-jitter must be between 0 and 1"
    );
    assert!(presigned_batches > 0, "--presigned-batches must be > 0");

    // Validate parameters.
    assert!(accounts_count >= 2, "need at least 2 accounts for a ring");
    assert!(value > 0, "transfer value must be > 0");
    assert!(
        value <= DEFAULT_ACCOUNT_BALANCE,
        "transfer value ({value}) must be <= DEFAULT_ACCOUNT_BALANCE ({DEFAULT_ACCOUNT_BALANCE})"
    );
    let value = NonZeroU64::new(value).expect("checked above");

    let runtime_cfg = commonware_runtime::tokio::Config::default();
    let runner = commonware_runtime::tokio::Runner::new(runtime_cfg);

    runner.start(|context| async move {
        // In deployer mode (--hosts), use JSON logs so Loki/Promtail can scrape them.
        let json_logs = cli.hosts.is_some();
        telemetry::init(
            context.child("telemetry"),
            telemetry::Logs {
                level: tracing::Level::INFO,
                json: json_logs,
            },
            None,
            None,
        );

        let strategy = context
            .create_strategy(NZUsize!(rayon_threads))
            .expect("failed to create parallel strategy");

        let config = RelayerModeConfig {
            relayer_url,
            accounts_count,
            value,
            seed_offset,
            accounts_jitter,
            relayer_submitters,
            presigned_batches,
            relayer_targets: primary_validators,
        };
        run_relayer_mode(config, strategy).await;
    });
}

struct RelayerModeConfig {
    relayer_url: String,
    accounts_count: u32,
    value: NonZeroU64,
    seed_offset: u64,
    accounts_jitter: f64,
    relayer_submitters: usize,
    presigned_batches: usize,
    relayer_targets: Vec<String>,
}

async fn run_relayer_mode(
    config: RelayerModeConfig,
    strategy: impl commonware_parallel::Strategy + 'static,
) {
    let RelayerModeConfig {
        relayer_url,
        accounts_count,
        value,
        seed_offset,
        accounts_jitter,
        relayer_submitters,
        presigned_batches,
        relayer_targets,
    } = config;

    info!(
        submitters = relayer_submitters,
        accounts = accounts_count,
        value = value.get(),
        seed_offset,
        accounts_jitter,
        %relayer_url,
        presigned_batches,
        "starting spammer relayer mode"
    );

    let stats = Arc::new(Stats::new());
    let start = Instant::now();

    for index in 0..relayer_submitters {
        let account_offset = seed_offset + (index as u64) * u64::from(accounts_count);
        let accounts = generate_accounts(accounts_count, account_offset);
        let target = relayer_target_for(&relayer_targets, index);
        let submitter = RelayerSubmitter::new(relayer_url.clone(), stats.clone(), index, target);
        let strategy = strategy.clone();
        let batches = spawn_presigner(
            strategy,
            accounts,
            value,
            accounts_jitter,
            account_offset,
            presigned_batches,
        );
        tokio::spawn(submit_presigned_batches(submitter, batches));
    }

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    loop {
        interval.tick().await;
        let finalized = stats.finalized.load(Ordering::Relaxed);
        let filtered = stats.filtered.load(Ordering::Relaxed);
        let dropped = stats.dropped.load(Ordering::Relaxed);
        let errors = stats.errors.load(Ordering::Relaxed);
        let elapsed = start.elapsed().as_secs_f64();
        let tps = if elapsed > 0.0 {
            finalized as f64 / elapsed
        } else {
            0.0
        };
        info!(
            finalized,
            filtered,
            dropped,
            errors,
            tps = format!("{tps:.0}"),
            elapsed_s = format!("{elapsed:.1}"),
            "progress"
        );
    }
}

fn spawn_presigner<St>(
    strategy: St,
    accounts: Vec<SpamAccount>,
    value: NonZeroU64,
    accounts_jitter: f64,
    account_offset: u64,
    presigned_batches: usize,
) -> mpsc::Receiver<Vec<Tx>>
where
    St: commonware_parallel::Strategy + Send + 'static,
{
    let (sender, receiver) = mpsc::channel(presigned_batches);
    // Keep the synchronous producer and bounded-channel backpressure off Tokio
    // worker threads; `sign_batch` uses the shared Rayon strategy for CPU parallelism.
    tokio::task::spawn_blocking(move || {
        let mut rng = JitterRng::new(account_offset.wrapping_add(1));
        let mut nonces = vec![0; accounts.len()];
        let mut cursor = 0;

        loop {
            let batch_size = jittered_batch_size(accounts.len(), accounts_jitter, &mut rng);
            let batch = sign_batch(
                &strategy,
                &accounts,
                value,
                &mut nonces,
                &mut cursor,
                batch_size,
            );
            if sender.blocking_send(batch).is_err() {
                return;
            }
        }
    });
    receiver
}

async fn submit_presigned_batches(
    submitter: RelayerSubmitter,
    mut batches: mpsc::Receiver<Vec<Tx>>,
) {
    while let Some(batch) = batches.recv().await {
        submitter.submit(batch).await;
    }
}

fn jittered_batch_size(accounts: usize, accounts_jitter: f64, rng: &mut JitterRng) -> usize {
    let extra = max_extra_accounts(accounts, accounts_jitter);
    if extra == 0 {
        return accounts;
    }
    accounts.saturating_add(rng.range(0, extra))
}

fn max_extra_accounts(accounts: usize, accounts_jitter: f64) -> usize {
    (accounts as f64 * accounts_jitter).floor() as usize
}

fn relayer_target_for(targets: &[String], index: usize) -> Option<String> {
    if targets.is_empty() {
        return None;
    }

    targets.get(index % targets.len()).cloned()
}

/// Tiny inline xorshift64 used to jitter per-batch sizes. We don't pull
/// `rand` in here because we only need a few bits per submission and the
/// statistical quality of xorshift is more than sufficient for visual block
/// size variance.
struct JitterRng {
    state: u64,
}

impl JitterRng {
    /// `seed` of zero would lock the generator; we map it to a non-zero value.
    const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
        }
    }

    const fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Uniform integer in `lo..=hi` (inclusive). Caller must pass `lo <= hi`.
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        debug_assert!(lo <= hi);
        let span = (hi - lo) as u64 + 1;
        lo + (self.next_u64() % span) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::{
        JitterRng, jittered_batch_size, max_extra_accounts, relayer_target_for, spawn_presigner,
    };
    use crate::accounts::generate_accounts;
    use commonware_parallel::Sequential;
    use core::num::NonZeroU64;
    use std::time::Duration;

    /// `range` must hit both endpoints over enough draws and never escape them.
    #[test]
    fn jitter_rng_range_is_inclusive_and_bounded() {
        let mut rng = JitterRng::new(42);
        let mut hit_lo = false;
        let mut hit_hi = false;
        for _ in 0..2_000 {
            let v = rng.range(1, 5);
            assert!((1..=5).contains(&v));
            if v == 1 {
                hit_lo = true;
            }
            if v == 5 {
                hit_hi = true;
            }
        }
        assert!(hit_lo, "should sample the lower bound");
        assert!(hit_hi, "should sample the upper bound");
    }

    /// `range(lo, lo)` collapses to the constant `lo`.
    #[test]
    fn jitter_rng_range_collapses_when_lo_equals_hi() {
        let mut rng = JitterRng::new(7);
        for _ in 0..32 {
            assert_eq!(rng.range(3, 3), 3);
        }
    }

    #[test]
    fn max_extra_accounts_uses_fractional_jitter() {
        assert_eq!(max_extra_accounts(100, 0.0), 0);
        assert_eq!(max_extra_accounts(100, 0.25), 25);
        assert_eq!(max_extra_accounts(3, 0.5), 1);
        assert_eq!(max_extra_accounts(10, 1.0), 10);
    }

    #[test]
    fn jittered_batch_size_only_adds_transactions() {
        let mut rng = JitterRng::new(42);
        let mut saw_base = false;
        let mut saw_max = false;

        for _ in 0..2_000 {
            let size = jittered_batch_size(10, 0.5, &mut rng);
            assert!((10..=15).contains(&size));
            if size == 10 {
                saw_base = true;
            }
            if size == 15 {
                saw_max = true;
            }
        }

        assert!(saw_base, "should sample the base account count");
        assert!(saw_max, "should sample the upper jitter bound");
    }

    #[test]
    fn relayer_targets_are_selected_by_submitter_index() {
        let targets = vec!["primary-0".to_string(), "primary-1".to_string()];

        assert_eq!(
            relayer_target_for(&targets, 0).as_deref(),
            Some("primary-0")
        );
        assert_eq!(
            relayer_target_for(&targets, 1).as_deref(),
            Some("primary-1")
        );
        assert_eq!(
            relayer_target_for(&targets, 2).as_deref(),
            Some("primary-0")
        );
        assert!(relayer_target_for(&[], 0).is_none());
    }

    #[tokio::test]
    async fn presigner_keeps_one_batch_ready_without_unbounded_local_queue() {
        let accounts = generate_accounts(3, 1000);
        let value = NonZeroU64::new(1).expect("non-zero value");
        let presigned_batches = 4;
        let mut batches =
            spawn_presigner(Sequential, accounts, value, 0.0, 1000, presigned_batches);

        let first = batches.recv().await.expect("first batch should be signed");
        assert_eq!(batch_nonces(&first), vec![0, 0, 0]);

        wait_for_presigned_batches(&batches, presigned_batches).await;
        assert_eq!(batches.len(), presigned_batches);

        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(batches.len(), presigned_batches);

        let second = batches.recv().await.expect("second batch should be ready");
        assert_eq!(batch_nonces(&second), vec![1, 1, 1]);
    }

    async fn wait_for_presigned_batches(
        batches: &tokio::sync::mpsc::Receiver<Vec<super::Tx>>,
        expected: usize,
    ) {
        for _ in 0..50 {
            if batches.len() == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("presigner did not fill the local queue");
    }

    fn batch_nonces(batch: &[super::Tx]) -> Vec<u64> {
        batch
            .iter()
            .map(|transaction| transaction.value().nonce)
            .collect()
    }
}
