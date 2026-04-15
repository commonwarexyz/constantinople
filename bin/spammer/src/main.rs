//! Constantinople spam bot binary.
//!
//! Generates deterministic accounts and submits ring-transfer transactions to
//! validator mempool endpoints in a continuous loop.
//!
//! Each validator gets its own independent set of accounts and runs a
//! sequential submission loop: sign one round, submit, wait for full
//! finalization, then sign and submit the next round. This guarantees
//! nonce ordering and eliminates cascading failures.

mod accounts;
mod cli;
mod config;
mod signer;
mod submitter;

use accounts::generate_accounts;
use clap::Parser;
use cli::Cli;
use commonware_runtime::{Metrics as _, Runner as _, ThreadPooler as _, tokio::telemetry};
use commonware_utils::NZUsize;
use constantinople_primitives::DEFAULT_ACCOUNT_BALANCE;
use core::num::NonZeroU64;
use signer::sign_rounds;
use std::{
    sync::{Arc, atomic::Ordering},
    time::Instant,
};
use submitter::{Stats, ValidatorSubmitter};
use tracing::info;

fn main() {
    let cli = Cli::parse();

    // Load config file if provided (deployer mode); CLI defaults are used otherwise.
    let (accounts_count, value, seed_offset, http_port) = if let Some(config_path) = &cli.config {
        let cfg = config::load_config(config_path);
        (cfg.accounts, cfg.value, cfg.seed_offset, cfg.http_port)
    } else {
        (cli.accounts, cli.value, cli.seed_offset, cli.http_port)
    };

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
            context.with_label("telemetry"),
            telemetry::Logging {
                level: tracing::Level::INFO,
                json: json_logs,
            },
            None,
            None,
        );

        let strategy = context
            .clone()
            .create_strategy(NZUsize!(cli.rayon_threads))
            .expect("failed to create parallel strategy");

        // Discover validator endpoints.
        let clients = if let Some(peers_path) = &cli.peers {
            config::clients_from_peers(peers_path)
        } else {
            let hosts_path = cli.hosts.as_ref().expect("clap ensures --peers or --hosts");
            config::clients_from_hosts(hosts_path, http_port)
        };
        let num_validators = clients.len();
        assert!(num_validators > 0, "no validator endpoints discovered");

        // Generate a separate set of accounts per validator.
        let accounts_per_validator: Vec<_> = (0..num_validators)
            .map(|v| {
                let offset = seed_offset + (v as u64) * u64::from(accounts_count);
                generate_accounts(accounts_count, offset)
            })
            .collect();

        info!(
            validators = num_validators,
            accounts_per_validator = accounts_count,
            value = value.get(),
            seed_offset,
            "starting spammer (continuous mode)"
        );

        // Shared stats for progress reporting.
        let stats = Arc::new(Stats::new());
        let start = Instant::now();

        // Spawn per-validator sequential submission loops.
        for (i, (client, accounts)) in clients.into_iter().zip(accounts_per_validator).enumerate() {
            let strategy = strategy.clone();
            let stats = stats.clone();
            tokio::spawn(async move {
                let submitter = ValidatorSubmitter::new(client, stats, i);
                let mut round = 0u64;
                loop {
                    // Sign one round: n txs, one per account, all at nonce = round.
                    let batch = sign_rounds(&strategy, &accounts, value, round, 1);
                    round += 1;

                    // Submit and block until every tx is finalized.
                    submitter.submit_until_finalized(batch).await;
                }
            });
        }

        // Progress reporter runs forever.
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            let finalized = stats.finalized.load(Ordering::Relaxed);
            let filtered = stats.filtered.load(Ordering::Relaxed);
            let dropped = stats.dropped.load(Ordering::Relaxed);
            let retried = stats.retried.load(Ordering::Relaxed);
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
                retried,
                errors,
                tps = format!("{tps:.0}"),
                elapsed_s = format!("{elapsed:.1}"),
                "progress"
            );
        }
    });
}
