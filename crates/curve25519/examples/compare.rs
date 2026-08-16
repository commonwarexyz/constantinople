//! Compares the pinned Commonware Ed25519 verifier with the vendored backend.

use commonware_codec::ReadExt as _;
use commonware_cryptography::{BatchVerifier as _, Signer as _, ed25519};
use commonware_parallel::Rayon;
use commonware_utils::TestRng;
use constantinople_curve25519::{
    backend_name,
    signing::{BatchVerifier, Signature, VerifyingKey},
};
use std::{
    num::NonZeroUsize,
    time::{Duration, Instant},
};

const NAMESPACE: &[u8] = b"constantinople-tx";

struct Fixture {
    old_key: ed25519::PublicKey,
    old_signature: ed25519::Signature,
    new_key: VerifyingKey,
    new_signature: Signature,
    message: [u8; 32],
}

fn fixtures(count: usize, unique_keys: usize) -> Vec<Fixture> {
    (0..count)
        .map(|index| {
            let signer = ed25519::PrivateKey::from_seed((index % unique_keys) as u64);
            let old_key = signer.public_key();
            let mut message = [0; 32];
            message[..8].copy_from_slice(&(index as u64).to_le_bytes());
            let old_signature = signer.sign(NAMESPACE, &message);
            let new_key = VerifyingKey::read(&mut &old_key.as_ref()[..])
                .expect("Commonware public key must use the Ed25519 wire encoding");
            let new_signature = Signature::read(&mut &old_signature.as_ref()[..])
                .expect("Commonware signature must use the Ed25519 wire encoding");
            Fixture {
                old_key,
                old_signature,
                new_key,
                new_signature,
                message,
            }
        })
        .collect()
}

fn run_old(fixtures: &[Fixture], strategy: &Rayon, seed: u64) -> Duration {
    let started = Instant::now();
    let mut verifier = ed25519::Batch::new(fixtures.len());
    for fixture in fixtures {
        assert!(verifier.add(
            NAMESPACE,
            &fixture.message,
            &fixture.old_key,
            &fixture.old_signature,
        ));
    }
    assert!(verifier.verify(&mut TestRng::new(seed), strategy));
    started.elapsed()
}

fn run_new(fixtures: &[Fixture], keys: &[VerifyingKey], strategy: &Rayon, seed: u64) -> Duration {
    let started = Instant::now();
    let mut verifier = BatchVerifier::new(fixtures.len());
    for (fixture, key) in fixtures.iter().zip(keys) {
        verifier.add(NAMESPACE, &fixture.message, key, &fixture.new_signature);
    }
    assert!(verifier.verify(&mut TestRng::new(seed), strategy));
    started.elapsed()
}

fn report(name: &str, count: usize, mut samples: Vec<Duration>) -> f64 {
    samples.sort_unstable();
    let median = samples[samples.len() / 2].as_secs_f64();
    let best = samples[0].as_secs_f64();
    let median_tps = count as f64 / median;
    println!(
        "backend={name} median_ms={:.3} best_ms={:.3} median_tps={median_tps:.0}",
        median * 1_000.0,
        best * 1_000.0,
    );
    median_tps
}

fn argument(index: usize, default: usize) -> usize {
    std::env::args()
        .nth(index)
        .map(|value| value.parse().expect("arguments must be positive integers"))
        .unwrap_or(default)
}

fn main() {
    let count = argument(1, 50_000);
    let rounds = argument(2, 7);
    let threads = argument(3, 13);
    let unique_keys = argument(4, count);
    assert!(count > 0, "signature count must be positive");
    assert!(rounds > 0, "round count must be positive");
    assert!(unique_keys > 0, "unique key count must be positive");
    let threads = NonZeroUsize::new(threads).expect("thread count must be positive");
    let strategy = Rayon::new(threads).expect("Rayon pool must start");

    println!(
        "backend={} generating {count} signatures across {unique_keys} keys; rounds={rounds} threads={threads}",
        backend_name(),
    );
    let fixtures = fixtures(count, unique_keys);
    let raw_keys: Vec<_> = fixtures
        .iter()
        .map(|fixture| fixture.new_key.clone())
        .collect();
    let prepared_keys = VerifyingKey::prepare_batch(raw_keys.clone(), &strategy)
        .expect("fixture keys must decompress");

    // Warm both paths and the adaptive policy before recording samples.
    let _ = run_old(&fixtures, &strategy, 0);
    let _ = run_new(&fixtures, &raw_keys, &strategy, 0);
    let _ = run_new(&fixtures, &prepared_keys, &strategy, 0);

    let mut old = Vec::with_capacity(rounds);
    let mut raw = Vec::with_capacity(rounds);
    let mut prepared = Vec::with_capacity(rounds);
    for round in 0..rounds {
        let seed = round as u64 + 1;
        match round % 3 {
            0 => {
                old.push(run_old(&fixtures, &strategy, seed));
                raw.push(run_new(&fixtures, &raw_keys, &strategy, seed));
                prepared.push(run_new(&fixtures, &prepared_keys, &strategy, seed));
            }
            1 => {
                raw.push(run_new(&fixtures, &raw_keys, &strategy, seed));
                prepared.push(run_new(&fixtures, &prepared_keys, &strategy, seed));
                old.push(run_old(&fixtures, &strategy, seed));
            }
            _ => {
                prepared.push(run_new(&fixtures, &prepared_keys, &strategy, seed));
                old.push(run_old(&fixtures, &strategy, seed));
                raw.push(run_new(&fixtures, &raw_keys, &strategy, seed));
            }
        }
    }

    let old_tps = report("pinned_commonware", count, old);
    let raw_tps = report("vendored_simd_raw", count, raw);
    let prepared_tps = report("vendored_simd_prepared", count, prepared);
    println!("raw_speedup={:.3}x", raw_tps / old_tps);
    println!("prepared_speedup={:.3}x", prepared_tps / old_tps);
}
