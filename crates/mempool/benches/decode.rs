//! Measures `Vec::<SignedTransaction>::decode_cfg` on realistic relayer batch
//! sizes. This is the ingress decode that `verify_body` runs on the strategy's
//! worker pool: at production batch sizes it is milliseconds of CPU work
//! (dominated by per-transaction seal hashing), too much to run inline on a
//! core tokio worker.

use commonware_codec::{Decode as _, Encode as _, RangeCfg};
use commonware_cryptography::{Signer as _, ed25519, sha256};
use constantinople_primitives::{SignedTransaction, Transaction, TransactionPublicKey};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::num::NonZeroU64;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

type TestHasher = sha256::Sha256;

const NAMESPACE: &[u8] = b"decode-bench";
const TRANSACTION_COUNTS: &[usize] = &[2048, 32_768];
const SIGNERS: usize = 1024;

/// Signs `n` transactions and encodes them as one length-prefixed batch, the
/// wire format relayers post to the ingress endpoints.
fn encoded_batch(n: usize) -> bytes::Bytes {
    let signers: Vec<ed25519::PrivateKey> = (0..SIGNERS as u64)
        .map(ed25519::PrivateKey::from_seed)
        .collect();
    (0..n)
        .map(|i| {
            let sender = &signers[i % SIGNERS];
            let recipient = signers[(i + 1) % SIGNERS].public_key();
            Transaction::new(
                TransactionPublicKey::ed25519(sender.public_key()),
                TransactionPublicKey::ed25519(recipient),
                NonZeroU64::new(1).expect("bench value must be non-zero"),
                i as u64,
            )
            .seal_and_sign(sender, NAMESPACE, &mut TestHasher::default())
        })
        .collect::<Vec<SignedTransaction<TestHasher>>>()
        .encode()
}

fn decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode");

    for &n in TRANSACTION_COUNTS {
        group.throughput(Throughput::Elements(n as u64));
        let encoded = encoded_batch(n);
        let cfg = (RangeCfg::new(1..=n), ());
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |bencher, _| {
            bencher.iter_with_large_drop(|| {
                Vec::<SignedTransaction<TestHasher>>::decode_cfg(encoded.as_ref(), &cfg)
                    .expect("bench batch must decode")
            });
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = decode
}
criterion_main!(benches);
