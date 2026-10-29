//! Measures block-body signature verification as consensus runs it: force the
//! lazily encoded body to decode on the strategy, then verify every signature
//! with all Ed25519 signatures in one randomized batch.
//!
//! Shapes cover distinct senders at increasing block sizes, heavy sender reuse,
//! and a body mixing Ed25519 with WebAuthn (secp256r1) senders. Each shape runs
//! against a warm public key cache (shared across iterations) and a cold one
//! (fresh per iteration). Fixture generation, body decoding into fresh lazy
//! transactions, and cache construction are not timed.

use bytes::{Buf as _, Bytes};
use commonware_allocator::mimalloc::{Config, MiMalloc, Purge, Reserve};
use commonware_codec::{Copying, DecodeExt as _, Encode as _, Read as _, ReadExt as _};
use commonware_cryptography::{Hasher as _, Signer as _, secp256r1::standard as secp256r1, sha256};
use commonware_cryptography_curve25519::signing as ed25519;
use commonware_parallel::Rayon;
use commonware_runtime::{Runner as _, deterministic};
use commonware_utils::{NZUsize, test_rng};
use constantinople_primitives::{
    LazySignedTransaction, PublicKeyCache, Sealable as _, SignedTransaction, Transaction,
    TransactionPublicKey, TransactionSignature, preload_transaction_slice,
    verify_transaction_batch,
};
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use p256::{
    ecdsa::{SigningKey, signature::Signer as _},
    elliptic_curve::Generate as _,
};
use std::{hint::black_box, num::NonZeroU64, time::Duration};

#[global_allocator]
static ALLOC: MiMalloc = MiMalloc::new(Config {
    purge: Purge::After(Duration::from_secs(10)),
    reserve: Some(Reserve::pinned(2 << 30)),
    ..Config::DEFAULT
});

type TestHasher = sha256::Sha256;
type Ed25519Signer = ed25519::SigningKey;

const NAMESPACE: &[u8] = b"verify-bench";
const WORKERS: usize = 8;
const CACHE_CAPACITY: usize = 100_000;

struct Shape {
    name: &'static str,
    ed25519_transactions: usize,
    ed25519_signers: usize,
    secp256r1_transactions: usize,
}

const SHAPES: &[Shape] = &[
    Shape {
        name: "distinct_1k",
        ed25519_transactions: 1_000,
        ed25519_signers: 1_000,
        secp256r1_transactions: 0,
    },
    Shape {
        name: "distinct_10k",
        ed25519_transactions: 10_000,
        ed25519_signers: 10_000,
        secp256r1_transactions: 0,
    },
    Shape {
        name: "distinct_50k",
        ed25519_transactions: 50_000,
        ed25519_signers: 50_000,
        secp256r1_transactions: 0,
    },
    Shape {
        name: "reuse_10k_16_signers",
        ed25519_transactions: 10_000,
        ed25519_signers: 16,
        secp256r1_transactions: 0,
    },
    Shape {
        name: "mixed_1k_16_webauthn",
        ed25519_transactions: 1_000,
        ed25519_signers: 1_000,
        secp256r1_transactions: 16,
    },
];

fn unsigned(sender: TransactionPublicKey, nonce: u64) -> Transaction<sha256::Digest> {
    Transaction::new(
        sender.clone(),
        sender,
        NonZeroU64::new(1).expect("bench value must be non-zero"),
        nonce,
    )
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let word = chunk.iter().enumerate().fold(0u32, |word, (i, byte)| {
            word | u32::from(*byte) << (16 - 8 * i)
        });
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(word >> (18 - 6 * i) & 0x3f) as usize] as char);
        }
    }
    out
}

fn webauthn_transaction(signer: &SigningKey, nonce: u64) -> SignedTransaction<TestHasher> {
    let sender = TransactionPublicKey::secp256r1(
        secp256r1::PublicKey::decode(Copying(
            signer.verifying_key().to_sec1_point(true).as_bytes(),
        ))
        .expect("compressed SEC1 key"),
    );
    let sealed = unsigned(sender, nonce).seal(&mut TestHasher::default());
    let mut authenticator_data = vec![0; 37];
    authenticator_data[32] = 0x04;
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}"}}"#,
        base64_url_no_pad(sealed.seal().as_ref())
    )
    .into_bytes();
    let mut payload = authenticator_data.clone();
    payload.extend_from_slice(TestHasher::hash(&[client_data_json.as_ref()]).as_ref());
    let signature: p256::ecdsa::Signature = signer.sign(&payload);
    let signature =
        secp256r1::Signature::decode(Copying(signature.normalize_s().to_bytes().as_slice()))
            .expect("fixed-size signature");
    let signature =
        TransactionSignature::secp256r1(signature, authenticator_data, client_data_json)
            .expect("assertion fits");
    SignedTransaction::new_unchecked(sealed, signature)
}

/// Encodes the shape's block body as lazily decoded transactions are framed in
/// a block.
fn encoded_body(shape: &Shape) -> Bytes {
    let signers: Vec<Ed25519Signer> = (0..shape.ed25519_signers as u64)
        .map(Ed25519Signer::from_seed)
        .collect();
    let mut transactions: Vec<_> =
        (0..shape.ed25519_transactions)
            .map(|i| {
                let signer = &signers[i % signers.len()];
                unsigned(TransactionPublicKey::ed25519(signer.public_key()), i as u64)
                    .seal_and_sign(signer, NAMESPACE, &mut TestHasher::default())
            })
            .collect();
    let mut rng = test_rng();
    for i in 0..shape.secp256r1_transactions {
        let signer = SigningKey::generate_from_rng(&mut rng);
        let position = (i + 1) * transactions.len() / (shape.secp256r1_transactions + 1);
        transactions.insert(position, webauthn_transaction(&signer, i as u64));
    }
    transactions
        .into_iter()
        .map(LazySignedTransaction::new)
        .collect::<Vec<_>>()
        .encode()
}

/// Decodes a fresh body whose transactions have not been decoded yet.
fn decode_body(encoded: &Bytes) -> Vec<LazySignedTransaction<TestHasher>> {
    let mut buf = encoded.clone();
    let len = usize::read_cfg(&mut buf, &commonware_codec::RangeCfg::new(..))
        .expect("body length prefix");
    let body: Vec<_> = (0..len)
        .map(|_| LazySignedTransaction::read(&mut buf).expect("bench transaction must frame"))
        .collect();
    assert!(!buf.has_remaining());
    body
}

fn new_cache() -> PublicKeyCache {
    deterministic::Runner::default()
        .start(|context| async move { PublicKeyCache::new(context, NZUsize!(CACHE_CAPACITY)) })
}

fn verify(cache: &PublicKeyCache, body: &[LazySignedTransaction<TestHasher>], strategy: &Rayon) {
    let valid = preload_transaction_slice(body, strategy)
        && verify_transaction_batch(NAMESPACE, &mut test_rng(), cache, body, strategy);
    assert!(black_box(valid));
}

fn bench(c: &mut Criterion) {
    let strategy = Rayon::new(NZUsize!(WORKERS)).expect("rayon pool");
    let mut group = c.benchmark_group("verify");
    group.sample_size(10);
    for shape in SHAPES {
        let encoded = encoded_body(shape);
        let transactions = shape.ed25519_transactions + shape.secp256r1_transactions;
        group.throughput(Throughput::Elements(transactions as u64));

        let warm = new_cache();
        verify(&warm, &decode_body(&encoded), &strategy);
        group.bench_function(BenchmarkId::new(shape.name, "warm"), |b| {
            b.iter_batched(
                || decode_body(&encoded),
                |body| verify(&warm, &body, &strategy),
                BatchSize::PerIteration,
            );
        });
        group.bench_function(BenchmarkId::new(shape.name, "cold"), |b| {
            b.iter_batched(
                || (new_cache(), decode_body(&encoded)),
                |(cache, body)| verify(&cache, &body, &strategy),
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
