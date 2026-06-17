//! Cache of decompressed transaction public keys for signature verification.

use crate::TransactionPublicKey;
use commonware_codec::{FixedSize as _, ReadExt as _};
use commonware_cryptography::{ed25519, secp256r1::standard as secp256r1};
use commonware_runtime::{
    Metrics,
    telemetry::metrics::{Counter, MetricsExt as _},
};
use commonware_utils::{cache::Clock, sync::RwLock};
use core::num::NonZeroUsize;
use p256::ecdsa::VerifyingKey;
use std::sync::Arc;

/// A public key decompressed into the form used by signature verification.
///
/// Both schemes store a compressed point on the wire. Recovering the affine
/// point (an Edwards point for Ed25519, the SEC1 `y` coordinate for secp256r1)
/// requires curve arithmetic that dominates per-signature verification cost.
#[derive(Clone)]
pub enum DecompressedPublicKey {
    /// A decompressed Ed25519 verification key.
    Ed25519(ed25519::PublicKey),
    /// A decompressed secp256r1 verifying key.
    Secp256r1(VerifyingKey),
}

/// A shared, fixed-capacity cache mapping a [`TransactionPublicKey`] to its
/// [`DecompressedPublicKey`].
///
/// The same sender's key recurs across mempool ingest and consensus
/// verification of every transaction it submits, so caching the decompression
/// is a large win for active accounts. A single instance is shared across the
/// mempool and consensus verification paths.
///
/// Cloning shares the underlying cache. Lookups take a shared read lock and run
/// concurrently on the hit path; only misses take the write lock to install the
/// computed key.
#[derive(Clone)]
pub struct PublicKeyCache {
    inner: Arc<RwLock<Clock<TransactionPublicKey, DecompressedPublicKey>>>,
    /// Cache-miss counter. Only misses are counted: a miss already holds the
    /// write lock, so the counter is contention-free, whereas a per-hit counter
    /// would be a shared atomic hit by every parallel verification shard. A miss
    /// rate of ~0 confirms the cache is effective.
    misses: Counter,
}

impl PublicKeyCache {
    /// Creates a cache holding at most `capacity` decompressed keys, registering
    /// its miss counter on the runtime metrics `context`.
    pub fn new(context: impl Metrics, capacity: NonZeroUsize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Clock::new(capacity))),
            misses: context.counter("misses", "Decompressed public key cache misses"),
        }
    }

    /// Returns the decompressed key for `key`, computing and caching it on a
    /// miss. Returns `None` if `key` does not encode a valid curve point.
    ///
    /// The hit path takes only a shared read lock, so concurrent verification
    /// shards look keys up in parallel. The read lock is released before the
    /// caller uses the returned key, so the expensive per-signature work never
    /// runs under the lock.
    pub fn decompress(&self, key: &TransactionPublicKey) -> Option<DecompressedPublicKey> {
        if let Some(decompressed) = self.inner.read().get(key).cloned() {
            return Some(decompressed);
        }
        let decompressed = Self::decompress_uncached(key)?;
        self.misses.inc();
        self.inner.write().put(key.clone(), decompressed.clone());
        Some(decompressed)
    }

    /// Decompresses `key` without consulting or populating the cache.
    fn decompress_uncached(key: &TransactionPublicKey) -> Option<DecompressedPublicKey> {
        match key {
            TransactionPublicKey::Ed25519 { .. } => {
                let bytes = &key.as_ref()[1..1 + ed25519::PublicKey::SIZE];
                let parsed = ed25519::PublicKey::read(&mut &bytes[..]).ok()?;
                Some(DecompressedPublicKey::Ed25519(parsed))
            }
            TransactionPublicKey::Secp256r1 { .. } => {
                let bytes = &key.as_ref()[1..1 + secp256r1::PublicKey::SIZE];
                let parsed = VerifyingKey::from_sec1_bytes(bytes).ok()?;
                Some(DecompressedPublicKey::Secp256r1(parsed))
            }
        }
    }

    /// Returns the maximum number of keys the cache can hold.
    pub fn capacity(&self) -> usize {
        self.inner.read().capacity()
    }

    /// Returns the number of keys currently cached.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Returns `true` if the cache holds no keys.
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }

    /// Returns `true` if `key` is currently cached.
    pub fn contains(&self, key: &TransactionPublicKey) -> bool {
        self.inner.read().contains(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode as _;
    use commonware_cryptography::{Signer as _, ed25519, secp256r1::standard as secp256r1};
    use commonware_math::algebra::Random as _;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::{NZUsize, test_rng};

    fn ed25519_key(seed: u64) -> TransactionPublicKey {
        let mut rng = test_rng();
        for _ in 0..seed {
            let _ = ed25519::PrivateKey::random(&mut rng);
        }
        TransactionPublicKey::ed25519(ed25519::PrivateKey::random(&mut rng).public_key())
    }

    fn secp256r1_key(seed: u64) -> TransactionPublicKey {
        let mut rng = test_rng();
        for _ in 0..seed {
            let _ = secp256r1::PrivateKey::random(&mut rng);
        }
        TransactionPublicKey::secp256r1(secp256r1::PrivateKey::random(&mut rng).public_key())
    }

    #[test]
    fn ed25519_decompress_matches_direct_and_caches() {
        deterministic::Runner::default().start(|context| async move {
            let cache = PublicKeyCache::new(context, NZUsize!(4));
            let key = ed25519_key(0);
            assert!(cache.is_empty());

            let DecompressedPublicKey::Ed25519(decompressed) =
                cache.decompress(&key).expect("valid key decompresses")
            else {
                panic!("ed25519 key should decompress to ed25519");
            };
            let expected =
                ed25519::PublicKey::read(&mut &key.as_ref()[1..1 + ed25519::PublicKey::SIZE])
                    .unwrap();
            assert_eq!(decompressed, expected);
            assert_eq!(cache.len(), 1);
            assert!(cache.contains(&key));

            // Hit path: no growth.
            assert!(cache.decompress(&key).is_some());
            assert_eq!(cache.len(), 1);
        });
    }

    #[test]
    fn secp256r1_decompress_matches_direct_and_caches() {
        deterministic::Runner::default().start(|context| async move {
            let cache = PublicKeyCache::new(context, NZUsize!(4));
            let key = secp256r1_key(0);

            let DecompressedPublicKey::Secp256r1(decompressed) =
                cache.decompress(&key).expect("valid key decompresses")
            else {
                panic!("secp256r1 key should decompress to secp256r1");
            };
            let expected =
                VerifyingKey::from_sec1_bytes(&key.as_ref()[1..1 + secp256r1::PublicKey::SIZE])
                    .unwrap();
            assert_eq!(decompressed, expected);
            assert_eq!(cache.len(), 1);
            assert!(cache.contains(&key));

            assert!(cache.decompress(&key).is_some());
            assert_eq!(cache.len(), 1);
        });
    }

    #[test]
    fn caches_both_schemes_together() {
        deterministic::Runner::default().start(|context| async move {
            let cache = PublicKeyCache::new(context, NZUsize!(8));
            let ed = ed25519_key(0);
            let r1 = secp256r1_key(0);

            assert!(matches!(
                cache.decompress(&ed),
                Some(DecompressedPublicKey::Ed25519(_))
            ));
            assert!(matches!(
                cache.decompress(&r1),
                Some(DecompressedPublicKey::Secp256r1(_))
            ));
            assert_eq!(cache.len(), 2);
            assert!(cache.contains(&ed));
            assert!(cache.contains(&r1));
        });
    }

    #[test]
    fn respects_capacity_via_eviction() {
        deterministic::Runner::default().start(|context| async move {
            let cache = PublicKeyCache::new(context, NZUsize!(1));
            let key_a = ed25519_key(0);
            let key_b = ed25519_key(1);
            assert_ne!(key_a, key_b);

            assert!(cache.decompress(&key_a).is_some());
            assert!(cache.decompress(&key_b).is_some());
            assert_eq!(cache.len(), 1);
            assert!(cache.contains(&key_b));
            assert!(!cache.contains(&key_a));
        });
    }

    #[test]
    fn rejects_invalid_point_and_does_not_cache() {
        deterministic::Runner::default().start(|context| async move {
            let cache = PublicKeyCache::new(context, NZUsize!(4));

            // A secp256r1 transaction key that decodes structurally but whose
            // bytes are not a curve point: decode accepts it, so decompression
            // rejects it.
            let valid = secp256r1_key(0);
            let mut encoded = valid.encode().to_vec();
            // Corrupt the x-coordinate so no matching y exists for most values.
            for byte in encoded.iter_mut().skip(1) {
                *byte = 0xff;
            }
            let key = TransactionPublicKey::read(&mut &encoded[..])
                .expect("decode no longer validates the point");
            assert_eq!(encoded.len(), TransactionPublicKey::SIZE);

            assert!(cache.decompress(&key).is_none());
            assert!(cache.is_empty());
        });
    }

    #[test]
    fn registers_and_counts_misses() {
        deterministic::Runner::default().start(|context| async move {
            let cache = PublicKeyCache::new(context.child("public_key_cache"), NZUsize!(4));
            let key = ed25519_key(0);
            assert!(cache.decompress(&key).is_some()); // miss
            assert!(cache.decompress(&key).is_some()); // hit (not counted)
            assert!(cache.decompress(&key).is_some()); // hit (not counted)

            let encoded = context.encode();
            assert!(
                encoded.contains("public_key_cache_misses_total 1"),
                "missing miss count:\n{encoded}"
            );
        });
    }
}
