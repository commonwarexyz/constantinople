//! Cache of decompressed transaction public keys for signature verification.

use crate::TransactionPublicKey;
use commonware_codec::{FixedSize as _, ReadExt as _};
use commonware_cryptography::{ed25519, secp256r1::standard as secp256r1};
use commonware_parallel::Strategy;
use commonware_runtime::{
    Metrics,
    telemetry::{
        metrics::{Counter, MetricsExt as _},
        traces::TracedExt as _,
    },
};
use commonware_utils::{cache::Clock, sync::RwLock};
use core::num::NonZeroUsize;
use p256::ecdsa::VerifyingKey;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// A public key decompressed into the form used by signature verification.
///
/// Both schemes store a compressed point on the wire. Recovering the affine
/// point (an Edwards point for Ed25519, the SEC1 `y` coordinate for secp256r1)
/// requires curve arithmetic that is a significant part of per-signature
/// verification cost.
#[derive(Clone)]
pub enum DecompressedPublicKey {
    /// A decompressed Ed25519 verification key.
    Ed25519(ed25519::PublicKey),
    /// A decompressed secp256r1 verifying key.
    Secp256r1(VerifyingKey),
}

/// A shared, fixed-capacity cache mapping a [`TransactionPublicKey`] to its
/// [`DecompressedPublicKey`].
#[derive(Clone)]
pub struct PublicKeyCache {
    inner: Arc<RwLock<Clock<TransactionPublicKey, DecompressedPublicKey>>>,
    misses: Counter,
}

impl PublicKeyCache {
    /// Creates a cache holding at most `capacity` decompressed keys.
    pub fn new(context: impl Metrics, capacity: NonZeroUsize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Clock::new(capacity))),
            misses: context.counter("misses", "Decompressed public key cache misses"),
        }
    }

    /// Resolves every key in `keys` to its decompressed form: hits share the
    /// read lock, misses are decompressed on `strategy` and inserted under a
    /// single write lock, so a miss-heavy batch pays neither serial curve
    /// arithmetic nor per-key lock traffic.
    ///
    /// Returns `None` if any key does not encode a valid curve point.
    pub fn decompress(
        &self,
        keys: &[&TransactionPublicKey],
        strategy: &impl Strategy,
    ) -> Option<Vec<DecompressedPublicKey>> {
        let span = tracing::info_span!(
            "primitives.public_key_cache.decompress",
            keys = keys.len().traced(),
            misses = tracing::field::Empty,
        );
        let _guard = span.enter();

        let missed = AtomicU64::new(0);
        let resolved: Vec<(DecompressedPublicKey, bool)> = strategy
            .try_map_collect_vec(keys, |&key| {
                if let Some(hit) = self.inner.read().get(key).cloned() {
                    return Ok((hit, false));
                }
                let decompressed = Self::decompress_uncached(key).ok_or(())?;
                missed.fetch_add(1, Ordering::Relaxed);
                Ok::<_, ()>((decompressed, true))
            })
            .ok()?;

        // Insert all misses under one write lock; a pure-hit batch never
        // takes it.
        let missed = missed.into_inner();
        span.record("misses", missed.traced());
        if missed > 0 {
            self.misses.inc_by(missed);
            let mut cache = self.inner.write();
            for (key, (decompressed, miss)) in keys.iter().zip(&resolved) {
                if *miss {
                    cache.put((*key).clone(), decompressed.clone());
                }
            }
        }

        Some(
            resolved
                .into_iter()
                .map(|(decompressed, _)| decompressed)
                .collect(),
        )
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

    fn decompress_one(
        cache: &PublicKeyCache,
        key: &TransactionPublicKey,
    ) -> Option<DecompressedPublicKey> {
        cache
            .decompress(&[key], &commonware_parallel::Sequential)
            .map(|mut keys| keys.remove(0))
    }

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
                decompress_one(&cache, &key).expect("valid key decompresses")
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
            assert!(decompress_one(&cache, &key).is_some());
            assert_eq!(cache.len(), 1);
        });
    }

    #[test]
    fn secp256r1_decompress_matches_direct_and_caches() {
        deterministic::Runner::default().start(|context| async move {
            let cache = PublicKeyCache::new(context, NZUsize!(4));
            let key = secp256r1_key(0);

            let DecompressedPublicKey::Secp256r1(decompressed) =
                decompress_one(&cache, &key).expect("valid key decompresses")
            else {
                panic!("secp256r1 key should decompress to secp256r1");
            };
            let expected =
                VerifyingKey::from_sec1_bytes(&key.as_ref()[1..1 + secp256r1::PublicKey::SIZE])
                    .unwrap();
            assert_eq!(decompressed, expected);
            assert_eq!(cache.len(), 1);
            assert!(cache.contains(&key));

            assert!(decompress_one(&cache, &key).is_some());
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
                decompress_one(&cache, &ed),
                Some(DecompressedPublicKey::Ed25519(_))
            ));
            assert!(matches!(
                decompress_one(&cache, &r1),
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

            assert!(decompress_one(&cache, &key_a).is_some());
            assert!(decompress_one(&cache, &key_b).is_some());
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

            assert!(decompress_one(&cache, &key).is_none());
            assert!(cache.is_empty());
        });
    }

    #[test]
    fn registers_and_counts_misses() {
        deterministic::Runner::default().start(|context| async move {
            let cache = PublicKeyCache::new(context.child("public_key_cache"), NZUsize!(4));
            let key = ed25519_key(0);
            assert!(decompress_one(&cache, &key).is_some()); // miss
            assert!(decompress_one(&cache, &key).is_some()); // hit (not counted)
            assert!(decompress_one(&cache, &key).is_some()); // hit (not counted)

            let encoded = context.encode();
            assert!(
                encoded.contains("public_key_cache_misses_total 1"),
                "missing miss count:\n{encoded}"
            );
        });
    }
}
