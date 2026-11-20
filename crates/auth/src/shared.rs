//! The keys a validator shares with the senders it has seen lately.

use crate::keys::{PrivateKey, PublicKey, SharedKey};
use commonware_parallel::Strategy;
use commonware_utils::{cache::Cache, sync::RwLock};
use core::num::NonZeroUsize;
use std::collections::HashMap;

/// A fixed-capacity cache of `K(u, i)` for one validator `i`.
///
/// Deriving a key is one Diffie-Hellman, about the cost of verifying a
/// signature, so a validator keeps the keys of the senders it has seen lately.
/// It looks keys up for a whole block or batch at a time: one lookup per
/// transaction, from every thread of a pool at once, would have the threads
/// queue on the cache's lock and run slower than a single thread.
pub struct SharedKeys {
    secret: PrivateKey,
    cache: RwLock<Cache<PublicKey, SharedKey>>,
}

impl SharedKeys {
    /// A cache of the keys `secret` shares with at most `capacity` senders.
    pub fn new(secret: PrivateKey, capacity: NonZeroUsize) -> Self {
        Self {
            secret,
            cache: RwLock::new(Cache::new(capacity)),
        }
    }

    /// The key this validator shares with each of `users`, in the order given.
    ///
    /// A user whose key is a low-order point shares no key and gets `None`.
    ///
    /// Keys in the cache are read under one read lock. The others are derived
    /// on `strategy`, once per distinct user, and stored under one write lock.
    pub fn resolve(
        &self,
        namespace: &[u8],
        users: &[PublicKey],
        strategy: &impl Strategy,
    ) -> Vec<Option<SharedKey>> {
        // The read lock must not be held across work on `strategy`: a pool
        // worker that waits inside a parallel operation runs other jobs, and
        // one of those could wait for this lock behind a queued writer while
        // this thread still holds it.
        let mut resolved: Vec<Option<SharedKey>> = {
            let cache = self.cache.read();
            users.iter().map(|user| cache.get(user).cloned()).collect()
        };

        // One sender may have many transactions in a block: derive its key once.
        let mut slots: HashMap<PublicKey, usize> = HashMap::new();
        let mut unique: Vec<PublicKey> = Vec::new();
        let mut missing: Vec<(usize, usize)> = Vec::new();
        for (index, hit) in resolved.iter().enumerate() {
            if hit.is_none() {
                let user = users[index];
                let slot = *slots.entry(user).or_insert_with(|| {
                    unique.push(user);
                    unique.len() - 1
                });
                missing.push((index, slot));
            }
        }
        if unique.is_empty() {
            return resolved;
        }

        let derived: Vec<Option<SharedKey>> =
            strategy.map_collect_vec(unique.iter(), |user| self.secret.with_user(namespace, user));
        {
            let mut cache = self.cache.write();
            for (user, key) in unique.iter().zip(&derived) {
                // A low-order key is not remembered: it is derived, and
                // refused, each time it is seen.
                if let Some(key) = key {
                    cache.put(*user, key.clone());
                }
            }
        }
        for (index, slot) in missing {
            resolved[index] = derived[slot].clone();
        }
        resolved
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_parallel::{Rayon, Sequential};
    use commonware_utils::{NZUsize, Participant, test_rng};

    const NAMESPACE: &[u8] = b"chain";

    fn tag(key: &SharedKey) -> crate::Tag {
        key.tag.tag(Participant::new(1), b"transaction", 86)
    }

    fn users(count: usize) -> Vec<PrivateKey> {
        let mut rng = test_rng();
        (0..count).map(|_| PrivateKey::random(&mut rng)).collect()
    }

    /// Every user gets the key it shares with the validator, in the order
    /// asked, whether the key was cached, derived, or asked for twice.
    #[test]
    fn resolve_returns_each_users_key_in_order() {
        let validator = PrivateKey::from([9; 32]);
        let users = users(8);
        let public: Vec<_> = users.iter().map(PrivateKey::public_key).collect();
        let keys = SharedKeys::new(validator.clone(), NZUsize!(64));
        let expected = |user: &PublicKey| tag(&validator.with_user(NAMESPACE, user).unwrap());

        // Half the users are cached before the others are first seen, and one
        // user appears three times in the same call.
        keys.resolve(NAMESPACE, &public[..4], &Sequential);
        let mut asked = public.clone();
        asked.push(public[6]);
        asked.push(public[6]);
        asked.reverse();

        let resolved = keys.resolve(NAMESPACE, &asked, &Sequential);
        assert_eq!(resolved.len(), asked.len());
        for (user, key) in asked.iter().zip(&resolved) {
            assert_eq!(tag(key.as_ref().unwrap()), expected(user));
        }
        // What a user derives for this validator is the same key.
        for (user, key) in users
            .iter()
            .zip(keys.resolve(NAMESPACE, &public, &Sequential))
        {
            let theirs = user
                .with_validator(NAMESPACE, &validator.public_key())
                .unwrap();
            assert_eq!(tag(&key.unwrap()), tag(&theirs));
        }
    }

    /// A low-order point shares no key, however often it is asked for and
    /// whatever it is asked with.
    #[test]
    fn resolve_refuses_low_order_keys() {
        let validator = PrivateKey::from([9; 32]);
        let good = users(1)[0].public_key();
        let low_order = PublicKey::from([0; 32]);
        let keys = SharedKeys::new(validator, NZUsize!(4));

        for _ in 0..2 {
            let resolved = keys.resolve(NAMESPACE, &[low_order, good, low_order], &Sequential);
            assert!(resolved[0].is_none());
            assert!(resolved[1].is_some());
            assert!(resolved[2].is_none());
        }
    }

    /// More users than the cache holds still get the right keys, from a pool
    /// of threads as from one.
    #[test]
    fn resolve_is_right_beyond_capacity_and_on_a_pool() {
        let validator = PrivateKey::from([9; 32]);
        let public: Vec<_> = users(200).iter().map(PrivateKey::public_key).collect();
        let pool = Rayon::new(NZUsize!(4)).unwrap();
        let small = SharedKeys::new(validator.clone(), NZUsize!(16));

        for _ in 0..3 {
            let on_pool = small.resolve(NAMESPACE, &public, &pool);
            for (user, key) in public.iter().zip(&on_pool) {
                let expected = validator.with_user(NAMESPACE, user).unwrap();
                assert_eq!(tag(key.as_ref().unwrap()), tag(&expected));
            }
        }
    }
}
