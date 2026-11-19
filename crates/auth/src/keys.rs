//! X25519 keys and the keys a user shares with a validator.

use crate::tag::TagKey;
use bytes::BufMut;
use commonware_codec::{Buf, Error, FixedSize, Read, Write};
use commonware_formatting::hex;
use core::fmt;
use rand::CryptoRng;
use x25519_dalek::StaticSecret;
use zeroize::{Zeroize, ZeroizeOnDrop};

const TAG_CONTEXT: &str = "constantinople mac-tx v1 tag key";
const CHANNEL_CONTEXT: &str = "constantinople mac-tx v1 channel key";

/// A long-lived X25519 secret of a user or of a validator.
///
/// A validator's secret is separate from the key it signs votes with.
#[derive(Clone)]
pub struct PrivateKey(StaticSecret);

impl PrivateKey {
    /// Samples a secret.
    pub fn random(rng: &mut impl CryptoRng) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let key = Self(StaticSecret::from(bytes));
        bytes.zeroize();
        key
    }

    /// The public key of this secret.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(x25519_dalek::PublicKey::from(&self.0).to_bytes())
    }

    /// The keys this user shares with `validator`.
    ///
    /// Returns `None` if `validator` is a low-order point.
    pub fn with_validator(&self, namespace: &[u8], validator: &PublicKey) -> Option<SharedKey> {
        self.agree(namespace, validator, &self.public_key(), validator)
    }

    /// The keys this validator shares with `user`.
    ///
    /// Returns `None` if `user` is a low-order point. This is one Diffie-Hellman, about
    /// the cost of verifying a signature; a validator caches the result per user.
    pub fn with_user(&self, namespace: &[u8], user: &PublicKey) -> Option<SharedKey> {
        self.agree(namespace, user, user, &self.public_key())
    }

    /// `K(u, i) = KDF(DH(u, i), pk_u, pk_i)`, with one subkey for tags and one for the
    /// channel between the two. The namespace separates chains.
    fn agree(
        &self,
        namespace: &[u8],
        peer: &PublicKey,
        user: &PublicKey,
        validator: &PublicKey,
    ) -> Option<SharedKey> {
        let secret = self
            .0
            .diffie_hellman(&x25519_dalek::PublicKey::from(peer.0));
        if !secret.was_contributory() {
            return None;
        }
        let mut material = Vec::with_capacity(8 + namespace.len() + 3 * 32);
        material.extend_from_slice(&(namespace.len() as u64).to_be_bytes());
        material.extend_from_slice(namespace);
        material.extend_from_slice(secret.as_bytes());
        material.extend_from_slice(&user.0);
        material.extend_from_slice(&validator.0);
        let keys = SharedKey {
            tag: TagKey::new(blake3::derive_key(TAG_CONTEXT, &material)),
            channel: ChannelKey(blake3::derive_key(CHANNEL_CONTEXT, &material)),
        };
        material.zeroize();
        Some(keys)
    }
}

impl From<[u8; 32]> for PrivateKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(StaticSecret::from(bytes))
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(..)")
    }
}

impl Write for PrivateKey {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(self.0.as_bytes());
    }
}

impl FixedSize for PrivateKey {
    const SIZE: usize = 32;
}

impl Read for PrivateKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let mut bytes = <[u8; 32]>::read_cfg(buf, &())?;
        let key = Self::from(bytes);
        bytes.zeroize();
        Ok(key)
    }
}

/// An X25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey([u8; 32]);

impl From<[u8; 32]> for PublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex(&self.0))
    }
}

impl Write for PublicKey {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.0);
    }
}

impl FixedSize for PublicKey {
    const SIZE: usize = 32;
}

impl Read for PublicKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        <[u8; 32]>::read_cfg(buf, &()).map(Self)
    }
}

/// `K(u, i)`: the keys shared by user `u` and validator `i`.
#[derive(Clone)]
pub struct SharedKey {
    /// Key of the tags `u` computes for `i`.
    pub tag: TagKey,
    /// Key of the authenticated channel between `u` and `i`.
    pub channel: ChannelKey,
}

/// The channel half of a key shared by a user and a validator.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChannelKey([u8; 32]);

impl ChannelKey {
    /// A full-length MAC over the concatenation of `parts`.
    ///
    /// The caller makes the concatenation unambiguous.
    pub(crate) fn mac(&self, parts: &[&[u8]]) -> Mac {
        let mut hasher = blake3::Hasher::new_keyed(&self.0);
        for part in parts {
            hasher.update(part);
        }
        Mac(*hasher.finalize().as_bytes())
    }
}

/// A full-length MAC under a [`ChannelKey`].
#[derive(Clone, Copy, Debug)]
pub struct Mac([u8; 32]);

// Comparison takes the same time whether or not the MACs match.
impl PartialEq for Mac {
    fn eq(&self, other: &Self) -> bool {
        blake3::Hash::from_bytes(self.0) == blake3::Hash::from_bytes(other.0)
    }
}

impl Eq for Mac {}

impl Write for Mac {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.0);
    }
}

impl FixedSize for Mac {
    const SIZE: usize = 32;
}

impl Read for Mac {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        <[u8; 32]>::read_cfg(buf, &()).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_utils::{Participant, test_rng};

    #[test]
    fn both_sides_derive_the_same_keys() {
        let mut rng = test_rng();
        let user = PrivateKey::random(&mut rng);
        let validator = PrivateKey::random(&mut rng);

        let by_user = user
            .with_validator(b"chain", &validator.public_key())
            .unwrap();
        let by_validator = validator.with_user(b"chain", &user.public_key()).unwrap();

        let proposer = Participant::new(3);
        assert_eq!(
            by_user.tag.tag(proposer, b"tr", 86),
            by_validator.tag.tag(proposer, b"tr", 86)
        );
        assert_eq!(
            by_user.channel.mac(&[b"message"]),
            by_validator.channel.mac(&[b"message"])
        );
    }

    #[test]
    fn keys_depend_on_namespace_roles_and_parties() {
        let mut rng = test_rng();
        let user = PrivateKey::random(&mut rng);
        let validator = PrivateKey::random(&mut rng);
        let other = PrivateKey::random(&mut rng);
        let tag = |key: &SharedKey| key.tag.tag(Participant::new(0), b"tr", 128);

        let key = user
            .with_validator(b"chain", &validator.public_key())
            .unwrap();
        let other_chain = user
            .with_validator(b"other", &validator.public_key())
            .unwrap();
        let other_validator = user.with_validator(b"chain", &other.public_key()).unwrap();
        // The same two parties with their roles exchanged.
        let swapped = validator
            .with_validator(b"chain", &user.public_key())
            .unwrap();

        assert_ne!(tag(&key), tag(&other_chain));
        assert_ne!(tag(&key), tag(&other_validator));
        assert_ne!(tag(&key), tag(&swapped));
    }

    #[test]
    fn low_order_points_are_rejected() {
        let mut rng = test_rng();
        let secret = PrivateKey::random(&mut rng);
        // The identity and a point of order eight.
        let low_order = [
            [0u8; 32],
            [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
                0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
                0x5f, 0x49, 0xb8, 0x00,
            ],
        ];
        for point in low_order {
            assert!(
                secret
                    .with_user(b"chain", &PublicKey::from(point))
                    .is_none()
            );
            assert!(
                secret
                    .with_validator(b"chain", &PublicKey::from(point))
                    .is_none()
            );
        }
    }

    #[test]
    fn keys_roundtrip() {
        let mut rng = test_rng();
        let secret = PrivateKey::random(&mut rng);
        let decoded = PrivateKey::decode(secret.encode()).unwrap();
        assert_eq!(decoded.public_key(), secret.public_key());

        let public = secret.public_key();
        assert_eq!(PublicKey::decode(public.encode()).unwrap(), public);
        assert_eq!(public.to_string().len(), 64);
        assert_eq!(format!("{secret:?}"), "PrivateKey(..)");
    }
}
