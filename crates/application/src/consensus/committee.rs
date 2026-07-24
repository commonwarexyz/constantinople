//! Epoch-indexed committee state and DKG participant-provider support.

use super::db::{CommitteeBatch, CommitteeDatabase};
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, RangeCfg, Read, ReadExt as _, Write};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{Hasher, ed25519};
use commonware_parallel::Strategy;
use commonware_runtime::{BufferPooler, Clock, Metrics, Storage};
use commonware_storage::translator::Translator;
use commonware_utils::{ordered::Set, sequence::U64};
pub use constantinople_primitives::BLOCKS_PER_EPOCH;

/// Maximum number of members in a committee.
pub const MAX_COMMITTEE_SIZE: usize = 64;

/// Canonical, non-empty committee stored in QMDB.
///
/// The unit codec configuration is intentional. The bound is part of this
/// application's wire format rather than supplied by callers, which keeps the
/// committee database's operation codec usable by the standard QMDB state-sync
/// resolver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Committee(Set<ed25519::PublicKey>);

impl Committee {
    /// Builds a validated canonical committee.
    pub fn new(members: Set<ed25519::PublicKey>) -> Result<Self, &'static str> {
        if members.is_empty() {
            return Err("committee must be non-empty");
        }
        if members.len() > MAX_COMMITTEE_SIZE {
            return Err("committee exceeds maximum size");
        }
        Ok(Self(members))
    }

    /// Returns the canonical member set.
    pub const fn members(&self) -> &Set<ed25519::PublicKey> {
        &self.0
    }

    /// Consumes the wrapper and returns the canonical member set.
    pub fn into_members(self) -> Set<ed25519::PublicKey> {
        self.0
    }

    /// Applies one idempotent desired-state assignment.
    pub fn assign(
        &mut self,
        peer: ed25519::PublicKey,
        registered: bool,
    ) -> Result<(), &'static str> {
        let contained = self.0.position(&peer).is_some();
        if contained == registered {
            return Ok(());
        }

        let members = if registered {
            Set::from_iter_dedup(self.0.iter().cloned().chain(core::iter::once(peer)))
        } else {
            Set::from_iter_dedup(self.0.iter().filter(|member| *member != &peer).cloned())
        };
        *self = Self::new(members)?;
        Ok(())
    }
}

impl Write for Committee {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
        buf.put_bytes(
            0,
            (MAX_COMMITTEE_SIZE - self.0.len()) * ed25519::PublicKey::SIZE,
        );
    }
}

impl FixedSize for Committee {
    // `Set` prefixes its length as a one-byte varint for the application bound
    // of 64, then stores up to 64 fixed-size Ed25519 public keys.
    const SIZE: usize = 1 + MAX_COMMITTEE_SIZE * ed25519::PublicKey::SIZE;
}

impl Read for Committee {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let members =
            Set::<ed25519::PublicKey>::read_cfg(buf, &(RangeCfg::new(1..=MAX_COMMITTEE_SIZE), ()))?;
        let padding = (MAX_COMMITTEE_SIZE - members.len()) * ed25519::PublicKey::SIZE;
        for _ in 0..padding {
            if u8::read(buf)? != 0 {
                return Err(CodecError::Invalid(
                    "Committee",
                    "non-zero fixed-width padding",
                ));
            }
        }
        Ok(Self(members))
    }
}

/// Returns the QMDB key for an epoch.
pub const fn epoch_key(epoch: Epoch) -> U64 {
    U64::new(epoch.get())
}

/// Seeds the required epoch-zero and epoch-one committee rows.
pub fn seed_committees<E, H, T, S>(
    batch: CommitteeBatch<E, H, T, S>,
    genesis: Committee,
    genesis_next: Committee,
) -> CommitteeBatch<E, H, T, S>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    T: Translator,
    S: Strategy,
{
    batch
        .write(U64::new(0), Some(genesis))
        .write(U64::new(1), Some(genesis_next))
}

/// Reads `epoch`, falling back to its predecessor when the requested row has
/// not yet been materialized.
pub async fn committee_for_epoch<E, H, T, S>(
    database: &CommitteeDatabase<E, H, T, S>,
    epoch: Epoch,
) -> Committee
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    T: Translator,
    S: Strategy,
{
    let requested = epoch_key(epoch);
    let fallback = epoch.get().checked_sub(1).map(U64::new);
    let database = database.read().await;
    if let Some(committee) = database
        .get(&requested)
        .await
        .expect("committee state read must succeed")
    {
        return committee;
    }
    if let Some(fallback) = fallback
        && let Some(committee) = database
            .get(&fallback)
            .await
            .expect("committee fallback read must succeed")
    {
        return committee;
    }
    panic!("committee row and predecessor are both absent for epoch {epoch}");
}

#[cfg(test)]
mod tests {
    use super::{Committee, MAX_COMMITTEE_SIZE};
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::{Signer as _, ed25519};
    use commonware_utils::ordered::Set;

    fn key(seed: u64) -> ed25519::PublicKey {
        ed25519::PrivateKey::from_seed(seed).public_key()
    }

    #[test]
    fn codec_enforces_nonempty_bounded_canonical_set() {
        let committee = Committee::new(Set::from_iter_dedup([key(2), key(1)])).unwrap();
        let encoded = committee.encode();
        assert_eq!(Committee::decode(encoded).unwrap(), committee);

        let empty = Set::<ed25519::PublicKey>::default().encode();
        assert!(Committee::decode(empty).is_err());

        let oversized =
            Set::from_iter_dedup((0..=MAX_COMMITTEE_SIZE).map(|index| key(index as u64 + 10)))
                .encode();
        assert!(Committee::decode(oversized).is_err());
    }

    #[test]
    fn assignment_is_idempotent_and_preserves_bounds() {
        let a = key(1);
        let b = key(2);
        let mut committee = Committee::new(Set::from_iter_dedup([a.clone()])).unwrap();

        committee.assign(a.clone(), true).unwrap();
        committee.assign(b.clone(), true).unwrap();
        committee.assign(a, false).unwrap();
        assert_eq!(committee.members(), &Set::from_iter_dedup([b.clone()]));

        assert!(committee.assign(b, false).is_err());
    }
}
