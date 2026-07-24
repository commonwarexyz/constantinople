//! Epoch-indexed committee state and DKG participant-provider support.

use super::db::{CommitteeBatch, CommitteeDatabase};
use bytes::{Buf, BufMut};
use commonware_codec::{
    EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{Hasher, ed25519};
use commonware_parallel::Strategy;
use commonware_runtime::{BufferPooler, Clock, Metrics, Storage};
use commonware_storage::translator::Translator;
use commonware_utils::{
    ordered::{Map, Set},
    sequence::U64,
};
pub use constantinople_primitives::BLOCKS_PER_EPOCH;
use std::net::SocketAddr;

/// Maximum number of members in a committee.
pub const MAX_COMMITTEE_SIZE: usize = 64;

/// Canonical, non-empty committee stored in QMDB.
///
/// The unit codec configuration is intentional. The bound is part of this
/// application's wire format rather than supplied by callers, which keeps the
/// committee database's operation codec usable by the standard QMDB state-sync
/// resolver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Committee(Map<ed25519::PublicKey, SocketAddr>);

// One IP-family byte, sixteen IPv6 octets, and a port.
const MAX_SOCKET_ADDR_SIZE: usize = 1 + 16 + u16::SIZE;
const MAX_ENTRY_SIZE: usize = ed25519::PublicKey::SIZE + MAX_SOCKET_ADDR_SIZE;

impl Committee {
    /// Builds a validated canonical committee.
    pub fn new(addresses: Map<ed25519::PublicKey, SocketAddr>) -> Result<Self, &'static str> {
        if addresses.is_empty() {
            return Err("committee must be non-empty");
        }
        if addresses.len() > MAX_COMMITTEE_SIZE {
            return Err("committee exceeds maximum size");
        }
        Ok(Self(addresses))
    }

    /// Returns the canonical member set.
    pub const fn members(&self) -> &Set<ed25519::PublicKey> {
        self.0.keys()
    }

    /// Returns the canonical peer-to-address map.
    pub const fn addresses(&self) -> &Map<ed25519::PublicKey, SocketAddr> {
        &self.0
    }

    /// Applies one idempotent desired-state assignment.
    pub fn assign(
        &mut self,
        peer: ed25519::PublicKey,
        address: Option<SocketAddr>,
    ) -> Result<(), &'static str> {
        if self.0.get_value(&peer).copied() == address {
            return Ok(());
        }
        if self.0.get_value(&peer).is_some() && address.is_some() {
            return Err("committee member address cannot be changed");
        }

        let addresses = self
            .0
            .iter_pairs()
            .filter(|(member, _)| *member != &peer)
            .map(|(member, address)| (member.clone(), *address))
            .chain(address.map(|address| (peer.clone(), address)));
        *self = Self::new(Map::from_iter_dedup(addresses))?;
        Ok(())
    }
}

impl Write for Committee {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.len().write(buf);
        let mut written = 0;
        for (peer, address) in self.0.iter_pairs() {
            peer.write(buf);
            address.write(buf);
            written += ed25519::PublicKey::SIZE + address.encode_size();
        }
        buf.put_bytes(0, MAX_COMMITTEE_SIZE * MAX_ENTRY_SIZE - written);
    }
}

impl FixedSize for Committee {
    // The count is a one-byte varint at this bound. Entries are variable-size,
    // with the remainder padded to the maximum IPv6 representation.
    const SIZE: usize = 1 + MAX_COMMITTEE_SIZE * MAX_ENTRY_SIZE;
}

impl Read for Committee {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let len = usize::read_cfg(buf, &RangeCfg::new(1..=MAX_COMMITTEE_SIZE))?;
        let mut entries = Vec::with_capacity(len);
        let mut read = 0;
        for _ in 0..len {
            let peer = ed25519::PublicKey::read(buf)?;
            let address = SocketAddr::read(buf)?;
            read += ed25519::PublicKey::SIZE + address.encode_size();
            if entries
                .last()
                .is_some_and(|(previous, _)| previous >= &peer)
            {
                return Err(CodecError::Invalid(
                    "Committee",
                    "members must be strictly ordered and unique",
                ));
            }
            entries.push((peer, address));
        }
        let padding = MAX_COMMITTEE_SIZE * MAX_ENTRY_SIZE - read;
        for _ in 0..padding {
            if u8::read(buf)? != 0 {
                return Err(CodecError::Invalid(
                    "Committee",
                    "non-zero fixed-width padding",
                ));
            }
        }
        Ok(Self(Map::from_iter_dedup(entries)))
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
    use bytes::{BufMut as _, BytesMut};
    use commonware_codec::{
        DecodeExt as _, Encode as _, EncodeSize as _, FixedSize as _, Write as _,
    };
    use commonware_cryptography::{Signer as _, ed25519};
    use commonware_utils::ordered::Map;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    fn key(seed: u64) -> ed25519::PublicKey {
        ed25519::PrivateKey::from_seed(seed).public_key()
    }

    fn address(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    #[test]
    fn codec_enforces_nonempty_bounded_canonical_set() {
        let committee = Committee::new(Map::from_iter_dedup([
            (key(2), address(2)),
            (key(1), SocketAddr::from((Ipv6Addr::LOCALHOST, 1))),
        ]))
        .unwrap();
        let encoded = committee.encode();
        assert_eq!(encoded.len(), Committee::SIZE);
        assert_eq!(Committee::decode(encoded).unwrap(), committee);

        let empty = Map::<ed25519::PublicKey, SocketAddr>::default().encode();
        assert!(Committee::decode(empty).is_err());

        let oversized = Map::from_iter_dedup(
            (0..=MAX_COMMITTEE_SIZE).map(|index| (key(index as u64 + 10), address(10))),
        )
        .encode();
        assert!(Committee::decode(oversized).is_err());

        let mut bad_padding = committee.encode().to_vec();
        *bad_padding.last_mut().unwrap() = 1;
        assert!(Committee::decode(bad_padding.as_slice()).is_err());

        let duplicate = key(3);
        let duplicate_address = address(3);
        let mut duplicate_encoding = BytesMut::new();
        2usize.write(&mut duplicate_encoding);
        for _ in 0..2 {
            duplicate.write(&mut duplicate_encoding);
            duplicate_address.write(&mut duplicate_encoding);
        }
        let payload = 2 * (ed25519::PublicKey::SIZE + duplicate_address.encode_size());
        duplicate_encoding.put_bytes(0, MAX_COMMITTEE_SIZE * super::MAX_ENTRY_SIZE - payload);
        assert!(Committee::decode(duplicate_encoding.freeze()).is_err());
    }

    #[test]
    fn assignment_is_idempotent_and_preserves_bounds() {
        let a = key(1);
        let b = key(2);
        let a_address = address(1);
        let b_address = address(2);
        let mut committee = Committee::new(Map::from_iter_dedup([(a.clone(), a_address)])).unwrap();

        committee.assign(a.clone(), Some(a_address)).unwrap();
        assert!(committee.assign(a.clone(), Some(address(99))).is_err());
        committee.assign(b.clone(), Some(b_address)).unwrap();
        committee.assign(a, None).unwrap();
        assert_eq!(committee.addresses().get_value(&b), Some(&b_address));

        assert!(committee.assign(b, None).is_err());
    }
}
