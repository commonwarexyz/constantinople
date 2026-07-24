//! Constantinople transaction type and transaction wrappers.

use crate::{AccountKey, Sealable, Sealed, TransactionPublicKey, TransactionSignature};
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error, FixedSize, Read, ReadExt, Write, types::lazy::Lazy,
};
use commonware_cryptography::{Digest, Hasher, Signer, ed25519};
use core::num::NonZeroU64;
use std::net::SocketAddr;

const TRANSFER_TAG: u8 = 0;
const SET_COMMITTEE_MEMBER_TAG: u8 = 1;
const MAX_SOCKET_ADDR_SIZE: usize = u8::SIZE + u128::SIZE + u16::SIZE;

/// A signed transaction accepted by the canonical block format.
#[derive(Debug)]
pub struct SignedTransaction<H>
where
    H: Hasher,
{
    inner: Sealed<Transaction<H::Digest>, H>,
    signature: TransactionSignature,
}

impl<H: Hasher> Clone for SignedTransaction<H> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            signature: self.signature.clone(),
        }
    }
}

impl<H> PartialEq for SignedTransaction<H>
where
    H: Hasher,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.signature == other.signature
    }
}

impl<H> Eq for SignedTransaction<H> where H: Hasher {}

/// A signed transaction whose signature has been accepted by the caller.
pub type VerifiedTransaction<H> = SignedTransaction<H>;

impl<H> SignedTransaction<H>
where
    H: Hasher,
{
    /// Minimum encoded signed transaction size.
    pub const MIN_SIZE: usize = Transaction::<H::Digest>::MIN_SIZE + TransactionSignature::MIN_SIZE;
    /// Maximum encoded signed transaction size.
    pub const MAX_SIZE: usize = Transaction::<H::Digest>::MAX_SIZE + TransactionSignature::MAX_SIZE;

    /// Creates a signed transaction without checking the signature.
    pub const fn new_unchecked(
        inner: Sealed<Transaction<H::Digest>, H>,
        signature: TransactionSignature,
    ) -> Self {
        Self { inner, signature }
    }

    /// Returns the inner sealed transaction.
    pub fn into_inner(self) -> Sealed<Transaction<H::Digest>, H> {
        self.inner
    }

    /// Returns a reference to the inner sealed transaction.
    pub const fn inner(&self) -> &Sealed<Transaction<H::Digest>, H> {
        &self.inner
    }

    /// Returns a reference to the transaction.
    pub fn value(&self) -> &Transaction<H::Digest> {
        self.inner()
    }

    /// Returns the transaction digest that was signed.
    pub const fn message_digest(&self) -> &H::Digest {
        self.inner.seal()
    }

    /// Returns the decoded transaction signature.
    pub const fn signature(&self) -> &TransactionSignature {
        &self.signature
    }
}

/// An action performed by a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Action {
    /// Transfers funds to another account.
    Transfer {
        /// The recipient account key.
        to: AccountKey,
        /// The non-zero value to transfer.
        value: NonZeroU64,
    },
    /// Idempotently updates a member of the next mutable future committee.
    SetCommitteeMember {
        /// The Ed25519 peer to update.
        peer: ed25519::PublicKey,
        /// The peer's address when adding it, or `None` when removing it.
        address: Option<SocketAddr>,
    },
}

impl Action {
    /// Minimum encoded action size.
    pub const MIN_SIZE: usize = u8::SIZE + ed25519::PublicKey::SIZE + bool::SIZE;
    /// Maximum encoded action size.
    pub const MAX_SIZE: usize =
        u8::SIZE + ed25519::PublicKey::SIZE + bool::SIZE + MAX_SOCKET_ADDR_SIZE;

    /// Creates a transfer action.
    pub const fn transfer(to: AccountKey, value: NonZeroU64) -> Self {
        Self::Transfer { to, value }
    }

    /// Creates an idempotent update to the next mutable future committee.
    pub const fn set_committee_member(
        peer: ed25519::PublicKey,
        address: Option<SocketAddr>,
    ) -> Self {
        Self::SetCommitteeMember { peer, address }
    }
}

impl Write for Action {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Transfer { to, value } => {
                TRANSFER_TAG.write(buf);
                to.write(buf);
                value.get().write(buf);
            }
            Self::SetCommitteeMember { peer, address } => {
                SET_COMMITTEE_MEMBER_TAG.write(buf);
                peer.write(buf);
                address.write(buf);
            }
        }
    }
}

impl EncodeSize for Action {
    fn encode_size(&self) -> usize {
        match self {
            Self::Transfer { .. } => u8::SIZE + AccountKey::SIZE + u64::SIZE,
            Self::SetCommitteeMember { address, .. } => {
                u8::SIZE + ed25519::PublicKey::SIZE + address.encode_size()
            }
        }
    }
}

impl Read for Action {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            TRANSFER_TAG => {
                let to = AccountKey::read(buf)?;
                let value = NonZeroU64::new(u64::read(buf)?)
                    .ok_or(Error::Invalid("Action", "transfer value must be non-zero"))?;
                Ok(Self::Transfer { to, value })
            }
            SET_COMMITTEE_MEMBER_TAG => Ok(Self::SetCommitteeMember {
                peer: ed25519::PublicKey::read(buf)?,
                address: Option::<SocketAddr>::read(buf)?,
            }),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl<H> Write for SignedTransaction<H>
where
    H: Hasher,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.inner.write(buf);
        self.signature.write(buf);
    }
}

impl<H> EncodeSize for SignedTransaction<H>
where
    H: Hasher,
{
    fn encode_size(&self) -> usize {
        self.inner.encode_size() + self.signature.encode_size()
    }
}

// Encoding borrowed transactions lets collections like `Vec<&SignedTransaction>`
// encode without cloning each transaction first.
impl<H> Write for &SignedTransaction<H>
where
    H: Hasher,
{
    fn write(&self, buf: &mut impl BufMut) {
        (**self).write(buf);
    }
}

impl<H> EncodeSize for &SignedTransaction<H>
where
    H: Hasher,
{
    fn encode_size(&self) -> usize {
        (**self).encode_size()
    }
}

impl<H> Read for SignedTransaction<H>
where
    H: Hasher,
{
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let inner = Sealed::<Transaction<H::Digest>, H>::read(buf)?;
        let signature = TransactionSignature::read(buf)?;
        Ok(Self { inner, signature })
    }
}

/// A transaction on the Constantinople blockchain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Transaction<D: Digest> {
    /// The sender public key, decoded lazily on demand.
    pub sender: Lazy<TransactionPublicKey>,
    /// The sender nonce.
    pub nonce: u64,
    /// The action to perform.
    pub action: Action,
    /// The digest type.
    pub _digest: core::marker::PhantomData<D>,
}

impl<D: Digest> Transaction<D> {
    /// Creates a new transfer transaction.
    ///
    /// This is an alias for [`Self::transfer`] retained for transfer callers.
    pub fn new(
        sender: TransactionPublicKey,
        to: TransactionPublicKey,
        value: NonZeroU64,
        nonce: u64,
    ) -> Self {
        Self::transfer(sender, to, value, nonce)
    }

    /// Creates a transaction containing an action.
    pub fn with_action(sender: TransactionPublicKey, action: Action, nonce: u64) -> Self {
        Self {
            sender: Lazy::new(sender),
            nonce,
            action,
            _digest: core::marker::PhantomData,
        }
    }

    /// Creates a transfer transaction.
    pub fn transfer(
        sender: TransactionPublicKey,
        to: TransactionPublicKey,
        value: NonZeroU64,
        nonce: u64,
    ) -> Self {
        Self::with_action(
            sender,
            Action::transfer(AccountKey::from_public_key(&to), value),
            nonce,
        )
    }

    /// Creates an idempotent update to the next mutable future committee.
    pub fn set_committee_member(
        sender: TransactionPublicKey,
        peer: ed25519::PublicKey,
        address: Option<SocketAddr>,
        nonce: u64,
    ) -> Self {
        Self::with_action(sender, Action::set_committee_member(peer, address), nonce)
    }

    /// Returns the decoded sender public key.
    pub fn sender(&self) -> Option<&TransactionPublicKey> {
        self.sender.get()
    }

    /// Returns the lazily decoded sender public key.
    pub const fn sender_lazy(&self) -> &Lazy<TransactionPublicKey> {
        &self.sender
    }

    /// Hashes the consensus-encoded transaction to produce a [`Digest`].
    ///
    /// If you want to cache the hash, consider using the [`Sealable`] trait.
    ///
    /// [`Digest`]: Digest
    pub fn hash_slow<H: Hasher>(&self, hasher: &mut H) -> H::Digest {
        hasher.update(&self.encode());
        let (next, digest) = core::mem::take(hasher).finalize();
        *hasher = next;
        digest
    }

    /// Seals and signs this transaction with a supported transaction signer.
    pub fn seal_and_sign<H, S>(
        self,
        signer: &S,
        namespace: &[u8],
        hasher: &mut H,
    ) -> SignedTransaction<H>
    where
        H: Hasher<Digest = D>,
        S: Signer,
        TransactionSignature: From<S::Signature>,
    {
        let sealed = self.seal(hasher);
        let signature = TransactionSignature::from(signer.sign(namespace, sealed.seal().as_ref()));
        SignedTransaction::new_unchecked(sealed, signature)
    }
}

impl<D: Digest> Write for Transaction<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.sender.write(buf);
        self.nonce.write(buf);
        self.action.write(buf);
    }
}

impl<D: Digest> EncodeSize for Transaction<D> {
    fn encode_size(&self) -> usize {
        TransactionPublicKey::SIZE + u64::SIZE + self.action.encode_size()
    }
}

impl<D: Digest> Read for Transaction<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let sender = Lazy::<TransactionPublicKey>::read(buf)?;

        Ok(Self {
            sender,
            nonce: u64::read(buf)?,
            action: Action::read(buf)?,
            _digest: core::marker::PhantomData,
        })
    }
}

impl<D: Digest> Transaction<D> {
    /// Minimum encoded transaction size.
    pub const MIN_SIZE: usize = TransactionPublicKey::SIZE + u64::SIZE + Action::MIN_SIZE;
    /// Maximum encoded transaction size.
    pub const MAX_SIZE: usize = TransactionPublicKey::SIZE + u64::SIZE + Action::MAX_SIZE;
}

impl<D: Digest> Sealable for Transaction<D> {
    type SealDigest = D;

    fn seal<H: Hasher<Digest = Self::SealDigest>>(self, hasher: &mut H) -> Sealed<Self, H> {
        let seal = self.hash_slow(hasher);
        Sealed::new_unchecked(self, seal)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<D: Digest> arbitrary::Arbitrary<'_> for Transaction<D> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let sender = commonware_cryptography::ed25519::PublicKey::arbitrary(u)?;
        Ok(Self {
            sender: Lazy::new(TransactionPublicKey::ed25519(sender)),
            nonce: u.arbitrary()?,
            action: u.arbitrary()?,
            _digest: core::marker::PhantomData,
        })
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl arbitrary::Arbitrary<'_> for Action {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        match u.int_in_range(TRANSFER_TAG..=SET_COMMITTEE_MEMBER_TAG)? {
            TRANSFER_TAG => {
                let to = commonware_cryptography::ed25519::PublicKey::arbitrary(u)?;
                let to = AccountKey::from_public_key(&TransactionPublicKey::ed25519(to));
                let value = NonZeroU64::new(u.int_in_range(1..=u64::MAX)?)
                    .expect("arbitrary non-zero value should construct");
                Ok(Self::transfer(to, value))
            }
            SET_COMMITTEE_MEMBER_TAG => Ok(Self::set_committee_member(
                ed25519::PublicKey::arbitrary(u)?,
                Option::<SocketAddr>::arbitrary(u)?,
            )),
            _ => unreachable!("arbitrary action tag is range constrained"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Sealable;
    use arbitrary::{Arbitrary, unstructured::Unstructured};
    use commonware_codec::{DecodeExt, Encode, EncodeSize};
    use commonware_cryptography::{ed25519, sha256};
    use commonware_formatting::hex;
    use commonware_math::algebra::Random;
    use rand::{SeedableRng, rngs::StdRng};
    use std::net::{Ipv4Addr, Ipv6Addr};

    const SENDER_BYTES: [u8; ed25519::PublicKey::SIZE] =
        hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const PEER_BYTES: [u8; ed25519::PublicKey::SIZE] =
        hex!("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");

    fn sender_key() -> ed25519::PublicKey {
        ed25519::PublicKey::decode(&SENDER_BYTES[..]).expect("fixture sender should decode")
    }

    fn peer_key() -> ed25519::PublicKey {
        ed25519::PublicKey::decode(&PEER_BYTES[..]).expect("fixture peer should decode")
    }

    fn peer_address() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 8080))
    }

    fn test_sender() -> TransactionPublicKey {
        let mut rng = StdRng::from_seed([7u8; 32]);
        TransactionPublicKey::ed25519(ed25519::PrivateKey::random(&mut rng).public_key())
    }

    #[test]
    fn test_roundtrip_transaction_consensus() {
        let reference_tx: Transaction<sha256::Digest> =
            Transaction::arbitrary(&mut Unstructured::new(&[])).unwrap();

        let mut encoded = Vec::with_capacity(reference_tx.encode_size());
        reference_tx.write(&mut encoded);

        let decoded = Transaction::<sha256::Digest>::decode(&mut &encoded[..])
            .expect("decoding should succeed");

        assert_eq!(
            decoded, reference_tx,
            "Decoded transaction should match the original"
        );
    }

    #[test]
    fn transaction_hash_slow_deterministic() {
        let tx: Transaction<sha256::Digest> =
            Transaction::arbitrary(&mut Unstructured::new(&[])).unwrap();
        let hasher = &mut sha256::Sha256::default();

        let h1 = tx.hash_slow(hasher);
        let h2 = tx.hash_slow(hasher);
        assert_eq!(h1, h2, "hash_slow should be deterministic");
    }

    #[test]
    fn transaction_seal_matches_hash_slow() {
        let tx: Transaction<sha256::Digest> =
            Transaction::arbitrary(&mut Unstructured::new(&[])).unwrap();
        let hasher = &mut sha256::Sha256::default();

        let expected = tx.hash_slow(hasher);
        let sealed = tx.seal(hasher);
        assert_eq!(*sealed.seal(), expected);
    }

    #[test]
    fn transaction_variants_roundtrip() {
        let transfer = Transaction::<sha256::Digest>::transfer(
            test_sender(),
            test_sender(),
            NonZeroU64::new(12_345).expect("test value should be non-zero"),
            1,
        );
        let committee = Transaction::<sha256::Digest>::set_committee_member(
            test_sender(),
            peer_key(),
            Some(peer_address()),
            u64::MAX,
        );
        let removal =
            Transaction::<sha256::Digest>::set_committee_member(test_sender(), peer_key(), None, 2);

        for transaction in [transfer, committee, removal] {
            let encoded = transaction.encode();
            let decoded =
                Transaction::<sha256::Digest>::decode(encoded).expect("decoding should succeed");
            assert_eq!(decoded, transaction);
        }
    }

    #[test]
    fn transaction_transfer_golden_vector() {
        let transaction = Transaction::<sha256::Digest>::transfer(
            TransactionPublicKey::ed25519(sender_key()),
            TransactionPublicKey::ed25519(peer_key()),
            NonZeroU64::new(19).expect("fixture value should be non-zero"),
            7,
        );
        let expected: [u8; 83] = hex!(
            "00d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a000000000000000007003d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c0000000000000013"
        );

        assert_eq!(transaction.encode().as_ref(), expected.as_slice());
        assert_eq!(
            expected[TransactionPublicKey::SIZE + u64::SIZE],
            TRANSFER_TAG
        );
    }

    #[test]
    fn transaction_add_committee_member_golden_vector() {
        let transaction = Transaction::<sha256::Digest>::set_committee_member(
            TransactionPublicKey::ed25519(sender_key()),
            peer_key(),
            Some(peer_address()),
            7,
        );
        let expected: [u8; 83] = hex!(
            "00d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a000000000000000007013d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c0104c00002011f90"
        );

        assert_eq!(transaction.encode().as_ref(), expected.as_slice());
        assert_eq!(
            expected[TransactionPublicKey::SIZE + u64::SIZE],
            SET_COMMITTEE_MEMBER_TAG
        );
    }

    #[test]
    fn transaction_remove_committee_member_golden_vector() {
        let transaction = Transaction::<sha256::Digest>::set_committee_member(
            TransactionPublicKey::ed25519(sender_key()),
            peer_key(),
            None,
            7,
        );
        let expected: [u8; 76] = hex!(
            "00d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a000000000000000007013d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c00"
        );

        assert_eq!(transaction.encode().as_ref(), expected.as_slice());
    }

    #[test]
    fn transaction_size_bounds_cover_both_actions() {
        let recipient = AccountKey::from_public_key(&TransactionPublicKey::ed25519(peer_key()));
        let transfer = Action::transfer(
            recipient,
            NonZeroU64::new(u64::MAX).expect("max value should be non-zero"),
        );
        let committee_min = Action::set_committee_member(peer_key(), None);
        let committee_max = Action::set_committee_member(
            peer_key(),
            Some(SocketAddr::from((Ipv6Addr::LOCALHOST, u16::MAX))),
        );

        assert_eq!(transfer.encode_size(), 41);
        assert_eq!(committee_min.encode_size(), Action::MIN_SIZE);
        assert_eq!(committee_max.encode_size(), Action::MAX_SIZE);
        assert_eq!(Action::MIN_SIZE, 34);
        assert_eq!(Action::MAX_SIZE, 53);
        assert_eq!(Transaction::<sha256::Digest>::MIN_SIZE, 76);
        assert_eq!(Transaction::<sha256::Digest>::MAX_SIZE, 95);
    }

    #[test]
    fn transaction_zero_value_decode_is_rejected() {
        let sender = test_sender();
        let recipient = AccountKey::from_public_key(&test_sender());

        let mut buf = Vec::new();
        sender.write(&mut buf);
        7u64.write(&mut buf);
        TRANSFER_TAG.write(&mut buf);
        recipient.write(&mut buf);
        0u64.write(&mut buf);

        let result = Transaction::<sha256::Digest>::decode(&mut &buf[..]);
        assert!(result.is_err(), "zero-value transactions must be rejected");
    }

    #[test]
    fn action_rejects_unknown_tag_and_invalid_address_fields() {
        assert!(matches!(
            Action::decode([2].as_slice()),
            Err(Error::InvalidEnum(2))
        ));

        let mut invalid_option = Vec::new();
        SET_COMMITTEE_MEMBER_TAG.write(&mut invalid_option);
        peer_key().write(&mut invalid_option);
        2u8.write(&mut invalid_option);
        assert!(matches!(
            Action::decode(invalid_option.as_slice()),
            Err(Error::InvalidBool)
        ));

        let mut invalid_address = invalid_option;
        *invalid_address
            .last_mut()
            .expect("option prefix should exist") = 1;
        5u8.write(&mut invalid_address);
        assert!(matches!(
            Action::decode(invalid_address.as_slice()),
            Err(Error::Invalid("IpAddr", "Invalid version"))
        ));
    }

    #[test]
    fn committee_member_action_rejects_every_truncation() {
        let action = Action::set_committee_member(
            peer_key(),
            Some(SocketAddr::from((Ipv6Addr::LOCALHOST, 8080))),
        );
        let encoded = action.encode();

        for end in 0..encoded.len() {
            assert!(
                Action::decode(&encoded[..end]).is_err(),
                "truncation at byte {end} must be rejected"
            );
        }
    }

    #[test]
    fn transaction_decode_defers_sender_validation() {
        let invalid_sender = (0u8..=u8::MAX)
            .flat_map(|first| (0u8..=u8::MAX).map(move |last| (first, last)))
            .find_map(|(first, last)| {
                let mut candidate = [0; TransactionPublicKey::SIZE];
                candidate[0] = 0;
                candidate[1] = first;
                candidate[TransactionPublicKey::SIZE - 1] = last;

                TransactionPublicKey::decode(&mut &candidate[..])
                    .is_err()
                    .then_some(candidate)
            })
            .expect("test should find invalid sender bytes");

        let mut buf = Vec::new();
        invalid_sender.write(&mut buf);
        9u64.write(&mut buf);
        Action::transfer(
            AccountKey::from_public_key(&test_sender()),
            NonZeroU64::new(1).expect("test value should be non-zero"),
        )
        .write(&mut buf);

        let decoded = Transaction::<sha256::Digest>::decode(&mut &buf[..])
            .expect("decoding should defer sender validation");

        assert!(decoded.sender().is_none());
    }
}
