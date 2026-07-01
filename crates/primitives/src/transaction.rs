//! Constantinople transaction type and transaction wrappers.

use crate::{AccountKey, Sealable, Sealed, TransactionPublicKey, TransactionSignature};
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error, FixedSize, Read, ReadExt, Write, types::lazy::Lazy,
};
use commonware_cryptography::{Digest, Hasher, Signer, ed25519};
use core::num::NonZeroU64;

const TRANSFER_TAG: u8 = 0;
const OPEN_CHANNEL_TAG: u8 = 1;
const CLOSE_CHANNEL_TAG: u8 = 2;

/// The operation a [`Transaction`] performs.
///
/// Every operation shares the [`Transaction`]-level `sender` and `nonce`; the
/// variant carries the operation-specific payload. A one-byte tag distinguishes
/// the variants on the wire. The [`Operation::Transfer`] variant is the classic
/// account transfer; the remaining variants drive unidirectional payment
/// channels.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Operation {
    /// Move `value` from the sender to `to`.
    Transfer {
        /// The recipient account key.
        to: AccountKey,
        /// The value to send.
        value: NonZeroU64,
    },
    /// Open and fund a payment channel from the sender (payer) to `receiver`.
    ///
    /// The channel account address is derived from
    /// `(sender, receiver, open_nonce)`, where `open_nonce` is this
    /// transaction's own nonce. Because account nonces are monotonic and never
    /// reused, every open yields a unique, never-recurring channel address, so
    /// the address is reconstructible without being stored, a settled channel
    /// can be deleted, and old vouchers can never be replayed against a new
    /// channel. The sender is debited `deposit`, which is added to the
    /// channel's escrow (a fresh address starts from zero).
    OpenChannel {
        /// The receiver (service) account key.
        receiver: AccountKey,
        /// The amount escrowed into the channel.
        deposit: NonZeroU64,
    },
    /// Claim a voucher and settle a payment channel.
    ///
    /// The sender is the receiver. The channel address is recomputed from
    /// `(payer, sender, open_nonce)`; `cumulative` of the escrow is paid to the
    /// receiver and the remainder is returned to the payer, closing the
    /// channel. `voucher` is the payer's signature over the voucher message
    /// (see [`crate::voucher_message`]).
    CloseChannel {
        /// The payer's public key (authenticated by the channel address).
        payer: TransactionPublicKey,
        /// The nonce of the `OpenChannel` transaction that created the channel.
        open_nonce: u64,
        /// The cumulative amount claimed by the receiver.
        cumulative: u64,
        /// The payer's voucher signature over `(channel_id, cumulative)`.
        voucher: ed25519::Signature,
    },
}

impl Operation {
    /// Encoded size of a transfer: tag, recipient, and value.
    const TRANSFER_SIZE: usize = 1 + AccountKey::SIZE + u64::SIZE;
    /// Encoded size of a channel open: tag, receiver, and deposit.
    const OPEN_CHANNEL_SIZE: usize = 1 + AccountKey::SIZE + u64::SIZE;
    /// Encoded size of a channel close: tag, payer, open nonce, cumulative, and voucher.
    const CLOSE_CHANNEL_SIZE: usize =
        1 + TransactionPublicKey::SIZE + u64::SIZE + u64::SIZE + ed25519::Signature::SIZE;
    /// Smallest encoded operation (a transfer).
    pub const MIN_SIZE: usize = Self::TRANSFER_SIZE;
    /// Largest encoded operation (a channel close).
    pub const MAX_SIZE: usize = Self::CLOSE_CHANNEL_SIZE;
}

impl Write for Operation {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Transfer { to, value } => {
                TRANSFER_TAG.write(buf);
                to.write(buf);
                value.get().write(buf);
            }
            Self::OpenChannel { receiver, deposit } => {
                OPEN_CHANNEL_TAG.write(buf);
                receiver.write(buf);
                deposit.get().write(buf);
            }
            Self::CloseChannel {
                payer,
                open_nonce,
                cumulative,
                voucher,
            } => {
                CLOSE_CHANNEL_TAG.write(buf);
                payer.write(buf);
                open_nonce.write(buf);
                cumulative.write(buf);
                voucher.write(buf);
            }
        }
    }
}

impl EncodeSize for Operation {
    fn encode_size(&self) -> usize {
        match self {
            Self::Transfer { .. } => Self::TRANSFER_SIZE,
            Self::OpenChannel { .. } => Self::OPEN_CHANNEL_SIZE,
            Self::CloseChannel { .. } => Self::CLOSE_CHANNEL_SIZE,
        }
    }
}

impl Read for Operation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let tag = u8::read(buf)?;
        match tag {
            TRANSFER_TAG => {
                let to = AccountKey::read(buf)?;
                let value = u64::read(buf)?;
                let value = NonZeroU64::new(value).ok_or(Error::Invalid(
                    "Operation",
                    "transfer value must be non-zero",
                ))?;
                Ok(Self::Transfer { to, value })
            }
            OPEN_CHANNEL_TAG => {
                let receiver = AccountKey::read(buf)?;
                let deposit = u64::read(buf)?;
                let deposit = NonZeroU64::new(deposit)
                    .ok_or(Error::Invalid("Operation", "deposit must be non-zero"))?;
                Ok(Self::OpenChannel { receiver, deposit })
            }
            CLOSE_CHANNEL_TAG => {
                let payer = TransactionPublicKey::read(buf)?;
                let open_nonce = u64::read(buf)?;
                let cumulative = u64::read(buf)?;
                let voucher = ed25519::Signature::read(buf)?;
                Ok(Self::CloseChannel {
                    payer,
                    open_nonce,
                    cumulative,
                    voucher,
                })
            }
            _ => Err(Error::Invalid("Operation", "unknown operation tag")),
        }
    }
}

/// A signed transaction accepted by the canonical block format.
#[derive(Debug, Clone)]
pub struct SignedTransaction<H>
where
    H: Hasher,
{
    inner: Sealed<Transaction<H::Digest>, H>,
    signature: TransactionSignature,
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
    /// Smallest possible encoded signed transaction.
    pub const MIN_ENCODED_SIZE: usize =
        Transaction::<H::Digest>::MIN_SIZE + TransactionSignature::MIN_SIZE;

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
    /// The operation this transaction performs.
    pub op: Operation,
    /// The digest type.
    pub _digest: core::marker::PhantomData<D>,
}

impl<D: Digest> Transaction<D> {
    /// Bytes shared by every transaction: the sender key and nonce.
    const COMMON_SIZE: usize = u64::SIZE + TransactionPublicKey::SIZE;
    /// Smallest possible encoded transaction.
    pub const MIN_SIZE: usize = Self::COMMON_SIZE + Operation::MIN_SIZE;
    /// Largest possible encoded transaction.
    pub const MAX_SIZE: usize = Self::COMMON_SIZE + Operation::MAX_SIZE;

    /// Creates a new transfer transaction.
    pub fn new(
        sender: TransactionPublicKey,
        to: TransactionPublicKey,
        value: NonZeroU64,
        nonce: u64,
    ) -> Self {
        Self::with_op(
            sender,
            nonce,
            Operation::Transfer {
                to: AccountKey::from_public_key(&to),
                value,
            },
        )
    }

    /// Creates a transaction that opens and funds a payment channel.
    ///
    /// The channel address is derived from this transaction's `nonce`, so the
    /// receiver settles by passing that same `nonce` to [`Self::close_channel`].
    pub fn open_channel(
        sender: TransactionPublicKey,
        receiver: TransactionPublicKey,
        deposit: NonZeroU64,
        nonce: u64,
    ) -> Self {
        Self::with_op(
            sender,
            nonce,
            Operation::OpenChannel {
                receiver: AccountKey::from_public_key(&receiver),
                deposit,
            },
        )
    }

    /// Creates a transaction that claims a voucher and settles a channel.
    ///
    /// The `sender` is the receiver; `payer` is the channel's payer; and
    /// `open_nonce` is the nonce of the `OpenChannel` that created the channel.
    pub fn close_channel(
        sender: TransactionPublicKey,
        payer: TransactionPublicKey,
        open_nonce: u64,
        cumulative: u64,
        voucher: ed25519::Signature,
        nonce: u64,
    ) -> Self {
        Self::with_op(
            sender,
            nonce,
            Operation::CloseChannel {
                payer,
                open_nonce,
                cumulative,
                voucher,
            },
        )
    }

    /// Creates a transaction from a sender, nonce, and operation.
    pub fn with_op(sender: TransactionPublicKey, nonce: u64, op: Operation) -> Self {
        Self {
            sender: Lazy::new(sender),
            nonce,
            op,
            _digest: core::marker::PhantomData,
        }
    }

    /// Returns the decoded sender public key.
    pub fn sender(&self) -> Option<&TransactionPublicKey> {
        self.sender.get()
    }

    /// Returns the lazily decoded sender public key.
    pub const fn sender_lazy(&self) -> &Lazy<TransactionPublicKey> {
        &self.sender
    }

    /// Returns the operation this transaction performs.
    pub const fn op(&self) -> &Operation {
        &self.op
    }

    /// Hashes the consensus-encoded transaction to produce a [`Digest`].
    ///
    /// If you want to cache the hash, consider using the [`Sealable`] trait.
    ///
    /// [`Digest`]: Digest
    pub fn hash_slow<H: Hasher>(&self, hasher: &mut H) -> H::Digest {
        hasher.update(&self.encode());
        hasher.finalize()
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
        self.op.write(buf);
    }
}

impl<D: Digest> EncodeSize for Transaction<D> {
    fn encode_size(&self) -> usize {
        Self::COMMON_SIZE + self.op.encode_size()
    }
}

impl<D: Digest> Read for Transaction<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let sender = Lazy::<TransactionPublicKey>::read(buf)?;
        let nonce = u64::read(buf)?;
        let op = Operation::read(buf)?;
        Ok(Self {
            sender,
            nonce,
            op,
            _digest: core::marker::PhantomData,
        })
    }
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
        let to = commonware_cryptography::ed25519::PublicKey::arbitrary(u)?;
        Ok(Self::new(
            TransactionPublicKey::ed25519(sender),
            TransactionPublicKey::ed25519(to),
            NonZeroU64::new(u.int_in_range(1..=u64::MAX)?)
                .expect("arbitrary non-zero value should construct"),
            u.arbitrary()?,
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Sealable;
    use arbitrary::{Arbitrary, unstructured::Unstructured};
    use commonware_codec::{DecodeExt, EncodeSize};
    use commonware_cryptography::{Signer, ed25519, sha256};
    use commonware_math::algebra::Random;
    use core::num::NonZeroU64;
    use rand::{SeedableRng, rngs::StdRng};

    fn test_sender() -> TransactionPublicKey {
        let mut rng = StdRng::from_seed([7u8; 32]);
        TransactionPublicKey::ed25519(ed25519::PrivateKey::random(&mut rng).public_key())
    }

    fn transfer_to(tx: &Transaction<sha256::Digest>) -> AccountKey {
        match tx.op() {
            Operation::Transfer { to, .. } => *to,
            _ => panic!("expected transfer"),
        }
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
    fn transaction_roundtrip() {
        let tx = Transaction::<sha256::Digest>::new(
            test_sender(),
            test_sender(),
            NonZeroU64::new(12_345).expect("test value should be non-zero"),
            1,
        );

        let mut buf = Vec::with_capacity(tx.encode_size());
        tx.write(&mut buf);

        let decoded =
            Transaction::<sha256::Digest>::decode(&mut &buf[..]).expect("decoding should succeed");
        assert_eq!(decoded, tx);
    }

    #[test]
    fn open_channel_roundtrip() {
        let tx = Transaction::<sha256::Digest>::open_channel(
            test_sender(),
            test_sender(),
            NonZeroU64::new(50).expect("deposit must be non-zero"),
            3,
        );

        let mut buf = Vec::with_capacity(tx.encode_size());
        tx.write(&mut buf);
        assert_eq!(buf.len(), tx.encode_size());

        let decoded =
            Transaction::<sha256::Digest>::decode(&mut &buf[..]).expect("decoding should succeed");
        assert_eq!(decoded, tx);
    }

    #[test]
    fn close_channel_roundtrip() {
        let mut rng = StdRng::from_seed([3u8; 32]);
        let payer = ed25519::PrivateKey::random(&mut rng);
        let voucher = payer.sign(b"voucher", b"message");
        let tx = Transaction::<sha256::Digest>::close_channel(
            test_sender(),
            TransactionPublicKey::ed25519(payer.public_key()),
            11,
            42,
            voucher,
            7,
        );

        let mut buf = Vec::with_capacity(tx.encode_size());
        tx.write(&mut buf);
        assert_eq!(buf.len(), tx.encode_size());

        let decoded =
            Transaction::<sha256::Digest>::decode(&mut &buf[..]).expect("decoding should succeed");
        assert_eq!(decoded, tx);
    }

    #[test]
    fn transaction_encode_size_matches_written() {
        let tx = Transaction::<sha256::Digest>::new(
            test_sender(),
            test_sender(),
            NonZeroU64::new(u64::MAX).expect("max value should be non-zero"),
            u64::MAX,
        );

        let expected = tx.encode_size();
        let mut buf = Vec::new();
        tx.write(&mut buf);
        assert_eq!(buf.len(), expected);
        assert!(buf.len() >= Transaction::<sha256::Digest>::MIN_SIZE);
        assert!(buf.len() <= Transaction::<sha256::Digest>::MAX_SIZE);
    }

    #[test]
    fn transaction_zero_value_decode_is_rejected() {
        let sender = test_sender();
        let tx = Transaction::<sha256::Digest>::new(
            sender.clone(),
            test_sender(),
            NonZeroU64::new(1).expect("test value should be non-zero"),
            7,
        );

        let mut buf = Vec::new();
        sender.write(&mut buf);
        tx.nonce.write(&mut buf);
        TRANSFER_TAG.write(&mut buf);
        transfer_to(&tx).write(&mut buf);
        0u64.write(&mut buf);

        let result = Transaction::<sha256::Digest>::decode(&mut &buf[..]);
        assert!(result.is_err(), "zero-value transactions must be rejected");
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
        TRANSFER_TAG.write(&mut buf);
        AccountKey::from_public_key(&test_sender()).write(&mut buf);
        1u64.write(&mut buf);

        let decoded = Transaction::<sha256::Digest>::decode(&mut &buf[..])
            .expect("decoding should defer sender validation");

        assert!(decoded.sender().is_none());
    }
}
