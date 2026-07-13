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
const TIMEOUT_CHANNEL_TAG: u8 = 3;
const MINT_TAG: u8 = 4;

/// `OpenChannel` expiry meaning the payer can never reclaim unilaterally.
pub const CHANNEL_NEVER_EXPIRES: u64 = u64::MAX;

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
    /// Open and fund a payment channel from the sender (payer) to `receiver`,
    /// settled by `operator`.
    ///
    /// The channel account address is derived from
    /// `(sender, receiver, operator, voucher_key, open_nonce)`, where
    /// `open_nonce` is this transaction's own nonce. Because account nonces
    /// are monotonic and never reused, every open yields a unique,
    /// never-recurring channel address, so
    /// the address is reconstructible without being stored, a settled channel
    /// can be deleted, and old vouchers can never be replayed against a new
    /// channel. The sender is debited `deposit`, which is added to the
    /// channel's escrow (a fresh address starts from zero).
    ///
    /// Naming the operator in the derivation is what lets a payee delegate
    /// settlement (x402-style facilitation) without handing over its key: only
    /// the operator's key can close the channel, but the settled cumulative is
    /// always paid to `receiver`. A payee that settles for itself names itself
    /// (`operator == receiver`).
    OpenChannel {
        /// The receiver (payee) account key the settled cumulative is paid to.
        receiver: AccountKey,
        /// The account whose key may settle the channel with a close.
        operator: AccountKey,
        /// The delegated Ed25519 key that signs this channel's vouchers. An
        /// authority, not an account: it can authorize payments from this
        /// channel's escrow to `receiver`, and nothing else. Naming it here
        /// is what lets any account — including one whose own key demands a
        /// user ceremony per signature — pay through a channel.
        voucher_key: ed25519::PublicKey,
        /// The amount escrowed into the channel.
        deposit: NonZeroU64,
        /// Block height after which the payer may unilaterally reclaim the
        /// escrow with [`Operation::TimeoutChannel`]. The operator can settle
        /// with a close at any height while the channel exists, so this is
        /// effectively the operator's settlement deadline.
        /// [`CHANNEL_NEVER_EXPIRES`] disables the timeout path.
        expiry: u64,
    },
    /// Claim a voucher and settle a payment channel.
    ///
    /// The sender is the operator. The channel address is recomputed from
    /// `(payer, receiver, sender, voucher_key, open_nonce)`; `cumulative` of
    /// the escrow is paid to `receiver` and the remainder is returned to the
    /// payer, closing the channel. `voucher` is the voucher key's signature
    /// over the voucher message (see [`crate::voucher_message`]) — the address
    /// it signs commits to the participants and the key, so a voucher cannot
    /// be redirected to a different payee or settler, and a closer cannot
    /// substitute a voucher key it controls.
    CloseChannel {
        /// The payer's account key (authenticated by the channel address);
        /// the escrow remainder refunds here.
        payer: AccountKey,
        /// The receiver (payee) account key the cumulative is paid to.
        receiver: AccountKey,
        /// The delegated voucher key the channel was opened with.
        voucher_key: ed25519::PublicKey,
        /// The nonce of the `OpenChannel` transaction that created the channel.
        open_nonce: u64,
        /// The cumulative amount claimed for the receiver.
        cumulative: u64,
        /// The voucher key's signature over `(channel_id, cumulative)`.
        voucher: ed25519::Signature,
    },
    /// Reclaim an expired payment channel's escrow.
    ///
    /// The sender is the payer. The channel address is recomputed from
    /// `(sender, receiver, operator, voucher_key, open_nonce)`; once the block
    /// height exceeds the expiry the channel was opened with, the payer
    /// reclaims the entire escrow (vouchers the operator failed to settle in
    /// time are voided) and the channel is deleted. Until then only the
    /// operator's close can move the escrow; if a close lands first the
    /// channel is gone and the timeout is rejected.
    TimeoutChannel {
        /// The receiver (payee) account key the channel was opened to.
        receiver: AccountKey,
        /// The operator account key the channel was opened with.
        operator: AccountKey,
        /// The delegated voucher key the channel was opened with.
        voucher_key: ed25519::PublicKey,
        /// The nonce of the `OpenChannel` transaction that created the channel.
        open_nonce: u64,
    },
    /// Mint `amount` new tokens to the sender.
    ///
    /// This demo chain's explicit (and only) token source: accounts start
    /// empty and mint what they need. The mint is deliberately permissionless
    /// but capped at [`Self::MAX_MINT_AMOUNT`] per transaction: minting can
    /// be repeated, but block size and block rate bound the chain's
    /// transaction throughput, so the cap bounds how fast supply (or any one
    /// balance) can grow — reaching `u64::MAX` would take years of
    /// monopolizing the whole chain. Amounts above the cap are rejected at
    /// decode, like zero amounts.
    Mint {
        /// The amount credited to the sender.
        amount: NonZeroU64,
    },
}

impl Operation {
    /// Largest amount a single [`Self::Mint`] may credit (see the variant's
    /// docs for why a per-transaction cap is meaningful on a feeless chain).
    pub const MAX_MINT_AMOUNT: u64 = 1_000_000;
    /// Encoded size of a transfer: tag, recipient, and value.
    const TRANSFER_SIZE: usize = 1 + AccountKey::SIZE + u64::SIZE;
    /// Encoded size of a channel open: tag, receiver, operator, voucher key,
    /// deposit, and expiry.
    const OPEN_CHANNEL_SIZE: usize =
        1 + AccountKey::SIZE + AccountKey::SIZE + ed25519::PublicKey::SIZE + u64::SIZE + u64::SIZE;
    /// Encoded size of a channel close: tag, payer, receiver, voucher key,
    /// open nonce, cumulative, and voucher.
    const CLOSE_CHANNEL_SIZE: usize = 1
        + AccountKey::SIZE
        + AccountKey::SIZE
        + ed25519::PublicKey::SIZE
        + u64::SIZE
        + u64::SIZE
        + ed25519::Signature::SIZE;
    /// Encoded size of a channel timeout: tag, receiver, operator, voucher
    /// key, and open nonce.
    const TIMEOUT_CHANNEL_SIZE: usize =
        1 + AccountKey::SIZE + AccountKey::SIZE + ed25519::PublicKey::SIZE + u64::SIZE;
    /// Encoded size of a mint: tag and amount.
    const MINT_SIZE: usize = 1 + u64::SIZE;
    /// Smallest encoded operation (a mint).
    pub const MIN_SIZE: usize = Self::MINT_SIZE;
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
            Self::OpenChannel {
                receiver,
                operator,
                voucher_key,
                deposit,
                expiry,
            } => {
                OPEN_CHANNEL_TAG.write(buf);
                receiver.write(buf);
                operator.write(buf);
                voucher_key.write(buf);
                deposit.get().write(buf);
                expiry.write(buf);
            }
            Self::CloseChannel {
                payer,
                receiver,
                voucher_key,
                open_nonce,
                cumulative,
                voucher,
            } => {
                CLOSE_CHANNEL_TAG.write(buf);
                payer.write(buf);
                receiver.write(buf);
                voucher_key.write(buf);
                open_nonce.write(buf);
                cumulative.write(buf);
                voucher.write(buf);
            }
            Self::TimeoutChannel {
                receiver,
                operator,
                voucher_key,
                open_nonce,
            } => {
                TIMEOUT_CHANNEL_TAG.write(buf);
                receiver.write(buf);
                operator.write(buf);
                voucher_key.write(buf);
                open_nonce.write(buf);
            }
            Self::Mint { amount } => {
                MINT_TAG.write(buf);
                amount.get().write(buf);
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
            Self::TimeoutChannel { .. } => Self::TIMEOUT_CHANNEL_SIZE,
            Self::Mint { .. } => Self::MINT_SIZE,
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
                let operator = AccountKey::read(buf)?;
                let voucher_key = ed25519::PublicKey::read(buf)?;
                let deposit = u64::read(buf)?;
                let deposit = NonZeroU64::new(deposit)
                    .ok_or(Error::Invalid("Operation", "deposit must be non-zero"))?;
                let expiry = u64::read(buf)?;
                Ok(Self::OpenChannel {
                    receiver,
                    operator,
                    voucher_key,
                    deposit,
                    expiry,
                })
            }
            CLOSE_CHANNEL_TAG => {
                let payer = AccountKey::read(buf)?;
                let receiver = AccountKey::read(buf)?;
                let voucher_key = ed25519::PublicKey::read(buf)?;
                let open_nonce = u64::read(buf)?;
                // `cumulative` may be zero: a zero voucher is a cooperative
                // early cancel (full refund, no payment).
                let cumulative = u64::read(buf)?;
                let voucher = ed25519::Signature::read(buf)?;
                Ok(Self::CloseChannel {
                    payer,
                    receiver,
                    voucher_key,
                    open_nonce,
                    cumulative,
                    voucher,
                })
            }
            TIMEOUT_CHANNEL_TAG => {
                let receiver = AccountKey::read(buf)?;
                let operator = AccountKey::read(buf)?;
                let voucher_key = ed25519::PublicKey::read(buf)?;
                let open_nonce = u64::read(buf)?;
                Ok(Self::TimeoutChannel {
                    receiver,
                    operator,
                    voucher_key,
                    open_nonce,
                })
            }
            MINT_TAG => {
                let amount = u64::read(buf)?;
                let amount = NonZeroU64::new(amount)
                    .ok_or(Error::Invalid("Operation", "mint amount must be non-zero"))?;
                if amount.get() > Self::MAX_MINT_AMOUNT {
                    return Err(Error::Invalid("Operation", "mint amount exceeds the cap"));
                }
                Ok(Self::Mint { amount })
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

    /// Creates a transfer transaction.
    pub fn transfer(
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
    /// `receiver` is an account key, not a public key: a payee that only ever
    /// gets paid (the operator settles on its behalf) needs no key at all.
    /// `voucher_key` is the delegated Ed25519 key that will sign this
    /// channel's vouchers — the sender itself may be any scheme.
    ///
    /// The channel address is derived from this transaction's `nonce`, so the
    /// operator settles by passing that same `nonce` to [`Self::close_channel`].
    /// After block height `expiry` the payer may reclaim the escrow with
    /// [`Self::timeout_channel`]; pass [`CHANNEL_NEVER_EXPIRES`] to disable.
    pub fn open_channel(
        sender: TransactionPublicKey,
        receiver: AccountKey,
        operator: AccountKey,
        voucher_key: ed25519::PublicKey,
        deposit: NonZeroU64,
        expiry: u64,
        nonce: u64,
    ) -> Self {
        Self::with_op(
            sender,
            nonce,
            Operation::OpenChannel {
                receiver,
                operator,
                voucher_key,
                deposit,
                expiry,
            },
        )
    }

    /// Creates a transaction that claims a voucher and settles a channel.
    ///
    /// The `sender` is the operator; `payer` is the channel's payer account;
    /// `receiver` is the payee the cumulative is paid to; `voucher_key` and
    /// `open_nonce` identify the channel exactly as they did at
    /// [`Self::open_channel`].
    // One parameter per wire field of `Operation::CloseChannel` (plus sender
    // and nonce); grouping them would just restate the operation struct.
    #[allow(clippy::too_many_arguments)]
    pub fn close_channel(
        sender: TransactionPublicKey,
        payer: AccountKey,
        receiver: AccountKey,
        voucher_key: ed25519::PublicKey,
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
                receiver,
                voucher_key,
                open_nonce,
                cumulative,
                voucher,
            },
        )
    }

    /// Creates a transaction that reclaims an expired channel's escrow.
    ///
    /// The `sender` is the payer; `receiver`, `operator`, `voucher_key`, and
    /// `open_nonce` identify the channel exactly as they did at
    /// [`Self::open_channel`]. Valid only once the block height exceeds the
    /// channel's expiry.
    pub fn timeout_channel(
        sender: TransactionPublicKey,
        receiver: AccountKey,
        operator: AccountKey,
        voucher_key: ed25519::PublicKey,
        open_nonce: u64,
        nonce: u64,
    ) -> Self {
        Self::with_op(
            sender,
            nonce,
            Operation::TimeoutChannel {
                receiver,
                operator,
                voucher_key,
                open_nonce,
            },
        )
    }

    /// Creates a transaction that mints `amount` new tokens to the sender.
    ///
    /// The chain's explicit token source: accounts start empty and mint what
    /// they need (see [`Operation::Mint`]). Amounts above
    /// [`Operation::MAX_MINT_AMOUNT`] encode fine but are rejected wherever
    /// the transaction is decoded, so they never enter a mempool or block.
    pub fn mint(sender: TransactionPublicKey, amount: NonZeroU64, nonce: u64) -> Self {
        Self::with_op(sender, nonce, Operation::Mint { amount })
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
        Ok(Self::transfer(
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
    use commonware_codec::{DecodeExt, Encode};
    use commonware_cryptography::{Signer, ed25519, sha256};
    use commonware_math::algebra::Random;
    use core::num::NonZeroU64;
    use rand::{SeedableRng, rngs::StdRng};

    fn test_sender() -> TransactionPublicKey {
        let mut rng = StdRng::from_seed([7u8; 32]);
        TransactionPublicKey::ed25519(ed25519::PrivateKey::random(&mut rng).public_key())
    }

    /// Encodes `tx` (`encode` itself asserts the size accounting) and asserts
    /// it decodes back to an equal transaction.
    fn assert_roundtrip(tx: Transaction<sha256::Digest>) {
        let buf = tx.encode();
        let decoded =
            Transaction::<sha256::Digest>::decode(&mut &buf[..]).expect("decoding should succeed");
        assert_eq!(decoded, tx);
    }

    /// Hand-encodes a mint of `amount` (bypassing the typed constructor's
    /// bounds) and attempts to decode it.
    fn decode_mint(amount: u64) -> Result<Transaction<sha256::Digest>, commonware_codec::Error> {
        let mut buf = Vec::new();
        test_sender().write(&mut buf);
        3u64.write(&mut buf);
        MINT_TAG.write(&mut buf);
        amount.write(&mut buf);
        Transaction::<sha256::Digest>::decode(&mut &buf[..])
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
        assert_roundtrip(Transaction::<sha256::Digest>::transfer(
            test_sender(),
            test_sender(),
            NonZeroU64::new(12_345).expect("test value should be non-zero"),
            1,
        ));
    }

    fn test_voucher_key() -> ed25519::PrivateKey {
        let mut rng = StdRng::from_seed([5u8; 32]);
        ed25519::PrivateKey::random(&mut rng)
    }

    #[test]
    fn open_channel_roundtrip() {
        assert_roundtrip(Transaction::<sha256::Digest>::open_channel(
            test_sender(),
            AccountKey::from_public_key(&test_sender()),
            AccountKey::from_public_key(&test_sender()),
            test_voucher_key().public_key(),
            NonZeroU64::new(50).expect("deposit must be non-zero"),
            1_000,
            3,
        ));
    }

    #[test]
    fn mint_roundtrip() {
        assert_roundtrip(Transaction::<sha256::Digest>::mint(
            test_sender(),
            NonZeroU64::new(1_000).expect("amount must be non-zero"),
            2,
        ));
    }

    #[test]
    fn zero_mint_decode_is_rejected() {
        assert!(
            decode_mint(0).is_err(),
            "zero-amount mints must be rejected"
        );
    }

    #[test]
    fn mint_above_cap_decode_is_rejected() {
        assert!(
            decode_mint(Operation::MAX_MINT_AMOUNT + 1).is_err(),
            "mints above the cap must be rejected"
        );
    }

    #[test]
    fn mint_at_cap_roundtrips() {
        assert_roundtrip(Transaction::<sha256::Digest>::mint(
            test_sender(),
            NonZeroU64::new(Operation::MAX_MINT_AMOUNT).expect("cap is non-zero"),
            2,
        ));
    }

    #[test]
    fn timeout_channel_roundtrip() {
        assert_roundtrip(Transaction::<sha256::Digest>::timeout_channel(
            test_sender(),
            AccountKey::from_public_key(&test_sender()),
            AccountKey::from_public_key(&test_sender()),
            test_voucher_key().public_key(),
            3,
            9,
        ));
    }

    #[test]
    fn close_channel_roundtrip() {
        let key = test_voucher_key();
        let voucher = key.sign(b"voucher", b"message");
        assert_roundtrip(Transaction::<sha256::Digest>::close_channel(
            test_sender(),
            AccountKey::from_public_key(&test_sender()),
            AccountKey::from_public_key(&test_sender()),
            key.public_key(),
            11,
            42,
            voucher,
            7,
        ));
    }

    #[test]
    fn zero_cumulative_close_roundtrips() {
        // A zero-cumulative close is a cooperative early cancel; it must stay
        // decodable (the execution lane skips the empty receiver credit).
        let key = test_voucher_key();
        let voucher = key.sign(b"voucher", b"message");
        assert_roundtrip(Transaction::<sha256::Digest>::close_channel(
            test_sender(),
            AccountKey::from_public_key(&test_sender()),
            AccountKey::from_public_key(&test_sender()),
            key.public_key(),
            11,
            0,
            voucher,
            7,
        ));
    }

    #[test]
    fn transaction_zero_value_decode_is_rejected() {
        let mut buf = Vec::new();
        test_sender().write(&mut buf);
        7u64.write(&mut buf);
        TRANSFER_TAG.write(&mut buf);
        AccountKey::from_public_key(&test_sender()).write(&mut buf);
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
