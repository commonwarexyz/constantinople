//! Block and header types for the Constantinople chain.
//!
//! This module defines:
//!
//! - [`Header`] - The execution header.
//! - [`Block`] - Execution payload and required consensus metadata.

use crate::{Sealable, Sealed, Signed, Verified, transaction::{Transaction, TransactionCfg}};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_consensus::{
    Block as ConsensusBlock, CertifiableBlock, Heightable, simplex::types::Context, types::Height,
};
use commonware_cryptography::{Digest, Hasher, PublicKey, Verifier};
use commonware_utils::range::NonEmptyRange;

/// A block header containing metadata, consensus context, and state commitment roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header<C, D, P>
where
    C: Digest,
    D: Digest,
    P: PublicKey,
{
    /// Consensus context required for certifiable block execution.
    pub context: Context<C, P>,
    /// The digest of the parent block.
    pub parent: D,
    /// The height of the block.
    pub height: u64,
    /// The timestamp of the block.
    pub timestamp: u64,
    /// A root of the chain state after applying this block.
    pub state_root: D,
    /// The active range of the state database.
    pub state_range: NonEmptyRange<u64>,
    /// A root of all transactions in the history, including those within this block.
    pub transactions_root: D,
    /// The active range of the transactions database.
    pub transactions_range: NonEmptyRange<u64>,
    /// A root of all transaction receipts in this block.
    pub receipts_root: D,
}

impl<C, D, P> Header<C, D, P>
where
    C: Digest,
    D: Digest,
    P: PublicKey,
{
    /// Hashes the encoded header to produce a digest.
    pub fn hash_slow<H: Hasher<Digest = D>>(&self, hasher: &mut H) -> D {
        hasher.reset();
        hasher.update(self.encode().as_ref());
        hasher.finalize()
    }
}

impl<C, D, P> EncodeSize for Header<C, D, P>
where
    C: Digest,
    D: Digest,
    P: PublicKey,
{
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.timestamp.encode_size()
            + self.state_root.encode_size()
            + self.state_range.encode_size()
            + self.transactions_root.encode_size()
            + self.transactions_range.encode_size()
            + self.receipts_root.encode_size()
    }
}

impl<C, D, P> Write for Header<C, D, P>
where
    C: Digest,
    D: Digest,
    P: PublicKey,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.timestamp.write(buf);
        self.state_root.write(buf);
        self.state_range.write(buf);
        self.transactions_root.write(buf);
        self.transactions_range.write(buf);
        self.receipts_root.write(buf);
    }
}

impl<C, D, P> Read for Header<C, D, P>
where
    C: Digest,
    D: Digest,
    P: PublicKey,
{
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let _ = cfg;
        Ok(Self {
            context: Context::read(buf)?,
            parent: D::read(buf)?,
            height: u64::read(buf)?,
            timestamp: u64::read(buf)?,
            state_root: D::read(buf)?,
            state_range: NonEmptyRange::read(buf)?,
            transactions_root: D::read(buf)?,
            transactions_range: NonEmptyRange::read(buf)?,
            receipts_root: D::read(buf)?,
        })
    }
}

#[cfg(any(feature = "arbitrary", test))]
impl<C, D, P> arbitrary::Arbitrary<'_> for Header<C, D, P>
where
    C: Digest + for<'a> arbitrary::Arbitrary<'a>,
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            context: u.arbitrary()?,
            parent: u.arbitrary()?,
            height: u.arbitrary()?,
            timestamp: u.arbitrary()?,
            state_root: u.arbitrary()?,
            state_range: u.arbitrary()?,
            transactions_root: u.arbitrary()?,
            transactions_range: u.arbitrary()?,
            receipts_root: u.arbitrary()?,
        })
    }
}

/// Codec configuration for decoding a [`Block`].
#[derive(Clone, Debug)]
pub struct BlockCfg {
    /// Maximum number of transactions in the block body.
    pub max_transactions: RangeCfg<usize>,
    /// Codec configuration for individual transactions.
    pub transaction: TransactionCfg,
}

impl Default for BlockCfg {
    fn default() -> Self {
        Self {
            max_transactions: RangeCfg::new(0..=usize::MAX),
            transaction: TransactionCfg::default(),
        }
    }
}

/// A block containing execution transactions and required epoch-consensus metadata.
pub type SignedTransaction<P, H> =
    Signed<Transaction<<H as Hasher>::Digest, P>, H, <P as Verifier>::Signature>;

/// A verified transaction paired with its cached sender address.
pub type VerifiedTransaction<P, H> =
    Verified<Transaction<<H as Hasher>::Digest, P>, H, <P as Verifier>::Signature>;

/// The canonical signed block type used for encoding and consensus.
pub type SignedBlock<C, P, H> = Block<C, P, H, SignedTransaction<P, H>>;

/// The in-memory verified block type used for execution.
pub type VerifiedBlock<C, P, H> = Block<C, P, H, VerifiedTransaction<P, H>>;

/// A block containing execution transactions and required epoch-consensus metadata.
#[derive(Debug, Clone)]
pub struct Block<C, P, H, Tx = SignedTransaction<P, H>>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    /// The execution header.
    pub header: Header<C, H::Digest, P>,
    /// Ordered transactions included in this execution payload.
    pub body: Vec<Tx>,
}

#[cfg(any(feature = "arbitrary", test))]
impl<C, P, H, Tx> arbitrary::Arbitrary<'_> for Block<C, P, H, Tx>
where
    C: Digest + for<'a> arbitrary::Arbitrary<'a>,
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    H: Hasher,
    H::Digest: for<'a> arbitrary::Arbitrary<'a>,
    Tx: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            header: u.arbitrary()?,
            body: u.arbitrary()?,
        })
    }
}

impl<C, P, H, Tx> PartialEq for Block<C, P, H, Tx>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    Tx: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header && self.body == other.body
    }
}

impl<C, P, H, Tx> Eq for Block<C, P, H, Tx>
where
    C: Digest,
    P: PublicKey + Eq,
    H: Hasher,
    H::Digest: Eq,
    Tx: Eq,
{
}

impl<C, P, H, Tx> Block<C, P, H, Tx>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    /// Creates a new block.
    pub const fn new(header: Header<C, H::Digest, P>, body: Vec<Tx>) -> Self {
        Self { header, body }
    }
}

impl<C, P, H, Tx> EncodeSize for Block<C, P, H, Tx>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    Tx: EncodeSize,
{
    fn encode_size(&self) -> usize {
        self.header.encode_size() + self.body.encode_size()
    }
}

impl<C, P, H, Tx> Write for Block<C, P, H, Tx>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    Tx: Write,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.header.write(buf);
        self.body.write(buf);
    }
}

impl<C, P, H> Read for SignedBlock<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    type Cfg = BlockCfg;

    fn read_cfg(buf: &mut impl bytes::Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let tx_vec_cfg = (cfg.max_transactions, cfg.transaction.clone());
        Ok(Self {
            header: Header::read_cfg(buf, &())?,
            body: Vec::read_cfg(buf, &tx_vec_cfg)?,
        })
    }
}

impl<C, P, H, Tx> Sealable for Block<C, P, H, Tx>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    type SealDigest = H::Digest;

    fn seal<T: Hasher<Digest = Self::SealDigest>>(self, hasher: &mut T) -> Sealed<Self, T>
    where
        Self: Sized,
    {
        let digest = self.header.hash_slow(hasher);

        Sealed::new_unchecked(self, digest)
    }
}

impl<C, P, H, Tx> Heightable for Sealed<Block<C, P, H, Tx>, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    fn height(&self) -> Height {
        Height::new(self.header.height)
    }
}

impl<C, P, H> ConsensusBlock for Sealed<SignedBlock<C, P, H>, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    fn parent(&self) -> Self::Digest {
        self.header.parent
    }
}

impl<C, P, H> CertifiableBlock for Sealed<SignedBlock<C, P, H>, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    type Context = Context<C, P>;

    fn context(&self) -> Self::Context {
        self.header.context.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Decode;
    use commonware_consensus::{
        simplex::types::Context,
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{Signer, blake3, ed25519};
    use commonware_math::algebra::Random;
    use commonware_utils::non_empty_range;
    use rand::{SeedableRng, rngs::StdRng};

    fn test_context() -> Context<blake3::Digest, ed25519::PublicKey> {
        let mut rng = StdRng::from_seed([7u8; 32]);
        let leader = ed25519::PrivateKey::random(&mut rng).public_key();
        Context {
            round: Round::new(Epoch::zero(), View::zero()),
            leader,
            parent: (View::zero(), blake3::Digest::EMPTY),
        }
    }

    fn test_header() -> Header<blake3::Digest, blake3::Digest, ed25519::PublicKey> {
        Header {
            context: test_context(),
            parent: blake3::Digest::EMPTY,
            height: 42,
            timestamp: 1000,
            state_root: blake3::Digest::EMPTY,
            state_range: non_empty_range!(0, 1),
            transactions_root: blake3::Digest::EMPTY,
            transactions_range: non_empty_range!(0, 1),
            receipts_root: blake3::Digest::EMPTY,
        }
    }

    #[test]
    fn header_codec_roundtrip() {
        let header = test_header();

        let mut buf = Vec::with_capacity(header.encode_size());
        header.write(&mut buf);

        let decoded = Header::<blake3::Digest, blake3::Digest, ed25519::PublicKey>::decode_cfg(
            &mut &buf[..],
            &(),
        )
        .expect("decoding should succeed");
        assert_eq!(decoded, header);
    }

    #[test]
    fn header_encode_size_matches_written() {
        let header = test_header();
        let expected = header.encode_size();

        let mut buf = Vec::new();
        header.write(&mut buf);
        assert_eq!(buf.len(), expected);
    }

    #[test]
    fn block_codec_roundtrip_empty_body() {
        let block = Block::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>::new(
            test_header(),
            vec![],
        );

        let mut buf = Vec::with_capacity(block.encode_size());
        block.write(&mut buf);

        let decoded = Block::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>::decode_cfg(
            &mut &buf[..],
            &BlockCfg::default(),
        )
        .expect("decoding should succeed");
        assert_eq!(decoded, block);
    }

    #[test]
    fn block_encode_size_matches_written() {
        let block = Block::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>::new(
            test_header(),
            vec![],
        );
        let expected = block.encode_size();

        let mut buf = Vec::new();
        block.write(&mut buf);
        assert_eq!(buf.len(), expected);
    }
}
