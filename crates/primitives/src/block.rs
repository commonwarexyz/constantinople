//! Block and header types for the Constantinople chain.
//!
//! This module defines:
//!
//! - [`Header`] - The execution header.
//! - [`Block`] - Execution payload and required consensus metadata.

use crate::{LazySignedTransaction, Sealable, Sealed, SignedTransaction};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_consensus::{
    Block as ConsensusBlock, CertifiableBlock, Heightable, simplex::types::Context, types::Height,
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
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
    /// The canonical root of the chain state after applying this block.
    pub state_root: D,
    /// The retained range needed to sync the state database.
    pub state_range: NonEmptyRange<u64>,
    /// A root of all transactions in the history, including those within this block.
    pub transactions_root: D,
    /// The active range of the transactions database.
    pub transactions_range: NonEmptyRange<u64>,
}

impl<C, D, P> Header<C, D, P>
where
    C: Digest,
    D: Digest,
    P: PublicKey,
{
    /// Hashes the encoded header to produce a digest.
    pub fn hash_slow<H: Hasher<Digest = D>>(&self, hasher: &mut H) -> D {
        hasher.update(self.encode().as_ref());
        hasher.finalize()
    }
}

impl<C, D, P> Sealable for Header<C, D, P>
where
    C: Digest,
    D: Digest,
    P: PublicKey,
{
    type SealDigest = D;

    fn seal<H: Hasher<Digest = Self::SealDigest>>(self, hasher: &mut H) -> Sealed<Self, H>
    where
        Self: Sized,
    {
        let digest = self.hash_slow(hasher);
        Sealed::new_unchecked(self, digest)
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
    }
}

impl<C, D, P> Read for Header<C, D, P>
where
    C: Digest,
    D: Digest,
    P: PublicKey,
{
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            context: Context::read(buf)?,
            parent: D::read(buf)?,
            height: u64::read(buf)?,
            timestamp: u64::read(buf)?,
            state_root: D::read(buf)?,
            state_range: NonEmptyRange::read(buf)?,
            transactions_root: D::read(buf)?,
            transactions_range: NonEmptyRange::read(buf)?,
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
        })
    }
}

/// Codec configuration for decoding a [`Block`].
#[derive(Clone, Debug)]
pub struct BlockCfg {
    /// Maximum number of transactions in the block body.
    pub max_transactions: RangeCfg<usize>,
}

impl Default for BlockCfg {
    fn default() -> Self {
        Self {
            max_transactions: RangeCfg::new(0..=usize::MAX),
        }
    }
}

/// A block containing signed transactions and required epoch-consensus metadata.
#[derive(Debug, Clone)]
pub struct Block<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    /// The execution header.
    pub header: Header<C, H::Digest, P>,
    /// Ordered transactions included in this execution payload.
    ///
    /// Each transaction is held in a [`LazySignedTransaction`] so block
    /// decoding does not pay the per-transaction decode + seal-hash cost on the
    /// caller's thread. Materialization is typically driven in parallel at
    /// verify time via a [`commonware_parallel::Strategy`].
    pub body: Vec<LazySignedTransaction<H>>,
}

/// A sealed canonical block.
pub type SealedBlock<C, P, H> = Sealed<Block<C, P, H>, H>;

#[cfg(any(feature = "arbitrary", test))]
impl<C, P, H> arbitrary::Arbitrary<'_> for Block<C, P, H>
where
    C: Digest + for<'a> arbitrary::Arbitrary<'a>,
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    H: Hasher,
    H::Digest: for<'a> arbitrary::Arbitrary<'a>,
    SignedTransaction<H>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let body: Vec<SignedTransaction<H>> = u.arbitrary()?;
        Ok(Self {
            header: u.arbitrary()?,
            body: body.into_iter().map(LazySignedTransaction::new).collect(),
        })
    }
}

impl<C, P, H> PartialEq for Block<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header && self.body == other.body
    }
}

impl<C, P, H> Eq for Block<C, P, H>
where
    C: Digest,
    P: PublicKey + Eq,
    H: Hasher,
    H::Digest: Eq,
{
}

impl<C, P, H> Block<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    /// Creates a new block from already-decoded transactions.
    pub fn new(header: Header<C, H::Digest, P>, body: Vec<SignedTransaction<H>>) -> Self {
        Self {
            header,
            body: body.into_iter().map(LazySignedTransaction::new).collect(),
        }
    }
}

impl<C, P, H> EncodeSize for Block<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    fn encode_size(&self) -> usize {
        self.header.encode_size() + self.body.encode_size()
    }
}

impl<C, P, H> Write for Block<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.header.write(buf);
        self.body.write(buf);
    }
}

impl<C, P, H> Read for Block<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    type Cfg = BlockCfg;

    fn read_cfg(buf: &mut impl bytes::Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let tx_vec_cfg = (cfg.max_transactions, ());
        Ok(Self {
            header: Header::read_cfg(buf, &())?,
            body: Vec::read_cfg(buf, &tx_vec_cfg)?,
        })
    }
}

impl<C, P, H> Sealable for Block<C, P, H>
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

impl<C, P, H> Heightable for Sealed<Block<C, P, H>, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    fn height(&self) -> Height {
        Height::new(self.header.height)
    }
}

impl<C, P, H> Heightable for Sealed<Header<C, H::Digest, P>, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    fn height(&self) -> Height {
        Height::new(self.height)
    }
}

impl<C, P, H> ConsensusBlock for Sealed<Block<C, P, H>, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    fn parent(&self) -> Self::Digest {
        self.header.parent
    }
}

impl<C, P, H> ConsensusBlock for Sealed<Header<C, H::Digest, P>, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    fn parent(&self) -> Self::Digest {
        self.parent
    }
}

impl<C, P, H> CertifiableBlock for Sealed<Block<C, P, H>, H>
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

impl<C, P, H> CertifiableBlock for Sealed<Header<C, H::Digest, P>, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    type Context = Context<C, P>;

    fn context(&self) -> Self::Context {
        self.context.clone()
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
    use commonware_cryptography::{Signer, ed25519, secp256r1::standard as secp256r1, sha256};
    use commonware_math::algebra::Random;
    use commonware_utils::non_empty_range;
    use rand::{SeedableRng, rngs::StdRng};

    fn test_context() -> Context<sha256::Digest, ed25519::PublicKey> {
        let mut rng = StdRng::from_seed([7u8; 32]);
        let leader = ed25519::PrivateKey::random(&mut rng).public_key();
        Context {
            round: Round::new(Epoch::zero(), View::zero()),
            leader,
            parent: (View::zero(), sha256::Digest::EMPTY),
        }
    }

    fn test_header() -> Header<sha256::Digest, sha256::Digest, ed25519::PublicKey> {
        Header {
            context: test_context(),
            parent: sha256::Digest::EMPTY,
            height: 42,
            timestamp: 1000,
            state_root: sha256::Digest::EMPTY,
            state_range: non_empty_range!(0, 1),
            transactions_root: sha256::Digest::EMPTY,
            transactions_range: non_empty_range!(0, 1),
        }
    }

    #[test]
    fn header_codec_roundtrip() {
        let header = test_header();

        let mut buf = Vec::with_capacity(header.encode_size());
        header.write(&mut buf);

        let decoded = Header::<sha256::Digest, sha256::Digest, ed25519::PublicKey>::decode_cfg(
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
        let block =
            Block::<sha256::Digest, ed25519::PublicKey, sha256::Sha256>::new(test_header(), vec![]);

        let mut buf = Vec::with_capacity(block.encode_size());
        block.write(&mut buf);

        let decoded = Block::<sha256::Digest, ed25519::PublicKey, sha256::Sha256>::decode_cfg(
            &mut &buf[..],
            &BlockCfg::default(),
        )
        .expect("decoding should succeed");
        assert_eq!(decoded, block);
    }

    #[test]
    fn block_encode_size_matches_written() {
        let block =
            Block::<sha256::Digest, ed25519::PublicKey, sha256::Sha256>::new(test_header(), vec![]);
        let expected = block.encode_size();

        let mut buf = Vec::new();
        block.write(&mut buf);
        assert_eq!(buf.len(), expected);
    }

    #[test]
    fn block_decode_consumes_webauthn_transaction_bytes() {
        let mut rng = StdRng::from_seed([9u8; 32]);
        let signer = secp256r1::PrivateKey::random(&mut rng);
        let public_key = crate::TransactionPublicKey::secp256r1(signer.public_key());
        let transaction = crate::Transaction::<sha256::Digest>::new(
            public_key.clone(),
            public_key,
            core::num::NonZeroU64::new(1).expect("test value should be non-zero"),
            0,
        );
        let sealed = transaction.seal(&mut sha256::Sha256::default());
        let signature = crate::TransactionSignature::secp256r1(
            signer.sign(crate::TRANSACTION_NAMESPACE, sealed.seal().as_ref()),
            vec![0; 37],
            br#"{"type":"webauthn.get","challenge":"test"}"#.to_vec(),
        )
        .expect("test WebAuthn signature should encode");
        let signed = crate::SignedTransaction::new_unchecked(sealed, signature);
        let block = Block::<sha256::Digest, ed25519::PublicKey, sha256::Sha256>::new(
            test_header(),
            vec![signed],
        );

        let encoded = block.encode();
        let mut reader = encoded.as_ref();
        let _decoded =
            <Block<sha256::Digest, ed25519::PublicKey, sha256::Sha256> as commonware_codec::Read>::read_cfg(
                &mut reader,
                &BlockCfg::default(),
            )
            .expect("block should decode");

        assert!(reader.is_empty(), "block decoder left trailing bytes");
    }
}
