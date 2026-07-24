//! Block and header types for the Constantinople chain.
//!
//! This module defines:
//!
//! - [`Header`] - The execution header.
//! - [`Block`] - Execution payload and required consensus metadata.

use crate::{LazySignedTransaction, Sealable, Sealed, SignedTransaction};
use commonware_codec::{
    Codec, Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write,
};
use commonware_consensus::{
    Block as ConsensusBlock, CertifiableBlock, Heightable, simplex::types::Context, types::Height,
};
use commonware_cryptography::{
    Digest, Hasher, PublicKey, Signer, bls12381::primitives::variant::Variant,
};
use commonware_glue::dkg::{ReshareBlock, network::Directory, types::Payload};
use commonware_utils::range::NonEmptyRange;

/// A block header containing metadata, consensus context, and state commitment roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header<C, D, P, R = ()>
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
    /// Commitment to the genesis/bootstrap directory of peer keys and addresses.
    pub eligible_peers_root: D,
    /// The canonical root of the chain state after applying this block.
    pub state_root: D,
    /// The retained range needed to sync the state database.
    pub state_range: NonEmptyRange<u64>,
    /// A root of all transactions in the history, including those within this block.
    pub transactions_root: D,
    /// The active range of the transactions database.
    pub transactions_range: NonEmptyRange<u64>,
    /// The canonical root of the committee database after applying this block.
    pub committee_root: D,
    /// The retained range needed to sync the committee database.
    pub committee_range: NonEmptyRange<u64>,
    /// Optional consensus metadata committed by this header.
    pub payload: Option<R>,
}

impl<C, D, P, R> Header<C, D, P, R>
where
    C: Digest,
    D: Digest,
    P: PublicKey,
    R: Write + EncodeSize,
{
    /// Hashes the encoded header to produce a digest.
    pub fn hash_slow<H: Hasher<Digest = D>>(&self, hasher: &mut H) -> D {
        hasher.update(self.encode().as_ref());
        let (next, digest) = core::mem::take(hasher).finalize();
        *hasher = next;
        digest
    }
}

impl<C, D, P, R> Sealable for Header<C, D, P, R>
where
    C: Digest,
    D: Digest,
    P: PublicKey,
    R: Write + EncodeSize,
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

impl<C, D, P, R> EncodeSize for Header<C, D, P, R>
where
    C: Digest,
    D: Digest,
    P: PublicKey,
    R: EncodeSize,
{
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.timestamp.encode_size()
            + self.eligible_peers_root.encode_size()
            + self.state_root.encode_size()
            + self.state_range.encode_size()
            + self.transactions_root.encode_size()
            + self.transactions_range.encode_size()
            + self.committee_root.encode_size()
            + self.committee_range.encode_size()
            + self.payload.encode_size()
    }
}

impl<C, D, P, R> Write for Header<C, D, P, R>
where
    C: Digest,
    D: Digest,
    P: PublicKey,
    R: Write,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.timestamp.write(buf);
        self.eligible_peers_root.write(buf);
        self.state_root.write(buf);
        self.state_range.write(buf);
        self.transactions_root.write(buf);
        self.transactions_range.write(buf);
        self.committee_root.write(buf);
        self.committee_range.write(buf);
        self.payload.write(buf);
    }
}

impl<C, D, P, R> Read for Header<C, D, P, R>
where
    C: Digest,
    D: Digest,
    P: PublicKey,
    R: Read,
{
    type Cfg = R::Cfg;

    fn read_cfg(buf: &mut impl bytes::Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            context: Context::read(buf)?,
            parent: D::read(buf)?,
            height: u64::read(buf)?,
            timestamp: u64::read(buf)?,
            eligible_peers_root: D::read(buf)?,
            state_root: D::read(buf)?,
            state_range: NonEmptyRange::read(buf)?,
            transactions_root: D::read(buf)?,
            transactions_range: NonEmptyRange::read(buf)?,
            committee_root: D::read(buf)?,
            committee_range: NonEmptyRange::read(buf)?,
            payload: Option::<R>::read_cfg(buf, cfg)?,
        })
    }
}

#[cfg(any(feature = "arbitrary", test))]
impl<C, D, P, R> arbitrary::Arbitrary<'_> for Header<C, D, P, R>
where
    C: Digest + for<'a> arbitrary::Arbitrary<'a>,
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    R: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            context: u.arbitrary()?,
            parent: u.arbitrary()?,
            height: u.arbitrary()?,
            timestamp: u.arbitrary()?,
            eligible_peers_root: u.arbitrary()?,
            state_root: u.arbitrary()?,
            state_range: u.arbitrary()?,
            transactions_root: u.arbitrary()?,
            transactions_range: u.arbitrary()?,
            committee_root: u.arbitrary()?,
            committee_range: u.arbitrary()?,
            payload: u.arbitrary()?,
        })
    }
}

/// Codec configuration for decoding a [`Block`].
#[derive(Clone, Debug)]
pub struct BlockCfg<RCfg = ()> {
    /// Maximum number of transactions in the block body.
    pub max_transactions: RangeCfg<usize>,
    /// Configuration for decoding the optional header payload.
    pub payload: RCfg,
}

impl<RCfg: Default> Default for BlockCfg<RCfg> {
    fn default() -> Self {
        Self {
            max_transactions: RangeCfg::new(0..=usize::MAX),
            payload: RCfg::default(),
        }
    }
}

/// A block containing signed transactions and required epoch-consensus metadata.
#[derive(Debug)]
pub struct Block<C, P, H, R = ()>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    /// The execution header.
    pub header: Header<C, H::Digest, P, R>,
    /// Ordered transactions included in this execution payload.
    ///
    /// Each transaction is held in a [`LazySignedTransaction`] so block
    /// decoding does not pay the per-transaction decode + seal-hash cost on the
    /// caller's thread. Materialization is typically driven in parallel at
    /// verify time via a [`commonware_parallel::Strategy`].
    pub body: Vec<LazySignedTransaction<H>>,
}

impl<C, P, H, R> Clone for Block<C, P, H, R>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    R: Clone,
{
    fn clone(&self) -> Self {
        Self {
            header: self.header.clone(),
            body: self.body.clone(),
        }
    }
}

/// A sealed canonical block.
pub type SealedBlock<C, P, H, R = ()> = Sealed<Block<C, P, H, R>, H>;

#[cfg(any(feature = "arbitrary", test))]
impl<C, P, H, R> arbitrary::Arbitrary<'_> for Block<C, P, H, R>
where
    C: Digest + for<'a> arbitrary::Arbitrary<'a>,
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    H: Hasher,
    H::Digest: for<'a> arbitrary::Arbitrary<'a>,
    R: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            header: u.arbitrary()?,
            body: Vec::new(),
        })
    }
}

impl<C, P, H, R> PartialEq for Block<C, P, H, R>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    R: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header && self.body == other.body
    }
}

impl<C, P, H, R> Eq for Block<C, P, H, R>
where
    C: Digest,
    P: PublicKey + Eq,
    H: Hasher,
    H::Digest: Eq,
    R: Eq,
{
}

impl<C, P, H, R> Block<C, P, H, R>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    /// Creates a new block from already-decoded transactions.
    pub fn new(header: Header<C, H::Digest, P, R>, body: Vec<SignedTransaction<H>>) -> Self {
        Self {
            header,
            body: body.into_iter().map(LazySignedTransaction::new).collect(),
        }
    }
}

impl<C, P, H, R> EncodeSize for Block<C, P, H, R>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    R: EncodeSize,
{
    fn encode_size(&self) -> usize {
        self.header.encode_size() + self.body.encode_size()
    }
}

impl<C, P, H, R> Write for Block<C, P, H, R>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    R: Write,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.header.write(buf);
        self.body.write(buf);
    }
}

impl<C, P, H, R> Read for Block<C, P, H, R>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    R: Read,
{
    type Cfg = BlockCfg<R::Cfg>;

    fn read_cfg(buf: &mut impl bytes::Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let tx_vec_cfg = (cfg.max_transactions, ());
        Ok(Self {
            header: Header::read_cfg(buf, &cfg.payload)?,
            body: Vec::read_cfg(buf, &tx_vec_cfg)?,
        })
    }
}

impl<C, P, H, R> Sealable for Block<C, P, H, R>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    R: Write + EncodeSize,
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

impl<C, P, H, R> Heightable for Sealed<Block<C, P, H, R>, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    fn height(&self) -> Height {
        Height::new(self.header.height)
    }
}

impl<C, P, H, R> Heightable for Sealed<Header<C, H::Digest, P, R>, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    fn height(&self) -> Height {
        Height::new(self.height)
    }
}

impl<C, P, H, R> ConsensusBlock for Sealed<Block<C, P, H, R>, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    R: Codec + Clone + Send + Sync + 'static,
{
    fn parent(&self) -> Self::Digest {
        self.header.parent
    }
}

impl<C, P, H, R> ConsensusBlock for Sealed<Header<C, H::Digest, P, R>, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    R: Codec + Clone + Send + Sync + 'static,
{
    fn parent(&self) -> Self::Digest {
        self.parent
    }
}

impl<C, P, H, R> CertifiableBlock for Sealed<Block<C, P, H, R>, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    R: Codec + Clone + Send + Sync + 'static,
{
    type Context = Context<C, P>;

    fn context(&self) -> Self::Context {
        self.header.context.clone()
    }
}

impl<C, P, H, R> CertifiableBlock for Sealed<Header<C, H::Digest, P, R>, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    R: Codec + Clone + Send + Sync + 'static,
{
    type Context = Context<C, P>;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

impl<C, P, H, V, S, Dir> ReshareBlock for Sealed<Block<C, P, H, Payload<V, S, Dir>>, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    V: Variant,
    S: Signer,
    Dir: Directory<S::PublicKey>,
{
    type Variant = V;
    type Signer = S;
    type Directory = Dir;

    fn payload(&self) -> Option<Payload<V, S, Dir>> {
        self.header.payload.clone()
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
    use commonware_cryptography::{
        Signer, bls12381::primitives::variant::MinPk, ed25519, secp256r1::standard as secp256r1,
        sha256,
    };
    use commonware_formatting::hex;
    use commonware_math::algebra::Random;
    use commonware_utils::non_empty_range;
    use rand::{RngExt as _, SeedableRng, rngs::StdRng};

    fn test_context() -> Context<sha256::Digest, ed25519::PublicKey> {
        let mut rng = StdRng::from_seed([7u8; 32]);
        let leader = ed25519::PrivateKey::random(&mut rng).public_key();
        Context {
            round: Round::new(Epoch::zero(), View::zero()),
            leader,
            parent: (View::zero(), sha256::Digest::EMPTY),
        }
    }

    fn test_header_with_payload<R>(
        payload: Option<R>,
    ) -> Header<sha256::Digest, sha256::Digest, ed25519::PublicKey, R> {
        Header {
            context: test_context(),
            parent: sha256::Digest::EMPTY,
            height: 42,
            timestamp: 1000,
            eligible_peers_root: sha256::Sha256::hash(&[b"test eligible peers"]),
            state_root: sha256::Digest::EMPTY,
            state_range: non_empty_range!(0, 1),
            transactions_root: sha256::Digest::EMPTY,
            transactions_range: non_empty_range!(0, 1),
            committee_root: sha256::Digest::EMPTY,
            committee_range: non_empty_range!(0, 1),
            payload,
        }
    }

    fn test_header() -> Header<sha256::Digest, sha256::Digest, ed25519::PublicKey> {
        test_header_with_payload(None)
    }

    fn arbitrary_value<T>() -> T
    where
        T: for<'a> arbitrary::Arbitrary<'a>,
    {
        let mut rng = StdRng::from_seed([11u8; 32]);
        for _ in 0..256 {
            let mut bytes = [0u8; 4096];
            rng.fill(&mut bytes);
            let mut unstructured = arbitrary::Unstructured::new(&bytes);
            if let Ok(value) = T::arbitrary(&mut unstructured) {
                return value;
            }
        }
        panic!("failed to generate arbitrary test value");
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
    fn header_hash_commits_eligible_peers_root() {
        let header = test_header();
        let mut changed = header.clone();
        changed.eligible_peers_root = sha256::Sha256::hash(&[b"different eligible peers"]);

        assert_ne!(
            header.hash_slow(&mut sha256::Sha256::default()),
            changed.hash_slow(&mut sha256::Sha256::default())
        );
    }

    #[test]
    fn header_hash_golden_vector() {
        let expected: [u8; 32] =
            hex!("a7ca2de8dd5b7d6f5e9a62f599a39062e9f9842a98152a4b64dd84a85701e07d");

        assert_eq!(
            test_header()
                .hash_slow(&mut sha256::Sha256::default())
                .as_ref(),
            expected.as_slice()
        );
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
    fn block_codec_roundtrip_with_bounded_payload() {
        let block = Block::<sha256::Digest, ed25519::PublicKey, sha256::Sha256, Vec<u8>>::new(
            test_header_with_payload(Some(vec![1, 2, 3, 4])),
            vec![],
        );
        let encoded = block.encode();
        let cfg = BlockCfg {
            max_transactions: RangeCfg::new(0..=0),
            payload: (RangeCfg::new(0..=4), ()),
        };

        let decoded =
            Block::<sha256::Digest, ed25519::PublicKey, sha256::Sha256, Vec<u8>>::decode_cfg(
                encoded.clone(),
                &cfg,
            )
            .expect("payload within the configured bound should decode");
        assert_eq!(decoded, block);

        let too_small = BlockCfg {
            max_transactions: RangeCfg::new(0..=0),
            payload: (RangeCfg::new(0..=3), ()),
        };
        assert!(
            Block::<sha256::Digest, ed25519::PublicKey, sha256::Sha256, Vec<u8>>::decode_cfg(
                encoded, &too_small,
            )
            .is_err(),
            "payload exceeding the configured bound should be rejected"
        );
    }

    #[test]
    fn block_seal_commits_to_payload() {
        let without_payload = Block::<sha256::Digest, ed25519::PublicKey, sha256::Sha256, u8>::new(
            test_header_with_payload(None),
            vec![],
        )
        .seal(&mut sha256::Sha256::default());
        let with_payload = Block::<sha256::Digest, ed25519::PublicKey, sha256::Sha256, u8>::new(
            test_header_with_payload(Some(7)),
            vec![],
        )
        .seal(&mut sha256::Sha256::default());

        assert_ne!(without_payload.seal(), with_payload.seal());
    }

    #[test]
    fn arbitrary_block_supports_payload() {
        let _: Block<sha256::Digest, ed25519::PublicKey, sha256::Sha256, u8> = arbitrary_value();
    }

    #[test]
    fn sealed_dkg_block_exposes_reshare_payload() {
        type DkgPayload = Payload<MinPk, ed25519::PrivateKey>;

        let payload = arbitrary_value::<DkgPayload>();
        let block = Block::<sha256::Digest, ed25519::PublicKey, sha256::Sha256, DkgPayload>::new(
            test_header_with_payload(Some(payload.clone())),
            vec![],
        )
        .seal(&mut sha256::Sha256::default());

        assert!(ReshareBlock::payload(&block) == Some(payload));
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
