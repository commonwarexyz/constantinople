//! Block and header types for the Constantinople chain.
//!
//! This module defines:
//!
//! - [`Header`] - The execution header.
//! - [`Block`] - Execution payload and required consensus metadata.
//!
//! A block's transactions are executed one block later. Block `h` carries its
//! own transactions, a notarization of block `h - 1` and one outcome bit per
//! transaction of block `h - 1`. The reports in the notarization fix which of
//! the parent's transactions authenticated by tags are authentic, and the
//! state the header commits to is the parent's state with the parent's
//! authentic transactions applied. An outcome bit says whether a transaction
//! was applied.

use crate::{
    LazySignedTransaction, Sealable, Sealed, SignedTransaction, proposal::MAXIMUM_BLOCK_SIZE,
};
use commonware_codec::{
    Buf, Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write,
};
use commonware_consensus::{
    Block as ConsensusBlock, CertifiableBlock, Heightable,
    simplex::types::{Context, Notarization},
    types::Height,
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_utils::{bitmap::BitMap, range::NonEmptyRange};
use constantinople_auth::{MAX_ENTRIES, Scheme};

/// The notarization of its parent that a block carries (`R` in the paper).
pub type ParentNotarization<C> = Notarization<Scheme, C>;

/// One bit per transaction of a block's parent, in order: whether it was applied.
pub type Outcomes = BitMap<1>;

/// The value of [`Header::parent_notarization`] for `notarization`.
pub fn notarization_digest<C: Digest, H: Hasher>(
    notarization: Option<&ParentNotarization<C>>,
    hasher: &mut H,
) -> H::Digest {
    match notarization {
        Some(notarization) => {
            hasher.update(&[1]);
            hasher.update(notarization.encode().as_ref());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    crate::finalize_in_place(hasher)
}

/// The value of [`Header::parent_outcomes`] for `outcomes`.
pub fn outcomes_digest<H: Hasher>(outcomes: &Outcomes, hasher: &mut H) -> H::Digest {
    hasher.update(outcomes.encode().as_ref());
    crate::finalize_in_place(hasher)
}

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
    /// Digest of the notarization of the parent carried by the block
    /// (see [`notarization_digest`]).
    pub parent_notarization: D,
    /// Digest of the outcome bits of the parent's transactions
    /// (see [`outcomes_digest`]).
    pub parent_outcomes: D,
    /// The canonical root of the chain state after applying the parent's
    /// authentic transactions to the parent's state.
    pub state_root: D,
    /// The retained range needed to sync the state database.
    pub state_range: NonEmptyRange<u64>,
    /// A root of all transactions in the history, including those within this block.
    /// It pins the block's body.
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
        crate::finalize_in_place(hasher)
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
            + self.parent_notarization.encode_size()
            + self.parent_outcomes.encode_size()
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
        self.parent_notarization.write(buf);
        self.parent_outcomes.write(buf);
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

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            context: Context::read(buf)?,
            parent: D::read(buf)?,
            height: u64::read(buf)?,
            timestamp: u64::read(buf)?,
            parent_notarization: D::read(buf)?,
            parent_outcomes: D::read(buf)?,
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
            parent_notarization: u.arbitrary()?,
            parent_outcomes: u.arbitrary()?,
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
    /// Maximum number of validators that sign the parent's notarization.
    pub max_validators: usize,
}

impl Default for BlockCfg {
    fn default() -> Self {
        Self {
            max_transactions: RangeCfg::new(0..=usize::MAX),
            max_validators: u16::MAX as usize,
        }
    }
}

/// A block containing signed transactions and required epoch-consensus metadata.
#[derive(Debug)]
pub struct Block<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    /// The execution header.
    pub header: Header<C, H::Digest, P>,
    /// A notarization of the parent. Its reports determine which of the
    /// parent's transactions authenticated by tags are authentic. A child of
    /// the genesis block carries none.
    pub notarization: Option<ParentNotarization<C>>,
    /// Whether each of the parent's transactions was applied.
    pub outcomes: Outcomes,
    /// Ordered transactions included in this execution payload.
    ///
    /// Each transaction is held in a [`LazySignedTransaction`] so block
    /// decoding does not pay the per-transaction decode + seal-hash cost on the
    /// caller's thread. Materialization is typically driven in parallel at
    /// verify time via a [`commonware_parallel::Strategy`].
    pub body: Vec<LazySignedTransaction<H>>,
}

impl<C, P, H> Clone for Block<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    fn clone(&self) -> Self {
        Self {
            header: self.header.clone(),
            notarization: self.notarization.clone(),
            outcomes: self.outcomes.clone(),
            body: self.body.clone(),
        }
    }
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
            notarization: None,
            outcomes: Outcomes::new(),
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
        self.header == other.header
            && self.notarization == other.notarization
            && self.outcomes == other.outcomes
            && self.body == other.body
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
    /// Creates a new block from already-decoded transactions, without a
    /// notarization of its parent and without outcomes.
    pub fn new(header: Header<C, H::Digest, P>, body: Vec<SignedTransaction<H>>) -> Self {
        Self::with_parent(header, None, Outcomes::new(), body)
    }

    /// Creates a new block from already-decoded transactions.
    ///
    /// The header must hold the digests of `notarization` and `outcomes`.
    pub fn with_parent(
        header: Header<C, H::Digest, P>,
        notarization: Option<ParentNotarization<C>>,
        outcomes: Outcomes,
        body: Vec<SignedTransaction<H>>,
    ) -> Self {
        Self {
            header,
            notarization,
            outcomes,
            body: body.into_iter().map(LazySignedTransaction::new).collect(),
        }
    }

    /// Whether the header holds the digests of the notarization and of the
    /// outcomes that the block carries.
    pub fn commits_to_parent(&self, hasher: &mut H) -> bool {
        notarization_digest(self.notarization.as_ref(), hasher) == self.header.parent_notarization
            && outcomes_digest(&self.outcomes, hasher) == self.header.parent_outcomes
    }
}

impl<C, P, H> EncodeSize for Block<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    fn encode_size(&self) -> usize {
        self.header.encode_size()
            + self.notarization.encode_size()
            + self.outcomes.encode_size()
            + self.body.encode_size()
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
        self.notarization.write(buf);
        self.outcomes.write(buf);
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

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        // Limit this block without consuming trailing metadata from its enclosing message.
        let mut buf = bytes::Buf::take(buf, MAXIMUM_BLOCK_SIZE);
        let tx_vec_cfg = (cfg.max_transactions, ());
        Ok(Self {
            header: Header::read_cfg(&mut buf, &())?,
            notarization: Option::read_cfg(&mut buf, &cfg.max_validators)?,
            outcomes: Outcomes::read_cfg(&mut buf, &RangeCfg::new(..=MAX_ENTRIES as u64))?,
            body: Vec::read_cfg(&mut buf, &tx_vec_cfg)?,
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
    use commonware_codec::{Decode, FixedSize};
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
            parent_notarization: sha256::Digest::EMPTY,
            parent_outcomes: sha256::Digest::EMPTY,
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

        let decoded =
            Header::<sha256::Digest, sha256::Digest, ed25519::PublicKey>::decode_cfg(buf, &())
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
            buf,
            &BlockCfg::default(),
        )
        .expect("decoding should succeed");
        assert_eq!(decoded, block);
    }

    fn encoded_block_with_size(size: usize) -> Vec<u8> {
        let mut encoded = test_header().encode().to_vec();
        false.write(&mut encoded);
        Outcomes::new().write(&mut encoded);
        let minimum_transaction =
            crate::Transaction::<sha256::Digest>::SIZE + crate::TransactionSignature::MIN_SIZE;
        let framed_transaction = minimum_transaction + minimum_transaction.encode_size();
        let body_bytes = size - encoded.len();
        let count = body_bytes / framed_transaction;
        let mut count = (body_bytes - count.encode_size()) / framed_transaction;

        // The last transaction takes the bytes the others leave. No transaction
        // fills exactly 129 bytes with its prefix, so one fewer leaves it more.
        let last_size = loop {
            let left = body_bytes - count.encode_size() - (count - 1) * framed_transaction;
            let last_size = if left <= 128 { left - 1 } else { left - 2 };
            if last_size.encode_size() + last_size == left {
                break last_size;
            }
            count -= 1;
        };
        count.write(&mut encoded);

        // Deferred transaction bodies isolate the block framing check from signature validation.
        for _ in 1..count {
            minimum_transaction.write(&mut encoded);
            encoded.resize(encoded.len() + minimum_transaction, 0);
        }
        assert!(
            last_size
                <= crate::Transaction::<sha256::Digest>::SIZE
                    + crate::TransactionSignature::MAX_SIZE
        );
        last_size.write(&mut encoded);
        encoded.resize(size, 0);
        encoded
    }

    #[test]
    fn block_codec_enforces_encoded_size_limit() {
        type TestBlock = Block<sha256::Digest, ed25519::PublicKey, sha256::Sha256>;

        for size in [MAXIMUM_BLOCK_SIZE - 1, MAXIMUM_BLOCK_SIZE] {
            let mut encoded = encoded_block_with_size(size);
            encoded.extend_from_slice(&[1, 2, 3, 4]);
            let mut reader = bytes::Bytes::from(encoded);
            let block = TestBlock::read_cfg(&mut reader, &BlockCfg::default())
                .expect("a block within the consensus limit should decode");
            assert_eq!(block.encode_size(), size);
            assert_eq!(reader.as_ref(), &[1, 2, 3, 4]);
        }

        let encoded = encoded_block_with_size(MAXIMUM_BLOCK_SIZE + 1);
        assert!(TestBlock::decode_cfg(encoded, &BlockCfg::default()).is_err());
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

    /// A notarization of a block with payload `payload` by five of six validators,
    /// each reporting `verdicts` on its transactions authenticated by tags.
    fn test_notarization(
        payload: sha256::Digest,
        verdicts: &[bool],
    ) -> ParentNotarization<sha256::Digest> {
        use commonware_consensus::simplex::types::{Notarize, Proposal};
        use constantinople_auth::Report;

        let fixture = constantinople_auth::fixture(&mut commonware_utils::test_rng(), b"test", 6);
        let proposal = Proposal::new(
            Round::new(Epoch::zero(), View::new(3)),
            View::new(2),
            payload,
        );
        let votes: Vec<_> = fixture.schemes[..5]
            .iter()
            .map(|scheme| {
                scheme.reports().insert(
                    proposal.round,
                    proposal.payload.as_ref(),
                    Report::new(verdicts),
                );
                Notarize::sign(scheme, proposal.clone()).expect("report was recorded")
            })
            .collect();
        Notarization::from_notarizes(
            &fixture.schemes[0],
            commonware_utils::non_empty![@votes.iter()],
            &commonware_parallel::Sequential,
        )
        .expect("five of six votes are a quorum")
    }

    #[test]
    fn block_carries_parent_notarization_and_outcomes() {
        type TestBlock = Block<sha256::Digest, ed25519::PublicKey, sha256::Sha256>;
        let hasher = &mut sha256::Sha256::default();

        let notarization = test_notarization(sha256::Digest::EMPTY, &[true, false, true]);
        let mut outcomes = Outcomes::new();
        for applied in [true, false, false, true] {
            outcomes.push(applied);
        }
        let mut header = test_header();
        header.parent_notarization = notarization_digest(Some(&notarization), hasher);
        header.parent_outcomes = outcomes_digest(&outcomes, hasher);
        let block = TestBlock::with_parent(
            header,
            Some(notarization.clone()),
            outcomes.clone(),
            Vec::new(),
        );
        assert!(block.commits_to_parent(hasher));

        let encoded = block.encode();
        assert_eq!(encoded.len(), block.encode_size());
        let config = BlockCfg {
            max_validators: 6,
            ..Default::default()
        };
        let decoded = TestBlock::decode_cfg(encoded.clone(), &config).expect("block decodes");
        assert_eq!(decoded, block);
        assert_eq!(decoded.notarization, Some(notarization));
        assert_eq!(decoded.outcomes, outcomes);

        // A committee of five has no sixth signer.
        let config = BlockCfg {
            max_validators: 5,
            ..Default::default()
        };
        assert!(TestBlock::decode_cfg(encoded, &config).is_err());

        // The header pins both: another notarization or other outcomes do not match.
        let mut other = block.clone();
        other.notarization = Some(test_notarization(
            sha256::Digest::EMPTY,
            &[true, true, true],
        ));
        assert!(!other.commits_to_parent(hasher));
        let mut other = block.clone();
        other.outcomes.flip(0);
        assert!(!other.commits_to_parent(hasher));
        let mut other = block;
        other.notarization = None;
        assert!(!other.commits_to_parent(hasher));
    }

    #[test]
    fn block_without_a_parent_notarization_commits_to_none() {
        type TestBlock = Block<sha256::Digest, ed25519::PublicKey, sha256::Sha256>;
        let hasher = &mut sha256::Sha256::default();
        let mut header = test_header();
        assert!(!TestBlock::new(header.clone(), vec![]).commits_to_parent(hasher));

        header.parent_notarization = notarization_digest::<sha256::Digest, _>(None, hasher);
        header.parent_outcomes = outcomes_digest(&Outcomes::new(), hasher);
        assert!(TestBlock::new(header, vec![]).commits_to_parent(hasher));
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
        let mut reader = encoded;
        let _decoded =
            <Block<sha256::Digest, ed25519::PublicKey, sha256::Sha256> as commonware_codec::Read>::read_cfg(
                &mut reader,
                &BlockCfg::default(),
            )
            .expect("block should decode");

        assert!(reader.is_empty(), "block decoder left trailing bytes");
    }
}
