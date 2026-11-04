//! Block and header types for the Constantinople chain.
//!
//! This module defines:
//!
//! - [`Header`] - The execution header.
//! - [`Block`] - Execution payload and required consensus metadata.

use crate::{
    Account, AccountKey, LazySignedTransaction, Sealable, Sealed, SignedTransaction,
    proposal::MAXIMUM_BLOCK_SIZE,
};
use commonware_codec::{
    Buf, Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write,
};
use commonware_consensus::{
    Block as ConsensusBlock, CertifiableBlock, Heightable, simplex::types::Context, types::Height,
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_storage::{
    mmr,
    qmdb::{
        self,
        any::{self, ordered::Update, value::FixedEncoding},
        current::proof::OpsRootWitness,
    },
};
use commonware_utils::{bitmap::Prunable, range::NonEmptyRange};
use std::sync::Arc;

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

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
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

/// Authenticates the operations root used by state sync against the header's current root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateSyncProof<D: Digest> {
    /// Operations root authenticated by `witness`.
    pub ops_root: D,
    /// Native current-root opening for the operations root.
    pub witness: OpsRootWitness<mmr::Family, D>,
}

impl<D: Digest> StateSyncProof<D> {
    /// The empty account database contains one active commit and no account updates.
    pub fn initial<H: Hasher<Digest = D>>() -> Self {
        let hasher = qmdb::hasher::<H>();
        let mut bitmap = Prunable::<32>::new();
        bitmap.push(true);
        let (chunk, bits) = bitmap.last_chunk();
        let ops_root =
            any::initial_root::<mmr::Family, Update<AccountKey, FixedEncoding<Account>>, H>();

        // The one-commit tree lies below the grafting height, so the virtual grafted root is
        // the operations root. Its active bit is committed by the partial chunk.
        Self {
            ops_root,
            witness: OpsRootWitness {
                grafted_root: ops_root,
                pending_chunk_digest: Default::default(),
                partial_chunk: Some((bits, hasher.digest(chunk))),
            },
        }
    }

    pub fn root<H: Hasher<Digest = D>>(&self) -> D {
        self.witness.root::<H>(&self.ops_root)
    }

    pub fn verify<H: Hasher<Digest = D>>(&self, root: &D) -> bool {
        self.witness.verify::<H>(&self.ops_root, root)
    }

    /// Upper bound on this proof's encoded size.
    pub fn max_encode_size() -> usize {
        Self {
            ops_root: D::EMPTY,
            witness: OpsRootWitness {
                grafted_root: D::EMPTY,
                pending_chunk_digest: Default::default(),
                partial_chunk: Some((u64::MAX, D::EMPTY)),
            },
        }
        .encode_size()
    }
}

impl<D: Digest> Write for StateSyncProof<D> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.ops_root.write(buf);
        self.witness.write(buf);
    }
}

impl<D: Digest> Read for StateSyncProof<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            ops_root: D::read(buf)?,
            witness: OpsRootWitness::read(buf)?,
        })
    }
}

impl<D: Digest> EncodeSize for StateSyncProof<D> {
    fn encode_size(&self) -> usize {
        self.ops_root.encode_size() + self.witness.encode_size()
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
    /// Proof material for syncing the state committed by the header.
    pub state_sync: StateSyncProof<H::Digest>,
    /// Ordered transactions included in this execution payload.
    ///
    /// Each transaction is held in a [`LazySignedTransaction`] so block
    /// decoding does not pay the per-transaction decode + seal-hash cost on the
    /// caller's thread. Materialization is typically driven in parallel at
    /// verify time via a [`commonware_parallel::Strategy`]. The list is shared
    /// behind an [`Arc`], so cloning a block copies neither the transactions
    /// nor their decoded values.
    pub body: Arc<Vec<LazySignedTransaction<H>>>,
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
            state_sync: self.state_sync.clone(),
            body: Arc::clone(&self.body),
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
        let state_sync = StateSyncProof::initial::<H>();
        let mut header: Header<C, H::Digest, P> = u.arbitrary()?;
        header.state_root = state_sync.root::<H>();
        Ok(Self {
            header,
            state_sync,
            body: Arc::new(body.into_iter().map(LazySignedTransaction::new).collect()),
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
            && self.state_sync == other.state_sync
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
    /// Creates a block from decoded transactions and its state-root opening.
    pub fn new(
        header: Header<C, H::Digest, P>,
        body: Vec<SignedTransaction<H>>,
        state_sync: StateSyncProof<H::Digest>,
    ) -> Self {
        Self {
            header,
            state_sync,
            body: Arc::new(body.into_iter().map(LazySignedTransaction::new).collect()),
        }
    }

    pub fn verify_state_root(&self) -> bool {
        self.state_sync.verify::<H>(&self.header.state_root)
    }
}

impl<C, P, H> EncodeSize for Block<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    fn encode_size(&self) -> usize {
        self.header.encode_size() + self.state_sync.encode_size() + self.body.encode_size()
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
        self.state_sync.write(buf);
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
        let header = Header::read_cfg(&mut buf, &())?;
        let state_sync = StateSyncProof::read(&mut buf)?;
        if !state_sync.verify::<H>(&header.state_root) {
            return Err(CodecError::Invalid(
                "Block",
                "state sync proof does not match header",
            ));
        }
        let tx_vec_cfg = (cfg.max_transactions, ());
        Ok(Self {
            header,
            state_sync,
            body: Arc::read_cfg(&mut buf, &tx_vec_cfg)?,
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
    use commonware_cryptography::{Signer, secp256r1::standard as secp256r1, sha256};
    use commonware_cryptography_curve25519::signing as ed25519;
    use commonware_math::algebra::Random;
    use commonware_utils::non_empty_range;
    use rand::{SeedableRng, rngs::StdRng};

    fn test_context() -> Context<sha256::Digest, ed25519::VerifyingKey> {
        let mut rng = StdRng::from_seed([7u8; 32]);
        let leader = ed25519::SigningKey::random(&mut rng).public_key();
        Context {
            round: Round::new(Epoch::zero(), View::zero()),
            leader,
            parent: (View::zero(), sha256::Digest::EMPTY),
        }
    }

    fn test_header() -> Header<sha256::Digest, sha256::Digest, ed25519::VerifyingKey> {
        Header {
            context: test_context(),
            parent: sha256::Digest::EMPTY,
            height: 42,
            timestamp: 1000,
            state_root: StateSyncProof::initial::<sha256::Sha256>().root::<sha256::Sha256>(),
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
            Header::<sha256::Digest, sha256::Digest, ed25519::VerifyingKey>::decode_cfg(buf, &())
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
        let block = Block::<sha256::Digest, ed25519::VerifyingKey, sha256::Sha256>::new(
            test_header(),
            vec![],
            StateSyncProof::initial::<sha256::Sha256>(),
        );

        let mut buf = Vec::with_capacity(block.encode_size());
        block.write(&mut buf);

        let decoded = Block::<sha256::Digest, ed25519::VerifyingKey, sha256::Sha256>::decode_cfg(
            buf,
            &BlockCfg::default(),
        )
        .expect("decoding should succeed");
        assert_eq!(decoded, block);
    }

    #[test]
    fn block_decode_authenticates_state_sync_proof() {
        type TestBlock = Block<sha256::Digest, ed25519::VerifyingKey, sha256::Sha256>;
        let block = TestBlock::new(
            test_header(),
            Vec::new(),
            StateSyncProof::initial::<sha256::Sha256>(),
        );
        assert!(block.verify_state_root());

        let mut wrong_ops = block.clone();
        wrong_ops.state_sync.ops_root = sha256::Digest::EMPTY;
        let mut wrong_witness = block.clone();
        wrong_witness.state_sync.witness.grafted_root = sha256::Digest::EMPTY;
        let mut wrong_root = block.clone();
        wrong_root.header.state_root = sha256::Digest::EMPTY;
        for invalid in [wrong_ops, wrong_witness, wrong_root] {
            assert!(!invalid.verify_state_root());
            assert!(TestBlock::decode_cfg(invalid.encode(), &BlockCfg::default()).is_err());
        }

        let header_bytes = block.header.encode_size();
        let proof_bytes = block.state_sync.encode_size();
        let encoded = block.encode();
        assert_eq!(&encoded[..header_bytes], block.header.encode().as_ref());
        for end in header_bytes..header_bytes + proof_bytes {
            assert!(TestBlock::decode_cfg(encoded.slice(..end), &BlockCfg::default()).is_err());
        }
    }

    #[test]
    fn state_sync_proof_size_bound_covers_chunk_shapes() {
        let mut proof = StateSyncProof::initial::<sha256::Sha256>();
        for partial in [
            None,
            Some((1, sha256::Digest::EMPTY)),
            Some((u64::MAX, sha256::Digest::EMPTY)),
        ] {
            proof.witness.partial_chunk = partial;
            assert!(proof.encode_size() <= StateSyncProof::<sha256::Digest>::max_encode_size());
        }
        assert_eq!(
            proof.encode_size(),
            StateSyncProof::<sha256::Digest>::max_encode_size(),
        );
    }

    #[test]
    fn cloned_block_shares_body_and_preserves_deferred_wire_bytes() {
        type TestBlock = Block<sha256::Digest, ed25519::VerifyingKey, sha256::Sha256>;

        // Frame two minimum-size transactions of filler bytes that never
        // decode, so the block holds only deferred wire bytes.
        let payload_size =
            crate::Transaction::<sha256::Digest>::SIZE + crate::TransactionSignature::MIN_SIZE;
        let mut encoded = test_header().encode().to_vec();
        StateSyncProof::initial::<sha256::Sha256>().write(&mut encoded);
        2usize.write(&mut encoded);
        for fill in [0xfe, 0xff] {
            payload_size.write(&mut encoded);
            encoded.resize(encoded.len() + payload_size, fill);
        }
        let block = TestBlock::decode_cfg(encoded.clone(), &BlockCfg::default()).unwrap();
        let weak = Arc::downgrade(&block.body);

        // A clone shares the body allocation and encodes the original bytes.
        let cloned = block.clone();
        assert!(Arc::ptr_eq(&block.body, &cloned.body));
        assert_eq!(block.body.as_ptr(), cloned.body.as_ptr());
        assert_eq!(cloned.encode().as_ref(), encoded.as_slice());

        // The body outlives the original block, still fails to decode, and
        // still encodes the original bytes. It is freed with the last clone.
        drop(block);
        assert_eq!(weak.strong_count(), 1);
        for transaction in cloned.body.iter() {
            assert!(transaction.get().is_none());
        }
        assert_eq!(cloned.encode().as_ref(), encoded.as_slice());
        drop(cloned);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn constructed_block_clones_share_materialized_transactions() {
        // Build a block from one signed transaction.
        let mut rng = StdRng::from_seed([31; 32]);
        let signer = ed25519::SigningKey::random(&mut rng);
        let key = crate::TransactionPublicKey::ed25519(signer.public_key());
        let transaction = crate::Transaction::<sha256::Digest>::new(
            key.clone(),
            key,
            core::num::NonZeroU64::MIN,
            0,
        )
        .seal_and_sign(
            &signer,
            crate::TRANSACTION_NAMESPACE,
            &mut sha256::Sha256::default(),
        );
        let block = Block::new(
            test_header(),
            vec![transaction],
            StateSyncProof::initial::<sha256::Sha256>(),
        );

        // A clone shares the body and its decoded transactions.
        let cloned = block.clone();
        assert!(Arc::ptr_eq(&block.body, &cloned.body));
        assert!(core::ptr::eq(
            block.body[0].get().unwrap(),
            cloned.body[0].get().unwrap()
        ));
        assert_eq!(block.encode(), cloned.encode());
    }

    fn encoded_block_with_size(size: usize) -> Vec<u8> {
        let mut encoded = test_header().encode().to_vec();
        StateSyncProof::initial::<sha256::Sha256>().write(&mut encoded);
        let minimum_transaction =
            crate::Transaction::<sha256::Digest>::SIZE + crate::TransactionSignature::MIN_SIZE;
        let framed_transaction = minimum_transaction + minimum_transaction.encode_size();
        let body_bytes = size - encoded.len();
        let count = body_bytes / framed_transaction;
        let count = (body_bytes - count.encode_size()) / framed_transaction;
        count.write(&mut encoded);

        // Deferred transaction bodies isolate the block framing check from signature validation.
        for _ in 1..count {
            minimum_transaction.write(&mut encoded);
            encoded.resize(encoded.len() + minimum_transaction, 0);
        }
        let last_size = size - encoded.len() - minimum_transaction.encode_size();
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
        type TestBlock = Block<sha256::Digest, ed25519::VerifyingKey, sha256::Sha256>;

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
        let block = Block::<sha256::Digest, ed25519::VerifyingKey, sha256::Sha256>::new(
            test_header(),
            vec![],
            StateSyncProof::initial::<sha256::Sha256>(),
        );
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
        let block = Block::<sha256::Digest, ed25519::VerifyingKey, sha256::Sha256>::new(
            test_header(),
            vec![signed],
            StateSyncProof::initial::<sha256::Sha256>(),
        );

        let encoded = block.encode();
        let mut reader = encoded;
        let _decoded =
            <Block<sha256::Digest, ed25519::VerifyingKey, sha256::Sha256> as commonware_codec::Read>::read_cfg(
                &mut reader,
                &BlockCfg::default(),
            )
            .expect("block should decode");

        assert!(reader.is_empty(), "block decoder left trailing bytes");
    }
}
