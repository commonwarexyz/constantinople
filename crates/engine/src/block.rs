use commonware_codec::{EncodeSize, Error, Read, Write};
use commonware_coding::ReedSolomon;
use commonware_consensus::{
    Block as ConsensusBlock, CertifiableBlock, Heightable,
    simplex::types::Context,
    types::{Height, coding::Commitment},
};
use commonware_cryptography::{Digestible, Hasher, PublicKey};
use constantinople_primitives::{Block, BlockCfg, Sealed, SealedBlock};
use std::{fmt, ops::Deref, sync::Arc};

/// The coding commitment carried by Constantinople blocks.
pub type EngineCommitment<H, P> = Commitment<EngineBlock<H, P>, ReedSolomon<H>, H>;

type InnerBlock<H, P> = SealedBlock<EngineCommitment<H, P>, P, H>;

/// A Constantinople block bound to its coding commitment type.
pub struct EngineBlock<H, P>(Arc<InnerBlock<H, P>>)
where
    H: Hasher,
    P: PublicKey;

impl<H, P> Clone for EngineBlock<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<H, P> fmt::Debug for EngineBlock<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineBlock")
            .field("digest", &self.digest())
            .finish()
    }
}

impl<H, P> PartialEq for EngineBlock<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<H, P> Eq for EngineBlock<H, P>
where
    H: Hasher,
    P: PublicKey,
{
}

impl<H, P> EngineBlock<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    pub(crate) fn inner_shared(&self) -> Arc<InnerBlock<H, P>> {
        Arc::clone(&self.0)
    }
}

impl<H, P> From<InnerBlock<H, P>> for EngineBlock<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn from(block: InnerBlock<H, P>) -> Self {
        Self(Arc::new(block))
    }
}

impl<H, P> Deref for EngineBlock<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    type Target = InnerBlock<H, P>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<H, P> Digestible for EngineBlock<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    type Digest = H::Digest;

    fn digest(&self) -> Self::Digest {
        self.0.digest()
    }
}

impl<H, P> EncodeSize for EngineBlock<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl<H, P> Write for EngineBlock<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf);
    }
}

impl<H, P> Read for EngineBlock<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    type Cfg = BlockCfg;

    fn read_cfg(buf: &mut impl bytes::Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        InnerBlock::read_cfg(buf, cfg).map(Self::from)
    }
}

impl<H, P> Heightable for EngineBlock<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn height(&self) -> Height {
        self.0.height()
    }
}

impl<H, P> ConsensusBlock for EngineBlock<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn parent(&self) -> Self::Digest {
        self.0.parent()
    }
}

impl<H, P> CertifiableBlock for EngineBlock<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    type Context = Context<EngineCommitment<H, P>, P>;

    fn context(&self) -> Self::Context {
        self.0.context()
    }
}

pub(crate) fn maximum_encoded_size<H, P>(max_transaction_bytes: usize) -> usize
where
    H: Hasher,
    P: PublicKey,
{
    Block::<EngineCommitment<H, P>, P, H>::maximum_encoded_size(max_transaction_bytes)
}

pub(crate) type ApplicationBlock<H, P> = Sealed<Block<EngineCommitment<H, P>, P, H>, H>;
