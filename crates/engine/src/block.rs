//! Nominal block type tying a coding commitment to the block it authenticates.

use crate::types::EngineCommitment;
use commonware_codec::{Buf, EncodeSize, Error, Read, Write};
use commonware_consensus::{
    Block as ConsensusBlock, CertifiableBlock, Heightable, simplex::types::Context, types::Height,
};
use commonware_cryptography::{Digestible, Hasher, PublicKey};
use constantinople_primitives::{Block, SealedBlock};
use std::{fmt, ops::Deref, sync::Arc};

/// A finalized execution block with its cached header digest.
///
/// The nominal wrapper lets Commonware's typed coding commitment refer back to
/// this exact block type. Its encoding and digest are those of the execution block.
pub struct EngineBlock<H: Hasher, P: PublicKey>(Arc<SealedBlock<EngineCommitment<H, P>, P, H>>);

impl<H: Hasher, P: PublicKey> EngineBlock<H, P> {
    /// Share the underlying execution block without copying its transactions.
    pub fn shared_execution(&self) -> Arc<SealedBlock<EngineCommitment<H, P>, P, H>> {
        self.0.clone()
    }

    /// Return the execution payload, reusing its allocation when unshared.
    pub fn into_inner(self) -> Block<EngineCommitment<H, P>, P, H> {
        Arc::unwrap_or_clone(self.0).into_inner()
    }
}

impl<H: Hasher, P: PublicKey> From<SealedBlock<EngineCommitment<H, P>, P, H>>
    for EngineBlock<H, P>
{
    fn from(block: SealedBlock<EngineCommitment<H, P>, P, H>) -> Self {
        Self(Arc::new(block))
    }
}
impl<H: Hasher, P: PublicKey> Clone for EngineBlock<H, P> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<H: Hasher, P: PublicKey> fmt::Debug for EngineBlock<H, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineBlock")
            .field("header", &self.header)
            .field("transactions", &self.body.len())
            .field("digest", self.seal())
            .finish()
    }
}
impl<H: Hasher, P: PublicKey> PartialEq for EngineBlock<H, P> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl<H: Hasher, P: PublicKey> Eq for EngineBlock<H, P> {}
impl<H: Hasher, P: PublicKey> Deref for EngineBlock<H, P> {
    type Target = SealedBlock<EngineCommitment<H, P>, P, H>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<H: Hasher, P: PublicKey> Write for EngineBlock<H, P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf);
    }
}
impl<H: Hasher, P: PublicKey> EncodeSize for EngineBlock<H, P> {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}
impl<H: Hasher, P: PublicKey> Read for EngineBlock<H, P> {
    type Cfg = constantinople_primitives::BlockCfg;
    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        SealedBlock::read_cfg(buf, cfg).map(Self::from)
    }
}
impl<H: Hasher, P: PublicKey> Digestible for EngineBlock<H, P> {
    type Digest = H::Digest;
    fn digest(&self) -> Self::Digest {
        self.0.digest()
    }
}
impl<H: Hasher, P: PublicKey> Heightable for EngineBlock<H, P> {
    fn height(&self) -> Height {
        self.0.height()
    }
}
impl<H: Hasher, P: PublicKey> ConsensusBlock for EngineBlock<H, P> {
    fn parent(&self) -> H::Digest {
        self.0.parent()
    }
}
impl<H: Hasher, P: PublicKey> CertifiableBlock for EngineBlock<H, P> {
    type Context = Context<EngineCommitment<H, P>, P>;
    fn context(&self) -> Self::Context {
        self.0.context()
    }
}
