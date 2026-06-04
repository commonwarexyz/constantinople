use bytes::Bytes;
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{Hasher, PublicKey};
use constantinople_engine::types::{EngineBlock, EngineHeader};
use constantinople_primitives::{Block, BlockCfg, LazySignedTransaction, Sealed};

pub(crate) fn encode_simplex_block_parts<H, P>(
    block: &EngineBlock<H, P>,
) -> (EngineHeader<H, P>, Bytes)
where
    H: Hasher,
    P: PublicKey,
{
    let header = Sealed::new_unchecked(block.header.clone(), *block.seal());
    let body = block.body.encode();
    (header, body)
}

pub(crate) fn decode_simplex_block_parts<H, P>(
    header: EngineHeader<H, P>,
    body: Bytes,
    cfg: &BlockCfg,
) -> Result<EngineBlock<H, P>, commonware_codec::Error>
where
    H: Hasher,
    P: PublicKey,
{
    let seal = *header.seal();
    let header = header.into_inner();
    let body_cfg = (cfg.max_transactions, ());
    let body = Vec::<LazySignedTransaction<H>>::decode_cfg(body, &body_cfg)?;
    Ok(Sealed::new_unchecked(Block { header, body }, seal))
}
