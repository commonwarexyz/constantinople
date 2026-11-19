use bytes::Bytes;
use commonware_codec::{Decode, EncodeSize, RangeCfg, Read, Write};
use commonware_cryptography::{Hasher, PublicKey};
use constantinople_auth::MAX_ENTRIES;
use constantinople_engine::types::{EngineBlock, EngineHeader};
use constantinople_primitives::{Block, BlockCfg, LazySignedTransaction, Outcomes, Sealed};

pub(crate) fn encode_simplex_block_parts<H, P>(
    block: &EngineBlock<H, P>,
) -> (EngineHeader<H, P>, Bytes)
where
    H: Hasher,
    P: PublicKey,
{
    let header = Sealed::new_unchecked(block.header.clone(), *block.seal());

    // Everything a block holds after its header: what it says about its parent,
    // then its transactions.
    let mut body = Vec::with_capacity(
        block.notarization.encode_size() + block.outcomes.encode_size() + block.body.encode_size(),
    );
    block.notarization.write(&mut body);
    block.outcomes.write(&mut body);
    block.body.write(&mut body);
    (header, body.into())
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
    let mut body = body;
    let notarization = Option::read_cfg(&mut body, &cfg.max_validators)?;
    let outcomes = Outcomes::read_cfg(&mut body, &RangeCfg::new(..=MAX_ENTRIES as u64))?;
    let body_cfg = (cfg.max_transactions, ());
    let body = Vec::<LazySignedTransaction<H>>::decode_cfg(body, &body_cfg)?;
    let block = Block {
        header,
        notarization,
        outcomes,
        body,
    };
    Ok(Sealed::new_unchecked(block, seal).into())
}
