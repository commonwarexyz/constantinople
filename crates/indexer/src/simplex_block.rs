use bytes::Bytes;
use commonware_codec::{Decode, Encode};
use commonware_consensus::types::coding::Commitment;
use commonware_cryptography::{Hasher, PublicKey};
use constantinople_primitives::{Block, BlockCfg, Header, LazySignedTransaction, Sealed};

type SimplexBlock<H, P, R> = Sealed<Block<Commitment, P, H, R>, H>;
type SimplexHeader<H, P, R> = Sealed<Header<Commitment, <H as Hasher>::Digest, P, R>, H>;

pub(crate) fn encode_simplex_block_parts<H, P, R>(
    block: &SimplexBlock<H, P, R>,
) -> (SimplexHeader<H, P, R>, Bytes)
where
    H: Hasher,
    P: PublicKey,
    R: Clone,
{
    let header = Sealed::new_unchecked(block.header.clone(), *block.seal());
    let body = block.body.encode();
    (header, body)
}

pub(crate) fn decode_simplex_block_parts<H, P, R, RCfg>(
    header: SimplexHeader<H, P, R>,
    body: Bytes,
    cfg: &BlockCfg<RCfg>,
) -> Result<SimplexBlock<H, P, R>, commonware_codec::Error>
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
