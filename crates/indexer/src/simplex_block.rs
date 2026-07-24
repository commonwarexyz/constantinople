use bytes::Bytes;
use commonware_codec::{Decode, Encode};
use commonware_consensus::types::coding::Commitment;
use commonware_cryptography::{Hasher, PublicKey};
use constantinople_primitives::{Block, BlockCfg, Header, LazySignedTransaction, Sealed};

pub(crate) fn encode_simplex_block_parts<H, P, R>(
    block: &Sealed<Block<Commitment, P, H, R>, H>,
) -> (Sealed<Header<Commitment, H::Digest, P, R>, H>, Bytes)
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
    header: Sealed<Header<Commitment, H::Digest, P, R>, H>,
    body: Bytes,
    cfg: &BlockCfg<RCfg>,
) -> Result<Sealed<Block<Commitment, P, H, R>, H>, commonware_codec::Error>
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
