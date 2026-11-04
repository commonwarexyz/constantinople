use bytes::{Bytes, BytesMut};
use commonware_codec::{Decode, EncodeSize, Error, ReadExt, Write};
use commonware_cryptography::{Hasher, PublicKey};
use constantinople_engine::types::{EngineBlock, EngineHeader};
use constantinople_primitives::{Block, BlockCfg, LazySignedTransaction, Sealed, StateSyncProof};

pub(crate) fn encode_simplex_block_parts<H, P>(
    block: &EngineBlock<H, P>,
) -> (EngineHeader<H, P>, Bytes)
where
    H: Hasher,
    P: PublicKey,
{
    let header = Sealed::new_unchecked(block.header.clone(), *block.seal());
    let mut body =
        BytesMut::with_capacity(block.state_sync.encode_size() + block.body.encode_size());
    block.state_sync.write(&mut body);
    block.body.write(&mut body);
    (header, body.freeze())
}

pub(crate) fn decode_simplex_block_parts<H, P>(
    header: EngineHeader<H, P>,
    mut body: Bytes,
    cfg: &BlockCfg,
) -> Result<EngineBlock<H, P>, commonware_codec::Error>
where
    H: Hasher,
    P: PublicKey,
{
    let seal = *header.seal();
    let header = header.into_inner();
    let state_sync = StateSyncProof::read(&mut body)?;
    if !state_sync.verify::<H>(&header.state_root) {
        return Err(Error::Invalid(
            "Block",
            "state sync proof does not match header",
        ));
    }
    let body_cfg = (cfg.max_transactions, ());
    let body = Vec::<LazySignedTransaction<H>>::decode_cfg(body, &body_cfg)?;
    Ok(Sealed::new_unchecked(
        Block {
            header,
            state_sync,
            body: body.into(),
        },
        seal,
    )
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::{
        simplex::types::Context,
        types::{Round, View},
    };
    use commonware_cryptography::{Digest, Sha256, Signer, sha256};
    use commonware_cryptography_curve25519::signing as ed25519;
    use commonware_utils::non_empty_range;
    use constantinople_engine::types::EngineCommitment;
    use constantinople_primitives::{Header, Sealable};

    #[test]
    fn stored_body_retains_and_authenticates_state_sync_proof() {
        let state_sync = StateSyncProof::initial::<Sha256>();
        let header = Header {
            context: Context {
                round: Round::zero(),
                leader: ed25519::SigningKey::from_seed(17).public_key(),
                parent: (
                    View::zero(),
                    EngineCommitment::<Sha256, ed25519::VerifyingKey>::default(),
                ),
            },
            parent: sha256::Digest::EMPTY,
            height: 0,
            timestamp: 0,
            state_root: state_sync.root::<Sha256>(),
            state_range: non_empty_range!(0, 1),
            transactions_root: sha256::Digest::EMPTY,
            transactions_range: non_empty_range!(0, 1),
        };
        let block: EngineBlock<Sha256, ed25519::VerifyingKey> =
            Block::new(header, Vec::new(), state_sync)
                .seal(&mut Sha256::default())
                .into();
        let (header, body) = encode_simplex_block_parts(&block);
        let decoded =
            decode_simplex_block_parts(header.clone(), body.clone(), &BlockCfg::default()).unwrap();
        assert_eq!(decoded, block);

        let mut altered = body.to_vec();
        altered[0] ^= 1;
        assert!(
            decode_simplex_block_parts(header.clone(), altered.into(), &BlockCfg::default(),)
                .is_err()
        );
        assert!(
            decode_simplex_block_parts(
                header.clone(),
                body.slice(..body.len() - 1),
                &BlockCfg::default(),
            )
            .is_err()
        );

        let mut trailing = body.to_vec();
        trailing.push(0);
        assert!(
            decode_simplex_block_parts(header, trailing.into(), &BlockCfg::default(),).is_err()
        );
    }
}
