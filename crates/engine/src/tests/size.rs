use crate::{
    tests::common::{TRANSACTION_NAMESPACE, TestBlock, TestHasher, TestPrivateKey, TestPublicKey},
    types::EngineCodedBlock,
};
use bytes::Buf;
use commonware_codec::{Decode, DecodeExt, Encode, EncodeSize};
use commonware_coding::{ReedSolomon, Scheme};
use commonware_consensus::{
    marshal::{
        coding::types::{CodedBlockCfg, coding_config_for_participants},
        resolver::handler::Key as ResolverKey,
    },
    simplex::types::Context,
    types::{Epoch, Round, View, coding::Commitment},
};
use commonware_cryptography::{Committable, Digest, Signer, sha256};
use commonware_macros::{test_group, test_traced};
use commonware_p2p::authenticated::MAX_PAYLOAD_OVERHEAD;
use commonware_parallel::Sequential;
use commonware_resolver::p2p::mocks::{Message as ResolverMessage, Payload as ResolverPayload};
use commonware_utils::non_empty_range;
use constantinople_primitives::{
    Block, BlockCfg, Header, Sealable, Transaction, TransactionPublicKey,
};
use std::num::NonZeroU64;

const DEPLOYED_MAX_PROPOSE_BYTES: usize = 25_165_824;
const WHOLE_MESSAGE_CEILING: usize = 32 * 1024 * 1024;
const DEPLOYED_VALIDATORS: u16 = 50;

#[test_group("slow")]
#[test_traced("INFO")]
fn deployed_max_proposal_round_trips_codec_resolver_and_coding() {
    let coding_config = coding_config_for_participants(DEPLOYED_VALIDATORS);
    let signer = TestPrivateKey::from_seed(4_000_000);
    let sender = TransactionPublicKey::ed25519(signer.public_key());
    let transaction = Transaction::new(
        sender.clone(),
        sender,
        NonZeroU64::new(1).expect("transfer value must be non-zero"),
        0,
    )
    .seal_and_sign(&signer, TRANSACTION_NAMESPACE, &mut TestHasher::default());
    let transaction_size = transaction.encode_size();
    let transaction_count = DEPLOYED_MAX_PROPOSE_BYTES / transaction_size;
    let proposal_bytes = transaction_count * transaction_size;
    assert_eq!(transaction_size, 147);
    assert_eq!(proposal_bytes, 25_165_812);
    assert!(proposal_bytes <= DEPLOYED_MAX_PROPOSE_BYTES);
    assert!(DEPLOYED_MAX_PROPOSE_BYTES - proposal_bytes < transaction_size);

    let parent = Commitment::from((
        sha256::Digest::EMPTY,
        sha256::Digest::EMPTY,
        sha256::Digest::EMPTY,
        coding_config,
    ));
    let header = Header {
        context: Context {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: signer.public_key(),
            parent: (View::zero(), parent),
        },
        parent: sha256::Digest::EMPTY,
        height: 1,
        timestamp: 1,
        state_root: sha256::Digest::EMPTY,
        state_range: non_empty_range!(0, 1),
        transactions_root: sha256::Digest::EMPTY,
        transactions_range: non_empty_range!(0, 1),
    };
    let block: TestBlock = Block::<Commitment, TestPublicKey, TestHasher>::new(
        header,
        vec![transaction; transaction_count],
    )
    .seal(&mut TestHasher::default());

    let block_bytes = block.encode();
    let mut block_cursor = block_bytes.as_ref();
    let decoded = TestBlock::decode_cfg(&mut block_cursor, &BlockCfg::default())
        .expect("production block codec must accept the deployed-size proposal");
    assert_eq!(decoded, block);
    assert_eq!(block_cursor.remaining(), 0);
    drop(decoded);

    let coded =
        EngineCodedBlock::<TestHasher, TestPublicKey>::new(block, coding_config, &Sequential);
    let expected = coded.commitment();
    let resolver_payload = coded.encode();
    let mut resolver_cursor = resolver_payload.as_ref();
    let decoded = EngineCodedBlock::<TestHasher, TestPublicKey>::decode_cfg(
        &mut resolver_cursor,
        &CodedBlockCfg {
            inner: BlockCfg::default(),
            expected,
        },
    )
    .expect("marshal resolver block payload must round-trip");
    assert_eq!(decoded, coded);
    assert_eq!(resolver_cursor.remaining(), 0);
    drop(decoded);

    let framed = ResolverMessage::<ResolverKey<Commitment>> {
        id: 7,
        payload: ResolverPayload::Response(resolver_payload.clone()),
    };
    let frame_bytes = framed.encode();
    assert_eq!(framed.encode_size(), frame_bytes.len());
    let decoded_frame = ResolverMessage::<ResolverKey<Commitment>>::decode(frame_bytes.clone())
        .expect("resolver response framing must round-trip");
    assert_eq!(decoded_frame, framed);
    assert!(frame_bytes.len() < WHOLE_MESSAGE_CEILING);
    assert!(
        frame_bytes.len() + (MAX_PAYLOAD_OVERHEAD as usize) < WHOLE_MESSAGE_CEILING,
        "resolver response plus maximum authenticated framing must fit below 32 MiB"
    );

    let coding_root = expected.root::<sha256::Digest>();
    let shards = coded.shards(&Sequential);
    assert_eq!(shards.len(), usize::from(DEPLOYED_VALIDATORS));
    let checked = shards
        .iter()
        .enumerate()
        .map(|(index, shard)| {
            ReedSolomon::<TestHasher>::check(
                &coding_config,
                &coding_root,
                u16::try_from(index).expect("validator index must fit in u16"),
                shard,
            )
            .expect("coded shard must verify")
        })
        .collect::<Vec<_>>();
    let minimum_shards = usize::from(coding_config.minimum_shards.get());
    let parity_quorum = &checked[checked.len() - minimum_shards..];
    let reconstructed = ReedSolomon::<TestHasher>::decode(
        &coding_config,
        &coding_root,
        parity_quorum.iter(),
        &Sequential,
    )
    .expect("parity-heavy 50-validator shard quorum must reconstruct");
    assert_eq!(reconstructed.as_slice(), resolver_payload.as_ref());
}
