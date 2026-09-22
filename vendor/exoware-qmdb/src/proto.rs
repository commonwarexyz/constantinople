pub mod common {
    pub mod kv {
        pub mod v1 {
            pub use exoware_sdk::common::kv::v1::*;
        }
    }
}

pub mod qmdb {
    pub mod v1 {
        #![allow(non_camel_case_types)]
        #![allow(unused_imports)]
        #![allow(clippy::derivable_impls)]
        #![allow(clippy::match_single_binding)]
        include!("gen/qmdb.v1.rs");
    }
}

use bytes::{BufMut, Bytes, BytesMut};
use commonware_codec::{Encode, EncodeSize, Write as CodecWrite};
use commonware_cryptography::Digest;
use commonware_storage::{
    merkle::Graftable,
    qmdb::{
        any::{ordered, unordered, value::ValueEncoding},
        operation::Key as QmdbKey,
    },
};
use connectrpc::PreEncoded;

use self::qmdb::v1::{
    GetCurrentOperationRangeResponse, GetManyResponse, GetOperationRangeResponse, GetRangeResponse,
    GetResponse, SubscribeResponse,
};
use crate::proof::{
    CurrentOperationRangeProofResult, OperationRangeCheckpoint, RawBatchMultiProof,
    RawKeyExclusionProof, RawKeyLookupProof, RawKeyRangeProof, RawKeyValueProof,
};

const WIRE_VARINT: u64 = buffa::encoding::WireType::Varint as u64;
const WIRE_LENGTH_DELIMITED: u64 = buffa::encoding::WireType::LengthDelimited as u64;

fn tag_len(field: u32, wire: u64) -> usize {
    buffa::encoding::varint_len(((field as u64) << 3) | wire)
}

fn write_tag(buf: &mut impl BufMut, field: u32, wire: buffa::encoding::WireType) {
    buffa::encoding::Tag::new(field, wire).encode(buf);
}

fn message_bytes(len: usize, write: impl FnOnce(&mut BytesMut)) -> Bytes {
    let mut buf = BytesMut::with_capacity(len);
    write(&mut buf);
    debug_assert_eq!(buf.len(), len, "protobuf encoder wrote an unexpected size");
    buf.freeze()
}

fn varint_field_len(field: u32, value: u64) -> usize {
    if value == 0 {
        0
    } else {
        tag_len(field, WIRE_VARINT) + buffa::encoding::varint_len(value)
    }
}

fn write_u64_field(buf: &mut impl BufMut, field: u32, value: u64) {
    if value != 0 {
        write_tag(buf, field, buffa::encoding::WireType::Varint);
        buffa::encoding::encode_varint(value, buf);
    }
}

fn length_delimited_len(field: u32, len: usize) -> usize {
    tag_len(field, WIRE_LENGTH_DELIMITED) + buffa::encoding::varint_len(len as u64) + len
}

fn bytes_field_len(field: u32, bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        0
    } else {
        length_delimited_len(field, bytes.len())
    }
}

fn repeated_bytes_field_len(field: u32, bytes: &[u8]) -> usize {
    length_delimited_len(field, bytes.len())
}

fn write_bytes_body(buf: &mut impl BufMut, bytes: &[u8]) {
    buffa::encoding::encode_varint(bytes.len() as u64, buf);
    buf.put_slice(bytes);
}

fn write_bytes_field(buf: &mut impl BufMut, field: u32, bytes: &[u8]) {
    if !bytes.is_empty() {
        write_tag(buf, field, buffa::encoding::WireType::LengthDelimited);
        write_bytes_body(buf, bytes);
    }
}

fn write_repeated_bytes_field(buf: &mut impl BufMut, field: u32, bytes: &[u8]) {
    write_tag(buf, field, buffa::encoding::WireType::LengthDelimited);
    write_bytes_body(buf, bytes);
}

fn codec_field_len<T: EncodeSize>(field: u32, value: &T) -> usize {
    let len = value.encode_size();
    if len == 0 {
        0
    } else {
        length_delimited_len(field, len)
    }
}

fn repeated_codec_field_len<T: EncodeSize>(field: u32, value: &T) -> usize {
    length_delimited_len(field, value.encode_size())
}

fn write_codec_body<T: CodecWrite + EncodeSize>(buf: &mut impl BufMut, value: &T) {
    let len = value.encode_size();
    buffa::encoding::encode_varint(len as u64, buf);
    let before = buf.remaining_mut();
    value.write(buf);
    debug_assert_eq!(
        before.saturating_sub(buf.remaining_mut()),
        len,
        "commonware-codec value wrote an unexpected size"
    );
}

fn write_codec_field<T: CodecWrite + EncodeSize>(buf: &mut impl BufMut, field: u32, value: &T) {
    if value.encode_size() != 0 {
        write_tag(buf, field, buffa::encoding::WireType::LengthDelimited);
        write_codec_body(buf, value);
    }
}

fn write_repeated_codec_field<T: CodecWrite + EncodeSize>(
    buf: &mut impl BufMut,
    field: u32,
    value: &T,
) {
    write_tag(buf, field, buffa::encoding::WireType::LengthDelimited);
    write_codec_body(buf, value);
}

fn message_field_len(field: u32, inner_len: usize) -> usize {
    length_delimited_len(field, inner_len)
}

fn write_message_field(buf: &mut impl BufMut, field: u32, inner_len: usize) {
    write_tag(buf, field, buffa::encoding::WireType::LengthDelimited);
    buffa::encoding::encode_varint(inner_len as u64, buf);
}

fn multi_proof_operation_len(location: u64, encoded_operation: &[u8]) -> usize {
    varint_field_len(1, location) + bytes_field_len(2, encoded_operation)
}

fn write_multi_proof_operation(buf: &mut impl BufMut, location: u64, encoded_operation: &[u8]) {
    write_u64_field(buf, 1, location);
    write_bytes_field(buf, 2, encoded_operation);
}

fn historical_multi_proof_len<D: Digest, F: Graftable>(proof: &RawBatchMultiProof<D, F>) -> usize {
    codec_field_len(1, &proof.proof)
        + proof
            .operations
            .iter()
            .map(|(location, encoded)| {
                message_field_len(2, multi_proof_operation_len(location.as_u64(), encoded))
            })
            .sum::<usize>()
        + codec_field_len(3, &proof.root)
        + proof
            .ops_root_witness
            .as_ref()
            .map(|witness| codec_field_len(4, witness))
            .unwrap_or_default()
}

fn write_historical_multi_proof<D: Digest, F: Graftable>(
    buf: &mut impl BufMut,
    proof: &RawBatchMultiProof<D, F>,
) {
    write_codec_field(buf, 1, &proof.proof);
    for (location, encoded) in &proof.operations {
        let inner_len = multi_proof_operation_len(location.as_u64(), encoded);
        write_message_field(buf, 2, inner_len);
        write_multi_proof_operation(buf, location.as_u64(), encoded);
    }
    write_codec_field(buf, 3, &proof.root);
    if let Some(witness) = &proof.ops_root_witness {
        write_codec_field(buf, 4, witness);
    }
}

fn operation_range_checkpoint_len<D: Digest, F: Graftable>(
    proof: &OperationRangeCheckpoint<D, F>,
) -> usize {
    codec_field_len(1, &proof.proof)
        + varint_field_len(2, proof.start_location.as_u64())
        + proof
            .encoded_operations
            .iter()
            .map(|encoded| repeated_bytes_field_len(3, encoded))
            .sum::<usize>()
        + codec_field_len(4, &proof.root)
        + proof
            .ops_root_witness
            .as_ref()
            .map(|witness| codec_field_len(5, witness))
            .unwrap_or_default()
        + proof
            .pinned_nodes
            .iter()
            .map(|node| repeated_codec_field_len(6, node))
            .sum::<usize>()
}

fn write_operation_range_checkpoint<D: Digest, F: Graftable>(
    buf: &mut impl BufMut,
    proof: &OperationRangeCheckpoint<D, F>,
) {
    write_codec_field(buf, 1, &proof.proof);
    write_u64_field(buf, 2, proof.start_location.as_u64());
    for encoded in &proof.encoded_operations {
        write_repeated_bytes_field(buf, 3, encoded);
    }
    write_codec_field(buf, 4, &proof.root);
    if let Some(witness) = &proof.ops_root_witness {
        write_codec_field(buf, 5, witness);
    }
    for node in &proof.pinned_nodes {
        write_repeated_codec_field(buf, 6, node);
    }
}

fn current_operation_range_proof_len<D: Digest, Op: Encode, const N: usize, F: Graftable>(
    proof: &CurrentOperationRangeProofResult<D, Op, N, F>,
) -> usize {
    codec_field_len(1, &proof.proof)
        + varint_field_len(2, proof.start_location.as_u64())
        + proof
            .operations
            .iter()
            .map(|operation| repeated_codec_field_len(3, operation))
            .sum::<usize>()
        + proof
            .chunks
            .iter()
            .map(|chunk| repeated_codec_field_len(4, chunk))
            .sum::<usize>()
}

fn write_current_operation_range_proof<D: Digest, Op: Encode, const N: usize, F: Graftable>(
    buf: &mut impl BufMut,
    proof: &CurrentOperationRangeProofResult<D, Op, N, F>,
) {
    write_codec_field(buf, 1, &proof.proof);
    write_u64_field(buf, 2, proof.start_location.as_u64());
    for operation in &proof.operations {
        write_repeated_codec_field(buf, 3, operation);
    }
    for chunk in &proof.chunks {
        write_repeated_codec_field(buf, 4, chunk);
    }
}

fn key_exclusion_proof_len<P: Encode>(proof: &P) -> usize {
    codec_field_len(1, proof)
}

fn write_key_exclusion_proof<P: Encode>(buf: &mut impl BufMut, proof: &P) {
    write_codec_field(buf, 1, proof);
}

fn key_value_proof_len<D: Digest, Op: Encode, const N: usize, F: Graftable>(
    proof: &RawKeyValueProof<D, Op, N, F>,
) -> usize {
    codec_field_len(1, &proof.proof) + codec_field_len(2, &proof.operation)
}

fn write_key_value_proof<D: Digest, Op: Encode, const N: usize, F: Graftable>(
    buf: &mut impl BufMut,
    proof: &RawKeyValueProof<D, Op, N, F>,
) {
    write_codec_field(buf, 1, &proof.proof);
    write_codec_field(buf, 2, &proof.operation);
}

fn key_lookup_result_hit_len<D: Digest, Op: Encode, const N: usize, F: Graftable>(
    proof: &RawKeyValueProof<D, Op, N, F>,
) -> usize {
    let proof_len = key_value_proof_len(proof);
    message_field_len(1, proof_len)
}

fn write_key_lookup_result_hit<D: Digest, Op: Encode, const N: usize, F: Graftable>(
    buf: &mut impl BufMut,
    proof: &RawKeyValueProof<D, Op, N, F>,
) {
    let proof_len = key_value_proof_len(proof);
    write_message_field(buf, 1, proof_len);
    write_key_value_proof(buf, proof);
}

fn key_lookup_result_miss_len<
    D: Digest,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
    F: Graftable,
    E: ValueEncoding<Value = V>,
>(
    proof: &RawKeyExclusionProof<D, K, V, N, F, E>,
) -> usize
where
    commonware_storage::qmdb::current::ordered::proof::constant::ExclusionProof<
        F, K, E, D, N,
    >: Encode,
{
    let proof_len = key_exclusion_proof_len(&proof.proof);
    message_field_len(2, proof_len)
}

fn write_key_lookup_result_miss<
    D: Digest,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
    F: Graftable,
    E: ValueEncoding<Value = V>,
>(
    buf: &mut impl BufMut,
    proof: &RawKeyExclusionProof<D, K, V, N, F, E>,
) where
    commonware_storage::qmdb::current::ordered::proof::constant::ExclusionProof<
        F, K, E, D, N,
    >: Encode,
{
    let proof_len = key_exclusion_proof_len(&proof.proof);
    write_message_field(buf, 2, proof_len);
    write_key_exclusion_proof(buf, &proof.proof);
}

pub(crate) fn get_response<D: Digest, Op: Encode, const N: usize, F: Graftable>(
    proof: &RawKeyValueProof<D, Op, N, F>,
) -> PreEncoded<GetResponse> {
    let proof_len = key_value_proof_len(proof);
    let len = message_field_len(1, proof_len);
    PreEncoded::from_bytes_unchecked(message_bytes(len, |buf| {
        write_message_field(buf, 1, proof_len);
        write_key_value_proof(buf, proof);
    }))
}

pub(crate) fn ordered_get_many_response<
    D: Digest,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
    F: Graftable,
    E: ValueEncoding<Value = V>,
>(
    proofs: &[RawKeyLookupProof<D, K, V, N, F, E>],
) -> PreEncoded<GetManyResponse>
where
    ordered::Operation<F, K, E>: Encode,
    commonware_storage::qmdb::current::ordered::proof::constant::ExclusionProof<
        F, K, E, D, N,
    >: Encode,
{
    let result_lens = proofs
        .iter()
        .map(|proof| match proof {
            RawKeyLookupProof::Hit(proof) => key_lookup_result_hit_len(proof),
            RawKeyLookupProof::Miss(proof) => key_lookup_result_miss_len(proof),
        })
        .collect::<Vec<_>>();
    let len = result_lens
        .iter()
        .map(|inner| message_field_len(1, *inner))
        .sum::<usize>();
    PreEncoded::from_bytes_unchecked(message_bytes(len, |buf| {
        for (proof, result_len) in commonware_utils::iter::zip_eq(proofs, result_lens) {
            write_message_field(buf, 1, result_len);
            match proof {
                RawKeyLookupProof::Hit(proof) => write_key_lookup_result_hit(buf, proof),
                RawKeyLookupProof::Miss(proof) => write_key_lookup_result_miss(buf, proof),
            }
        }
    }))
}

pub(crate) fn unordered_get_many_response<
    D: Digest,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
    F: Graftable,
    E: ValueEncoding<Value = V>,
>(
    proofs: &[RawKeyValueProof<D, unordered::Operation<F, K, E>, N, F>],
) -> PreEncoded<GetManyResponse>
where
    unordered::Operation<F, K, E>: Encode,
{
    let result_lens = proofs
        .iter()
        .map(key_lookup_result_hit_len)
        .collect::<Vec<_>>();
    let len = result_lens
        .iter()
        .map(|inner| message_field_len(1, *inner))
        .sum::<usize>();
    PreEncoded::from_bytes_unchecked(message_bytes(len, |buf| {
        for (proof, result_len) in commonware_utils::iter::zip_eq(proofs, result_lens) {
            write_message_field(buf, 1, result_len);
            write_key_lookup_result_hit(buf, proof);
        }
    }))
}

pub(crate) fn get_range_response<
    D: Digest,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
    F: Graftable,
    E: ValueEncoding<Value = V>,
>(
    proof: &RawKeyRangeProof<D, K, V, N, F, E>,
) -> PreEncoded<GetRangeResponse>
where
    ordered::Operation<F, K, E>: Encode,
    commonware_storage::qmdb::current::ordered::proof::constant::ExclusionProof<
        F, K, E, D, N,
    >: Encode,
{
    let entry_lens = proof
        .entries
        .iter()
        .map(key_value_proof_len)
        .collect::<Vec<_>>();
    let start_proof_len = proof
        .start_proof
        .as_ref()
        .map(|proof| key_exclusion_proof_len(&proof.proof));
    let len = entry_lens
        .iter()
        .map(|inner| message_field_len(1, *inner))
        .sum::<usize>()
        + start_proof_len
            .map(|inner| message_field_len(2, inner))
            .unwrap_or_default();
    PreEncoded::from_bytes_unchecked(message_bytes(len, |buf| {
        for (entry, entry_len) in proof.entries.iter().zip(entry_lens) {
            write_message_field(buf, 1, entry_len);
            write_key_value_proof(buf, entry);
        }
        if let (Some(proof), Some(proof_len)) = (&proof.start_proof, start_proof_len) {
            write_message_field(buf, 2, proof_len);
            write_key_exclusion_proof(buf, &proof.proof);
        }
    }))
}

pub(crate) fn get_operation_range_response<D: Digest, F: Graftable>(
    proof: &OperationRangeCheckpoint<D, F>,
    sequence_number: u64,
) -> PreEncoded<GetOperationRangeResponse> {
    let proof_len = operation_range_checkpoint_len(proof);
    let len = message_field_len(1, proof_len) + varint_field_len(2, sequence_number);
    PreEncoded::from_bytes_unchecked(message_bytes(len, |buf| {
        write_message_field(buf, 1, proof_len);
        write_operation_range_checkpoint(buf, proof);
        write_u64_field(buf, 2, sequence_number);
    }))
}

pub(crate) fn subscribe_response<D: Digest, F: Graftable>(
    resume_sequence_number: u64,
    proof: &RawBatchMultiProof<D, F>,
) -> PreEncoded<SubscribeResponse> {
    let proof_len = historical_multi_proof_len(proof);
    let len = varint_field_len(1, resume_sequence_number) + message_field_len(2, proof_len);
    PreEncoded::from_bytes_unchecked(message_bytes(len, |buf| {
        write_u64_field(buf, 1, resume_sequence_number);
        write_message_field(buf, 2, proof_len);
        write_historical_multi_proof(buf, proof);
    }))
}

pub(crate) fn get_current_operation_range_response<
    D: Digest,
    Op: Encode,
    const N: usize,
    F: Graftable,
>(
    proof: &CurrentOperationRangeProofResult<D, Op, N, F>,
) -> PreEncoded<GetCurrentOperationRangeResponse> {
    let proof_len = current_operation_range_proof_len(proof);
    let len = message_field_len(1, proof_len);
    PreEncoded::from_bytes_unchecked(message_bytes(len, |buf| {
        write_message_field(buf, 1, proof_len);
        write_current_operation_range_proof(buf, proof);
    }))
}
