use bytes::{Buf as _, BufMut, Bytes, BytesMut};
use commonware_codec::{Buf, Decode, EncodeSize, Error, Read, Write};
use commonware_consensus::{simplex::types, Block};
use commonware_cryptography::{certificate, Digest};

const HEADER_LENGTH_BYTES: usize = 4;

fn write_block_data<B>(header: &B, body: &[u8], buf: &mut impl BufMut)
where
    B: Write + EncodeSize,
{
    let header_len =
        u32::try_from(header.encode_size()).expect("header block encoding exceeds u32 length");
    buf.put_u32(header_len);
    header.write(buf);
    buf.put_slice(body);
}

pub fn encode_block_data<B>(header: &B, body: &[u8]) -> Bytes
where
    B: Write + EncodeSize,
{
    let mut buf = BytesMut::with_capacity(HEADER_LENGTH_BYTES + header.encode_size() + body.len());
    write_block_data(header, body, &mut buf);
    buf.freeze()
}

/// Simplex header bytes plus arbitrary body bytes that ride with them.
///
/// The header portion is the only part covered by the certificate digest.
/// The body portion can carry transactions or other non-certified data that
/// should be fetched and streamed with the header bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockData<B> {
    pub header: B,
    pub body: Bytes,
}

impl<B> BlockData<B> {
    pub fn new(header: B) -> Self {
        Self {
            header,
            body: Bytes::new(),
        }
    }

    pub fn with_body(header: B, body: impl Into<Bytes>) -> Self {
        Self {
            header,
            body: body.into(),
        }
    }
}

impl<B> Write for BlockData<B>
where
    B: Write + EncodeSize,
{
    fn write(&self, buf: &mut impl BufMut) {
        write_block_data(&self.header, &self.body, buf);
    }
}

impl<B> Read for BlockData<B>
where
    B: Read,
{
    type Cfg = <B as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        if buf.remaining() < HEADER_LENGTH_BYTES {
            return Err(Error::Invalid(
                "exoware_simplex::BlockData",
                "missing header length",
            ));
        }
        let header_len = buf.get_u32() as usize;
        if buf.remaining() < header_len {
            return Err(Error::Invalid(
                "exoware_simplex::BlockData",
                "header length exceeds remaining bytes",
            ));
        }
        let header = B::decode_cfg(buf.copy_to_bytes(header_len), cfg)?;
        let body = buf.copy_to_bytes(buf.remaining());
        Ok(Self { header, body })
    }
}

impl<B> EncodeSize for BlockData<B>
where
    B: EncodeSize,
{
    fn encode_size(&self) -> usize {
        HEADER_LENGTH_BYTES + self.header.encode_size() + self.body.len()
    }
}

/// A Simplex notarization plus the header bytes for its payload digest.
#[derive(Clone, Debug)]
pub struct Notarized<B, S: certificate::Scheme, D: Digest> {
    pub proof: types::Notarization<S, D>,
    pub header: B,
}

impl<B, S, D> PartialEq for Notarized<B, S, D>
where
    B: PartialEq,
    S: certificate::Scheme,
    D: Digest,
{
    fn eq(&self, other: &Self) -> bool {
        self.proof == other.proof && self.header == other.header
    }
}

impl<B, S, D> Eq for Notarized<B, S, D>
where
    B: Eq,
    S: certificate::Scheme,
    D: Digest,
{
}

impl<B, S, D> Notarized<B, S, D>
where
    B: Block<Digest = D>,
    S: certificate::Scheme,
    D: Digest,
{
    pub fn new(proof: types::Notarization<S, D>, header: B) -> Result<Self, Error> {
        if proof.proposal.payload != header.digest() {
            return Err(Error::Invalid(
                "exoware_simplex::Notarized",
                "proof payload does not match header digest",
            ));
        }
        Ok(Self { proof, header })
    }
}

impl<B, S, D> Write for Notarized<B, S, D>
where
    B: Block<Digest = D>,
    S: certificate::Scheme,
    D: Digest,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.header.write(buf);
    }
}

impl<B, S, D> Read for Notarized<B, S, D>
where
    B: Block<Digest = D>,
    S: certificate::Scheme,
    D: Digest,
    <S::Certificate as Read>::Cfg: Clone,
{
    type Cfg = (<S::Certificate as Read>::Cfg, <B as Read>::Cfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let (proof, header) = <(types::Notarization<S, D>, B) as Read>::read_cfg(buf, cfg)?;
        Self::new(proof, header)
    }
}

impl<B, S, D> EncodeSize for Notarized<B, S, D>
where
    B: Block<Digest = D>,
    S: certificate::Scheme,
    D: Digest,
{
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.header.encode_size()
    }
}

/// A Simplex finalization plus the header bytes for its payload digest.
#[derive(Clone, Debug)]
pub struct Finalized<B, S: certificate::Scheme, D: Digest> {
    pub proof: types::Finalization<S, D>,
    pub header: B,
}

impl<B, S, D> PartialEq for Finalized<B, S, D>
where
    B: PartialEq,
    S: certificate::Scheme,
    D: Digest,
{
    fn eq(&self, other: &Self) -> bool {
        self.proof == other.proof && self.header == other.header
    }
}

impl<B, S, D> Eq for Finalized<B, S, D>
where
    B: Eq,
    S: certificate::Scheme,
    D: Digest,
{
}

impl<B, S, D> Finalized<B, S, D>
where
    B: Block<Digest = D>,
    S: certificate::Scheme,
    D: Digest,
{
    pub fn new(proof: types::Finalization<S, D>, header: B) -> Result<Self, Error> {
        if proof.proposal.payload != header.digest() {
            return Err(Error::Invalid(
                "exoware_simplex::Finalized",
                "proof payload does not match header digest",
            ));
        }
        Ok(Self { proof, header })
    }
}

impl<B, S, D> Write for Finalized<B, S, D>
where
    B: Block<Digest = D>,
    S: certificate::Scheme,
    D: Digest,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.header.write(buf);
    }
}

impl<B, S, D> Read for Finalized<B, S, D>
where
    B: Block<Digest = D>,
    S: certificate::Scheme,
    D: Digest,
    <S::Certificate as Read>::Cfg: Clone,
{
    type Cfg = (<S::Certificate as Read>::Cfg, <B as Read>::Cfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let (proof, header) = <(types::Finalization<S, D>, B) as Read>::read_cfg(buf, cfg)?;
        Self::new(proof, header)
    }
}

impl<B, S, D> EncodeSize for Finalized<B, S, D>
where
    B: Block<Digest = D>,
    S: certificate::Scheme,
    D: Digest,
{
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.header.encode_size()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UploadSummary {
    pub headers: usize,
    pub blocks: usize,
    pub notarizations: usize,
    pub finalizations: usize,
    pub finalized_height_indexes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadReceipt {
    pub store_sequence_number: u64,
    pub summary: UploadSummary,
}
