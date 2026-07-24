//! Simplex certificate reporter backed by the chain Store.
//!
//! Consensus finalizes marshal commitments. Each commitment embeds the digest
//! of the Constantinople block header it certifies. This reporter writes full
//! block `{ header, body }` data by header digest for body reads, and writes
//! certificate artifacts with only the commitment-tagged header so height/latest
//! verification does not fetch the full body.

use ahash::AHashMap;
use bytes::Buf;
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_consensus::{
    Block, Heightable,
    simplex::types::Finalization,
    types::{Height, coding::Commitment},
};
use commonware_cryptography::{
    Digestible, Hasher, Signer, bls12381::primitives::variant::Variant, certificate::Scheme,
};
use constantinople_engine::types::{EngineBlock, EngineHeader};
use exoware_sdk::{StoreClient, StoreWriteBatch};
use exoware_simplex::{Finalized, PreparedUpload, SimplexClient};
use std::{fmt, sync::Arc};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::debug;

/// Cloneable sink for finalized blocks and their Simplex finalizations.
pub struct CertificateReporter<H, C, V, S>
where
    H: Hasher + Send + Sync + 'static,
    C: Signer + Send + Sync + 'static,
    V: Variant,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send,
{
    tx: mpsc::Sender<SimplexInput<H, C, V, S>>,
}

impl<H, C, V, S> CertificateReporter<H, C, V, S>
where
    H: Hasher,
    C: Signer,
    V: Variant,
    S: Scheme,
{
    /// Build a reporter and background uploader.
    pub fn connect(
        store_url: &str,
        buffer: usize,
        commit_metrics: super::StoreCommitMetrics,
    ) -> (Self, JoinHandle<()>)
    where
        H: Hasher + Send + Sync + 'static,
        C: Signer + Send + Sync + 'static,
        V: Variant,
        S: Scheme + Send + Sync + 'static,
        S::Certificate: Send + Sync,
    {
        let client = SimplexClient::new(
            crate::namespaces::simplex_client(&StoreClient::new(store_url))
                .expect("simplex namespace prefix must be valid"),
        );
        let (tx, rx) = mpsc::channel(buffer);
        let join = tokio::spawn(run_uploader::<H, C, V, S>(client, rx, commit_metrics));
        (Self { tx }, join)
    }

    /// Queue a finalized block for digest-addressed block upload and later
    /// certificate pairing.
    pub async fn publish_block(&self, block: Arc<EngineBlock<H, C, V>>)
    where
        H: Hasher,
        C: Signer,
        V: Variant,
    {
        let _ = self.tx.send(SimplexInput::Block(block)).await;
    }

    /// Queue the finalization corresponding to an ordered marshal block.
    ///
    /// Returns `false` if the uploader has stopped. The native marshal
    /// reporter uses that result to decide whether to acknowledge delivery.
    pub async fn publish_finalization(&self, finalization: Finalization<S, Commitment>) -> bool
    where
        S::Certificate: Send,
    {
        self.tx
            .send(SimplexInput::Finalization(finalization))
            .await
            .is_ok()
    }
}

impl<H, C, V, S> Clone for CertificateReporter<H, C, V, S>
where
    H: Hasher,
    C: Signer,
    V: Variant,
    S: Scheme,
{
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

enum SimplexInput<H, C, V, S>
where
    H: Hasher,
    C: Signer,
    V: Variant,
    S: Scheme,
{
    Block(Arc<EngineBlock<H, C, V>>),
    Finalization(Finalization<S, Commitment>),
}

struct PendingBlockCertificates<H, C, V, S>
where
    H: Hasher,
    C: Signer,
    V: Variant,
    S: Scheme,
{
    block: Option<Arc<EngineBlock<H, C, V>>>,
    finalization: Option<Finalization<S, Commitment>>,
}

impl<H, C, V, S> Default for PendingBlockCertificates<H, C, V, S>
where
    H: Hasher,
    C: Signer,
    V: Variant,
    S: Scheme,
{
    fn default() -> Self {
        Self {
            block: None,
            finalization: None,
        }
    }
}

/// Maximum encoded block-body bytes staged into one store commit.
const MAX_BLOCK_BYTES_PER_COMMIT: usize = 64 * 1024 * 1024;
/// Maximum inputs drained into one store commit.
const MAX_INPUTS_PER_COMMIT: usize = 256;

async fn run_uploader<H, C, V, S>(
    client: SimplexClient,
    mut rx: mpsc::Receiver<SimplexInput<H, C, V, S>>,
    commit_metrics: super::StoreCommitMetrics,
) where
    H: Hasher + Send + Sync + 'static,
    C: Signer + Send + Sync + 'static,
    V: Variant,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send + Sync,
{
    let mut pending: AHashMap<Vec<u8>, PendingBlockCertificates<H, C, V, S>> = AHashMap::new();
    while let Some(first) = rx.recv().await {
        // Drain the queued backlog (bounded by body bytes and input count) so
        // a burst of blocks and certificates pays one store round-trip
        // instead of one per block.
        let mut body_bytes = first.body_bytes();
        let mut inputs = vec![first];
        while inputs.len() < MAX_INPUTS_PER_COMMIT && body_bytes < MAX_BLOCK_BYTES_PER_COMMIT {
            let Ok(input) = rx.try_recv() else { break };
            body_bytes += input.body_bytes();
            inputs.push(input);
        }

        let mut prepared = PreparedUpload::new();
        let mut touched: Vec<Vec<u8>> = Vec::with_capacity(inputs.len());
        for input in inputs {
            let key = input.block_digest_key();
            let entry = pending.entry(key.clone()).or_default();
            match input {
                SimplexInput::Block(block) => {
                    let (header, body) = crate::simplex_block::encode_simplex_block_parts(&block);
                    prepared.extend(client.prepare_block(&header, body));
                    entry.block = Some(block);
                }
                SimplexInput::Finalization(finalization) => entry.finalization = Some(finalization),
            }
            touched.push(key);
        }
        touched.sort_unstable();
        touched.dedup();
        for key in touched {
            let entry = pending.get_mut(&key).expect("touched entries exist");
            if stage_ready_certificates(&client, entry, &mut prepared) {
                pending.remove(&key);
            }
        }

        if prepared.is_empty() {
            continue;
        }
        let mut batch = StoreWriteBatch::new();
        client
            .stage_upload(&prepared, &mut batch)
            .expect("prepared simplex upload must stage");
        let seq = super::commit_with_retry(
            client.store_client().client(),
            &batch,
            "simplex upload",
            &commit_metrics,
        )
        .await;
        let receipt = client.mark_upload_persisted(prepared, seq).await;
        debug!(
            headers = receipt.summary.headers,
            blocks = receipt.summary.blocks,
            notarizations = receipt.summary.notarizations,
            finalizations = receipt.summary.finalizations,
            store_sequence = receipt.store_sequence_number,
            "indexer uploaded simplex batch"
        );
    }
    debug!("simplex certificate uploader task exiting: channel closed");
}

impl<H, C, V, S> SimplexInput<H, C, V, S>
where
    H: Hasher,
    C: Signer,
    V: Variant,
    S: Scheme,
{
    fn block_digest_key(&self) -> Vec<u8> {
        match self {
            Self::Block(block) => block.seal().as_ref().to_vec(),
            Self::Finalization(finalization) => {
                block_digest_key::<H>(&finalization.proposal.payload)
            }
        }
    }

    /// Encoded body bytes this input stages (certificates are negligible).
    fn body_bytes(&self) -> usize {
        match self {
            Self::Block(block) => block.body.encode_size(),
            Self::Finalization(_) => 0,
        }
    }
}

fn block_digest_key<H>(commitment: &Commitment) -> Vec<u8>
where
    H: Hasher,
{
    commitment.block::<H::Digest>().as_ref().to_vec()
}

/// Stages the entry's ready certificates into `prepared`, returning whether a
/// finalization was staged (the entry is complete and can be dropped).
fn stage_ready_certificates<H, C, V, S>(
    client: &SimplexClient,
    entry: &mut PendingBlockCertificates<H, C, V, S>,
    prepared: &mut PreparedUpload,
) -> bool
where
    H: Hasher + Send + Sync + 'static,
    C: Signer + Send + Sync + 'static,
    V: Variant,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send + Sync,
{
    let Some(block) = entry.block.as_deref() else {
        return false;
    };

    let mut staged_finalization = false;
    if let Some(finalization) = entry.finalization.take() {
        staged_finalization = true;
        let certified = CertifiedHeader::new(finalization.proposal.payload, block);
        let finalized =
            Finalized::new(finalization, certified).expect("finalization matches certified header");
        prepared.extend(
            client
                .prepare_finalized(&finalized)
                .expect("finalization upload must prepare"),
        );
    }
    staged_finalization
}

/// A finalized header tagged with the marshal commitment certified by Simplex.
#[derive(PartialEq, Eq)]
pub struct CertifiedHeader<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    commitment: Commitment,
    header: EngineHeader<H, C, V>,
}

impl<H, C, V> fmt::Debug for CertifiedHeader<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertifiedHeader")
            .field("commitment", &self.commitment)
            .field("header_digest", self.header.seal())
            .field("height", &self.header.height)
            .finish_non_exhaustive()
    }
}

impl<H, C, V> Clone for CertifiedHeader<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment,
            header: self.header.clone(),
        }
    }
}

impl<H, C, V> CertifiedHeader<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    fn new(commitment: Commitment, block: &EngineBlock<H, C, V>) -> Self {
        debug_assert_eq!(commitment.block::<H::Digest>(), *block.seal());
        let header = EngineHeader::<H, C, V>::new_unchecked(block.header.clone(), *block.seal());
        Self { commitment, header }
    }

    /// Return the certified Constantinople block header.
    pub const fn header(&self) -> &EngineHeader<H, C, V> {
        &self.header
    }

    /// Return the certified block digest embedded in the marshal commitment.
    pub fn block_digest(&self) -> H::Digest {
        self.commitment.block::<H::Digest>()
    }
}

impl<H, C, V> Heightable for CertifiedHeader<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    fn height(&self) -> Height {
        self.header.height()
    }
}

impl<H, C, V> Digestible for CertifiedHeader<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    type Digest = Commitment;

    fn digest(&self) -> Self::Digest {
        self.commitment
    }
}

impl<H, C, V> Block for CertifiedHeader<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    fn parent(&self) -> Self::Digest {
        self.header.context.parent.1
    }
}

impl<H, C, V> EncodeSize for CertifiedHeader<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    fn encode_size(&self) -> usize {
        self.commitment.encode_size() + self.header.encode_size()
    }
}

impl<H, C, V> Write for CertifiedHeader<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.commitment.write(buf);
        self.header.write(buf);
    }
}

impl<H, C, V> Read for CertifiedHeader<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    type Cfg = <EngineHeader<H, C, V> as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let commitment = Commitment::read(buf)?;
        let header = EngineHeader::<H, C, V>::read_cfg(buf, cfg)?;
        if commitment.block::<H::Digest>() != *header.seal() {
            return Err(CodecError::Invalid(
                "CertifiedHeader",
                "commitment block digest does not match header",
            ));
        }
        Ok(Self { commitment, header })
    }
}
