//! Simplex certificate reporter backed by the chain Store.
//!
//! Consensus finalizes marshal commitments. Each commitment embeds the digest
//! of the Constantinople block header it certifies. This reporter writes full
//! block `{ header, body }` data by header digest for body reads, and writes
//! certificate artifacts with only the commitment-tagged header so height/latest
//! verification does not fetch the full body.

use bytes::Buf;
use commonware_actor::Feedback;
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_consensus::{
    Block, Heightable, Reporter,
    simplex::{self, types::Activity},
    types::{Height, coding::Commitment},
};
use commonware_cryptography::{Digestible, Hasher, PublicKey, certificate::Scheme};
use constantinople_engine::types::{EngineBlock, EngineHeader};
use exoware_sdk::{StoreClient, StoreWriteBatch};
use exoware_simplex::{Finalized, Notarized, PreparedUpload, SimplexClient};
use std::{collections::HashMap, time::Duration};
use tokio::{sync::mpsc, task::JoinHandle, time::sleep};
use tracing::{debug, warn};

/// Cloneable reporter over Simplex activity.
pub struct CertificateReporter<H, P, S>
where
    H: Hasher + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send,
{
    tx: mpsc::Sender<SimplexInput<H, P, S>>,
}

impl<H, P, S> CertificateReporter<H, P, S>
where
    H: Hasher,
    P: PublicKey,
    S: Scheme,
{
    /// Build a reporter and background uploader.
    pub fn connect(store_url: &str, buffer: usize) -> (Self, JoinHandle<()>)
    where
        H: Hasher + Send + Sync + 'static,
        P: PublicKey + Send + Sync + 'static,
        S: Scheme + Send + Sync + 'static,
        S::Certificate: Send + Sync,
    {
        let client = SimplexClient::new(store_url);
        let (tx, rx) = mpsc::channel(buffer);
        let join = tokio::spawn(run_uploader::<H, P, S>(client, rx));
        (Self { tx }, join)
    }

    /// Queue a finalized block for digest-addressed block upload and later
    /// certificate pairing.
    pub async fn publish_block(&self, block: &EngineBlock<H, P>)
    where
        H: Hasher,
        P: PublicKey,
    {
        let _ = self.tx.send(SimplexInput::Block(block.clone())).await;
    }
}

impl<H, P, S> Clone for CertificateReporter<H, P, S>
where
    H: Hasher,
    P: PublicKey,
    S: Scheme,
{
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

impl<H, P, S> Reporter for CertificateReporter<H, P, S>
where
    H: Hasher + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send,
    simplex::types::Notarization<S, Commitment>: Send,
    simplex::types::Finalization<S, Commitment>: Send,
{
    type Activity = Activity<S, Commitment>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match activity {
            Activity::Notarization(notarization) => {
                dispatch_input(&self.tx, SimplexInput::Notarization(notarization));
            }
            Activity::Finalization(finalization) => {
                dispatch_input(&self.tx, SimplexInput::Finalization(finalization));
            }
            _ => {}
        }
        Feedback::Ok
    }
}

fn dispatch_input<H, P, S>(tx: &mpsc::Sender<SimplexInput<H, P, S>>, input: SimplexInput<H, P, S>)
where
    H: Hasher + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send,
{
    let tx = tx.clone();
    tokio::spawn(async move {
        if let Err(error) = tx.send(input).await {
            warn!("simplex certificate uploader stopped; dropping activity: {error}");
        }
    });
}

enum SimplexInput<H, P, S>
where
    H: Hasher,
    P: PublicKey,
    S: Scheme,
{
    Block(EngineBlock<H, P>),
    Notarization(simplex::types::Notarization<S, Commitment>),
    Finalization(simplex::types::Finalization<S, Commitment>),
}

struct PendingBlockCertificates<H, P, S>
where
    H: Hasher,
    P: PublicKey,
    S: Scheme,
{
    block: Option<EngineBlock<H, P>>,
    notarization: Option<simplex::types::Notarization<S, Commitment>>,
    finalization: Option<simplex::types::Finalization<S, Commitment>>,
}

impl<H, P, S> Default for PendingBlockCertificates<H, P, S>
where
    H: Hasher,
    P: PublicKey,
    S: Scheme,
{
    fn default() -> Self {
        Self {
            block: None,
            notarization: None,
            finalization: None,
        }
    }
}

async fn run_uploader<H, P, S>(client: SimplexClient, mut rx: mpsc::Receiver<SimplexInput<H, P, S>>)
where
    H: Hasher + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send + Sync,
{
    let mut pending = HashMap::<Vec<u8>, PendingBlockCertificates<H, P, S>>::new();
    while let Some(input) = rx.recv().await {
        let key = input.block_digest_key();
        let entry = pending.entry(key.clone()).or_default();
        match input {
            SimplexInput::Block(block) => {
                upload_block_by_digest(&client, &block).await;
                entry.block = Some(block);
            }
            SimplexInput::Notarization(notarization) => entry.notarization = Some(notarization),
            SimplexInput::Finalization(finalization) => entry.finalization = Some(finalization),
        }

        if !prepare_ready_upload(&client, entry).await {
            continue;
        }
        pending.remove(&key);
    }
    debug!("simplex certificate uploader task exiting: channel closed");
}

impl<H, P, S> SimplexInput<H, P, S>
where
    H: Hasher,
    P: PublicKey,
    S: Scheme,
{
    fn block_digest_key(&self) -> Vec<u8> {
        match self {
            Self::Block(block) => block.seal().as_ref().to_vec(),
            Self::Notarization(notarization) => {
                block_digest_key::<H>(&notarization.proposal.payload)
            }
            Self::Finalization(finalization) => {
                block_digest_key::<H>(&finalization.proposal.payload)
            }
        }
    }
}

async fn upload_block_by_digest<H, P>(client: &SimplexClient, block: &EngineBlock<H, P>)
where
    H: Hasher + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
{
    let (header, body) = crate::simplex_block::encode_simplex_block_parts(block);
    let prepared = client.prepare_block(&header, body);
    let mut batch = StoreWriteBatch::new();
    client
        .stage_upload(&prepared, &mut batch)
        .expect("prepared simplex block upload must stage");
    let seq = commit_with_retry(client.store_client(), &batch).await;
    let receipt = client.mark_upload_persisted(prepared, seq).await;
    debug!(
        headers = receipt.summary.headers,
        blocks = receipt.summary.blocks,
        store_sequence = receipt.store_sequence_number,
        "indexer uploaded simplex block batch"
    );
}

fn block_digest_key<H>(commitment: &Commitment) -> Vec<u8>
where
    H: Hasher,
{
    commitment.block::<H::Digest>().as_ref().to_vec()
}

async fn prepare_ready_upload<H, P, S>(
    client: &SimplexClient,
    entry: &mut PendingBlockCertificates<H, P, S>,
) -> bool
where
    H: Hasher + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send + Sync,
{
    let Some(block) = entry.block.clone() else {
        return false;
    };
    let mut prepared = PreparedUpload::new();

    if let Some(notarization) = entry.notarization.take() {
        let certified = CertifiedHeader::new(notarization.proposal.payload, block.clone());
        let notarized =
            Notarized::new(notarization, certified).expect("notarization matches certified header");
        prepared.extend(
            client
                .prepare_notarized(&notarized)
                .expect("notarization upload must prepare"),
        );
    }

    let mut uploaded_finalization = false;
    if let Some(finalization) = entry.finalization.take() {
        uploaded_finalization = true;
        let certified = CertifiedHeader::new(finalization.proposal.payload, block);
        let finalized =
            Finalized::new(finalization, certified).expect("finalization matches certified header");
        prepared.extend(
            client
                .prepare_finalized(&finalized)
                .expect("finalization upload must prepare"),
        );
    }

    if prepared.is_empty() {
        return false;
    }

    let mut batch = StoreWriteBatch::new();
    client
        .stage_upload(&prepared, &mut batch)
        .expect("prepared simplex upload must stage");
    let seq = commit_with_retry(client.store_client(), &batch).await;
    let receipt = client.mark_upload_persisted(prepared, seq).await;
    debug!(
        headers = receipt.summary.headers,
        notarizations = receipt.summary.notarizations,
        finalizations = receipt.summary.finalizations,
        store_sequence = receipt.store_sequence_number,
        "indexer uploaded simplex header certificate batch"
    );
    uploaded_finalization
}

async fn commit_with_retry(client: &StoreClient, batch: &StoreWriteBatch) -> u64 {
    let mut attempt = 0u32;
    loop {
        match batch.commit(client).await {
            Ok(seq) => return seq,
            Err(error) => {
                attempt = attempt.saturating_add(1);
                warn!(
                    ?error,
                    attempt,
                    rows = batch.len(),
                    "simplex certificate upload failed, retrying"
                );
                sleep(retry_backoff(attempt)).await;
            }
        }
    }
}

fn retry_backoff(attempt: u32) -> Duration {
    const INITIAL: Duration = Duration::from_millis(100);
    const MAX: Duration = Duration::from_secs(2);
    let factor = 1u32 << attempt.min(5);
    INITIAL.saturating_mul(factor).min(MAX)
}

/// A finalized header tagged with the marshal commitment certified by Simplex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedHeader<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    commitment: Commitment,
    header: EngineHeader<H, P>,
}

impl<H, P> CertifiedHeader<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn new(commitment: Commitment, block: EngineBlock<H, P>) -> Self {
        debug_assert_eq!(commitment.block::<H::Digest>(), *block.seal());
        let header = EngineHeader::<H, P>::new_unchecked(block.header.clone(), *block.seal());
        Self { commitment, header }
    }

    /// Return the certified Constantinople block header.
    pub const fn header(&self) -> &EngineHeader<H, P> {
        &self.header
    }

    /// Return the certified block digest embedded in the marshal commitment.
    pub fn block_digest(&self) -> H::Digest {
        self.commitment.block::<H::Digest>()
    }
}

impl<H, P> Heightable for CertifiedHeader<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn height(&self) -> Height {
        self.header.height()
    }
}

impl<H, P> Digestible for CertifiedHeader<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    type Digest = Commitment;

    fn digest(&self) -> Self::Digest {
        self.commitment
    }
}

impl<H, P> Block for CertifiedHeader<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn parent(&self) -> Self::Digest {
        self.header.context.parent.1
    }
}

impl<H, P> EncodeSize for CertifiedHeader<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn encode_size(&self) -> usize {
        self.commitment.encode_size() + self.header.encode_size()
    }
}

impl<H, P> Write for CertifiedHeader<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.commitment.write(buf);
        self.header.write(buf);
    }
}

impl<H, P> Read for CertifiedHeader<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let commitment = Commitment::read(buf)?;
        let header = EngineHeader::<H, P>::read(buf)?;
        if commitment.block::<H::Digest>() != *header.seal() {
            return Err(CodecError::Invalid(
                "CertifiedHeader",
                "commitment block digest does not match header",
            ));
        }
        Ok(Self { commitment, header })
    }
}
