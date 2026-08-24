//! Simplex certificate reporter backed by the chain Store.
//!
//! Consensus finalizes marshal commitments. Each commitment embeds the digest
//! of the Constantinople block header it certifies. This reporter writes full
//! block `{ header, body }` data by header digest for body reads, and writes
//! certificate artifacts with only the commitment-tagged header so height/latest
//! verification does not fetch the full body.

use ahash::AHashMap;
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
use std::sync::Arc;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
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

/// The Simplex uploader stopped before accepting or persisting a block.
#[derive(Debug, thiserror::Error)]
#[error("Simplex certificate uploader stopped")]
pub struct CertificateUploaderStopped;

/// Completion signal for a digest-addressed Simplex block upload.
pub struct BlockUploadCompletion {
    rx: oneshot::Receiver<()>,
}

impl BlockUploadCompletion {
    /// Wait until the block upload has been marked persisted.
    pub async fn wait(self) -> Result<(), CertificateUploaderStopped> {
        self.rx.await.map_err(|_| CertificateUploaderStopped)
    }
}

impl<H, P, S> CertificateReporter<H, P, S>
where
    H: Hasher,
    P: PublicKey,
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
        P: PublicKey + Send + Sync + 'static,
        S: Scheme + Send + Sync + 'static,
        S::Certificate: Send + Sync,
    {
        let client = SimplexClient::new(
            crate::namespaces::simplex_client(&StoreClient::new(store_url))
                .expect("simplex namespace prefix must be valid"),
        );
        let (tx, rx) = mpsc::channel(buffer);
        let join = tokio::spawn(run_uploader::<H, P, S>(client, rx, commit_metrics));
        (Self { tx }, join)
    }

    /// Queue a finalized block for digest-addressed block upload and later
    /// certificate pairing.
    pub async fn publish_block(
        &self,
        block: Arc<EngineBlock<H, P>>,
    ) -> Result<BlockUploadCompletion, CertificateUploaderStopped>
    where
        H: Hasher,
        P: PublicKey,
    {
        let (completion, rx) = oneshot::channel();
        self.tx
            .send(SimplexInput::Block { block, completion })
            .await
            .map_err(|_| CertificateUploaderStopped)?;
        Ok(BlockUploadCompletion { rx })
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
    Block {
        block: Arc<EngineBlock<H, P>>,
        completion: oneshot::Sender<()>,
    },
    Notarization(simplex::types::Notarization<S, Commitment>),
    Finalization(simplex::types::Finalization<S, Commitment>),
}

struct PendingBlockCertificates<H, P, S>
where
    H: Hasher,
    P: PublicKey,
    S: Scheme,
{
    block: Option<Arc<EngineBlock<H, P>>>,
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

/// Maximum encoded block-body bytes staged into one store commit.
const MAX_BLOCK_BYTES_PER_COMMIT: usize = 64 * 1024 * 1024;
/// Maximum inputs drained into one store commit.
const MAX_INPUTS_PER_COMMIT: usize = 256;

async fn run_uploader<H, P, S>(
    client: SimplexClient,
    mut rx: mpsc::Receiver<SimplexInput<H, P, S>>,
    commit_metrics: super::StoreCommitMetrics,
) where
    H: Hasher + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send + Sync,
{
    let mut pending: AHashMap<Vec<u8>, PendingBlockCertificates<H, P, S>> = AHashMap::new();
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
        let mut block_completions = Vec::new();
        let mut touched: Vec<Vec<u8>> = Vec::with_capacity(inputs.len());
        for input in inputs {
            let key = input.block_digest_key();
            let entry = pending.entry(key.clone()).or_default();
            match input {
                SimplexInput::Block { block, completion } => {
                    let (header, body) = crate::simplex_block::encode_simplex_block_parts(&block);
                    prepared.extend(client.prepare_block(&header, body));
                    entry.block = Some(block);
                    block_completions.push(completion);
                }
                SimplexInput::Notarization(notarization) => entry.notarization = Some(notarization),
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
        for completion in block_completions {
            let _ = completion.send(());
        }
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

impl<H, P, S> SimplexInput<H, P, S>
where
    H: Hasher,
    P: PublicKey,
    S: Scheme,
{
    fn block_digest_key(&self) -> Vec<u8> {
        match self {
            Self::Block { block, .. } => block.seal().as_ref().to_vec(),
            Self::Notarization(notarization) => {
                block_digest_key::<H>(&notarization.proposal.payload)
            }
            Self::Finalization(finalization) => {
                block_digest_key::<H>(&finalization.proposal.payload)
            }
        }
    }

    /// Encoded body bytes this input stages (certificates are negligible).
    fn body_bytes(&self) -> usize {
        match self {
            Self::Block { block, .. } => block.body.encode_size(),
            Self::Notarization(_) | Self::Finalization(_) => 0,
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
fn stage_ready_certificates<H, P, S>(
    client: &SimplexClient,
    entry: &mut PendingBlockCertificates<H, P, S>,
    prepared: &mut PreparedUpload,
) -> bool
where
    H: Hasher + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    S: Scheme + Send + Sync + 'static,
    S::Certificate: Send + Sync,
{
    let Some(block) = entry.block.as_deref() else {
        return false;
    };

    if let Some(notarization) = entry.notarization.take() {
        let certified = CertifiedHeader::new(notarization.proposal.payload, block);
        let notarized =
            Notarized::new(notarization, certified).expect("notarization matches certified header");
        prepared.extend(
            client
                .prepare_notarized(&notarized)
                .expect("notarization upload must prepare"),
        );
    }

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
#[derive(Debug, PartialEq, Eq)]
pub struct CertifiedHeader<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    commitment: Commitment,
    header: EngineHeader<H, P>,
}

impl<H, P> Clone for CertifiedHeader<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment,
            header: self.header.clone(),
        }
    }
}

impl<H, P> CertifiedHeader<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn new(commitment: Commitment, block: &EngineBlock<H, P>) -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::{
        simplex::types::Context as SimplexContext,
        types::{Round, View},
    };
    use commonware_cryptography::{
        Digest as _, Signer as _,
        bls12381::primitives::variant::MinSig,
        ed25519,
        sha256::{Digest as Sha256Digest, Sha256},
    };
    use commonware_runtime::{Runner as _, Supervisor as _};
    use commonware_utils::non_empty_range;
    use constantinople_engine::ThresholdScheme;
    use constantinople_primitives::{Block, Header, Sealable, SignedTransaction};

    type TestReporter = CertificateReporter<
        Sha256,
        ed25519::PublicKey,
        ThresholdScheme<ed25519::PublicKey, MinSig>,
    >;

    #[test]
    fn block_completion_implies_store_persistence() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (server, url) = exoware_simulator::open_temp()
                .await
                .expect("spawn simulator");
            let (reporter, uploader) = TestReporter::connect(
                &url,
                1,
                super::super::StoreCommitMetrics::new(&context.child("metrics")),
            );
            let block = test_block();
            let digest = *block.seal();

            let completion = reporter
                .publish_block(block)
                .await
                .expect("uploader accepts block");
            completion.wait().await.expect("block upload completes");

            let client = SimplexClient::new(
                crate::namespaces::simplex_client(&StoreClient::new(&url))
                    .expect("simplex namespace"),
            );
            assert!(
                client
                    .get_block_raw(&digest)
                    .await
                    .expect("read uploaded block")
                    .is_some()
            );

            drop(reporter);
            uploader.await.expect("uploader exits cleanly");
            server.abort();
        });
    }

    #[test]
    fn publish_block_reports_stopped_uploader() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (reporter, uploader) = TestReporter::connect(
                "http://127.0.0.1:1",
                1,
                super::super::StoreCommitMetrics::new(&context.child("metrics")),
            );
            uploader.abort();
            let _ = uploader.await;

            assert!(matches!(
                reporter.publish_block(test_block()).await,
                Err(CertificateUploaderStopped)
            ));
        });
    }

    #[test]
    fn block_completion_reports_stopped_uploader() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (reporter, uploader) = TestReporter::connect(
                "http://127.0.0.1:1",
                1,
                super::super::StoreCommitMetrics::new(&context.child("metrics")),
            );
            let completion = reporter
                .publish_block(test_block())
                .await
                .expect("uploader accepts block");
            uploader.abort();
            let _ = uploader.await;

            assert!(matches!(
                completion.wait().await,
                Err(CertificateUploaderStopped)
            ));
        });
    }

    fn test_block() -> Arc<EngineBlock<Sha256, ed25519::PublicKey>> {
        let leader = ed25519::PrivateKey::from_seed(1).public_key();
        let header = Header {
            context: SimplexContext {
                round: Round::zero(),
                leader,
                parent: (View::zero(), Commitment::EMPTY),
            },
            parent: Sha256Digest::EMPTY,
            height: 1,
            timestamp: 0,
            state_root: Sha256Digest::EMPTY,
            state_range: non_empty_range!(0, 2),
            transactions_root: Sha256Digest::EMPTY,
            transactions_range: non_empty_range!(0, 2),
        };
        Arc::new(
            Block::new(header, Vec::<SignedTransaction<Sha256>>::new())
                .seal(&mut Sha256::default()),
        )
    }
}
