//! Transaction evidence a node builds from the blocks it finalized, without Store reads.
//!
//! The transaction-history database keeps only its Merkle frontier, so a node can prove a
//! transaction only from the range its block appended. [`RecentFinalized`] keeps that range
//! for the newest blocks and answers with the bundle `GetTransaction` serves for the same
//! transaction, anchored at the block's own finalization certificate.

use super::{Bundle, Certificate, TransactionRow};
use crate::publisher::certificate::CertifiedHeader;
use buffa::Message;
use commonware_codec::Encode;
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig,
    sha256::{Digest, Sha256},
};
use commonware_cryptography_curve25519::signing::VerifyingKey;
use commonware_storage::{
    merkle::{Family as _, Location, Proof, mem::Mem, mmr, multi_proof_positions},
    qmdb,
};
use constantinople_application::consensus::{FinalizedTransactions, TransactionHistoryOperation};
use constantinople_engine::types::{EngineBlock, EngineFinalization};
use exoware_qmdb::proof::{RawBatchMultiProof, encode_operation_multi_proof};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::watch;

/// Finalized blocks kept for evidence. Evidence is requested as a block's finalization is
/// reported, so only the newest blocks are ever asked for.
pub(super) const RETAINED_BLOCKS: usize = 64;

/// Longest a request waits for its evidence, which covers the node finalizing the block, the
/// certificate lookup and the proof. A node that follows consensus without voting finalizes a
/// block after the validator that reports it.
const EVIDENCE_TIMEOUT: Duration = Duration::from_millis(150);

/// Largest encoded evidence bundle a finalization report carries.
pub const MAX_EVIDENCE_BYTES: usize = 16 * 1024;

type Block = EngineBlock<Sha256, VerifyingKey>;
type Finalization = EngineFinalization<VerifyingKey, MinSig>;

/// Why a node has no evidence for a transaction it was asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Absence {
    /// The node did not finalize the block and build the evidence in time.
    Late,
    /// The node holds no finalization certificate for the block's own height. A block finalized
    /// only through a descendant's certificate has none.
    NoCertificate,
    /// The preceding block is not retained, as after a restart or a state sync.
    ParentMissing,
    /// The bundle exceeds [`MAX_EVIDENCE_BYTES`].
    TooLarge,
    /// The node retains no block at that height that contains the transaction.
    NotFound,
}

/// The transaction-history tree after one block, built once and shared by every proof for it.
struct Tree {
    /// Every node the block's operations added above the frontier before it.
    nodes: Mem<mmr::Family, Digest>,
    /// Body index of each transaction the block appended.
    indices: HashMap<Digest, usize>,
}

impl Tree {
    /// Extends the frontier before the block with its operations. Returns `None` when the result
    /// does not reproduce the header's transactions root.
    fn new(block: &Block, transactions: &FinalizedTransactions<Sha256>) -> Option<Self> {
        let hasher = qmdb::hasher::<Sha256>();
        let mut nodes = Mem::<mmr::Family, Digest>::from_components(
            Vec::new(),
            transactions.start,
            transactions.pinned_nodes.clone(),
        )
        .ok()?;
        let mut batch = nodes.new_batch();
        let mut indices = HashMap::with_capacity(transactions.operations.len());
        for (index, operation) in transactions.operations.iter().enumerate() {
            if let TransactionHistoryOperation::<Sha256>::Append(entry) = operation {
                indices.insert(entry.digest, index);
            }
            batch = batch.add(&hasher, &operation.encode());
        }
        let batch = batch.merkleize(&nodes, &hasher);
        nodes.apply_batch(&batch).ok()?;
        let root = nodes
            .root(&hasher, inactive_peaks(block, transactions))
            .ok()?;
        (root == block.header.transactions_root).then_some(Self { nodes, indices })
    }
}

/// Peaks below the inactivity floor that the header's transactions root commits to.
fn inactive_peaks(block: &Block, transactions: &FinalizedTransactions<Sha256>) -> usize {
    mmr::Family::inactive_peaks(
        transactions.end,
        Location::new(block.header.transactions_range.start()),
    )
}

/// A finalized block, the transaction-history range it appended and its lazily built tree.
struct Recorded {
    block: Block,
    transactions: FinalizedTransactions<Sha256>,
    tree: OnceLock<Option<Tree>>,
    /// Set once the job that builds the tree has been started.
    building: AtomicBool,
    /// Set once that job has finished.
    built: watch::Sender<bool>,
}

impl Recorded {
    /// Returns the block's tree. The block's operations are hashed in one blocking job that
    /// every request for the block shares, and `merkleized` counts those jobs.
    ///
    /// The job is detached, so a request that stops waiting neither cancels nor repeats it.
    async fn tree(self: &Arc<Self>, merkleized: &Arc<AtomicU64>) -> Option<&Tree> {
        if self.tree.get().is_none() {
            if !self.building.swap(true, Ordering::AcqRel) {
                let recorded = self.clone();
                let merkleized = merkleized.clone();
                tokio::task::spawn_blocking(move || {
                    merkleized.fetch_add(1, Ordering::Relaxed);
                    let tree = Tree::new(&recorded.block, &recorded.transactions);
                    recorded.tree.get_or_init(|| tree);
                    recorded.built.send_replace(true);
                });
            }
            let mut built = self.built.subscribe();
            built.wait_for(|built| *built).await.ok()?;
        }
        self.tree.get()?.as_ref()
    }

    /// Builds the encoded bundle for the transaction at body `index`.
    fn bundle(
        &self,
        tree: &Tree,
        parent: Option<&Block>,
        finalization: Finalization,
        index: usize,
    ) -> Option<Vec<u8>> {
        let header = &self.block.header;
        let transactions = &self.transactions;
        let operation = transactions.operations.get(index)?;
        let TransactionHistoryOperation::<Sha256>::Append(entry) = operation else {
            return None;
        };
        let transaction = self.block.body.get(index)?;
        let location = transactions.start.checked_add(index as u64)?;

        // A multi-proof for one location holds the tree nodes at these positions, in this order.
        let digests = multi_proof_positions(transactions.end, &[location])
            .ok()?
            .into_iter()
            .map(|position| tree.nodes.get_node(position))
            .collect::<Option<Vec<_>>>()?;
        let proof = RawBatchMultiProof {
            watermark: Location::new(transactions.end.as_u64().checked_sub(1)?),
            ops_root: header.transactions_root,
            ops_root_witness: None,
            proof: Proof {
                leaves: transactions.end,
                inactive_peaks: inactive_peaks(&self.block, transactions),
                digests,
            },
            operations: vec![(location, operation.encode())],
        };

        // Block one has no parent header. Every later block links to its parent's digest.
        let headers = parent.map_or_else(Vec::new, |parent| vec![parent.header.encode().to_vec()]);
        let certified = CertifiedHeader::new(finalization.proposal.payload, &self.block);
        let certificate = Certificate::new(finalization, certified).ok()?;
        Some(
            Bundle {
                certificate: certificate.encode().to_vec(),
                headers,
                transactions: vec![TransactionRow {
                    location: location.as_u64(),
                    body: transaction.encoded_signed_transaction().to_vec(),
                    height: header.height,
                    index: u32::try_from(index).ok()?,
                    sender_index: entry.sender_index,
                    recipient_index: entry.recipient_index,
                    ..Default::default()
                }],
                transactions_proof: Some(encode_operation_multi_proof(&proof)),
                ..Default::default()
            }
            .encode_to_vec(),
        )
    }
}

/// The newest blocks a node finalized, from which it proves transaction inclusion.
pub struct RecentFinalized {
    blocks: Mutex<VecDeque<Arc<Recorded>>>,
    /// Height of the newest recorded block.
    height: watch::Sender<u64>,
    /// Blocks whose operations have been hashed for a proof.
    merkleized: Arc<AtomicU64>,
    /// Largest bundle returned.
    max_bytes: usize,
}

impl Default for RecentFinalized {
    fn default() -> Self {
        Self {
            blocks: Mutex::new(VecDeque::with_capacity(RETAINED_BLOCKS)),
            height: watch::Sender::new(0),
            merkleized: Arc::default(),
            max_bytes: MAX_EVIDENCE_BYTES,
        }
    }
}

impl RecentFinalized {
    /// Returns an empty ring that refuses bundles above `max_bytes`.
    #[cfg(test)]
    pub(super) fn bounded(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            ..Self::default()
        }
    }

    /// Records a finalized block with the transaction-history range it appended. Recording
    /// stores shared handles and never waits, so it can run on the finalization path.
    pub fn record(&self, block: Block, transactions: FinalizedTransactions<Sha256>) {
        let height = block.header.height;
        let recorded = Arc::new(Recorded {
            block,
            transactions,
            tree: OnceLock::new(),
            building: AtomicBool::new(false),
            built: watch::Sender::new(false),
        });
        let mut blocks = self.blocks.lock().expect("recent blocks lock poisoned");
        let evicted = (blocks.len() == RETAINED_BLOCKS)
            .then(|| blocks.pop_front())
            .flatten();
        blocks.push_back(recorded);
        drop(blocks);
        self.height.send_replace(height);

        // Freeing a block's body and tree takes time proportional to its size, so it runs on
        // a blocking thread when a runtime is present.
        if let Some(evicted) = evicted {
            match tokio::runtime::Handle::try_current() {
                Ok(runtime) => drop(runtime.spawn_blocking(move || drop(evicted))),
                Err(_) => drop(evicted),
            }
        }
    }

    /// Returns how many blocks have had their operations hashed. A block is hashed at most
    /// once, on the first request for one of its transactions.
    pub fn merkleized_blocks(&self) -> u64 {
        self.merkleized.load(Ordering::Relaxed)
    }

    /// Returns the encoded bundle `GetTransaction` serves for the transaction `digest` in the
    /// block finalized at `height`, or the reason this node cannot provide it.
    ///
    /// `finalization` resolves to the certificate the node holds for exactly `height`. It is
    /// awaited only once the block and its parent are known. The bundle carries a zero Store
    /// sequence because no Store read backs it.
    pub async fn prove(
        &self,
        height: u64,
        digest: Digest,
        finalization: impl Future<Output = Option<Finalization>> + Send,
    ) -> Result<Vec<u8>, Absence> {
        tokio::time::timeout(
            EVIDENCE_TIMEOUT,
            self.evidence(height, digest, finalization),
        )
        .await
        .unwrap_or(Err(Absence::Late))
    }

    async fn evidence(
        &self,
        height: u64,
        digest: Digest,
        finalization: impl Future<Output = Option<Finalization>> + Send,
    ) -> Result<Vec<u8>, Absence> {
        // A finalization can be reported before this node has finalized the block itself.
        let mut recorded = self.height.subscribe();
        let _ = recorded.wait_for(|recorded| *recorded >= height).await;
        let block = self.block(height).ok_or(Absence::NotFound)?;

        let tree = block
            .tree(&self.merkleized)
            .await
            .ok_or(Absence::NotFound)?;
        let index = *tree.indices.get(&digest).ok_or(Absence::NotFound)?;
        let parent = match height.checked_sub(1) {
            None | Some(0) => None,
            Some(parent) => Some(
                self.block(parent)
                    .filter(|parent| *parent.block.seal() == block.block.header.parent)
                    .ok_or(Absence::ParentMissing)?,
            ),
        };

        // Evidence anchors at the block's own certificate.
        let finalization = finalization
            .await
            .filter(|finalization| finalization.proposal.payload.block() == *block.block.seal())
            .ok_or(Absence::NoCertificate)?;
        let bundle = block
            .bundle(
                tree,
                parent.as_ref().map(|parent| &parent.block),
                finalization,
                index,
            )
            .ok_or(Absence::NotFound)?;
        if bundle.len() > self.max_bytes {
            return Err(Absence::TooLarge);
        }
        Ok(bundle)
    }

    /// Returns the recorded block at `height`, if it is still retained.
    fn block(&self, height: u64) -> Option<Arc<Recorded>> {
        self.blocks
            .lock()
            .expect("recent blocks lock poisoned")
            .iter()
            .rev()
            .find(|recorded| recorded.block.header.height == height)
            .cloned()
    }
}
