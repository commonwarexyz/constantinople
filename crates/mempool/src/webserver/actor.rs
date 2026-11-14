//! Mempool webserver actor.
//!
//! Owns byte-bounded foreground and background FIFO pools. Receives
//! batch submissions from HTTP handlers and serves proposals to the
//! consensus layer via the [`Mailbox`].

use super::{
    AccountReader, ActorReceiver, Mailbox, http,
    mailbox::{Message, SubmissionLane},
};
use ahash::{AHashMap, AHashSet};
use commonware_codec::EncodeSize;
use commonware_consensus::marshal::Update;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::{ContextCell, Handle, Metrics, Spawner, spawn_cell};
use commonware_utils::{Acknowledgement, channel::fallible::OneshotExt};
use constantinople_primitives::{LazySignedTransaction, PublicKeyCache, VerifiedTransaction};
use futures::future::{Either, select};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    fmt::Display,
    hash::Hash,
    pin::pin,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tracing::warn;

const MAX_STATUS_ENTRIES: usize = 1_000_000;

/// Most messages pulled from the mailbox ahead of the one being served when proposal priority
/// is on.
const MAX_BACKLOG: usize = 4096;

/// Digests of block-report bookkeeping between chances to serve a queued proposal request when
/// proposal priority is on. A few thousand digests take on the order of a millisecond.
const REPORT_SLICE_DIGESTS: usize = 4096;

/// Shared cell that lets the mempool answer account lookups once the
/// validator's state database is attached. The cell is populated after engine
/// startup; HTTP handlers return 503 until then.
pub type AccountReaderCell = Arc<OnceLock<Arc<dyn AccountReader>>>;

/// Outcome of a submitted batch, delivered when the result is known.
///
/// Submitters already know their batch's digests, so partial finalization
/// reports counts rather than digest lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TxStatus {
    /// The batch's block was finalized.
    Finalized { height: u64 },
    /// The batch's block was finalized, but some transactions were filtered.
    PartiallyFinalized {
        height: u64,
        included: u64,
        filtered: u64,
    },
    /// The batch was proposed but its block was not finalized.
    Dropped,
}

/// Latest known status for a submitted batch, as served by the status API.
///
/// Fully finalized, dropped, and accepted batches are described by the status
/// alone (the submitter knows which digests it sent); only partial
/// finalization carries hex-encoded digest lists, so callers can tell which
/// transactions landed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BatchStatus {
    /// The batch is accepted by this validator but has not resolved yet.
    Accepted,
    /// The batch's block was finalized.
    Finalized { height: u64 },
    /// The batch's block was finalized, but some transactions were filtered.
    PartiallyFinalized {
        height: u64,
        included: Vec<String>,
        filtered: Vec<String>,
    },
    /// The batch was proposed but its block was not finalized.
    Dropped,
}

/// Actor-internal batch status.
///
/// Digests stay raw so the actor's bookkeeping never formats hex strings;
/// [`StoredBatchStatus::to_wire`] converts at the HTTP boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum StoredBatchStatus<D> {
    Accepted,
    Finalized {
        height: u64,
    },
    PartiallyFinalized {
        height: u64,
        included: Vec<D>,
        filtered: Vec<D>,
    },
    Dropped,
}

impl<D: Display> StoredBatchStatus<D> {
    /// Converts to the wire form, hex-encoding any digest lists.
    pub(super) fn to_wire(&self) -> BatchStatus {
        match self {
            Self::Accepted => BatchStatus::Accepted,
            Self::Finalized { height } => BatchStatus::Finalized { height: *height },
            Self::PartiallyFinalized {
                height,
                included,
                filtered,
            } => BatchStatus::PartiallyFinalized {
                height: *height,
                included: included.iter().map(ToString::to_string).collect(),
                filtered: filtered.iter().map(ToString::to_string).collect(),
            },
            Self::Dropped => BatchStatus::Dropped,
        }
    }

    pub(super) const fn digest_list_len(&self) -> Option<usize> {
        match self {
            Self::PartiallyFinalized {
                included, filtered, ..
            } => Some(included.len().saturating_add(filtered.len())),
            _ => None,
        }
    }
}

/// Mempool actor configuration.
pub struct Config<St: Strategy> {
    /// Maximum total bytes the pool will hold. Must exceed `max_propose_bytes`.
    pub max_pool_bytes: usize,
    /// Maximum encoded signed transaction bytes per proposal and admitted batch.
    /// Callers must reserve block framing from their encoded-block budget
    /// before setting this limit.
    pub max_propose_bytes: usize,
    /// Transaction signing namespace used for signature verification.
    pub namespace: &'static [u8],
    /// Number of finalized blocks to wait before marking a proposed
    /// batch as [`TxStatus::Dropped`].
    pub drop_grace_blocks: u64,
    /// Parallel execution strategy for ingress batch verification (decoding,
    /// seal hashing, batch signature verification), finalized-block digest
    /// extraction and block release in the actor, and hex-encoding digest
    /// lists for status responses.
    pub strategy: St,
    /// Shared cache of decompressed secp256r1 transaction public keys.
    pub public_key_cache: PublicKeyCache,
}

/// A batch of transactions waiting in the pool.
///
/// Each transaction is held behind a shared handle, the element type of a block body, so serving
/// a proposal moves handles rather than transactions. The handles of an admitted batch share one
/// buffer of `total_bytes` that holds the batch's encoding and nothing else.
struct PoolEntry<H: Hasher> {
    transactions: Vec<LazySignedTransaction<H>>,
    /// The message digest of each transaction, in order.
    digests: Vec<H::Digest>,
    total_bytes: usize,
}

struct PoolLane<H: Hasher> {
    entries: VecDeque<PoolEntry<H>>,
    bytes: usize,
}

impl<H: Hasher> PoolLane<H> {
    const fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            bytes: 0,
        }
    }
}

/// A batch proposed at a given height.
struct ProposedBatch<D> {
    height: u64,
    digests: Vec<D>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DigestOutcome {
    Finalized { height: u64 },
    Dropped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum IngestStatus {
    Accepted,
    Dropped,
}

const fn ingest_status_from_batch<D>(status: &StoredBatchStatus<D>) -> IngestStatus {
    match status {
        StoredBatchStatus::Accepted | StoredBatchStatus::Finalized { .. } => IngestStatus::Accepted,
        StoredBatchStatus::PartiallyFinalized { .. } | StoredBatchStatus::Dropped => {
            IngestStatus::Dropped
        }
    }
}

#[cfg(test)]
fn status_for_finalized_block<D>(
    height: u64,
    digests: &[D],
    finalized: &AHashSet<D>,
) -> Option<TxStatus>
where
    D: Copy + Eq + Hash,
{
    let mut included = 0;
    let mut filtered = 0;

    for digest in digests {
        if finalized.contains(digest) {
            included += 1;
        } else {
            filtered += 1;
        }
    }

    if included == 0 {
        return None;
    }

    if filtered == 0 {
        return Some(TxStatus::Finalized { height });
    }

    Some(TxStatus::PartiallyFinalized {
        height,
        included,
        filtered,
    })
}

fn batch_status_from_outcomes<D>(
    digests: &[D],
    outcomes: &AHashMap<D, DigestOutcome>,
) -> Option<StoredBatchStatus<D>>
where
    D: Copy + Eq + Hash,
{
    let mut included = Vec::new();
    let mut filtered = Vec::new();
    let mut finalized_height = 0;

    for digest in digests {
        match outcomes.get(digest) {
            Some(DigestOutcome::Finalized { height }) => {
                finalized_height = finalized_height.max(*height);
                included.push(*digest);
            }
            Some(DigestOutcome::Dropped) => filtered.push(*digest),
            None => return None,
        }
    }

    if included.is_empty() {
        return Some(StoredBatchStatus::Dropped);
    }

    if filtered.is_empty() {
        return Some(StoredBatchStatus::Finalized {
            height: finalized_height,
        });
    }

    Some(StoredBatchStatus::PartiallyFinalized {
        height: finalized_height,
        included,
        filtered,
    })
}

const fn tx_status_from_batch<D>(status: &StoredBatchStatus<D>) -> Option<TxStatus> {
    match status {
        StoredBatchStatus::Accepted => None,
        StoredBatchStatus::Finalized { height } => Some(TxStatus::Finalized { height: *height }),
        StoredBatchStatus::PartiallyFinalized {
            height,
            included,
            filtered,
        } => Some(TxStatus::PartiallyFinalized {
            height: *height,
            included: included.len() as u64,
            filtered: filtered.len() as u64,
        }),
        StoredBatchStatus::Dropped => Some(TxStatus::Dropped),
    }
}

fn remember_status<D>(
    statuses: &mut AHashMap<Arc<str>, StoredBatchStatus<D>>,
    status_order: &mut VecDeque<Arc<str>>,
    batch_id: Arc<str>,
    status: StoredBatchStatus<D>,
) -> Vec<Arc<str>> {
    if !statuses.contains_key(&batch_id) {
        status_order.push_back(Arc::clone(&batch_id));
    }
    statuses.insert(batch_id, status);

    let mut expired = Vec::new();
    while statuses.len() > MAX_STATUS_ENTRIES {
        let Some(expired_batch_id) = status_order.pop_front() else {
            break;
        };
        statuses.remove(&expired_batch_id);
        expired.push(expired_batch_id);
    }
    expired
}

fn send_pending_waiters<D>(
    pending_waiters: &mut AHashMap<Arc<str>, Vec<oneshot::Sender<TxStatus>>>,
    batch_id: &str,
    status: &StoredBatchStatus<D>,
) {
    let Some(status) = tx_status_from_batch(status) else {
        return;
    };
    let Some(waiters) = pending_waiters.remove(batch_id) else {
        return;
    };
    for waiter in waiters {
        let _ = waiter.send(status);
    }
}

fn watch_batch<D>(batch_id: &Arc<str>, digests: &[D], watchers: &mut AHashMap<D, Vec<Arc<str>>>)
where
    D: Copy + Eq + Hash,
{
    let mut seen: AHashSet<D> = AHashSet::new();
    for digest in digests {
        if !seen.insert(*digest) {
            continue;
        }
        watchers
            .entry(*digest)
            .or_default()
            .push(Arc::clone(batch_id));
    }
}

fn forget_batch<D>(
    batch_id: &str,
    batch_digests: &mut AHashMap<Arc<str>, Vec<D>>,
    watchers: &mut AHashMap<D, Vec<Arc<str>>>,
    outcomes: &mut AHashMap<D, DigestOutcome>,
    pending_waiters: &mut AHashMap<Arc<str>, Vec<oneshot::Sender<TxStatus>>>,
) where
    D: Copy + Eq + Hash,
{
    pending_waiters.remove(batch_id);
    let Some(digests) = batch_digests.remove(batch_id) else {
        return;
    };

    let mut seen: AHashSet<D> = AHashSet::new();
    for digest in digests {
        if !seen.insert(digest) {
            continue;
        }
        let Some(batch_ids) = watchers.get_mut(&digest) else {
            continue;
        };
        batch_ids.retain(|known| known.as_ref() != batch_id);
        if batch_ids.is_empty() {
            watchers.remove(&digest);
            outcomes.remove(&digest);
        }
    }
}

fn forget_expired_batches<D>(
    expired: Vec<Arc<str>>,
    batch_digests: &mut AHashMap<Arc<str>, Vec<D>>,
    watchers: &mut AHashMap<D, Vec<Arc<str>>>,
    outcomes: &mut AHashMap<D, DigestOutcome>,
    pending_waiters: &mut AHashMap<Arc<str>, Vec<oneshot::Sender<TxStatus>>>,
) where
    D: Copy + Eq + Hash,
{
    for batch_id in expired {
        forget_batch(
            &batch_id,
            batch_digests,
            watchers,
            outcomes,
            pending_waiters,
        );
    }
}

fn watched_batches_for<D>(
    digests: &[D],
    watchers: &AHashMap<D, Vec<Arc<str>>>,
) -> AHashSet<Arc<str>>
where
    D: Copy + Eq + Hash,
{
    let mut affected: AHashSet<Arc<str>> = AHashSet::new();
    for digest in digests {
        let Some(batch_ids) = watchers.get(digest) else {
            continue;
        };
        affected.extend(batch_ids.iter().cloned());
    }
    affected
}

/// Pops pool entries for a proposal at `height`, recording each served batch.
///
/// `filled` counts encoded signed transaction bytes already selected.
/// Initial selections and refills both stay within the remaining budget.
fn pop_lane_proposal<H>(
    pool: &mut PoolLane<H>,
    proposed: &mut VecDeque<ProposedBatch<H::Digest>>,
    height: u64,
    filled: usize,
    max_propose_bytes: usize,
) -> (Vec<LazySignedTransaction<H>>, usize)
where
    H: Hasher,
{
    let budget = max_propose_bytes.saturating_sub(filled);
    let mut batch_txs = Vec::new();
    let mut batch_bytes = 0;

    while let Some(entry) = pool.entries.front() {
        if entry.total_bytes > budget - batch_bytes {
            break;
        }
        let entry = pool.entries.pop_front().expect("front was Some");
        pool.bytes -= entry.total_bytes;
        batch_bytes += entry.total_bytes;
        proposed.push_back(ProposedBatch {
            height,
            digests: entry.digests,
        });
        batch_txs.extend(entry.transactions);
    }
    (batch_txs, batch_bytes)
}

fn pop_proposal<H>(
    foreground_pool: &mut PoolLane<H>,
    background_pool: &mut PoolLane<H>,
    proposed: &mut VecDeque<ProposedBatch<H::Digest>>,
    height: u64,
    filled: usize,
    max_propose_bytes: usize,
) -> Vec<LazySignedTransaction<H>>
where
    H: Hasher,
{
    let (mut transactions, foreground_bytes) =
        pop_lane_proposal(foreground_pool, proposed, height, filled, max_propose_bytes);
    let (background_transactions, _) = pop_lane_proposal(
        background_pool,
        proposed,
        height,
        filled.saturating_add(foreground_bytes),
        max_propose_bytes,
    );
    transactions.extend(background_transactions);
    transactions
}

/// Applies one finalized block's digest set to the outstanding proposed
/// batches, recording per-digest outcomes and pruning `known_digests`.
///
/// Returns the batch ids whose digests gained outcomes, for terminal-status
/// resolution by the caller.
#[cfg(test)]
fn resolve_proposed_batches<D>(
    proposed: &mut VecDeque<ProposedBatch<D>>,
    finalized: &AHashSet<D>,
    height: u64,
    drop_grace_blocks: u64,
    known_digests: &mut AHashSet<D>,
    digest_outcomes: &mut AHashMap<D, DigestOutcome>,
    digest_watchers: &AHashMap<D, Vec<Arc<str>>>,
) -> Vec<Arc<str>>
where
    D: Copy + Eq + Hash,
{
    let mut resolution = ReportResolution::new(height, drop_grace_blocks, proposed.len());
    resolution.examine(
        proposed,
        finalized,
        usize::MAX,
        known_digests,
        digest_outcomes,
        digest_watchers,
    );
    resolution.unsettled
}

/// One finalized block's effect on this node's proposed batches, applied in
/// bounded slices.
///
/// The block resolves exactly the batches proposed before it was reported.
/// They are the first `unexamined` entries of `proposed`.
///
/// Between slices the actor may serve proposal requests and nothing else.
/// Serving a request only pops pool entries and appends to `proposed` behind
/// the batches this block resolves. Resolution never touches the pools and
/// never examines those appended batches, so every result matches serving the
/// requests after the whole report.
///
/// A partial match does not prove the unmatched digests are dead. A
/// speculative reuse can split one selection across two finalized blocks,
/// with the filtered digests in the parent and the remainder in the next
/// block this node proposes. Matched digests finalize immediately. The
/// remainder stays outstanding until its own block is reported or the grace
/// window expires.
struct ReportResolution<D> {
    height: u64,
    drop_grace_blocks: u64,
    /// Batches at the front of `proposed` this block has yet to examine.
    unexamined: usize,
    /// Examined batches still outstanding, in proposal order.
    retained: VecDeque<ProposedBatch<D>>,
    /// Submitted batches whose digests gained outcomes.
    affected: AHashSet<Arc<str>>,
    /// Affected batches to check for a terminal status once every proposed
    /// batch is examined, and how many of them are checked.
    unsettled: Vec<Arc<str>>,
    settled: usize,
}

impl<D> ReportResolution<D>
where
    D: Copy + Eq + Hash,
{
    /// Starts resolving a block at `height` against the first `unexamined`
    /// proposed batches.
    fn new(height: u64, drop_grace_blocks: u64, unexamined: usize) -> Self {
        Self {
            height,
            drop_grace_blocks,
            unexamined,
            retained: VecDeque::new(),
            affected: AHashSet::new(),
            unsettled: Vec::new(),
            settled: 0,
        }
    }

    /// Records outcomes for whole batches from the front of `proposed` until
    /// `budget` digests are spent, returning whether every batch is examined.
    fn examine(
        &mut self,
        proposed: &mut VecDeque<ProposedBatch<D>>,
        finalized: &AHashSet<D>,
        budget: usize,
        known_digests: &mut AHashSet<D>,
        digest_outcomes: &mut AHashMap<D, DigestOutcome>,
        digest_watchers: &AHashMap<D, Vec<Arc<str>>>,
    ) -> bool {
        let mut spent = 0usize;
        while self.unexamined > 0 && spent < budget {
            let batch = proposed
                .pop_front()
                .expect("unexamined batches must stay at the front");
            self.unexamined -= 1;
            spent = spent.saturating_add(batch.digests.len().max(1));

            let expired = self.height >= batch.height + self.drop_grace_blocks;
            let any_finalized = batch
                .digests
                .iter()
                .any(|digest| finalized.contains(digest));
            if !any_finalized && !expired {
                self.retained.push_back(batch);
                continue;
            }

            self.affected
                .extend(watched_batches_for(&batch.digests, digest_watchers));
            let mut outstanding = Vec::new();
            for digest in &batch.digests {
                if finalized.contains(digest) {
                    digest_outcomes.insert(
                        *digest,
                        DigestOutcome::Finalized {
                            height: self.height,
                        },
                    );
                    known_digests.remove(digest);
                } else if expired {
                    digest_outcomes.insert(*digest, DigestOutcome::Dropped);
                    known_digests.remove(digest);
                } else {
                    outstanding.push(*digest);
                }
            }
            if !outstanding.is_empty() {
                self.retained.push_back(ProposedBatch {
                    height: batch.height,
                    digests: outstanding,
                });
            }
        }
        if self.unexamined > 0 {
            return false;
        }

        // Batches proposed during the report follow the retained ones, as
        // they would had they been proposed after it.
        self.retained.append(proposed);
        std::mem::swap(proposed, &mut self.retained);
        self.unsettled.extend(self.affected.drain());
        true
    }

    /// Resolves terminal statuses for affected batches until `budget` digests
    /// are spent, returning whether every affected batch is checked. Call
    /// only after [`Self::examine`] has returned `true`.
    #[allow(clippy::too_many_arguments)]
    fn settle(
        &mut self,
        budget: usize,
        statuses: &mut AHashMap<Arc<str>, StoredBatchStatus<D>>,
        status_order: &mut VecDeque<Arc<str>>,
        batch_digests: &mut AHashMap<Arc<str>, Vec<D>>,
        digest_watchers: &mut AHashMap<D, Vec<Arc<str>>>,
        digest_outcomes: &mut AHashMap<D, DigestOutcome>,
        pending_waiters: &mut AHashMap<Arc<str>, Vec<oneshot::Sender<TxStatus>>>,
    ) -> bool {
        let mut spent = 0usize;
        while spent < budget {
            let Some(batch_id) = self.unsettled.get(self.settled) else {
                return true;
            };
            self.settled += 1;
            spent = spent.saturating_add(
                batch_digests
                    .get(batch_id.as_ref())
                    .map_or(1, |digests| digests.len().max(1)),
            );
            resolve_batch_if_terminal(
                batch_id,
                statuses,
                status_order,
                batch_digests,
                digest_watchers,
                digest_outcomes,
                pending_waiters,
            );
        }
        self.settled == self.unsettled.len()
    }
}

/// Moves already queued messages into `backlog`, up to [`MAX_BACKLOG`].
fn fill_backlog<T>(backlog: &mut VecDeque<T>, rx: &mut mpsc::Receiver<T>) {
    while backlog.len() < MAX_BACKLOG {
        let Ok(message) = rx.try_recv() else {
            break;
        };
        backlog.push_back(message);
    }
}

/// Serves every proposal request queued in the mailbox or `backlog`, leaving
/// other messages in `backlog` in arrival order.
fn serve_queued_proposals<C, P, H>(
    backlog: &mut VecDeque<Message<C, P, H>>,
    rx: &mut mpsc::Receiver<Message<C, P, H>>,
    foreground_pool: &mut PoolLane<H>,
    background_pool: &mut PoolLane<H>,
    proposed: &mut VecDeque<ProposedBatch<H::Digest>>,
    max_propose_bytes: usize,
) where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    fill_backlog(backlog, rx);
    while let Some(index) = backlog
        .iter()
        .position(|message| matches!(message, Message::Propose { .. }))
    {
        let Some(Message::Propose {
            height,
            filled,
            response,
        }) = backlog.remove(index)
        else {
            unreachable!("the position must hold a proposal request");
        };
        let batch_txs = pop_proposal(
            foreground_pool,
            background_pool,
            proposed,
            height,
            filled,
            max_propose_bytes,
        );
        response.send_lossy(batch_txs);
    }
}

fn resolve_batch_if_terminal<D>(
    batch_id: &Arc<str>,
    statuses: &mut AHashMap<Arc<str>, StoredBatchStatus<D>>,
    status_order: &mut VecDeque<Arc<str>>,
    batch_digests: &mut AHashMap<Arc<str>, Vec<D>>,
    digest_watchers: &mut AHashMap<D, Vec<Arc<str>>>,
    digest_outcomes: &mut AHashMap<D, DigestOutcome>,
    pending_waiters: &mut AHashMap<Arc<str>, Vec<oneshot::Sender<TxStatus>>>,
) where
    D: Copy + Eq + Hash,
{
    let Some(digests) = batch_digests.get(batch_id.as_ref()) else {
        return;
    };
    let Some(status) = batch_status_from_outcomes(digests, digest_outcomes) else {
        return;
    };

    let expired = remember_status(statuses, status_order, Arc::clone(batch_id), status);
    if let Some(status) = statuses.get(batch_id.as_ref()) {
        send_pending_waiters(pending_waiters, batch_id.as_ref(), status);
    }
    forget_batch(
        batch_id.as_ref(),
        batch_digests,
        digest_watchers,
        digest_outcomes,
        pending_waiters,
    );
    forget_expired_batches(
        expired,
        batch_digests,
        digest_watchers,
        digest_outcomes,
        pending_waiters,
    );
}

/// Builds the pool entry of a submission's transactions not already known, recording their
/// digests as known.
fn new_entry<H>(
    transactions: Vec<VerifiedTransaction<H>>,
    known_digests: &mut AHashSet<H::Digest>,
) -> PoolEntry<H>
where
    H: Hasher,
    H::Digest: Copy + Eq + Hash,
{
    let mut entry = PoolEntry {
        transactions: Vec::with_capacity(transactions.len()),
        digests: Vec::with_capacity(transactions.len()),
        total_bytes: 0,
    };
    for transaction in transactions {
        let digest = *transaction.message_digest();
        if !known_digests.insert(digest) {
            continue;
        }
        entry.total_bytes += transaction.encode_size();
        entry.digests.push(digest);
        entry
            .transactions
            .push(LazySignedTransaction::new(transaction));
    }
    entry
}

fn remove_known_digests<D>(digests: &[D], known_digests: &mut AHashSet<D>)
where
    D: Eq + Hash,
{
    for digest in digests {
        known_digests.remove(digest);
    }
}

fn can_admit_submission(
    lane: SubmissionLane,
    foreground_pool_bytes: usize,
    background_pool_bytes: usize,
    batch_bytes: usize,
    max_pool_bytes: usize,
    max_propose_bytes: usize,
) -> bool {
    if batch_bytes > max_propose_bytes {
        return false;
    }

    let Some(total_bytes) = foreground_pool_bytes
        .checked_add(background_pool_bytes)
        .and_then(|total| total.checked_add(batch_bytes))
    else {
        return false;
    };
    if total_bytes > max_pool_bytes {
        return false;
    }

    match lane {
        SubmissionLane::Foreground => true,
        SubmissionLane::Background => background_pool_bytes
            .checked_add(batch_bytes)
            .is_some_and(|bytes| bytes <= max_pool_bytes.saturating_sub(max_propose_bytes)),
    }
}

/// The mempool actor.
///
/// Create via [`Actor::new`], which consumes the receiver half of a mailbox
/// created by [`Mailbox::channel`](super::Mailbox::channel). Call
/// [`Actor::start`] to spawn the event loop and HTTP server on the runtime.
pub struct Actor<E, C, P, H, St>
where
    E: Spawner,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    context: ContextCell<E>,
    mailbox: Mailbox<C, P, H>,
    rx: mpsc::Receiver<Message<C, P, H>>,
    foreground_pool: PoolLane<H>,
    background_pool: PoolLane<H>,
    max_pool_bytes: usize,
    max_propose_bytes: usize,
    namespace: &'static [u8],
    drop_grace_blocks: u64,
    strategy: St,
    public_key_cache: PublicKeyCache,
    account_reader: AccountReaderCell,
}

impl<E, C, P, H, St> Actor<E, C, P, H, St>
where
    E: Spawner + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    H::Digest: Eq + Hash,
    St: Strategy,
{
    /// Creates a new mempool actor.
    ///
    /// `mailbox` is the handle previously paired with `receiver` by
    /// [`Mailbox::channel`](super::Mailbox::channel). `account_reader` is a
    /// shared cell populated once the validator's state database is attached;
    /// HTTP account lookups return `503 Service Unavailable` while it is
    /// empty.
    pub fn new(
        context: E,
        config: Config<St>,
        mailbox: Mailbox<C, P, H>,
        receiver: ActorReceiver<C, P, H>,
        account_reader: AccountReaderCell,
    ) -> Self {
        assert!(
            config.max_pool_bytes > config.max_propose_bytes,
            "pool must leave capacity for background submissions"
        );
        Self {
            context: ContextCell::new(context),
            mailbox,
            rx: receiver.rx,
            foreground_pool: PoolLane::new(),
            background_pool: PoolLane::new(),
            max_pool_bytes: config.max_pool_bytes,
            max_propose_bytes: config.max_propose_bytes,
            namespace: config.namespace,
            drop_grace_blocks: config.drop_grace_blocks,
            strategy: config.strategy,
            public_key_cache: config.public_key_cache,
            account_reader,
        }
    }

    /// Spawns the actor event loop and HTTP server on the runtime.
    ///
    pub fn start(mut self, listener: tokio::net::TcpListener) -> Handle<()> {
        spawn_cell!(self.context, self.run(listener))
    }

    async fn run(self, listener: tokio::net::TcpListener) {
        let Self {
            context,
            mailbox,
            mut rx,
            mut foreground_pool,
            mut background_pool,
            max_pool_bytes,
            max_propose_bytes,
            namespace,
            drop_grace_blocks,
            strategy,
            public_key_cache,
            account_reader,
        } = self;

        let background_capacity = max_pool_bytes - max_propose_bytes;
        let background_bytes = Arc::new(AtomicUsize::new(0));
        let app_state = Arc::new(http::AppState {
            mailbox,
            namespace,
            max_batch_bytes: max_propose_bytes,
            background_capacity,
            background_bytes: background_bytes.clone(),
            strategy: strategy.clone(),
            public_key_cache,
            account_reader,
            ingress_permits: Arc::new(Semaphore::new(
                http::INGRESS_PERMITS.load(Ordering::Relaxed),
            )),
        });
        let app = http::router::<C, P, H, St>(app_state);
        let _http_handle = context.as_present().child("http").spawn(|_| async {
            let _ = axum::serve(listener, app).await;
        });

        let mut proposed: VecDeque<ProposedBatch<H::Digest>> = VecDeque::new();
        let mut statuses: AHashMap<Arc<str>, StoredBatchStatus<H::Digest>> = AHashMap::new();
        let mut status_order = VecDeque::new();
        let mut batch_digests: AHashMap<Arc<str>, Vec<H::Digest>> = AHashMap::new();
        let mut digest_watchers: AHashMap<H::Digest, Vec<Arc<str>>> = AHashMap::new();
        let mut digest_outcomes: AHashMap<H::Digest, DigestOutcome> = AHashMap::new();
        let mut pending_waiters: AHashMap<Arc<str>, Vec<oneshot::Sender<TxStatus>>> =
            AHashMap::new();
        let mut known_digests: AHashSet<H::Digest> = AHashSet::new();

        // With proposal priority on, everything already queued is taken first and a proposal
        // request among it is served before the rest, and block reports pause between bounded
        // slices to serve proposal requests that arrive meanwhile.
        let prioritize = http::PROPOSE_PRIORITY.load(Ordering::Relaxed);
        let report_slice = if prioritize {
            REPORT_SLICE_DIGESTS
        } else {
            usize::MAX
        };
        let mut backlog: VecDeque<Message<C, P, H>> = VecDeque::new();
        loop {
            background_bytes.store(background_pool.bytes, Ordering::Relaxed);
            if backlog.is_empty() {
                let Some(message) = rx.recv().await else {
                    break;
                };
                backlog.push_back(message);
            }
            if prioritize {
                fill_backlog(&mut backlog, &mut rx);
            }
            let next = if prioritize {
                backlog
                    .iter()
                    .position(|message| matches!(message, Message::Propose { .. }))
                    .unwrap_or(0)
            } else {
                0
            };
            let message = backlog
                .remove(next)
                .expect("the backlog must hold a message");
            match message {
                Message::Submit {
                    lane,
                    batch_id,
                    digests,
                    transactions,
                    result,
                    ingest_result,
                } => {
                    let batch_id: Arc<str> = batch_id.into();
                    if let Some(status) = statuses.get(batch_id.as_ref()) {
                        if let Some(ingest_result) = ingest_result {
                            let _ = ingest_result.send(ingest_status_from_batch(status));
                        }
                        if let Some(result) = result {
                            if let Some(status) = tx_status_from_batch(status) {
                                let _ = result.send(status);
                            } else {
                                pending_waiters.entry(batch_id).or_default().push(result);
                            }
                        }
                        continue;
                    }

                    let mut entry = new_entry(transactions, &mut known_digests);
                    if !entry.transactions.is_empty()
                        && !can_admit_submission(
                            lane,
                            foreground_pool.bytes,
                            background_pool.bytes,
                            entry.total_bytes,
                            max_pool_bytes,
                            max_propose_bytes,
                        )
                    {
                        remove_known_digests(&entry.digests, &mut known_digests);

                        // A background batch that would fit the empty pool is refused only for
                        // lack of room right now. Its waiter is closed without an answer, which
                        // tells the submitter to retry the identical batch. Other refusals are
                        // final.
                        let retryable = lane == SubmissionLane::Background
                            && can_admit_submission(
                                lane,
                                0,
                                0,
                                entry.total_bytes,
                                max_pool_bytes,
                                max_propose_bytes,
                            );
                        if let Some(result) = result.filter(|_| !retryable) {
                            let _ = result.send(TxStatus::Dropped);
                        }
                        if let Some(ingest_result) = ingest_result {
                            let _ = ingest_result.send(IngestStatus::Dropped);
                        }
                        continue;
                    }

                    let expired = remember_status(
                        &mut statuses,
                        &mut status_order,
                        Arc::clone(&batch_id),
                        StoredBatchStatus::Accepted,
                    );
                    watch_batch(&batch_id, &digests, &mut digest_watchers);
                    batch_digests.insert(Arc::clone(&batch_id), digests);
                    forget_expired_batches(
                        expired,
                        &mut batch_digests,
                        &mut digest_watchers,
                        &mut digest_outcomes,
                        &mut pending_waiters,
                    );
                    if let Some(result) = result {
                        pending_waiters
                            .entry(Arc::clone(&batch_id))
                            .or_default()
                            .push(result);
                    }
                    if let Some(ingest_result) = ingest_result {
                        let _ = ingest_result.send(IngestStatus::Accepted);
                    }
                    if !entry.transactions.is_empty() {
                        // The batch is queued with its encoding in one buffer, so a block that
                        // takes it encodes it by copying that buffer.
                        LazySignedTransaction::pack(&mut entry.transactions);
                        let pool = match lane {
                            SubmissionLane::Foreground => &mut foreground_pool,
                            SubmissionLane::Background => &mut background_pool,
                        };
                        pool.bytes += entry.total_bytes;
                        pool.entries.push_back(entry);
                    }
                }
                Message::QueryStatus { batch_id, response } => {
                    let _ = response.send(statuses.get(batch_id.as_str()).cloned());
                }
                Message::Propose {
                    height,
                    filled,
                    response,
                } => {
                    let batch_txs = pop_proposal(
                        &mut foreground_pool,
                        &mut background_pool,
                        &mut proposed,
                        height,
                        filled,
                        max_propose_bytes,
                    );
                    response.send_lossy(batch_txs);
                }
                Message::Report(Update::Block(block, acknowledgement)) => {
                    // Only this node's outstanding proposals consume the
                    // finalized-digest set (~1 in `participants` views), so
                    // the full-body decode is skipped otherwise. Adaptive
                    // scheduling may release a small block inline.
                    if proposed.is_empty() {
                        let work_size = block.inner().body.len();
                        drop(strategy.spawn(work_size, move |_: St| drop(block)));
                        acknowledgement.acknowledge();
                        continue;
                    }

                    let height = block.inner().header.height;
                    let work_size = block.inner().body.len();

                    // The block resolves the batches proposed so far. Requests served while it
                    // is in progress propose behind them.
                    let mut resolution =
                        ReportResolution::new(height, drop_grace_blocks, proposed.len());

                    // Deriving the finalized set decodes any transaction the
                    // application has not already materialized. The strategy
                    // schedules that work and block release together, but may
                    // run small jobs inline. With proposal priority on, requests
                    // arriving during an off-task extraction are served at once.
                    let extraction = strategy.spawn(work_size, move |_: St| {
                        block
                            .inner()
                            .body
                            .iter()
                            .filter_map(|tx| tx.get().map(|tx| *tx.message_digest()))
                            .collect::<AHashSet<H::Digest>>()
                    });
                    let finalized = if prioritize {
                        let mut extraction = pin!(extraction);
                        loop {
                            let received = {
                                let receive = pin!(rx.recv());
                                match select(extraction.as_mut(), receive).await {
                                    Either::Left((finalized, _)) => break finalized,
                                    Either::Right((received, _)) => received,
                                }
                            };
                            let Some(message) = received else {
                                break extraction.await;
                            };
                            backlog.push_back(message);
                            serve_queued_proposals(
                                &mut backlog,
                                &mut rx,
                                &mut foreground_pool,
                                &mut background_pool,
                                &mut proposed,
                                max_propose_bytes,
                            );
                        }
                    } else {
                        extraction.await
                    };

                    while !resolution.examine(
                        &mut proposed,
                        &finalized,
                        report_slice,
                        &mut known_digests,
                        &mut digest_outcomes,
                        &digest_watchers,
                    ) {
                        serve_queued_proposals(
                            &mut backlog,
                            &mut rx,
                            &mut foreground_pool,
                            &mut background_pool,
                            &mut proposed,
                            max_propose_bytes,
                        );
                    }
                    while !resolution.settle(
                        report_slice,
                        &mut statuses,
                        &mut status_order,
                        &mut batch_digests,
                        &mut digest_watchers,
                        &mut digest_outcomes,
                        &mut pending_waiters,
                    ) {
                        serve_queued_proposals(
                            &mut backlog,
                            &mut rx,
                            &mut foreground_pool,
                            &mut background_pool,
                            &mut proposed,
                            max_propose_bytes,
                        );
                    }

                    acknowledgement.acknowledge();
                }
                Message::Report(Update::Tip(..)) => {}
            }
        }
        warn!("mempool actor stopped: all senders dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Actor, ActorReceiver, Config, DigestOutcome, IngestStatus, Mailbox, Message, PoolEntry,
        PoolLane, ProposedBatch, ReportResolution, StoredBatchStatus, SubmissionLane, TxStatus,
        batch_status_from_outcomes, can_admit_submission, ingest_status_from_batch, new_entry,
        pop_lane_proposal, pop_proposal, remember_status, resolve_proposed_batches,
        serve_queued_proposals, status_for_finalized_block, watch_batch,
    };
    use ahash::{AHashMap, AHashSet};
    use commonware_codec::{Encode as _, EncodeSize as _};
    use commonware_cryptography::{Signer, sha256};
    use commonware_cryptography_curve25519::signing as ed25519;
    use commonware_math::algebra::Random;
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, Supervisor as _};
    use commonware_utils::NZUsize;
    use constantinople_primitives::{
        LazySignedTransaction, PublicKeyCache, TRANSACTION_NAMESPACE, Transaction,
        TransactionPublicKey, VerifiedTransaction,
    };
    use core::num::NonZeroU64;
    use rand::{SeedableRng, rngs::StdRng};
    use std::{
        collections::VecDeque,
        sync::{Arc, OnceLock},
    };
    use tokio::sync::{mpsc, oneshot};

    #[test]
    #[should_panic(expected = "pool must leave capacity for background submissions")]
    fn background_requires_capacity_beyond_foreground_reserve() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (mailbox, receiver) =
                Mailbox::<sha256::Digest, ed25519::VerifyingKey, sha256::Sha256>::channel(1);
            let config = Config {
                max_pool_bytes: 1_000,
                max_propose_bytes: 1_000,
                namespace: TRANSACTION_NAMESPACE,
                drop_grace_blocks: 2,
                strategy: Sequential,
                public_key_cache: PublicKeyCache::new(
                    context.child("public_key_cache"),
                    NZUsize!(16),
                ),
            };

            let _actor = Actor::new(
                context,
                config,
                mailbox,
                receiver,
                Arc::new(OnceLock::new()),
            );
        });
    }

    #[test]
    fn terminal_batch_statuses_preserve_ingest_truth() {
        assert_eq!(
            ingest_status_from_batch::<sha256::Digest>(&StoredBatchStatus::Accepted),
            IngestStatus::Accepted,
        );
        assert_eq!(
            ingest_status_from_batch::<sha256::Digest>(&StoredBatchStatus::Finalized { height: 7 }),
            IngestStatus::Accepted,
        );
        assert_eq!(
            ingest_status_from_batch(&StoredBatchStatus::PartiallyFinalized {
                height: 7,
                included: vec![sha256::Digest::from([1; 32])],
                filtered: vec![sha256::Digest::from([2; 32])],
            }),
            IngestStatus::Dropped,
        );
        assert_eq!(
            ingest_status_from_batch::<sha256::Digest>(&StoredBatchStatus::Dropped),
            IngestStatus::Dropped,
        );
    }

    #[test]
    fn partial_finalization_reports_filtered_digests() {
        let mut rng = StdRng::from_seed([7; 32]);
        let first = sha256::Digest::random(&mut rng);
        let second = sha256::Digest::random(&mut rng);
        let third = sha256::Digest::random(&mut rng);
        let digests = vec![first, second, third];
        let finalized = [first, third].into_iter().collect::<AHashSet<_>>();

        let status = status_for_finalized_block(42, &digests, &finalized);

        assert_eq!(
            status,
            Some(TxStatus::PartiallyFinalized {
                height: 42,
                included: 2,
                filtered: 1,
            }),
        );
    }

    #[test]
    fn finalized_status_requires_full_inclusion() {
        let mut rng = StdRng::from_seed([9; 32]);
        let first = sha256::Digest::random(&mut rng);
        let second = sha256::Digest::random(&mut rng);
        let digests = vec![first, second];
        let finalized = [first, second].into_iter().collect::<AHashSet<_>>();

        let status = status_for_finalized_block(11, &digests, &finalized);

        assert_eq!(status, Some(TxStatus::Finalized { height: 11 }));
    }

    #[test]
    fn new_transactions_filters_duplicate_digests() {
        let signer = ed25519::SigningKey::from_seed(1);
        let recipient = ed25519::SigningKey::from_seed(2).public_key();
        let transaction = Transaction::new(
            TransactionPublicKey::ed25519(signer.public_key()),
            TransactionPublicKey::ed25519(recipient),
            NonZeroU64::new(1).expect("non-zero"),
            0,
        )
        .seal_and_sign(
            &signer,
            TRANSACTION_NAMESPACE,
            &mut sha256::Sha256::default(),
        );
        let duplicate = transaction.clone();
        let mut known: AHashSet<_> = AHashSet::new();

        let entry = new_entry(vec![transaction, duplicate], &mut known);

        assert_eq!(entry.transactions.len(), 1);
        assert_eq!(entry.digests.len(), 1);
        assert_eq!(known.len(), 1);
    }

    #[test]
    fn batch_status_waits_for_duplicate_digest_outcomes() {
        let mut rng = StdRng::from_seed([11; 32]);
        let first = sha256::Digest::random(&mut rng);
        let second = sha256::Digest::random(&mut rng);
        let digests = vec![first, second];
        let outcomes = [(first, DigestOutcome::Finalized { height: 7 })]
            .into_iter()
            .collect::<AHashMap<_, _>>();

        let status = batch_status_from_outcomes(&digests, &outcomes);

        assert_eq!(status, None);
    }

    #[test]
    fn batch_status_reports_partially_finalized_duplicate_batch() {
        let mut rng = StdRng::from_seed([13; 32]);
        let first = sha256::Digest::random(&mut rng);
        let second = sha256::Digest::random(&mut rng);
        let digests = vec![first, second];
        let outcomes = [
            (first, DigestOutcome::Finalized { height: 7 }),
            (second, DigestOutcome::Dropped),
        ]
        .into_iter()
        .collect::<AHashMap<_, _>>();

        let status = batch_status_from_outcomes(&digests, &outcomes);

        assert_eq!(
            status,
            Some(StoredBatchStatus::PartiallyFinalized {
                height: 7,
                included: vec![first],
                filtered: vec![second],
            }),
        );
    }

    /// A speculative reuse can split one selection across two finalized
    /// blocks: the filtered digest lands in the parent, the remainder in the
    /// next block this node proposes. Both must resolve as finalized.
    #[test]
    fn split_selection_finalizes_across_two_blocks() {
        let mut rng = StdRng::from_seed([17; 32]);
        let filtered = sha256::Digest::random(&mut rng);
        let reused = sha256::Digest::random(&mut rng);
        let mut proposed = VecDeque::from([ProposedBatch {
            height: 2,
            digests: vec![filtered, reused],
        }]);
        let mut known: AHashSet<_> = [filtered, reused].into_iter().collect();
        let mut outcomes = AHashMap::new();
        let watchers = AHashMap::new();

        // The parent block (containing the filtered digest) finalizes first.
        let parent_body: AHashSet<_> = [filtered].into_iter().collect();
        resolve_proposed_batches(
            &mut proposed,
            &parent_body,
            2,
            10,
            &mut known,
            &mut outcomes,
            &watchers,
        );
        assert_eq!(proposed.len(), 1, "remainder must stay outstanding");
        assert_eq!(proposed[0].digests, vec![reused]);
        assert_eq!(
            batch_status_from_outcomes(&[filtered, reused], &outcomes),
            None,
            "batch must not resolve until the remainder settles"
        );

        // The reuse block (containing the remainder) finalizes next.
        let reuse_body: AHashSet<_> = [reused].into_iter().collect();
        resolve_proposed_batches(
            &mut proposed,
            &reuse_body,
            3,
            10,
            &mut known,
            &mut outcomes,
            &watchers,
        );
        assert!(proposed.is_empty());
        assert!(known.is_empty());
        assert_eq!(
            batch_status_from_outcomes(&[filtered, reused], &outcomes),
            Some(StoredBatchStatus::Finalized { height: 3 }),
            "both digests finalized, split across blocks"
        );
    }

    /// A remainder that never finalizes still ages out at the grace bound.
    #[test]
    fn split_selection_remainder_drops_after_grace() {
        let mut rng = StdRng::from_seed([19; 32]);
        let included = sha256::Digest::random(&mut rng);
        let dead = sha256::Digest::random(&mut rng);
        let mut proposed = VecDeque::from([ProposedBatch {
            height: 2,
            digests: vec![included, dead],
        }]);
        let mut known: AHashSet<_> = [included, dead].into_iter().collect();
        let mut outcomes = AHashMap::new();
        let watchers = AHashMap::new();

        let first_body: AHashSet<_> = [included].into_iter().collect();
        resolve_proposed_batches(
            &mut proposed,
            &first_body,
            2,
            3,
            &mut known,
            &mut outcomes,
            &watchers,
        );
        assert_eq!(proposed.len(), 1);

        // Nothing includes the remainder; grace (height 2 + 3) expires it.
        let empty_body = AHashSet::new();
        resolve_proposed_batches(
            &mut proposed,
            &empty_body,
            5,
            3,
            &mut known,
            &mut outcomes,
            &watchers,
        );
        assert!(proposed.is_empty());
        assert_eq!(
            batch_status_from_outcomes(&[included, dead], &outcomes),
            Some(StoredBatchStatus::PartiallyFinalized {
                height: 2,
                included: vec![included],
                filtered: vec![dead],
            }),
        );
    }

    /// A whole selection that lands entirely in one block resolves
    /// immediately; one that is never included drops once the grace window
    /// expires.
    #[test]
    fn whole_selection_finalizes_in_one_block_or_drops_after_grace() {
        let mut rng = StdRng::from_seed([23; 32]);
        let a = sha256::Digest::random(&mut rng);
        let b = sha256::Digest::random(&mut rng);

        // Full inclusion resolves immediately.
        let mut proposed = VecDeque::from([ProposedBatch {
            height: 2,
            digests: vec![a, b],
        }]);
        let mut known: AHashSet<_> = [a, b].into_iter().collect();
        let mut outcomes = AHashMap::new();
        let body: AHashSet<_> = [a, b].into_iter().collect();
        resolve_proposed_batches(
            &mut proposed,
            &body,
            2,
            10,
            &mut known,
            &mut outcomes,
            &AHashMap::new(),
        );
        assert!(proposed.is_empty());
        assert_eq!(
            batch_status_from_outcomes(&[a, b], &outcomes),
            Some(StoredBatchStatus::Finalized { height: 2 }),
        );

        // No inclusion within grace keeps the batch pending, then drops it.
        let c = sha256::Digest::random(&mut rng);
        let mut proposed = VecDeque::from([ProposedBatch {
            height: 2,
            digests: vec![c],
        }]);
        let mut known: AHashSet<_> = [c].into_iter().collect();
        let mut outcomes = AHashMap::new();
        resolve_proposed_batches(
            &mut proposed,
            &AHashSet::new(),
            3,
            3,
            &mut known,
            &mut outcomes,
            &AHashMap::new(),
        );
        assert_eq!(proposed.len(), 1, "still within grace");
        resolve_proposed_batches(
            &mut proposed,
            &AHashSet::new(),
            5,
            3,
            &mut known,
            &mut outcomes,
            &AHashMap::new(),
        );
        assert!(proposed.is_empty());
        assert_eq!(
            batch_status_from_outcomes(&[c], &outcomes),
            Some(StoredBatchStatus::Dropped),
        );
    }

    fn total_bytes_for(transactions: &[VerifiedTransaction<sha256::Sha256>]) -> usize {
        transactions
            .iter()
            .map(|transaction| transaction.encode_size())
            .sum()
    }

    fn signed_transactions(seed: u64, txs: usize) -> Vec<VerifiedTransaction<sha256::Sha256>> {
        let signer = ed25519::SigningKey::from_seed(seed);
        let recipient = ed25519::SigningKey::from_seed(seed + 100).public_key();
        (0..txs as u64)
            .map(|nonce| {
                Transaction::new(
                    TransactionPublicKey::ed25519(signer.public_key()),
                    TransactionPublicKey::ed25519(recipient.clone()),
                    NonZeroU64::new(1).expect("non-zero"),
                    nonce,
                )
                .seal_and_sign(
                    &signer,
                    TRANSACTION_NAMESPACE,
                    &mut sha256::Sha256::default(),
                )
            })
            .collect()
    }

    fn pool_entry(seed: u64, txs: usize, total_bytes: usize) -> PoolEntry<sha256::Sha256> {
        let transactions = signed_transactions(seed, txs);
        PoolEntry {
            digests: transactions.iter().map(|tx| *tx.message_digest()).collect(),
            transactions: transactions
                .into_iter()
                .map(LazySignedTransaction::new)
                .collect(),
            total_bytes,
        }
    }

    fn digest_of(transaction: &LazySignedTransaction<sha256::Sha256>) -> sha256::Digest {
        *transaction
            .get()
            .expect("pooled transactions are decoded")
            .message_digest()
    }

    #[test]
    fn pop_proposal_respects_remaining_headroom() {
        let mut pool = PoolLane {
            entries: VecDeque::from([pool_entry(1, 2, 600), pool_entry(2, 1, 300)]),
            bytes: 900,
        };
        let mut proposed = VecDeque::new();

        // Insufficient headroom preserves the FIFO entry for a later proposal.
        let (txs, selected_bytes) = pop_lane_proposal(&mut pool, &mut proposed, 5, 500, 1_000);
        assert!(txs.is_empty());
        assert_eq!(selected_bytes, 0);
        assert_eq!(pool.entries.len(), 2);
        assert_eq!(pool.bytes, 900);
        assert!(proposed.is_empty());

        // Headroom covering only the head entry stops before the next.
        let (txs, selected_bytes) = pop_lane_proposal(&mut pool, &mut proposed, 5, 400, 1_000);
        assert_eq!(txs.len(), 2);
        assert_eq!(selected_bytes, 600);
        assert_eq!(pool.entries.len(), 1);
        assert_eq!(pool.bytes, 300);
        assert_eq!(proposed.len(), 1);

        // A full block has no headroom and nothing is served.
        let mut pool = PoolLane {
            entries: VecDeque::from([pool_entry(3, 1, 400)]),
            bytes: 400,
        };
        for filled in [300, 301, usize::MAX] {
            let (txs, selected_bytes) = pop_lane_proposal(&mut pool, &mut proposed, 5, filled, 300);
            assert!(txs.is_empty(), "no headroom left");
            assert_eq!(selected_bytes, 0);
        }

        // An empty proposal obeys the same strict budget.
        let (txs, selected_bytes) = pop_lane_proposal(&mut pool, &mut proposed, 5, 0, 300);
        assert!(txs.is_empty());
        assert_eq!(selected_bytes, 0);
        assert_eq!(pool.entries.len(), 1);
        assert_eq!(pool.bytes, 400);
    }

    #[test]
    fn pop_proposal_accepts_exact_transaction_budget() {
        for filled in [0, 100] {
            let mut pool = PoolLane {
                entries: VecDeque::from([pool_entry(1, 2, 600), pool_entry(2, 1, 300)]),
                bytes: 900,
            };
            let mut proposed = VecDeque::new();

            let (txs, selected_bytes) =
                pop_lane_proposal(&mut pool, &mut proposed, 5, filled, filled + 599);
            assert!(txs.is_empty());
            assert_eq!(selected_bytes, 0);
            assert_eq!(pool.bytes, 900);
            assert!(proposed.is_empty());

            let (txs, selected_bytes) =
                pop_lane_proposal(&mut pool, &mut proposed, 5, filled, filled + 900);
            assert_eq!(txs.len(), 3);
            assert_eq!(selected_bytes, 900);
            assert!(pool.entries.is_empty());
            assert_eq!(pool.bytes, 0);
            assert_eq!(proposed.len(), 2);
        }
    }

    type TestMailbox = Mailbox<sha256::Digest, ed25519::VerifyingKey, sha256::Sha256>;
    type ActorMessage = Message<sha256::Digest, ed25519::VerifyingKey, sha256::Sha256>;

    /// Starts an actor with the given pool and proposal budgets.
    async fn start_test_actor(
        context: commonware_runtime::tokio::Context,
        max_pool_bytes: usize,
        max_propose_bytes: usize,
    ) -> (TestMailbox, mpsc::Sender<ActorMessage>, super::Handle<()>) {
        let (sender, rx) = mpsc::channel(8);
        let mailbox = Mailbox::new(sender.clone());
        let public_key_cache = PublicKeyCache::new(context.child("cache"), NZUsize!(16));
        let actor = Actor::new(
            context,
            Config {
                max_pool_bytes,
                max_propose_bytes,
                namespace: TRANSACTION_NAMESPACE,
                drop_grace_blocks: 3,
                strategy: Sequential,
                public_key_cache,
            },
            mailbox.clone(),
            ActorReceiver { rx },
            Arc::new(OnceLock::new()),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        (mailbox, sender, actor.start(listener))
    }

    async fn propose(
        sender: &mpsc::Sender<ActorMessage>,
        height: u64,
    ) -> Vec<LazySignedTransaction<sha256::Sha256>> {
        let (response, result) = oneshot::channel();
        sender
            .send(Message::Propose {
                height,
                filled: 0,
                response,
            })
            .await
            .unwrap();
        result.await.unwrap()
    }

    #[test]
    fn actor_drops_oversized_batches_without_retaining_digests() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let transactions = signed_transactions(1, 2);
            let digests: Vec<_> = transactions.iter().map(|tx| *tx.message_digest()).collect();
            let max_propose_bytes = total_bytes_for(&transactions[..1]);
            let (mailbox, sender, _handle) =
                start_test_actor(context, total_bytes_for(&transactions), max_propose_bytes).await;

            let result = mailbox
                .try_submit(
                    "oversized-submit".into(),
                    digests.clone(),
                    transactions.clone(),
                )
                .unwrap();
            assert_eq!(result.await.unwrap(), TxStatus::Dropped);

            let result = mailbox
                .try_ingest(
                    "oversized-ingest".into(),
                    digests.clone(),
                    transactions.clone(),
                )
                .unwrap();
            assert!(matches!(result.await.unwrap(), IngestStatus::Dropped));

            // A rejected batch must leave its transactions eligible for admission.
            let result = mailbox
                .try_ingest(
                    "fits".into(),
                    vec![digests[0]],
                    vec![transactions[0].clone()],
                )
                .unwrap();
            assert!(matches!(result.await.unwrap(), IngestStatus::Accepted));

            let proposal = propose(&sender, 1).await;
            assert_eq!(proposal.len(), 1);
            assert_eq!(digest_of(&proposal[0]), digests[0]);
            assert_eq!(
                proposal[0].get().expect("decoded").encode_size(),
                max_propose_bytes
            );
        });
    }

    #[test]
    fn admitted_batch_serves_its_encoding_from_one_buffer() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let transactions = signed_transactions(1, 3);
            let digests = digests_of(&transactions);
            let (mailbox, sender, _handle) =
                start_test_actor(context, 1 << 20, total_bytes_for(&transactions)).await;

            // Admit the first transaction alone, then a batch that repeats it. The pool drops
            // the repeat, so the second entry holds the other two.
            for (batch_id, range) in [("first", 0..1), ("second", 0..3)] {
                let result = mailbox
                    .try_ingest(
                        batch_id.into(),
                        digests[range.clone()].to_vec(),
                        transactions[range].to_vec(),
                    )
                    .unwrap();
                assert!(matches!(result.await.unwrap(), IngestStatus::Accepted));
            }
            let proposal = propose(&sender, 1).await;
            assert_eq!(proposal.len(), 3);

            // Every served transaction encodes to the bytes of its decoded value.
            let served: Vec<_> = proposal
                .iter()
                .map(LazySignedTransaction::encoded_signed_transaction)
                .collect();
            for (bytes, transaction) in served.iter().zip(&transactions) {
                assert_eq!(bytes, &transaction.encode());
            }

            // The second entry's transactions lie back to back in a buffer nothing else holds.
            assert_eq!(served[1].as_ptr_range().end, served[2].as_ptr());
            drop(proposal);
            let [_, second, third] = served.try_into().unwrap();
            drop(second);
            assert!(third.is_unique());
        });
    }

    fn digests_of(transactions: &[VerifiedTransaction<sha256::Sha256>]) -> Vec<sha256::Digest> {
        transactions
            .iter()
            .map(|transaction| *transaction.message_digest())
            .collect()
    }

    fn submit(
        mailbox: &TestMailbox,
        lane: SubmissionLane,
        batch_id: &str,
        transactions: &[VerifiedTransaction<sha256::Sha256>],
    ) -> oneshot::Receiver<TxStatus> {
        mailbox
            .try_submit_in_lane(
                lane,
                batch_id.into(),
                digests_of(transactions),
                transactions.to_vec(),
            )
            .unwrap()
    }

    #[test]
    fn background_refused_for_room_is_retryable_without_residue() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let batches: Vec<_> = (1..=3).map(|seed| signed_transactions(seed, 2)).collect();
            let batch_bytes = total_bytes_for(&batches[0]);
            let background = SubmissionLane::Background;

            // The background lane holds two batches beside the foreground reserve.
            let (mailbox, sender, _handle) =
                start_test_actor(context, 3 * batch_bytes, batch_bytes).await;
            let _first = submit(&mailbox, background, "first", &batches[0]);
            let _second = submit(&mailbox, background, "second", &batches[1]);
            assert!(
                submit(&mailbox, background, "third", &batches[2])
                    .await
                    .is_err(),
                "a batch refused for lack of room gets no answer"
            );

            // A proposal frees room, and the identical batch is then admitted whole.
            let proposed = |proposal: Vec<LazySignedTransaction<sha256::Sha256>>| {
                proposal.iter().map(digest_of).collect::<Vec<_>>()
            };
            assert_eq!(proposed(propose(&sender, 1).await), digests_of(&batches[0]));
            let _third = submit(&mailbox, background, "third", &batches[2]);
            assert_eq!(proposed(propose(&sender, 2).await), digests_of(&batches[1]));
            assert_eq!(proposed(propose(&sender, 3).await), digests_of(&batches[2]));
        });
    }

    #[test]
    fn final_refusals_answer_dropped() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let batches: Vec<_> = (1..=4).map(|seed| signed_transactions(seed, 2)).collect();
            let batch_bytes = total_bytes_for(&batches[0]);
            let (mailbox, _sender, _handle) =
                start_test_actor(context, 3 * batch_bytes, batch_bytes).await;
            let _first = submit(&mailbox, SubmissionLane::Background, "first", &batches[0]);
            let _second = submit(&mailbox, SubmissionLane::Background, "second", &batches[1]);
            let _third = submit(&mailbox, SubmissionLane::Foreground, "third", &batches[2]);

            // A foreground batch without room and a background batch that cannot fit the empty
            // lane are both refused for good.
            let fourth = submit(&mailbox, SubmissionLane::Foreground, "fourth", &batches[3]);
            let oversized = submit(
                &mailbox,
                SubmissionLane::Background,
                "oversized",
                &signed_transactions(5, 4),
            );

            assert_eq!(fourth.await.unwrap(), TxStatus::Dropped);
            assert_eq!(oversized.await.unwrap(), TxStatus::Dropped);
        });
    }

    #[test]
    fn foreground_consumes_proposal_before_background() {
        let foreground_entry = pool_entry(4, 1, 1_000);
        let foreground_digest = foreground_entry.digests[0];
        let mut foreground_pool = PoolLane {
            entries: VecDeque::from([foreground_entry]),
            bytes: 1_000,
        };
        let mut background_pool = PoolLane {
            entries: VecDeque::from([pool_entry(5, 1, 400)]),
            bytes: 400,
        };
        let mut proposed = VecDeque::new();

        let transactions = pop_proposal(
            &mut foreground_pool,
            &mut background_pool,
            &mut proposed,
            5,
            0,
            1_000,
        );

        assert_eq!(transactions.len(), 1);
        assert_eq!(digest_of(&transactions[0]), foreground_digest);
        assert!(foreground_pool.entries.is_empty());
        assert_eq!(foreground_pool.bytes, 0);
        assert_eq!(background_pool.entries.len(), 1);
        assert_eq!(background_pool.bytes, 400);
    }

    #[test]
    fn background_borrows_full_proposal_when_foreground_is_empty() {
        let mut foreground_pool = PoolLane::new();
        let mut background_pool = PoolLane {
            entries: VecDeque::from([pool_entry(6, 1, 600), pool_entry(7, 1, 400)]),
            bytes: 1_000,
        };
        let mut proposed = VecDeque::new();

        let transactions = pop_proposal(
            &mut foreground_pool,
            &mut background_pool,
            &mut proposed,
            5,
            0,
            1_000,
        );

        assert_eq!(transactions.len(), 2);
        assert!(background_pool.entries.is_empty());
        assert_eq!(background_pool.bytes, 0);
        assert_eq!(proposed.len(), 2);
    }

    #[test]
    fn proposal_lanes_share_remaining_headroom() {
        for filled in [0, 100] {
            let mut foreground_pool = PoolLane {
                entries: VecDeque::from([pool_entry(8, 1, 600)]),
                bytes: 600,
            };
            let mut background_pool = PoolLane {
                entries: VecDeque::from([pool_entry(9, 1, 400)]),
                bytes: 400,
            };
            let mut proposed = VecDeque::new();

            let transactions = pop_proposal(
                &mut foreground_pool,
                &mut background_pool,
                &mut proposed,
                5,
                filled,
                filled + 999,
            );
            assert_eq!(transactions.len(), 1);
            assert_eq!(foreground_pool.bytes, 0);
            assert_eq!(background_pool.bytes, 400);
            assert_eq!(background_pool.entries.len(), 1);
            assert_eq!(proposed.len(), 1);

            let transactions = pop_proposal(
                &mut foreground_pool,
                &mut background_pool,
                &mut proposed,
                5,
                filled + 600,
                filled + 1_000,
            );
            assert_eq!(transactions.len(), 1);
            assert_eq!(background_pool.bytes, 0);
            assert!(background_pool.entries.is_empty());
            assert_eq!(proposed.len(), 2);
        }
    }

    #[test]
    fn both_lanes_reject_batches_above_proposal_budget() {
        for lane in [SubmissionLane::Foreground, SubmissionLane::Background] {
            assert!(can_admit_submission(lane, 0, 0, 300, 1_000, 300));
            assert!(!can_admit_submission(lane, 0, 0, 301, 1_000, 300));
        }
    }

    #[test]
    fn saturated_background_preserves_foreground_admission() {
        assert!(can_admit_submission(
            SubmissionLane::Foreground,
            0,
            700,
            300,
            1_000,
            300,
        ));
        assert!(!can_admit_submission(
            SubmissionLane::Background,
            0,
            700,
            1,
            1_000,
            300,
        ));
        assert!(!can_admit_submission(
            SubmissionLane::Foreground,
            0,
            700,
            301,
            1_000,
            300,
        ));
    }

    type TestDigest = sha256::Digest;

    /// Actor bookkeeping just before a block report: six submitted batches, four of them
    /// proposed and two still pooled, with a waiter on each.
    struct ReportFixture {
        foreground: PoolLane<sha256::Sha256>,
        background: PoolLane<sha256::Sha256>,
        proposed: VecDeque<ProposedBatch<TestDigest>>,
        finalized: AHashSet<TestDigest>,
        known: AHashSet<TestDigest>,
        outcomes: AHashMap<TestDigest, DigestOutcome>,
        statuses: AHashMap<Arc<str>, StoredBatchStatus<TestDigest>>,
        status_order: VecDeque<Arc<str>>,
        batch_digests: AHashMap<Arc<str>, Vec<TestDigest>>,
        watchers: AHashMap<TestDigest, Vec<Arc<str>>>,
        waiters: AHashMap<Arc<str>, Vec<oneshot::Sender<TxStatus>>>,
        receivers: Vec<(Arc<str>, oneshot::Receiver<TxStatus>)>,
    }

    /// Height of the reported block.
    const REPORT_HEIGHT: u64 = 4;

    /// Grace window, after which batches proposed at height 1 drop at the report.
    const REPORT_GRACE: u64 = 3;

    /// Builds the same [`ReportFixture`] on every call.
    fn report_fixture() -> ReportFixture {
        let mut rng = StdRng::from_seed([29; 32]);
        let [a, b, c, d, e, f] = std::array::from_fn(|_| TestDigest::random(&mut rng));
        let pooled = pool_entry(7, 2, 300);
        let pooled_tail = pool_entry(8, 1, 300);

        // The block finalizes one whole proposed batch, half of another, and the first digest
        // of a still-pooled batch (another validator included the same transaction).
        let finalized: AHashSet<_> = [a, b, c, pooled.digests[0]].into_iter().collect();
        let proposed = VecDeque::from([
            ProposedBatch {
                height: 2,
                digests: vec![a, b],
            },
            ProposedBatch {
                height: 2,
                digests: vec![c, d],
            },
            ProposedBatch {
                height: 1,
                digests: vec![e],
            },
            ProposedBatch {
                height: 3,
                digests: vec![f],
            },
        ]);
        let submissions: Vec<(&str, Vec<TestDigest>)> = vec![
            ("finalized", vec![a, b]),
            ("partial", vec![c, d]),
            ("expired", vec![e]),
            ("pending", vec![f]),
            ("pooled", pooled.digests.clone()),
            ("pooled-tail", pooled_tail.digests.clone()),
        ];

        let mut fixture = ReportFixture {
            foreground: PoolLane {
                entries: VecDeque::new(),
                bytes: 0,
            },
            background: PoolLane::new(),
            proposed,
            finalized,
            known: AHashSet::new(),
            outcomes: AHashMap::new(),
            statuses: AHashMap::new(),
            status_order: VecDeque::new(),
            batch_digests: AHashMap::new(),
            watchers: AHashMap::new(),
            waiters: AHashMap::new(),
            receivers: Vec::new(),
        };
        for (batch_id, digests) in submissions {
            // Record each submission as the actor's Submit handler does.
            let batch_id: Arc<str> = batch_id.into();
            remember_status(
                &mut fixture.statuses,
                &mut fixture.status_order,
                Arc::clone(&batch_id),
                StoredBatchStatus::Accepted,
            );
            watch_batch(&batch_id, &digests, &mut fixture.watchers);
            fixture.known.extend(digests.iter().copied());
            fixture.batch_digests.insert(Arc::clone(&batch_id), digests);
            let (waiter, receiver) = oneshot::channel();
            fixture
                .waiters
                .entry(Arc::clone(&batch_id))
                .or_default()
                .push(waiter);
            fixture.receivers.push((batch_id, receiver));
        }
        for entry in [pooled, pooled_tail] {
            fixture.foreground.bytes += entry.total_bytes;
            fixture.foreground.entries.push_back(entry);
        }
        fixture
    }

    /// Everything a caller can observe of a [`ReportFixture`], in a comparable form. Status
    /// insertion order among one report's batches follows hash-set order, so it is compared
    /// as a set.
    #[derive(Debug, PartialEq)]
    struct ReportOutcome {
        proposed: Vec<(u64, Vec<TestDigest>)>,
        pool: Vec<Vec<TestDigest>>,
        pool_bytes: usize,
        known: Vec<TestDigest>,
        outcomes: Vec<(TestDigest, DigestOutcome)>,
        statuses: Vec<(String, StoredBatchStatus<TestDigest>)>,
        status_order: Vec<String>,
        batch_digests: Vec<(String, Vec<TestDigest>)>,
        watchers: Vec<(TestDigest, Vec<String>)>,
        waiting: Vec<String>,
        notified: Vec<(String, Option<TxStatus>)>,
        served: Vec<TestDigest>,
    }

    fn observe(
        mut fixture: ReportFixture,
        served: &[LazySignedTransaction<sha256::Sha256>],
    ) -> ReportOutcome {
        fn sorted<T: Ord>(mut items: Vec<T>) -> Vec<T> {
            items.sort();
            items
        }
        ReportOutcome {
            proposed: fixture
                .proposed
                .iter()
                .map(|batch| (batch.height, batch.digests.clone()))
                .collect(),
            pool: fixture
                .foreground
                .entries
                .iter()
                .map(|entry| entry.digests.clone())
                .collect(),
            pool_bytes: fixture.foreground.bytes,
            known: sorted(fixture.known.iter().copied().collect()),
            outcomes: {
                let mut outcomes: Vec<_> = fixture.outcomes.iter().map(|(d, o)| (*d, *o)).collect();
                outcomes.sort_by_key(|(digest, _)| *digest);
                outcomes
            },
            statuses: {
                let mut statuses: Vec<_> = fixture
                    .statuses
                    .iter()
                    .map(|(id, status)| (id.to_string(), status.clone()))
                    .collect();
                statuses.sort_by(|left, right| left.0.cmp(&right.0));
                statuses
            },
            status_order: sorted(
                fixture
                    .status_order
                    .iter()
                    .map(|id| id.to_string())
                    .collect(),
            ),
            batch_digests: sorted(
                fixture
                    .batch_digests
                    .iter()
                    .map(|(id, digests)| (id.to_string(), digests.clone()))
                    .collect(),
            ),
            watchers: sorted(
                fixture
                    .watchers
                    .iter()
                    .map(|(digest, ids)| (*digest, ids.iter().map(|id| id.to_string()).collect()))
                    .collect(),
            ),
            waiting: sorted(fixture.waiters.keys().map(|id| id.to_string()).collect()),
            notified: fixture
                .receivers
                .iter_mut()
                .map(|(id, receiver)| (id.to_string(), receiver.try_recv().ok()))
                .collect(),
            served: served.iter().map(digest_of).collect(),
        }
    }

    /// Advances a report one slice of `budget` digests, examining before settling. Returns
    /// whether the report is complete.
    fn report_slice(
        fixture: &mut ReportFixture,
        resolution: &mut ReportResolution<TestDigest>,
        budget: usize,
    ) -> bool {
        if !resolution.examine(
            &mut fixture.proposed,
            &fixture.finalized,
            budget,
            &mut fixture.known,
            &mut fixture.outcomes,
            &fixture.watchers,
        ) {
            return false;
        }
        resolution.settle(
            budget,
            &mut fixture.statuses,
            &mut fixture.status_order,
            &mut fixture.batch_digests,
            &mut fixture.watchers,
            &mut fixture.outcomes,
            &mut fixture.waiters,
        )
    }

    fn serve_proposal(fixture: &mut ReportFixture) -> Vec<LazySignedTransaction<sha256::Sha256>> {
        pop_proposal(
            &mut fixture.foreground,
            &mut fixture.background,
            &mut fixture.proposed,
            REPORT_HEIGHT + 1,
            0,
            10_000,
        )
    }

    /// A proposal served between any two slices of a block report sees the same pool and
    /// leaves every status, outcome, waiter, known digest, and proposed batch as serving it
    /// after the whole report does.
    #[test]
    fn proposal_between_report_slices_matches_proposal_after_report() {
        // Resolve the whole report in one slice, then serve the proposal.
        let mut fixture = report_fixture();
        let mut resolution =
            ReportResolution::new(REPORT_HEIGHT, REPORT_GRACE, fixture.proposed.len());
        assert!(report_slice(&mut fixture, &mut resolution, usize::MAX));
        let served = serve_proposal(&mut fixture);
        let expected = observe(fixture, &served);

        // The serial order resolves the finalized and expired batches, leaves the partial and
        // pending ones outstanding, and keeps the newly proposed batch whole even though the
        // block holds one of its digests.
        let notified: AHashMap<_, _> = expected.notified.iter().cloned().collect();
        assert_eq!(
            notified["finalized"],
            Some(TxStatus::Finalized {
                height: REPORT_HEIGHT
            })
        );
        assert_eq!(notified["expired"], Some(TxStatus::Dropped));
        assert_eq!(notified["partial"], None);
        assert_eq!(notified["pending"], None);
        assert_eq!(expected.served.len(), 3, "both pooled batches are served");
        assert_eq!(expected.proposed.len(), 4);
        assert_eq!(expected.proposed[2].0, REPORT_HEIGHT + 1);
        assert_eq!(expected.proposed[2].1.len(), 2);

        // Count the slices a report takes at one digest per slice.
        let total = {
            let mut fixture = report_fixture();
            let mut resolution =
                ReportResolution::new(REPORT_HEIGHT, REPORT_GRACE, fixture.proposed.len());
            let mut total = 1;
            while !report_slice(&mut fixture, &mut resolution, 1) {
                total += 1;
            }
            total
        };
        assert_eq!(total, 6, "four batches to examine, then three to settle");

        // Serve the proposal after each possible number of slices. Serving before the first
        // slice is a proposal served while the finalized set is extracted.
        for serve_at in 0..=total {
            let mut fixture = report_fixture();
            let mut resolution =
                ReportResolution::new(REPORT_HEIGHT, REPORT_GRACE, fixture.proposed.len());
            let mut served = Vec::new();
            for slice in 0..=total {
                if slice == serve_at {
                    served = serve_proposal(&mut fixture);
                }
                if slice < total {
                    let done = report_slice(&mut fixture, &mut resolution, 1);
                    assert_eq!(done, slice + 1 == total);
                }
            }
            assert_eq!(
                observe(fixture, &served),
                expected,
                "serving the proposal after {serve_at} slices must not change the result"
            );
        }
    }

    /// Serving queued proposal requests answers every one, from the backlog and the mailbox,
    /// in arrival order, and leaves the other messages queued in arrival order.
    #[test]
    fn queued_proposals_are_served_ahead_of_other_messages() {
        type TestMessage = Message<TestDigest, ed25519::VerifyingKey, sha256::Sha256>;
        let query = |batch_id: &str| -> TestMessage {
            let (response, _) = oneshot::channel();
            TestMessage::QueryStatus {
                batch_id: batch_id.into(),
                response,
            }
        };
        let mut fixture = report_fixture();
        let pooled: Vec<Vec<TestDigest>> = fixture
            .foreground
            .entries
            .iter()
            .map(|entry| entry.digests.clone())
            .collect();

        // Queue a query and a proposal request in the backlog, then a proposal request and a
        // query in the mailbox.
        let (first, mut first_result) = oneshot::channel();
        let (second, mut second_result) = oneshot::channel();
        let mut backlog = VecDeque::from([
            query("q1"),
            TestMessage::Propose {
                height: 5,
                filled: 0,
                response: first,
            },
        ]);
        let (sender, mut rx) = mpsc::channel(8);
        assert!(
            sender
                .try_send(TestMessage::Propose {
                    height: 6,
                    filled: 0,
                    response: second,
                })
                .is_ok()
        );
        assert!(sender.try_send(query("q2")).is_ok());

        // Each request takes one 300-byte pooled batch, in arrival order.
        serve_queued_proposals(
            &mut backlog,
            &mut rx,
            &mut fixture.foreground,
            &mut fixture.background,
            &mut fixture.proposed,
            300,
        );
        let digests = |served: Vec<LazySignedTransaction<sha256::Sha256>>| -> Vec<TestDigest> {
            served.iter().map(digest_of).collect()
        };
        assert_eq!(
            digests(
                first_result
                    .try_recv()
                    .expect("first proposal must be served")
            ),
            pooled[0]
        );
        assert_eq!(
            digests(
                second_result
                    .try_recv()
                    .expect("second proposal must be served")
            ),
            pooled[1]
        );
        let heights: Vec<u64> = fixture.proposed.iter().map(|batch| batch.height).collect();
        assert_eq!(heights, vec![2, 2, 1, 3, 5, 6]);

        // The queries stay queued in arrival order and the mailbox is drained.
        let queued: Vec<String> = backlog
            .iter()
            .map(|message| match message {
                TestMessage::QueryStatus { batch_id, .. } => batch_id.clone(),
                _ => panic!("only queries must remain queued"),
            })
            .collect();
        assert_eq!(queued, vec!["q1", "q2"]);
        assert!(rx.try_recv().is_err());
    }
}
