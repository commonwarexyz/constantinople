//! Mempool webserver actor.
//!
//! Owns a byte-bounded FIFO pool of verified transactions. Receives
//! batch submissions from HTTP handlers and serves proposals to the
//! consensus layer via the [`Mailbox`].

use super::{AccountReader, ActorReceiver, Mailbox, http, mailbox::Message};
use ahash::{AHashMap, AHashSet};
use commonware_codec::EncodeSize;
use commonware_consensus::marshal::Update;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::{ContextCell, Handle, Metrics, Spawner, spawn_cell};
use commonware_utils::{Acknowledgement, channel::fallible::OneshotExt};
use constantinople_primitives::{PublicKeyCache, VerifiedTransaction};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    fmt::Display,
    hash::Hash,
    sync::{Arc, OnceLock},
};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tracing::warn;

const MAX_STATUS_ENTRIES: usize = 1_000_000;

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

    /// Whether the wire form carries digest lists (nontrivial to encode).
    pub(super) const fn has_digest_lists(&self) -> bool {
        matches!(self, Self::PartiallyFinalized { .. })
    }
}

/// Mempool actor configuration.
pub struct Config<St: Strategy> {
    /// Maximum total bytes the pool will hold.
    pub max_pool_bytes: usize,
    /// Maximum bytes returned in a single `propose` call, and the
    /// maximum accepted batch size for submissions.
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
    /// Shared cache of decompressed transaction public keys.
    pub public_key_cache: PublicKeyCache,
}

/// A batch of transactions waiting in the pool.
struct PoolEntry<H: Hasher> {
    transactions: Vec<VerifiedTransaction<H>>,
    total_bytes: usize,
}

/// A batch proposed at a given height.
struct ProposedBatch<D> {
    height: u64,
    digests: Vec<D>,
}

#[derive(Clone, Copy)]
enum DigestOutcome {
    Finalized { height: u64 },
    Dropped,
}

pub(super) enum IngestStatus {
    Accepted,
    Dropped,
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
/// `filled` is the encoded size the proposal already holds, so the served
/// batch stays within `max_propose_bytes - filled`. A refill for a non-empty
/// block (`filled > 0`) never overshoots that headroom, so refills cannot
/// inflate the block; an initial selection (`filled == 0`) may overshoot by
/// one entry so an oversized head entry cannot wedge the pool.
fn pop_proposal<H>(
    pool: &mut VecDeque<PoolEntry<H>>,
    pool_bytes: &mut usize,
    proposed: &mut VecDeque<ProposedBatch<H::Digest>>,
    height: u64,
    filled: usize,
    max_propose_bytes: usize,
) -> Vec<VerifiedTransaction<H>>
where
    H: Hasher,
{
    let budget = max_propose_bytes.saturating_sub(filled);
    let strict = filled > 0;
    let mut batch_txs = Vec::new();
    let mut batch_bytes = 0;

    while let Some(entry) = pool.front() {
        if batch_bytes + entry.total_bytes > budget && (strict || !batch_txs.is_empty()) {
            break;
        }
        let entry = pool.pop_front().expect("front was Some");
        *pool_bytes -= entry.total_bytes;
        batch_bytes += entry.total_bytes;
        let mut digests = Vec::with_capacity(entry.transactions.len());
        for tx in &entry.transactions {
            digests.push(*tx.message_digest());
        }
        proposed.push_back(ProposedBatch { height, digests });
        batch_txs.extend(entry.transactions);
    }
    batch_txs
}

/// Applies one finalized block's digest set to the outstanding proposed
/// batches, recording per-digest outcomes and pruning `known_digests`.
///
/// A partial match does not prove the unmatched digests are dead: a
/// speculative reuse can split one selection across two finalized blocks (the
/// filtered digests land in the parent, the remainder in the next block this
/// node proposes). Matched digests finalize immediately; the remainder stays
/// outstanding until its own block is reported or the grace window expires.
///
/// Returns the batch ids whose digests gained outcomes, for terminal-status
/// resolution by the caller.
fn resolve_proposed_batches<D>(
    proposed: &mut VecDeque<ProposedBatch<D>>,
    finalized: &AHashSet<D>,
    height: u64,
    drop_grace_blocks: u64,
    known_digests: &mut AHashSet<D>,
    digest_outcomes: &mut AHashMap<D, DigestOutcome>,
    digest_watchers: &AHashMap<D, Vec<Arc<str>>>,
) -> AHashSet<Arc<str>>
where
    D: Copy + Eq + Hash,
{
    let mut affected: AHashSet<Arc<str>> = AHashSet::new();
    let mut remaining = VecDeque::new();
    for batch in proposed.drain(..) {
        let expired = height >= batch.height + drop_grace_blocks;
        let any_finalized = batch
            .digests
            .iter()
            .any(|digest| finalized.contains(digest));
        if !any_finalized && !expired {
            remaining.push_back(batch);
            continue;
        }

        affected.extend(watched_batches_for(&batch.digests, digest_watchers));
        let mut outstanding = Vec::new();
        for digest in &batch.digests {
            if finalized.contains(digest) {
                digest_outcomes.insert(*digest, DigestOutcome::Finalized { height });
                known_digests.remove(digest);
            } else if expired {
                digest_outcomes.insert(*digest, DigestOutcome::Dropped);
                known_digests.remove(digest);
            } else {
                outstanding.push(*digest);
            }
        }
        if !outstanding.is_empty() {
            remaining.push_back(ProposedBatch {
                height: batch.height,
                digests: outstanding,
            });
        }
    }
    *proposed = remaining;
    affected
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

fn new_transactions<H>(
    transactions: Vec<VerifiedTransaction<H>>,
    known_digests: &mut AHashSet<H::Digest>,
) -> Vec<VerifiedTransaction<H>>
where
    H: Hasher,
    H::Digest: Copy + Eq + Hash,
{
    let mut accepted = Vec::with_capacity(transactions.len());
    for transaction in transactions {
        if !known_digests.insert(*transaction.message_digest()) {
            continue;
        }
        accepted.push(transaction);
    }
    accepted
}

fn remove_known_digests<H>(
    transactions: &[VerifiedTransaction<H>],
    known_digests: &mut AHashSet<H::Digest>,
) where
    H: Hasher,
    H::Digest: Eq + Hash,
{
    for transaction in transactions {
        known_digests.remove(transaction.message_digest());
    }
}

fn total_bytes_for<H>(transactions: &[VerifiedTransaction<H>]) -> usize
where
    H: Hasher,
{
    transactions.iter().map(EncodeSize::encode_size).sum()
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
    pool: VecDeque<PoolEntry<H>>,
    pool_bytes: usize,
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
        Self {
            context: ContextCell::new(context),
            mailbox,
            rx: receiver.rx,
            pool: VecDeque::new(),
            pool_bytes: 0,
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
            mut pool,
            mut pool_bytes,
            max_pool_bytes,
            max_propose_bytes,
            namespace,
            drop_grace_blocks,
            strategy,
            public_key_cache,
            account_reader,
        } = self;

        let app_state = Arc::new(http::AppState {
            mailbox,
            namespace,
            max_batch_bytes: max_propose_bytes,
            strategy: strategy.clone(),
            public_key_cache,
            account_reader,
            ingress_permits: Arc::new(Semaphore::new(http::MAX_CONCURRENT_INGRESS)),
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

        while let Some(message) = rx.recv().await {
            match message {
                Message::Submit {
                    batch_id,
                    digests,
                    transactions,
                    total_bytes,
                    result,
                    ingest_result,
                } => {
                    let batch_id: Arc<str> = batch_id.into();
                    if let Some(status) = statuses.get(batch_id.as_ref()) {
                        if let Some(ingest_result) = ingest_result {
                            let _ = ingest_result.send(IngestStatus::Accepted);
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

                    let transactions = new_transactions(transactions, &mut known_digests);
                    let total_bytes = total_bytes_for(&transactions).min(total_bytes);
                    if !transactions.is_empty() && pool_bytes + total_bytes > max_pool_bytes {
                        remove_known_digests(&transactions, &mut known_digests);
                        if let Some(result) = result {
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
                    if !transactions.is_empty() {
                        pool_bytes += total_bytes;
                        pool.push_back(PoolEntry {
                            transactions,
                            total_bytes,
                        });
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
                        &mut pool,
                        &mut pool_bytes,
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
                    // the full-body decode is skipped otherwise; the block is
                    // still released on the strategy's pool off this loop.
                    if proposed.is_empty() {
                        drop(strategy.spawn(move |_: St| drop(block)));
                        acknowledgement.acknowledge();
                        continue;
                    }

                    let height = block.header.height;

                    // Deriving the finalized set decodes any transaction the
                    // application has not already materialized, so it runs on
                    // the strategy's pool (which also releases the block
                    // there).
                    let finalized: AHashSet<H::Digest> = strategy
                        .spawn(move |_: St| {
                            block
                                .body
                                .iter()
                                .filter_map(|tx| tx.get().map(|tx| *tx.message_digest()))
                                .collect()
                        })
                        .await;

                    let affected = resolve_proposed_batches(
                        &mut proposed,
                        &finalized,
                        height,
                        drop_grace_blocks,
                        &mut known_digests,
                        &mut digest_outcomes,
                        &digest_watchers,
                    );
                    for batch_id in affected {
                        resolve_batch_if_terminal(
                            &batch_id,
                            &mut statuses,
                            &mut status_order,
                            &mut batch_digests,
                            &mut digest_watchers,
                            &mut digest_outcomes,
                            &mut pending_waiters,
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
        DigestOutcome, PoolEntry, ProposedBatch, StoredBatchStatus, TxStatus,
        batch_status_from_outcomes, new_transactions, pop_proposal, resolve_proposed_batches,
        status_for_finalized_block,
    };
    use ahash::{AHashMap, AHashSet};
    use commonware_cryptography::{Signer, ed25519, sha256};
    use commonware_math::algebra::Random;
    use constantinople_primitives::{TRANSACTION_NAMESPACE, Transaction, TransactionPublicKey};
    use core::num::NonZeroU64;
    use rand::{SeedableRng, rngs::StdRng};
    use std::collections::VecDeque;

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
        let signer = ed25519::PrivateKey::from_seed(1);
        let recipient = ed25519::PrivateKey::from_seed(2).public_key();
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

        let accepted = new_transactions(vec![transaction, duplicate], &mut known);

        assert_eq!(accepted.len(), 1);
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

    fn pool_entry(seed: u64, txs: usize, total_bytes: usize) -> PoolEntry<sha256::Sha256> {
        let signer = ed25519::PrivateKey::from_seed(seed);
        let recipient = ed25519::PrivateKey::from_seed(seed + 100).public_key();
        let transactions = (0..txs as u64)
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
            .collect();
        PoolEntry {
            transactions,
            total_bytes,
        }
    }

    /// A refill for a non-empty block never overshoots the remaining
    /// headroom; an initial selection may overshoot by exactly one entry.
    #[test]
    fn pop_proposal_respects_remaining_headroom() {
        let mut pool = VecDeque::from([pool_entry(1, 2, 600), pool_entry(2, 1, 300)]);
        let mut pool_bytes = 900;
        let mut proposed = VecDeque::new();

        // Refill headroom (1_000 - 500) below the head entry: nothing served.
        let txs = pop_proposal(&mut pool, &mut pool_bytes, &mut proposed, 5, 500, 1_000);
        assert!(txs.is_empty());
        assert_eq!(pool.len(), 2);
        assert_eq!(pool_bytes, 900);
        assert!(proposed.is_empty());

        // Headroom covering only the head entry stops before the next.
        let txs = pop_proposal(&mut pool, &mut pool_bytes, &mut proposed, 5, 300, 1_000);
        assert_eq!(txs.len(), 2);
        assert_eq!(pool.len(), 1);
        assert_eq!(pool_bytes, 300);
        assert_eq!(proposed.len(), 1);

        // A full block has no headroom and nothing is served.
        let mut pool = VecDeque::from([pool_entry(3, 1, 400)]);
        let mut pool_bytes = 400;
        let txs = pop_proposal(&mut pool, &mut pool_bytes, &mut proposed, 5, 300, 300);
        assert!(txs.is_empty(), "no headroom left");

        // An initial selection overshoots by one entry so an oversized head
        // cannot wedge the pool.
        let txs = pop_proposal(&mut pool, &mut pool_bytes, &mut proposed, 5, 0, 300);
        assert_eq!(txs.len(), 1);
        assert!(pool.is_empty());
        assert_eq!(pool_bytes, 0);
    }
}
