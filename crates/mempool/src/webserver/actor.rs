//! Mempool webserver actor.
//!
//! Owns a byte-bounded FIFO pool of verified transactions. Receives
//! batch submissions from HTTP handlers and serves proposals to the
//! consensus layer via the [`Mailbox`].

use super::{AccountReader, ActorReceiver, Mailbox, http, mailbox::Message};
use ahash::{AHashMap, AHashSet};
use commonware_codec::EncodeSize;
use commonware_consensus::{marshal::Update, types::Round};
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
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

const MAX_STATUS_ENTRIES: usize = 1_000_000;

/// Shared cell that lets the mempool answer account lookups once the
/// validator's state database is attached. The cell is populated after engine
/// startup; HTTP handlers return 503 until then.
pub type AccountReaderCell = Arc<OnceLock<Arc<dyn AccountReader>>>;

/// Outcome of a submitted batch, delivered when the result is known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TxStatus {
    /// The batch's block was finalized.
    Finalized { height: u64 },
    /// The batch's block was finalized, but some transactions were filtered.
    ///
    /// The `included` and `filtered` digests are hex-encoded transaction
    /// message digests in the original batch order.
    PartiallyFinalized {
        height: u64,
        included: Vec<String>,
        filtered: Vec<String>,
    },
    /// The batch was proposed but its block was not finalized.
    Dropped,
}

/// Latest known status for a submitted batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BatchStatus {
    /// The batch is accepted by this validator but has not resolved yet.
    Accepted { digests: Vec<String> },
    /// The batch's block was finalized.
    Finalized { height: u64, included: Vec<String> },
    /// The batch's block was finalized, but some transactions were filtered.
    PartiallyFinalized {
        height: u64,
        included: Vec<String>,
        filtered: Vec<String>,
    },
    /// The batch was proposed but its block was not finalized.
    Dropped { filtered: Vec<String> },
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
    /// Parallel execution strategy for transaction verification: decoding, seal
    /// hashing, and batch signature verification.
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
struct ProposedBatch<H: Hasher> {
    height: u64,
    digests: Vec<H::Digest>,
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
    D: Copy + Display + Eq + Hash,
{
    let mut included = Vec::new();
    let mut filtered = Vec::new();

    for digest in digests {
        if finalized.contains(digest) {
            included.push(digest.to_string());
        } else {
            filtered.push(digest.to_string());
        }
    }

    if included.is_empty() {
        return None;
    }

    if filtered.is_empty() {
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
) -> Option<BatchStatus>
where
    D: Copy + Display + Eq + Hash,
{
    let mut included = Vec::new();
    let mut filtered = Vec::new();
    let mut finalized_height = 0;

    for digest in digests {
        match outcomes.get(digest) {
            Some(DigestOutcome::Finalized { height }) => {
                finalized_height = finalized_height.max(*height);
                included.push(digest.to_string());
            }
            Some(DigestOutcome::Dropped) => filtered.push(digest.to_string()),
            None => return None,
        }
    }

    if included.is_empty() {
        return Some(BatchStatus::Dropped { filtered });
    }

    if filtered.is_empty() {
        return Some(BatchStatus::Finalized {
            height: finalized_height,
            included,
        });
    }

    Some(BatchStatus::PartiallyFinalized {
        height: finalized_height,
        included,
        filtered,
    })
}

fn tx_status_from_batch(status: &BatchStatus) -> Option<TxStatus> {
    match status {
        BatchStatus::Accepted { .. } => None,
        BatchStatus::Finalized { height, .. } => Some(TxStatus::Finalized { height: *height }),
        BatchStatus::PartiallyFinalized {
            height,
            included,
            filtered,
        } => Some(TxStatus::PartiallyFinalized {
            height: *height,
            included: included.clone(),
            filtered: filtered.clone(),
        }),
        BatchStatus::Dropped { .. } => Some(TxStatus::Dropped),
    }
}

fn accepted_status<D>(digests: &[D]) -> BatchStatus
where
    D: Display,
{
    BatchStatus::Accepted {
        digests: digests.iter().map(ToString::to_string).collect(),
    }
}

fn remember_status(
    statuses: &mut AHashMap<String, BatchStatus>,
    status_order: &mut VecDeque<String>,
    batch_id: String,
    status: BatchStatus,
) -> Vec<String> {
    if !statuses.contains_key(&batch_id) {
        status_order.push_back(batch_id.clone());
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

fn send_pending_waiters(
    pending_waiters: &mut AHashMap<String, Vec<oneshot::Sender<TxStatus>>>,
    batch_id: &str,
    status: &BatchStatus,
) {
    let Some(status) = tx_status_from_batch(status) else {
        return;
    };
    let Some(waiters) = pending_waiters.remove(batch_id) else {
        return;
    };
    for waiter in waiters {
        let _ = waiter.send(status.clone());
    }
}

fn watch_batch<D>(batch_id: &str, digests: &[D], watchers: &mut AHashMap<D, Vec<String>>)
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
            .push(batch_id.to_string());
    }
}

fn forget_batch<D>(
    batch_id: &str,
    batch_digests: &mut AHashMap<String, Vec<D>>,
    watchers: &mut AHashMap<D, Vec<String>>,
    outcomes: &mut AHashMap<D, DigestOutcome>,
    pending_waiters: &mut AHashMap<String, Vec<oneshot::Sender<TxStatus>>>,
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
        batch_ids.retain(|known| known != batch_id);
        if batch_ids.is_empty() {
            watchers.remove(&digest);
            outcomes.remove(&digest);
        }
    }
}

fn forget_expired_batches<D>(
    expired: Vec<String>,
    batch_digests: &mut AHashMap<String, Vec<D>>,
    watchers: &mut AHashMap<D, Vec<String>>,
    outcomes: &mut AHashMap<D, DigestOutcome>,
    pending_waiters: &mut AHashMap<String, Vec<oneshot::Sender<TxStatus>>>,
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

fn watched_batches_for<D>(digests: &[D], watchers: &AHashMap<D, Vec<String>>) -> AHashSet<String>
where
    D: Copy + Eq + Hash,
{
    let mut affected: AHashSet<String> = AHashSet::new();
    for digest in digests {
        let Some(batch_ids) = watchers.get(digest) else {
            continue;
        };
        affected.extend(batch_ids.iter().cloned());
    }
    affected
}

fn resolve_batch_if_terminal<D>(
    batch_id: &str,
    statuses: &mut AHashMap<String, BatchStatus>,
    status_order: &mut VecDeque<String>,
    batch_digests: &mut AHashMap<String, Vec<D>>,
    digest_watchers: &mut AHashMap<D, Vec<String>>,
    digest_outcomes: &mut AHashMap<D, DigestOutcome>,
    pending_waiters: &mut AHashMap<String, Vec<oneshot::Sender<TxStatus>>>,
) where
    D: Copy + Display + Eq + Hash,
{
    let Some(digests) = batch_digests.get(batch_id) else {
        return;
    };
    let Some(status) = batch_status_from_outcomes(digests, digest_outcomes) else {
        return;
    };

    let expired = remember_status(statuses, status_order, batch_id.to_string(), status);
    if let Some(status) = statuses.get(batch_id) {
        send_pending_waiters(pending_waiters, batch_id, status);
    }
    forget_batch(
        batch_id,
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

const fn rotation_round(round: Round) -> u64 {
    round.epoch().get().wrapping_add(round.view().get())
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
            strategy,
            public_key_cache,
            account_reader,
        });
        let app = http::router::<C, P, H, St>(app_state);
        let _http_handle = context.as_present().child("http").spawn(|_| async {
            let _ = axum::serve(listener, app).await;
        });

        let mut proposed: VecDeque<ProposedBatch<H>> = VecDeque::new();
        let mut statuses: AHashMap<String, BatchStatus> = AHashMap::new();
        let mut status_order = VecDeque::new();
        let mut batch_digests: AHashMap<String, Vec<H::Digest>> = AHashMap::new();
        let mut digest_watchers: AHashMap<H::Digest, Vec<String>> = AHashMap::new();
        let mut digest_outcomes: AHashMap<H::Digest, DigestOutcome> = AHashMap::new();
        let mut pending_waiters: AHashMap<String, Vec<oneshot::Sender<TxStatus>>> = AHashMap::new();
        let mut known_digests: AHashSet<H::Digest> = AHashSet::new();
        let mut highest_consensus_round = 0;

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
                    if let Some(status) = statuses.get(&batch_id) {
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
                        batch_id.clone(),
                        accepted_status(&digests),
                    );
                    batch_digests.insert(batch_id.clone(), digests.clone());
                    watch_batch(&batch_id, &digests, &mut digest_watchers);
                    forget_expired_batches(
                        expired,
                        &mut batch_digests,
                        &mut digest_watchers,
                        &mut digest_outcomes,
                        &mut pending_waiters,
                    );
                    if let Some(result) = result {
                        pending_waiters
                            .entry(batch_id.clone())
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
                    let _ = response.send(statuses.get(&batch_id).cloned());
                }
                Message::QueryConsensusRound { response } => {
                    let _ = response.send(highest_consensus_round);
                }
                Message::Propose { height, response } => {
                    let mut batch_txs = Vec::new();
                    let mut batch_bytes = 0;

                    while let Some(entry) = pool.front() {
                        if batch_bytes + entry.total_bytes > max_propose_bytes
                            && !batch_txs.is_empty()
                        {
                            break;
                        }
                        let entry = pool.pop_front().expect("front was Some");
                        pool_bytes -= entry.total_bytes;
                        batch_bytes += entry.total_bytes;
                        let mut digests = Vec::with_capacity(entry.transactions.len());
                        for tx in &entry.transactions {
                            digests.push(*tx.message_digest());
                        }
                        proposed.push_back(ProposedBatch { height, digests });
                        batch_txs.extend(entry.transactions);
                    }
                    response.send_lossy(batch_txs);
                }
                Message::Report(Update::Block(block, acknowledgement)) => {
                    highest_consensus_round =
                        highest_consensus_round.max(rotation_round(block.header.context.round));
                    let height = block.header.height;
                    let finalized: AHashSet<H::Digest> = block
                        .body
                        .iter()
                        .filter_map(|tx| tx.get().map(|tx| *tx.message_digest()))
                        .collect();

                    let mut remaining = VecDeque::new();
                    for batch in proposed.drain(..) {
                        let affected = watched_batches_for(&batch.digests, &digest_watchers);
                        if batch
                            .digests
                            .iter()
                            .any(|digest| finalized.contains(digest))
                        {
                            for digest in &batch.digests {
                                if finalized.contains(digest) {
                                    digest_outcomes
                                        .insert(*digest, DigestOutcome::Finalized { height });
                                } else {
                                    digest_outcomes.insert(*digest, DigestOutcome::Dropped);
                                }
                                known_digests.remove(digest);
                            }
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
                        } else if height >= batch.height + drop_grace_blocks {
                            for digest in &batch.digests {
                                digest_outcomes.insert(*digest, DigestOutcome::Dropped);
                                known_digests.remove(digest);
                            }
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
                        } else {
                            remaining.push_back(batch);
                        }
                    }
                    proposed = remaining;

                    acknowledgement.acknowledge();
                }
                Message::Report(Update::Tip(round, ..)) => {
                    highest_consensus_round = highest_consensus_round.max(rotation_round(round));
                }
            }
        }
        warn!("mempool actor stopped: all senders dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BatchStatus, DigestOutcome, TxStatus, batch_status_from_outcomes, new_transactions,
        status_for_finalized_block,
    };
    use ahash::{AHashMap, AHashSet};
    use commonware_cryptography::{Signer, ed25519, sha256};
    use commonware_math::algebra::Random;
    use constantinople_primitives::{TRANSACTION_NAMESPACE, Transaction, TransactionPublicKey};
    use core::num::NonZeroU64;
    use rand::{SeedableRng, rngs::StdRng};

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
                included: vec![first.to_string(), third.to_string()],
                filtered: vec![second.to_string()],
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
            Some(BatchStatus::PartiallyFinalized {
                height: 7,
                included: vec![first.to_string()],
                filtered: vec![second.to_string()],
            }),
        );
    }
}
