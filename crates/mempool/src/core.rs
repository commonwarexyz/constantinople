use crate::{
    PendingTransaction,
    server::{InclusionReceipt, TransactionState, TransactionStatus},
};
use commonware_codec::EncodeSize;
use commonware_cryptography::{Hasher, PublicKey};
use commonware_utils::hex;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::Duration,
};
use tokio::{sync::oneshot, time::Instant};

const MAX_RECENT_STATUSES: usize = 1_000_000;
const RECENT_STATUS_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcceptError {
    MempoolFull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct EntryId {
    slot: usize,
    generation: u64,
}

#[derive(Debug)]
struct Entry<H: Hasher, P: PublicKey> {
    tx: PendingTransaction<P, H>,
    encoded_len: usize,
    leased: bool,
}

#[derive(Debug)]
struct EntrySlot<H: Hasher, P: PublicKey> {
    generation: u64,
    entry: Option<Entry<H, P>>,
}

#[derive(Debug)]
struct LeaseBatch {
    entries: Vec<EntryId>,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct RecentTransactionStatus {
    status: TransactionStatus,
    recorded_at: Instant,
}

#[derive(Debug)]
pub(crate) struct ResolveNotification {
    pub receipt: InclusionReceipt,
    pub waiters: Vec<oneshot::Sender<InclusionReceipt>>,
}

#[derive(Debug)]
struct CandidateTransaction<H: Hasher, P: PublicKey> {
    tx: PendingTransaction<P, H>,
    hash: Vec<u8>,
    tx_hash: String,
    encoded_len: usize,
}

/// High-throughput FIFO transaction core.
///
/// The core keeps O(1) lookup structures on the hot path and uses lazy
/// tombstones to avoid queue compaction during finalize or rejection. Ready
/// transactions live in a FIFO deque. Once a transaction is proposed it moves
/// into an in-flight batch and is retried from that batch until it is
/// explicitly included or rejected.
#[derive(Debug)]
pub(crate) struct FifoCore<H: Hasher, P: PublicKey> {
    slots: Vec<EntrySlot<H, P>>,
    free_slots: Vec<usize>,
    by_hash: HashMap<Vec<u8>, EntryId>,
    ready: VecDeque<EntryId>,
    inflight_batches: VecDeque<LeaseBatch>,
    pending_bytes: usize,
    waiters: HashMap<Vec<u8>, Vec<oneshot::Sender<InclusionReceipt>>>,
    recent_order: VecDeque<(Vec<u8>, Instant)>,
    recent_statuses: HashMap<Vec<u8>, RecentTransactionStatus>,
}

impl<H: Hasher, P: PublicKey> FifoCore<H, P> {
    pub(crate) fn new() -> Self {
        Self {
            slots: Vec::new(),
            free_slots: Vec::new(),
            by_hash: HashMap::new(),
            ready: VecDeque::new(),
            inflight_batches: VecDeque::new(),
            pending_bytes: 0,
            waiters: HashMap::new(),
            recent_order: VecDeque::new(),
            recent_statuses: HashMap::new(),
        }
    }

    pub(crate) fn accept_many(
        &mut self,
        transactions: Vec<PendingTransaction<P, H>>,
        max_pool_bytes: usize,
        now: Instant,
    ) -> Result<Vec<String>, AcceptError> {
        self.cleanup_recent_statuses(now);

        let candidates = transactions
            .into_iter()
            .map(|tx| {
                let hash = tx.message_digest().as_ref().to_vec();
                let tx_hash = hex(&hash);
                let encoded_len = tx.encode_size();
                CandidateTransaction {
                    tx,
                    hash,
                    tx_hash,
                    encoded_len,
                }
            })
            .collect::<Vec<_>>();

        let mut insertable_hashes = HashSet::with_capacity(candidates.len());
        let mut added_bytes = 0_usize;
        for candidate in &candidates {
            if self.by_hash.contains_key(&candidate.hash)
                || self.recent_statuses.contains_key(&candidate.hash)
                || !insertable_hashes.insert(candidate.hash.clone())
            {
                continue;
            }

            added_bytes += candidate.encoded_len;
            if self.pending_bytes + added_bytes > max_pool_bytes {
                return Err(AcceptError::MempoolFull);
            }
        }

        let mut inserted = HashSet::with_capacity(insertable_hashes.len());
        for candidate in candidates.iter() {
            if !insertable_hashes.contains(&candidate.hash)
                || !inserted.insert(candidate.hash.clone())
            {
                continue;
            }

            let entry = Entry {
                tx: candidate.tx.clone(),
                encoded_len: candidate.encoded_len,
                leased: false,
            };
            let entry_id = self.insert_entry(entry);
            self.pending_bytes += candidate.encoded_len;
            self.by_hash.insert(candidate.hash.clone(), entry_id);
            self.ready.push_back(entry_id);
        }

        Ok(candidates
            .into_iter()
            .map(|candidate| candidate.tx_hash)
            .collect())
    }

    pub(crate) fn register_waiter(
        &mut self,
        hash: &[u8],
    ) -> Option<oneshot::Receiver<InclusionReceipt>> {
        if !self.by_hash.contains_key(hash) {
            return None;
        }

        let (sender, receiver) = oneshot::channel();
        self.waiters.entry(hash.to_vec()).or_default().push(sender);
        Some(receiver)
    }

    pub(crate) fn register_waiters(
        &mut self,
        requested_hashes: &[Vec<u8>],
    ) -> Vec<oneshot::Receiver<InclusionReceipt>> {
        requested_hashes
            .iter()
            .filter_map(|hash| self.register_waiter(hash))
            .collect()
    }

    pub(crate) fn status_many(
        &mut self,
        requested_hashes: &[Vec<u8>],
        tx_hashes: &[String],
        now: Instant,
    ) -> Vec<TransactionStatus> {
        self.cleanup_recent_statuses(now);

        requested_hashes
            .iter()
            .zip(tx_hashes.iter())
            .map(|(hash, tx_hash)| self.status_for_hash(hash, tx_hash.clone()))
            .collect()
    }

    pub(crate) fn propose(
        &mut self,
        max_bytes: usize,
        proposal_lease_duration: Duration,
        now: Instant,
    ) -> Vec<PendingTransaction<P, H>> {
        if let Some(batch) = self.propose_expired_batch(max_bytes, proposal_lease_duration, now) {
            return batch;
        }

        let mut batch = Vec::new();
        let mut batch_bytes = 0_usize;
        let mut leased_entries = Vec::new();

        while let Some(entry_id) = self.ready.pop_front() {
            let Some(entry) = self.entry_mut(entry_id) else {
                continue;
            };
            if entry.leased {
                continue;
            }

            if batch_bytes + entry.encoded_len > max_bytes && !batch.is_empty() {
                self.ready.push_front(entry_id);
                break;
            }

            entry.leased = true;
            batch_bytes += entry.encoded_len;
            batch.push(entry.tx.clone());
            leased_entries.push(entry_id);
        }

        if !leased_entries.is_empty() {
            self.inflight_batches.push_back(LeaseBatch {
                entries: leased_entries,
                expires_at: now + proposal_lease_duration,
            });
        }

        batch
    }

    pub(crate) fn resolve_included(
        &mut self,
        hash: Vec<u8>,
        receipt: InclusionReceipt,
        now: Instant,
    ) -> ResolveNotification {
        if let Some(entry_id) = self.by_hash.remove(&hash) {
            self.remove_entry(entry_id);
        }

        self.finish_resolution(hash, receipt, now)
    }

    pub(crate) fn resolve_rejected(
        &mut self,
        hash: Vec<u8>,
        receipt: InclusionReceipt,
        now: Instant,
    ) -> ResolveNotification {
        let Some(entry_id) = self.by_hash.remove(&hash) else {
            return ResolveNotification {
                receipt,
                waiters: Vec::new(),
            };
        };

        self.remove_entry(entry_id);

        self.finish_resolution(hash, receipt, now)
    }

    fn finish_resolution(
        &mut self,
        hash: Vec<u8>,
        receipt: InclusionReceipt,
        now: Instant,
    ) -> ResolveNotification {
        self.store_recent_status(hash.clone(), transaction_status_from_receipt(&receipt), now);
        let waiters = self.waiters.remove(&hash).unwrap_or_default();

        ResolveNotification { receipt, waiters }
    }

    fn propose_expired_batch(
        &mut self,
        max_bytes: usize,
        proposal_lease_duration: Duration,
        now: Instant,
    ) -> Option<Vec<PendingTransaction<P, H>>> {
        loop {
            let expired = self.inflight_batches.front()?.expires_at <= now;
            if !expired {
                return None;
            }

            let lease_batch = self
                .inflight_batches
                .pop_front()
                .expect("expired in-flight batch should exist");
            let mut batch = Vec::new();
            let mut batch_bytes = 0_usize;
            let mut retried_entries = Vec::new();

            for entry_id in lease_batch.entries {
                let Some(entry) = self.entry_mut(entry_id) else {
                    continue;
                };
                if !entry.leased {
                    continue;
                }

                if batch_bytes + entry.encoded_len > max_bytes && !batch.is_empty() {
                    break;
                }

                batch_bytes += entry.encoded_len;
                batch.push(entry.tx.clone());
                retried_entries.push(entry_id);
            }

            if retried_entries.is_empty() {
                continue;
            }

            self.inflight_batches.push_back(LeaseBatch {
                entries: retried_entries,
                expires_at: now + proposal_lease_duration,
            });
            return Some(batch);
        }
    }
    fn status_for_hash(&self, hash: &[u8], tx_hash: String) -> TransactionStatus {
        if self.by_hash.contains_key(hash) {
            return TransactionStatus {
                tx_hash,
                state: TransactionState::Pending,
                height: 0,
            };
        }

        if let Some(recent) = self.recent_statuses.get(hash) {
            return recent.status.clone();
        }

        TransactionStatus {
            tx_hash,
            state: TransactionState::Unknown,
            height: 0,
        }
    }

    fn store_recent_status(&mut self, hash: Vec<u8>, status: TransactionStatus, now: Instant) {
        self.recent_order.push_back((hash.clone(), now));
        self.recent_statuses.insert(
            hash,
            RecentTransactionStatus {
                status,
                recorded_at: now,
            },
        );
        self.cleanup_recent_statuses(now);
    }

    fn cleanup_recent_statuses(&mut self, now: Instant) {
        while let Some((hash, recorded_at)) = self.recent_order.front().cloned() {
            let remove = match self.recent_statuses.get(&hash) {
                Some(recent) if recent.recorded_at != recorded_at => true,
                Some(recent) if now.duration_since(recent.recorded_at) > RECENT_STATUS_TTL => true,
                Some(_) if self.recent_statuses.len() > MAX_RECENT_STATUSES => true,
                None => true,
                _ => false,
            };
            if !remove {
                break;
            }

            self.recent_order.pop_front();
            if self
                .recent_statuses
                .get(&hash)
                .is_some_and(|recent| recent.recorded_at == recorded_at)
            {
                self.recent_statuses.remove(&hash);
            }
        }
    }

    fn insert_entry(&mut self, entry: Entry<H, P>) -> EntryId {
        if let Some(slot_index) = self.free_slots.pop() {
            let slot = self
                .slots
                .get_mut(slot_index)
                .expect("free slot should exist in entry table");
            slot.generation = slot.generation.saturating_add(1);
            slot.entry = Some(entry);
            return EntryId {
                slot: slot_index,
                generation: slot.generation,
            };
        }

        let slot = self.slots.len();
        self.slots.push(EntrySlot {
            generation: 0,
            entry: Some(entry),
        });
        EntryId {
            slot,
            generation: 0,
        }
    }

    fn remove_entry(&mut self, entry_id: EntryId) {
        let Some(slot) = self.slots.get_mut(entry_id.slot) else {
            return;
        };
        if slot.generation != entry_id.generation {
            return;
        }

        let Some(entry) = slot.entry.take() else {
            return;
        };
        self.pending_bytes = self
            .pending_bytes
            .checked_sub(entry.encoded_len)
            .expect("pending bytes underflowed during entry removal");
        self.free_slots.push(entry_id.slot);
    }

    fn entry_mut(&mut self, entry_id: EntryId) -> Option<&mut Entry<H, P>> {
        let slot = self.slots.get_mut(entry_id.slot)?;
        if slot.generation != entry_id.generation {
            return None;
        }
        slot.entry.as_mut()
    }
}

fn transaction_status_from_receipt(receipt: &InclusionReceipt) -> TransactionStatus {
    TransactionStatus {
        tx_hash: receipt.tx_hash.clone(),
        state: if receipt.included {
            TransactionState::Included
        } else {
            TransactionState::Rejected
        },
        height: receipt.height,
    }
}
