//! Off-chain payment-channel exercise for the spammer.
//!
//! Drives channel-client lifecycles against a live node and operator: open a
//! channel on-chain, register it with the operator, stream vouchers off-chain,
//! then ask the operator to settle with a single on-chain close. The close is
//! owned by the operator so deposit bounds and final cumulative accounting live
//! behind the same service boundary used in testnet.
//!
//! The channels exercise the delegated (x402-style) topology: each payer's
//! settlements pay a *keyless* receiver account derived from the payer (see
//! [`derive_receiver`]), and the operator settles on that receiver's behalf —
//! the payee never signs anything, on-chain or off. The operator itself earns
//! nothing (fees are deliberately out of scope), so its account only ever
//! holds abandon-burn dust.
//!
//! Every open carries an expiry (block height) after which the payer may
//! reclaim the escrow with a `TimeoutChannel`. A jittered fraction of
//! lifecycles exercise that path deliberately (short expiry, no registration,
//! unilateral reclaim); the rest use a generous runway and settle normally. A
//! lifecycle that strands its deposit (registration or settlement failure) is
//! queued and reclaimed once its expiry passes, so failures no longer lose
//! funds permanently.
//!
//! A lifecycle spends most of its wall-clock off-chain (registration retries,
//! voucher streaming, waiting on the settle), so one lifecycle at a time
//! yields sparse, bursty on-chain traffic. [`LifecyclePool`] runs several
//! runners — each owning a disjoint slice of the account ring — concurrently,
//! staggering their phases into a steady stream of opens, closes, and
//! reclaims while the submitter keeps landing transfer batches.
//!
//! Channels use their own account ring, so their nonces never collide with the
//! transfer presigner's accounts. Accounts start empty, so each runner's first
//! act is a warm-up block of mints (each account's nonce 0) for
//! [`crate::RING_MINT_AMOUNT`]; every settlement then drains the payer by the
//! settled cumulative — the mint funds a very long run, and a drained account
//! simply fails its open (skipped at proposal, never negative).

use crate::{
    JitterRng,
    accounts::SpamAccount,
    signer::{Tx, sign_mint_batches},
    submitter::{RelayerSubmitter, Stats},
};
use commonware_cryptography::{Hasher as _, Sha256, ed25519, sha256};
use commonware_parallel::Sequential;
use constantinople_primitives::{
    AccountKey, TRANSACTION_NAMESPACE, Transaction, TransactionPublicKey, Voucher, channel_address,
    operator_api::{
        OperatorError, PublicKeyResponse, RegisterRequest, RegisterResponse, SettleRequest,
        SettleResponse, VoucherRequest,
    },
};
use core::num::NonZeroU64;
use std::sync::{Arc, atomic::Ordering};
use tracing::warn;

const PARTIAL_SETTLEMENT_PROBABILITY: f64 = 0.5;
pub(crate) const MAX_REFUND_VOUCHERS: u64 = 3;
const REGISTRATION_ATTEMPTS: usize = 10;
const REGISTRATION_BACKOFF: core::time::Duration = core::time::Duration::from_millis(500);
/// Spammer-side slack added on top of the operator's advertised margins when
/// picking a channel expiry: covers the height estimate lagging finalization,
/// registration retries, and voucher streaming on a fast local chain. (With
/// the operator's default margins the derived runway lands near the 256
/// blocks previously hardcoded.)
const CHANNEL_EXPIRY_SLACK: u64 = 224;

/// Blocks of runway a normal (settled) channel is opened with, derived from
/// the operator's advertised margins so the spammer and operator cannot
/// drift apart on what "enough runway" means.
pub const fn channel_expiry_runway(response: &PublicKeyResponse) -> u64 {
    response
        .min_runway
        .saturating_add(response.settle_margin)
        .saturating_add(CHANNEL_EXPIRY_SLACK)
}

/// Everything the runners need to know about the operator, resolved once at
/// startup from its `/public-key` advertisement.
#[derive(Clone)]
pub struct OperatorContext {
    pub client: OperatorClient,
    /// The operator's account key (every channel names it in its address
    /// derivation).
    pub account: AccountKey,
    /// Blocks of runway settled channels are opened with (see
    /// [`channel_expiry_runway`]).
    pub expiry_runway: u64,
    /// Amount each voucher steps the cumulative by: the spammer's `--value`.
    /// (The operator charges nothing; this is purely the spammer's knob.)
    pub voucher_value: u64,
}
/// Fraction of lifecycles that exercise the payer timeout path instead of
/// settling through the operator.
const TIMEOUT_LIFECYCLE_PROBABILITY: f64 = 0.1;
/// Blocks until a timeout-exercise channel expires.
const TIMEOUT_EXPIRY_DELTA: u64 = 3;
/// How many times to resubmit a timeout while waiting for expiry to pass.
const RECLAIM_ATTEMPTS: usize = 30;
const RECLAIM_BACKOFF: core::time::Duration = core::time::Duration::from_millis(500);

/// Domain separator for the spammer's derived (keyless) receiver accounts.
const RECEIVER_DOMAIN: &[u8] = b"constantinople-spammer-receiver";

/// Derives the keyless receiver account a payer's channels pay out to.
///
/// A channel's payee never signs anything — the operator settles on its
/// behalf — so the demo pays each payer's settlements to an account no key
/// produces: its balance accumulates in the explorer, spendable by no one.
fn derive_receiver(payer: &AccountKey) -> AccountKey {
    let mut hasher = Sha256::default();
    hasher.update(RECEIVER_DOMAIN);
    hasher.update(payer.as_ref());
    AccountKey::from_digest(&hasher.finalize())
}

/// Runs several channel runners' lifecycles concurrently.
///
/// Each runner owns a disjoint slice of the channel account ring (its own
/// nonces, reclaims, and warm-up), so lifecycles never share mutable state:
/// a runner travels into its task and comes back when the lifecycle ends.
pub struct LifecyclePool {
    idle: Vec<ChannelRunner>,
    busy: tokio::task::JoinSet<ChannelRunner>,
}

/// Concurrent lifecycles per submitter. A lifecycle spends most of its
/// wall-clock waiting on finalization, so aggregate voucher throughput is
/// (concurrency x vouchers-per-lifecycle / lifecycle seconds) — this many
/// runners keeps the fleet's off-chain volume near the operator's
/// verification throughput instead of trickling at a few percent of it.
const CONCURRENT_LIFECYCLES: usize = 32;

impl LifecyclePool {
    /// Splits a submitter's channel account ring into per-runner slices so
    /// several lifecycles can be in flight at once. Each runner needs at
    /// least two accounts (a ring), so small configurations get fewer
    /// runners.
    pub fn split(
        accounts: Vec<SpamAccount>,
        operator: OperatorContext,
        avg_vouchers: u64,
        channel_offset: u64,
        stats: &Arc<Stats>,
    ) -> Self {
        let runner_count = (accounts.len() / 2).clamp(1, CONCURRENT_LIFECYCLES);
        let mut slices: Vec<Vec<SpamAccount>> = (0..runner_count).map(|_| Vec::new()).collect();
        for (index, account) in accounts.into_iter().enumerate() {
            slices[index % runner_count].push(account);
        }
        let idle = slices
            .into_iter()
            .enumerate()
            .map(|(index, slice)| {
                ChannelRunner::new(
                    slice,
                    operator.clone(),
                    avg_vouchers,
                    // Distinct voucher-count RNG stream per runner (and from
                    // the submitter's coin flip, seeded at offset + 1).
                    channel_offset.wrapping_add(2 + index as u64),
                    stats.clone(),
                )
            })
            .collect();
        Self {
            idle,
            busy: tokio::task::JoinSet::new(),
        }
    }

    /// A pool with no runners: channel traffic disabled.
    pub fn disabled() -> Self {
        Self {
            idle: Vec::new(),
            busy: tokio::task::JoinSet::new(),
        }
    }

    /// Whether the pool has no runners at all (channels disabled).
    pub fn is_empty(&self) -> bool {
        self.idle.is_empty() && self.busy.is_empty()
    }

    /// Starts lifecycles until every runner is busy, reaping finished tasks
    /// first. Returns how many were started (zero when the pool is already
    /// saturated). Filling the pool — rather than starting one lifecycle per
    /// turn — is what keeps aggregate voucher volume up: turns arrive every
    /// couple of seconds, so one-at-a-time starts would cap concurrency at a
    /// handful of lifecycles no matter how many runners exist.
    pub fn fill(&mut self, submitter: &RelayerSubmitter) -> usize {
        while let Some(runner) = self.busy.try_join_next() {
            self.idle.push(runner.expect("lifecycle task panicked"));
        }
        let started = self.idle.len();
        while let Some(mut runner) = self.idle.pop() {
            let submitter = submitter.clone();
            self.busy.spawn(async move {
                runner.run_once(&submitter).await;
                runner
            });
        }
        started
    }
}

/// A stranded deposit awaiting reclaim once its channel's expiry passes.
struct PendingReclaim {
    payer_i: usize,
    open_nonce: u64,
    expiry: u64,
    /// The signed `TimeoutChannel`, created on the first attempt and reused
    /// by every retry. Re-signing per attempt would reserve a fresh payer
    /// nonce each time; if an earlier attempt never landed, that nonce is a
    /// permanent gap, and enough gaps wedge the payer's run-ahead window.
    timeout: Option<Tx>,
}

impl PendingReclaim {
    const fn new(payer_i: usize, open_nonce: u64, expiry: u64) -> Self {
        Self {
            payer_i,
            open_nonce,
            expiry,
            timeout: None,
        }
    }
}

/// Runs channel lifecycles over a dedicated account ring.
pub struct ChannelRunner {
    accounts: Vec<SpamAccount>,
    /// The keyless receiver each payer's channels pay out to, index-aligned
    /// with `accounts` (see [`derive_receiver`]).
    receivers: Vec<AccountKey>,
    nonces: Vec<u64>,
    cursor: usize,
    operator: OperatorContext,
    avg_vouchers: u64,
    rng: JitterRng,
    /// Shared submission stats; expiry selection and reclaim due-checks read
    /// the fleet-wide finalized height from it. The runner must not keep its
    /// own copy: channel lifecycles can be many blocks apart, and an expiry
    /// computed from a stale height is rejected (or reclaimed) instead of
    /// settled.
    stats: Arc<Stats>,
    /// Deposits stranded by registration or settlement failures, reclaimed
    /// via timeout once due.
    reclaims: Vec<PendingReclaim>,
    /// Whether the ring's warm-up mints have run (accounts start empty).
    warmed: bool,
}

impl ChannelRunner {
    /// Creates a runner over `accounts` (a ring; needs at least two), streaming
    /// on average `avg_vouchers` vouchers per channel, each stepping the
    /// cumulative by the spammer's `--value`.
    /// `seed` seeds the per-channel voucher-count jitter; `stats`
    /// supplies the fleet-wide finalized height (kept fresh by every
    /// submission).
    pub fn new(
        accounts: Vec<SpamAccount>,
        operator: OperatorContext,
        avg_vouchers: u64,
        seed: u64,
        stats: Arc<Stats>,
    ) -> Self {
        assert!(
            accounts.len() >= 2,
            "channel ring needs at least two accounts"
        );
        assert!(avg_vouchers >= 1, "average vouchers must be >= 1");
        assert!(operator.voucher_value >= 1, "voucher value must be >= 1");
        // Like the transfer presigner, the spammer assumes a fresh chain per
        // run: accounts are seed-derived and nonces restart at zero (the
        // warm-up mint), so rerunning against a chain that already consumed
        // them makes every lifecycle no-op at proposal.
        let nonces = vec![0; accounts.len()];
        let receivers = accounts
            .iter()
            .map(|account| {
                derive_receiver(&AccountKey::from_public_key(
                    &TransactionPublicKey::ed25519(account.public_key.clone()),
                ))
            })
            .collect();
        Self {
            accounts,
            receivers,
            nonces,
            cursor: 0,
            operator,
            avg_vouchers,
            rng: JitterRng::new(seed),
            stats,
            reclaims: Vec::new(),
            warmed: false,
        }
    }

    /// Lands the ring's warm-up mints: every account's first transaction
    /// (nonce 0) mints its working balance.
    async fn warm_up(&mut self, submitter: &RelayerSubmitter) {
        // The channel ring is small; sequential signing is fine here.
        submitter
            .land_mints(sign_mint_batches(
                &Sequential,
                &self.accounts,
                crate::RING_MINT_AMOUNT,
            ))
            .await;
        // Nonce 0 is consumed by the mint on every account.
        for nonce in &mut self.nonces {
            *nonce = 1;
        }
    }

    /// Latest finalized height observed by any submitter.
    fn height(&self) -> u64 {
        self.stats.height.load(Ordering::Relaxed)
    }

    /// Counts a finalized on-chain channel transaction (open, close, or
    /// timeout reclaim) in the shared stats.
    fn count_channel_tx(&self) {
        self.stats.channel_txs.fetch_add(1, Ordering::Relaxed);
    }

    fn payer_pk(&self, payer_i: usize) -> TransactionPublicKey {
        TransactionPublicKey::ed25519(self.accounts[payer_i].public_key.clone())
    }

    /// The payer's channel voucher key: its own ring key (self-delegation —
    /// the ring account is already an unattended ed25519 signer, so no
    /// separate delegated key is needed).
    fn voucher_pk(&self, payer_i: usize) -> ed25519::PublicKey {
        self.accounts[payer_i].public_key.clone()
    }

    /// Seals and signs `tx` with the payer's key.
    fn sign_as(&self, payer_i: usize, tx: Transaction<sha256::Digest>) -> Tx {
        tx.seal_and_sign(
            &self.accounts[payer_i].private_key,
            TRANSACTION_NAMESPACE,
            &mut Sha256::default(),
        )
    }

    /// Reserves the payer's next transaction nonce.
    fn next_nonce(&mut self, payer_i: usize) -> u64 {
        let nonce = self.nonces[payer_i];
        self.nonces[payer_i] += 1;
        nonce
    }

    /// Queues a stranded deposit for a timeout reclaim once `expiry` passes.
    fn queue_reclaim(&mut self, payer_i: usize, open_nonce: u64, expiry: u64) {
        self.reclaims
            .push(PendingReclaim::new(payer_i, open_nonce, expiry));
    }

    /// Voucher count for the next channel, jittered around the average so
    /// channel lifetimes vary. Uniform in `[ceil(avg/2), avg + avg/2]`.
    fn next_voucher_count(&mut self) -> u64 {
        let avg = self.avg_vouchers as usize;
        let lo = (avg / 2).max(1);
        let hi = avg.saturating_add(avg / 2).max(lo);
        self.rng.range(lo, hi) as u64
    }

    /// Deposit for the next channel. Half of channels carry a small extra
    /// escrow so the close path exercises payer refunds instead of always
    /// exhausting the channel exactly.
    fn next_deposit(&mut self, cumulative: u64) -> u64 {
        if !self.rng.bernoulli(PARTIAL_SETTLEMENT_PROBABILITY) {
            return cumulative;
        }

        let extra_vouchers = self.rng.range(1, MAX_REFUND_VOUCHERS as usize) as u64;
        cumulative.saturating_add(extra_vouchers.saturating_mul(self.operator.voucher_value))
    }

    /// Runs one lifecycle: open -> stream vouchers off-chain -> close (or, for
    /// a jittered fraction, open -> wait out expiry -> unilateral timeout).
    /// Also retries any reclaims whose expiry has passed. Progress is counted
    /// directly in the shared stats.
    pub async fn run_once(&mut self, submitter: &RelayerSubmitter) {
        if !self.warmed {
            self.warm_up(submitter).await;
            self.warmed = true;
        }
        self.reclaim_due(submitter).await;

        let n = self.accounts.len();
        let payer_i = self.cursor;
        self.cursor = (self.cursor + 1) % n;

        if self.rng.bernoulli(TIMEOUT_LIFECYCLE_PROBABILITY) {
            self.run_timeout_lifecycle(submitter, payer_i).await;
            return;
        }

        let payer_pk = self.payer_pk(payer_i);
        let payer_account = AccountKey::from_public_key(&payer_pk);

        let vouchers = self.next_voucher_count();
        let cumulative = vouchers.saturating_mul(self.operator.voucher_value);
        let deposit_value = self.next_deposit(cumulative);
        let Some(deposit) = NonZeroU64::new(deposit_value) else {
            return;
        };

        // On-chain: open the channel. The expiry gives the operator plenty of
        // runway; if anything below strands the deposit, the reclaim queue
        // recovers it after this height passes.
        let expiry = self.height().saturating_add(self.operator.expiry_runway);
        let Some((open_nonce, open_tx_digest)) = self
            .submit_open(submitter, payer_i, &payer_pk, deposit, expiry)
            .await
        else {
            return;
        };

        // Off-chain: stream vouchers, verifying each with the shared predicate.
        // These are the payments that never touch the chain.
        // Delegated topology: the payout goes to the payer's keyless
        // receiver; the operator only settles. The ring key doubles as the
        // channel's voucher key (self-delegation).
        let channel = channel_address(
            &payer_account,
            &self.receivers[payer_i],
            &self.operator.account,
            &self.voucher_pk(payer_i),
            open_nonce,
        );
        // The open is finalized but the operator's indexer may not have
        // ingested it yet. Retry through transient lag (503/transport); a 400
        // rejection will keep failing, so go straight to the timeout reclaim.
        let zero_voucher = Voucher::sign(&self.accounts[payer_i].private_key, channel, 0).signature;
        let mut capability = None;
        for attempt in 1..=REGISTRATION_ATTEMPTS {
            match self
                .operator
                .client
                .register_channel(&open_tx_digest, &zero_voucher)
                .await
            {
                Ok(granted) => {
                    capability = Some(granted);
                    break;
                }
                Err(error @ OperatorError::Rejected(_)) => {
                    warn!(%error, %channel, "operator rejected the channel registration");
                    break;
                }
                Err(error) => {
                    warn!(%error, %channel, attempt, "operator channel registration failed");
                    tokio::time::sleep(REGISTRATION_BACKOFF).await;
                }
            }
        }
        let Some(capability) = capability else {
            self.queue_reclaim(payer_i, open_nonce, expiry);
            return;
        };

        let mut served = 0u64;
        for i in 1..=vouchers {
            let amount = i.saturating_mul(self.operator.voucher_value);
            let voucher = Voucher::sign(&self.accounts[payer_i].private_key, channel, amount);
            match self.operator.client.serve_voucher(&voucher).await {
                Ok(()) => served += 1,
                Err(error) => {
                    warn!(%error, %channel, amount, "operator voucher rejected");
                    break;
                }
            }
        }
        self.stats.vouchers.fetch_add(served, Ordering::Relaxed);
        if served == 0 {
            self.queue_reclaim(payer_i, open_nonce, expiry);
            return;
        }

        if let Err(error) = self
            .operator
            .client
            .settle_channel(channel, &capability)
            .await
        {
            warn!(%error, %channel, "operator settlement failed");
            self.queue_reclaim(payer_i, open_nonce, expiry);
            return;
        }
        self.count_channel_tx();
    }

    /// Builds and submits an `OpenChannel` paying the payer's derived
    /// receiver via the operator, reserving the payer's next nonce (the
    /// channel address derives from it, so every open is a fresh,
    /// never-recurring channel). Returns the open nonce and transaction
    /// digest once the open finalizes. On failure, don't close a channel that
    /// doesn't exist — but without a height the chain never judged the open
    /// (dropped batch or transport error) and it may still finalize,
    /// escrowing the deposit, so queue a reclaim rather than strand it (a
    /// reclaim that finds no channel is dropped).
    async fn submit_open(
        &mut self,
        submitter: &RelayerSubmitter,
        payer_i: usize,
        payer_pk: &TransactionPublicKey,
        deposit: NonZeroU64,
        expiry: u64,
    ) -> Option<(u64, sha256::Digest)> {
        let open_nonce = self.next_nonce(payer_i);
        let open = self.sign_as(
            payer_i,
            Transaction::open_channel(
                payer_pk.clone(),
                self.receivers[payer_i],
                self.operator.account,
                self.voucher_pk(payer_i),
                deposit,
                expiry,
                open_nonce,
            ),
        );
        let open_tx_digest = *open.message_digest();
        let report = submitter.submit_reporting_with_height(vec![open]).await;
        if report.finalized == 0 {
            // The open may still finalize later: a dropped single-tx batch is
            // reported without a height whether the chain judged it or not, so
            // the nonce stays burned and the deposit is reclaimed once expiry
            // passes. A payer whose opens keep getting filtered thus leaves a
            // nonce gap per failed lifecycle; returning those nonces would
            // need the mempool to report judged-drops with a height.
            if report.height.is_none() {
                self.queue_reclaim(payer_i, open_nonce, expiry);
            }
            return None;
        }
        self.count_channel_tx();
        Some((open_nonce, open_tx_digest))
    }

    /// Opens a short-expiry channel, skips the operator entirely, and reclaims
    /// the deposit with a unilateral timeout once the expiry passes.
    async fn run_timeout_lifecycle(&mut self, submitter: &RelayerSubmitter, payer_i: usize) {
        let payer_pk = self.payer_pk(payer_i);
        let expiry = self.height().saturating_add(TIMEOUT_EXPIRY_DELTA);
        let deposit = NonZeroU64::new(self.operator.voucher_value).expect("voucher value is >= 1");
        let Some((open_nonce, _)) = self
            .submit_open(submitter, payer_i, &payer_pk, deposit, expiry)
            .await
        else {
            return;
        };

        // A `TimeoutChannel` is invalid until the chain's height exceeds the
        // channel's expiry, so wait that out locally — polling the same
        // observed height `reclaim_due` gates on — instead of burning doomed
        // relayer round trips. If the height stalls, fall through anyway:
        // `try_reclaim` retries with the same backoff and a still-early
        // attempt re-queues as `Transient`, exactly as before.
        for _ in 0..RECLAIM_ATTEMPTS {
            if self.height() > expiry {
                break;
            }
            tokio::time::sleep(RECLAIM_BACKOFF).await;
        }
        self.resolve_reclaim(submitter, PendingReclaim::new(payer_i, open_nonce, expiry))
            .await;
    }

    /// Attempts `reclaim` once and settles its outcome: count a landed
    /// reclaim, drop a vanished channel with a warning, or re-queue anything
    /// indefinite (keeping its signed timeout so retries reuse the same
    /// nonce).
    async fn resolve_reclaim(&mut self, submitter: &RelayerSubmitter, mut reclaim: PendingReclaim) {
        match self.try_reclaim(submitter, &mut reclaim).await {
            ReclaimOutcome::Reclaimed => self.count_channel_tx(),
            ReclaimOutcome::ChannelGone => {
                // The chain processed the timeout past expiry and skipped it,
                // so the channel no longer exists — a close won the race and
                // there is nothing left to reclaim. (For a timeout exercise,
                // which never registers, this is unexpected; drop rather than
                // retry forever.)
                warn!(
                    open_nonce = reclaim.open_nonce,
                    expiry = reclaim.expiry,
                    "reclaim found no channel; dropping"
                );
            }
            // A transport failure proves nothing about the channel; keep the
            // deposit queued rather than stranding it.
            ReclaimOutcome::Transient => self.reclaims.push(reclaim),
        }
    }

    /// Retries queued reclaims whose expiry has passed (one attempt each).
    async fn reclaim_due(&mut self, submitter: &RelayerSubmitter) {
        let height = self.height();
        let (due, pending): (Vec<_>, Vec<_>) = core::mem::take(&mut self.reclaims)
            .into_iter()
            .partition(|reclaim| height > reclaim.expiry);
        self.reclaims = pending;
        for reclaim in due {
            self.resolve_reclaim(submitter, reclaim).await;
        }
    }

    /// Submits the reclaim's `TimeoutChannel`, resubmitting the same signed
    /// transaction (same nonce) until it lands, is definitively rejected, or
    /// attempts run out. The transaction is signed once and stored on the
    /// reclaim, so a re-queued `Transient` retry resubmits it rather than
    /// burning a fresh nonce.
    async fn try_reclaim(
        &mut self,
        submitter: &RelayerSubmitter,
        reclaim: &mut PendingReclaim,
    ) -> ReclaimOutcome {
        let payer_i = reclaim.payer_i;
        if reclaim.timeout.is_none() {
            let payer_pk = self.payer_pk(payer_i);
            let nonce = self.next_nonce(payer_i);
            reclaim.timeout = Some(self.sign_as(
                payer_i,
                Transaction::timeout_channel(
                    payer_pk,
                    self.receivers[payer_i],
                    self.operator.account,
                    self.voucher_pk(payer_i),
                    reclaim.open_nonce,
                    nonce,
                ),
            ));
        }
        let timeout = reclaim.timeout.as_ref().expect("signed above");
        for _ in 0..RECLAIM_ATTEMPTS {
            let report = submitter
                .submit_reporting_with_height(vec![timeout.clone()])
                .await;
            if report.finalized > 0 {
                return ReclaimOutcome::Reclaimed;
            }
            // Only a response carrying a finalization height proves the chain
            // actually processed (and skipped) the timeout; a transport error
            // or dropped batch proves nothing about the channel.
            if report.height.is_some_and(|height| height > reclaim.expiry) {
                return ReclaimOutcome::ChannelGone;
            }
            tokio::time::sleep(RECLAIM_BACKOFF).await;
        }
        ReclaimOutcome::Transient
    }
}

/// Outcome of a [`ChannelRunner::try_reclaim`] attempt.
enum ReclaimOutcome {
    /// The timeout finalized; the deposit is back with the payer.
    Reclaimed,
    /// The chain processed the timeout past the expiry and skipped it: the
    /// channel no longer exists (a close landed first).
    ChannelGone,
    /// Nothing definitive happened (transport errors, dropped batches, or the
    /// expiry has not passed on chain yet); worth retrying later.
    Transient,
}

#[derive(Clone)]
pub struct OperatorClient {
    url: String,
    http: reqwest::Client,
}

impl OperatorClient {
    /// Upper bound on any operator call. The operator's `/settle` blocks
    /// server-side until the close resolves — seconds on a healthy chain, but
    /// unbounded if the chain wedges. Without a timeout a hung settle stalls
    /// this submitter's whole ring silently; with one, the lifecycle errors
    /// into the reclaim queue and the ring keeps spamming. (A settle that
    /// times out but later succeeds is safe: its reclaim finds the channel
    /// gone and is dropped.)
    const REQUEST_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(60);

    pub fn new(url: String) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                .timeout(Self::REQUEST_TIMEOUT)
                .build()
                .expect("operator http client builds"),
        }
    }

    /// Fetches the operator's public key (the settling identity every channel
    /// names in its address derivation) plus the full advertisement: its
    /// latest observed finalized height (seeds channel expiry selection) and
    /// its expiry margins (see [`channel_expiry_runway`]).
    pub async fn public_key(&self) -> Result<(TransactionPublicKey, PublicKeyResponse), String> {
        let response = self
            .http
            .get(format!("{}/public-key", self.url))
            .send()
            .await
            .map_err(|error| format!("operator public-key request failed: {error}"))?;
        if !response.status().is_success() {
            return Err(format!("operator public-key status {}", response.status()));
        }
        let body = response
            .bytes()
            .await
            .map_err(|error| format!("operator public-key body failed: {error}"))?;
        let public_key: PublicKeyResponse = serde_json::from_slice(&body)
            .map_err(|error| format!("operator public-key response invalid: {error}"))?;
        let decoded = public_key
            .public_key()
            .map_err(|error| format!("operator public key invalid: {error}"))?;
        Ok((decoded, public_key))
    }

    async fn register_channel(
        &self,
        open_tx_digest: &sha256::Digest,
        zero_voucher: &ed25519::Signature,
    ) -> Result<String, OperatorError> {
        let body = self
            .post_json(
                "/channels",
                &RegisterRequest::new(open_tx_digest, zero_voucher),
            )
            .await?;
        let response: RegisterResponse = serde_json::from_slice(&body).map_err(|error| {
            OperatorError::unavailable(format!("operator register response invalid: {error}"))
        })?;
        if response.capability.is_empty() {
            return Err(OperatorError::unavailable(
                "operator register response has an empty capability",
            ));
        }
        Ok(response.capability)
    }

    async fn serve_voucher(&self, voucher: &Voucher) -> Result<(), String> {
        self.post_json("/vouchers", &VoucherRequest::new(voucher))
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    async fn settle_channel(&self, channel: AccountKey, capability: &str) -> Result<(), String> {
        let body = self
            .post_json("/settle", &SettleRequest::new(&channel, capability))
            .await
            .map_err(|error| error.to_string())?;
        let settle: SettleResponse = serde_json::from_slice(&body)
            .map_err(|error| format!("operator settle response invalid: {error}"))?;
        // An abandoned close answers 200 with settled=false: nothing landed
        // on-chain and the escrow is still locked, so the caller must queue a
        // timeout reclaim rather than count a settlement.
        if !settle.settled {
            return Err("operator abandoned the close; escrow remains on-chain".to_string());
        }
        Ok(())
    }

    /// Posts a JSON request and returns the success body (rejections surface
    /// the operator's error detail). A `4xx` maps back to
    /// [`OperatorError::Rejected`] (the operator answers `503` for transient
    /// dependency lag); transport errors and `5xx` are `Unavailable`.
    async fn post_json<T: serde::Serialize>(
        &self,
        path: &str,
        value: &T,
    ) -> Result<bytes::Bytes, OperatorError> {
        let body = serde_json::to_vec(value).map_err(|error| {
            OperatorError::unavailable(format!("operator request encode failed: {error}"))
        })?;
        let response = self
            .http
            .post(format!("{}{path}", self.url))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|error| {
                OperatorError::unavailable(format!("operator request failed: {error}"))
            })?;
        if response.status().is_success() {
            return response.bytes().await.map_err(|error| {
                OperatorError::unavailable(format!("operator response body failed: {error}"))
            });
        }
        // The operator explains rejections in the body ({"error": ...});
        // surface it, or debugging is a guessing game of anonymous 400s.
        let status = response.status();
        let body = response.bytes().await.unwrap_or_default();
        let message = format!(
            "operator request status {status}: {}",
            String::from_utf8_lossy(&body)
        );
        if status.is_client_error() {
            Err(OperatorError::Rejected(message))
        } else {
            Err(OperatorError::Unavailable(message))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AccountKey, ChannelRunner, OperatorClient, OperatorContext};
    use crate::{accounts::generate_accounts, submitter::Stats};
    use commonware_cryptography::Signer as _;
    use std::sync::Arc;

    fn runner(
        accounts: Vec<crate::accounts::SpamAccount>,
        avg_vouchers: u64,
        voucher_value: u64,
        seed: u64,
    ) -> ChannelRunner {
        let operator = OperatorContext {
            client: OperatorClient::new("http://127.0.0.1:1".to_string()),
            account: AccountKey::from_public_key(
                &constantinople_primitives::TransactionPublicKey::ed25519(
                    commonware_cryptography::ed25519::PrivateKey::from_seed(9).public_key(),
                ),
            ),
            expiry_runway: super::CHANNEL_EXPIRY_SLACK,
            voucher_value,
        };
        ChannelRunner::new(
            accounts,
            operator,
            avg_vouchers,
            seed,
            Arc::new(Stats::new()),
        )
    }

    #[test]
    fn receivers_are_deterministic_distinct_and_keyless() {
        let accounts = generate_accounts(4, 7_300);
        let a = runner(accounts, 8, 1, 1);
        let b = runner(generate_accounts(4, 7_300), 8, 1, 2);

        // Deterministic per payer (a restarted spammer reclaims against the
        // same channels), distinct across payers, and never the operator.
        assert_eq!(a.receivers, b.receivers);
        let unique: std::collections::HashSet<_> = a.receivers.iter().collect();
        assert_eq!(unique.len(), a.receivers.len());
        assert!(a.receivers.iter().all(|r| *r != a.operator.account));
    }

    #[test]
    fn voucher_count_stays_within_jitter_bounds() {
        let accounts = generate_accounts(4, 7_000);
        let mut runner = runner(accounts, 8, 1, 42);
        for _ in 0..1_000 {
            let v = runner.next_voucher_count();
            // avg=8 -> lo=4, hi=12
            assert!((4..=12).contains(&v), "voucher count {v} out of bounds");
        }
    }

    #[test]
    fn small_average_still_streams_at_least_one() {
        let accounts = generate_accounts(2, 7_100);
        let mut runner = runner(accounts, 1, 1, 1);
        for _ in 0..100 {
            assert!(runner.next_voucher_count() >= 1);
        }
    }

    #[test]
    fn deposits_include_exact_and_refundable_channels() {
        let accounts = generate_accounts(4, 7_200);
        let mut runner = runner(accounts, 8, 2, 99);
        let cumulative = 16;
        let mut saw_exact = false;
        let mut saw_refund = false;

        for _ in 0..1_000 {
            let deposit = runner.next_deposit(cumulative);
            assert!(
                (cumulative..=cumulative + 6).contains(&deposit),
                "deposit {deposit} out of bounds"
            );
            saw_exact |= deposit == cumulative;
            saw_refund |= deposit > cumulative;
        }

        assert!(saw_exact, "should still exercise fully exhausted channels");
        assert!(saw_refund, "should exercise partial settlement refunds");
    }
}
