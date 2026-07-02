//! Off-chain payment-channel exercise for the spammer.
//!
//! Drives channel-client lifecycles against a live node and operator: open a
//! channel on-chain, register it with the operator, stream vouchers off-chain,
//! then ask the operator to settle with a single on-chain close. The close is
//! owned by the operator so deposit bounds and final cumulative accounting live
//! behind the same service boundary used in testnet.
//!
//! Every open carries an expiry (block height) after which the payer may
//! reclaim the escrow with a `TimeoutChannel`. A jittered fraction of
//! lifecycles exercise that path deliberately (short expiry, no registration,
//! unilateral reclaim); the rest use a generous runway and settle normally. A
//! lifecycle that strands its deposit (registration or settlement failure) is
//! queued and reclaimed once its expiry passes, so failures no longer lose
//! funds permanently.
//!
//! Channels use their own account ring, so their nonces never collide with the
//! transfer presigner's accounts. Every channel pays the operator (the
//! receiver key is the operator's), so ring accounts only ever drain: each
//! lifecycle costs the payer the settled cumulative, with any extra escrow
//! refunded on close. Starting from the default account balance an account
//! funds only a bounded number of lifecycles (about a dozen at the default
//! voucher count and price) before its opens start failing for insufficient
//! balance; a drained account simply fails its open (handled gracefully below)
//! rather than ever going negative.

use crate::{JitterRng, accounts::SpamAccount, signer::Tx, submitter::RelayerSubmitter};
use commonware_codec::{DecodeExt as _, Encode};
use commonware_cryptography::Sha256;
use commonware_formatting::{from_hex, hex};
use constantinople_primitives::{
    AccountKey, TRANSACTION_NAMESPACE, Transaction, TransactionPublicKey, Voucher, channel_address,
};
use core::num::NonZeroU64;
use tracing::warn;

const PARTIAL_SETTLEMENT_PROBABILITY: f64 = 0.5;
pub(crate) const MAX_REFUND_VOUCHERS: u64 = 3;
const REGISTRATION_ATTEMPTS: usize = 10;
const REGISTRATION_BACKOFF: core::time::Duration = core::time::Duration::from_millis(500);
/// Blocks of runway a normal (settled) channel is opened with. Must comfortably
/// exceed the operator's registration runway plus settle margin.
const CHANNEL_EXPIRY_RUNWAY: u64 = 128;
/// Fraction of lifecycles that exercise the payer timeout path instead of
/// settling through the operator.
const TIMEOUT_LIFECYCLE_PROBABILITY: f64 = 0.1;
/// Blocks until a timeout-exercise channel expires.
const TIMEOUT_EXPIRY_DELTA: u64 = 3;
/// How many times to resubmit a timeout while waiting for expiry to pass.
const RECLAIM_ATTEMPTS: usize = 30;
const RECLAIM_BACKOFF: core::time::Duration = core::time::Duration::from_millis(500);

/// Outcome of one channel lifecycle.
pub struct LifecycleStats {
    /// On-chain channel transactions that finalized (opens, closes, and
    /// timeout reclaims).
    pub channel_txs: u64,
    /// Off-chain vouchers streamed and verified.
    pub vouchers: u64,
}

/// A stranded deposit awaiting reclaim once its channel's expiry passes.
struct PendingReclaim {
    payer_i: usize,
    open_nonce: u64,
    expiry: u64,
}

/// Runs channel lifecycles over a dedicated account ring.
pub struct ChannelRunner {
    accounts: Vec<SpamAccount>,
    nonces: Vec<u64>,
    cursor: usize,
    operator: OperatorClient,
    operator_pk: TransactionPublicKey,
    operator_account: AccountKey,
    avg_vouchers: u64,
    price: u64,
    rng: JitterRng,
    /// Latest finalized height observed via submissions; expiry selection and
    /// reclaim due-checks read this.
    height: u64,
    /// Deposits stranded by registration or settlement failures, reclaimed
    /// via timeout once due.
    reclaims: Vec<PendingReclaim>,
}

impl ChannelRunner {
    /// Creates a runner over `accounts` (a ring; needs at least two), streaming
    /// on average `avg_vouchers` vouchers per channel at `price` each. `seed`
    /// seeds the per-channel voucher-count jitter; `initial_height` seeds the
    /// height estimate (refined by every finalized submission).
    pub fn new(
        accounts: Vec<SpamAccount>,
        operator: OperatorClient,
        operator_pk: TransactionPublicKey,
        avg_vouchers: u64,
        price: u64,
        seed: u64,
        initial_height: u64,
    ) -> Self {
        assert!(
            accounts.len() >= 2,
            "channel ring needs at least two accounts"
        );
        assert!(avg_vouchers >= 1, "average vouchers must be >= 1");
        assert!(price >= 1, "voucher price must be >= 1");
        // Like the transfer presigner, the spammer assumes a fresh chain per
        // run: accounts are seed-derived and nonces restart at zero, so
        // rerunning against a chain that already consumed them makes every
        // lifecycle no-op at proposal.
        let nonces = vec![0; accounts.len()];
        let operator_account = AccountKey::from_public_key(&operator_pk);
        Self {
            accounts,
            nonces,
            cursor: 0,
            operator,
            operator_pk,
            operator_account,
            avg_vouchers,
            price,
            rng: JitterRng::new(seed),
            height: initial_height,
            reclaims: Vec::new(),
        }
    }

    fn observe_height(&mut self, height: Option<u64>) {
        if let Some(height) = height {
            self.height = self.height.max(height);
        }
    }

    fn payer_pk(&self, payer_i: usize) -> TransactionPublicKey {
        TransactionPublicKey::ed25519(self.accounts[payer_i].public_key.clone())
    }

    /// Reserves the payer's next transaction nonce.
    fn next_nonce(&mut self, payer_i: usize) -> u64 {
        let nonce = self.nonces[payer_i];
        self.nonces[payer_i] += 1;
        nonce
    }

    /// Queues a stranded deposit for a timeout reclaim once `expiry` passes.
    fn queue_reclaim(&mut self, payer_i: usize, open_nonce: u64, expiry: u64) {
        self.reclaims.push(PendingReclaim {
            payer_i,
            open_nonce,
            expiry,
        });
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
        cumulative.saturating_add(extra_vouchers.saturating_mul(self.price))
    }

    /// Runs one lifecycle: open -> stream vouchers off-chain -> close (or, for
    /// a jittered fraction, open -> wait out expiry -> unilateral timeout).
    /// Also retries any reclaims whose expiry has passed.
    pub async fn run_once(&mut self, submitter: &RelayerSubmitter) -> LifecycleStats {
        let mut stats = LifecycleStats {
            channel_txs: 0,
            vouchers: 0,
        };
        self.reclaim_due(submitter, &mut stats).await;

        let n = self.accounts.len();
        let payer_i = self.cursor;
        self.cursor = (self.cursor + 1) % n;

        if self.rng.bernoulli(TIMEOUT_LIFECYCLE_PROBABILITY) {
            self.run_timeout_lifecycle(submitter, payer_i, &mut stats)
                .await;
            return stats;
        }

        let payer_pk = self.payer_pk(payer_i);
        let payer_account = AccountKey::from_public_key(&payer_pk);

        let vouchers = self.next_voucher_count();
        let cumulative = vouchers.saturating_mul(self.price);
        let deposit_value = self.next_deposit(cumulative);
        let Some(deposit) = NonZeroU64::new(deposit_value) else {
            return stats;
        };

        // On-chain: open the channel. The address derives from this nonce, so
        // every open is a fresh, never-recurring channel. The expiry gives the
        // operator plenty of runway; if anything below strands the deposit,
        // the reclaim queue recovers it after this height passes.
        let open_nonce = self.next_nonce(payer_i);
        let expiry = self.height.saturating_add(CHANNEL_EXPIRY_RUNWAY);
        let open = build_open(
            &self.accounts[payer_i],
            &payer_pk,
            &self.operator_pk,
            deposit,
            expiry,
            open_nonce,
        );
        let open_tx_digest = *open.message_digest();
        let (finalized, height) = submitter.submit_reporting_with_height(vec![open]).await;
        self.observe_height(height);
        if finalized == 0 {
            // Open did not finalize; don't close a channel that doesn't exist.
            return stats;
        }
        stats.channel_txs += 1;

        // Off-chain: stream vouchers, verifying each with the shared predicate.
        // These are the payments that never touch the chain.
        let channel = channel_address(&payer_account, &self.operator_account, open_nonce);
        // The open is finalized but the operator's indexer may not have
        // ingested it yet. Retry through transient lag; if registration never
        // lands, queue the deposit for a timeout reclaim.
        let mut registered = false;
        for attempt in 1..=REGISTRATION_ATTEMPTS {
            match self
                .operator
                .register_channel(channel, &payer_pk, open_nonce, &open_tx_digest)
                .await
            {
                Ok(()) => {
                    registered = true;
                    break;
                }
                Err(error) => {
                    warn!(%error, %channel, attempt, "operator channel registration failed");
                    tokio::time::sleep(REGISTRATION_BACKOFF).await;
                }
            }
        }
        if !registered {
            self.queue_reclaim(payer_i, open_nonce, expiry);
            return stats;
        }

        for i in 1..=vouchers {
            let amount = i.saturating_mul(self.price);
            let voucher = Voucher::sign(&self.accounts[payer_i].private_key, channel, amount);
            match self.operator.serve_voucher(&voucher).await {
                Ok(()) => stats.vouchers += 1,
                Err(error) => {
                    warn!(%error, %channel, amount, "operator voucher rejected");
                    break;
                }
            }
        }
        if stats.vouchers == 0 {
            self.queue_reclaim(payer_i, open_nonce, expiry);
            return stats;
        }

        if let Err(error) = self.operator.settle_channel(channel).await {
            warn!(%error, %channel, "operator settlement failed");
            self.queue_reclaim(payer_i, open_nonce, expiry);
            return stats;
        }
        stats.channel_txs += 1;

        stats
    }

    /// Opens a short-expiry channel, skips the operator entirely, and reclaims
    /// the deposit with a unilateral timeout once the expiry passes.
    async fn run_timeout_lifecycle(
        &mut self,
        submitter: &RelayerSubmitter,
        payer_i: usize,
        stats: &mut LifecycleStats,
    ) {
        let payer_pk = self.payer_pk(payer_i);
        let open_nonce = self.next_nonce(payer_i);
        let expiry = self.height.saturating_add(TIMEOUT_EXPIRY_DELTA);
        let deposit = NonZeroU64::new(self.price).expect("price is >= 1");
        let open = build_open(
            &self.accounts[payer_i],
            &payer_pk,
            &self.operator_pk,
            deposit,
            expiry,
            open_nonce,
        );
        let (finalized, height) = submitter.submit_reporting_with_height(vec![open]).await;
        self.observe_height(height);
        if finalized == 0 {
            return;
        }
        stats.channel_txs += 1;

        match self
            .try_reclaim(submitter, payer_i, open_nonce, expiry)
            .await
        {
            ReclaimOutcome::Reclaimed => stats.channel_txs += 1,
            // No close can exist for an unregistered channel, so a definitive
            // rejection here is unexpected; drop rather than retry forever.
            ReclaimOutcome::ChannelGone => {
                warn!(open_nonce, expiry, "timeout-exercise channel vanished");
            }
            ReclaimOutcome::Transient => self.queue_reclaim(payer_i, open_nonce, expiry),
        }
    }

    /// Retries queued reclaims whose expiry has passed (one attempt each).
    async fn reclaim_due(&mut self, submitter: &RelayerSubmitter, stats: &mut LifecycleStats) {
        let height = self.height;
        let (due, pending): (Vec<_>, Vec<_>) = core::mem::take(&mut self.reclaims)
            .into_iter()
            .partition(|reclaim| height > reclaim.expiry);
        self.reclaims = pending;
        for reclaim in due {
            match self
                .try_reclaim(
                    submitter,
                    reclaim.payer_i,
                    reclaim.open_nonce,
                    reclaim.expiry,
                )
                .await
            {
                ReclaimOutcome::Reclaimed => stats.channel_txs += 1,
                ReclaimOutcome::ChannelGone => {
                    // The chain processed the timeout past expiry and skipped
                    // it, so the channel no longer exists — the operator's
                    // close won the race and there is nothing left to reclaim.
                    warn!(
                        open_nonce = reclaim.open_nonce,
                        expiry = reclaim.expiry,
                        "reclaim found no channel; dropping"
                    );
                }
                // A transport failure proves nothing about the channel; keep
                // the deposit queued rather than stranding it.
                ReclaimOutcome::Transient => self.reclaims.push(reclaim),
            }
        }
    }

    /// Submits a `TimeoutChannel` for the channel, resubmitting the same
    /// transaction (same nonce) until it lands, is definitively rejected, or
    /// attempts run out.
    async fn try_reclaim(
        &mut self,
        submitter: &RelayerSubmitter,
        payer_i: usize,
        open_nonce: u64,
        expiry: u64,
    ) -> ReclaimOutcome {
        let payer_pk = self.payer_pk(payer_i);
        let nonce = self.next_nonce(payer_i);
        let timeout =
            Transaction::timeout_channel(payer_pk, self.operator_pk.clone(), open_nonce, nonce)
                .seal_and_sign(
                    &self.accounts[payer_i].private_key,
                    TRANSACTION_NAMESPACE,
                    &mut Sha256::default(),
                );
        for _ in 0..RECLAIM_ATTEMPTS {
            let (finalized, height) = submitter
                .submit_reporting_with_height(vec![timeout.clone()])
                .await;
            self.observe_height(height);
            if finalized > 0 {
                return ReclaimOutcome::Reclaimed;
            }
            // Only a response carrying a finalization height proves the chain
            // actually processed (and skipped) the timeout; a transport error
            // or dropped batch proves nothing about the channel.
            if height.is_some_and(|height| height > expiry) {
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

fn build_open(
    payer: &SpamAccount,
    payer_pk: &TransactionPublicKey,
    receiver_pk: &TransactionPublicKey,
    deposit: NonZeroU64,
    expiry: u64,
    nonce: u64,
) -> Tx {
    Transaction::open_channel(
        payer_pk.clone(),
        receiver_pk.clone(),
        deposit,
        expiry,
        nonce,
    )
    .seal_and_sign(
        &payer.private_key,
        TRANSACTION_NAMESPACE,
        &mut Sha256::default(),
    )
}

#[derive(Clone)]
pub struct OperatorClient {
    url: String,
    http: reqwest::Client,
}

#[derive(serde::Deserialize)]
struct PublicKeyResponse {
    public_key: String,
    #[serde(default)]
    height: u64,
}

#[derive(serde::Serialize)]
struct RegisterRequest {
    channel: String,
    payer: String,
    open_nonce: u64,
    open_tx_digest: String,
}

#[derive(serde::Serialize)]
struct VoucherRequest {
    channel: String,
    cumulative: u64,
    signature: String,
}

#[derive(serde::Serialize)]
struct SettleRequest {
    channel: String,
}

impl OperatorClient {
    pub fn new(url: String) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Fetches the operator's receiver public key plus its latest observed
    /// finalized height (used to seed channel expiry selection).
    pub async fn public_key(&self) -> Result<(TransactionPublicKey, u64), String> {
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
        let bytes = from_hex(&public_key.public_key)
            .ok_or_else(|| "operator public key is not hex".to_string())?;
        let decoded = TransactionPublicKey::decode(bytes.as_slice())
            .map_err(|error| format!("operator public key invalid: {error}"))?;
        Ok((decoded, public_key.height))
    }

    async fn register_channel(
        &self,
        channel: AccountKey,
        payer: &TransactionPublicKey,
        open_nonce: u64,
        open_tx_digest: &<Sha256 as commonware_cryptography::Hasher>::Digest,
    ) -> Result<(), String> {
        self.post_json(
            "/channels",
            &RegisterRequest {
                channel: channel.to_string(),
                payer: hex(&payer.encode()),
                open_nonce,
                open_tx_digest: hex(open_tx_digest.as_ref()),
            },
        )
        .await
    }

    async fn serve_voucher(&self, voucher: &Voucher) -> Result<(), String> {
        self.post_json(
            "/vouchers",
            &VoucherRequest {
                channel: voucher.channel.to_string(),
                cumulative: voucher.cumulative,
                signature: hex(voucher.signature.as_ref()),
            },
        )
        .await
    }

    async fn settle_channel(&self, channel: AccountKey) -> Result<(), String> {
        self.post_json(
            "/settle",
            &SettleRequest {
                channel: channel.to_string(),
            },
        )
        .await
    }

    async fn post_json<T: serde::Serialize>(&self, path: &str, value: &T) -> Result<(), String> {
        let body = serde_json::to_vec(value)
            .map_err(|error| format!("operator request encode failed: {error}"))?;
        let response = self
            .http
            .post(format!("{}{path}", self.url))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|error| format!("operator request failed: {error}"))?;
        if response.status().is_success() {
            return Ok(());
        }
        Err(format!("operator request status {}", response.status()))
    }
}

#[cfg(test)]
mod tests {
    use super::{ChannelRunner, OperatorClient};
    use crate::accounts::generate_accounts;
    use commonware_cryptography::Signer as _;

    fn runner(
        accounts: Vec<crate::accounts::SpamAccount>,
        avg_vouchers: u64,
        price: u64,
        seed: u64,
    ) -> ChannelRunner {
        let operator = OperatorClient::new("http://127.0.0.1:1".to_string());
        let operator_pk = constantinople_primitives::TransactionPublicKey::ed25519(
            commonware_cryptography::ed25519::PrivateKey::from_seed(9).public_key(),
        );
        ChannelRunner::new(
            accounts,
            operator,
            operator_pk,
            avg_vouchers,
            price,
            seed,
            0,
        )
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
