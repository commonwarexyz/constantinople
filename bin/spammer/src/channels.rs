//! Off-chain payment-channel exercise for the spammer.
//!
//! Drives channel-client lifecycles against a live node and operator: open a
//! channel on-chain, register it with the operator, stream vouchers off-chain,
//! then ask the operator to settle with a single on-chain close. The close is
//! owned by the operator so deposit bounds and final cumulative accounting live
//! behind the same service boundary used in testnet.
//!
//! Channels use their own account ring, so their nonces never collide with the
//! transfer presigner's accounts. Each account is a payer once and a receiver
//! once per full cycle, and is visited as receiver immediately before it pays
//! (the cursor advances to the receiver, who becomes the next payer), so a
//! drained account is topped up just before it has to fund an open. Voucher
//! counts are jittered independently, though, so per-account net flow is only
//! roughly zero and balances drift slowly; a drained account simply fails its
//! open (handled gracefully below) rather than ever going negative.

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

/// Outcome of one channel lifecycle.
pub struct LifecycleStats {
    /// On-chain channel transactions that finalized (open + close).
    pub channel_txs: u64,
    /// Off-chain vouchers streamed and verified.
    pub vouchers: u64,
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
}

impl ChannelRunner {
    /// Creates a runner over `accounts` (a ring; needs at least two), streaming
    /// on average `avg_vouchers` vouchers per channel at `price` each. `seed`
    /// seeds the per-channel voucher-count jitter.
    pub fn new(
        accounts: Vec<SpamAccount>,
        operator: OperatorClient,
        operator_pk: TransactionPublicKey,
        avg_vouchers: u64,
        price: u64,
        seed: u64,
    ) -> Self {
        assert!(
            accounts.len() >= 2,
            "channel ring needs at least two accounts"
        );
        assert!(avg_vouchers >= 1, "average vouchers must be >= 1");
        assert!(price >= 1, "voucher price must be >= 1");
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
        }
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

    /// Runs one lifecycle: open -> stream vouchers off-chain -> close.
    pub async fn run_once(&mut self, submitter: &RelayerSubmitter) -> LifecycleStats {
        let n = self.accounts.len();
        let payer_i = self.cursor;
        self.cursor = (self.cursor + 1) % n;

        let payer_pk = TransactionPublicKey::ed25519(self.accounts[payer_i].public_key.clone());
        let payer_account = AccountKey::from_public_key(&payer_pk);

        let vouchers = self.next_voucher_count();
        let cumulative = vouchers.saturating_mul(self.price);
        let deposit_value = self.next_deposit(cumulative);
        let Some(deposit) = NonZeroU64::new(deposit_value) else {
            return LifecycleStats {
                channel_txs: 0,
                vouchers: 0,
            };
        };

        // On-chain: open the channel. The address derives from this nonce, so
        // every open is a fresh, never-recurring channel.
        let open_nonce = self.nonces[payer_i];
        self.nonces[payer_i] += 1;
        let open = build_open(
            &self.accounts[payer_i],
            &payer_pk,
            &self.operator_pk,
            deposit,
            open_nonce,
        );
        if submitter.submit_reporting(vec![open]).await == 0 {
            // Open did not finalize; don't close a channel that doesn't exist.
            return LifecycleStats {
                channel_txs: 0,
                vouchers: 0,
            };
        }

        // Off-chain: stream vouchers, verifying each with the shared predicate.
        // These are the payments that never touch the chain.
        let channel = channel_address(&payer_account, &self.operator_account, open_nonce);
        if let Err(error) = self
            .operator
            .register_channel(channel, &payer_pk, open_nonce, deposit_value)
            .await
        {
            warn!(%error, %channel, "operator channel registration failed");
            return LifecycleStats {
                channel_txs: 1,
                vouchers: 0,
            };
        }

        let mut served = 0u64;
        for i in 1..=vouchers {
            let amount = i.saturating_mul(self.price);
            let voucher = Voucher::sign(&self.accounts[payer_i].private_key, channel, amount);
            match self.operator.serve_voucher(&voucher).await {
                Ok(()) => served += 1,
                Err(error) => {
                    warn!(%error, %channel, amount, "operator voucher rejected");
                    break;
                }
            }
        }
        if served == 0 {
            return LifecycleStats {
                channel_txs: 1,
                vouchers: 0,
            };
        }

        if let Err(error) = self.operator.settle_channel(channel).await {
            warn!(%error, %channel, "operator settlement failed");
            return LifecycleStats {
                channel_txs: 1,
                vouchers: served,
            };
        }

        LifecycleStats {
            channel_txs: 2,
            vouchers: served,
        }
    }
}

fn build_open(
    payer: &SpamAccount,
    payer_pk: &TransactionPublicKey,
    receiver_pk: &TransactionPublicKey,
    deposit: NonZeroU64,
    nonce: u64,
) -> Tx {
    Transaction::open_channel(payer_pk.clone(), receiver_pk.clone(), deposit, nonce).seal_and_sign(
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
}

#[derive(serde::Serialize)]
struct RegisterRequest {
    channel: String,
    payer: String,
    open_nonce: u64,
    deposit: u64,
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

    pub async fn public_key(&self) -> Result<TransactionPublicKey, String> {
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
        TransactionPublicKey::decode(bytes.as_slice())
            .map_err(|error| format!("operator public key invalid: {error}"))
    }

    async fn register_channel(
        &self,
        channel: AccountKey,
        payer: &TransactionPublicKey,
        open_nonce: u64,
        deposit: u64,
    ) -> Result<(), String> {
        self.post_json(
            "/channels",
            &RegisterRequest {
                channel: channel.to_string(),
                payer: hex(&payer.encode()),
                open_nonce,
                deposit,
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
        ChannelRunner::new(accounts, operator, operator_pk, avg_vouchers, price, seed)
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
