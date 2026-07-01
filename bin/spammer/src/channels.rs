//! Off-chain payment-channel exercise for the spammer.
//!
//! Drives full channel lifecycles against a live node: open a channel on-chain,
//! stream vouchers off-chain (signing as the payer and verifying as the
//! receiver/operator with the same predicate the chain uses at settlement),
//! then settle with a single on-chain close. The close is only submitted after
//! the open finalizes — a close before its open exists would be rejected.
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
use commonware_cryptography::Sha256;
use constantinople_primitives::{
    AccountKey, TRANSACTION_NAMESPACE, Transaction, TransactionPublicKey, Voucher, channel_address,
    verify_voucher,
};
use core::num::NonZeroU64;

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
    avg_vouchers: u64,
    price: u64,
    rng: JitterRng,
}

impl ChannelRunner {
    /// Creates a runner over `accounts` (a ring; needs at least two), streaming
    /// on average `avg_vouchers` vouchers per channel at `price` each. `seed`
    /// seeds the per-channel voucher-count jitter.
    pub fn new(accounts: Vec<SpamAccount>, avg_vouchers: u64, price: u64, seed: u64) -> Self {
        assert!(
            accounts.len() >= 2,
            "channel ring needs at least two accounts"
        );
        assert!(avg_vouchers >= 1, "average vouchers must be >= 1");
        assert!(price >= 1, "voucher price must be >= 1");
        let nonces = vec![0; accounts.len()];
        Self {
            accounts,
            nonces,
            cursor: 0,
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

    /// Runs one lifecycle: open -> stream vouchers off-chain -> close.
    pub async fn run_once(&mut self, submitter: &RelayerSubmitter) -> LifecycleStats {
        let n = self.accounts.len();
        let payer_i = self.cursor;
        let receiver_i = (self.cursor + 1) % n;
        self.cursor = receiver_i;

        let payer_pk = TransactionPublicKey::ed25519(self.accounts[payer_i].public_key.clone());
        let receiver_pk =
            TransactionPublicKey::ed25519(self.accounts[receiver_i].public_key.clone());
        let payer_account = AccountKey::from_public_key(&payer_pk);
        let receiver_account = AccountKey::from_public_key(&receiver_pk);

        let vouchers = self.next_voucher_count();
        let cumulative = vouchers.saturating_mul(self.price);
        let Some(deposit) = NonZeroU64::new(cumulative) else {
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
            &receiver_pk,
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
        let channel = channel_address(&payer_account, &receiver_account, open_nonce);
        let mut served = 0u64;
        let mut latest = None;
        for i in 1..=vouchers {
            let amount = i.saturating_mul(self.price);
            let voucher = Voucher::sign(&self.accounts[payer_i].private_key, channel, amount);
            if verify_voucher(&payer_pk, &channel, amount, &voucher.signature) {
                served += 1;
                latest = Some(voucher.signature);
            }
        }
        let Some(signature) = latest else {
            return LifecycleStats {
                channel_txs: 1,
                vouchers: 0,
            };
        };

        // On-chain: settle the latest voucher (the receiver submits the close).
        let receiver_nonce = self.nonces[receiver_i];
        self.nonces[receiver_i] += 1;
        let close = build_close(
            &self.accounts[receiver_i],
            &receiver_pk,
            &payer_pk,
            open_nonce,
            cumulative,
            signature,
            receiver_nonce,
        );
        // Retry the fixed (same-nonce) close until it settles. The open has
        // finalized, so abandoning here would leak escrow. Each failed attempt
        // is paced by the HTTP round-trip/backoff in the submitter.
        settle_close(submitter, close).await;

        LifecycleStats {
            channel_txs: 2,
            vouchers: served,
        }
    }
}

async fn settle_close(submitter: &RelayerSubmitter, close: Tx) {
    loop {
        if submitter.submit_reporting(vec![close.clone()]).await > 0 {
            return;
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

fn build_close(
    receiver: &SpamAccount,
    receiver_pk: &TransactionPublicKey,
    payer_pk: &TransactionPublicKey,
    open_nonce: u64,
    cumulative: u64,
    voucher: commonware_cryptography::ed25519::Signature,
    nonce: u64,
) -> Tx {
    Transaction::close_channel(
        receiver_pk.clone(),
        payer_pk.clone(),
        open_nonce,
        cumulative,
        voucher,
        nonce,
    )
    .seal_and_sign(
        &receiver.private_key,
        TRANSACTION_NAMESPACE,
        &mut Sha256::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::ChannelRunner;
    use crate::accounts::generate_accounts;

    #[test]
    fn voucher_count_stays_within_jitter_bounds() {
        let accounts = generate_accounts(4, 7_000);
        let mut runner = ChannelRunner::new(accounts, 8, 1, 42);
        for _ in 0..1_000 {
            let v = runner.next_voucher_count();
            // avg=8 -> lo=4, hi=12
            assert!((4..=12).contains(&v), "voucher count {v} out of bounds");
        }
    }

    #[test]
    fn small_average_still_streams_at_least_one() {
        let accounts = generate_accounts(2, 7_100);
        let mut runner = ChannelRunner::new(accounts, 1, 1, 1);
        for _ in 0..100 {
            assert!(runner.next_voucher_count() >= 1);
        }
    }
}
