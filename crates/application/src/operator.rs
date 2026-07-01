//! Off-chain payment-channel operator.
//!
//! This is the off-chain half of a payment channel: the service that accepts streaming
//! micropayments. For each request it receives a voucher — the payer's
//! signature over a monotonically increasing cumulative amount — and verifies
//! it locally, with no on-chain transaction per payment. Periodically (here,
//! once at the end) it submits the latest voucher on-chain to settle.
//!
//! The verification the operator performs uses the exact same
//! [`constantinople_primitives::verify_voucher`] predicate the chain applies at
//! settlement, plus the off-chain-only monotonicity and affordability checks.
//! This is the guarantee that matters: the operator never accepts a voucher the
//! chain would later reject (which would leave it unpaid). See
//! [`constantinople_primitives::Voucher`] for the shared voucher type.

use ahash::AHashMap;
use constantinople_primitives::{AccountKey, TransactionPublicKey, Voucher};

/// Why the operator refused to serve against a voucher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeError {
    /// No channel is registered at the voucher's address.
    UnknownChannel,
    /// The voucher signature did not verify against the payer's key.
    BadSignature,
    /// The cumulative amount does not cover the already-charged total plus the
    /// price of this request (a stale or insufficient voucher).
    Insufficient,
    /// The cumulative amount exceeds the channel's escrowed deposit (an
    /// over-claim the chain would reject).
    Overdraft,
}

/// Per-channel accounting tracked by the operator.
struct ChannelMeter {
    payer: TransactionPublicKey,
    deposit: u64,
    charged: u64,
}

/// A minimal off-chain operator that meters one channel per payer/receiver pair.
pub struct ChannelOperator {
    price: u64,
    channels: AHashMap<AccountKey, ChannelMeter>,
}

impl ChannelOperator {
    /// Creates an operator charging `price` per served request.
    pub fn new(price: u64) -> Self {
        Self {
            price,
            channels: AHashMap::new(),
        }
    }

    /// Registers a channel the operator will accept vouchers against.
    ///
    /// `channel` is the on-chain channel address, `payer` the key whose
    /// vouchers it will verify, and `deposit` the escrow it must never exceed.
    pub fn register_channel(
        &mut self,
        channel: AccountKey,
        payer: TransactionPublicKey,
        deposit: u64,
    ) {
        self.channels.insert(
            channel,
            ChannelMeter {
                payer,
                deposit,
                charged: 0,
            },
        );
    }

    /// Verifies a voucher and serves one request against it.
    ///
    /// On success, advances the channel's charged total to the voucher's
    /// cumulative amount and returns it. Applies exactly the checks the chain
    /// would: a valid payer signature and `cumulative <= deposit`, plus the
    /// off-chain monotonic/affordability rule `cumulative >= charged + price`.
    pub fn serve(&mut self, voucher: &Voucher) -> Result<u64, ServeError> {
        let price = self.price;
        let meter = self
            .channels
            .get_mut(&voucher.channel)
            .ok_or(ServeError::UnknownChannel)?;

        if !voucher.verify(&meter.payer) {
            return Err(ServeError::BadSignature);
        }
        if voucher.cumulative > meter.deposit {
            return Err(ServeError::Overdraft);
        }
        // Saturate: if `charged + price` would overflow `u64`, no voucher
        // (itself <= deposit <= u64::MAX) can reach it, so the request is
        // correctly insufficient — and we avoid a debug panic / release wrap
        // that could accept a stale voucher.
        let required_cumulative = meter.charged.saturating_add(price);
        if voucher.cumulative < required_cumulative {
            return Err(ServeError::Insufficient);
        }

        meter.charged = voucher.cumulative;
        Ok(meter.charged)
    }

    /// Returns the cumulative amount charged against a channel so far.
    pub fn charged(&self, channel: &AccountKey) -> Option<u64> {
        self.channels.get(channel).map(|meter| meter.charged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::FixedSize as _;
    use commonware_cryptography::{Signer as _, ed25519};
    use commonware_math::algebra::Random as _;
    use constantinople_primitives::channel_address;
    use rand::{SeedableRng, rngs::StdRng};

    fn setup() -> (ed25519::PrivateKey, AccountKey, ChannelOperator) {
        let payer = ed25519::PrivateKey::random(&mut StdRng::from_seed([1u8; 32]));
        let payer_key =
            AccountKey::from_public_key(&TransactionPublicKey::ed25519(payer.public_key()));
        let receiver = AccountKey::from([2u8; AccountKey::SIZE]);
        let channel = channel_address(&payer_key, &receiver, 0);

        let mut operator = ChannelOperator::new(5);
        operator.register_channel(
            channel,
            TransactionPublicKey::ed25519(payer.public_key()),
            50,
        );
        (payer, channel, operator)
    }

    #[test]
    fn serves_monotonic_vouchers() {
        let (payer, channel, mut operator) = setup();
        for i in 1..=4u64 {
            let voucher = Voucher::sign(&payer, channel, i * 5);
            assert_eq!(operator.serve(&voucher), Ok(i * 5));
        }
        assert_eq!(operator.charged(&channel), Some(20));
    }

    #[test]
    fn rejects_stale_voucher() {
        let (payer, channel, mut operator) = setup();
        assert_eq!(operator.serve(&Voucher::sign(&payer, channel, 10)), Ok(10));
        // A voucher that does not advance past charged + price is refused.
        assert_eq!(
            operator.serve(&Voucher::sign(&payer, channel, 10)),
            Err(ServeError::Insufficient)
        );
    }

    #[test]
    fn rejects_overdraft_voucher() {
        let (payer, channel, mut operator) = setup();
        assert_eq!(
            operator.serve(&Voucher::sign(&payer, channel, 55)),
            Err(ServeError::Overdraft)
        );
    }

    #[test]
    fn rejects_forged_voucher() {
        let (_payer, channel, mut operator) = setup();
        let attacker = ed25519::PrivateKey::random(&mut StdRng::from_seed([9u8; 32]));
        assert_eq!(
            operator.serve(&Voucher::sign(&attacker, channel, 10)),
            Err(ServeError::BadSignature)
        );
    }

    #[test]
    fn rejects_voucher_when_charge_threshold_overflows() {
        let payer = ed25519::PrivateKey::random(&mut StdRng::from_seed([3u8; 32]));
        let payer_pk = TransactionPublicKey::ed25519(payer.public_key());
        let payer_account = AccountKey::from_public_key(&payer_pk);
        let receiver = AccountKey::from([4u8; AccountKey::SIZE]);
        let channel = channel_address(&payer_account, &receiver, 0);

        let mut operator = ChannelOperator::new(10);
        operator.register_channel(channel, payer_pk, u64::MAX);

        // Charge near the top so the next threshold (charged + price) would
        // overflow `u64`.
        let high = u64::MAX - 5;
        assert_eq!(
            operator.serve(&Voucher::sign(&payer, channel, high)),
            Ok(high)
        );

        // A stale voucher must be refused, and the overflow must not panic
        // (debug) or wrap (release) into accepting it.
        assert_eq!(
            operator.serve(&Voucher::sign(&payer, channel, high)),
            Err(ServeError::Insufficient)
        );
    }
}
