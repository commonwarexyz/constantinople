//! The operator's on-chain settlement state machine.
//!
//! `RegisteredChannel` meters vouchers; this module also owns everything
//! around it that used to live only in the operator binary: registration
//! validation, the expiry/runway arithmetic, the operator-nonce window, and
//! the settle/abandon orchestration. It is generic over a [`Clock`] and two
//! narrow I/O traits ([`Relayer`], [`ChainReader`]) so the deterministic
//! runtime can drive a full lifecycle against a real chain in a test, with
//! the binary supplying HTTP adapters in production.

use commonware_cryptography::{Hasher, Sha256, ed25519};
use commonware_runtime::Clock;
use commonware_utils::NZU64;
use constantinople_primitives::{
    AccountKey, CHANNEL_NEVER_EXPIRES, NONCE_BITMAP_CAPACITY, Nonce, SignedTransaction,
    TRANSACTION_NAMESPACE, Transaction, TransactionPublicKey, Voucher, channel_address,
    verify_voucher,
};
use core::num::NonZeroU64;
use futures::lock::Mutex;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tracing::{debug, info, warn};

/// Concrete signed transaction type the operator submits.
pub type Tx = SignedTransaction<Sha256>;
/// Transaction digest type.
pub type Digest = <Sha256 as Hasher>::Digest;

// The service and its HTTP clients share one failure classification; the
// wire-contract home is `operator_api`.
pub use constantinople_primitives::operator_api::OperatorError;

const SUBMIT_ERROR_BACKOFF: Duration = Duration::from_millis(100);
const STARTUP_FETCH_BACKOFF: Duration = Duration::from_millis(500);
const NONCE_WINDOW_BACKOFF: Duration = Duration::from_millis(100);

/// Where a channel stands relative to its expiry under the operator's
/// margins. The single home for the expiry arithmetic (including the
/// [`CHANNEL_NEVER_EXPIRES`] sentinel) so callers cannot drift.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpiryPhase {
    /// Far enough from expiry to serve vouchers.
    Serving,
    /// Within the settle margin: stop serving and settle now.
    Settling,
    /// Past the expiry: the payer may reclaim the escrow at any moment.
    Expired,
}

/// The operator's expiry-safety parameters.
#[derive(Clone, Copy, Debug)]
pub struct Margins {
    /// Minimum blocks of runway a channel must have left at registration.
    pub min_runway: u64,
    /// Blocks before expiry at which vouchers stop and settlement starts.
    pub settle_margin: u64,
}

impl Margins {
    /// Classifies `expiry` against `height` under the settle margin.
    const fn expiry_phase(&self, height: u64, expiry: u64) -> ExpiryPhase {
        if expiry == CHANNEL_NEVER_EXPIRES {
            ExpiryPhase::Serving
        } else if height > expiry {
            ExpiryPhase::Expired
        } else if height.saturating_add(self.settle_margin) >= expiry {
            ExpiryPhase::Settling
        } else {
            ExpiryPhase::Serving
        }
    }

    /// Whether a channel expiring at `expiry` still has the registration
    /// runway required to serve and settle it safely.
    fn has_runway(&self, height: u64, expiry: u64) -> bool {
        let required_runway = self.min_runway.max(self.settle_margin);
        expiry > height.saturating_add(required_runway)
    }
}

/// An `OpenChannel` transaction the chain reader verified as finalized.
#[derive(Clone, Debug)]
pub struct VerifiedOpenChannel {
    /// The payer account that signed and funded the open.
    pub payer: AccountKey,
    /// The receiver (payee) account the channel pays out to.
    pub receiver: AccountKey,
    /// The delegated Ed25519 key that signs this channel's vouchers.
    pub voucher_key: ed25519::PublicKey,
    /// The operator account named in the open (whose key settles the channel).
    pub operator: AccountKey,
    /// The open transaction's nonce (the channel address derives from it).
    pub open_nonce: u64,
    /// The escrowed deposit (non-zero by chain rule, as on
    /// [`constantinople_primitives::Operation::OpenChannel`]).
    pub deposit: NonZeroU64,
    /// Block height after which the payer may reclaim the escrow.
    pub expiry: u64,
    /// Height of the latest certified header the verification ran against;
    /// used to keep expiry checks honest even before the height poller's
    /// first result lands.
    pub tip_height: u64,
}

/// Definitive outcome of one relayer submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// The transaction finalized at `height`.
    Included {
        /// Finalization height.
        height: u64,
    },
    /// The relayer processed the submission to a definitive non-inclusion
    /// (dropped or filtered at proposal).
    Excluded,
}

/// Submits the operator's transactions to the chain.
///
/// `Ok` means the relayer processed the submission to a definitive
/// [`SubmitOutcome`]; `Err` is transport-level and proves nothing about the
/// transaction's fate.
pub trait Relayer {
    /// Submits one signed transaction and reports its outcome.
    fn submit(&self, tx: Tx) -> impl Future<Output = Result<SubmitOutcome, String>>;

    /// Fetches the committed nonce state for `public_key` (`None` if the
    /// account is unwritten).
    fn fetch_nonce(
        &self,
        public_key: &TransactionPublicKey,
    ) -> impl Future<Output = Result<Option<Nonce>, String>>;
}

/// Reads finalized chain state the operator's decisions depend on.
pub trait ChainReader {
    /// Latest finalized height, or `None` before the first block.
    fn latest_height(&self) -> impl Future<Output = Result<Option<u64>, String>>;

    /// Verifies that `digest` is a finalized `OpenChannel` transaction and
    /// returns its contents. `Unavailable` covers lookups the reader could
    /// not complete (including a not-yet-ingested open); `Rejected` means the
    /// digest does not name a valid open.
    fn verify_open_channel(
        &self,
        digest: &Digest,
    ) -> impl Future<Output = Result<VerifiedOpenChannel, OperatorError>>;

    /// Whether `digest` has been observed finalized.
    fn is_finalized(&self, digest: &Digest) -> impl Future<Output = Result<bool, String>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SettlementState {
    Open,
    Settling,
    Settled,
    /// The close could not finalize before the payer reclaimed the channel;
    /// its vouchers are forfeited.
    Abandoned,
}

/// Why the operator refused to serve against a voucher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeError {
    /// The voucher signature did not verify against the payer's key.
    BadSignature,
    /// The cumulative is lower than the latest accepted voucher.
    Stale,
    /// The cumulative amount exceeds the channel's escrowed deposit (an
    /// over-claim the chain would reject).
    Overdraft,
}

/// A channel's stream meter at the moment of a consume decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeterSnapshot {
    /// Stream tokens delivered against the channel so far.
    pub served: u64,
    /// Cumulative amount the channel's latest voucher has paid for.
    pub paid: u64,
}

/// Outcome of metering one stream chunk against a channel's credit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumeOutcome {
    /// The chunk was paid for (within the debt limit); the meter advanced.
    Served(MeterSnapshot),
    /// Serving would exceed the caller's content limit; the meter did not
    /// advance.
    ContentExhausted(MeterSnapshot),
    /// Serving would exceed the debt limit; a fresher voucher unblocks it.
    PaymentRequired(MeterSnapshot),
    /// Serving would exceed the deposit; no voucher can unblock it.
    DepositExhausted(MeterSnapshot),
}

/// A verified channel the operator serves vouchers against: the registration
/// metadata plus the per-channel meter (the latest-voucher accounting).
pub(crate) struct RegisteredChannel {
    /// The payer account the close refunds the escrow remainder to.
    payer: AccountKey,
    /// The delegated key this channel's vouchers verify against.
    voucher_key: ed25519::PublicKey,
    /// The receiver (payee) account the settled cumulative is paid to.
    receiver: AccountKey,
    open_nonce: u64,
    /// The escrowed deposit the served cumulative must never exceed.
    deposit: NonZeroU64,
    /// Block height after which the payer may reclaim the escrow.
    expiry: u64,
    /// Stream tokens delivered against this channel (the metered-content
    /// side of the accounting; vouchers pay it down). In-memory only, like
    /// the voucher state.
    served: u64,
    /// The latest accepted voucher. Never absent: registration requires an
    /// initial zero-value voucher, so every registered channel is closeable
    /// — including one that never pays.
    latest: Voucher,
    settlement: SettlementState,
}

impl RegisteredChannel {
    /// A freshly registered channel: nothing served, the initial (zero)
    /// voucher as its starting settlement, nothing settled.
    pub(crate) fn new(open: &VerifiedOpenChannel, initial: Voucher) -> Self {
        Self {
            payer: open.payer,
            voucher_key: open.voucher_key.clone(),
            receiver: open.receiver,
            open_nonce: open.open_nonce,
            deposit: open.deposit,
            expiry: open.expiry,
            served: 0,
            latest: initial,
            settlement: SettlementState::Open,
        }
    }

    /// Test convenience for metering without a content bound.
    #[cfg(test)]
    pub(crate) const fn consume(&mut self, cost: u64, debt_limit: u64) -> ConsumeOutcome {
        self.consume_bounded(cost, debt_limit, u64::MAX)
    }

    /// Meters `cost` stream tokens without allowing the served total to
    /// exceed `max_served`.
    ///
    /// Serving is allowed while the served total stays within `debt_limit`
    /// of the paid cumulative (the latest voucher), below `max_served`, and
    /// within the deposit. Refusals do not advance the meter, so a `cost` of
    /// zero is a free probe of the channel's credit.
    pub(crate) const fn consume_bounded(
        &mut self,
        cost: u64,
        debt_limit: u64,
        max_served: u64,
    ) -> ConsumeOutcome {
        let paid = self.latest.cumulative;
        let next = self.served.saturating_add(cost);
        if next > max_served {
            return ConsumeOutcome::ContentExhausted(MeterSnapshot {
                served: self.served,
                paid,
            });
        }
        if next > self.deposit.get() {
            return ConsumeOutcome::DepositExhausted(MeterSnapshot {
                served: self.served,
                paid,
            });
        }
        if next > paid.saturating_add(debt_limit) {
            return ConsumeOutcome::PaymentRequired(MeterSnapshot {
                served: self.served,
                paid,
            });
        }
        self.served = next;
        ConsumeOutcome::Served(MeterSnapshot { served: next, paid })
    }

    /// Verifies a voucher and serves one request against it.
    ///
    /// On success, stores the voucher as the channel's latest and returns
    /// the accepted cumulative. Applies exactly the checks the chain would:
    /// a valid voucher-key signature and `cumulative <= deposit`, plus the
    /// off-chain-only monotonicity rule that the cumulative strictly exceeds
    /// the latest accepted one (a replayed/stale voucher buys nothing).
    pub(crate) fn serve(&mut self, voucher: Voucher) -> Result<u64, ServeError> {
        if !verify_voucher(
            &self.voucher_key,
            &voucher.channel,
            voucher.cumulative,
            &voucher.signature,
        ) {
            return Err(ServeError::BadSignature);
        }
        if voucher.cumulative > self.deposit.get() {
            return Err(ServeError::Overdraft);
        }
        if voucher.cumulative < self.latest.cumulative {
            return Err(ServeError::Stale);
        }

        // Posting a voucher is idempotent: the client may retry after the
        // operator accepted it but its HTTP acknowledgement was lost. The
        // signature was verified above, so an equal cumulative authorizes
        // exactly the claim already retained.
        if voucher.cumulative == self.latest.cumulative {
            return Ok(voucher.cumulative);
        }

        let cumulative = voucher.cumulative;
        self.latest = voucher;
        Ok(cumulative)
    }
}

struct OperatorState {
    /// Next operator transaction nonce to reserve for a close.
    nonce: u64,
    /// Close nonces reserved but not yet finalized. Reservation is windowed
    /// against the smallest entry so a fast-finalizing close can never jump the
    /// operator's nonce base past a still-pending lower nonce (which would
    /// permanently wedge that settlement).
    inflight: BTreeSet<u64>,
    /// Whether the chain's nonce base is known to have caught up to
    /// [`Self::nonce`]. False after recovering from a dirty (mid-settlement
    /// crash) bitmap; the first close then settles alone so its jump lands
    /// before anything runs ahead of it.
    aligned: bool,
    channels: BTreeMap<AccountKey, RegisteredChannel>,
    /// Vouchers accepted over the service's lifetime — the off-chain payment
    /// count the chain never sees, surfaced via [`OperatorService::stats`].
    vouchers_served: u64,
    /// Streamed content delivered over the service's lifetime (all
    /// channels), denominated in chain units — identical to a token count
    /// while the advertised price per token is 1.
    tokens_streamed: u64,
    /// Channels handed to a settle task by [`OperatorService::due_settlements`]
    /// whose settlement has not yet moved past `Open` (a settle task can wait
    /// on the nonce window with the channel still `Open`); tracked so a sweep
    /// never hands out the same channel twice.
    sweep_claimed: BTreeSet<AccountKey>,
}

impl OperatorState {
    /// Fresh state: no channels, no in-flight nonces, no served vouchers.
    const fn new(nonce: u64, aligned: bool) -> Self {
        Self {
            nonce,
            inflight: BTreeSet::new(),
            aligned,
            channels: BTreeMap::new(),
            vouchers_served: 0,
            tokens_streamed: 0,
            sweep_claimed: BTreeSet::new(),
        }
    }

    /// Registers an already-verified channel, idempotently.
    ///
    /// Returns whether the channel was newly inserted. A replayed
    /// registration with matching metadata is a no-op (crucially, it must not
    /// reset the voucher accounting); mismatched metadata is an error.
    fn register_verified_channel(
        &mut self,
        channel: AccountKey,
        registration: RegisteredChannel,
    ) -> Result<bool, OperatorError> {
        if let Some(registered) = self.channels.get(&channel) {
            if registered.payer != registration.payer
                || registered.voucher_key != registration.voucher_key
                || registered.open_nonce != registration.open_nonce
                || registered.receiver != registration.receiver
                || registered.deposit != registration.deposit
                || registered.expiry != registration.expiry
            {
                return Err(OperatorError::rejected(
                    "channel already registered with different metadata",
                ));
            }
            return Ok(false);
        }

        self.channels.insert(channel, registration);
        Ok(true)
    }
}

/// Reserves the next operator transaction nonce if the in-flight window
/// allows it.
///
/// A transaction may reserve a nonce at most [`NONCE_BITMAP_CAPACITY`]
/// ahead of the oldest unfinalized one. Beyond that, the chain would
/// consume it as a far jump that clears the run-ahead bitmap and strands
/// every pending lower nonce. Callers that receive `None` wait
/// [`NONCE_WINDOW_BACKOFF`] and retry.
///
/// Takes the [`OperatorState`] fields it needs individually (rather than
/// `&mut OperatorState`) so a caller can reserve while holding a borrow of
/// another field, e.g. a `channels` entry.
fn try_reserve_nonce(nonce: &mut u64, inflight: &mut BTreeSet<u64>, aligned: bool) -> Option<u64> {
    let can_reserve = match inflight.first() {
        None => true,
        Some(&oldest) => aligned && *nonce - oldest <= NONCE_BITMAP_CAPACITY,
    };
    if !can_reserve {
        return None;
    }
    let reserved = *nonce;
    *nonce = nonce.saturating_add(1);
    inflight.insert(reserved);
    Some(reserved)
}

/// Looks up a channel and applies the gates every serving path shares: the
/// channel must be registered, its settlement must not have started (work
/// served after the close is built will never be paid for), and its expiry
/// must be far enough away that what is served can still settle safely.
///
/// A free function over the channels map (rather than a method) so callers
/// can keep borrowing the rest of [`OperatorState`] alongside the returned
/// channel.
fn servable_channel<'a>(
    margins: Margins,
    height: u64,
    channels: &'a mut BTreeMap<AccountKey, RegisteredChannel>,
    channel: &AccountKey,
) -> Result<&'a mut RegisteredChannel, OperatorError> {
    let Some(registered) = channels.get_mut(channel) else {
        return Err(OperatorError::rejected("channel metadata missing"));
    };
    if registered.settlement != SettlementState::Open {
        return Err(OperatorError::rejected(
            "channel settlement already started",
        ));
    }
    if margins.expiry_phase(height, registered.expiry) != ExpiryPhase::Serving {
        return Err(OperatorError::rejected("channel is about to expire"));
    }
    Ok(registered)
}

/// Outcome of settling one channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettleOutcome {
    /// Whether the close finalized (false: abandoned, vouchers forfeited).
    pub settled: bool,
    /// The cumulative amount the settlement covered.
    pub cumulative: u64,
}

/// A snapshot of the operator's lifetime counters, for observability (the
/// off-chain voucher count is the one number the chain cannot report).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperatorStats {
    /// Channels registered (lifetime; settled and abandoned ones included).
    pub channels: u64,
    /// Channels whose close finalized.
    pub settled: u64,
    /// Channels whose close was abandoned (vouchers forfeited).
    pub abandoned: u64,
    /// Vouchers accepted off-chain.
    pub vouchers: u64,
    /// Stream tokens delivered (all channels, lifetime).
    pub streamed: u64,
}

/// The operator's settlement service: voucher metering plus everything needed
/// to turn accepted vouchers into finalized closes.
pub struct OperatorService<E, R, C> {
    context: E,
    relayer: R,
    chain: C,
    operator: ed25519::PrivateKey,
    operator_pk: TransactionPublicKey,
    operator_account: AccountKey,
    margins: Margins,
    /// Latest finalized height observed; all expiry decisions read this
    /// cache. Refreshed by [`Self::refresh_height`] and seeded by every
    /// registration's certified-header verification.
    height: AtomicU64,
    state: Mutex<OperatorState>,
}

impl<E, R, C> OperatorService<E, R, C>
where
    E: Clock,
    R: Relayer,
    C: ChainReader,
{
    /// Builds the service, recovering the operator's next transaction nonce
    /// from committed chain state.
    ///
    /// The nonce cannot start at zero: after any prior settlement a fresh
    /// process would reuse a consumed nonce, the close would never finalize,
    /// and every settlement would wedge behind it. Retries until the relayer
    /// answers — the operator cannot safely guess. A clean state (empty
    /// run-ahead bitmap) resumes at the base. A dirty bitmap (crash
    /// mid-settlement) resumes one past the run-ahead window, so the first
    /// close jump-clears the leftovers; that close settles alone
    /// (`aligned = false`) so the jump lands before later closes run ahead of
    /// it.
    pub async fn init(
        context: E,
        relayer: R,
        chain: C,
        operator: ed25519::PrivateKey,
        margins: Margins,
    ) -> Self {
        use commonware_cryptography::Signer as _;
        let operator_pk = TransactionPublicKey::ed25519(operator.public_key());
        let operator_account = AccountKey::from_public_key(&operator_pk);

        // Known hazard: `fetch_nonce` reads committed (not finalized)
        // validator state, so a restart in the narrow window after a
        // settlement finalizes but before it commits can recover a stale base
        // with a clean bitmap and resume on a consumed nonce. Closing that
        // window needs a finalized-state read or a durable local nonce store;
        // until then the consumed-nonce checks in the submit path abandon
        // such a settlement instead of wedging on it — misreported (the
        // channel stays open on chain, closeable with a fresh nonce), but
        // never blocking later settlements.
        let (nonce, aligned) = loop {
            match relayer.fetch_nonce(&operator_pk).await {
                Ok(None) => break (0, true),
                Ok(Some(nonce)) if nonce.bitmap == 0 => break (nonce.base, true),
                Ok(Some(nonce)) => {
                    break (nonce.base.saturating_add(NONCE_BITMAP_CAPACITY + 1), false);
                }
                Err(error) => {
                    warn!(%error, "operator account lookup failed, retrying");
                    context.sleep(STARTUP_FETCH_BACKOFF).await;
                }
            }
        };
        info!(nonce, aligned, "recovered operator nonce from chain");

        Self {
            context,
            relayer,
            chain,
            operator,
            operator_pk,
            operator_account,
            margins,
            height: AtomicU64::new(0),
            state: Mutex::new(OperatorState::new(nonce, aligned)),
        }
    }

    /// The operator key channels must name to be settled by this service.
    pub const fn operator_public_key(&self) -> &TransactionPublicKey {
        &self.operator_pk
    }

    /// The operator's account key.
    pub const fn operator_account(&self) -> &AccountKey {
        &self.operator_account
    }

    /// The expiry-safety margins the service enforces (advertised to clients
    /// so they can derive channel expiries from the real configuration).
    pub const fn margins(&self) -> Margins {
        self.margins
    }

    /// Latest finalized height the service has observed (0 until the first
    /// refresh or registration lands).
    pub fn height(&self) -> u64 {
        self.height.load(Ordering::Relaxed)
    }

    /// Polls the chain once and advances the height cache.
    pub async fn refresh_height(&self) -> Result<(), String> {
        if let Some(height) = self.chain.latest_height().await? {
            self.height.fetch_max(height, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Verifies and registers a channel opened to this operator.
    ///
    /// The registration names only the open transaction and the channel's
    /// initial zero-value voucher; everything else — the payer, receiver,
    /// voucher key, and the channel address itself — is derived from the
    /// verified open, so the request carries nothing a client could assert
    /// incorrectly. The zero voucher must verify against the open's voucher
    /// key: it proves the registrant holds that key and becomes the
    /// channel's starting voucher, so every registered channel is closeable.
    ///
    /// Returns the channel address and whether it was newly inserted: a
    /// matching replay is `Ok((_, false))`, a replay with mismatched
    /// metadata is an error. A replay re-verifies the open against the
    /// chain (the indexer has necessarily ingested it, though a transport
    /// blip can still answer a retryable unavailable) and skips the runway
    /// gate, so a lost registration response stays recoverable even after
    /// the height drifts inside the margin.
    pub async fn register_channel(
        &self,
        open_tx_digest: &Digest,
        zero_voucher: ed25519::Signature,
    ) -> Result<(AccountKey, bool), OperatorError> {
        let open = self.chain.verify_open_channel(open_tx_digest).await?;
        if open.operator != self.operator_account {
            return Err(OperatorError::rejected(
                "open transaction names a different operator",
            ));
        }
        // The verification above ran against a certified header, so its
        // height also seeds the cache — the runway check below cannot be
        // fooled by a cache still at zero right after startup.
        self.height.fetch_max(open.tip_height, Ordering::Relaxed);

        let channel = channel_address(
            &open.payer,
            &open.receiver,
            &self.operator_account,
            &open.voucher_key,
            open.open_nonce,
        );
        let initial = Voucher {
            channel,
            cumulative: 0,
            signature: zero_voucher,
        };
        if !verify_voucher(&open.voucher_key, &channel, 0, &initial.signature) {
            return Err(OperatorError::rejected(
                "initial zero voucher does not verify against the channel's voucher key",
            ));
        }

        let mut state = self.state.lock().await;
        // Runway gates NEW registrations only, and is checked after the
        // replay lookup: a client whose successful registration's response
        // was lost may retry after the height drifted inside the margin, and
        // that replay must stay idempotent — the operator already committed
        // to serving and settling this channel.
        if !state.channels.contains_key(&channel) {
            // Past the expiry the payer can reclaim the whole escrow,
            // voiding any unsettled vouchers; refuse channels without
            // enough runway to serve and settle safely.
            let height = self.height();
            if !self.margins.has_runway(height, open.expiry) {
                return Err(OperatorError::rejected("channel expires too soon"));
            }
        }
        let inserted =
            state.register_verified_channel(channel, RegisteredChannel::new(&open, initial))?;
        if inserted {
            debug!(%channel, deposit = open.deposit.get(), "registered channel");
        } else {
            debug!(%channel, "channel registration replayed");
        }
        Ok((channel, inserted))
    }

    /// Verifies a voucher and serves one request against it, returning the
    /// accepted cumulative.
    pub async fn serve_voucher(&self, voucher: Voucher) -> Result<u64, OperatorError> {
        let height = self.height();
        let mut guard = self.state.lock().await;
        let state = &mut *guard;
        let registered =
            servable_channel(self.margins, height, &mut state.channels, &voucher.channel)?;
        let replayed = voucher.cumulative == registered.latest.cumulative;
        let cumulative = registered
            .serve(voucher)
            .map_err(|error| OperatorError::rejected(format!("voucher rejected: {error:?}")))?;
        if !replayed {
            state.vouchers_served += 1;
        }
        Ok(cumulative)
    }

    /// Meters `cost` stream tokens against a channel's credit, returning the
    /// meter after the decision.
    ///
    /// Applies the same gates as voucher serving — the channel must be
    /// registered, its settlement not started, and its expiry far enough
    /// away — then the credit policy documented on the channel-level
    /// `RegisteredChannel::consume_bounded`. Terminal channel states are errors;
    /// running out of credit is a [`ConsumeOutcome`], not an error, because
    /// the caller's next move differs (wait for a voucher vs. give up).
    pub async fn consume(
        &self,
        channel: &AccountKey,
        cost: u64,
        debt_limit: u64,
    ) -> Result<ConsumeOutcome, OperatorError> {
        self.consume_bounded(channel, cost, debt_limit, u64::MAX)
            .await
    }

    /// Meters `cost` stream tokens while atomically enforcing a maximum
    /// served total supplied by the content provider.
    ///
    /// The content bound is checked under the same state lock that advances
    /// the meter, so concurrent streams cannot reserve the same final chunk.
    pub async fn consume_bounded(
        &self,
        channel: &AccountKey,
        cost: u64,
        debt_limit: u64,
        max_served: u64,
    ) -> Result<ConsumeOutcome, OperatorError> {
        let height = self.height();
        let mut guard = self.state.lock().await;
        let state = &mut *guard;
        let registered = servable_channel(self.margins, height, &mut state.channels, channel)?;
        let outcome = registered.consume_bounded(cost, debt_limit, max_served);
        if matches!(outcome, ConsumeOutcome::Served(_)) {
            state.tokens_streamed = state.tokens_streamed.saturating_add(cost);
        }
        Ok(outcome)
    }

    /// A snapshot of the service's lifetime counters.
    pub async fn stats(&self) -> OperatorStats {
        let state = self.state.lock().await;
        let mut settled = 0;
        let mut abandoned = 0;
        for registered in state.channels.values() {
            match registered.settlement {
                SettlementState::Settled => settled += 1,
                SettlementState::Abandoned => abandoned += 1,
                SettlementState::Open | SettlementState::Settling => {}
            }
        }
        OperatorStats {
            channels: state.channels.len() as u64,
            settled,
            abandoned,
            vouchers: state.vouchers_served,
            streamed: state.tokens_streamed,
        }
    }

    /// Channels whose expiry is near enough that settlement must start now
    /// (every registered channel is voucher-bearing: registration installed
    /// the initial zero voucher). Each channel is returned once: the service
    /// remembers what it has handed out until that settlement moves past
    /// `Open`.
    ///
    /// An operator that misses a channel's expiry forfeits its receiver's
    /// vouchers (the payer reclaims the whole escrow), so settlement cannot
    /// wait for the payer to ask.
    pub async fn due_settlements(&self) -> Vec<AccountKey> {
        let height = self.height();
        let mut guard = self.state.lock().await;
        let OperatorState {
            channels,
            sweep_claimed,
            ..
        } = &mut *guard;
        // A claim outlives `Open` only until the settle task resolves it; a
        // task parked on the nonce window keeps the channel `Open`, so the
        // claim is what stops the next sweep from spawning a duplicate.
        sweep_claimed.retain(|channel| {
            channels
                .get(channel)
                .is_some_and(|registered| registered.settlement == SettlementState::Open)
        });
        let due: Vec<AccountKey> = channels
            .iter()
            .filter(|(channel, registered)| {
                registered.settlement == SettlementState::Open
                    && self.margins.expiry_phase(height, registered.expiry) != ExpiryPhase::Serving
                    && !sweep_claimed.contains(channel)
            })
            .map(|(channel, _)| *channel)
            .collect();
        sweep_claimed.extend(due.iter().copied());
        due
    }

    /// Settles a registered channel's latest voucher on chain.
    ///
    /// Callable concurrently (by a settle request and the expiry sweep): the
    /// first caller drives the settlement, later callers block until it
    /// resolves, and every caller gets the same definitive outcome.
    ///
    /// Not cancellation-safe: the driving caller marks the channel `Settling`
    /// and reserves a nonce before awaiting chain work, and only the final
    /// state update releases them. Dropping the future mid-flight strands the
    /// channel in `Settling` (nothing retries it) and leaks the nonce from
    /// the in-flight window. Drive it from an owned task, not directly from a
    /// cancellable request handler.
    pub async fn settle_channel(
        &self,
        channel: AccountKey,
    ) -> Result<SettleOutcome, OperatorError> {
        let (payer, receiver, voucher_key, open_nonce, expiry, latest, nonce) = loop {
            {
                let mut guard = self.state.lock().await;
                // Split the borrow so the nonce reservation below can run
                // while `registered` still borrows `channels` (the same shape
                // as `due_settlements`).
                let OperatorState {
                    nonce: next_nonce,
                    inflight,
                    aligned,
                    channels,
                    ..
                } = &mut *guard;
                let Some(registered) = channels.get_mut(&channel) else {
                    return Err(OperatorError::rejected("unknown channel"));
                };
                match registered.settlement {
                    SettlementState::Settled | SettlementState::Abandoned => {
                        let cumulative = registered.latest.cumulative;
                        return Ok(SettleOutcome {
                            settled: registered.settlement == SettlementState::Settled,
                            cumulative,
                        });
                    }
                    // Another task (the sweep or a concurrent request) is
                    // mid-settlement; wait for its definitive outcome. An
                    // immediate `settled: false` here would be
                    // indistinguishable from an abandonment.
                    SettlementState::Settling => {}
                    SettlementState::Open => {
                        if let Some(nonce) = try_reserve_nonce(next_nonce, inflight, *aligned) {
                            registered.settlement = SettlementState::Settling;
                            break (
                                registered.payer,
                                registered.receiver,
                                registered.voucher_key.clone(),
                                registered.open_nonce,
                                registered.expiry,
                                registered.latest.clone(),
                                nonce,
                            );
                        }
                        // The nonce window is full; wait below for an
                        // in-flight transaction to finalize.
                    }
                }
            }
            self.context.sleep(NONCE_WINDOW_BACKOFF).await;
        };

        // Build and sign the close outside the lock: only the nonce
        // reservation and settlement flag above need mutual exclusion.
        let cumulative = latest.cumulative;
        let close = Transaction::close_channel(
            self.operator_pk.clone(),
            payer,
            receiver,
            voucher_key,
            open_nonce,
            cumulative,
            latest.signature,
            nonce,
        )
        .seal_and_sign(
            &self.operator,
            TRANSACTION_NAMESPACE,
            &mut Sha256::default(),
        );
        let close_digest = *close.message_digest();
        let mut finalized = self.submit_tx(close, nonce, expiry, "close").await;
        if !finalized {
            // Giving up does not mean the close is dead: an earlier
            // submission may still be queued at a validator and finalize
            // later. Race a same-nonce burn against it — exactly one of the
            // two can consume the reserved nonce — so the in-flight window's
            // invariant (every nonce below the oldest in-flight one is
            // consumed) stays true whichever wins. A minimal mint is the
            // ideal burn: valid regardless of the operator's balance.
            warn!(%channel, "close did not finalize before expiry; racing a nonce burn against it");
            let burn = Transaction::mint(self.operator_pk.clone(), NZU64!(1), nonce).seal_and_sign(
                &self.operator,
                TRANSACTION_NAMESPACE,
                &mut Sha256::default(),
            );
            finalized = self
                .resolve_abandoned_close(burn, nonce, &close_digest)
                .await;
        }

        let mut guard = self.state.lock().await;
        let state = &mut *guard;
        state.inflight.remove(&nonce);
        // Either the close or its burn consumed the nonce on chain, so the
        // chain's nonce base has caught up past any startup jump; later
        // closes may run ahead again.
        state.aligned = true;
        if let Some(registered) = state.channels.get_mut(&channel) {
            registered.settlement = if finalized {
                SettlementState::Settled
            } else {
                SettlementState::Abandoned
            };
        }
        Ok(SettleOutcome {
            settled: finalized,
            cumulative,
        })
    }

    /// Submits an operator transaction until it finalizes, or gives up once
    /// the chain is past `expiry` (pass [`CHANNEL_NEVER_EXPIRES`] to retry
    /// until inclusion or an observed finalization).
    ///
    /// The expiry gate exists for closes: a close stays valid on-chain at any
    /// height while the channel exists, so giving up requires more than the
    /// clock — the relayer must have processed a submission to a definitive
    /// non-inclusion (the proposer filtered the close, which past expiry
    /// means the channel is likely reclaimed). A transport error proves
    /// nothing and always retries — abandoning on it would forfeit vouchers a
    /// live channel could still settle. `what` labels the transaction in
    /// logs.
    ///
    /// A definitive exclusion is also how a lost acknowledgement looks: the
    /// first submission finalized and consumed the nonce, so every retry is
    /// filtered as a duplicate. Each exclusion therefore consults the chain
    /// before retrying — without that check a never-expiring channel's close
    /// would loop forever, pinning its nonce in the in-flight window until
    /// every settlement wedged.
    ///
    /// An exclusion with the nonce consumed but the digest unseen means a
    /// *different* transaction from the operator account owns the nonce (the
    /// stale-recovery hazard documented on [`Self::init`]): this transaction
    /// can never land, at any height, so the submission gives up regardless
    /// of expiry.
    ///
    /// Returns whether the transaction finalized.
    async fn submit_tx(&self, tx: Tx, nonce: u64, expiry: u64, what: &'static str) -> bool {
        let digest = *tx.message_digest();
        loop {
            let definitive = match self.relayer.submit(tx.clone()).await {
                Ok(SubmitOutcome::Included { height }) => {
                    debug!(height, what, "operator transaction finalized");
                    return true;
                }
                Ok(SubmitOutcome::Excluded) => {
                    warn!(what, "operator transaction not finalized, retrying");
                    true
                }
                Err(error) => {
                    warn!(%error, what, "operator transaction submit failed, retrying");
                    false
                }
            };
            if definitive {
                if self.observed_finalized(&digest, what).await {
                    info!(
                        what,
                        "operator transaction finalized (acknowledgement was lost)"
                    );
                    return true;
                }
                // Consumption is checked before the digest re-check:
                // consumed nonces stay consumed, so a digest still unseen
                // *afterwards* proves the consumer was someone else (up to
                // the chain reader lagging the committed nonce state, the
                // same accepted hazard as recovery itself).
                if self.nonce_consumed(nonce).await {
                    if self.observed_finalized(&digest, what).await {
                        return true;
                    }
                    warn!(
                        what,
                        nonce, "nonce consumed by a different operator transaction; giving up"
                    );
                    return false;
                }
                if self.margins.expiry_phase(self.height(), expiry) == ExpiryPhase::Expired {
                    return false;
                }
            }
            self.context.sleep(SUBMIT_ERROR_BACKOFF).await;
        }
    }

    /// Resolves an abandoned close by racing a same-nonce burn against it.
    ///
    /// The close may still finalize after [`Self::submit_tx`] gives up (a
    /// submission can sit in a validator mempool through a transport error),
    /// and the burn is signed with the same nonce, so exactly one of the two
    /// can ever consume it. Submits the burn until either transaction is
    /// observed finalized: the burn landing abandons the settlement, the
    /// close landing completes it. Without this check a blind burn retry
    /// would spin forever once the close won the race, pinning the nonce in
    /// the in-flight set and wedging all settlements.
    ///
    /// A third outcome ends the race too: the nonce is consumed but neither
    /// digest ever finalizes, meaning a different transaction from the
    /// operator account owns it (the stale-recovery hazard documented on
    /// [`Self::init`]). Neither the close nor the burn can land then, so the
    /// settlement is abandoned.
    ///
    /// Returns whether the close finalized.
    async fn resolve_abandoned_close(&self, burn: Tx, nonce: u64, close_digest: &Digest) -> bool {
        let burn_digest = *burn.message_digest();
        loop {
            match self.relayer.submit(burn.clone()).await {
                Ok(SubmitOutcome::Included { height }) => {
                    debug!(height, "abandoned close's nonce burned");
                    return false;
                }
                Ok(SubmitOutcome::Excluded) => {
                    warn!("nonce burn not finalized, retrying");
                }
                Err(error) => {
                    warn!(%error, "nonce burn submit failed, retrying");
                }
            }
            // The burn stays filtered while the close still owns the nonce
            // (and a finalized burn's acknowledgement can itself be lost to a
            // transport error), so consult the chain for whichever actually
            // landed.
            if self.observed_finalized(close_digest, "close").await {
                info!("abandoned close finalized after all; settlement complete");
                return true;
            }
            if self.observed_finalized(&burn_digest, "burn").await {
                debug!("abandoned close's nonce burned");
                return false;
            }
            // Consumption is checked after both digests missed, and the
            // close is re-checked after it: consumed nonces stay consumed,
            // so a digest still unseen afterwards proves the consumer was a
            // different operator transaction.
            if self.nonce_consumed(nonce).await {
                if self.observed_finalized(close_digest, "close").await {
                    return true;
                }
                warn!(
                    nonce,
                    "nonce consumed by a different operator transaction; abandoning settlement"
                );
                return false;
            }
            self.context.sleep(SUBMIT_ERROR_BACKOFF).await;
        }
    }

    /// Whether the chain has observed `digest` finalized. Lookup errors are
    /// logged and read as "not yet" — the caller retries.
    async fn observed_finalized(&self, digest: &Digest, what: &'static str) -> bool {
        match self.chain.is_finalized(digest).await {
            Ok(observed) => observed,
            Err(error) => {
                warn!(%error, what, "finalization lookup failed; treating as not yet finalized");
                false
            }
        }
    }

    /// Whether the operator account's committed nonce state records `nonce`
    /// as consumed (below the base, or set in the run-ahead bitmap). Lookup
    /// errors are logged and read as "not consumed" — the caller retries.
    async fn nonce_consumed(&self, nonce: u64) -> bool {
        match self.relayer.fetch_nonce(&self.operator_pk).await {
            Ok(state) => state.is_some_and(|state| state.is_consumed(nonce)),
            Err(error) => {
                warn!(%error, "nonce lookup failed; treating the nonce as not consumed");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::FixedSize as _;
    use commonware_cryptography::Signer as _;
    use commonware_runtime::{Runner as _, deterministic};
    use futures::future::join_all;

    #[derive(Clone, Copy)]
    struct UnusedIo;

    impl Relayer for UnusedIo {
        async fn submit(&self, _tx: Tx) -> Result<SubmitOutcome, String> {
            unreachable!("metering does not submit transactions")
        }

        async fn fetch_nonce(
            &self,
            _public_key: &TransactionPublicKey,
        ) -> Result<Option<Nonce>, String> {
            Ok(None)
        }
    }

    impl ChainReader for UnusedIo {
        async fn latest_height(&self) -> Result<Option<u64>, String> {
            Ok(None)
        }

        async fn verify_open_channel(
            &self,
            _digest: &Digest,
        ) -> Result<VerifiedOpenChannel, OperatorError> {
            unreachable!("metering does not verify channel opens")
        }

        async fn is_finalized(&self, _digest: &Digest) -> Result<bool, String> {
            unreachable!("metering does not inspect finality")
        }
    }

    /// A registered channel with deposit 50, plus the delegated voucher key
    /// that signs its vouchers.
    fn metered_channel() -> (ed25519::PrivateKey, AccountKey, RegisteredChannel) {
        let voucher_key = ed25519::PrivateKey::from_seed(1);
        let payer_account = AccountKey::from([1u8; AccountKey::SIZE]);
        let receiver = AccountKey::from([2u8; AccountKey::SIZE]);
        let channel = channel_address(
            &payer_account,
            &receiver,
            &receiver,
            &voucher_key.public_key(),
            0,
        );
        let open = VerifiedOpenChannel {
            payer: payer_account,
            receiver,
            voucher_key: voucher_key.public_key(),
            operator: receiver,
            open_nonce: 0,
            deposit: NZU64!(50),
            expiry: CHANNEL_NEVER_EXPIRES,
            tip_height: 0,
        };
        let initial = Voucher::sign(&voucher_key, channel, 0);
        let registered = RegisteredChannel::new(&open, initial);
        (voucher_key, channel, registered)
    }

    #[test]
    fn registration_runway_is_never_weaker_than_settle_margin() {
        let margins = Margins {
            min_runway: 2,
            settle_margin: 10,
        };

        assert!(!margins.has_runway(100, 110));
        assert!(margins.has_runway(100, 111));
        assert_eq!(margins.expiry_phase(100, 111), ExpiryPhase::Serving);
    }

    #[test]
    fn registration_runway_still_honors_larger_minimum() {
        let margins = Margins {
            min_runway: 10,
            settle_margin: 2,
        };

        assert!(!margins.has_runway(100, 110));
        assert!(margins.has_runway(100, 111));
    }

    #[test]
    fn serves_increasing_vouchers() {
        let (payer, channel, mut registered) = metered_channel();
        for i in 1..=4u64 {
            let voucher = Voucher::sign(&payer, channel, i * 5);
            assert_eq!(registered.serve(voucher), Ok(i * 5));
        }
        assert_eq!(registered.latest.cumulative, 20);
    }

    #[test]
    fn accepts_exact_replay_but_rejects_lower_voucher() {
        let (payer, channel, mut registered) = metered_channel();
        assert_eq!(registered.serve(Voucher::sign(&payer, channel, 10)), Ok(10));
        // An exact retry can follow a lost acknowledgement and is a no-op.
        assert_eq!(registered.serve(Voucher::sign(&payer, channel, 10)), Ok(10));
        // Moving backward would replace the operator's stronger claim.
        assert_eq!(
            registered.serve(Voucher::sign(&payer, channel, 9)),
            Err(ServeError::Stale)
        );
    }

    #[test]
    fn rejects_overdraft_voucher() {
        let (payer, channel, mut registered) = metered_channel();
        assert_eq!(
            registered.serve(Voucher::sign(&payer, channel, 55)),
            Err(ServeError::Overdraft)
        );
    }

    #[test]
    fn rejects_forged_voucher() {
        let (_payer, channel, mut registered) = metered_channel();
        let attacker = ed25519::PrivateKey::from_seed(9);
        assert_eq!(
            registered.serve(Voucher::sign(&attacker, channel, 10)),
            Err(ServeError::BadSignature)
        );
    }

    #[test]
    fn consume_pauses_at_debt_limit_and_vouchers_unlock() {
        let (payer, channel, mut registered) = metered_channel();
        let limit = 3;

        // An unpaid channel streams up to the debt limit, then pauses.
        for served in 1..=limit {
            assert_eq!(
                registered.consume(1, limit),
                ConsumeOutcome::Served(MeterSnapshot { served, paid: 0 })
            );
        }
        assert_eq!(
            registered.consume(1, limit),
            ConsumeOutcome::PaymentRequired(MeterSnapshot {
                served: limit,
                paid: 0
            })
        );

        // Paying moves the window; a refused consume did not advance the
        // meter.
        registered
            .serve(Voucher::sign(&payer, channel, 2))
            .expect("voucher should be accepted");
        assert_eq!(
            registered.consume(1, limit),
            ConsumeOutcome::Served(MeterSnapshot { served: 4, paid: 2 })
        );
    }

    #[test]
    fn consume_never_exceeds_deposit() {
        let (payer, channel, mut registered) = metered_channel();
        // Fully paid up (deposit is 50), so only the deposit can bind.
        registered
            .serve(Voucher::sign(&payer, channel, 50))
            .expect("voucher should be accepted");
        assert_eq!(
            registered.consume(50, u64::MAX),
            ConsumeOutcome::Served(MeterSnapshot {
                served: 50,
                paid: 50
            })
        );
        assert_eq!(
            registered.consume(1, u64::MAX),
            ConsumeOutcome::DepositExhausted(MeterSnapshot {
                served: 50,
                paid: 50
            })
        );
    }

    #[test]
    fn zero_cost_consume_probes_without_advancing() {
        let (_payer, _channel, mut registered) = metered_channel();
        // A zero-cost probe reports the meter without consuming credit.
        assert_eq!(
            registered.consume(0, 1),
            ConsumeOutcome::Served(MeterSnapshot { served: 0, paid: 0 })
        );
        assert_eq!(
            registered.consume(1, 1),
            ConsumeOutcome::Served(MeterSnapshot { served: 1, paid: 0 })
        );
        // A refusal does not advance the meter, and the probe still answers
        // after it.
        assert_eq!(
            registered.consume(1, 1),
            ConsumeOutcome::PaymentRequired(MeterSnapshot { served: 1, paid: 0 })
        );
        assert_eq!(
            registered.consume(0, 1),
            ConsumeOutcome::Served(MeterSnapshot { served: 1, paid: 0 })
        );
    }

    #[test]
    fn bounded_consume_stops_at_content_limit_without_advancing() {
        let (_payer, _channel, mut registered) = metered_channel();

        assert_eq!(
            registered.consume_bounded(3, 10, 3),
            ConsumeOutcome::Served(MeterSnapshot { served: 3, paid: 0 })
        );
        assert_eq!(
            registered.consume_bounded(1, 10, 3),
            ConsumeOutcome::ContentExhausted(MeterSnapshot { served: 3, paid: 0 })
        );
        assert_eq!(
            registered.consume(0, 10),
            ConsumeOutcome::Served(MeterSnapshot { served: 3, paid: 0 })
        );
    }

    #[test]
    fn concurrent_bounded_consumes_reserve_each_chunk_once() {
        deterministic::Runner::default().start(|context| async move {
            let service = OperatorService::init(
                context,
                UnusedIo,
                UnusedIo,
                ed25519::PrivateKey::from_seed(99),
                Margins {
                    min_runway: 10,
                    settle_margin: 5,
                },
            )
            .await;
            let (_payer, channel, registered) = metered_channel();
            service
                .state
                .lock()
                .await
                .channels
                .insert(channel, registered);

            let outcomes =
                join_all((0..8).map(|_| service.consume_bounded(&channel, 1, u64::MAX, 3))).await;
            assert_eq!(
                outcomes
                    .iter()
                    .filter(|outcome| matches!(outcome, Ok(ConsumeOutcome::Served(_))))
                    .count(),
                3
            );
            assert_eq!(
                outcomes
                    .iter()
                    .filter(|outcome| {
                        matches!(
                            outcome,
                            Ok(ConsumeOutcome::ContentExhausted(MeterSnapshot {
                                served: 3,
                                paid: 0
                            }))
                        )
                    })
                    .count(),
                5
            );
            assert_eq!(service.stats().await.streamed, 3);
        });
    }

    #[test]
    fn voucher_replay_is_idempotent_and_not_counted_twice() {
        deterministic::Runner::default().start(|context| async move {
            let service = OperatorService::init(
                context,
                UnusedIo,
                UnusedIo,
                ed25519::PrivateKey::from_seed(99),
                Margins {
                    min_runway: 10,
                    settle_margin: 5,
                },
            )
            .await;
            let (payer, channel, registered) = metered_channel();
            service
                .state
                .lock()
                .await
                .channels
                .insert(channel, registered);
            let voucher = Voucher::sign(&payer, channel, 10);

            assert_eq!(service.serve_voucher(voucher.clone()).await, Ok(10));
            assert_eq!(service.serve_voucher(voucher).await, Ok(10));
            assert_eq!(service.stats().await.vouchers, 1);
        });
    }

    #[test]
    fn nonce_window_bounds_runahead_and_serializes_unaligned() {
        let mut state = OperatorState::new(0, true);
        fn reserve(state: &mut OperatorState) -> Option<u64> {
            try_reserve_nonce(&mut state.nonce, &mut state.inflight, state.aligned)
        }

        // The window admits nonces up to NONCE_BITMAP_CAPACITY ahead of the
        // oldest unfinalized one, then blocks.
        for expected in 0..=NONCE_BITMAP_CAPACITY {
            assert_eq!(reserve(&mut state), Some(expected));
        }
        assert_eq!(reserve(&mut state), None, "window full");

        // Finalizing the oldest opens exactly one slot.
        state.inflight.remove(&0);
        assert_eq!(reserve(&mut state), Some(NONCE_BITMAP_CAPACITY + 1));

        // An un-aligned operator (dirty startup) reserves only with an empty
        // in-flight set, so its first transaction lands alone.
        state.aligned = false;
        assert_eq!(reserve(&mut state), None);
        state.inflight.clear();
        assert_eq!(reserve(&mut state), Some(NONCE_BITMAP_CAPACITY + 2));
    }

    #[test]
    fn duplicate_registration_preserves_accepted_voucher_state() {
        let voucher_key = ed25519::PrivateKey::from_seed(42);
        let payer_account = AccountKey::from([42u8; AccountKey::SIZE]);
        let receiver_account = AccountKey::from([43u8; AccountKey::SIZE]);
        let open_nonce = 7;
        let channel = channel_address(
            &payer_account,
            &receiver_account,
            &receiver_account,
            &voucher_key.public_key(),
            open_nonce,
        );
        let open = |deposit: NonZeroU64| VerifiedOpenChannel {
            payer: payer_account,
            receiver: receiver_account,
            voucher_key: voucher_key.public_key(),
            operator: receiver_account,
            open_nonce,
            deposit,
            expiry: CHANNEL_NEVER_EXPIRES,
            tip_height: 0,
        };
        let initial = Voucher::sign(&voucher_key, channel, 0);
        let voucher = Voucher::sign(&voucher_key, channel, 10);

        let mut state = OperatorState::new(0, true);
        assert!(
            state
                .register_verified_channel(
                    channel,
                    RegisteredChannel::new(&open(NZU64!(20)), initial.clone()),
                )
                .expect("initial registration should succeed")
        );
        let registered = state
            .channels
            .get_mut(&channel)
            .expect("registration metadata should exist");
        registered
            .serve(voucher.clone())
            .expect("voucher should be accepted before replay");
        registered.settlement = SettlementState::Settling;

        assert!(
            !state
                .register_verified_channel(
                    channel,
                    RegisteredChannel::new(&open(NZU64!(20)), initial.clone()),
                )
                .expect("duplicate registration should be idempotent")
        );
        assert!(
            state
                .register_verified_channel(
                    channel,
                    RegisteredChannel::new(&open(NZU64!(21)), initial),
                )
                .is_err(),
            "mismatched metadata must be rejected"
        );

        let registered = state
            .channels
            .get_mut(&channel)
            .expect("registration metadata should remain");
        assert_eq!(registered.latest.cumulative, 10);
        assert_eq!(registered.settlement, SettlementState::Settling);
        assert_eq!(
            registered.serve(voucher),
            Ok(10),
            "duplicate registration must not reset the latest-voucher accounting"
        );
        assert_eq!(
            registered.serve(Voucher::sign(&voucher_key, channel, 9)),
            Err(ServeError::Stale)
        );
    }
}
