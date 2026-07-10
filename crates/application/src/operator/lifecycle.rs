//! Deterministic end-to-end lifecycle tests: the [`OperatorService`] driven
//! against a real chain (the consensus test harness), with a payer on the
//! other side. Every submission proposes and finalizes an actual block, so
//! registration validation, voucher gating, the operator-nonce window, and
//! the settle/abandon race are all exercised against real execution
//! semantics — the gap that let the operator's registration path ship broken
//! end-to-end.

use super::service::{
    ChainReader, Digest, Margins, OperatorError, OperatorService, Relayer, SettleOutcome,
    SubmitOutcome, Tx, VerifiedOpenChannel,
};
use crate::consensus::tests::{
    TEST_TX_NS, TestApp, TestBlock, TestDbs, bootstrap, propose_and_finalize, read_account,
    read_raw,
};
use commonware_cryptography::{Signer as _, ed25519, sha256};
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
use commonware_utils::NZU64;
use constantinople_primitives::{
    AccountKey, CHANNEL_NEVER_EXPIRES, Nonce, Transaction, TransactionPublicKey, Voucher,
    channel_address,
};
use futures::lock::Mutex;
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

const STEP: u64 = 5;
const DEPOSIT: u64 = 25;
const FUNDED: u64 = 1_000;
const MARGINS: Margins = Margins {
    min_runway: 4,
    settle_margin: 2,
};

/// The chain the mock operator environment runs against: the consensus test
/// harness plus the bookkeeping the [`Relayer`]/[`ChainReader`] traits need.
struct Harness {
    context: deterministic::Context,
    dbs: TestDbs,
    app: TestApp,
    leader: ed25519::PublicKey,
    tip: TestBlock,
    /// Digests of transactions that finalized (whole-batch bookkeeping; the
    /// mock only commits batches that land or skip atomically).
    finalized: HashSet<Digest>,
    /// Finalized `OpenChannel` transactions, as the indexer-backed verifier
    /// would report them. The proof plumbing is the binary's concern; the
    /// registration *decisions* on the verified contents are the library's,
    /// and are what these tests exercise.
    opens: HashMap<Digest, VerifiedOpenChannel>,
}

impl Harness {
    fn height(&self) -> u64 {
        self.tip.header.height
    }

    /// Proposes a block carrying `txs` and finalizes it. Returns how many of
    /// them the proposer actually included (skipped channel operations drop
    /// out; the block advances the chain either way).
    async fn commit(&mut self, txs: Vec<Tx>) -> usize {
        let digests: Vec<Digest> = txs.iter().map(|tx| *tx.message_digest()).collect();
        let (block, included) = propose_and_finalize(
            &mut self.app,
            &self.context,
            &self.dbs,
            &self.leader,
            &self.tip,
            txs,
        )
        .await;
        self.tip = block;
        if included == digests.len() {
            self.finalized.extend(digests);
        }
        included
    }
}

/// Shared handle implementing the service's I/O traits over the harness.
#[derive(Clone)]
struct MockChain(Arc<Mutex<Harness>>);

impl Relayer for MockChain {
    async fn submit(&self, tx: Tx) -> Result<SubmitOutcome, String> {
        let mut harness = self.0.lock().await;
        let included = harness.commit(vec![tx]).await;
        if included == 1 {
            Ok(SubmitOutcome::Included {
                height: harness.height(),
            })
        } else {
            Ok(SubmitOutcome::Excluded)
        }
    }

    async fn fetch_nonce(
        &self,
        public_key: &TransactionPublicKey,
    ) -> Result<Option<Nonce>, String> {
        let harness = self.0.lock().await;
        let key = AccountKey::from_public_key(public_key);
        Ok(read_raw(&harness.dbs, &key)
            .await
            .map(|account| account.nonce))
    }
}

impl ChainReader for MockChain {
    async fn latest_height(&self) -> Result<Option<u64>, String> {
        Ok(Some(self.0.lock().await.height()))
    }

    async fn verify_open_channel(
        &self,
        digest: &Digest,
    ) -> Result<VerifiedOpenChannel, OperatorError> {
        let harness = self.0.lock().await;
        let mut open = harness
            .opens
            .get(digest)
            .cloned()
            .ok_or_else(|| OperatorError::unavailable("open transaction is not finalized"))?;
        open.tip_height = harness.height();
        Ok(open)
    }

    async fn is_finalized(&self, digest: &Digest) -> Result<bool, String> {
        Ok(self.0.lock().await.finalized.contains(digest))
    }
}

/// A payer driving the client side of the lifecycle: funds itself, opens
/// channels, signs vouchers, and reclaims timeouts — the spammer's role.
struct Payer {
    key: ed25519::PrivateKey,
    pk: TransactionPublicKey,
    account: AccountKey,
    nonce: u64,
}

impl Payer {
    fn new(seed: u64) -> Self {
        let key = ed25519::PrivateKey::from_seed(seed);
        let pk = TransactionPublicKey::ed25519(key.public_key());
        let account = AccountKey::from_public_key(&pk);
        Self {
            key,
            pk,
            account,
            nonce: 0,
        }
    }

    fn sign(&self, tx: Transaction<sha256::Digest>) -> Tx {
        tx.seal_and_sign(&self.key, TEST_TX_NS, &mut sha256::Sha256::default())
    }

    fn mint(&mut self, amount: u64) -> Tx {
        let nonce = self.nonce;
        self.nonce += 1;
        self.sign(Transaction::mint(self.pk.clone(), NZU64!(amount), nonce))
    }

    fn voucher(&self, channel: AccountKey, cumulative: u64) -> Voucher {
        Voucher::sign(&self.key, channel, cumulative)
    }

    fn timeout(&mut self, receiver: AccountKey, open_nonce: u64) -> Tx {
        let nonce = self.nonce;
        self.nonce += 1;
        // Payee-run channels: the operator is the receiver.
        self.sign(Transaction::timeout_channel(
            self.pk.clone(),
            receiver,
            receiver,
            open_nonce,
            nonce,
        ))
    }

    /// Opens a payee-run channel (the receiver settles for itself) on chain
    /// and records it in the harness the way a verifying indexer would.
    /// Returns the channel address, the open digest, and the nonce it
    /// consumed.
    async fn open_channel(
        &mut self,
        chain: &MockChain,
        receiver: AccountKey,
        deposit: u64,
        expiry: u64,
    ) -> (AccountKey, Digest, u64) {
        self.open_channel_via(chain, receiver, receiver, deposit, expiry)
            .await
    }

    /// Opens a channel paying `receiver`, settled by `operator` (the
    /// delegated x402-style topology when the two differ).
    async fn open_channel_via(
        &mut self,
        chain: &MockChain,
        receiver: AccountKey,
        operator: AccountKey,
        deposit: u64,
        expiry: u64,
    ) -> (AccountKey, Digest, u64) {
        let open_nonce = self.nonce;
        self.nonce += 1;
        let deposit = NZU64!(deposit);
        let channel = channel_address(&self.account, &receiver, &operator, open_nonce);
        let open = self.sign(Transaction::open_channel(
            self.pk.clone(),
            receiver,
            operator,
            deposit,
            expiry,
            open_nonce,
        ));
        let digest = *open.message_digest();

        let mut harness = chain.0.lock().await;
        let included = harness.commit(vec![open]).await;
        assert_eq!(included, 1, "open must land");
        harness.opens.insert(
            digest,
            VerifiedOpenChannel {
                payer: self.pk.clone(),
                receiver,
                operator,
                open_nonce,
                deposit,
                expiry,
                // Overwritten with the live tip on every verification.
                tip_height: 0,
            },
        );
        (channel, digest, open_nonce)
    }
}

/// Bootstraps the chain, the payer (funded), and the operator service.
async fn setup(
    context: &deterministic::Context,
) -> (
    MockChain,
    Payer,
    OperatorService<deterministic::Context, MockChain, MockChain>,
) {
    setup_with_relayer(context, |chain| chain).await
}

/// Like [`setup`], but lets the test wrap the service's relayer (say, in a
/// fault injector); the chain reader stays the plain harness.
async fn setup_with_relayer<R: Relayer>(
    context: &deterministic::Context,
    wrap: impl FnOnce(MockChain) -> R,
) -> (
    MockChain,
    Payer,
    OperatorService<deterministic::Context, R, MockChain>,
) {
    let (dbs, app, genesis, leader) = bootstrap(context).await;
    let chain = MockChain(Arc::new(Mutex::new(Harness {
        context: context.child("chain"),
        dbs,
        app,
        leader,
        tip: genesis,
        finalized: HashSet::new(),
        opens: HashMap::new(),
    })));

    let mut payer = Payer::new(7);
    let mint = payer.mint(FUNDED);
    assert_eq!(chain.0.lock().await.commit(vec![mint]).await, 1);

    let receiver = ed25519::PrivateKey::from_seed(9);
    let service = OperatorService::init(
        context.child("operator"),
        wrap(chain.clone()),
        chain.clone(),
        receiver,
        MARGINS,
    )
    .await;
    service.refresh_height().await.expect("height refresh");
    (chain, payer, service)
}

/// Full happy path plus the abandon race, in one continuous history so the
/// receiver-nonce window is exercised across both.
#[test]
fn operator_settles_and_abandons_against_live_chain() {
    deterministic::Runner::default().start(|context| async move {
        let (chain, mut payer, service) = setup(&context).await;
        let receiver_account = *service.operator_account();

        // --- Happy path: open, register, stream, settle. ---
        let expiry = chain.0.lock().await.height() + 100;
        let (channel, open_digest, open_nonce) = payer
            .open_channel(&chain, receiver_account, DEPOSIT, expiry)
            .await;

        // Registration validates the verified open and is idempotent.
        assert_eq!(
            service
                .register_channel(channel, payer.pk.clone(), open_nonce, &open_digest)
                .await,
            Ok(true)
        );
        assert_eq!(
            service
                .register_channel(channel, payer.pk.clone(), open_nonce, &open_digest)
                .await,
            Ok(false),
            "matching replay is a no-op"
        );

        // A registration whose channel address does not match the open is
        // refused, as is one for an open the chain never finalized.
        let bogus = channel_address(&payer.account, &receiver_account, &receiver_account, 99);
        assert!(
            service
                .register_channel(bogus, payer.pk.clone(), open_nonce, &open_digest)
                .await
                .is_err(),
            "mismatched channel address must be refused"
        );
        let unknown = sha256::Digest::from([9u8; 32]);
        assert!(
            service
                .register_channel(channel, payer.pk.clone(), open_nonce, &unknown)
                .await
                .is_err(),
            "unverified open must be refused"
        );

        // Stream vouchers; the operator charges each step.
        for i in 1..=3u64 {
            let voucher = payer.voucher(channel, i * STEP);
            assert_eq!(service.serve_voucher(voucher).await, Ok(i * STEP));
        }
        // Stale and over-deposit vouchers are refused.
        assert!(
            service
                .serve_voucher(payer.voucher(channel, 3 * STEP))
                .await
                .is_err(),
            "stale voucher must be refused"
        );
        assert!(
            service
                .serve_voucher(payer.voucher(channel, DEPOSIT + 1))
                .await
                .is_err(),
            "overdraft voucher must be refused"
        );

        // Settle: the close lands on the real chain.
        let outcome = service.settle_channel(channel).await.expect("settle");
        assert_eq!(
            outcome,
            SettleOutcome {
                settled: true,
                cumulative: 3 * STEP,
            }
        );
        {
            let harness = chain.0.lock().await;
            assert_eq!(
                read_account(&harness.dbs, &receiver_account).await.balance,
                3 * STEP,
                "receiver was paid the settled cumulative"
            );
            assert_eq!(
                read_raw(&harness.dbs, &channel).await,
                None,
                "settled channel is deleted"
            );
            assert_eq!(
                read_account(&harness.dbs, &payer.account).await.balance,
                FUNDED - 3 * STEP,
                "payer reclaimed the deposit minus the settled amount"
            );
        }
        // Settling again reports the same outcome without touching the chain.
        assert_eq!(service.settle_channel(channel).await, Ok(outcome));

        // Serving against a settled channel is refused.
        assert!(
            service
                .serve_voucher(payer.voucher(channel, 4 * STEP))
                .await
                .is_err(),
            "settled channel must not serve"
        );

        // --- Runway: a channel expiring too soon is refused at registration. ---
        let height = chain.0.lock().await.height();
        let (short_channel, short_digest, short_nonce) = payer
            .open_channel(&chain, receiver_account, STEP, height + MARGINS.min_runway)
            .await;
        assert!(
            service
                .register_channel(short_channel, payer.pk.clone(), short_nonce, &short_digest)
                .await
                .is_err(),
            "channel without runway must be refused"
        );

        // --- Abandon path: the payer reclaims before the close can land. ---
        let expiry = chain.0.lock().await.height() + 8;
        let (channel, open_digest, open_nonce) = payer
            .open_channel(&chain, receiver_account, DEPOSIT, expiry)
            .await;
        assert_eq!(
            service
                .register_channel(channel, payer.pk.clone(), open_nonce, &open_digest)
                .await,
            Ok(true)
        );
        assert_eq!(
            service.serve_voucher(payer.voucher(channel, STEP)).await,
            Ok(STEP)
        );

        // Advance the chain past the expiry, then reclaim unilaterally — the
        // receiver "missed" its deadline.
        while chain.0.lock().await.height() <= expiry {
            let filler = payer.mint(1);
            chain.0.lock().await.commit(vec![filler]).await;
        }
        let timeout = payer.timeout(receiver_account, open_nonce);
        assert_eq!(
            chain.0.lock().await.commit(vec![timeout]).await,
            1,
            "timeout past expiry reclaims the channel"
        );
        service.refresh_height().await.expect("height refresh");

        // The close is now unincludable (the channel is gone); the service
        // must burn the reserved nonce and mark the settlement abandoned
        // instead of retrying forever.
        let payer_before = {
            let harness = chain.0.lock().await;
            read_account(&harness.dbs, &payer.account).await.balance
        };
        let outcome = service.settle_channel(channel).await.expect("settle");
        assert_eq!(
            outcome,
            SettleOutcome {
                settled: false,
                cumulative: STEP,
            },
            "settlement is abandoned, vouchers forfeited"
        );
        {
            let harness = chain.0.lock().await;
            let receiver = read_account(&harness.dbs, &receiver_account).await;
            assert_eq!(
                receiver.balance,
                3 * STEP + 1,
                "receiver got nothing from the abandoned channel but the Mint(1) burn"
            );
            assert_eq!(
                receiver.nonce.base, 2,
                "close consumed nonce 0, the burn consumed nonce 1"
            );
            assert_eq!(
                read_account(&harness.dbs, &payer.account).await.balance,
                payer_before,
                "the payer kept the reclaimed escrow"
            );
        }

        // --- The abandon must not wedge later settlements. ---
        let expiry = chain.0.lock().await.height() + 100;
        let (channel, open_digest, open_nonce) = payer
            .open_channel(&chain, receiver_account, DEPOSIT, expiry)
            .await;
        assert_eq!(
            service
                .register_channel(channel, payer.pk.clone(), open_nonce, &open_digest)
                .await,
            Ok(true)
        );
        assert_eq!(
            service.serve_voucher(payer.voucher(channel, STEP)).await,
            Ok(STEP)
        );
        let outcome = service.settle_channel(channel).await.expect("settle");
        assert_eq!(
            outcome,
            SettleOutcome {
                settled: true,
                cumulative: STEP,
            },
            "settlement works after an abandon"
        );
        let harness = chain.0.lock().await;
        assert_eq!(
            read_account(&harness.dbs, &receiver_account).await.balance,
            4 * STEP + 1,
        );
    });
}

/// The expiry sweep: a voucher-bearing channel becomes due exactly when its
/// expiry enters the settle margin, is handed out once, and disappears after
/// settlement.
#[test]
fn sweep_marks_expiring_channels_due_once() {
    deterministic::Runner::default().start(|context| async move {
        let (chain, mut payer, service) = setup(&context).await;
        let receiver_account = *service.operator_account();

        let expiry = chain.0.lock().await.height() + 8;
        let (channel, open_digest, open_nonce) = payer
            .open_channel(&chain, receiver_account, DEPOSIT, expiry)
            .await;
        assert_eq!(
            service
                .register_channel(channel, payer.pk.clone(), open_nonce, &open_digest)
                .await,
            Ok(true)
        );

        // No voucher yet: nothing to settle even near expiry.
        assert!(service.due_settlements().await.is_empty());

        assert_eq!(
            service.serve_voucher(payer.voucher(channel, STEP)).await,
            Ok(STEP)
        );
        // Far from expiry: still serving.
        assert!(service.due_settlements().await.is_empty());

        // Advance into the settle margin (height + settle_margin >= expiry).
        while chain.0.lock().await.height() + MARGINS.settle_margin < expiry {
            let filler = payer.mint(1);
            chain.0.lock().await.commit(vec![filler]).await;
        }
        service.refresh_height().await.expect("height refresh");

        // Vouchers stop, settlement becomes due — exactly once.
        assert!(
            service
                .serve_voucher(payer.voucher(channel, 2 * STEP))
                .await
                .is_err(),
            "vouchers must stop inside the settle margin"
        );
        assert_eq!(service.due_settlements().await, vec![channel]);
        assert!(
            service.due_settlements().await.is_empty(),
            "a channel already handed out is not returned again"
        );

        // Settlement succeeds inside the margin (the channel still exists),
        // and the settled channel stays out of the sweep.
        let outcome = service.settle_channel(channel).await.expect("settle");
        assert!(outcome.settled);
        assert!(service.due_settlements().await.is_empty());
    });
}

/// The delegated x402-style topology: the channel's payee is a third account
/// that never signs anything, and the operator settles on its behalf. The
/// settled cumulative must land on the receiver — the operator that signed
/// the close moves no funds of its own.
#[test]
fn delegated_operator_pays_the_named_receiver() {
    deterministic::Runner::default().start(|context| async move {
        let (chain, mut payer, service) = setup(&context).await;
        let operator_account = *service.operator_account();

        // The payee: a distinct key with no on-chain footprint.
        let receiver_account = AccountKey::from_public_key(&TransactionPublicKey::ed25519(
            ed25519::PrivateKey::from_seed(11).public_key(),
        ));
        assert_ne!(receiver_account, operator_account);

        let expiry = chain.0.lock().await.height() + 100;
        let (channel, open_digest, open_nonce) = payer
            .open_channel_via(&chain, receiver_account, operator_account, DEPOSIT, expiry)
            .await;

        assert_eq!(
            service
                .register_channel(channel, payer.pk.clone(), open_nonce, &open_digest)
                .await,
            Ok(true)
        );
        for i in 1..=2 {
            assert_eq!(
                service
                    .serve_voucher(payer.voucher(channel, i * STEP))
                    .await,
                Ok(i * STEP)
            );
        }

        let outcome = service.settle_channel(channel).await.expect("settle");
        assert_eq!(
            outcome,
            SettleOutcome {
                settled: true,
                cumulative: 2 * STEP,
            }
        );

        let harness = chain.0.lock().await;
        assert_eq!(
            read_account(&harness.dbs, &receiver_account).await.balance,
            2 * STEP,
            "the named receiver was paid without ever transacting"
        );
        assert_eq!(
            read_account(&harness.dbs, &operator_account).await.balance,
            0,
            "the settling operator received nothing"
        );
        assert_eq!(
            read_account(&harness.dbs, &payer.account).await.balance,
            FUNDED - 2 * STEP,
            "payer reclaimed the deposit minus the settled amount"
        );
        assert_eq!(
            read_raw(&harness.dbs, &channel).await,
            None,
            "settled channel is deleted"
        );
    });
}

/// A relayer that loses acknowledgements on demand: the submission still
/// reaches the chain, but the caller sees a transport error.
#[derive(Clone)]
struct LossyRelayer {
    inner: MockChain,
    lose_next: Arc<AtomicBool>,
}

impl Relayer for LossyRelayer {
    async fn submit(&self, tx: Tx) -> Result<SubmitOutcome, String> {
        let outcome = self.inner.submit(tx).await;
        if self.lose_next.swap(false, Ordering::Relaxed) {
            return Err("acknowledgement lost".to_string());
        }
        outcome
    }

    async fn fetch_nonce(
        &self,
        public_key: &TransactionPublicKey,
    ) -> Result<Option<Nonce>, String> {
        self.inner.fetch_nonce(public_key).await
    }
}

/// A close whose acknowledgement is lost on a never-expiring channel: every
/// resubmission is filtered (the nonce is consumed), the expiry gate can
/// never fire, and only the exclusion-path finalization check keeps the
/// settlement from looping forever with its nonce pinned in flight.
#[test]
fn settlement_survives_a_lost_close_acknowledgement() {
    deterministic::Runner::default().start(|context| async move {
        let lose_next = Arc::new(AtomicBool::new(false));
        let lose_handle = lose_next.clone();
        let (chain, mut payer, service) = setup_with_relayer(&context, move |chain| LossyRelayer {
            inner: chain,
            lose_next: lose_handle,
        })
        .await;
        let receiver_account = *service.operator_account();

        let (channel, open_digest, open_nonce) = payer
            .open_channel(&chain, receiver_account, DEPOSIT, CHANNEL_NEVER_EXPIRES)
            .await;
        assert_eq!(
            service
                .register_channel(channel, payer.pk.clone(), open_nonce, &open_digest)
                .await,
            Ok(true)
        );
        assert_eq!(
            service.serve_voucher(payer.voucher(channel, STEP)).await,
            Ok(STEP)
        );

        lose_next.store(true, Ordering::Relaxed);
        let outcome = service.settle_channel(channel).await.expect("settle");
        assert_eq!(
            outcome,
            SettleOutcome {
                settled: true,
                cumulative: STEP,
            },
            "the close finalized despite the lost acknowledgement"
        );
        let harness = chain.0.lock().await;
        assert_eq!(
            read_account(&harness.dbs, &receiver_account).await.balance,
            STEP,
            "the close landed exactly once"
        );
        assert_eq!(
            read_raw(&harness.dbs, &channel).await,
            None,
            "settled channel is deleted"
        );
    });
}
