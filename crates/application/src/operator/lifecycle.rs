//! Deterministic end-to-end lifecycle tests: the [`OperatorService`] driven
//! against a real chain (the consensus test harness), with a payer on the
//! other side. Every submission proposes and finalizes an actual block, so
//! registration validation, voucher gating, the operator-nonce window, and
//! the settle/abandon race are all exercised against real execution
//! semantics — the gap that let the operator's registration path ship broken
//! end-to-end.

use super::service::{
    ChainReader, ConsumeOutcome, Digest, Margins, MeterSnapshot, OperatorError, OperatorService,
    Relayer, SettleOutcome, SubmitOutcome, Tx, VerifiedOpenChannel,
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
/// Seed of the operator key [`setup`] builds the service with; tests that
/// need to sign competing operator-account transactions derive it too.
const OPERATOR_SEED: u64 = 9;
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
/// Its account key and voucher key are deliberately distinct: delegation is
/// the design, so the tests exercise it.
struct Payer {
    key: ed25519::PrivateKey,
    pk: TransactionPublicKey,
    account: AccountKey,
    /// The delegated voucher key the payer's channels name.
    voucher_key: ed25519::PrivateKey,
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
            voucher_key: ed25519::PrivateKey::from_seed(seed + 1_000),
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
        Voucher::sign(&self.voucher_key, channel, cumulative)
    }

    /// The initial zero-value voucher registration carries.
    fn zero_voucher(&self, channel: AccountKey) -> ed25519::Signature {
        Voucher::sign(&self.voucher_key, channel, 0).signature
    }

    fn timeout(&mut self, receiver: AccountKey, open_nonce: u64) -> Tx {
        let nonce = self.nonce;
        self.nonce += 1;
        // Payee-run channels: the operator is the receiver.
        self.sign(Transaction::timeout_channel(
            self.pk.clone(),
            receiver,
            receiver,
            self.voucher_key.public_key(),
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
        let voucher_pk = self.voucher_key.public_key();
        let channel = channel_address(&self.account, &receiver, &operator, &voucher_pk, open_nonce);
        let open = self.sign(Transaction::open_channel(
            self.pk.clone(),
            receiver,
            operator,
            voucher_pk.clone(),
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
                payer: self.account,
                receiver,
                voucher_key: voucher_pk,
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

    let receiver = ed25519::PrivateKey::from_seed(OPERATOR_SEED);
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
        let (channel, open_digest, _open_nonce) = payer
            .open_channel(&chain, receiver_account, DEPOSIT, expiry)
            .await;

        // Registration validates the verified open and is idempotent.
        assert_eq!(
            service
                .register_channel(&open_digest, payer.zero_voucher(channel))
                .await,
            Ok((channel, true)),
            "the operator derives the channel address the payer derived"
        );
        assert_eq!(
            service
                .register_channel(&open_digest, payer.zero_voucher(channel))
                .await,
            Ok((channel, false)),
            "matching replay is a no-op"
        );

        // A zero voucher signed by a key other than the open's voucher key is
        // refused, as is a registration for an open the chain never
        // finalized.
        let forged = Voucher::sign(&payer.key, channel, 0).signature;
        assert!(
            service
                .register_channel(&open_digest, forged)
                .await
                .is_err(),
            "zero voucher from the wrong key must be refused"
        );
        let unknown = sha256::Digest::from([9u8; 32]);
        assert!(
            service
                .register_channel(&unknown, payer.zero_voucher(channel))
                .await
                .is_err(),
            "unverified open must be refused"
        );

        // Stream vouchers; the operator charges each step.
        for i in 1..=3u64 {
            let voucher = payer.voucher(channel, i * STEP);
            assert_eq!(service.serve_voucher(voucher).await, Ok(i * STEP));
        }
        // Exact retry is idempotent (its acknowledgement may have been
        // lost), while a lower and an over-deposit voucher are refused.
        assert_eq!(
            service
                .serve_voucher(payer.voucher(channel, 3 * STEP))
                .await,
            Ok(3 * STEP)
        );
        assert!(
            service
                .serve_voucher(payer.voucher(channel, 2 * STEP))
                .await
                .is_err(),
            "lower voucher must be refused"
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
        let (short_channel, short_digest, _) = payer
            .open_channel(&chain, receiver_account, STEP, height + MARGINS.min_runway)
            .await;
        assert!(
            service
                .register_channel(&short_digest, payer.zero_voucher(short_channel))
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
                .register_channel(&open_digest, payer.zero_voucher(channel))
                .await,
            Ok((channel, true))
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
        let (channel, open_digest, _open_nonce) = payer
            .open_channel(&chain, receiver_account, DEPOSIT, expiry)
            .await;
        assert_eq!(
            service
                .register_channel(&open_digest, payer.zero_voucher(channel))
                .await,
            Ok((channel, true))
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

/// The stream meter against a live chain: content pauses at the debt limit,
/// vouchers resume it, the deposit caps it absolutely, and the settlement
/// pays out what the meter charged.
#[test]
fn stream_meter_paces_content_against_vouchers() {
    deterministic::Runner::default().start(|context| async move {
        let (chain, mut payer, service) = setup(&context).await;
        let receiver_account = *service.operator_account();
        const LIMIT: u64 = 4;

        // Metering an unregistered channel is refused outright.
        let bogus = channel_address(
            &payer.account,
            &receiver_account,
            &receiver_account,
            &payer.voucher_key.public_key(),
            99,
        );
        assert!(service.consume(&bogus, 1, LIMIT).await.is_err());

        let expiry = chain.0.lock().await.height() + 100;
        let (channel, open_digest, _open_nonce) = payer
            .open_channel(&chain, receiver_account, DEPOSIT, expiry)
            .await;
        assert_eq!(
            service
                .register_channel(&open_digest, payer.zero_voucher(channel))
                .await,
            Ok((channel, true))
        );

        // An unpaid channel streams a debt limit's worth, then pauses; a
        // voucher resumes it up to the deposit. (The per-token policy edges
        // — refusals not advancing the meter, the deposit cap, zero-cost
        // probes — are pinned by the service unit tests; this scenario
        // exercises the spine against real registration and settlement.)
        assert_eq!(
            service.consume(&channel, LIMIT, LIMIT).await,
            Ok(ConsumeOutcome::Served(MeterSnapshot {
                served: LIMIT,
                paid: 0
            }))
        );
        assert_eq!(
            service.consume(&channel, 1, LIMIT).await,
            Ok(ConsumeOutcome::PaymentRequired(MeterSnapshot {
                served: LIMIT,
                paid: 0
            }))
        );
        assert_eq!(
            service.serve_voucher(payer.voucher(channel, DEPOSIT)).await,
            Ok(DEPOSIT)
        );
        assert_eq!(
            service.consume(&channel, DEPOSIT - LIMIT, u64::MAX).await,
            Ok(ConsumeOutcome::Served(MeterSnapshot {
                served: DEPOSIT,
                paid: DEPOSIT
            }))
        );

        // The settlement pays the receiver everything the meter charged, and
        // a settled channel no longer streams.
        assert_eq!(
            service.settle_channel(channel).await,
            Ok(SettleOutcome {
                settled: true,
                cumulative: DEPOSIT,
            })
        );
        {
            let harness = chain.0.lock().await;
            assert_eq!(
                read_account(&harness.dbs, &receiver_account).await.balance,
                DEPOSIT,
                "receiver was paid the streamed total"
            );
        }
        assert!(
            service.consume(&channel, 1, LIMIT).await.is_err(),
            "settled channel must not stream"
        );

        let stats = service.stats().await;
        assert_eq!(stats.streamed, DEPOSIT, "every served token is counted");
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
        let (channel, open_digest, _open_nonce) = payer
            .open_channel(&chain, receiver_account, DEPOSIT, expiry)
            .await;
        assert_eq!(
            service
                .register_channel(&open_digest, payer.zero_voucher(channel))
                .await,
            Ok((channel, true))
        );

        // Far from expiry: nothing is due (every registered channel carries
        // its initial zero voucher, so nearness to expiry is the only gate).
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
        let (channel, open_digest, _open_nonce) = payer
            .open_channel_via(&chain, receiver_account, operator_account, DEPOSIT, expiry)
            .await;

        assert_eq!(
            service
                .register_channel(&open_digest, payer.zero_voucher(channel))
                .await,
            Ok((channel, true))
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

/// A settlement whose reserved nonce was consumed by a different transaction
/// from the operator account (how the stale-nonce recovery documented on
/// `init` looks once it bites): neither the close nor its burn can ever
/// land, so the settlement must resolve as abandoned instead of looping with
/// the nonce pinned in flight — and the next settlement must still work.
#[test]
fn settlement_abandons_a_nonce_consumed_by_another_transaction() {
    deterministic::Runner::default().start(|context| async move {
        let (chain, mut payer, service) = setup(&context).await;
        let receiver_account = *service.operator_account();

        let (channel, open_digest, _open_nonce) = payer
            .open_channel(&chain, receiver_account, DEPOSIT, CHANNEL_NEVER_EXPIRES)
            .await;
        assert_eq!(
            service
                .register_channel(&open_digest, payer.zero_voucher(channel))
                .await,
            Ok((channel, true))
        );
        assert_eq!(
            service.serve_voucher(payer.voucher(channel, STEP)).await,
            Ok(STEP)
        );

        // A competing operator-signed transaction consumes nonce 0 out from
        // under the service, exactly as a stale recovered base would. Amount
        // 2 keeps its digest distinct from the service's own nonce burn (a
        // mint of 1), so the abandon must come from the consumed-nonce
        // check, not from mistaking the rogue transaction for the burn.
        let operator_key = ed25519::PrivateKey::from_seed(OPERATOR_SEED);
        let rogue = Transaction::mint(service.operator_public_key().clone(), NZU64!(2), 0)
            .seal_and_sign(&operator_key, TEST_TX_NS, &mut sha256::Sha256::default());
        assert_eq!(chain.0.lock().await.commit(vec![rogue]).await, 1);

        let outcome = service
            .settle_channel(channel)
            .await
            .expect("settle resolves");
        assert_eq!(
            outcome,
            SettleOutcome {
                settled: false,
                cumulative: STEP,
            },
            "the settlement is abandoned, not wedged"
        );
        {
            let harness = chain.0.lock().await;
            assert!(
                read_raw(&harness.dbs, &channel).await.is_some(),
                "the escrow is untouched — the close never landed"
            );
        }

        // The abandoned nonce left the in-flight window: a second channel
        // settles normally on the next nonce.
        let (channel, open_digest, _open_nonce) = payer
            .open_channel(&chain, receiver_account, DEPOSIT, CHANNEL_NEVER_EXPIRES)
            .await;
        assert_eq!(
            service
                .register_channel(&open_digest, payer.zero_voucher(channel))
                .await,
            Ok((channel, true))
        );
        assert_eq!(
            service.serve_voucher(payer.voucher(channel, STEP)).await,
            Ok(STEP)
        );
        assert_eq!(
            service.settle_channel(channel).await,
            Ok(SettleOutcome {
                settled: true,
                cumulative: STEP,
            })
        );
    });
}

/// A registration replay stays idempotent even after the chain drifts
/// inside the runway margin: the client whose successful registration's
/// response was lost must get `Ok((_, false))` on retry, not a permanent
/// "expires too soon" — the operator already committed to the channel.
#[test]
fn registration_replay_survives_runway_drift() {
    deterministic::Runner::default().start(|context| async move {
        let (chain, mut payer, service) = setup(&context).await;
        let receiver_account = *service.operator_account();

        // Just enough runway to register now, but not after a few blocks.
        let expiry = chain.0.lock().await.height() + MARGINS.min_runway + 3;
        let (channel, open_digest, _open_nonce) = payer
            .open_channel(&chain, receiver_account, DEPOSIT, expiry)
            .await;
        assert_eq!(
            service
                .register_channel(&open_digest, payer.zero_voucher(channel))
                .await,
            Ok((channel, true))
        );

        // Advance the chain until a fresh registration would be refused.
        for _ in 0..4 {
            let mint = payer.mint(1);
            chain.0.lock().await.commit(vec![mint]).await;
        }
        service.refresh_height().await.expect("height refresh");
        // Prove the drift consumed the runway: a NEW channel with the same
        // expiry is refused...
        let (fresh_channel, fresh_digest, _open_nonce) = payer
            .open_channel(&chain, receiver_account, DEPOSIT, expiry)
            .await;
        assert!(
            service
                .register_channel(&fresh_digest, payer.zero_voucher(fresh_channel))
                .await
                .is_err(),
            "a fresh registration inside the margin must be refused"
        );

        // ...while the replay (lost-response retry) is still answered
        // idempotently.
        assert_eq!(
            service
                .register_channel(&open_digest, payer.zero_voucher(channel))
                .await,
            Ok((channel, false)),
            "a matching replay must not be re-gated on runway"
        );
    });
}

/// The zero-voucher registration's promise, end to end: a channel that never
/// pays is still closeable. Settling it submits a cumulative-0 close (the
/// cooperative cancel), the payer gets the whole escrow back, the receiver
/// is never written, and the channel leaves no state.
#[test]
fn never_paid_channel_settles_with_a_zero_close() {
    deterministic::Runner::default().start(|context| async move {
        let (chain, mut payer, service) = setup(&context).await;
        let receiver_account = *service.operator_account();

        let expiry = chain.0.lock().await.height() + 100;
        let (channel, open_digest, _open_nonce) = payer
            .open_channel(&chain, receiver_account, DEPOSIT, expiry)
            .await;
        assert_eq!(
            service
                .register_channel(&open_digest, payer.zero_voucher(channel))
                .await,
            Ok((channel, true))
        );

        // No voucher is ever served; the settle claims the initial zero.
        let outcome = service.settle_channel(channel).await.expect("settle");
        assert_eq!(
            outcome,
            SettleOutcome {
                settled: true,
                cumulative: 0,
            }
        );

        let harness = chain.0.lock().await;
        assert_eq!(
            read_account(&harness.dbs, &payer.account).await.balance,
            FUNDED,
            "the whole escrow refunds to the payer"
        );
        // The receiver (here also the close-signing operator, whose nonce
        // consumption writes its account) is paid nothing.
        assert_eq!(
            read_account(&harness.dbs, &receiver_account).await.balance,
            0,
            "a zero-cumulative close pays the receiver nothing"
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

        let (channel, open_digest, _open_nonce) = payer
            .open_channel(&chain, receiver_account, DEPOSIT, CHANNEL_NEVER_EXPIRES)
            .await;
        assert_eq!(
            service
                .register_channel(&open_digest, payer.zero_voucher(channel))
                .await,
            Ok((channel, true))
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
