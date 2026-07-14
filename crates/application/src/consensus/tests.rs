use super::{
    Application, Databases, StateSyncTarget, TransactionHistoryTarget, genesis_block,
    history::parent_transactions_inactivity_floor,
};
use crate::operator::service::{RegisteredChannel, VerifiedOpenChannel};
use commonware_consensus::{
    simplex::{
        scheme::bls12381_threshold::standard as threshold, types::Context as SimplexContext,
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    Digest as _, Hasher as _, Signer as _, bls12381::primitives::variant::MinSig, ed25519,
    secp256r1::standard as secp256r1, sha256,
};
use commonware_glue::stateful::db::{DatabaseSet as _, Merkleized as _, Unmerkleized as _};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{
    journal::contiguous::{
        fixed::Config as FixedJournalConfig, variable::Config as VariableJournalConfig,
    },
    merkle::{full::Config as MmrConfig, mmr},
    qmdb::{any::FixedConfig, batch_chain::Bounds, keyless::fixed as keyless_fixed},
    translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range};
use constantinople_mempool::mocks::StaticTransactionSource;
use constantinople_primitives::{
    Account, AccountKey, Block, CHANNEL_NEVER_EXPIRES, Header, Operation, PublicKeyCache, Sealable,
    SealedBlock, SignedTransaction, Transaction, TransactionPublicKey, TransactionSignature,
    Voucher, channel_address,
};
use std::{num::NonZeroU64, time::Duration};

pub(crate) type TestApp = Application<
    deterministic::Context,
    sha256::Sha256,
    sha256::Digest,
    threshold::Scheme<ed25519::PublicKey, MinSig>,
    ed25519::PublicKey,
    StaticTransactionSource<sha256::Digest, ed25519::PublicKey, sha256::Sha256>,
    (),
    Sequential,
>;
pub(crate) type TestDbs = Databases<deterministic::Context, sha256::Sha256, EightCap, Sequential>;

pub(crate) const TEST_TX_NS: &[u8] = b"constantinople-application-test-transactions";

fn empty_state_target() -> StateSyncTarget<sha256::Digest> {
    StateSyncTarget::new(
        sha256::Digest::EMPTY,
        non_empty_range!(mmr::Location::new(0), mmr::Location::new(1)),
    )
}

fn state_config(cache: CacheRef) -> FixedConfig<EightCap, Sequential> {
    FixedConfig {
        merkle_config: MmrConfig {
            journal_partition: "verify-invalid-state-merkle-journal".into(),
            metadata_partition: "verify-invalid-state-merkle-metadata".into(),
            items_per_blob: NZU64!(1024),
            write_buffer: NZUsize!(4096),
            strategy: Sequential,
            page_cache: cache.clone(),
        },
        journal_config: FixedJournalConfig {
            partition: "verify-invalid-state-log".into(),
            items_per_blob: NZU64!(1024),
            page_cache: cache,
            write_buffer: NZUsize!(4096),
        },
        translator: EightCap,
    }
}

fn transaction_config(cache: CacheRef) -> keyless_fixed::CompactConfig<Sequential> {
    keyless_fixed::CompactConfig {
        strategy: Sequential,
        witness: VariableJournalConfig {
            partition: "verify-invalid-transactions-witness".into(),
            items_per_section: NZU64!(1024),
            compression: None,
            codec_config: (),
            page_cache: cache,
            write_buffer: NZUsize!(4096),
        },
        commit_codec_config: (),
    }
}

fn sync_range_from_bounds(
    bounds: &Bounds<mmr::Family>,
) -> commonware_utils::range::NonEmptyRange<mmr::Location> {
    non_empty_range!(
        bounds.inactivity_floor,
        mmr::Location::new(bounds.total_size)
    )
}

#[test]
fn verify_rejects_invalid_body() {
    deterministic::Runner::default().start(|context| async move {
        let cache = CacheRef::from_pooler(&context, NZU16!(16), NZUsize!(4096));
        let dbs = TestDbs::init(
            context.child("dbs"),
            (
                state_config(cache.clone()),
                transaction_config(cache.clone()),
            ),
        )
        .await;
        let (state_batch, transaction_batch) = dbs.new_batches().await;
        let state = state_batch.merkleize().await.expect("genesis state");
        let transactions = transaction_batch
            .merkleize()
            .await
            .expect("genesis transactions");
        let state_target =
            StateSyncTarget::new(state.root(), sync_range_from_bounds(state.bounds()));
        let transaction_target = TransactionHistoryTarget::new(
            transactions.root(),
            mmr::Location::new(transactions.bounds().total_size),
        );
        dbs.finalize((state, transactions)).await;

        let leader = ed25519::PrivateKey::from_seed(21);
        let sender = ed25519::PrivateKey::from_seed(22);
        let recipient = ed25519::PrivateKey::from_seed(23);
        let mut app = TestApp::new(
            context.child("app"),
            Sequential,
            leader.public_key(),
            sha256::Digest::EMPTY,
            TEST_TX_NS,
            PublicKeyCache::new(context.child("public_key_cache"), NZUsize!(64)),
            state_target.clone(),
            transaction_target.clone(),
            None,
        );
        let parent = genesis_block::<sha256::Digest, _, sha256::Sha256>(
            &mut sha256::Sha256::default(),
            leader.public_key(),
            0,
            state_target,
            transaction_target,
        );

        let tx = |value| {
            Transaction::transfer(
                TransactionPublicKey::ed25519(sender.public_key()),
                TransactionPublicKey::ed25519(recipient.public_key()),
                NonZeroU64::new(value).expect("test value should be non-zero"),
                0,
            )
            .seal_and_sign(&sender, TEST_TX_NS, &mut sha256::Sha256::default())
        };
        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };
        let header = Header {
            context: consensus_context.clone(),
            parent: *parent.seal(),
            height: 1,
            timestamp: 1,
            state_root: parent.header.state_root,
            state_range: parent.header.state_range.clone(),
            transactions_root: parent.header.transactions_root,
            transactions_range: parent.header.transactions_range.clone(),
        };
        let block = Block::<sha256::Digest, _, sha256::Sha256>::new(header, vec![tx(1), tx(2)])
            .seal(&mut sha256::Sha256::default());

        let result = app
            .verify_child(
                (context.child("verify"), consensus_context),
                block,
                &parent,
                dbs.new_batches().await,
            )
            .await;

        assert!(result.is_none());
    });
}

#[test]
fn parent_inactivity_floor_skips_the_parent_commit() {
    let leader = ed25519::PrivateKey::from_seed(7);
    let recipient = ed25519::PrivateKey::from_seed(8);
    let genesis_target = TransactionHistoryTarget {
        root: sha256::Digest::EMPTY,
        leaf_count: commonware_storage::mmr::Location::new(1),
    };
    let mut header = genesis_block::<sha256::Digest, _, sha256::Sha256>(
        &mut sha256::Sha256::default(),
        leader.public_key(),
        0,
        empty_state_target(),
        genesis_target,
    )
    .into_inner()
    .header;
    header.transactions_range = non_empty_range!(5, 10);

    let to = recipient.public_key();
    let parent = Block::<sha256::Digest, _, sha256::Sha256>::new(
        header,
        (0..3)
            .map(|nonce| {
                Transaction::transfer(
                    TransactionPublicKey::ed25519(leader.public_key()),
                    TransactionPublicKey::ed25519(to.clone()),
                    NonZeroU64::new(nonce + 1).expect("test value should be non-zero"),
                    nonce,
                )
                .seal_and_sign(
                    &leader,
                    constantinople_primitives::TRANSACTION_NAMESPACE,
                    &mut sha256::Sha256::default(),
                )
            })
            .collect(),
    )
    .seal(&mut sha256::Sha256::default());

    assert_eq!(
        parent_transactions_inactivity_floor(&parent),
        commonware_storage::mmr::Location::new(6)
    );
}

pub(crate) type TestTx = SignedTransaction<sha256::Sha256>;
pub(crate) type TestBlock = SealedBlock<sha256::Digest, ed25519::PublicKey, sha256::Sha256>;

/// Boots a fresh chain: initialized databases, an application, and the genesis
/// block to build on.
pub(crate) async fn bootstrap(
    context: &deterministic::Context,
) -> (TestDbs, TestApp, TestBlock, ed25519::PublicKey) {
    let cache = CacheRef::from_pooler(context, NZU16!(16), NZUsize!(4096));
    let dbs = TestDbs::init(
        context.child("dbs"),
        (
            state_config(cache.clone()),
            transaction_config(cache.clone()),
        ),
    )
    .await;
    let (state_batch, transaction_batch) = dbs.new_batches().await;
    let state = state_batch.merkleize().await.expect("genesis state");
    let transactions = transaction_batch
        .merkleize()
        .await
        .expect("genesis transactions");
    let state_target = StateSyncTarget::new(state.root(), sync_range_from_bounds(state.bounds()));
    let transaction_target = TransactionHistoryTarget::new(
        transactions.root(),
        mmr::Location::new(transactions.bounds().total_size),
    );
    dbs.finalize((state, transactions)).await;

    let leader = ed25519::PrivateKey::from_seed(1);
    let app = TestApp::new(
        context.child("app"),
        Sequential,
        leader.public_key(),
        sha256::Digest::EMPTY,
        TEST_TX_NS,
        PublicKeyCache::new(context.child("public_key_cache"), NZUsize!(64)),
        state_target.clone(),
        transaction_target.clone(),
        None,
    );
    let parent = genesis_block::<sha256::Digest, _, sha256::Sha256>(
        &mut sha256::Sha256::default(),
        leader.public_key(),
        0,
        state_target,
        transaction_target,
    );
    (dbs, app, parent, leader.public_key())
}

/// Proposes a child block carrying `txs`, finalizes the result, and returns the
/// proposed block together with the number of transactions it actually
/// included (zero means the proposal rejected the body).
pub(crate) async fn propose_and_finalize(
    app: &mut TestApp,
    context: &deterministic::Context,
    dbs: &TestDbs,
    leader: &ed25519::PublicKey,
    parent: &TestBlock,
    txs: Vec<TestTx>,
) -> (TestBlock, usize) {
    let height = parent.header.height + 1;
    let consensus_context = SimplexContext {
        round: Round::new(Epoch::zero(), View::new(height)),
        leader: leader.clone(),
        parent: (View::zero(), *parent.seal()),
    };
    let mut source = StaticTransactionSource::new(vec![txs]);
    let batches = dbs.new_batches().await;
    let proposed = app
        .propose_child(
            (context.child("propose"), consensus_context),
            parent,
            batches,
            &mut source,
        )
        .await
        .expect("propose should produce a block");
    let included = proposed.block.body.len();
    dbs.finalize(proposed.merkleized).await;
    (proposed.block, included)
}

/// Reads an account from finalized state, defaulting like the executor.
pub(crate) async fn read_account(dbs: &TestDbs, key: &AccountKey) -> Account {
    read_raw(dbs, key).await.unwrap_or_default()
}

/// Reads the raw stored account, distinguishing an absent/deleted account
/// (`None`) from one that was explicitly written (even if empty).
pub(crate) async fn read_raw(dbs: &TestDbs, key: &AccountKey) -> Option<Account> {
    dbs.0
        .read()
        .await
        .get(key)
        .await
        .expect("state read should succeed")
}

const DEPOSIT: u64 = 50;
const STEP: u64 = 5;
const PAYMENTS: u64 = 4;
/// Amount test accounts mint for themselves before spending (accounts start
/// empty; tokens only enter through explicit mints).
const FUNDED: u64 = 100;

/// Builds a signed mint of [`FUNDED`] tokens at the signer's nonce 0.
fn mint_tx(signer: &ed25519::PrivateKey) -> TestTx {
    Transaction::mint(
        TransactionPublicKey::ed25519(signer.public_key()),
        NonZeroU64::new(FUNDED).expect("funding amount is non-zero"),
        0,
    )
    .seal_and_sign(signer, TEST_TX_NS, &mut sha256::Sha256::default())
}

/// Proposes a block minting [`FUNDED`] to each signer (consuming their nonce
/// 0), returning the funded chain tip to build on.
async fn fund(
    app: &mut TestApp,
    context: &deterministic::Context,
    dbs: &TestDbs,
    leader: &ed25519::PublicKey,
    parent: &TestBlock,
    signers: &[&ed25519::PrivateKey],
) -> TestBlock {
    let mints = signers.iter().map(|signer| mint_tx(signer)).collect();
    let (block, included) = propose_and_finalize(app, context, dbs, leader, parent, mints).await;
    assert_eq!(included, signers.len(), "every funding mint must land");
    block
}

/// The common two-party topology used by channel consensus tests.
///
/// Transaction ordering and assertions stay in each test; this fixture only
/// centralizes account derivation and the protocol's signed wire objects.
struct ChannelFixture {
    payer: ed25519::PrivateKey,
    receiver: ed25519::PrivateKey,
    payer_pk: TransactionPublicKey,
    receiver_pk: TransactionPublicKey,
    payer_key: AccountKey,
    receiver_key: AccountKey,
    open_nonce: u64,
    channel: AccountKey,
}

impl ChannelFixture {
    fn new(payer_seed: u64, receiver_seed: u64, open_nonce: u64) -> Self {
        let payer = ed25519::PrivateKey::from_seed(payer_seed);
        let receiver = ed25519::PrivateKey::from_seed(receiver_seed);
        let payer_pk = TransactionPublicKey::ed25519(payer.public_key());
        let receiver_pk = TransactionPublicKey::ed25519(receiver.public_key());
        let payer_key = AccountKey::from_public_key(&payer_pk);
        let receiver_key = AccountKey::from_public_key(&receiver_pk);
        let channel = channel_address(
            &payer_key,
            &receiver_key,
            &receiver_key,
            &payer.public_key(),
            open_nonce,
        );
        Self {
            payer,
            receiver,
            payer_pk,
            receiver_pk,
            payer_key,
            receiver_key,
            open_nonce,
            channel,
        }
    }

    fn open(&self, deposit: u64, expiry: u64) -> TestTx {
        Transaction::open_channel(
            self.payer_pk.clone(),
            self.receiver_key,
            self.receiver_key,
            self.payer.public_key(),
            NonZeroU64::new(deposit).expect("deposit is non-zero"),
            expiry,
            self.open_nonce,
        )
        .seal_and_sign(&self.payer, TEST_TX_NS, &mut sha256::Sha256::default())
    }

    fn voucher(&self, cumulative: u64) -> Voucher {
        Voucher::sign(&self.payer, self.channel, cumulative)
    }

    fn close(&self, voucher: &Voucher, nonce: u64) -> TestTx {
        Transaction::close_channel(
            self.receiver_pk.clone(),
            self.payer_key,
            self.receiver_key,
            self.payer.public_key(),
            self.open_nonce,
            voucher.cumulative,
            voucher.signature.clone(),
            nonce,
        )
        .seal_and_sign(&self.receiver, TEST_TX_NS, &mut sha256::Sha256::default())
    }

    fn timeout(&self, nonce: u64) -> TestTx {
        Transaction::timeout_channel(
            self.payer_pk.clone(),
            self.receiver_key,
            self.receiver_key,
            self.payer.public_key(),
            self.open_nonce,
            nonce,
        )
        .seal_and_sign(&self.payer, TEST_TX_NS, &mut sha256::Sha256::default())
    }
}

/// The full channel demo: open a channel, stream vouchers entirely off-chain,
/// then settle the latest voucher with a single on-chain transaction.
///
/// Proves the throughput claim end to end: `PAYMENTS` payments stream with
/// **zero** on-chain transactions, and the channel's whole lifecycle costs
/// exactly two on-chain transactions (open + settle), not one per payment.
#[test]
fn channel_streams_offchain_and_settles_onchain() {
    deterministic::Runner::default().start(|context| async move {
        let (dbs, mut app, genesis, leader) = bootstrap(&context).await;

        let channel = ChannelFixture::new(2, 3, 1);
        // The payer mints its working funds first (accounts start empty), so
        // the open consumes its next nonce — from which the channel address is
        // derived.
        let genesis = fund(
            &mut app,
            &context,
            &dbs,
            &leader,
            &genesis,
            &[&channel.payer],
        )
        .await;

        let mut chain_txs = 0;

        // --- On-chain: open + escrow the deposit. ---
        let open = channel.open(DEPOSIT, CHANNEL_NEVER_EXPIRES);
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &genesis, vec![open]).await;
        assert_eq!(included, 1, "opening a channel is one on-chain transaction");
        chain_txs += included;

        // Deposit locked: payer debited, channel funded with exactly the deposit.
        assert_eq!(
            read_account(&dbs, &channel.payer_key).await.balance,
            FUNDED - DEPOSIT
        );
        assert_eq!(read_account(&dbs, &channel.channel).await.balance, DEPOSIT);

        // --- Off-chain: stream PAYMENTS vouchers, verified locally. No chain txs. ---
        let mut meter = RegisteredChannel::new(
            &VerifiedOpenChannel {
                payer: channel.payer_key,
                receiver: channel.receiver_key,
                voucher_key: channel.payer.public_key(),
                operator: channel.receiver_key,
                open_nonce: channel.open_nonce,
                deposit: NZU64!(DEPOSIT),
                expiry: CHANNEL_NEVER_EXPIRES,
                tip_height: 0,
            },
            channel.voucher(0),
        );
        let mut latest = None;
        for i in 1..=PAYMENTS {
            let voucher = channel.voucher(i * STEP);
            assert_eq!(
                meter.serve(voucher.clone()),
                Ok(i * STEP),
                "operator accepts each monotonic voucher off-chain"
            );
            latest = Some(voucher);
        }
        let latest = latest.expect("at least one voucher streamed");
        assert_eq!(latest.cumulative, PAYMENTS * STEP);

        // --- On-chain: settle the latest voucher with a single transaction. ---
        let close = channel.close(&latest, 0);
        let (_block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![close]).await;
        assert_eq!(
            included, 1,
            "settling a channel is one on-chain transaction"
        );
        chain_txs += included;

        // Receiver received exactly the claimed amount; payer reclaimed the rest;
        // the channel is deleted, leaving no state.
        let claimed = PAYMENTS * STEP;
        assert_eq!(
            read_account(&dbs, &channel.receiver_key).await.balance,
            claimed
        );
        assert_eq!(
            read_account(&dbs, &channel.payer_key).await.balance,
            FUNDED - claimed,
            "payer reclaimed deposit minus the settled amount"
        );
        assert_eq!(
            read_raw(&dbs, &channel.channel).await,
            None,
            "settled channel is deleted, leaving no state"
        );

        // The whole lifecycle cost two on-chain transactions, not PAYMENTS.
        // (The demo is only meaningful when payments outnumber the two
        // lifecycle transactions, which `PAYMENTS` is chosen to satisfy.)
        const _: () = assert!(PAYMENTS > 2);
        assert_eq!(chain_txs, 2);
    });
}

/// A cross-lane account conflict must not blank the proposal: when a channel
/// operation touches an account the transfer lane writes in the same block,
/// the proposer drops only that channel operation and keeps the transfers —
/// otherwise a cheap transfer to a publicly-derivable account (every close
/// credits the operator's receiver account) could empty any block carrying a
/// channel operation.
#[test]
fn cross_lane_conflict_drops_only_the_conflicting_channel_op() {
    deterministic::Runner::default().start(|context| async move {
        let (dbs, mut app, genesis, leader) = bootstrap(&context).await;

        let sender = ed25519::PrivateKey::from_seed(31);
        let target = ed25519::PrivateKey::from_seed(32);
        let sender_pk = TransactionPublicKey::ed25519(sender.public_key());
        let target_pk = TransactionPublicKey::ed25519(target.public_key());
        let sender_key = AccountKey::from_public_key(&sender_pk);
        let target_key = AccountKey::from_public_key(&target_pk);
        let genesis = fund(&mut app, &context, &dbs, &leader, &genesis, &[&sender]).await;

        // The transfer credits `target` while the channel lane's mint from
        // `target` writes the same account: a same-block cross-lane conflict.
        let value = 7;
        let transfer = Transaction::transfer(
            sender_pk.clone(),
            target_pk.clone(),
            NonZeroU64::new(value).expect("test value is non-zero"),
            1, // nonce 0 was the funding mint
        )
        .seal_and_sign(&sender, TEST_TX_NS, &mut sha256::Sha256::default());
        let mint = mint_tx(&target);

        let (_block, included) = propose_and_finalize(
            &mut app,
            &context,
            &dbs,
            &leader,
            &genesis,
            vec![transfer, mint],
        )
        .await;

        assert_eq!(included, 1, "only the conflicting mint is dropped");
        assert_eq!(
            read_account(&dbs, &target_key).await.balance,
            value,
            "the transfer landed; the conflicting mint did not"
        );
        assert_eq!(
            read_account(&dbs, &sender_key).await.balance,
            FUNDED - value
        );
    });
}

/// The chain refuses to settle a voucher that claims more than the escrow, even
/// though the voucher signature itself is valid.
#[test]
fn chain_rejects_overclaim_voucher() {
    deterministic::Runner::default().start(|context| async move {
        let (dbs, mut app, genesis, leader) = bootstrap(&context).await;

        let channel = ChannelFixture::new(2, 3, 1);
        let genesis = fund(
            &mut app,
            &context,
            &dbs,
            &leader,
            &genesis,
            &[&channel.payer],
        )
        .await;

        let open = channel.open(DEPOSIT, CHANNEL_NEVER_EXPIRES);
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &genesis, vec![open]).await;
        assert_eq!(included, 1);

        // A validly-signed voucher claiming more than the deposit.
        let overclaim = channel.voucher(DEPOSIT + 10);
        let close = channel.close(&overclaim, 0);
        let (_block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![close]).await;
        assert_eq!(included, 0, "over-claim settlement must be rejected");

        // Escrow untouched.
        assert_eq!(read_account(&dbs, &channel.channel).await.balance, DEPOSIT);
    });
}

/// The chain refuses to settle a voucher whose signature was not produced by the
/// channel's payer.
#[test]
fn chain_rejects_forged_voucher() {
    deterministic::Runner::default().start(|context| async move {
        let (dbs, mut app, genesis, leader) = bootstrap(&context).await;

        let channel = ChannelFixture::new(2, 3, 1);
        let attacker = ed25519::PrivateKey::from_seed(99);
        let genesis = fund(
            &mut app,
            &context,
            &dbs,
            &leader,
            &genesis,
            &[&channel.payer],
        )
        .await;

        let open = channel.open(DEPOSIT, CHANNEL_NEVER_EXPIRES);
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &genesis, vec![open]).await;
        assert_eq!(included, 1);

        // Attacker signs a voucher for a channel they do not control.
        let forged = Voucher::sign(&attacker, channel.channel, STEP);
        let close = channel.close(&forged, 0);
        let (_block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![close]).await;
        assert_eq!(included, 0, "forged-voucher settlement must be rejected");
        assert_eq!(read_account(&dbs, &channel.channel).await.balance, DEPOSIT);
    });
}

/// Opening two channels from the same payer in a single block exercises the
/// channel lane's deduplicated state load (the payer key appears twice) and
/// sequential composition (the second open spends the balance the first left).
#[test]
fn multiple_opens_in_one_block_compose() {
    deterministic::Runner::default().start(|context| async move {
        let (dbs, mut app, genesis, leader) = bootstrap(&context).await;

        let payer = ed25519::PrivateKey::from_seed(2);
        let receiver_a = ed25519::PrivateKey::from_seed(3);
        let receiver_b = ed25519::PrivateKey::from_seed(4);
        let payer_pk = TransactionPublicKey::ed25519(payer.public_key());
        let payer_key = AccountKey::from_public_key(&payer_pk);
        let recv_a_pk = TransactionPublicKey::ed25519(receiver_a.public_key());
        let recv_b_pk = TransactionPublicKey::ed25519(receiver_b.public_key());
        // The payer mints first (nonce 0), so each open's address is derived
        // from its own later nonce (1 and 2).
        let genesis = fund(&mut app, &context, &dbs, &leader, &genesis, &[&payer]).await;
        let channel_a = channel_address(
            &payer_key,
            &AccountKey::from_public_key(&recv_a_pk),
            &AccountKey::from_public_key(&recv_a_pk),
            &payer.public_key(),
            1,
        );
        let channel_b = channel_address(
            &payer_key,
            &AccountKey::from_public_key(&recv_b_pk),
            &AccountKey::from_public_key(&recv_b_pk),
            &payer.public_key(),
            2,
        );

        let open_a = Transaction::open_channel(
            payer_pk.clone(),
            AccountKey::from_public_key(&recv_a_pk),
            AccountKey::from_public_key(&recv_a_pk),
            payer.public_key(),
            NonZeroU64::new(30).expect("deposit is non-zero"),
            CHANNEL_NEVER_EXPIRES,
            1,
        )
        .seal_and_sign(&payer, TEST_TX_NS, &mut sha256::Sha256::default());
        let open_b = Transaction::open_channel(
            payer_pk.clone(),
            AccountKey::from_public_key(&recv_b_pk),
            AccountKey::from_public_key(&recv_b_pk),
            payer.public_key(),
            NonZeroU64::new(20).expect("deposit is non-zero"),
            CHANNEL_NEVER_EXPIRES,
            2,
        )
        .seal_and_sign(&payer, TEST_TX_NS, &mut sha256::Sha256::default());

        let (_block, included) = propose_and_finalize(
            &mut app,
            &context,
            &dbs,
            &leader,
            &genesis,
            vec![open_a, open_b],
        )
        .await;
        assert_eq!(included, 2, "both opens land in one block");

        // The payer is debited both deposits; each channel holds exactly its own.
        assert_eq!(
            read_account(&dbs, &payer_key).await.balance,
            FUNDED - 30 - 20
        );
        assert_eq!(read_account(&dbs, &channel_a).await.balance, 30);
        assert_eq!(read_account(&dbs, &channel_b).await.balance, 20);
    });
}

/// An old voucher cannot be replayed once its channel has settled. The channel
/// address is derived from the open nonce (which never recurs), so the settled
/// channel is deleted and can never be re-funded — resubmitting the same
/// voucher is rejected, and the receiver is not paid twice.
#[test]
fn settled_voucher_cannot_be_replayed() {
    deterministic::Runner::default().start(|context| async move {
        let (dbs, mut app, genesis, leader) = bootstrap(&context).await;

        let channel = ChannelFixture::new(2, 3, 1);
        let genesis = fund(
            &mut app,
            &context,
            &dbs,
            &leader,
            &genesis,
            &[&channel.payer],
        )
        .await;

        let open = channel.open(DEPOSIT, CHANNEL_NEVER_EXPIRES);
        let (block, _) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &genesis, vec![open]).await;

        let voucher = channel.voucher(STEP);
        // `nonce` is the receiver's transaction nonce; both closes carry the
        // same voucher.
        let close = |nonce| channel.close(&voucher, nonce);

        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![close(0)]).await;
        assert_eq!(included, 1, "first settlement succeeds");
        assert_eq!(
            read_raw(&dbs, &channel.channel).await,
            None,
            "channel deleted after settlement"
        );
        let receiver_balance = read_account(&dbs, &channel.receiver_key).await.balance;

        // Replaying the same voucher is rejected — the channel is gone.
        let (_block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![close(1)]).await;
        assert_eq!(included, 0, "replayed voucher must be rejected");
        assert_eq!(
            read_account(&dbs, &channel.receiver_key).await.balance,
            receiver_balance,
            "receiver is not paid twice"
        );
    });
}

/// Documents a known limitation of the no-residual-state design: deleting a
/// settled channel stops replay against a *new* channel, but not against the
/// *same* address if it is re-funded. The address is publicly derivable and an
/// ordinary transfer can credit it after settlement, at which point the old
/// (still validly signed) voucher settles again. This only ever happens by a
/// deliberate transfer to a dead address — no `OpenChannel` can trigger it — so
/// it cannot arise in normal operation; the channel module doc explains the
/// trade-off against keeping a durable closed-marker.
#[test]
fn refunding_a_settled_channel_address_enables_replay() {
    deterministic::Runner::default().start(|context| async move {
        let (dbs, mut app, genesis, leader) = bootstrap(&context).await;

        let channel = ChannelFixture::new(2, 3, 1);
        let genesis = fund(
            &mut app,
            &context,
            &dbs,
            &leader,
            &genesis,
            &[&channel.payer],
        )
        .await;

        let open = channel.open(DEPOSIT, CHANNEL_NEVER_EXPIRES);
        let (block, _) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &genesis, vec![open]).await;

        let voucher = channel.voucher(STEP);
        let close = |nonce| channel.close(&voucher, nonce);

        // First settlement deletes the channel.
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![close(0)]).await;
        assert_eq!(included, 1);
        assert_eq!(
            read_raw(&dbs, &channel.channel).await,
            None,
            "channel deleted"
        );
        let receiver_after_first = read_account(&dbs, &channel.receiver_key).await.balance;

        // An ordinary transfer re-funds the (publicly derivable) dead address.
        let refund = Transaction::with_op(
            channel.payer_pk.clone(),
            2,
            Operation::Transfer {
                to: channel.channel,
                value: NonZeroU64::new(STEP).expect("step is non-zero"),
            },
        )
        .seal_and_sign(&channel.payer, TEST_TX_NS, &mut sha256::Sha256::default());
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![refund]).await;
        assert_eq!(included, 1, "transfer to the dead channel address lands");
        // The address is live again; the transfer lane credits onto the funded
        // default, so the exact balance is incidental — what matters is that an
        // old voucher can now find escrow here.
        assert!(
            read_raw(&dbs, &channel.channel).await.is_some(),
            "channel re-funded"
        );

        // The same old voucher now settles again — the documented replay gap.
        let (_block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![close(1)]).await;
        assert_eq!(included, 1, "replay against the re-funded address succeeds");
        assert_eq!(
            read_account(&dbs, &channel.receiver_key).await.balance,
            receiver_after_first + STEP,
            "receiver is paid a second time"
        );
    });
}

/// A block carrying a channel settlement that one node proposes is accepted by
/// another node verifying it: the proposer and verifier re-execute the same
/// channel lane and agree on the resulting commitments. This guards the
/// consensus-critical invariant for the new lane.
#[test]
fn verifier_accepts_a_proposed_channel_block() {
    deterministic::Runner::default().start(|context| async move {
        let (dbs, mut app, genesis, leader) = bootstrap(&context).await;

        let channel = ChannelFixture::new(2, 3, 1);
        let genesis = fund(
            &mut app,
            &context,
            &dbs,
            &leader,
            &genesis,
            &[&channel.payer],
        )
        .await;

        let open = channel.open(DEPOSIT, CHANNEL_NEVER_EXPIRES);
        let (parent, _) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &genesis, vec![open]).await;

        // Advance the clock so the settlement block has a strictly greater
        // timestamp than its parent (a child-timestamp validity requirement).
        context.sleep(Duration::from_secs(1)).await;

        let voucher = channel.voucher(STEP);
        let close = channel.close(&voucher, 0);

        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(parent.header.height + 1)),
            leader: leader.clone(),
            parent: (View::zero(), *parent.seal()),
        };

        // Proposer path: build the settlement block.
        let mut source = StaticTransactionSource::new(vec![vec![close]]);
        let proposed = app
            .propose_child(
                (context.child("propose"), consensus_context.clone()),
                &parent,
                dbs.new_batches().await,
                &mut source,
            )
            .await
            .expect("proposer should produce a block");
        assert_eq!(proposed.block.body.len(), 1, "settlement was included");

        // Verifier path: a different node re-executes the same block and must
        // accept it (its commitments match the proposer's).
        let verified = app
            .verify_child(
                (context.child("verify"), consensus_context),
                proposed.block.clone(),
                &parent,
                dbs.new_batches().await,
            )
            .await;
        assert!(
            verified.is_some(),
            "verifier must accept the proposer's channel block"
        );
    });
}

/// A channel opened by a non-Ed25519 (secp256r1) payer is accepted. Vouchers
/// are signed by the delegated Ed25519 voucher key named in the open, not by
/// the payer's transaction key, so a secp256r1 (passkey-style) account can
/// open channels by delegating voucher signing to an Ed25519 key.
#[test]
fn open_channel_accepts_non_ed25519_payer() {
    deterministic::Runner::default().start(|context| async move {
        let (dbs, mut app, genesis, leader) = bootstrap(&context).await;

        let payer = secp256r1::PrivateKey::from_seed(2);
        let receiver = ed25519::PrivateKey::from_seed(3);
        let funder = ed25519::PrivateKey::from_seed(4);
        // The delegated Ed25519 key that will sign this channel's vouchers on
        // the secp256r1 payer's behalf.
        let voucher_signer = ed25519::PrivateKey::from_seed(5);
        let payer_pk = TransactionPublicKey::secp256r1(payer.public_key());
        let receiver_pk = TransactionPublicKey::ed25519(receiver.public_key());
        let funder_pk = TransactionPublicKey::ed25519(funder.public_key());
        let payer_key = AccountKey::from_public_key(&payer_pk);
        let receiver_key = AccountKey::from_public_key(&receiver_pk);

        // Fund the secp256r1 payer with an ordinary transfer (`mint_tx` and
        // `seal_and_sign` are Ed25519-only, but any account can be credited).
        let genesis = fund(&mut app, &context, &dbs, &leader, &genesis, &[&funder]).await;
        let fund_payer = Transaction::with_op(
            funder_pk.clone(),
            1,
            Operation::Transfer {
                to: payer_key,
                value: NonZeroU64::new(DEPOSIT).expect("deposit is non-zero"),
            },
        )
        .seal_and_sign(&funder, TEST_TX_NS, &mut sha256::Sha256::default());
        let (block, included) = propose_and_finalize(
            &mut app,
            &context,
            &dbs,
            &leader,
            &genesis,
            vec![fund_payer],
        )
        .await;
        assert_eq!(included, 1, "funding transfer must land");

        // `seal_and_sign` only supports Ed25519 transaction signatures, and the
        // propose path does not verify the transaction signature, so build the
        // open with the secp256r1 payer and attach a placeholder signature.
        let open = Transaction::<sha256::Digest>::open_channel(
            payer_pk,
            receiver_key,
            receiver_key,
            voucher_signer.public_key(),
            NonZeroU64::new(DEPOSIT).expect("deposit is non-zero"),
            CHANNEL_NEVER_EXPIRES,
            0,
        );
        let sealed = open.seal(&mut sha256::Sha256::default());
        let placeholder = ed25519::PrivateKey::from_seed(99);
        let signature =
            TransactionSignature::ed25519(placeholder.sign(TEST_TX_NS, sealed.seal().as_ref()));
        let signed = SignedTransaction::new_unchecked(sealed, signature);

        let (_block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![signed]).await;
        assert_eq!(
            included, 1,
            "a non-Ed25519 payer's open with a delegated voucher key must execute"
        );

        // The deposit moved from the secp256r1 payer into the channel escrow.
        let channel = channel_address(
            &payer_key,
            &receiver_key,
            &receiver_key,
            &voucher_signer.public_key(),
            0,
        );
        assert_eq!(read_account(&dbs, &channel).await.balance, DEPOSIT);
        assert_eq!(read_account(&dbs, &payer_key).await.balance, 0);
    });
}

/// One poison channel operation must not empty an otherwise-valid proposal.
///
/// Channel operations can fail in ways the mempool cannot screen (a statically
/// invalid secp256r1 open passes signature checks; a close's validity depends
/// on execution-time escrow), so the proposer drops the failing operation
/// individually instead of collapsing the whole batch to an empty block.
#[test]
fn poison_channel_op_does_not_empty_the_proposal() {
    deterministic::Runner::default().start(|context| async move {
        let (dbs, mut app, genesis, leader) = bootstrap(&context).await;

        let alice = ed25519::PrivateKey::from_seed(2);
        let bob = ed25519::PrivateKey::from_seed(3);
        let payer = ed25519::PrivateKey::from_seed(4);
        let receiver = ed25519::PrivateKey::from_seed(5);
        let alice_pk = TransactionPublicKey::ed25519(alice.public_key());
        let bob_pk = TransactionPublicKey::ed25519(bob.public_key());
        let payer_pk = TransactionPublicKey::ed25519(payer.public_key());
        let receiver_pk = TransactionPublicKey::ed25519(receiver.public_key());
        let alice_key = AccountKey::from_public_key(&alice_pk);
        let bob_key = AccountKey::from_public_key(&bob_pk);
        let payer_key = AccountKey::from_public_key(&payer_pk);
        let receiver_key = AccountKey::from_public_key(&receiver_pk);

        // Fund the spenders (their mints consume nonce 0).
        let genesis = fund(
            &mut app,
            &context,
            &dbs,
            &leader,
            &genesis,
            &[&alice, &payer],
        )
        .await;

        // A valid transfer and a valid open, co-batched with the poison ops.
        let transfer = Transaction::with_op(
            alice_pk.clone(),
            1,
            Operation::Transfer {
                to: bob_key,
                value: NonZeroU64::new(STEP).expect("step is non-zero"),
            },
        )
        .seal_and_sign(&alice, TEST_TX_NS, &mut sha256::Sha256::default());
        let open = Transaction::open_channel(
            payer_pk.clone(),
            receiver_key,
            receiver_key,
            payer.public_key(),
            NonZeroU64::new(DEPOSIT).expect("deposit is non-zero"),
            CHANNEL_NEVER_EXPIRES,
            1,
        )
        .seal_and_sign(&payer, TEST_TX_NS, &mut sha256::Sha256::default());

        // Semantically invalid: an open from an unfunded secp256r1 payer
        // prepares fine (the voucher key is delegated, so the payer's scheme
        // no longer matters) but fails at execution for lack of balance.
        let secp = secp256r1::PrivateKey::from_seed(6);
        let secp_pk = TransactionPublicKey::secp256r1(secp.public_key());
        let sealed_bad_open = Transaction::<sha256::Digest>::open_channel(
            secp_pk,
            receiver_key,
            receiver_key,
            payer.public_key(),
            NonZeroU64::new(DEPOSIT).expect("deposit is non-zero"),
            CHANNEL_NEVER_EXPIRES,
            0,
        )
        .seal(&mut sha256::Sha256::default());
        let placeholder = ed25519::PrivateKey::from_seed(99);
        let signature = TransactionSignature::ed25519(
            placeholder.sign(TEST_TX_NS, sealed_bad_open.seal().as_ref()),
        );
        let bad_open = SignedTransaction::new_unchecked(sealed_bad_open, signature);

        // Semantically invalid: a validly signed close of a channel that was
        // never opened, only detectable at execution time.
        let phantom = channel_address(
            &payer_key,
            &receiver_key,
            &receiver_key,
            &payer.public_key(),
            7,
        );
        let voucher = Voucher::sign(&payer, phantom, STEP);
        let bad_close = Transaction::close_channel(
            receiver_pk.clone(),
            payer_key,
            AccountKey::from_public_key(&receiver_pk),
            payer.public_key(),
            7,
            voucher.cumulative,
            voucher.signature.clone(),
            0,
        )
        .seal_and_sign(&receiver, TEST_TX_NS, &mut sha256::Sha256::default());

        let (_block, included) = propose_and_finalize(
            &mut app,
            &context,
            &dbs,
            &leader,
            &genesis,
            vec![transfer, bad_open, bad_close, open],
        )
        .await;
        assert_eq!(included, 2, "only the poison channel ops are dropped");

        // Both valid transactions took effect.
        assert_eq!(read_account(&dbs, &alice_key).await.balance, FUNDED - STEP);
        assert_eq!(read_account(&dbs, &bob_key).await.balance, STEP);
        assert_eq!(
            read_account(&dbs, &payer_key).await.balance,
            FUNDED - DEPOSIT
        );
        assert_eq!(
            read_account(
                &dbs,
                &channel_address(
                    &payer_key,
                    &receiver_key,
                    &receiver_key,
                    &payer.public_key(),
                    1
                )
            )
            .await
            .balance,
            DEPOSIT
        );
        // The skipped ops left no trace: the phantom channel does not exist and
        // the bad close's nonce was not consumed.
        assert_eq!(read_raw(&dbs, &phantom).await, None);
        assert_eq!(
            read_account(&dbs, &receiver_key).await.nonce.base,
            0,
            "skipped close must not consume the receiver's nonce"
        );
    });
}

/// A timeout is rejected while the channel is unexpired, reclaims the entire
/// escrow once the block height exceeds the expiry, and leaves nothing for a
/// late close to settle.
#[test]
fn timeout_respects_expiry_then_reclaims() {
    deterministic::Runner::default().start(|context| async move {
        let (dbs, mut app, genesis, leader) = bootstrap(&context).await;

        let channel = ChannelFixture::new(2, 3, 1);
        let genesis = fund(
            &mut app,
            &context,
            &dbs,
            &leader,
            &genesis,
            &[&channel.payer],
        )
        .await;
        // The funding mint lands at height 1 and the open at height 2, so the
        // channel is expired (reclaimable) from height 4 on.
        let expiry = 3;

        let open = channel.open(DEPOSIT, expiry);
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &genesis, vec![open]).await;
        assert_eq!(included, 1);
        // The channel account's (otherwise unusable) nonce slot records the
        // expiry.
        let stored = read_raw(&dbs, &channel.channel)
            .await
            .expect("channel exists");
        assert_eq!(stored.nonce.base, expiry);
        assert_eq!(stored.balance, DEPOSIT);

        // The payer signs a voucher off-chain; the receiver will miss the
        // deadline and forfeit it.
        let voucher = channel.voucher(STEP);

        let timeout = channel.timeout(2);

        // Height 3 is not past the expiry; the timeout is rejected and the
        // channel is untouched.
        let (block, included) = propose_and_finalize(
            &mut app,
            &context,
            &dbs,
            &leader,
            &block,
            vec![timeout.clone()],
        )
        .await;
        assert_eq!(included, 0, "timeout before expiry must be rejected");
        assert_eq!(read_account(&dbs, &channel.channel).await.balance, DEPOSIT);

        // Height 4 exceeds the expiry; the same transaction now reclaims the
        // full escrow and deletes the channel.
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![timeout]).await;
        assert_eq!(included, 1, "timeout after expiry reclaims the channel");
        assert_eq!(
            read_account(&dbs, &channel.payer_key).await.balance,
            FUNDED,
            "payer reclaimed the entire escrow"
        );
        assert_eq!(
            read_raw(&dbs, &channel.channel).await,
            None,
            "channel deleted"
        );

        // The receiver's (still validly signed) voucher is now worthless.
        let close = channel.close(&voucher, 0);
        let (_block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![close]).await;
        assert_eq!(included, 0, "close after reclaim must be rejected");
        assert_eq!(read_account(&dbs, &channel.receiver_key).await.balance, 0);
    });
}

/// A close is valid at any height while the channel exists: even past the
/// expiry, a close that lands before the payer's timeout settles normally and
/// leaves nothing to reclaim.
#[test]
fn close_beats_timeout_after_expiry() {
    deterministic::Runner::default().start(|context| async move {
        let (dbs, mut app, genesis, leader) = bootstrap(&context).await;

        let channel = ChannelFixture::new(2, 3, 1);
        let genesis = fund(
            &mut app,
            &context,
            &dbs,
            &leader,
            &genesis,
            &[&channel.payer],
        )
        .await;

        // Expired as soon as the next block: the open lands at height 2 and
        // the expiry is 2.
        let open = channel.open(DEPOSIT, 2);
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &genesis, vec![open]).await;
        assert_eq!(included, 1);

        // The close still settles at height 3 (> expiry) because the channel
        // exists until someone deletes it.
        let voucher = channel.voucher(STEP);
        let close = channel.close(&voucher, 0);
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![close]).await;
        assert_eq!(included, 1, "close settles even after expiry");
        assert_eq!(
            read_account(&dbs, &channel.receiver_key).await.balance,
            STEP
        );

        // The payer's timeout finds no channel.
        let timeout = channel.timeout(2);
        let (_block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![timeout]).await;
        assert_eq!(included, 0, "timeout after close finds no channel");
        assert_eq!(
            read_account(&dbs, &channel.payer_key).await.balance,
            FUNDED - STEP,
            "payer keeps only the close refund"
        );
    });
}

/// A zero-cumulative close is a cooperative early cancel: the payer signs a
/// zero voucher, the operator settles, the full escrow refunds the payer —
/// and the receiver, owed nothing, is never written (execution never writes
/// an empty account; see `apply_channel_writes`).
#[test]
fn zero_cumulative_close_cancels_without_writing_the_receiver() {
    deterministic::Runner::default().start(|context| async move {
        let (dbs, mut app, genesis, leader) = bootstrap(&context).await;

        let payer = ed25519::PrivateKey::from_seed(2);
        let receiver = ed25519::PrivateKey::from_seed(3);
        let operator = ed25519::PrivateKey::from_seed(4);
        let payer_pk = TransactionPublicKey::ed25519(payer.public_key());
        let receiver_pk = TransactionPublicKey::ed25519(receiver.public_key());
        let operator_pk = TransactionPublicKey::ed25519(operator.public_key());
        let payer_key = AccountKey::from_public_key(&payer_pk);
        let receiver_key = AccountKey::from_public_key(&receiver_pk);
        let operator_key = AccountKey::from_public_key(&operator_pk);
        let genesis = fund(&mut app, &context, &dbs, &leader, &genesis, &[&payer]).await;
        let open_nonce: u64 = 1;
        let channel = channel_address(
            &payer_key,
            &receiver_key,
            &operator_key,
            &payer.public_key(),
            open_nonce,
        );

        let open = Transaction::open_channel(
            payer_pk.clone(),
            receiver_key,
            operator_key,
            payer.public_key(),
            NonZeroU64::new(DEPOSIT).expect("deposit is non-zero"),
            1_000,
            open_nonce,
        )
        .seal_and_sign(&payer, TEST_TX_NS, &mut sha256::Sha256::default());
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &genesis, vec![open]).await;
        assert_eq!(included, 1);

        // The payer authorizes the cancel by signing a voucher over zero.
        let voucher = Voucher::sign(&payer, channel, 0);
        let close = Transaction::close_channel(
            operator_pk.clone(),
            payer_key,
            receiver_key,
            payer.public_key(),
            open_nonce,
            voucher.cumulative,
            voucher.signature.clone(),
            0,
        )
        .seal_and_sign(&operator, TEST_TX_NS, &mut sha256::Sha256::default());
        let (_block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![close]).await;
        assert_eq!(included, 1, "zero-cumulative close settles");

        assert_eq!(
            read_account(&dbs, &payer_key).await.balance,
            FUNDED,
            "the full escrow refunds the payer"
        );
        assert_eq!(read_raw(&dbs, &channel).await, None, "channel deleted");
        assert_eq!(
            read_raw(&dbs, &receiver_key).await,
            None,
            "a receiver owed nothing is never written"
        );
    });
}

/// Minting is the chain's only token source: accounts start empty, credit
/// themselves explicitly, and repeated mints accumulate.
#[test]
fn mint_credits_the_sender() {
    deterministic::Runner::default().start(|context| async move {
        let (dbs, mut app, genesis, leader) = bootstrap(&context).await;

        let minter = ed25519::PrivateKey::from_seed(2);
        let minter_pk = TransactionPublicKey::ed25519(minter.public_key());
        let minter_key = AccountKey::from_public_key(&minter_pk);
        assert_eq!(
            read_raw(&dbs, &minter_key).await,
            None,
            "accounts start unwritten and empty"
        );

        let block = fund(&mut app, &context, &dbs, &leader, &genesis, &[&minter]).await;
        assert_eq!(read_account(&dbs, &minter_key).await.balance, FUNDED);

        // A second mint accumulates on top of the first.
        let again = Transaction::mint(
            minter_pk.clone(),
            NonZeroU64::new(7).expect("amount is non-zero"),
            1,
        )
        .seal_and_sign(&minter, TEST_TX_NS, &mut sha256::Sha256::default());
        let (_block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![again]).await;
        assert_eq!(included, 1);
        let account = read_account(&dbs, &minter_key).await;
        assert_eq!(account.balance, FUNDED + 7);
        assert_eq!(account.nonce.base, 2, "each mint consumes a nonce");
    });
}

/// A receiver whose balance sits at `u64::MAX` must still be able to settle
/// channels and consume nonces: credits saturate instead of failing, so no
/// balance state can wedge the operator's close or its `Mint(1)` nonce burn.
/// The mint cap makes such a balance practically unreachable (the funding
/// mint below is forged above the cap, which only decoding enforces), but the
/// executor must stay total regardless of how state got there.
#[test]
fn saturated_receiver_still_settles_and_mints() {
    deterministic::Runner::default().start(|context| async move {
        let (dbs, mut app, genesis, leader) = bootstrap(&context).await;

        let payer = ed25519::PrivateKey::from_seed(2);
        let receiver = ed25519::PrivateKey::from_seed(3);
        let payer_pk = TransactionPublicKey::ed25519(payer.public_key());
        let receiver_pk = TransactionPublicKey::ed25519(receiver.public_key());
        let payer_key = AccountKey::from_public_key(&payer_pk);
        let receiver_key = AccountKey::from_public_key(&receiver_pk);

        // Fund the payer normally and saturate the receiver's balance.
        let max_mint = Transaction::mint(
            receiver_pk.clone(),
            NonZeroU64::new(u64::MAX).expect("amount is non-zero"),
            0,
        )
        .seal_and_sign(&receiver, TEST_TX_NS, &mut sha256::Sha256::default());
        let (block, included) = propose_and_finalize(
            &mut app,
            &context,
            &dbs,
            &leader,
            &genesis,
            vec![mint_tx(&payer), max_mint],
        )
        .await;
        assert_eq!(included, 2);
        assert_eq!(read_account(&dbs, &receiver_key).await.balance, u64::MAX);

        // Open a channel to the saturated receiver and settle it: the
        // receiver's credit saturates rather than failing the close.
        let open_nonce: u64 = 1;
        let channel = channel_address(
            &payer_key,
            &receiver_key,
            &receiver_key,
            &payer.public_key(),
            open_nonce,
        );
        let open = Transaction::open_channel(
            payer_pk.clone(),
            receiver_key,
            receiver_key,
            payer.public_key(),
            NonZeroU64::new(DEPOSIT).expect("deposit is non-zero"),
            CHANNEL_NEVER_EXPIRES,
            open_nonce,
        )
        .seal_and_sign(&payer, TEST_TX_NS, &mut sha256::Sha256::default());
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![open]).await;
        assert_eq!(included, 1, "open must land");

        let cumulative = STEP;
        let voucher = Voucher::sign(&payer, channel, cumulative);
        let close = Transaction::close_channel(
            receiver_pk.clone(),
            payer_key,
            AccountKey::from_public_key(&receiver_pk),
            payer.public_key(),
            open_nonce,
            cumulative,
            voucher.signature.clone(),
            1,
        )
        .seal_and_sign(&receiver, TEST_TX_NS, &mut sha256::Sha256::default());
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![close]).await;
        assert_eq!(
            included, 1,
            "close must land despite the saturated receiver"
        );
        let account = read_account(&dbs, &receiver_key).await;
        assert_eq!(account.balance, u64::MAX, "credit saturates, not fails");
        assert_eq!(account.nonce.base, 2, "close consumed the receiver's nonce");
        assert_eq!(
            read_account(&dbs, &payer_key).await.balance,
            FUNDED - cumulative,
            "payer reclaimed deposit minus the settled amount"
        );
        assert_eq!(read_raw(&dbs, &channel).await, None, "channel is deleted");

        // The operator's abandon path burns a nonce with `Mint(1)`; it must
        // stay valid when the balance cannot grow.
        let burn = Transaction::mint(
            receiver_pk.clone(),
            NonZeroU64::new(1).expect("amount is non-zero"),
            2,
        )
        .seal_and_sign(&receiver, TEST_TX_NS, &mut sha256::Sha256::default());
        let (_block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![burn]).await;
        assert_eq!(included, 1, "nonce burn must land on a saturated account");
        let account = read_account(&dbs, &receiver_key).await;
        assert_eq!(account.balance, u64::MAX);
        assert_eq!(account.nonce.base, 3, "burn consumed the nonce");
    });
}

#[test]
fn genesis_block_uses_the_initialized_transaction_target() {
    let leader = ed25519::PrivateKey::from_seed(11).public_key();
    let target = TransactionHistoryTarget {
        root: sha256::Sha256::hash(b"genesis"),
        leaf_count: commonware_storage::mmr::Location::new(1),
    };

    let block = genesis_block::<sha256::Digest, _, sha256::Sha256>(
        &mut sha256::Sha256::default(),
        leader,
        0,
        empty_state_target(),
        target.clone(),
    );

    assert_eq!(block.header.transactions_root, target.root);
    assert_eq!(block.header.transactions_range, non_empty_range!(0, 1));
}
