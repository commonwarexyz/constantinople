use super::{
    Application, Databases, StateSyncTarget, TransactionHistoryTarget, genesis_block,
    history::parent_transactions_inactivity_floor,
};
use crate::operator::ChannelOperator;
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

type TestApp = Application<
    deterministic::Context,
    sha256::Sha256,
    sha256::Digest,
    threshold::Scheme<ed25519::PublicKey, MinSig>,
    ed25519::PublicKey,
    StaticTransactionSource<sha256::Digest, ed25519::PublicKey, sha256::Sha256>,
    (),
    Sequential,
>;
type TestDbs = Databases<deterministic::Context, sha256::Sha256, EightCap, Sequential>;

const TEST_TX_NS: &[u8] = b"constantinople-application-test-transactions";

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
            Transaction::new(
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
                Transaction::new(
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

type TestTx = SignedTransaction<sha256::Sha256>;
type TestBlock = SealedBlock<sha256::Digest, ed25519::PublicKey, sha256::Sha256>;

/// Boots a fresh chain: initialized databases, an application, and the genesis
/// block to build on.
async fn bootstrap(
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
async fn propose_and_finalize(
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
async fn read_account(dbs: &TestDbs, key: &AccountKey) -> Account {
    read_raw(dbs, key).await.unwrap_or_default()
}

/// Reads the raw stored account, distinguishing an absent/deleted account
/// (`None`) from one that merely holds the default balance.
async fn read_raw(dbs: &TestDbs, key: &AccountKey) -> Option<Account> {
    dbs.0
        .read()
        .await
        .get(key)
        .await
        .expect("state read should succeed")
}

const DEPOSIT: u64 = 50;
const PRICE: u64 = 5;
const PAYMENTS: u64 = 4;

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

        let payer = ed25519::PrivateKey::from_seed(2);
        let receiver = ed25519::PrivateKey::from_seed(3);
        let payer_pk = TransactionPublicKey::ed25519(payer.public_key());
        let receiver_pk = TransactionPublicKey::ed25519(receiver.public_key());
        let payer_key = AccountKey::from_public_key(&payer_pk);
        let receiver_key = AccountKey::from_public_key(&receiver_pk);
        // The channel address is derived from the open transaction's nonce.
        let open_nonce: u64 = 0;
        let channel = channel_address(&payer_key, &receiver_key, open_nonce);

        let mut chain_txs = 0;

        // --- On-chain: open + escrow the deposit. ---
        let open = Transaction::open_channel(
            payer_pk.clone(),
            receiver_pk.clone(),
            NonZeroU64::new(DEPOSIT).expect("deposit is non-zero"),
            CHANNEL_NEVER_EXPIRES,
            open_nonce,
        )
        .seal_and_sign(&payer, TEST_TX_NS, &mut sha256::Sha256::default());
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &genesis, vec![open]).await;
        assert_eq!(included, 1, "opening a channel is one on-chain transaction");
        chain_txs += included;

        // Deposit locked: payer debited, channel funded with exactly the deposit.
        assert_eq!(read_account(&dbs, &payer_key).await.balance, 100 - DEPOSIT);
        assert_eq!(read_account(&dbs, &channel).await.balance, DEPOSIT);

        // --- Off-chain: stream PAYMENTS vouchers, verified locally. No chain txs. ---
        let mut operator = ChannelOperator::new(PRICE);
        operator.register_channel(channel, payer_pk.clone(), DEPOSIT);
        let mut latest = None;
        for i in 1..=PAYMENTS {
            let voucher = Voucher::sign(&payer, channel, i * PRICE);
            assert_eq!(
                operator.serve(&voucher),
                Ok(i * PRICE),
                "operator accepts each monotonic voucher off-chain"
            );
            latest = Some(voucher);
        }
        let latest = latest.expect("at least one voucher streamed");
        assert_eq!(latest.cumulative, PAYMENTS * PRICE);

        // --- On-chain: settle the latest voucher with a single transaction. ---
        let close = Transaction::close_channel(
            receiver_pk.clone(),
            payer_pk.clone(),
            open_nonce,
            latest.cumulative,
            latest.signature.clone(),
            0,
        )
        .seal_and_sign(&receiver, TEST_TX_NS, &mut sha256::Sha256::default());
        let (_block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![close]).await;
        assert_eq!(
            included, 1,
            "settling a channel is one on-chain transaction"
        );
        chain_txs += included;

        // Receiver received exactly the claimed amount; payer reclaimed the rest;
        // the channel is deleted, leaving no state.
        let claimed = PAYMENTS * PRICE;
        assert_eq!(
            read_account(&dbs, &receiver_key).await.balance,
            100 + claimed
        );
        assert_eq!(
            read_account(&dbs, &payer_key).await.balance,
            100 - claimed,
            "payer reclaimed deposit minus the settled amount"
        );
        assert_eq!(
            read_raw(&dbs, &channel).await,
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

/// The chain refuses to settle a voucher that claims more than the escrow, even
/// though the voucher signature itself is valid.
#[test]
fn chain_rejects_overclaim_voucher() {
    deterministic::Runner::default().start(|context| async move {
        let (dbs, mut app, genesis, leader) = bootstrap(&context).await;

        let payer = ed25519::PrivateKey::from_seed(2);
        let receiver = ed25519::PrivateKey::from_seed(3);
        let payer_pk = TransactionPublicKey::ed25519(payer.public_key());
        let receiver_pk = TransactionPublicKey::ed25519(receiver.public_key());
        let payer_key = AccountKey::from_public_key(&payer_pk);
        let receiver_key = AccountKey::from_public_key(&receiver_pk);
        let open_nonce: u64 = 0;
        let channel = channel_address(&payer_key, &receiver_key, open_nonce);

        let open = Transaction::open_channel(
            payer_pk.clone(),
            receiver_pk.clone(),
            NonZeroU64::new(DEPOSIT).expect("deposit is non-zero"),
            CHANNEL_NEVER_EXPIRES,
            open_nonce,
        )
        .seal_and_sign(&payer, TEST_TX_NS, &mut sha256::Sha256::default());
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &genesis, vec![open]).await;
        assert_eq!(included, 1);

        // A validly-signed voucher claiming more than the deposit.
        let overclaim = Voucher::sign(&payer, channel, DEPOSIT + 10);
        let close = Transaction::close_channel(
            receiver_pk.clone(),
            payer_pk.clone(),
            open_nonce,
            overclaim.cumulative,
            overclaim.signature.clone(),
            0,
        )
        .seal_and_sign(&receiver, TEST_TX_NS, &mut sha256::Sha256::default());
        let (_block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![close]).await;
        assert_eq!(included, 0, "over-claim settlement must be rejected");

        // Escrow untouched.
        assert_eq!(read_account(&dbs, &channel).await.balance, DEPOSIT);
    });
}

/// The chain refuses to settle a voucher whose signature was not produced by the
/// channel's payer.
#[test]
fn chain_rejects_forged_voucher() {
    deterministic::Runner::default().start(|context| async move {
        let (dbs, mut app, genesis, leader) = bootstrap(&context).await;

        let payer = ed25519::PrivateKey::from_seed(2);
        let receiver = ed25519::PrivateKey::from_seed(3);
        let attacker = ed25519::PrivateKey::from_seed(99);
        let payer_pk = TransactionPublicKey::ed25519(payer.public_key());
        let receiver_pk = TransactionPublicKey::ed25519(receiver.public_key());
        let payer_key = AccountKey::from_public_key(&payer_pk);
        let receiver_key = AccountKey::from_public_key(&receiver_pk);
        let open_nonce: u64 = 0;
        let channel = channel_address(&payer_key, &receiver_key, open_nonce);

        let open = Transaction::open_channel(
            payer_pk.clone(),
            receiver_pk.clone(),
            NonZeroU64::new(DEPOSIT).expect("deposit is non-zero"),
            CHANNEL_NEVER_EXPIRES,
            open_nonce,
        )
        .seal_and_sign(&payer, TEST_TX_NS, &mut sha256::Sha256::default());
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &genesis, vec![open]).await;
        assert_eq!(included, 1);

        // Attacker signs a voucher for a channel they do not control.
        let forged = Voucher::sign(&attacker, channel, PRICE);
        let close = Transaction::close_channel(
            receiver_pk.clone(),
            payer_pk.clone(),
            open_nonce,
            forged.cumulative,
            forged.signature.clone(),
            0,
        )
        .seal_and_sign(&receiver, TEST_TX_NS, &mut sha256::Sha256::default());
        let (_block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![close]).await;
        assert_eq!(included, 0, "forged-voucher settlement must be rejected");
        assert_eq!(read_account(&dbs, &channel).await.balance, DEPOSIT);
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
        // Each open's address is derived from its own nonce (0 and 1).
        let channel_a = channel_address(&payer_key, &AccountKey::from_public_key(&recv_a_pk), 0);
        let channel_b = channel_address(&payer_key, &AccountKey::from_public_key(&recv_b_pk), 1);

        let open_a = Transaction::open_channel(
            payer_pk.clone(),
            recv_a_pk,
            NonZeroU64::new(30).expect("deposit is non-zero"),
            CHANNEL_NEVER_EXPIRES,
            0,
        )
        .seal_and_sign(&payer, TEST_TX_NS, &mut sha256::Sha256::default());
        let open_b = Transaction::open_channel(
            payer_pk.clone(),
            recv_b_pk,
            NonZeroU64::new(20).expect("deposit is non-zero"),
            CHANNEL_NEVER_EXPIRES,
            1,
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
        assert_eq!(read_account(&dbs, &payer_key).await.balance, 100 - 30 - 20);
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

        let payer = ed25519::PrivateKey::from_seed(2);
        let receiver = ed25519::PrivateKey::from_seed(3);
        let payer_pk = TransactionPublicKey::ed25519(payer.public_key());
        let receiver_pk = TransactionPublicKey::ed25519(receiver.public_key());
        let payer_key = AccountKey::from_public_key(&payer_pk);
        let receiver_key = AccountKey::from_public_key(&receiver_pk);
        let open_nonce: u64 = 0;
        let channel = channel_address(&payer_key, &receiver_key, open_nonce);

        let open = Transaction::open_channel(
            payer_pk.clone(),
            receiver_pk.clone(),
            NonZeroU64::new(DEPOSIT).expect("deposit is non-zero"),
            CHANNEL_NEVER_EXPIRES,
            open_nonce,
        )
        .seal_and_sign(&payer, TEST_TX_NS, &mut sha256::Sha256::default());
        let (block, _) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &genesis, vec![open]).await;

        let voucher = Voucher::sign(&payer, channel, PRICE);
        // `nonce` is the receiver's transaction nonce; both closes carry the
        // same voucher.
        let close = |nonce: u64| {
            Transaction::close_channel(
                receiver_pk.clone(),
                payer_pk.clone(),
                open_nonce,
                voucher.cumulative,
                voucher.signature.clone(),
                nonce,
            )
            .seal_and_sign(&receiver, TEST_TX_NS, &mut sha256::Sha256::default())
        };

        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![close(0)]).await;
        assert_eq!(included, 1, "first settlement succeeds");
        assert_eq!(
            read_raw(&dbs, &channel).await,
            None,
            "channel deleted after settlement"
        );
        let receiver_balance = read_account(&dbs, &receiver_key).await.balance;

        // Replaying the same voucher is rejected — the channel is gone.
        let (_block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![close(1)]).await;
        assert_eq!(included, 0, "replayed voucher must be rejected");
        assert_eq!(
            read_account(&dbs, &receiver_key).await.balance,
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

        let payer = ed25519::PrivateKey::from_seed(2);
        let receiver = ed25519::PrivateKey::from_seed(3);
        let payer_pk = TransactionPublicKey::ed25519(payer.public_key());
        let receiver_pk = TransactionPublicKey::ed25519(receiver.public_key());
        let payer_key = AccountKey::from_public_key(&payer_pk);
        let receiver_key = AccountKey::from_public_key(&receiver_pk);
        let open_nonce: u64 = 0;
        let channel = channel_address(&payer_key, &receiver_key, open_nonce);

        let open = Transaction::open_channel(
            payer_pk.clone(),
            receiver_pk.clone(),
            NonZeroU64::new(DEPOSIT).expect("deposit is non-zero"),
            CHANNEL_NEVER_EXPIRES,
            open_nonce,
        )
        .seal_and_sign(&payer, TEST_TX_NS, &mut sha256::Sha256::default());
        let (block, _) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &genesis, vec![open]).await;

        let voucher = Voucher::sign(&payer, channel, PRICE);
        let close = |nonce: u64| {
            Transaction::close_channel(
                receiver_pk.clone(),
                payer_pk.clone(),
                open_nonce,
                voucher.cumulative,
                voucher.signature.clone(),
                nonce,
            )
            .seal_and_sign(&receiver, TEST_TX_NS, &mut sha256::Sha256::default())
        };

        // First settlement deletes the channel.
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![close(0)]).await;
        assert_eq!(included, 1);
        assert_eq!(read_raw(&dbs, &channel).await, None, "channel deleted");
        let receiver_after_first = read_account(&dbs, &receiver_key).await.balance;

        // An ordinary transfer re-funds the (publicly derivable) dead address.
        let refund = Transaction::with_op(
            payer_pk.clone(),
            1,
            Operation::Transfer {
                to: channel,
                value: NonZeroU64::new(PRICE).expect("price is non-zero"),
            },
        )
        .seal_and_sign(&payer, TEST_TX_NS, &mut sha256::Sha256::default());
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![refund]).await;
        assert_eq!(included, 1, "transfer to the dead channel address lands");
        // The address is live again; the transfer lane credits onto the funded
        // default, so the exact balance is incidental — what matters is that an
        // old voucher can now find escrow here.
        assert!(
            read_raw(&dbs, &channel).await.is_some(),
            "channel re-funded"
        );

        // The same old voucher now settles again — the documented replay gap.
        let (_block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![close(1)]).await;
        assert_eq!(included, 1, "replay against the re-funded address succeeds");
        assert_eq!(
            read_account(&dbs, &receiver_key).await.balance,
            receiver_after_first + PRICE,
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

        let payer = ed25519::PrivateKey::from_seed(2);
        let receiver = ed25519::PrivateKey::from_seed(3);
        let payer_pk = TransactionPublicKey::ed25519(payer.public_key());
        let receiver_pk = TransactionPublicKey::ed25519(receiver.public_key());
        let payer_key = AccountKey::from_public_key(&payer_pk);
        let receiver_key = AccountKey::from_public_key(&receiver_pk);
        let open_nonce: u64 = 0;
        let channel = channel_address(&payer_key, &receiver_key, open_nonce);

        let open = Transaction::open_channel(
            payer_pk.clone(),
            receiver_pk.clone(),
            NonZeroU64::new(DEPOSIT).expect("deposit is non-zero"),
            CHANNEL_NEVER_EXPIRES,
            open_nonce,
        )
        .seal_and_sign(&payer, TEST_TX_NS, &mut sha256::Sha256::default());
        let (parent, _) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &genesis, vec![open]).await;

        // Advance the clock so the settlement block has a strictly greater
        // timestamp than its parent (a child-timestamp validity requirement).
        context.sleep(Duration::from_secs(1)).await;

        let voucher = Voucher::sign(&payer, channel, PRICE);
        let close = Transaction::close_channel(
            receiver_pk.clone(),
            payer_pk.clone(),
            open_nonce,
            voucher.cumulative,
            voucher.signature.clone(),
            0,
        )
        .seal_and_sign(&receiver, TEST_TX_NS, &mut sha256::Sha256::default());

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

/// A channel opened by a non-Ed25519 (secp256r1) payer is rejected. Vouchers
/// are Ed25519, so such a channel could never be settled and its deposit would
/// be locked; the chain refuses to create it.
#[test]
fn open_channel_rejects_non_ed25519_payer() {
    deterministic::Runner::default().start(|context| async move {
        let (dbs, mut app, genesis, leader) = bootstrap(&context).await;

        let payer = secp256r1::PrivateKey::from_seed(2);
        let receiver = ed25519::PrivateKey::from_seed(3);
        let payer_pk = TransactionPublicKey::secp256r1(payer.public_key());
        let receiver_pk = TransactionPublicKey::ed25519(receiver.public_key());

        // `seal_and_sign` only supports Ed25519 transaction signatures, and the
        // propose path does not verify the transaction signature, so build the
        // open with the secp256r1 payer and attach a placeholder signature.
        let open = Transaction::<sha256::Digest>::open_channel(
            payer_pk,
            receiver_pk,
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
            propose_and_finalize(&mut app, &context, &dbs, &leader, &genesis, vec![signed]).await;
        assert_eq!(included, 0, "a non-Ed25519-payer open must be rejected");
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

        // A valid transfer and a valid open, co-batched with the poison ops.
        let transfer = Transaction::with_op(
            alice_pk.clone(),
            0,
            Operation::Transfer {
                to: bob_key,
                value: NonZeroU64::new(PRICE).expect("price is non-zero"),
            },
        )
        .seal_and_sign(&alice, TEST_TX_NS, &mut sha256::Sha256::default());
        let open = Transaction::open_channel(
            payer_pk.clone(),
            receiver_pk.clone(),
            NonZeroU64::new(DEPOSIT).expect("deposit is non-zero"),
            CHANNEL_NEVER_EXPIRES,
            0,
        )
        .seal_and_sign(&payer, TEST_TX_NS, &mut sha256::Sha256::default());

        // Statically invalid: an open from a secp256r1 payer passes the
        // mempool's signature check but can never be prepared.
        let secp = secp256r1::PrivateKey::from_seed(6);
        let secp_pk = TransactionPublicKey::secp256r1(secp.public_key());
        let sealed_bad_open = Transaction::<sha256::Digest>::open_channel(
            secp_pk,
            receiver_pk.clone(),
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
        let phantom = channel_address(&payer_key, &receiver_key, 7);
        let voucher = Voucher::sign(&payer, phantom, PRICE);
        let bad_close = Transaction::close_channel(
            receiver_pk.clone(),
            payer_pk.clone(),
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
        assert_eq!(read_account(&dbs, &alice_key).await.balance, 100 - PRICE);
        assert_eq!(read_account(&dbs, &bob_key).await.balance, 100 + PRICE);
        assert_eq!(read_account(&dbs, &payer_key).await.balance, 100 - DEPOSIT);
        assert_eq!(
            read_account(&dbs, &channel_address(&payer_key, &receiver_key, 0))
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

        let payer = ed25519::PrivateKey::from_seed(2);
        let receiver = ed25519::PrivateKey::from_seed(3);
        let payer_pk = TransactionPublicKey::ed25519(payer.public_key());
        let receiver_pk = TransactionPublicKey::ed25519(receiver.public_key());
        let payer_key = AccountKey::from_public_key(&payer_pk);
        let receiver_key = AccountKey::from_public_key(&receiver_pk);
        let open_nonce: u64 = 0;
        let channel = channel_address(&payer_key, &receiver_key, open_nonce);
        // The open lands at height 1, so the channel is expired (reclaimable)
        // from height 3 on.
        let expiry = 2;

        let open = Transaction::open_channel(
            payer_pk.clone(),
            receiver_pk.clone(),
            NonZeroU64::new(DEPOSIT).expect("deposit is non-zero"),
            expiry,
            open_nonce,
        )
        .seal_and_sign(&payer, TEST_TX_NS, &mut sha256::Sha256::default());
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &genesis, vec![open]).await;
        assert_eq!(included, 1);
        // The channel account's (otherwise unusable) nonce slot records the
        // expiry.
        let stored = read_raw(&dbs, &channel).await.expect("channel exists");
        assert_eq!(stored.nonce.base, expiry);
        assert_eq!(stored.balance, DEPOSIT);

        // The payer signs a voucher off-chain; the receiver will miss the
        // deadline and forfeit it.
        let voucher = Voucher::sign(&payer, channel, PRICE);

        let timeout =
            Transaction::timeout_channel(payer_pk.clone(), receiver_pk.clone(), open_nonce, 1)
                .seal_and_sign(&payer, TEST_TX_NS, &mut sha256::Sha256::default());

        // Height 2 is not past the expiry; the timeout is rejected and the
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
        assert_eq!(read_account(&dbs, &channel).await.balance, DEPOSIT);

        // Height 3 exceeds the expiry; the same transaction now reclaims the
        // full escrow and deletes the channel.
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![timeout]).await;
        assert_eq!(included, 1, "timeout after expiry reclaims the channel");
        assert_eq!(
            read_account(&dbs, &payer_key).await.balance,
            100,
            "payer reclaimed the entire escrow"
        );
        assert_eq!(read_raw(&dbs, &channel).await, None, "channel deleted");

        // The receiver's (still validly signed) voucher is now worthless.
        let close = Transaction::close_channel(
            receiver_pk.clone(),
            payer_pk.clone(),
            open_nonce,
            voucher.cumulative,
            voucher.signature.clone(),
            0,
        )
        .seal_and_sign(&receiver, TEST_TX_NS, &mut sha256::Sha256::default());
        let (_block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![close]).await;
        assert_eq!(included, 0, "close after reclaim must be rejected");
        assert_eq!(read_account(&dbs, &receiver_key).await.balance, 100);
    });
}

/// A close is valid at any height while the channel exists: even past the
/// expiry, a close that lands before the payer's timeout settles normally and
/// leaves nothing to reclaim.
#[test]
fn close_beats_timeout_after_expiry() {
    deterministic::Runner::default().start(|context| async move {
        let (dbs, mut app, genesis, leader) = bootstrap(&context).await;

        let payer = ed25519::PrivateKey::from_seed(2);
        let receiver = ed25519::PrivateKey::from_seed(3);
        let payer_pk = TransactionPublicKey::ed25519(payer.public_key());
        let receiver_pk = TransactionPublicKey::ed25519(receiver.public_key());
        let payer_key = AccountKey::from_public_key(&payer_pk);
        let receiver_key = AccountKey::from_public_key(&receiver_pk);
        let open_nonce: u64 = 0;
        let channel = channel_address(&payer_key, &receiver_key, open_nonce);

        // Expired as soon as the next block: the open lands at height 1 and
        // the expiry is 1.
        let open = Transaction::open_channel(
            payer_pk.clone(),
            receiver_pk.clone(),
            NonZeroU64::new(DEPOSIT).expect("deposit is non-zero"),
            1,
            open_nonce,
        )
        .seal_and_sign(&payer, TEST_TX_NS, &mut sha256::Sha256::default());
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &genesis, vec![open]).await;
        assert_eq!(included, 1);

        // The close still settles at height 2 (> expiry) because the channel
        // exists until someone deletes it.
        let voucher = Voucher::sign(&payer, channel, PRICE);
        let close = Transaction::close_channel(
            receiver_pk.clone(),
            payer_pk.clone(),
            open_nonce,
            voucher.cumulative,
            voucher.signature.clone(),
            0,
        )
        .seal_and_sign(&receiver, TEST_TX_NS, &mut sha256::Sha256::default());
        let (block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![close]).await;
        assert_eq!(included, 1, "close settles even after expiry");
        assert_eq!(read_account(&dbs, &receiver_key).await.balance, 100 + PRICE);

        // The payer's timeout finds no channel.
        let timeout =
            Transaction::timeout_channel(payer_pk.clone(), receiver_pk.clone(), open_nonce, 1)
                .seal_and_sign(&payer, TEST_TX_NS, &mut sha256::Sha256::default());
        let (_block, included) =
            propose_and_finalize(&mut app, &context, &dbs, &leader, &block, vec![timeout]).await;
        assert_eq!(included, 0, "timeout after close finds no channel");
        assert_eq!(
            read_account(&dbs, &payer_key).await.balance,
            100 - PRICE,
            "payer keeps only the close refund"
        );
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
