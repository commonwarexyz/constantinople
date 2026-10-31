use super::{
    Application, Databases, StateSyncTarget, TransactionHistoryTarget, genesis_block,
    history::parent_transactions_inactivity_floor,
};
use commonware_codec::{DecodeExt as _, Encode, EncodeSize as _, Write as _};
use commonware_consensus::{
    Handoff,
    marshal::ancestry,
    simplex::{
        scheme::bls12381_threshold::standard as threshold, types::Context as SimplexContext,
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    Digest, Digested, Digestible as _, Hasher as _, Signer as _,
    bls12381::primitives::variant::MinSig, secp256r1::standard as secp256r1, sha256,
};
use commonware_cryptography_curve25519::signing as ed25519;
use commonware_glue::stateful::{
    Application as StatefulApplication, Finality, Input,
    db::{DatabaseSet, Merkleized as _, Unmerkleized as _},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{
    journal::contiguous::{
        fixed::Config as FixedJournalConfig, variable::Config as VariableJournalConfig,
    },
    merkle::{Family as _, full::Config as MmrConfig, mem::Mem, mmr},
    qmdb::{any::FixedConfig, chain::Bounds, keyless::fixed as keyless_fixed},
    translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range};
use constantinople_mempool::mocks::StaticTransactionSource;
use constantinople_primitives::{
    Account, AccountKey, Block, Header, LazySignedTransaction, Nonce, PublicKeyCache, Sealable,
    SealedBlock, SignedTransaction, Transaction, TransactionPublicKey, TransactionSignature,
    proposal::MAXIMUM_BLOCK_SIZE,
};
use std::{num::NonZeroU64, sync::Arc, time::Duration};

type TestApp = Application<
    deterministic::Context,
    sha256::Sha256,
    sha256::Digest,
    threshold::Scheme<ed25519::VerifyingKey, MinSig>,
    ed25519::VerifyingKey,
    StaticTransactionSource<sha256::Digest, ed25519::VerifyingKey, sha256::Sha256>,
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
            replay_buffer: NZUsize!(4096),
            strategy: Sequential,
            page_cache: cache.clone(),
        },
        journal_config: FixedJournalConfig {
            partition: "verify-invalid-state-log".into(),
            items_per_blob: NZU64!(1024),
            page_cache: cache,
            write_buffer: NZUsize!(4096),
            replay_buffer: NZUsize!(4096),
        },
        translator: EightCap,
        init_cache: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
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
            replay_buffer: NZUsize!(4096),
        },
        commit_codec_config: (),
    }
}

fn sync_range_from_bounds<D>(
    bounds: &Bounds<mmr::Family, D>,
) -> commonware_utils::range::NonEmptyRange<mmr::Location>
where
    D: Digest,
{
    non_empty_range!(bounds.inactivity_floor, bounds.tip.size)
}

type TestBlock = SealedBlock<sha256::Digest, ed25519::VerifyingKey, sha256::Sha256>;

/// Genesis-backed fixture shared by the propose/verify tests.
///
/// `sender` and `alt_sender` are funded at genesis so tests can execute real
/// transfers; `recipient` starts empty.
struct VerifyHarness {
    app: TestApp,
    dbs: TestDbs,
    parent: TestBlock,
    leader: ed25519::SigningKey,
    sender: ed25519::SigningKey,
    alt_sender: ed25519::SigningKey,
    recipient: ed25519::SigningKey,
    state_target: StateSyncTarget<sha256::Digest>,
    transaction_target: TransactionHistoryTarget<sha256::Digest>,
}

async fn verify_harness(context: &deterministic::Context) -> VerifyHarness {
    let cache = CacheRef::new(NZU16!(16), NZUsize!(4096));
    let dbs = TestDbs::init(
        context.child("dbs"),
        (
            state_config(cache.clone()),
            transaction_config(cache.clone()),
        ),
        None,
    )
    .await;

    let leader = ed25519::SigningKey::from_seed(21);
    let sender = ed25519::SigningKey::from_seed(22);
    let recipient = ed25519::SigningKey::from_seed(23);
    let alt_sender = ed25519::SigningKey::from_seed(24);

    let (mut state_batch, transaction_batch) = dbs.new_batches().await;
    for funded in [&sender, &alt_sender] {
        state_batch = state_batch.write(
            AccountKey::from_public_key(&TransactionPublicKey::ed25519(funded.public_key())),
            Some(Account {
                balance: 1_000_000,
                nonce: Nonce::default(),
            }),
        );
    }
    let state = state_batch.merkleize().await.expect("genesis state");
    let transactions = transaction_batch
        .merkleize()
        .await
        .expect("genesis transactions");
    let state_target = StateSyncTarget::new(state.root(), sync_range_from_bounds(state.bounds()));
    let transaction_target = TransactionHistoryTarget {
        root: transactions.root(),
        size: transactions.bounds().tip.size,
    };
    dbs.apply((state, transactions)).await;
    assert!(dbs.finalize().await.durable().await);

    let parent = genesis_block::<sha256::Digest, _, sha256::Sha256>(
        &mut sha256::Sha256::default(),
        leader.public_key(),
        0,
        state_target.clone(),
        transaction_target.clone(),
    );
    VerifyHarness {
        app: TestApp::new(
            context.child("app"),
            Sequential,
            leader.public_key(),
            sha256::Digest::EMPTY,
            TEST_TX_NS,
            PublicKeyCache::new(context.child("public_key_cache"), NZUsize!(64)),
            state_target.clone(),
            transaction_target.clone(),
        ),
        dbs,
        parent,
        leader,
        sender,
        alt_sender,
        recipient,
        state_target,
        transaction_target,
    }
}

type TestSource = StaticTransactionSource<sha256::Digest, ed25519::VerifyingKey, sha256::Sha256>;

fn transfer(
    sender: &ed25519::SigningKey,
    recipient: &ed25519::SigningKey,
    value: u64,
) -> SignedTransaction<sha256::Sha256> {
    Transaction::new(
        TransactionPublicKey::ed25519(sender.public_key()),
        TransactionPublicKey::ed25519(recipient.public_key()),
        NonZeroU64::new(value).expect("test value should be non-zero"),
        0,
    )
    .seal_and_sign(sender, TEST_TX_NS, &mut sha256::Sha256::default())
}

/// Builds a child header that reuses the parent's commitments.
fn unexecuted_child_header(
    parent: &TestBlock,
    consensus_context: &SimplexContext<sha256::Digest, ed25519::VerifyingKey>,
) -> Header<sha256::Digest, sha256::Digest, ed25519::VerifyingKey> {
    Header {
        context: consensus_context.clone(),
        parent: *parent.seal(),
        height: 1,
        timestamp: 1,
        state_root: parent.header.state_root,
        state_range: parent.header.state_range.clone(),
        transactions_root: parent.header.transactions_root,
        transactions_range: parent.header.transactions_range.clone(),
    }
}

fn sized_unverified_block(
    header: Header<sha256::Digest, sha256::Digest, ed25519::VerifyingKey>,
    encoded_size: usize,
) -> TestBlock {
    let lazy = |payload_size: usize| {
        let mut encoded = Vec::new();
        payload_size.write(&mut encoded);
        encoded.resize(encoded.len() + payload_size, 0xff);
        LazySignedTransaction::<sha256::Sha256>::decode(encoded)
            .expect("lazy framing should decode without materializing the invalid payload")
    };
    let transaction = lazy(256);
    let count = (encoded_size - header.encode_size()) / transaction.encode_size();
    let mut body = vec![transaction; count - 1];
    let remaining = encoded_size
        - header.encode_size()
        - count.encode_size()
        - body.iter().map(|tx| tx.encode_size()).sum::<usize>();
    let payload_size = remaining - remaining.encode_size();
    body.push(lazy(payload_size));
    let block = Block {
        header,
        body: body.into(),
    }
    .seal(&mut sha256::Sha256::default());
    assert_eq!(block.encode_size(), encoded_size);
    assert_eq!(block.encode().len(), encoded_size);
    block
}

#[test]
fn verify_checks_block_size_before_fetching_parent() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent,
            leader,
            ..
        } = Box::pin(verify_harness(&context)).await;
        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };

        // Returning no parent isolates the size gate from execution. The
        // malformed lazy payloads make signature preparation inexpensive.
        for encoded_size in [
            MAXIMUM_BLOCK_SIZE - 1,
            MAXIMUM_BLOCK_SIZE,
            MAXIMUM_BLOCK_SIZE + 1,
        ] {
            let block = sized_unverified_block(
                unexecuted_child_header(&parent, &consensus_context),
                encoded_size,
            );
            let mut parent_polled = false;
            let result = app
                .verify_child(
                    (context.child("verify_size"), consensus_context.clone()),
                    Arc::new(block),
                    async {
                        parent_polled = true;
                        None
                    },
                    dbs.new_batches().await,
                )
                .await;

            assert!(result.is_none());
            assert_eq!(parent_polled, encoded_size <= MAXIMUM_BLOCK_SIZE);
        }
    });
}

#[test]
fn propose_rejects_oversized_transaction_source_output() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent,
            leader,
            sender,
            recipient,
            ..
        } = Box::pin(verify_harness(&context)).await;
        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };

        // A custom source can bypass admission. Inflate an unchecked
        // signature so the final guard runs after executing just one transfer.
        let signer = secp256r1::PrivateKey::from_seed(25);
        let signature = TransactionSignature::Secp256r1 {
            signature: signer.sign(TEST_TX_NS, b"unchecked source"),
            authenticator_data: Vec::new(),
            client_data_json: Vec::new(),
            encoded: vec![0; MAXIMUM_BLOCK_SIZE],
        };
        let transaction = SignedTransaction::new_unchecked(
            transfer(&sender, &recipient, 1).into_inner(),
            signature,
        );
        assert!(transaction.encode_size() > MAXIMUM_BLOCK_SIZE);
        let mut input = StaticTransactionSource::new(vec![vec![transaction]]);
        let proposed = app
            .propose_child(
                (context.child("propose_size"), consensus_context),
                Arc::new(parent),
                dbs.new_batches().await,
                &mut input,
            )
            .await;

        assert!(proposed.is_none());
    });
}

#[test]
fn verify_rejects_invalid_body() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent,
            leader,
            sender,
            recipient,
            ..
        } = Box::pin(verify_harness(&context)).await;

        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };
        let header = unexecuted_child_header(&parent, &consensus_context);
        let block = Block::<sha256::Digest, _, sha256::Sha256>::new(
            header,
            vec![
                transfer(&sender, &recipient, 1),
                transfer(&sender, &recipient, 2),
            ],
        )
        .seal(&mut sha256::Sha256::default());

        let result = app
            .verify_child(
                (context.child("verify"), consensus_context),
                Arc::new(block),
                std::future::ready(Some(Arc::new(parent))),
                dbs.new_batches().await,
            )
            .await;

        assert!(result.is_none());
    });
}

#[test]
fn replay_rejects_invalid_body() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent,
            leader,
            sender,
            recipient,
            ..
        } = Box::pin(verify_harness(&context)).await;

        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };
        let header = unexecuted_child_header(&parent, &consensus_context);
        let block = Block::<sha256::Digest, _, sha256::Sha256>::new(
            header,
            vec![
                transfer(&sender, &recipient, 1),
                transfer(&sender, &recipient, 2),
            ],
        )
        .seal(&mut sha256::Sha256::default());

        let result = StatefulApplication::process(
            &mut app,
            (context.child("replay"), consensus_context),
            ancestry::from_iter([Digested::precomputed(block.clone(), block.digest())]),
            dbs.new_batches().await,
            Finality::Finalized,
        )
        .await;

        assert!(result.is_none());
    });
}

/// Replay takes the transaction-history floor from the block's header, so an
/// uncertified ancestor can name a floor past its own commit.
#[test]
fn replay_rejects_transaction_floor_past_commit() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent,
            leader,
            ..
        } = Box::pin(verify_harness(&context)).await;

        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };

        // An empty body appends only its commit, at the parent's history size.
        let commit = parent.header.transactions_range.end();
        let mut header = unexecuted_child_header(&parent, &consensus_context);
        header.transactions_range = non_empty_range!(commit + 1, commit + 2);
        let block = Block::<sha256::Digest, _, sha256::Sha256>::new(header, Vec::new())
            .seal(&mut sha256::Sha256::default());

        let result = StatefulApplication::process(
            &mut app,
            (context.child("replay"), consensus_context),
            ancestry::from_iter([Digested::precomputed(block.clone(), block.digest())]),
            dbs.new_batches().await,
            Finality::Finalized,
        )
        .await;

        assert!(result.is_none());
    });
}

#[test]
fn verify_rejects_missing_parent() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent,
            leader,
            sender,
            recipient,
            ..
        } = Box::pin(verify_harness(&context)).await;

        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };
        let header = unexecuted_child_header(&parent, &consensus_context);
        let block = Block::<sha256::Digest, _, sha256::Sha256>::new(
            header,
            vec![transfer(&sender, &recipient, 1)],
        )
        .seal(&mut sha256::Sha256::default());

        // Signature verification dispatches before the parent resolves; a
        // parent that never arrives must still reject the block.
        let result = app
            .verify_child(
                (context.child("verify"), consensus_context),
                Arc::new(block),
                std::future::ready(None),
                dbs.new_batches().await,
            )
            .await;

        assert!(result.is_none());
    });
}

#[test]
fn propose_drops_inapplicable_and_refills() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent,
            leader,
            sender,
            alt_sender,
            recipient,
            ..
        } = Box::pin(verify_harness(&context)).await;

        context.sleep(Duration::from_millis(10)).await;

        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };

        // Both selected transfers consume the same nonce: proposing keeps the
        // first, drops the duplicate, and tops the block up from the mempool
        // toward the proposal budget. The proposed block is the applicable
        // subset plus the top-up.
        let keep = transfer(&sender, &recipient, 1);
        let duplicate = transfer(&sender, &recipient, 2);
        let refill = transfer(&alt_sender, &recipient, 3);
        let mut input =
            StaticTransactionSource::new(vec![vec![keep.clone(), duplicate], vec![refill.clone()]]);
        let proposed = app
            .propose_child(
                (context.child("propose"), consensus_context.clone()),
                Arc::new(parent.clone()),
                dbs.new_batches().await,
                &mut input,
            )
            .await
            .expect("best-effort proposal must succeed");
        assert_eq!(
            body_digests(&proposed.block),
            vec![*keep.message_digest(), *refill.message_digest()]
        );

        // The surviving subset re-executes cleanly under all-or-nothing
        // verification.
        let accepted = app
            .verify_child(
                (context.child("verify"), consensus_context),
                Arc::new(proposed.block.clone()),
                std::future::ready(Some(Arc::new(parent))),
                dbs.new_batches().await,
            )
            .await;
        assert!(accepted.is_some());
    });
}

#[test]
fn prepare_stages_the_block_propose_builds() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent,
            leader,
            sender,
            recipient,
            ..
        } = Box::pin(verify_harness(&context)).await;
        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };

        // Give both builds the same parent, parent state, and transactions.
        let transaction = transfer(&sender, &recipient, 1);
        let ancestry =
            || ancestry::from_iter([Digested::precomputed(parent.clone(), parent.digest())]);
        let input = || Input {
            upstream: (),
            provider: TestSource::new(vec![vec![transaction.clone()]]),
        };

        let Handoff::Stage(prepared) = StatefulApplication::prepare(
            &mut app,
            (context.child("prepare"), consensus_context.clone()),
            ancestry(),
            dbs.new_batches().await,
            input(),
        )
        .await
        else {
            panic!("prepare must stage the block it builds");
        };
        let proposed = StatefulApplication::propose(
            &mut app,
            (context.child("propose"), consensus_context),
            ancestry(),
            dbs.new_batches().await,
            input(),
        )
        .await
        .expect("propose must build a block");

        // Each build reads the clock, so only the timestamps may differ.
        let mut prepared_header = prepared.block.header.clone();
        prepared_header.timestamp = proposed.block.header.timestamp;
        assert_eq!(prepared_header, proposed.block.header);
        assert_eq!(
            body_digests(&prepared.block),
            vec![*transaction.message_digest()]
        );
        assert_eq!(body_digests(&prepared.block), body_digests(&proposed.block));
    });
}

/// The outgoing leader equivocated at view 1 and its block P2 replaced the
/// parent P1 before P1 certified, so view 2 is requested on each in turn.
#[test]
fn prepare_restages_on_a_replacement_parent() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent: genesis,
            leader,
            sender,
            alt_sender,
            recipient,
            ..
        } = Box::pin(verify_harness(&context)).await;
        let fork = |parent: &<TestDbs as DatabaseSet<deterministic::Context>>::Merkleized| {
            <TestDbs as DatabaseSet<deterministic::Context>>::fork_batches(parent)
        };

        // Both parents are children of genesis at view 1. P1 consumes the
        // sender's nonce 0 and P2 does not.
        let parent_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), genesis.digest()),
        };
        let p1 = app
            .propose_child(
                (context.child("propose_p1"), parent_context.clone()),
                Arc::new(genesis.clone()),
                dbs.new_batches().await,
                &mut TestSource::new(vec![vec![transfer(&sender, &recipient, 1)]]),
            )
            .await
            .expect("P1 must build");
        let p2 = app
            .propose_child(
                (context.child("propose_p2"), parent_context),
                Arc::new(genesis),
                dbs.new_batches().await,
                &mut TestSource::new(vec![vec![transfer(&alt_sender, &recipient, 1)]]),
            )
            .await
            .expect("P2 must build");

        // Stamping P2 ahead of the local clock lets only a child of P2 take
        // its timestamp.
        let Block { mut header, body } = p2.block.into_inner();
        header.timestamp = 10_000;
        let p2_block = Block { header, body }.seal(&mut sha256::Sha256::default());
        let p2_state = p2.merkleized;

        // Each request for view 2 offers the sender's nonce-0 transfer.
        let transaction = transfer(&sender, &recipient, 2);
        let child_context = |parent: &TestBlock| SimplexContext {
            round: Round::new(Epoch::zero(), View::new(2)),
            leader: leader.public_key(),
            parent: (View::new(1), parent.digest()),
        };
        let ancestry_of = |parent: &TestBlock| {
            ancestry::from_iter([Digested::precomputed(parent.clone(), parent.digest())])
        };
        let input = || Input {
            upstream: (),
            provider: TestSource::new(vec![vec![transaction.clone()]]),
        };

        // Both requests stage a block, the second on the replacement parent.
        let Handoff::Stage(on_p1) = StatefulApplication::prepare(
            &mut app,
            (context.child("prepare_p1"), child_context(&p1.block)),
            ancestry_of(&p1.block),
            fork(&p1.merkleized),
            input(),
        )
        .await
        else {
            panic!("prepare must stage a block on P1");
        };
        let Handoff::Stage(on_p2) = StatefulApplication::prepare(
            &mut app,
            (context.child("prepare_p2"), child_context(&p2_block)),
            ancestry_of(&p2_block),
            fork(&p2_state),
            input(),
        )
        .await
        else {
            panic!("prepare must stage a block on the replacement P2");
        };

        // Each body follows its parent's nonce, so only P2's child carries
        // the transfer.
        assert!(body_digests(&on_p1.block).is_empty());
        assert_eq!(
            body_digests(&on_p2.block),
            vec![*transaction.message_digest()]
        );

        // The second block extends P2 and commits to different state.
        let header = on_p2.block.header.clone();
        assert_eq!(header.context, child_context(&p2_block));
        assert_eq!(header.parent, p2_block.digest());
        assert_eq!(header.height, p2_block.header.height + 1);
        assert!(header.timestamp >= p2_block.header.timestamp);
        assert!(on_p1.block.header.timestamp < p2_block.header.timestamp);
        assert_ne!(header.state_root, on_p1.block.header.state_root);
        assert_ne!(
            header.transactions_root,
            on_p1.block.header.transactions_root
        );

        // It verifies and replays to its sync targets on P2's state.
        let accepted = app
            .verify_child(
                (context.child("verify_p2"), header.context.clone()),
                Arc::new(on_p2.block.clone()),
                std::future::ready(Some(Arc::new(p2_block))),
                fork(&p2_state),
            )
            .await;
        assert!(accepted.is_some());
        let applied = StatefulApplication::process(
            &mut app,
            (context.child("apply_p2"), header.context.clone()),
            ancestry::from_iter([Digested::precomputed(
                on_p2.block.clone(),
                on_p2.block.digest(),
            )]),
            fork(&p2_state),
            Finality::Finalized,
        )
        .await
        .expect("the block applies on P2's state");
        assert!(
            <TestDbs as DatabaseSet<deterministic::Context>>::matches_sync_targets(
                &applied,
                &<TestApp as StatefulApplication<deterministic::Context>>::sync_targets(
                    &on_p2.block
                ),
            )
        );

        // P1 already consumed the nonce, so the block fails on P1's state.
        let rejected = app
            .verify_child(
                (context.child("verify_p1"), header.context),
                Arc::new(on_p2.block),
                std::future::ready(Some(Arc::new(p1.block))),
                fork(&p1.merkleized),
            )
            .await;
        assert!(rejected.is_none());
    });
}

/// Pins the application's own decline: the stateful actor declines an empty
/// ancestry before it would call `prepare`.
#[test]
fn prepare_waits_without_a_parent() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent,
            leader,
            ..
        } = Box::pin(verify_harness(&context)).await;
        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };

        let prepared = StatefulApplication::prepare(
            &mut app,
            (context.child("prepare"), consensus_context),
            ancestry::from_iter(std::iter::empty::<Digested<TestBlock>>()),
            dbs.new_batches().await,
            Input {
                upstream: (),
                provider: TestSource::new(Vec::new()),
            },
        )
        .await;
        assert!(prepared.is_wait());
    });
}

fn finalized_range_root<Op: Encode>(
    range: &super::FinalizedRange<sha256::Digest, Op>,
    floor: u64,
) -> sha256::Digest {
    let hasher = commonware_storage::qmdb::hasher::<sha256::Sha256>();
    let mut memory =
        Mem::<mmr::Family, _>::from_components(Vec::new(), range.start, range.pinned_nodes.clone())
            .expect("captured frontier initializes the prefix");
    let mut batch = memory.new_batch();
    for operation in range.operations.iter() {
        batch = batch.add(&hasher, &operation.encode());
    }
    let batch = batch.merkleize(&memory, &hasher);
    memory.apply_batch(&batch).expect("apply captured suffix");
    assert_eq!(memory.leaves(), range.end);
    let inactive_peaks = mmr::Family::inactive_peaks(range.end, mmr::Location::new(floor));
    memory.root(&hasher, inactive_peaks).expect("captured root")
}

#[test]
fn finalized_capture_preserves_both_authenticated_ranges() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            mut parent,
            leader,
            sender,
            recipient,
            ..
        } = Box::pin(verify_harness(&context)).await;

        // The empty successor retains its parent's transaction range, so its
        // inactivity floor and append start produce different root commitments.
        for height in 1..=2 {
            context.sleep(Duration::from_millis(10)).await;
            let consensus_context = SimplexContext {
                round: Round::new(Epoch::zero(), View::new(height)),
                leader: leader.public_key(),
                parent: (View::new(height - 1), *parent.seal()),
            };
            let transactions = if height == 1 {
                vec![transfer(&sender, &recipient, 1)]
            } else {
                Vec::new()
            };
            let mut input = StaticTransactionSource::new(vec![transactions]);
            let parent_state_end = parent.header.state_range.end();
            let parent_transaction_end = parent.header.transactions_range.end();
            let proposed = app
                .propose_child(
                    (context.child("propose"), consensus_context.clone()),
                    Arc::new(parent),
                    dbs.new_batches().await,
                    &mut input,
                )
                .await
                .expect("proposal succeeds");
            let artifacts = StatefulApplication::capture(
                &mut app,
                (context.child("capture"), consensus_context),
                &proposed.block,
                &proposed.merkleized,
                dbs.readers(),
            )
            .await;
            let header = &proposed.block.header;

            assert_eq!(artifacts.state.start.as_u64(), parent_state_end);
            assert_eq!(artifacts.state.end.as_u64(), header.state_range.end());
            assert_eq!(artifacts.state.root, header.state_root);
            assert_eq!(
                finalized_range_root(&artifacts.state, header.state_range.start()),
                header.state_root,
            );
            assert_eq!(
                artifacts.transactions.start.as_u64(),
                parent_transaction_end
            );
            assert_eq!(
                artifacts.transactions.end.as_u64(),
                header.transactions_range.end()
            );
            assert_eq!(artifacts.transactions.root, header.transactions_root);
            assert_eq!(
                finalized_range_root(&artifacts.transactions, header.transactions_range.start()),
                header.transactions_root,
            );
            assert_ne!(
                header.transactions_range.start(),
                artifacts.transactions.start.as_u64()
            );
            if height == 2 {
                assert_ne!(
                    finalized_range_root(
                        &artifacts.transactions,
                        artifacts.transactions.start.as_u64(),
                    ),
                    header.transactions_root,
                );
            }

            dbs.apply(proposed.merkleized).await;
            parent = proposed.block;
        }
    });
}

#[test]
fn verify_accepts_proposed_child_and_rejects_stale_timestamp() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            leader,
            state_target,
            transaction_target,
            ..
        } = Box::pin(verify_harness(&context)).await;

        // Stamp the parent ahead of the local clock, as a proposer whose clock
        // runs fast would. A child built before the local clock catches up
        // takes the parent's timestamp.
        let parent = genesis_block::<sha256::Digest, _, sha256::Sha256>(
            &mut sha256::Sha256::default(),
            leader.public_key(),
            10_000,
            state_target,
            transaction_target,
        );

        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };
        let mut input = StaticTransactionSource::new(Vec::new());
        let proposed = app
            .propose_child(
                (context.child("propose"), consensus_context.clone()),
                Arc::new(parent.clone()),
                dbs.new_batches().await,
                &mut input,
            )
            .await
            .expect("empty proposal must succeed");
        assert_eq!(proposed.block.header.timestamp, parent.header.timestamp);

        let replayed = StatefulApplication::process(
            &mut app,
            (context.child("replay"), consensus_context.clone()),
            ancestry::from_iter([Digested::precomputed(
                proposed.block.clone(),
                proposed.block.digest(),
            )]),
            dbs.new_batches().await,
            Finality::Finalized,
        )
        .await
        .expect("valid block replays");
        assert_eq!(replayed.0.root(), proposed.block.header.state_root);
        assert_eq!(replayed.1.root(), proposed.block.header.transactions_root);

        // The freshly proposed child verifies against the same parent.
        let accepted = app
            .verify_child(
                (context.child("verify"), consensus_context.clone()),
                Arc::new(proposed.block.clone()),
                std::future::ready(Some(Arc::new(parent.clone()))),
                dbs.new_batches().await,
            )
            .await;
        assert!(accepted.is_some());

        // The identical block with its timestamp rewound below the parent's is
        // rejected by the timestamp check alone.
        let Block { mut header, body } = proposed.block.into_inner();
        assert!(
            body.is_empty(),
            "stale block must mirror the empty proposal"
        );
        header.timestamp = parent.header.timestamp - 1;
        let stale = Block::<sha256::Digest, _, sha256::Sha256>::new(header, Vec::new())
            .seal(&mut sha256::Sha256::default());
        let rejected = app
            .verify_child(
                (context.child("verify_stale"), consensus_context),
                Arc::new(stale),
                std::future::ready(Some(Arc::new(parent))),
                dbs.new_batches().await,
            )
            .await;
        assert!(rejected.is_none());
    });
}

#[test]
fn parent_inactivity_floor_skips_the_parent_commit() {
    let leader = ed25519::SigningKey::from_seed(7);
    let recipient = ed25519::SigningKey::from_seed(8);
    let genesis_target = TransactionHistoryTarget {
        root: sha256::Digest::EMPTY,
        size: commonware_storage::mmr::Location::new(1),
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

#[test]
fn genesis_block_uses_the_initialized_transaction_target() {
    let leader = ed25519::SigningKey::from_seed(11).public_key();
    let target = TransactionHistoryTarget {
        root: sha256::Sha256::hash(&[b"genesis"]),
        size: commonware_storage::mmr::Location::new(1),
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

/// Digests of a sealed block's body transactions.
fn body_digests(block: &TestBlock) -> Vec<sha256::Digest> {
    block
        .body
        .iter()
        .map(|tx| {
            *tx.get()
                .expect("test bodies are materialized")
                .message_digest()
        })
        .collect()
}

/// Wraps a static source with a virtual-time delay so a test can control how
/// much of the build budget each mempool round trip consumes.
struct DelayedSource {
    context: deterministic::Context,
    delay: Duration,
    inner: TestSource,
}

// Required by `TransactionSource`'s `Reporter: Clone` supertrait; never
// invoked in these tests.
impl Clone for DelayedSource {
    fn clone(&self) -> Self {
        Self {
            context: self.context.child("clone"),
            delay: self.delay,
            inner: self.inner.clone(),
        }
    }
}

impl
    constantinople_mempool::TransactionSource<sha256::Digest, ed25519::VerifyingKey, sha256::Sha256>
    for DelayedSource
{
    async fn propose(
        &mut self,
        parent: &Header<sha256::Digest, sha256::Digest, ed25519::VerifyingKey>,
        round: Round,
        filled: usize,
    ) -> Vec<constantinople_primitives::VerifiedTransaction<sha256::Sha256>> {
        self.context.sleep(self.delay).await;
        self.inner.propose(parent, round, filled).await
    }
}

impl commonware_consensus::Reporter for DelayedSource {
    type Activity = commonware_consensus::marshal::Update<TestBlock>;

    fn report(&mut self, activity: Self::Activity) -> commonware_actor::Feedback {
        self.inner.report(activity)
    }
}

#[test]
fn build_timeout_bounds_refill_rounds() {
    deterministic::Runner::default().start(|context| async move {
        let harness = Box::pin(verify_harness(&context)).await;
        let seed_keep = transfer(&harness.sender, &harness.recipient, 1);
        let seed_dup = transfer(&harness.sender, &harness.recipient, 2);
        let refill_one = transfer(&harness.alt_sender, &harness.recipient, 3);
        let never_pulled = transfer(&harness.recipient, &harness.sender, 4);

        // Each mempool round trip burns 60ms of virtual time — past the 50ms
        // build deadline after one refill.
        let slow = |batches| DelayedSource {
            context: context.child("slow_clock"),
            delay: Duration::from_millis(60),
            inner: StaticTransactionSource::new(batches),
        };
        let mut app: Application<
            deterministic::Context,
            sha256::Sha256,
            sha256::Digest,
            threshold::Scheme<ed25519::VerifyingKey, MinSig>,
            ed25519::VerifyingKey,
            DelayedSource,
            Sequential,
        > = Application::new(
            context.child("deadline_app"),
            Sequential,
            harness.leader.public_key(),
            sha256::Digest::EMPTY,
            TEST_TX_NS,
            PublicKeyCache::new(context.child("deadline_pkc"), NZUsize!(64)),
            harness.state_target.clone(),
            harness.transaction_target.clone(),
        );

        context.sleep(Duration::from_millis(10)).await;

        // The seed pull happens before the build deadline starts; the first
        // refill (delayed 60ms) lands past the deadline, so a second refill
        // is never requested even though headroom and candidates remain.
        let mut input = slow(vec![
            vec![seed_keep.clone(), seed_dup],
            vec![refill_one.clone()],
            vec![never_pulled],
        ]);
        let ctx1 = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: harness.leader.public_key(),
            parent: (View::zero(), *harness.parent.seal()),
        };
        let proposed = app
            .propose_child(
                (context.child("propose_deadline"), ctx1),
                Arc::new(harness.parent.clone()),
                harness.dbs.new_batches().await,
                &mut input,
            )
            .await
            .expect("proposal must succeed");

        assert_eq!(
            body_digests(&proposed.block),
            vec![*seed_keep.message_digest(), *refill_one.message_digest()],
            "the deadline must stop the loop after the first refill"
        );
    });
}
