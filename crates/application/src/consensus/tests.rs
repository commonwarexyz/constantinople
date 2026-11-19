use super::{
    Application, Chain, Databases, StateSyncTarget, TransactionHistoryTarget, genesis_block,
    history::parent_transactions_inactivity_floor,
};
use commonware_codec::{DecodeExt as _, Encode, EncodeSize as _, Write as _};
use commonware_consensus::{
    simplex::types::{Context as SimplexContext, Notarization, Notarize, Proposal},
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    Digest, Hasher as _, Signer as _, certificate::mocks::Fixture, ed25519,
    secp256r1::standard as secp256r1, sha256,
};
use commonware_glue::stateful::{
    Application as StatefulApplication,
    db::{DatabaseSet as _, Merkleized as _, Unmerkleized as _},
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
use commonware_utils::{NZU16, NZU64, NZUsize, non_empty, non_empty_range, sync::Mutex};
use constantinople_auth::{Report, Submission, Tags};
use constantinople_mempool::{Candidate, mocks::StaticTransactionSource};
use constantinople_primitives::{
    Account, AccountKey, Block, Header, LazySignedTransaction, Nonce, Outcomes, ParentNotarization,
    PublicKeyCache, Sealable, SealedBlock, SignedTransaction, Transaction, TransactionPublicKey,
    TransactionSignature, notarization_digest, outcomes_digest, proposal::MAXIMUM_BLOCK_SIZE,
};
use std::{collections::HashMap, num::NonZeroU64, sync::Arc, time::Duration};

/// The number of validators. One of them may be faulty, a notarization holds
/// five votes, and three approving reports make a transaction authentic.
const VALIDATORS: u32 = 6;
const CONSENSUS_NS: &[u8] = b"constantinople-application-test-consensus";

/// The chain as the tests present it to the application.
#[derive(Clone, Default)]
struct TestChain {
    notarizations: Arc<Mutex<HashMap<(Round, sha256::Digest), ParentNotarization<sha256::Digest>>>>,
    built: Arc<Mutex<Vec<(sha256::Digest, Vec<Tags>)>>>,
    blocks: Arc<Mutex<HashMap<sha256::Digest, Arc<TestBlock>>>>,
}

impl Chain<sha256::Digest, ed25519::PublicKey, sha256::Sha256> for TestChain {
    async fn notarization(
        &self,
        round: Round,
        payload: sha256::Digest,
    ) -> Option<ParentNotarization<sha256::Digest>> {
        self.notarizations.lock().get(&(round, payload)).cloned()
    }

    fn built(&self, block: &TestBlock, authenticators: Vec<Tags>) {
        self.built.lock().push((*block.seal(), authenticators));
    }

    async fn parent(&self, block: &TestBlock) -> Option<Arc<TestBlock>> {
        self.blocks.lock().get(&block.header.parent).cloned()
    }
}

type TestApp = Application<
    deterministic::Context,
    sha256::Sha256,
    sha256::Digest,
    TestChain,
    ed25519::PublicKey,
    StaticTransactionSource<sha256::Digest, ed25519::PublicKey, sha256::Sha256>,
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

type TestBlock = SealedBlock<sha256::Digest, ed25519::PublicKey, sha256::Sha256>;

/// Genesis-backed fixture shared by the propose/verify tests.
///
/// `sender` and `alt_sender` are funded at genesis so tests can execute real
/// transfers; `recipient` starts empty.
struct VerifyHarness {
    app: TestApp,
    dbs: TestDbs,
    chain: TestChain,
    /// The validators' vote schemes.
    validators: Fixture<constantinople_auth::Scheme>,
    parent: TestBlock,
    leader: ed25519::PrivateKey,
    sender: ed25519::PrivateKey,
    alt_sender: ed25519::PrivateKey,
    /// A funded account whose transactions are authenticated by tags.
    tagged_sender: constantinople_auth::PrivateKey,
    recipient: ed25519::PrivateKey,
}

async fn verify_harness(context: &deterministic::Context) -> VerifyHarness {
    let cache = CacheRef::from_pooler(context, NZU16!(16), NZUsize!(4096));
    let dbs = TestDbs::init(
        context.child("dbs"),
        (
            state_config(cache.clone()),
            transaction_config(cache.clone()),
        ),
        None,
    )
    .await;

    let leader = ed25519::PrivateKey::from_seed(21);
    let sender = ed25519::PrivateKey::from_seed(22);
    let recipient = ed25519::PrivateKey::from_seed(23);
    let alt_sender = ed25519::PrivateKey::from_seed(24);

    let tagged_sender = constantinople_auth::PrivateKey::from([26; 32]);
    let validators =
        constantinople_auth::fixture(&mut context.child("validators"), CONSENSUS_NS, VALIDATORS);
    let chain = TestChain::default();

    let (mut state_batch, transaction_batch) = dbs.new_batches().await;
    for funded in [
        TransactionPublicKey::ed25519(sender.public_key()),
        TransactionPublicKey::ed25519(alt_sender.public_key()),
        TransactionPublicKey::x25519(tagged_sender.public_key()),
    ] {
        state_batch = state_batch.write(
            AccountKey::from_public_key(&funded),
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
            validators.verifier.clone(),
            chain.clone(),
        ),
        dbs,
        chain,
        validators,
        parent,
        leader,
        sender,
        alt_sender,
        tagged_sender,
        recipient,
    }
}

type TestSource = StaticTransactionSource<sha256::Digest, ed25519::PublicKey, sha256::Sha256>;

/// The consensus context of a child of `parent` proposed in view `view`.
///
/// The tests use a block's digest as its consensus payload.
fn child_context(
    leader: &ed25519::PrivateKey,
    parent: &TestBlock,
    view: u64,
) -> SimplexContext<sha256::Digest, ed25519::PublicKey> {
    SimplexContext {
        round: Round::new(Epoch::zero(), View::new(view)),
        leader: leader.public_key(),
        parent: (parent.header.context.round.view(), *parent.seal()),
    }
}

/// A notarization of `block` by the first five validators, where validator `i`
/// reports `verdicts(i)` on the block's transactions authenticated by tags.
fn notarization(
    validators: &Fixture<constantinople_auth::Scheme>,
    block: &TestBlock,
    verdicts: impl Fn(usize) -> Vec<bool>,
) -> ParentNotarization<sha256::Digest> {
    let proposal = Proposal::new(
        block.header.context.round,
        block.header.context.parent.0,
        *block.seal(),
    );
    let votes: Vec<_> = validators.schemes[..5]
        .iter()
        .enumerate()
        .map(|(validator, scheme)| {
            scheme.reports().insert(
                proposal.round,
                proposal.payload.as_ref(),
                Report::new(&verdicts(validator)),
            );
            Notarize::sign(scheme, proposal.clone()).expect("report was recorded")
        })
        .collect();
    Notarization::from_notarizes(
        &validators.schemes[0],
        non_empty![@votes.iter()],
        &Sequential,
    )
    .expect("five of six votes are a quorum")
}

impl VerifyHarness {
    /// Makes the chain hold `block` and a notarization of it in which every
    /// validator approves every transaction authenticated by tags.
    fn notarize(&self, block: &TestBlock) -> ParentNotarization<sha256::Digest> {
        let tagged = block
            .body
            .iter()
            .filter(|tx| tx.get().is_some_and(SignedTransaction::is_mac))
            .count();
        self.notarize_with(block, |_| vec![true; tagged])
    }

    /// Makes the chain hold `block` and a notarization of it with the given
    /// reports (see [`notarization`]).
    fn notarize_with(
        &self,
        block: &TestBlock,
        verdicts: impl Fn(usize) -> Vec<bool>,
    ) -> ParentNotarization<sha256::Digest> {
        let notarization = notarization(&self.validators, block, verdicts);
        self.chain.notarizations.lock().insert(
            (block.header.context.round, *block.seal()),
            notarization.clone(),
        );
        self.chain
            .blocks
            .lock()
            .insert(*block.seal(), Arc::new(block.clone()));
        notarization
    }

    /// A transfer from the account authenticated by tags, with the tags its
    /// sender submits to validator `proposer`.
    fn tagged_transfer(&self, proposer: u32, value: u64, nonce: u64) -> Candidate<sha256::Sha256> {
        let transaction = Transaction::new(
            TransactionPublicKey::x25519(self.tagged_sender.public_key()),
            TransactionPublicKey::ed25519(self.recipient.public_key()),
            NonZeroU64::new(value).expect("test value should be non-zero"),
            nonce,
        )
        .seal_for_mac(&mut sha256::Sha256::default());

        // The tests only need tags of the right shape: the application never
        // compares them.
        let keys: Vec<_> = (0..VALIDATORS as u8)
            .map(|validator| {
                let validator = constantinople_auth::PrivateKey::from([100 + validator; 32]);
                self.tagged_sender
                    .with_validator(TEST_TX_NS, &validator.public_key())
                    .expect("validator key is not low order")
            })
            .collect();
        let submission = Submission::new(
            &keys,
            commonware_utils::Participant::new(proposer),
            (),
            transaction.message_digest().as_ref(),
        );
        Candidate {
            transaction,
            authenticator: Some(submission.authenticator),
        }
    }

    /// The balance and nonce of the account with public key `key`, as of the
    /// applied state.
    async fn account(&self, key: &TransactionPublicKey) -> Account {
        let (state, _) = self.dbs.new_batches().await;
        let key = AccountKey::from_public_key(key);
        let (values, _) = state.stage(&[&key]).await.expect("account loads");
        values[0].unwrap_or_default()
    }
}

fn transfer(
    sender: &ed25519::PrivateKey,
    recipient: &ed25519::PrivateKey,
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
    consensus_context: &SimplexContext<sha256::Digest, ed25519::PublicKey>,
) -> Header<sha256::Digest, sha256::Digest, ed25519::PublicKey> {
    Header {
        context: consensus_context.clone(),
        parent: *parent.seal(),
        height: 1,
        timestamp: 1,
        parent_notarization: notarization_digest::<sha256::Digest, _>(
            None,
            &mut sha256::Sha256::default(),
        ),
        parent_outcomes: outcomes_digest(&Outcomes::new(), &mut sha256::Sha256::default()),
        state_root: parent.header.state_root,
        state_range: parent.header.state_range.clone(),
        transactions_root: parent.header.transactions_root,
        transactions_range: parent.header.transactions_range.clone(),
    }
}

fn sized_unverified_block(
    header: Header<sha256::Digest, sha256::Digest, ed25519::PublicKey>,
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
    let fixed = header.encode_size() + false.encode_size() + Outcomes::new().encode_size();
    let count = (encoded_size - fixed) / transaction.encode_size();
    let mut body = vec![transaction; count - 1];
    let remaining = encoded_size
        - fixed
        - count.encode_size()
        - body.iter().map(|tx| tx.encode_size()).sum::<usize>();
    let payload_size = remaining - remaining.encode_size();
    body.push(lazy(payload_size));
    let block = Block {
        header,
        notarization: None,
        outcomes: Outcomes::new(),
        body,
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
            chain,
            validators,
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
            chain.notarizations.lock().insert(
                (parent.header.context.round, *parent.seal()),
                notarization(&validators, &parent, |_| Vec::new()),
            );
        }
    });
}

#[test]
fn verify_accepts_proposed_child_and_rejects_stale_timestamp() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent,
            leader,
            ..
        } = Box::pin(verify_harness(&context)).await;

        // Advance past the genesis timestamp so the proposal's clock-derived
        // timestamp is strictly greater than the parent's.
        context.sleep(Duration::from_millis(10)).await;

        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };
        let mut input = TestSource::new(Vec::<Vec<SignedTransaction<_>>>::new());
        let proposed = app
            .propose_child(
                (context.child("propose"), consensus_context.clone()),
                Arc::new(parent.clone()),
                dbs.new_batches().await,
                &mut input,
            )
            .await
            .expect("empty proposal must succeed");

        let replayed = StatefulApplication::apply(
            &mut app,
            (context.child("replay"), consensus_context.clone()),
            &proposed.block,
            dbs.new_batches().await,
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

        // The identical block with its timestamp rewound to the parent's is
        // rejected by the timestamp check alone.
        let Block {
            mut header, body, ..
        } = proposed.block.into_inner();
        assert!(
            body.is_empty(),
            "stale block must mirror the empty proposal"
        );
        header.timestamp = parent.header.timestamp;
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
    let leader = ed25519::PrivateKey::from_seed(7);
    let recipient = ed25519::PrivateKey::from_seed(8);
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
    let leader = ed25519::PrivateKey::from_seed(11).public_key();
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

impl VerifyHarness {
    /// Proposes a child of `parent` in view `view` from `candidates`, without
    /// applying it.
    async fn propose(
        &mut self,
        context: &deterministic::Context,
        parent: &TestBlock,
        view: u64,
        candidates: Vec<Candidate<sha256::Sha256>>,
    ) -> Option<commonware_glue::stateful::Proposed<TestApp, deterministic::Context>> {
        // Advance the clock so the child's timestamp follows its parent's.
        context.sleep(Duration::from_millis(10)).await;
        let mut input = TestSource::new(vec![candidates]);
        self.app
            .propose_child(
                (
                    context.child("propose"),
                    child_context(&self.leader, parent, view),
                ),
                Arc::new(parent.clone()),
                self.dbs.new_batches().await,
                &mut input,
            )
            .await
    }

    /// Whether a validator accepts `block` as a child of `parent` in view `view`.
    async fn verifies(
        &mut self,
        context: &deterministic::Context,
        parent: &TestBlock,
        view: u64,
        block: &TestBlock,
    ) -> bool {
        self.app
            .verify_child(
                (
                    context.child("verify"),
                    child_context(&self.leader, parent, view),
                ),
                Arc::new(block.clone()),
                std::future::ready(Some(Arc::new(parent.clone()))),
                self.dbs.new_batches().await,
            )
            .await
            .is_some()
    }

    /// Whether `block`, a child of `parent` proposed in view `view`, replays to
    /// the commitments in its header.
    async fn replays(
        &mut self,
        context: &deterministic::Context,
        parent: &TestBlock,
        view: u64,
        block: &TestBlock,
    ) -> bool {
        StatefulApplication::apply(
            &mut self.app,
            (
                context.child("replay"),
                child_context(&self.leader, parent, view),
            ),
            block,
            self.dbs.new_batches().await,
        )
        .await
        .is_some_and(|replayed| {
            replayed.0.root() == block.header.state_root
                && replayed.1.root() == block.header.transactions_root
        })
    }

    /// Proposes a child of `parent`, checks that a validator accepts it and that
    /// it replays, and makes it the applied state.
    async fn extend(
        &mut self,
        context: &deterministic::Context,
        parent: &TestBlock,
        view: u64,
        candidates: Vec<Candidate<sha256::Sha256>>,
    ) -> TestBlock {
        let proposed = self
            .propose(context, parent, view, candidates)
            .await
            .expect("proposal succeeds");
        assert!(self.verifies(context, parent, view, &proposed.block).await);
        assert!(self.replays(context, parent, view, &proposed.block).await);
        self.dbs.apply(proposed.merkleized).await;
        proposed.block
    }
}

fn outcomes(block: &TestBlock) -> Vec<bool> {
    (0..block.outcomes.len())
        .map(|bit| block.outcomes.get(bit))
        .collect()
}

/// `block` after `edit`, with a header that commits to the edited notarization
/// and outcomes.
fn tampered(
    block: &TestBlock,
    edit: impl FnOnce(&mut Block<sha256::Digest, ed25519::PublicKey, sha256::Sha256>),
) -> TestBlock {
    let hasher = &mut sha256::Sha256::default();
    let mut inner = block.clone().into_inner();
    edit(&mut inner);
    inner.header.parent_notarization = notarization_digest(inner.notarization.as_ref(), hasher);
    inner.header.parent_outcomes = outcomes_digest(&inner.outcomes, hasher);
    inner.seal(hasher)
}

#[test]
fn transactions_execute_one_block_later() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Box::pin(verify_harness(&context)).await;
        let genesis = h.parent.clone();
        let sender = TransactionPublicKey::ed25519(h.sender.public_key());
        let recipient = TransactionPublicKey::ed25519(h.recipient.public_key());
        let payment = transfer(&h.sender, &h.recipient, 7);

        // The block that lists the transfer does not execute it: the accounts are
        // as at genesis, and the history has the transfer.
        let first = h
            .extend(&context, &genesis, 1, vec![payment.clone().into()])
            .await;
        assert_eq!(body_digests(&first), vec![*payment.message_digest()]);
        assert!(first.notarization.is_none());
        assert!(outcomes(&first).is_empty());
        assert_ne!(
            first.header.transactions_root,
            genesis.header.transactions_root
        );
        assert_eq!(h.account(&sender).await.balance, 1_000_000);

        // The next block carries a notarization of the first and executes it.
        let notarization = h.notarize(&first);
        let second = h.extend(&context, &first, 2, Vec::new()).await;
        assert_eq!(second.notarization, Some(notarization));
        assert_eq!(outcomes(&second), vec![true]);
        assert_eq!(h.account(&sender).await.balance, 1_000_000 - 7);
        assert_eq!(
            h.account(&recipient).await.balance,
            Account::default().balance + 7
        );

        // A block after an empty block has nothing to execute.
        h.notarize(&second);
        let third = h.extend(&context, &second, 3, Vec::new()).await;
        assert!(outcomes(&third).is_empty());
        assert_eq!(h.account(&sender).await.balance, 1_000_000 - 7);
    });
}

#[test]
fn a_tagged_transaction_is_applied_iff_enough_reports_approve() {
    // Each case gives the report of validator `i` on the one tagged transaction
    // and whether the transaction is applied. Three approvals are needed.
    let cases: [(fn(usize) -> Vec<bool>, bool); 4] = [
        (|_| vec![true], true),
        (|validator| vec![validator < 3], true),
        (|validator| vec![validator < 2], false),
        // The first of three approving reports is a bitmap over nine
        // transactions: it is malformed for this block and approves nothing.
        (
            |validator| match validator {
                0 => (0..9).map(|position| position == 0).collect(),
                1 | 2 => vec![true],
                _ => vec![false],
            },
            false,
        ),
    ];
    for (verdicts, applied) in cases {
        deterministic::Runner::default().start(|context| async move {
            let mut h = Box::pin(verify_harness(&context)).await;
            let genesis = h.parent.clone();
            let sender = TransactionPublicKey::x25519(h.tagged_sender.public_key());
            let payment = h.tagged_transfer(0, 5, 0);
            let authenticator = payment.authenticator.clone().expect("tagged");

            // The proposer hands the tags to the chain: they are not in the block.
            let first = h.extend(&context, &genesis, 1, vec![payment]).await;
            assert_eq!(
                h.chain.built.lock().last(),
                Some(&(*first.seal(), vec![authenticator]))
            );

            h.notarize_with(&first, verdicts);
            let second = h.extend(&context, &first, 2, Vec::new()).await;
            assert_eq!(outcomes(&second), vec![applied]);
            let account = h.account(&sender).await;
            assert_eq!(account.balance, 1_000_000 - if applied { 5 } else { 0 });
            assert_eq!(account.nonce != Nonce::default(), applied);
        });
    }
}

#[test]
fn signed_and_tagged_transactions_share_a_block() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Box::pin(verify_harness(&context)).await;
        let genesis = h.parent.clone();
        let candidates = vec![
            transfer(&h.sender, &h.recipient, 1).into(),
            h.tagged_transfer(0, 2, 0),
            transfer(&h.alt_sender, &h.recipient, 3).into(),
            h.tagged_transfer(0, 4, 1),
        ];
        let first = h.extend(&context, &genesis, 1, candidates).await;
        assert_eq!(h.chain.built.lock().last().expect("built").1.len(), 2);

        // Reports cover the two tagged transactions, in block order: the second
        // is rejected. Signed transactions need no report.
        h.notarize_with(&first, |_| vec![true, false]);
        let second = h.extend(&context, &first, 2, Vec::new()).await;
        assert_eq!(outcomes(&second), vec![true, true, true, false]);
        let recipient = TransactionPublicKey::ed25519(h.recipient.public_key());
        assert_eq!(
            h.account(&recipient).await.balance,
            Account::default().balance + 1 + 2 + 3
        );
    });
}

#[test]
fn a_transaction_that_cannot_apply_is_skipped() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Box::pin(verify_harness(&context)).await;
        let genesis = h.parent.clone();
        let sender = TransactionPublicKey::ed25519(h.sender.public_key());

        // The first two transfers use the same nonce. The block that lists them
        // is valid, and the second is skipped when they execute.
        let candidates = vec![
            transfer(&h.sender, &h.recipient, 1).into(),
            transfer(&h.sender, &h.recipient, 2).into(),
            transfer(&h.alt_sender, &h.recipient, 3).into(),
        ];
        let first = h.extend(&context, &genesis, 1, candidates).await;
        assert_eq!(first.body.len(), 3);

        h.notarize(&first);
        let second = h.extend(&context, &first, 2, Vec::new()).await;
        assert_eq!(outcomes(&second), vec![true, false, true]);
        assert_eq!(h.account(&sender).await.balance, 1_000_000 - 1);
    });
}

#[test]
fn propose_needs_a_notarization_of_its_parent() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Box::pin(verify_harness(&context)).await;
        let genesis = h.parent.clone();
        let first = h.extend(&context, &genesis, 1, Vec::new()).await;

        assert!(h.propose(&context, &first, 2, Vec::new()).await.is_none());

        // A notarization of another block does not help.
        let other = notarization(&h.validators, &genesis, |_| Vec::new());
        h.chain
            .notarizations
            .lock()
            .insert((first.header.context.round, *first.seal()), other);
        assert!(h.propose(&context, &first, 2, Vec::new()).await.is_none());

        h.notarize(&first);
        assert!(h.propose(&context, &first, 2, Vec::new()).await.is_some());
    });
}

#[test]
fn propose_leaves_out_duplicates_and_tagged_transactions_without_tags() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Box::pin(verify_harness(&context)).await;
        let genesis = h.parent.clone();
        let keep = transfer(&h.sender, &h.recipient, 1);
        let tagged = h.tagged_transfer(0, 2, 0);

        let mut untagged = h.tagged_transfer(0, 3, 1);
        untagged.authenticator = None;
        let mut short = h.tagged_transfer(0, 4, 2);
        short.authenticator = Some(Tags::new(constantinople_auth::tag_bits(VALIDATORS)));

        let candidates = vec![
            keep.clone().into(),
            untagged,
            keep.clone().into(),
            short,
            tagged.clone(),
            tagged.clone(),
        ];
        let first = h.extend(&context, &genesis, 1, candidates).await;
        assert_eq!(
            body_digests(&first),
            vec![*keep.message_digest(), *tagged.transaction.message_digest()]
        );
        assert_eq!(
            h.chain.built.lock().last().expect("built").1,
            vec![tagged.authenticator.expect("tagged")]
        );
    });
}

#[test]
fn verify_rejects_a_block_that_misstates_its_parent() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Box::pin(verify_harness(&context)).await;
        let genesis = h.parent.clone();
        let candidates = vec![
            h.tagged_transfer(0, 5, 0),
            transfer(&h.sender, &h.recipient, 1).into(),
        ];
        let first = h.extend(&context, &genesis, 1, candidates).await;
        h.notarize(&first);
        let second = h
            .propose(&context, &first, 2, Vec::new())
            .await
            .expect("proposal succeeds")
            .block;
        assert_eq!(outcomes(&second), vec![true, true]);
        assert!(h.verifies(&context, &first, 2, &second).await);

        // Outcomes that execution does not produce.
        let wrong = tampered(&second, |block| block.outcomes.flip(1));
        assert!(!h.verifies(&context, &first, 2, &wrong).await);
        assert!(!h.replays(&context, &first, 2, &wrong).await);
        let wrong = tampered(&second, |block| block.outcomes = Outcomes::new());
        assert!(!h.verifies(&context, &first, 2, &wrong).await);

        // No notarization of the parent.
        let wrong = tampered(&second, |block| block.notarization = None);
        assert!(!h.verifies(&context, &first, 2, &wrong).await);
        assert!(!h.replays(&context, &first, 2, &wrong).await);

        // A notarization of another block.
        let other = notarization(&h.validators, &genesis, |_| Vec::new());
        let wrong = tampered(&second, |block| block.notarization = Some(other));
        assert!(!h.verifies(&context, &first, 2, &wrong).await);
        assert!(!h.replays(&context, &first, 2, &wrong).await);

        // Another notarization of the parent, in which too few validators
        // approve the tagged transaction. The outcomes no longer follow from it.
        let rejecting = notarization(&h.validators, &first, |validator| vec![validator < 2]);
        let wrong = tampered(&second, |block| block.notarization = Some(rejecting));
        assert!(!h.verifies(&context, &first, 2, &wrong).await);
        assert!(!h.replays(&context, &first, 2, &wrong).await);

        // Votes that the validators did not sign.
        let strangers =
            constantinople_auth::fixture(&mut context.child("strangers"), CONSENSUS_NS, VALIDATORS);
        let forged = notarization(&strangers, &first, |_| vec![true]);
        let wrong = tampered(&second, |block| block.notarization = Some(forged));
        assert!(!h.verifies(&context, &first, 2, &wrong).await);

        // A header that does not commit to what the block carries.
        let mut inner = second.clone().into_inner();
        inner.header.parent_outcomes = sha256::Digest::EMPTY;
        let wrong = inner.seal(&mut sha256::Sha256::default());
        assert!(!h.verifies(&context, &first, 2, &wrong).await);
        assert!(!h.replays(&context, &first, 2, &wrong).await);

        // None of this disturbed the block itself.
        assert!(h.verifies(&context, &first, 2, &second).await);
        assert!(h.replays(&context, &first, 2, &second).await);
    });
}

#[test]
fn the_first_block_carries_no_notarization() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Box::pin(verify_harness(&context)).await;
        let genesis = h.parent.clone();
        let first = h
            .propose(&context, &genesis, 1, Vec::new())
            .await
            .expect("proposal succeeds")
            .block;

        let spurious = notarization(&h.validators, &genesis, |_| Vec::new());
        let wrong = tampered(&first, |block| block.notarization = Some(spurious));
        assert!(!h.verifies(&context, &genesis, 1, &wrong).await);
        assert!(!h.replays(&context, &genesis, 1, &wrong).await);
        assert!(h.verifies(&context, &genesis, 1, &first).await);
    });
}

#[test]
fn replay_needs_the_parent() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Box::pin(verify_harness(&context)).await;
        let genesis = h.parent.clone();
        let first = h
            .extend(
                &context,
                &genesis,
                1,
                vec![transfer(&h.sender, &h.recipient, 1).into()],
            )
            .await;
        h.notarize(&first);
        let second = h
            .propose(&context, &first, 2, Vec::new())
            .await
            .expect("proposal succeeds")
            .block;
        assert!(h.replays(&context, &first, 2, &second).await);

        // The replay is handed the block alone and executes its parent's body.
        h.chain.blocks.lock().clear();
        assert!(!h.replays(&context, &first, 2, &second).await);
    });
}

#[test]
fn a_block_lists_a_transaction_once() {
    let sender = ed25519::PrivateKey::from_seed(1);
    let recipient = ed25519::PrivateKey::from_seed(2);
    let lazy = |value| LazySignedTransaction::new(transfer(&sender, &recipient, value));
    let digests = |body: &[_]| super::execution::body_digests(&Sequential, body);

    assert_eq!(
        digests(&[lazy(1), lazy(2)]).map(|digests| digests.len()),
        Ok(2)
    );
    assert_eq!(
        digests(&[lazy(1), lazy(2), lazy(1)]),
        Err(super::DUPLICATE_TRANSACTION)
    );
}
