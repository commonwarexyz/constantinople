use super::*;

#[path = "scan_tests.rs"]
mod scan_tests;

use crate::{
    publisher::{
        Publisher, PublisherMetrics,
        certificate::CertificateReporter,
        fixture::{Scheme, threshold},
        qmdb::{CapturedFinalizedUpload, QueuedFinalizedUpload, QueuedFinalizedUploadCfg},
    },
    store::writer_store_client,
    test_store::ObservedStore,
};
use axum::{
    body::{Body, to_bytes},
    http::{HeaderName, Method, Request},
};
use commonware_codec::Encode;
use commonware_consensus::{
    marshal::coding::types::coding_config_for_participants,
    simplex::types::{Context as SimplexContext, Finalization, Finalize, Proposal},
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    Committable as _, Digest as _, Digested, Hasher as _, Signer as _,
    secp256r1::standard as secp256r1,
};
use commonware_cryptography_curve25519::signing as ed25519;
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _};
use commonware_storage::{
    merkle::{Family as _, mem::Mem},
    qmdb::any::unordered::Update,
};
use commonware_utils::{NZUsize, non_empty_range};
use constantinople_application::consensus::{
    FinalizedArtifacts, FinalizedRange, StateOperation as CapturedStateOperation,
    TransactionHistoryOperation,
};
use constantinople_engine::types::{EngineBlock, EngineCodedBlock, EngineFinalization};
use constantinople_primitives::{
    Block, Header as BlockHeader, Nonce, PublicKeyCache, Sealable, TRANSACTION_NAMESPACE,
    Transaction, TransactionPublicKey, TransactionSignature, verify_transactions,
};
use p256::ecdsa::{SigningKey, signature::Signer as _};
use rand::{SeedableRng, rngs::StdRng};
use serde_json::{Value, json};
use std::num::NonZeroU64;
use tower::ServiceExt as _;
use tower_http::cors::{Any, CorsLayer};

type TestBlock = EngineBlock<Sha256, VerifyingKey>;
type TestFinalization = EngineFinalization<VerifyingKey, MinSig>;
type Upload = QueuedFinalizedUpload<Sha256, VerifyingKey, MinSig>;

/// One finalized fixture block with its certificate and publisher upload.
struct FixtureBlock {
    block: TestBlock,
    finalization: TestFinalization,
    upload: Upload,
    /// Transaction-hash QMDB location of the block's first transaction.
    first_transaction: u64,
    transactions: Vec<SignedTransaction<Sha256>>,
}

/// Chained fixture blocks and the accounts their transactions touch.
struct Fixture {
    blocks: Vec<FixtureBlock>,
    /// Sender of every ed25519 fixture transaction.
    account: AccountKey,
    /// Receiver of every non-final transfer in a block.
    recipient: AccountKey,
    /// Hex threshold identity that verifies fixture certificates.
    verification_material: String,
}

/// Store, explorer router, and publishing workers for one fixture run.
struct FixtureStore {
    store: ObservedStore,
    client: StoreClient,
    router: Router,
    publisher: Publisher<Sha256, VerifyingKey>,
    worker: commonware_runtime::Handle<()>,
    reporter: CertificateReporter<Sha256, VerifyingKey, Scheme>,
    reporter_worker: commonware_runtime::Handle<()>,
}

impl FixtureStore {
    /// Opens an observed Store and connects the router, QMDB publisher, and
    /// certificate reporter with the same writer credential.
    async fn open(context: commonware_runtime::tokio::Context) -> Self {
        let store = ObservedStore::open("explorer-fixture").await.unwrap();
        let client = writer_store_client(&store.url, Some("explorer-fixture")).unwrap();
        let router = router(&client).unwrap();
        let (publisher, worker) = Publisher::connect(
            context.child("publisher"),
            &store.url,
            Some("explorer-fixture"),
            4,
            PublisherMetrics::new(&context.child("metrics")),
            Sequential,
            true,
        )
        .await
        .unwrap();
        let (reporter, reporter_worker) =
            CertificateReporter::<Sha256, VerifyingKey, Scheme>::connect(
                context.child("certificates"),
                &store.url,
                Some("explorer-fixture"),
                4,
            )
            .unwrap();
        Self {
            store,
            client,
            router,
            publisher,
            worker,
            reporter,
            reporter_worker,
        }
    }

    /// Drains both workers before shutting down the Store.
    async fn close(self) {
        drop(self.reporter);
        self.reporter_worker.await.unwrap();
        drop(self.publisher);
        self.worker.await.unwrap();
        self.store.shutdown().await;
    }
}

/// Builds the captured QMDB range from `start` to the end of `operations`,
/// rooted at the inactivity `floor`.
fn captured_range<Op: Clone + Encode>(
    operations: &[Op],
    start: u64,
    floor: u64,
) -> FinalizedRange<Digest, Op> {
    // Merkleize every operation and compute the root at the inactivity floor.
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    let mut memory = Mem::<mmr::Family, _>::new();
    let mut batch = memory.new_batch();
    for operation in operations {
        batch = batch.add(&hasher, &operation.encode());
    }
    let batch = batch.merkleize(&memory, &hasher);
    let end = Location::new(operations.len() as u64);
    let root = batch
        .root(
            &hasher,
            mmr::Family::inactive_peaks(end, Location::new(floor)),
        )
        .expect("fixture range must have a root at its inactivity floor");

    // Apply the operations and pin the prefix nodes so the range can be
    // published from `start`.
    memory
        .apply_batch(&batch)
        .expect("fixture operations must apply to the in-memory log");
    let start = Location::new(start);
    let pinned_nodes = mmr::Family::nodes_to_pin(start)
        .map(|position| {
            memory
                .get_node(position)
                .expect("fixture prefix nodes must be present")
        })
        .collect();
    FinalizedRange {
        start,
        end,
        root,
        pinned_nodes,
        operations: Arc::new(operations[start.as_u64() as usize..].to_vec()),
    }
}

/// Builds a valid secp256r1 WebAuthn transaction whose encoding is exactly
/// [`MAX_TRANSACTION_BYTES`].
fn webauthn_transaction() -> SignedTransaction<Sha256> {
    let signer = SigningKey::from_slice(&[3; 32]).expect("fixture P256 scalar must be valid");
    let key = secp256r1::PublicKey::decode(Bytes::copy_from_slice(
        signer.verifying_key().to_sec1_point(true).as_bytes(),
    ))
    .unwrap();
    let sender = TransactionPublicKey::secp256r1(key);
    let sealed = Transaction::<Digest>::new(sender.clone(), sender, NonZeroU64::MIN, 0)
        .seal(&mut Sha256::default());

    // Encode the transaction digest as the unpadded base64url challenge.
    let mut challenge = String::new();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for chunk in sealed.seal().as_ref().chunks(3) {
        let word = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for shift in [18, 12, 6, 0].into_iter().take(chunk.len() + 1) {
            challenge.push(alphabet[((word >> shift) & 63) as usize] as char);
        }
    }

    // Pad client and authenticator data to their maximum sizes, then sign the
    // authenticator data followed by the client-data hash with a low-S signature.
    let mut client_data =
        serde_json::to_vec(&json!({"type": "webauthn.get", "challenge": challenge})).unwrap();
    client_data.resize(512, b' ');
    let mut authenticator_data = vec![0; 256];
    authenticator_data[32] = 4;
    let mut payload = authenticator_data.clone();
    payload.extend_from_slice(Sha256::hash(&[&client_data]).as_ref());
    let signature: p256::ecdsa::Signature = signer.sign(&payload);
    let signature = signature.normalize_s();
    let signature =
        secp256r1::Signature::decode(Bytes::copy_from_slice(signature.to_bytes().as_slice()))
            .unwrap();
    let signature =
        TransactionSignature::secp256r1(signature, authenticator_data, client_data).unwrap();
    let signed = SignedTransaction::new_unchecked(sealed, signature);

    // The padded transaction must reach the codec limit exactly.
    assert_eq!(signed.encode().len(), MAX_TRANSACTION_BYTES);
    signed
}

/// Builds four chained blocks with 3, 55, 0, and 2 transactions, each with a
/// threshold finalization. Block 2's upload omits its certificate, and block 4
/// carries a maximum-size WebAuthn transaction.
async fn fixture() -> Fixture {
    // Derive deterministic consensus, transaction, and leader keys.
    let mut rng = StdRng::from_seed([42; 32]);
    let (schemes, verifier) = threshold(&mut rng, b"constantinople_CONSENSUS", 4);
    let signer = ed25519::SigningKey::from_seed(7);
    let sender = TransactionPublicKey::ed25519(signer.public_key());
    let receiver = TransactionPublicKey::ed25519(ed25519::SigningKey::from_seed(8).public_key());
    let account = AccountKey::from_public_key(&sender);
    let recipient = AccountKey::from_public_key(&receiver);
    let leader = ed25519::SigningKey::from_seed(9).public_key();

    // Both QMDB logs start with an initial commit at location zero.
    let mut state_operations = vec![CapturedStateOperation::CommitFloor(None, Location::new(0))];
    let mut transaction_operations = vec![TransactionHistoryOperation::<Sha256>::Commit(
        None,
        Location::new(0),
    )];
    let mut blocks: Vec<FixtureBlock> = Vec::new();
    let mut parent = Digest::EMPTY;
    let coding_config = coding_config_for_participants(schemes.len() as u16);
    let mut parent_commitment = EngineCommitment::<Sha256, VerifyingKey>::from((
        Digest::EMPTY,
        Digest::EMPTY,
        Digest::EMPTY,
        coding_config,
    ));
    let mut nonce = 0;
    let mut balance = 100;

    for (index, count) in [3, 55, 0, 2].into_iter().enumerate() {
        // Each block's transaction floor is its parent's first transaction, so
        // earlier blocks fall below the floor of later certificates.
        let height = index as u64 + 1;
        let state_start = state_operations.len() as u64;
        let transaction_start = transaction_operations.len() as u64;
        let first_transaction = transaction_operations.len() as u64;
        let transaction_floor = blocks.last().map_or(0, |parent| parent.first_transaction);

        // Every transfer goes to the recipient except each block's last, which
        // is a self-transfer. Block 4's last slot holds the WebAuthn fixture.
        let transactions = (0..count)
            .map(|index| {
                if height == 4 && index == 1 {
                    let transaction = webauthn_transaction();
                    transaction_operations.push(TransactionHistoryOperation::<Sha256>::Append(
                        *transaction.message_digest(),
                    ));
                    return transaction;
                }
                let to = if index + 1 == count {
                    sender.clone()
                } else {
                    receiver.clone()
                };
                if to != sender {
                    balance -= 1;
                }
                let transaction =
                    Transaction::<Digest>::new(sender.clone(), to, NonZeroU64::MIN, nonce)
                        .seal_and_sign(&signer, TRANSACTION_NAMESPACE, &mut Sha256::default());
                nonce += 1;
                transaction_operations.push(TransactionHistoryOperation::<Sha256>::Append(
                    *transaction.message_digest(),
                ));
                transaction
            })
            .collect::<Vec<_>>();

        // Close the block with a transaction commit, an account update, and a
        // state commit.
        transaction_operations.push(TransactionHistoryOperation::<Sha256>::Commit(
            None,
            Location::new(transaction_floor),
        ));
        state_operations.push(CapturedStateOperation::Update(Update(
            account,
            Account {
                balance,
                nonce: Nonce::new(nonce, 0),
            },
        )));
        state_operations.push(CapturedStateOperation::CommitFloor(None, Location::new(1)));

        // Capture both ranges and seal a header that commits to their roots.
        let state = captured_range(&state_operations, state_start, 0);
        let transactions_range = captured_range(
            &transaction_operations,
            transaction_start,
            transaction_floor,
        );
        let header = BlockHeader {
            context: SimplexContext {
                round: Round::new(Epoch::zero(), View::new(height)),
                leader: leader.clone(),
                parent: (View::new(height - 1), parent_commitment),
            },
            parent,
            height,
            timestamp: height,
            state_root: state.root,
            state_range: non_empty_range!(0, state.end.as_u64()),
            transactions_root: transactions_range.root,
            transactions_range: non_empty_range!(
                transaction_floor,
                transactions_range.end.as_u64()
            ),
        };
        let block: TestBlock = Block::new(header, transactions.clone())
            .seal(&mut Sha256::default())
            .into();

        // Certify the coded commitment that consensus would finalize.
        let coded = EngineCodedBlock::encode(
            Digested::precomputed(block.clone(), *block.seal()),
            coding_config,
            &Sequential,
        )
        .await;
        let commitment = coded.commitment();
        let finalization = finalization(&block, commitment, &schemes, &verifier);

        // Round-trip the upload through the publisher queue encoding, omitting
        // block 2's certificate.
        let captured =
            CapturedFinalizedUpload::<Sha256, VerifyingKey, MinSig>::from_finalized_artifacts(
                &block,
                (height != 2).then(|| finalization.clone()),
                height as i64,
                FinalizedArtifacts {
                    state,
                    transactions: transactions_range,
                },
            )
            .expect("fixture artifacts must form a captured upload");
        let upload = Upload::decode_cfg(captured.encode(), &QueuedFinalizedUploadCfg::default())
            .expect("captured upload must decode as a queued upload");

        parent = *block.seal();
        parent_commitment = commitment;
        blocks.push(FixtureBlock {
            block,
            finalization,
            upload,
            first_transaction,
            transactions,
        });
    }
    Fixture {
        blocks,
        account,
        recipient,
        verification_material: hex(&verifier.identity().encode()),
    }
}

/// Signs `block`'s proposal with every scheme and assembles the certificate.
fn finalization(
    block: &TestBlock,
    commitment: EngineCommitment<Sha256, VerifyingKey>,
    schemes: &[Scheme],
    verifier: &Scheme,
) -> TestFinalization {
    let proposal = Proposal::new(
        block.header.context.round,
        block.header.context.parent.0,
        commitment,
    );
    let votes = schemes
        .iter()
        .map(|scheme| {
            Finalize::sign(scheme, proposal.clone())
                .expect("every fixture scheme must sign the proposal")
        })
        .collect::<Vec<_>>();
    Finalization::from_finalizes(
        verifier,
        commonware_utils::iter::NonEmpty::try_new(votes.iter()).unwrap(),
        &Sequential,
    )
    .expect("fixture votes must assemble a threshold certificate")
}

/// Publishes a fixture block's QMDB upload and then its Simplex block, with the
/// certificate only when `certificate` is set, waiting for both writes.
async fn publish(
    publisher: &Publisher<Sha256, VerifyingKey>,
    reporter: &CertificateReporter<Sha256, VerifyingKey, Scheme>,
    block: &FixtureBlock,
    certificate: bool,
) {
    let upload =
        Upload::decode_cfg(block.upload.encode(), &QueuedFinalizedUploadCfg::default()).unwrap();
    publisher
        .enqueue_queued_finalized(upload)
        .await
        .expect("fixture block must enqueue")
        .published()
        .await
        .expect("fixture block must publish");
    reporter
        .publish_finalized_block(
            block.block.clone(),
            certificate.then(|| block.finalization.clone()),
        )
        .await
        .expect("fixture certificate must enqueue")
        .wait()
        .await
        .expect("fixture certificate must publish");
}

/// Sends a GET through the router and returns the status and JSON body.
async fn get(router: &Router, path: &str) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
        .await
        .expect("response must fit within the response limit");
    (
        status,
        serde_json::from_slice(&body).expect("response must be JSON"),
    )
}

/// Asserts that a GET succeeds and returns its JSON body.
async fn ok(router: &Router, path: &str) -> Value {
    let (status, response) = get(router, path).await;
    assert_eq!(status, StatusCode::OK, "{path} must succeed: {response}");
    response
}

/// Decodes the height certified by a bundle's certificate.
fn certificate_height(bundle: &Value) -> u64 {
    let encoded = hex_bytes_dynamic(bundle["certificate"].as_str().unwrap());
    Certificate::decode_cfg(Bytes::from(encoded), &((), ()))
        .unwrap()
        .header
        .header()
        .height
}

fn hex_bytes_dynamic(value: &str) -> Vec<u8> {
    let (pairs, _) = value.as_bytes().as_chunks::<2>();
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

/// Asserts that a bundle returns `count` rows of `block` starting at block index
/// `offset`, with a proof exactly when rows are present.
fn assert_transactions(bundle: &Value, block: &FixtureBlock, offset: usize, count: usize) {
    let rows = bundle["transactions"].as_array().unwrap();
    assert_eq!(rows.len(), count);
    for (index, row) in rows.iter().enumerate() {
        let position = offset + index;
        assert_eq!(row["height"], block.block.header.height.to_string());
        assert_eq!(row["index"], position);
        assert_eq!(
            row["location"],
            (block.first_transaction + position as u64).to_string()
        );
        assert_eq!(row["body"], hex(&block.transactions[position].encode()));
    }
    assert_eq!(bundle["transactionsProof"].is_null(), count == 0);
}

/// Asserts that a bundle carries the multi-proof an independent QMDB client
/// produces at `certified`'s tip for the returned locations.
async fn assert_transaction_proof(client: &StoreClient, bundle: &Value, certified: &FixtureBlock) {
    // Recompute the proof directly from the transaction log.
    let locations = bundle["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| Location::new(row["location"].as_str().unwrap().parse().unwrap()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let log = TransactionLog::new(transactions_qmdb_client(client).unwrap(), ());
    let proof = log
        .operation_multi_proof(
            Location::new(certified.block.header.transactions_range.end() - 1),
            &locations,
            None,
        )
        .await
        .expect("native QMDB client must prove the returned locations");

    // The bundle must carry the same proof, which verifies against the
    // certified root.
    assert_eq!(proof.ops_root, certified.block.header.transactions_root);
    assert!(proof.verify::<Sha256>());
    assert_eq!(
        bundle["transactionsProof"],
        hex(&encode_historical_multi_proof(&proof))
    );

    // A changed operation or root must fail verification.
    let mut changed = proof.clone();
    changed.operations[0].1[0] ^= 1;
    assert!(!changed.verify::<Sha256>());
    let mut wrong_root = proof;
    wrong_root.ops_root = Digest::EMPTY;
    assert!(!wrong_root.verify::<Sha256>());
}

/// Publishes blocks 1 through 3 with only block 3 certified, then returns the
/// bundles for block 1 and its first transaction.
async fn historical_bundles(
    context: commonware_runtime::tokio::Context,
    fixture: &Fixture,
) -> (Value, Value) {
    // Publish the first three blocks, certifying only block 3.
    let environment = FixtureStore::open(context).await;
    for (index, block) in fixture.blocks[..3].iter().enumerate() {
        publish(
            &environment.publisher,
            &environment.reporter,
            block,
            index == 2,
        )
        .await;
    }

    // Block 1's transactions sit below block 3's inactivity floor yet remain
    // provable at block 3's tip.
    let block = &fixture.blocks[0];
    let certified = &fixture.blocks[2];
    assert!(block.first_transaction < certified.block.header.transactions_range.start());
    let native = TransactionLog::new(transactions_qmdb_client(&environment.client).unwrap(), ());
    let proof = native
        .operation_multi_proof(
            Location::new(certified.block.header.transactions_range.end() - 1),
            &[Location::new(block.first_transaction)],
            None,
        )
        .await
        .expect("locations below the inactivity floor must remain provable");
    assert_eq!(proof.ops_root, certified.block.header.transactions_root);
    assert!(proof.verify::<Sha256>());

    // Both routes prove block 1 through block 3's certificate.
    let historical_block = ok(&environment.router, "/explorer/blocks/1").await;
    assert_eq!(certificate_height(&historical_block), 3);
    assert_transactions(&historical_block, block, 0, 3);
    let digest = hex(block.transactions[0].message_digest().as_ref());
    let historical_transaction = ok(
        &environment.router,
        &format!("/explorer/transactions/{digest}"),
    )
    .await;
    assert_eq!(certificate_height(&historical_transaction), 3);
    assert_transactions(&historical_transaction, block, 0, 1);
    environment.close().await;
    (historical_block, historical_transaction)
}

#[test]
fn historical_transactions_below_inactivity_floor_remain_available() {
    commonware_runtime::tokio::Runner::default().start(|context| async move {
        let fixture = fixture().await;
        Box::pin(historical_bundles(context, &fixture)).await;
    });
}

/// Adds a `server-timing` header with the handler duration in milliseconds.
async fn measure_handler(request: Request<Body>, next: axum::middleware::Next) -> Response {
    let start = std::time::Instant::now();
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        HeaderName::from_static("server-timing"),
        format!("handler;dur={:.3}", start.elapsed().as_secs_f64() * 1000.0)
            .parse()
            .unwrap(),
    );
    response
}

/// Serves the fixture router for browser tests when
/// `EXPLORER_LIVE_METADATA_PATH` is set, until a POST to `/__shutdown`.
async fn serve_fixture_if_requested(router: Router, fixture: &Fixture) {
    let Some(path) = std::env::var_os("EXPLORER_LIVE_METADATA_PATH") else {
        return;
    };

    // Bind a local listener and add timing, shutdown, and CORS layers for
    // browser access.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("live fixture listener must bind");
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let shutdown = Arc::new(std::sync::Mutex::new(Some(shutdown)));
    let server = router
        .layer(axum::middleware::from_fn(measure_handler))
        .route(
            "/__shutdown",
            axum::routing::post(move || {
                let shutdown = shutdown.clone();
                async move {
                    if let Some(shutdown) = shutdown.lock().unwrap().take() {
                        let _ = shutdown.send(());
                    }
                    StatusCode::NO_CONTENT
                }
            }),
        )
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST])
                .allow_headers(Any)
                .expose_headers([HeaderName::from_static("server-timing")]),
        );

    // Write the server URL and sample request parameters for the browser test.
    let account = hex(fixture.account.as_ref());
    let snapshot_digest = hex(fixture.blocks[2].block.seal().as_ref());
    let metadata = json!({
        "url": url,
        "verificationMaterial": fixture.verification_material,
        "account": account,
        "recipient": hex(fixture.recipient.as_ref()),
        "latestAccountHeight": "4",
        "latestAccountDigest": hex(fixture.blocks[3].block.seal().as_ref()),
        "sampleAccountPath": format!("/explorer/accounts/{account}?at=3&digest={snapshot_digest}"),
        "blockHeight": "2",
        "transactionDigest": hex(fixture.blocks[1].transactions[54].message_digest().as_ref()),
        "shutdownUrl": format!("{url}/__shutdown"),
    });
    let path = std::path::PathBuf::from(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("live fixture metadata directory must be creatable");
    }
    std::fs::write(path, serde_json::to_vec_pretty(&metadata).unwrap())
        .expect("live fixture metadata must be writable");

    // Serve until the shutdown route fires.
    axum::serve(listener, server)
        .with_graceful_shutdown(async {
            let _ = stopped.await;
        })
        .await
        .expect("live fixture server must run until shutdown");
}

#[test]
fn publisher_bundles_cover_descendants_empty_blocks_and_fixed_account_pages() {
    commonware_runtime::tokio::Runner::default().start(|context| async move {
        // The fixture's WebAuthn block must pass ordinary signature verification.
        let fixture = fixture().await;
        assert!(verify_transactions(
            TRANSACTION_NAMESPACE,
            &mut StdRng::from_seed([77; 32]),
            &PublicKeyCache::new(context.child("signature_cache"), NZUsize!(4)),
            &fixture.blocks[3].transactions,
            &Sequential,
        ));

        // Publish block 1 with a certificate and block 2 without one.
        let environment = FixtureStore::open(context.child("primary")).await;
        let store = &environment.store;
        let client = &environment.client;
        let router = &environment.router;
        let publisher = &environment.publisher;
        let reporter = &environment.reporter;
        publish(publisher, reporter, &fixture.blocks[0], true).await;
        publish(publisher, reporter, &fixture.blocks[1], false).await;

        // Block 2 has no covering certificate yet, so it stays unavailable while
        // the account view falls back to block 1's certificate.
        let (status, _) = get(router, "/explorer/blocks/2").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let account_path = format!("/explorer/accounts/{}", hex(fixture.account.as_ref()));
        let lagging_account = ok(router, &account_path).await;
        assert_eq!(certificate_height(&lagging_account), 1);
        assert_eq!(lagging_account["transactions"].as_array().unwrap().len(), 3);

        // Certifying block 3 lets block 1 prove directly and block 2 prove
        // through block 3's ancestry.
        publish(publisher, reporter, &fixture.blocks[2], true).await;
        let direct = ok(router, "/explorer/blocks/1").await;
        assert_eq!(certificate_height(&direct), 1);
        assert_eq!(direct["headers"], json!([]));
        assert_transactions(&direct, &fixture.blocks[0], 0, 3);
        assert_transaction_proof(client, &direct, &fixture.blocks[0]).await;
        let descendant = ok(router, "/explorer/blocks/2").await;
        assert_eq!(certificate_height(&descendant), 3);
        assert_eq!(
            descendant["headers"],
            json!([
                hex(&fixture.blocks[1].block.header.encode()),
                hex(&fixture.blocks[0].block.header.encode()),
            ])
        );
        assert_transactions(&descendant, &fixture.blocks[1], 0, 50);
        assert_transaction_proof(client, &descendant, &fixture.blocks[2]).await;

        // Block 2 pages at 50 transactions, returns an empty page at its exact
        // count, and rejects any offset beyond it.
        assert_eq!(descendant["nextCursor"], "50");
        let last = ok(router, "/explorer/blocks/2?offset=50").await;
        assert_transactions(&last, &fixture.blocks[1], 50, 5);
        assert!(last["nextCursor"].is_null());
        let terminal = ok(router, "/explorer/blocks/2?offset=55").await;
        assert_transactions(&terminal, &fixture.blocks[1], 55, 0);
        assert_eq!(
            get(router, "/explorer/blocks/2?offset=56").await.0,
            StatusCode::BAD_REQUEST
        );

        // An empty block returns its certificate and parent header without a
        // proof.
        let empty = ok(router, "/explorer/blocks/3").await;
        assert_eq!(certificate_height(&empty), 3);
        assert_transactions(&empty, &fixture.blocks[2], 0, 0);
        assert_eq!(
            empty["headers"],
            json!([hex(&fixture.blocks[1].block.header.encode())])
        );

        // The account view proves the latest update and returns the newest ten
        // activity rows.
        let account = ok(router, &account_path).await;
        assert_eq!(certificate_height(&account), 3);
        assert_eq!(account["account"]["location"], "5");
        assert_eq!(account["transactions"].as_array().unwrap().len(), 10);
        assert_eq!(account["transactions"][0]["index"], 54);
        assert_eq!(account["transactions"][0]["role"], 0);
        assert_transaction_proof(client, &account, &fixture.blocks[2]).await;

        // A cursor on the pinned snapshot continues with the next ten rows.
        let cursor = account["nextCursor"].as_str().unwrap();
        let pinned = format!(
            "{account_path}?at=3&digest={}&cursor={cursor}",
            hex(fixture.blocks[2].block.seal().as_ref())
        );
        let next = ok(router, &pinned).await;
        assert_eq!(next["transactions"][0]["index"], 44);
        assert_eq!(next["transactions"][9]["index"], 35);

        // Disabling activity keeps the account proof and returns no rows.
        let state_only = ok(router, &format!("{account_path}?activity=false")).await;
        assert!(state_only["transactions"].as_array().unwrap().is_empty());
        assert!(state_only["transactionsProof"].is_null());
        assert_eq!(state_only["account"], account["account"]);

        // The recipient has no state update, and its received filter returns
        // only receiver rows.
        let recipient = ok(
            router,
            &format!(
                "/explorer/accounts/{}?mode=received",
                hex(fixture.recipient.as_ref())
            ),
        )
        .await;
        assert!(recipient["account"].is_null());
        assert_eq!(recipient["transactions"][0]["index"], 53);
        assert_eq!(recipient["transactions"][0]["role"], 1);

        // A transaction in block 2 proves through block 3's certificate.
        let digest = hex(fixture.blocks[1].transactions[54].message_digest().as_ref());
        let transaction = ok(router, &format!("/explorer/transactions/{digest}")).await;
        assert_eq!(certificate_height(&transaction), 3);
        assert_transactions(&transaction, &fixture.blocks[1], 54, 1);

        // After block 4 arrives, the pinned page is unchanged while the latest
        // view moves to block 4 and still reaches earlier blocks.
        publish(publisher, reporter, &fixture.blocks[3], true).await;
        let after_arrival = ok(router, &pinned).await;
        for field in [
            "certificate",
            "headers",
            "account",
            "transactions",
            "transactionsProof",
            "nextCursor",
        ] {
            assert_eq!(after_arrival[field], next[field], "pinned field {field} must not change");
        }
        let account_with_history = ok(router, &account_path).await;
        assert_eq!(certificate_height(&account_with_history), 4);
        assert!(account_with_history["transactions"].as_array().unwrap().iter().any(|row| {
            row["location"].as_str().unwrap().parse::<u64>().unwrap()
                < fixture.blocks[3].block.header.transactions_range.start()
        }));

        // Both routes serve block 4's maximum-size WebAuthn transaction in full.
        let webauthn_digest = hex(fixture.blocks[3].transactions[1].message_digest().as_ref());
        let webauthn_block = ok(router, "/explorer/blocks/4").await;
        assert_transactions(&webauthn_block, &fixture.blocks[3], 0, 2);
        let webauthn_bundle = ok(
            router,
            &format!("/explorer/transactions/{webauthn_digest}"),
        )
        .await;
        assert_transactions(&webauthn_bundle, &fixture.blocks[3], 1, 1);
        assert_eq!(
            webauthn_bundle["transactions"][0]["body"]
                .as_str()
                .unwrap()
                .len(),
            MAX_TRANSACTION_BYTES * 2
        );

        // Export the bundles for browser verification tests when requested.
        if let Some(path) = std::env::var_os("EXPLORER_FIXTURE_PATH") {
            let (historical_block, historical_transaction) = Box::pin(historical_bundles(context.child("historical_export"), &fixture)).await;
            let export = json!({
                "verificationMaterial": fixture.verification_material,
                "account": hex(fixture.account.as_ref()),
                "recipient": hex(fixture.recipient.as_ref()),
                "transactionDigest": digest,
                "directBlock": direct,
                "descendantBlock": descendant,
                "descendantLastPage": last,
                "emptyBlock": empty,
                "accountBundle": account,
                "accountNext": next,
                "accountStateOnly": state_only,
                "recipientBundle": recipient,
                "transactionBundle": transaction,
                "webauthnDigest": webauthn_digest,
                "webauthnBlock": webauthn_block,
                "webauthnBundle": webauthn_bundle,
                "accountWithHistory": account_with_history,
                "historicalBlock": historical_block,
                "historicalTransaction": historical_transaction,
                "historicalDigest": hex(fixture.blocks[0].transactions[0].message_digest().as_ref()),
            });
            std::fs::write(path, serde_json::to_vec_pretty(&export).unwrap())
                .expect("requested browser fixture must be writable");
        }

        // Every Store request must carry the writer credential.
        assert!(store.requests().iter().all(|request| request.authorized));

        serve_fixture_if_requested(environment.router.clone(), &fixture).await;
        environment.close().await;
    });
}

#[test]
fn signed_transaction_size_limit_matches_the_public_codec() {
    // The fixture sits exactly at the codec limit, and one more byte exceeds it.
    let transaction = webauthn_transaction();
    let mut body = transaction.encode().to_vec();
    assert_eq!(body.len(), 919);
    assert!(transaction_body(&body, transaction.message_digest()).is_ok());
    body.push(0);
    let error = transaction_body(&body, transaction.message_digest()).unwrap_err();
    assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn malformed_inputs_are_rejected_before_store_reads() {
    // Open a router over an empty observed Store.
    let store = ObservedStore::open("explorer-fixture").await.unwrap();
    let client = writer_store_client(&store.url, Some("explorer-fixture")).unwrap();
    let router = router(&client).unwrap();

    // Each path must fail parsing with 400 before any Store read.
    let account = "00".repeat(32);
    let paths = [
        "/explorer/blocks/0".to_owned(),
        "/explorer/blocks/-1".to_owned(),
        "/explorer/blocks/18446744073709551616".to_owned(),
        "/explorer/blocks/1?offset=-1".to_owned(),
        "/explorer/blocks/1?offset=18446744073709551616".to_owned(),
        "/explorer/accounts/00".to_owned(),
        format!("/explorer/accounts/{}", "gg".repeat(32)),
        format!("/explorer/accounts/{account}?mode=unknown"),
        format!("/explorer/accounts/{account}?cursor=00"),
        format!("/explorer/accounts/{account}?cursor={}", "00".repeat(24)),
        format!("/explorer/accounts/{account}?at=1"),
        format!("/explorer/accounts/{account}?digest={account}"),
        format!("/explorer/accounts/{account}?at=0&digest={account}"),
        format!("/explorer/accounts/{account}?activity=maybe"),
        "/explorer/transactions/00".to_owned(),
        format!("/explorer/transactions/{}", "zz".repeat(32)),
    ];
    for path in paths {
        let (status, response) = get(&router, &path).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{path} must be rejected: {response}"
        );
    }
    assert!(store.requests().is_empty());
    store.shutdown().await;
}
