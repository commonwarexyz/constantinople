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

struct FixtureBlock {
    block: TestBlock,
    finalization: TestFinalization,
    upload: Upload,
    first_transaction: u64,
    transactions: Vec<SignedTransaction<Sha256>>,
}

struct Fixture {
    blocks: Vec<FixtureBlock>,
    account: AccountKey,
    recipient: AccountKey,
    verification_material: String,
}

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

    async fn close(self) {
        drop(self.reporter);
        self.reporter_worker.await.unwrap();
        drop(self.publisher);
        self.worker.await.unwrap();
        self.store.shutdown().await;
    }
}

fn captured_range<Op: Clone + Encode>(
    operations: &[Op],
    start: u64,
    floor: u64,
) -> FinalizedRange<Digest, Op> {
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
        .expect("fixture root at inactivity floor");
    memory
        .apply_batch(&batch)
        .expect("apply fixture operations");
    let start = Location::new(start);
    let pinned_nodes = mmr::Family::nodes_to_pin(start)
        .map(|position| memory.get_node(position).expect("fixture prefix node"))
        .collect();
    FinalizedRange {
        start,
        end,
        root,
        pinned_nodes,
        operations: Arc::new(operations[start.as_u64() as usize..].to_vec()),
    }
}

fn webauthn_transaction() -> SignedTransaction<Sha256> {
    let signer = SigningKey::from_slice(&[3; 32]).expect("fixture P256 scalar");
    let key = secp256r1::PublicKey::decode(Bytes::copy_from_slice(
        signer.verifying_key().to_sec1_point(true).as_bytes(),
    ))
    .unwrap();
    let sender = TransactionPublicKey::secp256r1(key);
    let sealed = Transaction::<Digest>::new(sender.clone(), sender, NonZeroU64::MIN, 0)
        .seal(&mut Sha256::default());
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
    assert_eq!(signed.encode().len(), MAX_TRANSACTION_BYTES);
    signed
}

async fn fixture() -> Fixture {
    let mut rng = StdRng::from_seed([42; 32]);
    let (schemes, verifier) = threshold(&mut rng, b"constantinople_CONSENSUS", 4);
    let signer = ed25519::SigningKey::from_seed(7);
    let sender = TransactionPublicKey::ed25519(signer.public_key());
    let receiver = TransactionPublicKey::ed25519(ed25519::SigningKey::from_seed(8).public_key());
    let account = AccountKey::from_public_key(&sender);
    let recipient = AccountKey::from_public_key(&receiver);
    let leader = ed25519::SigningKey::from_seed(9).public_key();
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
        let height = index as u64 + 1;
        let state_start = state_operations.len() as u64;
        let transaction_start = transaction_operations.len() as u64;
        let first_transaction = transaction_operations.len() as u64;
        let transaction_floor = blocks.last().map_or(0, |parent| parent.first_transaction);
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
        let coded = EngineCodedBlock::encode(
            Digested::precomputed(block.clone(), *block.seal()),
            coding_config,
            &Sequential,
        )
        .await;
        let commitment = coded.commitment();
        let finalization = finalization(&block, commitment, &schemes, &verifier);
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
            .expect("captured publisher fixture");
        let upload = Upload::decode_cfg(captured.encode(), &QueuedFinalizedUploadCfg::default())
            .expect("publisher queue fixture");
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
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("fixture vote"))
        .collect::<Vec<_>>();
    Finalization::from_finalizes(
        verifier,
        commonware_utils::iter::NonEmpty::try_new(votes.iter()).unwrap(),
        &Sequential,
    )
    .expect("fixture threshold certificate")
}

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
        .expect("enqueue fixture block")
        .published()
        .await
        .expect("publish fixture block");
    reporter
        .publish_finalized_block(
            block.block.clone(),
            certificate.then(|| block.finalization.clone()),
        )
        .await
        .expect("enqueue fixture certificate")
        .wait()
        .await
        .expect("publish fixture certificate");
}

async fn get(router: &Router, path: &str) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
        .await
        .expect("bounded response");
    (
        status,
        serde_json::from_slice(&body).expect("JSON response"),
    )
}

async fn ok(router: &Router, path: &str) -> Value {
    let (status, response) = get(router, path).await;
    assert_eq!(status, StatusCode::OK, "{path}: {response}");
    response
}

fn certificate_height(bundle: &Value) -> u64 {
    let encoded = hex_bytes_dynamic(bundle["certificate"].as_str().unwrap());
    Certificate::decode_cfg(Bytes::from(encoded), &((), ()))
        .unwrap()
        .header
        .header()
        .height
}

fn hex_bytes_dynamic(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

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

async fn assert_transaction_proof(client: &StoreClient, bundle: &Value, certified: &FixtureBlock) {
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
        .expect("independent native transaction proof");
    assert_eq!(proof.ops_root, certified.block.header.transactions_root);
    assert!(proof.verify::<Sha256>());
    assert_eq!(
        bundle["transactionsProof"],
        hex(&encode_historical_multi_proof(&proof))
    );
    let mut changed = proof.clone();
    changed.operations[0].1[0] ^= 1;
    assert!(!changed.verify::<Sha256>());
    let mut wrong_root = proof;
    wrong_root.ops_root = Digest::EMPTY;
    assert!(!wrong_root.verify::<Sha256>());
}

async fn historical_bundles(
    context: commonware_runtime::tokio::Context,
    fixture: &Fixture,
) -> (Value, Value) {
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
        .expect("historical proof below inactivity floor");
    assert_eq!(proof.ops_root, certified.block.header.transactions_root);
    assert!(proof.verify::<Sha256>());
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
        historical_bundles(context, &fixture).await;
    });
}

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

async fn serve_fixture_if_requested(router: Router, fixture: &Fixture) {
    let Some(path) = std::env::var_os("EXPLORER_LIVE_METADATA_PATH") else {
        return;
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind live fixture");
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
        std::fs::create_dir_all(parent).expect("create live fixture metadata directory");
    }
    std::fs::write(path, serde_json::to_vec_pretty(&metadata).unwrap())
        .expect("write live fixture metadata");
    axum::serve(listener, server)
        .with_graceful_shutdown(async {
            let _ = stopped.await;
        })
        .await
        .expect("serve live fixture");
}

#[test]
fn publisher_bundles_cover_descendants_empty_blocks_and_fixed_account_pages() {
    commonware_runtime::tokio::Runner::default().start(|context| async move {
        let fixture = fixture().await;
        assert!(verify_transactions(
            TRANSACTION_NAMESPACE,
            &mut StdRng::from_seed([77; 32]),
            &PublicKeyCache::new(context.child("signature_cache"), NZUsize!(4)),
            &fixture.blocks[3].transactions,
            &Sequential,
        ));
        let environment = FixtureStore::open(context.child("primary")).await;
        let store = &environment.store;
        let client = &environment.client;
        let router = &environment.router;
        let publisher = &environment.publisher;
        let reporter = &environment.reporter;
        publish(&publisher, &reporter, &fixture.blocks[0], true).await;
        publish(&publisher, &reporter, &fixture.blocks[1], false).await;

        let (status, _) = get(&router, "/explorer/blocks/2").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let account_path = format!("/explorer/accounts/{}", hex(fixture.account.as_ref()));
        let lagging_account = ok(&router, &account_path).await;
        assert_eq!(certificate_height(&lagging_account), 1);
        assert_eq!(lagging_account["transactions"].as_array().unwrap().len(), 3);

        publish(&publisher, &reporter, &fixture.blocks[2], true).await;
        let direct = ok(&router, "/explorer/blocks/1").await;
        assert_eq!(certificate_height(&direct), 1);
        assert_eq!(direct["headers"], json!([]));
        assert_transactions(&direct, &fixture.blocks[0], 0, 3);
        assert_transaction_proof(&client, &direct, &fixture.blocks[0]).await;
        let descendant = ok(&router, "/explorer/blocks/2").await;
        assert_eq!(certificate_height(&descendant), 3);
        assert_eq!(
            descendant["headers"],
            json!([
                hex(&fixture.blocks[1].block.header.encode()),
                hex(&fixture.blocks[0].block.header.encode()),
            ])
        );
        assert_transactions(&descendant, &fixture.blocks[1], 0, 50);
        assert_transaction_proof(&client, &descendant, &fixture.blocks[2]).await;
        assert_eq!(descendant["nextCursor"], "50");
        let last = ok(&router, "/explorer/blocks/2?offset=50").await;
        assert_transactions(&last, &fixture.blocks[1], 50, 5);
        assert!(last["nextCursor"].is_null());
        let terminal = ok(&router, "/explorer/blocks/2?offset=55").await;
        assert_transactions(&terminal, &fixture.blocks[1], 55, 0);
        assert_eq!(
            get(&router, "/explorer/blocks/2?offset=56").await.0,
            StatusCode::BAD_REQUEST
        );

        let empty = ok(&router, "/explorer/blocks/3").await;
        assert_eq!(certificate_height(&empty), 3);
        assert_transactions(&empty, &fixture.blocks[2], 0, 0);
        assert_eq!(
            empty["headers"],
            json!([hex(&fixture.blocks[1].block.header.encode())])
        );

        let account = ok(&router, &account_path).await;
        assert_eq!(certificate_height(&account), 3);
        assert_eq!(account["account"]["location"], "5");
        assert_eq!(account["transactions"].as_array().unwrap().len(), 10);
        assert_eq!(account["transactions"][0]["index"], 54);
        assert_eq!(account["transactions"][0]["role"], 0);
        assert_transaction_proof(&client, &account, &fixture.blocks[2]).await;
        let cursor = account["nextCursor"].as_str().unwrap();
        let pinned = format!(
            "{account_path}?at=3&digest={}&cursor={cursor}",
            hex(fixture.blocks[2].block.seal().as_ref())
        );
        let next = ok(&router, &pinned).await;
        assert_eq!(next["transactions"][0]["index"], 44);
        assert_eq!(next["transactions"][9]["index"], 35);
        let state_only = ok(&router, &format!("{account_path}?activity=false")).await;
        assert!(state_only["transactions"].as_array().unwrap().is_empty());
        assert!(state_only["transactionsProof"].is_null());
        assert_eq!(state_only["account"], account["account"]);
        let recipient = ok(
            &router,
            &format!(
                "/explorer/accounts/{}?mode=received",
                hex(fixture.recipient.as_ref())
            ),
        )
        .await;
        assert!(recipient["account"].is_null());
        assert_eq!(recipient["transactions"][0]["index"], 53);
        assert_eq!(recipient["transactions"][0]["role"], 1);

        let digest = hex(fixture.blocks[1].transactions[54].message_digest().as_ref());
        let transaction = ok(&router, &format!("/explorer/transactions/{digest}")).await;
        assert_eq!(certificate_height(&transaction), 3);
        assert_transactions(&transaction, &fixture.blocks[1], 54, 1);

        publish(&publisher, &reporter, &fixture.blocks[3], true).await;
        let after_arrival = ok(&router, &pinned).await;
        for field in [
            "certificate",
            "headers",
            "account",
            "transactions",
            "transactionsProof",
            "nextCursor",
        ] {
            assert_eq!(after_arrival[field], next[field], "pinned field {field}");
        }
        let account_with_history = ok(&router, &account_path).await;
        assert_eq!(certificate_height(&account_with_history), 4);
        assert!(account_with_history["transactions"].as_array().unwrap().iter().any(|row| {
            row["location"].as_str().unwrap().parse::<u64>().unwrap()
                < fixture.blocks[3].block.header.transactions_range.start()
        }));
        let webauthn_digest = hex(fixture.blocks[3].transactions[1].message_digest().as_ref());
        let webauthn_block = ok(&router, "/explorer/blocks/4").await;
        assert_transactions(&webauthn_block, &fixture.blocks[3], 0, 2);
        let webauthn_bundle = ok(
            &router,
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

        if let Some(path) = std::env::var_os("EXPLORER_FIXTURE_PATH") {
            let (historical_block, historical_transaction) = historical_bundles(context.child("historical_export"), &fixture).await;
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
                .expect("write requested browser fixture");
        }
        assert!(store.requests().iter().all(|request| request.authorized));
        serve_fixture_if_requested(environment.router.clone(), &fixture).await;
        environment.close().await;
    });
}

#[test]
fn signed_transaction_size_limit_matches_the_public_codec() {
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
    let store = ObservedStore::open("explorer-fixture").await.unwrap();
    let client = writer_store_client(&store.url, Some("explorer-fixture")).unwrap();
    let router = router(&client).unwrap();
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
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {response}");
    }
    assert!(store.requests().is_empty());
    store.shutdown().await;
}
