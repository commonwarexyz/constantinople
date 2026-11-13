use super::*;

#[path = "scan_tests.rs"]
mod scan_tests;

use crate::{
    proto,
    publisher::{
        Publisher, PublisherMetrics,
        certificate::CertificateReporter,
        fixture::{Scheme, threshold},
        qmdb::{CapturedFinalizedUpload, QueuedFinalizedUpload, QueuedFinalizedUploadCfg},
        sql::{
            AccountMetaRow, TxActivityRole, TxActivityRow, encode_account_meta_row,
            encode_tx_activity_row,
        },
    },
    store::writer_store_client,
    test_store::ObservedStore,
};
use axum::{
    body::{Body, to_bytes},
    http::{HeaderName, Method, Request, StatusCode},
    response::Response,
};
use buffa::Message;
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
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef};
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig,
    merkle::{Family as _, mem::Mem},
    qmdb::{current::unordered::fixed::Db, floor::Proportional},
    translator::TwoCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range};
use constantinople_account_proof::{VerifiedAccountLookup, verify_current_account_lookup};
use constantinople_application::consensus::{
    FinalizedArtifacts, FinalizedRange, TransactionHistoryOperation,
};
use constantinople_engine::types::{EngineBlock, EngineCodedBlock, EngineFinalization};
use constantinople_primitives::{
    Block, DEFAULT_ACCOUNT_BALANCE, Header as BlockHeader, Nonce, PublicKeyCache, Sealable,
    StateSyncProof, TRANSACTION_NAMESPACE, Transaction, TransactionHistoryEntry,
    TransactionPublicKey, TransactionSignature, verify_transactions,
};
use p256::ecdsa::{SigningKey, signature::Signer as _};
use rand::{SeedableRng, rngs::StdRng};
use serde_json::{Value, json};
use std::{future::Future, num::NonZeroU64};
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
    /// Transaction-history range the block appended, as the finalized hook captures it.
    transactions_range: FinalizedRange<Digest, TransactionHistoryOperation<Sha256>>,
    transactions: Vec<SignedTransaction<Sha256>>,
    history: Vec<TransactionHistoryEntry<Digest>>,
    account_location: Option<u64>,
    account_write_height: Option<u64>,
}

impl FixtureBlock {
    /// Returns the block's transaction-history range as the finalized hook hands it over.
    fn captured_transactions(&self) -> FinalizedRange<Digest, TransactionHistoryOperation<Sha256>> {
        FinalizedRange {
            start: self.transactions_range.start,
            end: self.transactions_range.end,
            root: self.transactions_range.root,
            pinned_nodes: self.transactions_range.pinned_nodes.clone(),
            operations: self.transactions_range.operations.clone(),
        }
    }
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
        let router = router(&client, None).unwrap();
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
async fn fixture(context: commonware_runtime::tokio::Context) -> Fixture {
    fixture_with_counts(context, &[3, 55, 0, 2]).await
}

async fn fixture_with_counts(
    context: commonware_runtime::tokio::Context,
    counts: &[u64],
) -> Fixture {
    // Derive deterministic consensus, transaction, and leader keys.
    let mut rng = StdRng::from_seed([42; 32]);
    let (schemes, verifier) = threshold(&mut rng, b"constantinople_CONSENSUS", 4);
    let signer = ed25519::SigningKey::from_seed(7);
    let sender = TransactionPublicKey::ed25519(signer.public_key());
    let receiver = TransactionPublicKey::ed25519(ed25519::SigningKey::from_seed(8).public_key());
    let account = AccountKey::from_public_key(&sender);
    let recipient = AccountKey::from_public_key(&receiver);
    let leader = ed25519::SigningKey::from_seed(9).public_key();

    let page_cache = CacheRef::new(NZU16!(88), NZUsize!(8));
    let mut state_db =
        Db::<mmr::Family, _, AccountKey, Account, Sha256, TwoCap, 32, Sequential>::init(
            context,
            commonware_storage::qmdb::current::Config {
                merkle_config: commonware_storage::merkle::full::Config {
                    journal_partition: "fixture-state-merkle".into(),
                    metadata_partition: "fixture-state-merkle-meta".into(),
                    items_per_blob: NZU64!(11),
                    write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                    strategy: Sequential,
                    page_cache: page_cache.clone(),
                },
                journal_config: JournalConfig {
                    partition: "fixture-state-operations".into(),
                    items_per_blob: NZU64!(7),
                    page_cache,
                    write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                },
                grafted_metadata_partition: "fixture-state-grafted-meta".into(),
                translator: TwoCap,
                init_cache: None,
                init_buffer: NZUsize!(4096),
                init_concurrency: (),
            },
            None,
        )
        .await
        .unwrap();
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
    let mut sender_count = 0;
    let mut recipient_count = 0;

    for (index, &count) in counts.iter().enumerate() {
        // Each block's transaction floor is its parent's first transaction, so
        // earlier blocks fall below the floor of later certificates.
        let height = index as u64 + 1;
        let transaction_start = transaction_operations.len() as u64;
        let first_transaction = transaction_operations.len() as u64;
        let transaction_floor = blocks.last().map_or(0, |parent| parent.first_transaction);

        // Every transfer goes to the recipient except each block's last, which
        // is a self-transfer. Block 4's last slot holds the WebAuthn fixture.
        let mut history = Vec::new();
        let transactions = (0..count)
            .map(|index| {
                if height == 4 && index == 1 {
                    let transaction = webauthn_transaction();
                    let entry = TransactionHistoryEntry {
                        digest: *transaction.message_digest(),
                        sender_index: 0,
                        recipient_index: 0,
                    };
                    transaction_operations
                        .push(TransactionHistoryOperation::<Sha256>::Append(entry));
                    history.push(entry);
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
                let entry = TransactionHistoryEntry {
                    digest: *transaction.message_digest(),
                    sender_index: sender_count,
                    recipient_index: if transaction.value().to == account {
                        sender_count
                    } else {
                        let index = recipient_count;
                        recipient_count += 1;
                        index
                    },
                };
                sender_count += 1;
                transaction_operations.push(TransactionHistoryOperation::<Sha256>::Append(entry));
                history.push(entry);
                transaction
            })
            .collect::<Vec<_>>();

        transaction_operations.push(TransactionHistoryOperation::<Sha256>::Commit(
            None,
            Location::new(transaction_floor),
        ));
        let mut batch = state_db.new_batch();
        if sender_count > 0 {
            batch = batch.write(
                account,
                Some(Account {
                    balance,
                    nonce: Nonce::new(nonce, 0),
                    tx_count: sender_count,
                }),
            );
            batch = batch.write(
                recipient,
                Some(Account {
                    balance: recipient_count,
                    nonce: Nonce::default(),
                    tx_count: recipient_count,
                }),
            );
        }
        if height == 4 {
            batch = batch.write(
                AccountKey::from_public_key(transactions[1].value().sender().unwrap()),
                Some(Account {
                    balance: 100,
                    nonce: Nonce::new(1, 0),
                    tx_count: 1,
                }),
            );
        }
        let batch = batch
            .merkleize(&state_db, None, &mut Proportional)
            .await
            .unwrap();
        let (state_start, operations) = batch.operations();
        let state = FinalizedRange {
            start: state_start,
            end: batch.bounds().tip.size,
            root: batch.ops_root(),
            pinned_nodes: batch.ops_pinned_nodes(&state_db).unwrap(),
            operations,
        };
        let state_boundary = batch.boundary();
        let state_sync = StateSyncProof {
            ops_root: batch.ops_root(),
            witness: batch.ops_root_witness().clone(),
        };
        state_db = state_db.apply_batch(batch).await.unwrap();
        let account_location = state_db
            .key_value_proof(account)
            .await
            .ok()
            .map(|proof| proof.loc.as_u64());
        let account_write_height = account_location.map(|location| {
            if location >= state_start.as_u64() {
                height
            } else {
                blocks.last().unwrap().account_write_height.unwrap()
            }
        });
        let transactions_range = captured_range(
            &transaction_operations,
            transaction_start,
            transaction_floor,
        );
        let captured_transactions = FinalizedRange {
            start: transactions_range.start,
            end: transactions_range.end,
            root: transactions_range.root,
            pinned_nodes: transactions_range.pinned_nodes.clone(),
            operations: transactions_range.operations.clone(),
        };
        let header = BlockHeader {
            context: SimplexContext {
                round: Round::new(Epoch::zero(), View::new(height)),
                leader: leader.clone(),
                parent: (View::new(height - 1), parent_commitment),
            },
            parent,
            height,
            timestamp: height,
            state_root: state_boundary.root,
            state_range: non_empty_range!(state_db.sync_boundary().as_u64(), state.end.as_u64()),
            transactions_root: transactions_range.root,
            transactions_range: non_empty_range!(
                transaction_floor,
                transactions_range.end.as_u64()
            ),
        };
        let block: TestBlock = Block::new(header, transactions.clone(), state_sync)
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
                    state_boundary,
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
            transactions_range: captured_transactions,
            transactions,
            history,
            account_location,
            account_write_height,
        });
    }
    state_db.destroy().await.unwrap();
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

/// Sends a protobuf unary request through the public Connect transport.
async fn post(router: &Router, method: &str, body: Vec<u8>) -> (StatusCode, Bytes) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/constantinople.explorer.v1.ExplorerService/{method}"
                ))
                .header("content-type", "application/proto")
                .header("connect-protocol-version", "1")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    if status.is_success() {
        assert_eq!(response.headers()["content-type"], "application/proto");
    }
    let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
        .await
        .expect("response must fit within the response limit");
    (status, body)
}

trait ProofRequest: Message {
    const METHOD: &'static str;
}

impl ProofRequest for proto::GetAccountRequest {
    const METHOD: &'static str = "GetAccount";
}

impl ProofRequest for proto::GetBlockRequest {
    const METHOD: &'static str = "GetBlock";
}

impl ProofRequest for proto::GetTransactionRequest {
    const METHOD: &'static str = "GetTransaction";
}

/// Decodes the wire response before adapting evidence for shared browser fixtures.
async fn proof_bundle<Q: ProofRequest>(router: &Router, request: &Q) -> Value {
    let (status, body) = post(router, Q::METHOD, request.encode_to_vec()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{} must succeed: {body:?}",
        Q::METHOD
    );
    let bundle = proto::ProofBundle::decode_from_slice(&body)
        .expect("successful proof response must decode as ProofBundle");
    bundle_json(&bundle)
}

/// Preserves raw evidence bytes and integer precision in browser fixture JSON.
fn bundle_json(bundle: &proto::ProofBundle) -> Value {
    let next_cursor = bundle.next_cursor.as_ref().map(|cursor| match cursor {
        proto::proof_bundle::NextCursor::ActivityCursor(cursor) => hex(cursor),
        proto::proof_bundle::NextCursor::BlockOffset(offset) => offset.to_string(),
    });
    let transactions = bundle
        .transactions
        .iter()
        .map(|row| {
            let mut value = json!({
                "location": row.location.to_string(),
                "body": hex(&row.body),
                "height": row.height.to_string(),
                "index": row.index,
                "senderIndex": row.sender_index.to_string(),
                "recipientIndex": row.recipient_index.to_string(),
            });
            if let Some(role) = row.role {
                value["role"] = json!(role.to_i32());
            }
            value
        })
        .collect::<Vec<_>>();
    json!({
        "certificate": hex(&bundle.certificate),
        "headers": bundle.headers.iter().map(|header| hex(header)).collect::<Vec<_>>(),
        "sequenceNumber": bundle.sequence_number.to_string(),
        "account": bundle.account.as_option().map(|account| {
            json!({
                "location": account.location.to_string(),
                "proof": hex(&account.proof),
                "writeHeight": account.write_height.to_string(),
                "encodedOperation": hex(&account.encoded_operation),
            })
        }),
        "transactions": transactions,
        "transactionsProof": bundle.transactions_proof.as_ref().map(|proof| hex(proof)),
        "nextCursor": next_cursor,
    })
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
        assert_eq!(
            row["senderIndex"],
            block.history[position].sender_index.to_string()
        );
        assert_eq!(
            row["recipientIndex"],
            block.history[position].recipient_index.to_string()
        );
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
    for (location, bytes) in &proof.operations {
        let TransactionOperation::Append(entry) =
            TransactionOperation::decode_cfg(Bytes::copy_from_slice(bytes), &()).unwrap()
        else {
            panic!("transaction proof must contain an append");
        };
        assert_eq!(entry.encode().len(), 48);
        let row = bundle["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| {
                row["location"].as_str().unwrap().parse::<u64>().unwrap() == location.as_u64()
            })
            .unwrap();
        let transaction = SignedTransaction::<Sha256>::decode(Bytes::from(hex_bytes_dynamic(
            row["body"].as_str().unwrap(),
        )))
        .unwrap();
        assert_eq!(entry.digest, *transaction.message_digest());
        assert_eq!(row["senderIndex"], entry.sender_index.to_string());
        assert_eq!(row["recipientIndex"], entry.recipient_index.to_string());
    }
    assert_eq!(
        bundle["transactionsProof"],
        hex(&encode_operation_multi_proof(&proof))
    );

    // A changed operation or root must fail verification.
    let mut changed = proof.clone();
    changed.operations[0].1[0] ^= 1;
    assert!(!changed.verify::<Sha256>());
    let mut wrong_root = proof;
    wrong_root.ops_root = Digest::EMPTY;
    assert!(!wrong_root.verify::<Sha256>());
}

fn verify_account_bundle(
    bundle: &Value,
    key: AccountKey,
    block: &FixtureBlock,
) -> VerifiedAccountLookup {
    let certificate = Certificate::decode_cfg(
        Bytes::from(hex_bytes_dynamic(bundle["certificate"].as_str().unwrap())),
        &((), ()),
    )
    .unwrap();
    let header = certificate.header.header();
    assert_eq!(header.height, block.block.header.height);
    assert_eq!(header.state_root, block.block.header.state_root);
    assert_eq!(header.state_range, block.block.header.state_range);
    let account = &bundle["account"];
    let proof = hex_bytes_dynamic(account["proof"].as_str().unwrap());
    let operation = hex_bytes_dynamic(account["encodedOperation"].as_str().unwrap());
    verify_current_account_lookup(
        &proof,
        header.state_root.as_ref(),
        key.as_ref(),
        header.state_range.end() - 1,
        &operation,
    )
    .unwrap()
}

/// Checks that an account without an active update is reported as not found. The unordered
/// account database has no key spans, so absence carries no proof.
async fn assert_not_found(router: &Router, request: &proto::GetAccountRequest) {
    let (status, body) = post(router, "GetAccount", request.encode_to_vec()).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body:?}");
}

fn assert_lookup_context_rejected(bundle: &Value, key: AccountKey, block: &FixtureBlock) {
    let account = &bundle["account"];
    let proof = hex_bytes_dynamic(account["proof"].as_str().unwrap());
    let operation = hex_bytes_dynamic(account["encodedOperation"].as_str().unwrap());
    assert_eq!(operation.len(), 65);
    let root = block.block.header.state_root.as_ref();
    let tip = block.block.header.state_range.end() - 1;
    let check = |bytes: &[u8], root: &[u8], key: &[u8], tip, operation: &[u8]| {
        verify_current_account_lookup(bytes, root, key, tip, operation).is_err()
    };
    let mut changed_root = root.to_vec();
    changed_root[0] ^= 1;
    assert!(check(&proof, &changed_root, key.as_ref(), tip, &operation));
    assert!(check(&proof, root, key.as_ref(), tip + 1, &operation));
    assert!(check(
        &proof[..proof.len() - 1],
        root,
        key.as_ref(),
        tip,
        &operation
    ));
    let mut trailing = proof.clone();
    trailing.push(0);
    assert!(check(&trailing, root, key.as_ref(), tip, &operation));
    assert!(check(&proof, root, &[0; 32], tip, &operation));
    let mut changed_operation = operation.clone();
    changed_operation[33] ^= 1;
    assert!(check(&proof, root, key.as_ref(), tip, &changed_operation));
    assert!(check(&proof, root, key.as_ref(), tip, &operation[..64]));
}

/// Checks the complete descending interval certified by an account's count.
fn assert_account_page(bundle: &Value, end: u64) {
    let start = end.saturating_sub(TRANSACTION_PAGE);
    let rows = bundle["transactions"].as_array().unwrap();
    assert_eq!(rows.len() as u64, end - start);
    for (row, expected) in rows.iter().zip((start..end).rev()) {
        let index = if row["role"] == 0 {
            &row["senderIndex"]
        } else {
            assert_eq!(row["role"], 1);
            &row["recipientIndex"]
        };
        assert_eq!(index, &json!(expected.to_string()));
    }
    if start == 0 {
        assert!(bundle["nextCursor"].is_null());
    } else {
        assert_eq!(bundle["nextCursor"], hex(&start.to_be_bytes()));
    }
}

fn activity_hint(fixture: &Fixture, transaction_index: usize) -> TxActivityRow {
    let block = &fixture.blocks[1];
    let transaction = block.transactions[transaction_index].value();
    TxActivityRow {
        account: fixture.account.as_ref().try_into().unwrap(),
        account_index: block.history[transaction_index].sender_index,
        role: TxActivityRole::Sender,
        height: 2,
        index: transaction_index as u32,
        digest: block.transactions[transaction_index]
            .message_digest()
            .as_ref()
            .try_into()
            .unwrap(),
        counterparty: transaction.to.as_ref().try_into().unwrap(),
        value: transaction.value.get(),
        nonce: transaction.nonce,
        qmdb_location: block.first_transaction + transaction_index as u64,
    }
}

#[test]
fn account_pages_reject_untrusted_sql_hints() {
    commonware_runtime::tokio::Runner::default().start(|context| async move {
        let fixture = fixture(context.child("state_fixture")).await;
        let environment = FixtureStore::open(context).await;
        for block in &fixture.blocks[..3] {
            publish(&environment.publisher, &environment.reporter, block, true).await;
        }
        let location = fixture.blocks[2].account_location.unwrap();
        let write_height = fixture.blocks[2].account_write_height.unwrap();
        let request = proto::GetAccountRequest {
            account: fixture.account.as_ref().to_vec(),
            at: Some(3),
            digest: Some(fixture.blocks[2].block.seal().as_ref().to_vec()),
            account_location: Some(location),
            ..Default::default()
        };
        let baseline = proof_bundle(&environment.router, &request).await;
        assert_account_page(&baseline, 58);
        let explorer = Explorer::new(&environment.client).unwrap();
        let anchor = explorer
            .anchor(1, Some((3, *fixture.blocks[2].block.seal())), true)
            .await
            .unwrap();
        let table = anchor
            .sql
            .deregister_table("account_meta")
            .unwrap()
            .unwrap();
        anchor
            .sql
            .register_table(
                "account_meta",
                Arc::new(
                    datafusion::datasource::MemTable::try_new(table.schema(), vec![vec![]])
                        .unwrap(),
                ),
            )
            .unwrap();
        let parsed = AccountRequest::parse(request.clone()).unwrap();
        let error = match explorer.account_proof(&anchor, &parsed).await {
            Err(error) => error,
            Ok(_) => panic!("a native hit without SQL provenance must remain unavailable"),
        };
        assert_eq!(error.0, ErrorCode::Unavailable);
        assert_eq!(error.1, "account update metadata is not available");
        let missing = AccountRequest::parse(proto::GetAccountRequest {
            account: vec![0; 32],
            ..Default::default()
        })
        .unwrap();
        let error = match explorer.account_proof(&anchor, &missing).await {
            Err(error) => error,
            Ok(_) => panic!("a native miss must be reported as not found"),
        };
        assert_eq!(error.0, ErrorCode::NotFound);
        anchor.sql.deregister_table("account_meta").unwrap();
        anchor.sql.register_table("account_meta", table).unwrap();
        let schema = build_meta_schema(sql_meta_client(&environment.client).unwrap()).unwrap();
        let mut writer = schema.batch_writer();

        // Each replacement keeps the SQL key while changing evidence for a
        // page position. Restoring it must restore the same proven page.
        for (case, expected_error) in [
            ("omitted", "account history page is incomplete"),
            (
                "wrong index",
                "transaction does not occupy the requested account index",
            ),
            (
                "wrong role",
                "transaction does not occupy the requested account index",
            ),
            ("duplicate", "duplicate account transaction"),
        ] {
            let target = match case {
                // The remaining page must stay contiguous to exercise its length check.
                "omitted" => 5,
                "duplicate" => 53,
                _ => 54,
            };
            let mut hint = activity_hint(&fixture, target);
            match case {
                "omitted" => hint.height = 4,
                "wrong index" => {
                    hint = activity_hint(&fixture, 4);
                    hint.account_index = 57;
                }
                "wrong role" => hint.role = TxActivityRole::Receiver,
                "duplicate" => {
                    hint = activity_hint(&fixture, 54);
                    hint.account_index = 56;
                }
                _ => unreachable!(),
            }
            let row = encode_tx_activity_row(hint);
            writer.insert(row.table, row.values).unwrap();
            writer.flush().await.unwrap();
            let (status, body) =
                post(&environment.router, "GetAccount", request.encode_to_vec()).await;
            assert_eq!(
                status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "{case}: {body:?}"
            );
            let error: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(error["code"], "internal", "{case}");
            assert_eq!(error["message"], expected_error, "{case}");

            let row = encode_tx_activity_row(activity_hint(&fixture, target));
            writer.insert(row.table, row.values).unwrap();
            writer.flush().await.unwrap();
            let restored = proof_bundle(&environment.router, &request).await;
            assert_eq!(restored["transactions"], baseline["transactions"], "{case}");
        }

        // The certified count rejects fabricated past and future page bounds.
        for (count, height, expected_error) in [
            (57, write_height, "account proof disagrees with metadata"),
            (59, write_height, "account proof disagrees with metadata"),
            (
                u64::MAX,
                write_height,
                "account proof disagrees with metadata",
            ),
            (58, 1, "account update is outside its inclusion block"),
        ] {
            let row = encode_account_meta_row(AccountMetaRow {
                account: fixture.account.as_ref().try_into().unwrap(),
                balance: 44,
                nonce_base: 58,
                nonce_bitmap: 0,
                qmdb_location: location,
                tx_count: count,
                write_height: height,
            });
            writer.insert(row.table, row.values).unwrap();
            writer.flush().await.unwrap();
            let (status, body) =
                post(&environment.router, "GetAccount", request.encode_to_vec()).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            let error: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(error["message"], expected_error);
        }
        environment.close().await;
    });
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
            &[
                Location::new(block.first_transaction),
                Location::new(block.first_transaction + 2),
            ],
            None,
        )
        .await
        .expect("locations below the inactivity floor must remain provable");
    assert_eq!(proof.ops_root, certified.block.header.transactions_root);
    assert!(proof.verify::<Sha256>());
    if let Some(path) = std::env::var_os("EXPLORER_ACTIVITY_FIXTURE_PATH") {
        let operations = proof
            .operations
            .iter()
            .map(|(location, bytes)| {
                let TransactionOperation::Append(entry) =
                    TransactionOperation::decode_cfg(Bytes::copy_from_slice(bytes), &()).unwrap()
                else {
                    panic!("history fixture must prove an append");
                };
                json!({
                    "location": location.as_u64().to_string(),
                    "digest": hex(entry.digest.as_ref()),
                    "senderIndex": entry.sender_index.to_string(),
                    "recipientIndex": entry.recipient_index.to_string(),
                    "value": hex(&entry.encode()),
                })
            })
            .collect::<Vec<_>>();
        let export = json!({
            "root": hex(proof.ops_root.as_ref()),
            "tip": (certified.block.header.transactions_range.end() - 1).to_string(),
            "proof": hex(&encode_operation_multi_proof(&proof)),
            "operations": operations,
        });
        std::fs::write(path, serde_json::to_vec_pretty(&export).unwrap())
            .expect("requested history proof fixture must be writable");
    }

    // Both routes prove block 1 through block 3's certificate.
    let historical_block = proof_bundle(
        &environment.router,
        &proto::GetBlockRequest {
            height: 1,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(certificate_height(&historical_block), 3);
    assert_transactions(&historical_block, block, 0, 3);
    assert_transaction_proof(&environment.client, &historical_block, certified).await;
    let historical_transaction = proof_bundle(
        &environment.router,
        &proto::GetTransactionRequest {
            digest: block.transactions[0].message_digest().as_ref().to_vec(),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(certificate_height(&historical_transaction), 3);
    assert_transactions(&historical_transaction, block, 0, 1);
    assert_transaction_proof(&environment.client, &historical_transaction, certified).await;
    environment.close().await;
    (historical_block, historical_transaction)
}

/// Resolves to the certificate a node holds for fixture block `height`.
fn certificate(
    fixture: &Fixture,
    height: u64,
) -> impl Future<Output = Option<TestFinalization>> + Send + 'static {
    let finalization = fixture.blocks[height as usize - 1].finalization.clone();
    async move { Some(finalization) }
}

/// Proves `digest` at `height` with the block's own certificate and decodes the bundle.
async fn evidence_json(
    recent: &RecentFinalized,
    fixture: &Fixture,
    height: u64,
    digest: &Digest,
) -> Value {
    let encoded = recent
        .prove(height, *digest, certificate(fixture, height))
        .await
        .expect("recorded block must prove its transaction");
    bundle_json(&proto::ProofBundle::decode_from_slice(&encoded).unwrap())
}

#[test]
fn recent_finalized_blocks_prove_inclusion_once_per_block_and_name_each_absence() {
    commonware_runtime::tokio::Runner::default().start(|context| async move {
        // Two blocks more than the ring retains, so the first two are evicted.
        let newest = evidence::RETAINED_BLOCKS + 2;
        let fixture = Arc::new(fixture_with_counts(context, &vec![2; newest]).await);
        let digest = |height: usize, index: usize| {
            *fixture.blocks[height - 1].transactions[index].message_digest()
        };
        let record = |recent: &RecentFinalized, height: usize| {
            let block = &fixture.blocks[height - 1];
            recent.record(block.block.clone(), block.captured_transactions());
        };
        let recent = Arc::new(RecentFinalized::default());

        // A request for a block this node has not finalized waits for it, within the bound.
        assert_eq!(
            recent
                .prove(1, digest(1, 0), certificate(&fixture, 1))
                .await,
            Err(Absence::Late)
        );
        let waiting = tokio::spawn({
            let (recent, fixture, digest) = (recent.clone(), fixture.clone(), digest(1, 0));
            async move { recent.prove(1, digest, certificate(&fixture, 1)).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        record(&recent, 1);
        assert!(waiting.await.unwrap().is_ok());

        for height in 2..=newest {
            record(&recent, height);
        }

        // Every transaction of a block is proven from one merkleization of that block.
        let merkleized = recent.merkleized_blocks();
        let digests = [digest(newest, 0), digest(newest, 1)];
        let bundles = futures::future::join_all(
            digests
                .iter()
                .map(|digest| evidence_json(&recent, &fixture, newest as u64, digest)),
        )
        .await;
        for (index, bundle) in bundles.iter().enumerate() {
            assert_eq!(certificate_height(bundle), newest as u64);
            assert_transactions(bundle, &fixture.blocks[newest - 1], index, 1);
            assert_eq!(
                bundle["headers"],
                json!([hex(&fixture.blocks[newest - 2].block.header.encode())])
            );
        }
        evidence_json(&recent, &fixture, newest as u64, &digests[0]).await;
        assert_eq!(recent.merkleized_blocks(), merkleized + 1);

        // Each reason a node cannot answer has its own name.
        for (name, height, transaction, certified, expected) in [
            ("evicted block", 2, digest(2, 0), Some(2), Absence::NotFound),
            (
                "transaction of another block",
                newest,
                digest(newest - 1, 0),
                Some(newest),
                Absence::NotFound,
            ),
            (
                "oldest retained block",
                3,
                digest(3, 0),
                Some(3),
                Absence::ParentMissing,
            ),
            (
                "no certificate",
                newest,
                digest(newest, 0),
                None,
                Absence::NoCertificate,
            ),
            (
                "certificate of another block",
                newest,
                digest(newest, 0),
                Some(newest - 1),
                Absence::NoCertificate,
            ),
        ] {
            let finalization =
                certified.map(|height: usize| fixture.blocks[height - 1].finalization.clone());
            assert_eq!(
                recent
                    .prove(height as u64, transaction, async move { finalization })
                    .await,
                Err(expected),
                "{name}"
            );
        }
        let bounded = RecentFinalized::bounded(64);
        record(&bounded, newest - 1);
        record(&bounded, newest);
        assert_eq!(
            bounded
                .prove(
                    newest as u64,
                    digest(newest, 0),
                    certificate(&fixture, newest as u64)
                )
                .await,
            Err(Absence::TooLarge)
        );
    });
}

#[test]
fn historical_transactions_below_inactivity_floor_remain_available() {
    commonware_runtime::tokio::Runner::default().start(|context| async move {
        let fixture = fixture(context.child("state_fixture")).await;
        Box::pin(historical_bundles(context, &fixture)).await;
    });
}

#[test]
fn published_feed_carries_indirect_finality_and_exact_append_intervals() {
    commonware_runtime::tokio::Runner::default().start(|context| async move {
        let fixture = fixture(context.child("state_fixture")).await;
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
        let client = proto::ExplorerServiceClient::new(
            connectrpc::client::ServiceTransport::new(environment.router.clone()),
            connectrpc::client::ClientConfig::new("http://localhost".parse().unwrap()),
        );
        for (after, lowest) in [(None, 2), (Some(0), 1), (Some(1), 1), (Some(2), 2)] {
            let mut stream = client
                .watch_blocks(proto::WatchBlocksRequest {
                    after,
                    ..Default::default()
                })
                .await
                .unwrap();
            let batch = tokio::time::timeout(std::time::Duration::from_secs(5), stream.message())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .to_owned_message();
            let certified =
                Certificate::decode_cfg(Bytes::from(batch.certificate), &((), ())).unwrap();
            assert_eq!(certified.header.header().height, 3);
            assert_eq!(
                certified.header.header().seal(),
                fixture.blocks[2].block.seal()
            );
            let expected = (lowest..3)
                .rev()
                .map(|height| fixture.blocks[height - 1].block.header.encode().to_vec())
                .collect::<Vec<_>>();
            assert_eq!(batch.headers, expected);
            assert!(batch.sequence_number > 0);
        }

        // The publisher advances the inactivity floor independently of each
        // block's append interval. Only adjacent ends determine its count.
        let headers = fixture.blocks[..3]
            .iter()
            .map(|block| &block.block.header)
            .collect::<Vec<_>>();
        assert!(headers[2].transactions_range.start() > headers[0].transactions_range.start());
        assert_eq!(headers[0].transactions_range.end() - 2, 3);
        assert_eq!(
            headers[1].transactions_range.end() - headers[0].transactions_range.end() - 1,
            55
        );
        assert_eq!(
            headers[2].transactions_range.end() - headers[1].transactions_range.end() - 1,
            0
        );
        environment.close().await;
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
                .allow_methods([Method::POST])
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
        "sampleAccountRequest": {"account": account, "at": "3", "digest": snapshot_digest},
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
        let fixture = fixture(context.child("state_fixture")).await;
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

        for (value, kind) in [
            (fixture.account.as_ref().to_vec(), 0),
            (fixture.blocks[1].transactions[0].message_digest().as_ref().to_vec(), 1),
        ] {
            let request = proto::SearchRequest { value: value.clone(), ..Default::default() };
            let (status, body) = post(router, "Search", request.encode_to_vec()).await;
            assert_eq!(status, StatusCode::OK);
            let response = proto::SearchResponse::decode_from_slice(&body).unwrap();
            assert_eq!(response.kind.to_i32(), kind);
            assert_eq!(response.value, value);
        }

        // Block 2 has no covering certificate yet, so it stays unavailable while
        // the account view falls back to block 1's certificate.
        let request = proto::GetBlockRequest { height: 2, ..Default::default() };
        let (status, body) = post(router, "GetBlock", request.encode_to_vec()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["code"], "unavailable");
        let account_request = proto::GetAccountRequest {
            account: fixture.account.as_ref().to_vec(),
            ..Default::default()
        };
        let lagging_account = proof_bundle(router, &account_request).await;
        assert_eq!(certificate_height(&lagging_account), 1);
        assert_account_page(&lagging_account, 3);

        // Certifying block 3 lets block 1 prove directly and block 2 prove
        // through block 3's ancestry.
        publish(publisher, reporter, &fixture.blocks[2], true).await;
        let direct = proof_bundle(router, &proto::GetBlockRequest {
            height: 1, offset: 0, ..Default::default()
        }).await;
        assert_eq!(certificate_height(&direct), 1);
        assert_eq!(direct["headers"], json!([]));
        assert_transactions(&direct, &fixture.blocks[0], 0, 3);
        assert_transaction_proof(client, &direct, &fixture.blocks[0]).await;
        let descendant = proof_bundle(router, &proto::GetBlockRequest {
            height: 2, offset: 0, ..Default::default()
        }).await;
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
        let last = proof_bundle(router, &proto::GetBlockRequest {
            height: 2, offset: 50, ..Default::default()
        }).await;
        assert_transactions(&last, &fixture.blocks[1], 50, 5);
        assert!(last["nextCursor"].is_null());
        let terminal = proof_bundle(router, &proto::GetBlockRequest {
            height: 2, offset: 55, ..Default::default()
        }).await;
        assert_transactions(&terminal, &fixture.blocks[1], 55, 0);
        let invalid_offset = proto::GetBlockRequest {
            height: 2, offset: 56, ..Default::default()
        };
        let (status, body) = post(router, "GetBlock", invalid_offset.encode_to_vec()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["code"], "invalid_argument");

        // An empty block returns its certificate and parent header without a
        // proof.
        let empty = proof_bundle(router, &proto::GetBlockRequest {
            height: 3, offset: 0, ..Default::default()
        }).await;
        assert_eq!(certificate_height(&empty), 3);
        assert_transactions(&empty, &fixture.blocks[2], 0, 0);
        assert_eq!(
            empty["headers"],
            json!([hex(&fixture.blocks[1].block.header.encode())])
        );

        // The account view proves the latest update and returns the newest page
        // of activity rows.
        let account = proof_bundle(router, &account_request).await;
        assert_eq!(certificate_height(&account), 3);
        let account_location = fixture.blocks[2].account_location.unwrap();
        let account_write_height = fixture.blocks[2].account_write_height.unwrap();
        assert_eq!(account["account"]["location"], account_location.to_string());
        assert_eq!(account["account"]["writeHeight"], account_write_height.to_string());
        let expected_headers = fixture.blocks[account_write_height.saturating_sub(2) as usize..2]
            .iter().rev().map(|block| hex(&block.block.header.encode())).collect::<Vec<_>>();
        assert_eq!(account["headers"], json!(expected_headers));
        let verified = verify_account_bundle(&account, fixture.account, &fixture.blocks[2]);
        assert_eq!((verified.location, verified.account.tx_count), (account_location, 58));
        assert_lookup_context_rejected(&account, fixture.account, &fixture.blocks[2]);
        assert_account_page(&account, 58);
        assert_eq!(account["transactions"][0]["index"], 54);
        assert_eq!(account["transactions"][0]["role"], 0);
        assert_transaction_proof(client, &account, &fixture.blocks[2]).await;

        // A cursor on the pinned snapshot continues with the remaining rows,
        // which end block 2's transactions and cover all of block 1's.
        let pinned = proto::GetAccountRequest {
            cursor: Some(hex_bytes_dynamic(account["nextCursor"].as_str().unwrap())),
            at: Some(3),
            digest: Some(fixture.blocks[2].block.seal().as_ref().to_vec()),
            account_location: Some(account_location),
            ..account_request.clone()
        };
        let next = proof_bundle(router, &pinned).await;
        assert_account_page(&next, 8);
        assert_eq!(next["transactions"][0]["index"], 4);
        assert_eq!(next["transactions"][4]["index"], 0);
        assert_eq!(next["transactions"][5]["height"], "1");
        assert!(next["nextCursor"].is_null());
        let oldest = proof_bundle(router, &proto::GetAccountRequest {
            cursor: Some(3_u64.to_be_bytes().to_vec()),
            ..pinned.clone()
        }).await;
        assert_account_page(&oldest, 3);
        assert_eq!(oldest["transactions"][0]["height"], "1");
        assert_transaction_proof(client, &oldest, &fixture.blocks[2]).await;
        let exhausted = proof_bundle(router, &proto::GetAccountRequest {
            cursor: Some(0_u64.to_be_bytes().to_vec()),
            ..pinned.clone()
        }).await;
        assert_account_page(&exhausted, 0);
        assert_eq!(exhausted["account"], account["account"]);
        assert!(exhausted["transactionsProof"].is_null());
        for (invalid, expected_status) in [
            (proto::GetAccountRequest {
                cursor: Some(u64::MAX.to_be_bytes().to_vec()),
                ..pinned.clone()
            }, StatusCode::BAD_REQUEST),
            (proto::GetAccountRequest {
                digest: Some(vec![0; 32]),
                ..pinned.clone()
            }, StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            let (status, _) = post(router, "GetAccount", invalid.encode_to_vec()).await;
            assert_eq!(status, expected_status);
        }
        let (status, _) = post(router, "GetAccount", proto::GetAccountRequest {
            account_location: Some(account_location + 1),
            ..pinned.clone()
        }.encode_to_vec()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        // State-only requests retain the account proof without an activity page.
        let state_only = proof_bundle(router, &proto::GetAccountRequest {
            activity: Some(false),
            ..account_request.clone()
        }).await;
        assert_eq!(state_only["account"], account["account"]);
        assert!(state_only["transactions"].as_array().unwrap().is_empty());
        assert!(state_only["transactionsProof"].is_null());
        assert!(state_only["nextCursor"].is_null());

        // Recipient indices advance independently of the sender's self-transfers.
        let recipient = proof_bundle(router, &proto::GetAccountRequest {
            account: fixture.recipient.as_ref().to_vec(),
            ..Default::default()
        }).await;
        assert_account_page(&recipient, 56);
        assert_eq!(recipient["transactions"][0]["index"], 53);
        assert_eq!(recipient["transactions"][0]["role"], 1);
        assert_transaction_proof(client, &recipient, &fixture.blocks[2]).await;

        // An account without an active update is not found, with no absence proof.
        let unknown = proto::GetAccountRequest {
            account: vec![0; 32],
            ..Default::default()
        };
        assert_not_found(router, &unknown).await;
        let future_key = AccountKey::from_public_key(fixture.blocks[3].transactions[1].value().sender().unwrap());
        let future_request = proto::GetAccountRequest {
            account: future_key.as_ref().to_vec(), at: Some(3),
            digest: Some(fixture.blocks[2].block.seal().as_ref().to_vec()),
            ..Default::default()
        };
        assert_not_found(router, &future_request).await;

        let empty_fixture = fixture_with_counts(context.child("empty_state"), &[0]).await;
        let empty_environment = FixtureStore::open(context.child("empty_store")).await;
        publish(&empty_environment.publisher, &empty_environment.reporter, &empty_fixture.blocks[0], true).await;
        assert_not_found(&empty_environment.router, &unknown).await;
        empty_environment.close().await;

        // A transaction in block 2 proves through block 3's certificate.
        let digest = hex(fixture.blocks[1].transactions[54].message_digest().as_ref());
        let transaction = proof_bundle(router, &proto::GetTransactionRequest {
            digest: fixture.blocks[1].transactions[54].message_digest().as_ref().to_vec(),
            ..Default::default()
        }).await;
        assert_eq!(certificate_height(&transaction), 3);
        assert_transactions(&transaction, &fixture.blocks[1], 54, 1);

        // After block 4 arrives, the pinned page is unchanged while the latest
        // view moves to block 4 and still reaches earlier blocks.
        publish(publisher, reporter, &fixture.blocks[3], true).await;
        let after_arrival = proof_bundle(router, &pinned).await;
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
        assert_not_found(router, &future_request).await;
        let future_present = proof_bundle(router, &proto::GetAccountRequest {
            account: future_key.as_ref().to_vec(), activity: Some(false), ..Default::default()
        }).await;
        assert_eq!(verify_account_bundle(&future_present, future_key, &fixture.blocks[3]).account.tx_count, 1);
        let account_with_history = proof_bundle(router, &account_request).await;
        assert_eq!(certificate_height(&account_with_history), 4);
        assert_account_page(&account_with_history, 59);
        assert!(account_with_history["transactions"].as_array().unwrap().iter().any(|row| {
            row["location"].as_str().unwrap().parse::<u64>().unwrap()
                < fixture.blocks[3].block.header.transactions_range.start()
        }));

        // Both routes serve block 4's maximum-size WebAuthn transaction in full.
        let webauthn_digest = hex(fixture.blocks[3].transactions[1].message_digest().as_ref());
        let webauthn_block = proof_bundle(router, &proto::GetBlockRequest {
            height: 4, offset: 0, ..Default::default()
        }).await;
        assert_transactions(&webauthn_block, &fixture.blocks[3], 0, 2);
        let webauthn_bundle = proof_bundle(router, &proto::GetTransactionRequest {
            digest: fixture.blocks[3].transactions[1].message_digest().as_ref().to_vec(),
            ..Default::default()
        }).await;
        assert_transactions(&webauthn_bundle, &fixture.blocks[3], 1, 1);
        assert_eq!(
            webauthn_bundle["transactions"][0]["body"]
                .as_str()
                .unwrap()
                .len(),
            MAX_TRANSACTION_BYTES * 2
        );

        // Evidence a node builds from the blocks it finalized is the bundle the route serves
        // for the same transaction, apart from the Store sequence it cannot observe.
        let recent = RecentFinalized::default();
        for block in &fixture.blocks {
            recent.record(block.block.clone(), block.captured_transactions());
        }
        let webauthn = fixture.blocks[3].transactions[1].message_digest();
        let submission_evidence = evidence_json(&recent, &fixture, 4, webauthn).await;
        let first = fixture.blocks[0].transactions[0].message_digest();
        let first_bundle = proof_bundle(router, &proto::GetTransactionRequest {
            digest: first.as_ref().to_vec(),
            ..Default::default()
        }).await;
        for (built, served) in [
            (&submission_evidence, &webauthn_bundle),
            (&evidence_json(&recent, &fixture, 1, first).await, &first_bundle),
        ] {
            assert_eq!(built["sequenceNumber"], "0");
            for field in [
                "certificate",
                "headers",
                "account",
                "transactions",
                "transactionsProof",
                "nextCursor",
            ] {
                assert_eq!(built[field], served[field], "evidence field {field}");
            }
        }

        // Export the bundles for browser verification tests when requested.
        if let Some(path) = std::env::var_os("EXPLORER_FIXTURE_PATH") {
            let (historical_block, historical_transaction) = Box::pin(historical_bundles(context.child("historical_export"), &fixture)).await;
            let export = json!({
                "verificationMaterial": fixture.verification_material,
                "defaultAccountBalance": DEFAULT_ACCOUNT_BALANCE.to_string(),
                "account": hex(fixture.account.as_ref()),
                "recipient": hex(fixture.recipient.as_ref()),
                "transactionDigest": digest,
                "directBlock": direct,
                "descendantBlock": descendant,
                "descendantLastPage": last,
                "emptyBlock": empty,
                "accountBundle": account,
                "accountNext": next,
                "accountOldest": oldest,
                "accountExhausted": exhausted,
                "accountStateOnly": state_only,
                "recipientBundle": recipient,
                "transactionBundle": transaction,
                "webauthnDigest": webauthn_digest,
                "webauthnBlock": webauthn_block,
                "webauthnBundle": webauthn_bundle,
                "submissionEvidence": submission_evidence,
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
    assert_eq!(error.0, connectrpc::ErrorCode::ResourceExhausted);
}

#[tokio::test]
async fn malformed_inputs_are_rejected_before_store_reads() {
    let store = ObservedStore::open("explorer-fixture").await.unwrap();
    let client = writer_store_client(&store.url, Some("explorer-fixture")).unwrap();
    let router = router(&client, None).unwrap();
    let valid_account = proto::GetAccountRequest {
        account: vec![0; 32],
        ..Default::default()
    };
    let mut requests = Vec::new();

    // Each identity is exactly 32 bytes, including all-zero identities.
    for length in [0, 1, 31, 33] {
        requests.push((
            "GetAccount",
            proto::GetAccountRequest {
                account: vec![0; length],
                ..Default::default()
            }
            .encode_to_vec(),
        ));
        requests.push((
            "GetTransaction",
            proto::GetTransactionRequest {
                digest: vec![0; length],
                ..Default::default()
            }
            .encode_to_vec(),
        ));
        requests.push((
            "Search",
            proto::SearchRequest {
                value: vec![0; length],
                ..Default::default()
            }
            .encode_to_vec(),
        ));
    }
    requests.push((
        "GetBlock",
        proto::GetBlockRequest::default().encode_to_vec(),
    ));

    // Cursors are fixed-width exclusive indices and require both snapshot pins.
    for length in [0, 1, 7, 9, 24] {
        requests.push((
            "GetAccount",
            proto::GetAccountRequest {
                cursor: Some(vec![0; length]),
                at: Some(1),
                digest: Some(vec![0; 32]),
                account_location: Some(1),
                ..valid_account.clone()
            }
            .encode_to_vec(),
        ));
    }
    for (at, digest, account_location) in [
        (None, None, None),
        (Some(1), Some(vec![0; 32]), None),
        (None, None, Some(1)),
    ] {
        requests.push((
            "GetAccount",
            proto::GetAccountRequest {
                cursor: Some(1_u64.to_be_bytes().to_vec()),
                at,
                digest,
                account_location,
                ..valid_account.clone()
            }
            .encode_to_vec(),
        ));
    }
    requests.push((
        "GetAccount",
        proto::GetAccountRequest {
            account_location: Some(1),
            ..valid_account.clone()
        }
        .encode_to_vec(),
    ));

    // Snapshot pins require both a positive height and a complete digest.
    for (at, digest) in [
        (Some(1), None),
        (None, Some(vec![0; 32])),
        (Some(0), Some(vec![0; 32])),
        (Some(1), Some(vec![])),
        (Some(1), Some(vec![0; 31])),
        (Some(1), Some(vec![0; 33])),
    ] {
        requests.push((
            "GetAccount",
            proto::GetAccountRequest {
                at,
                digest,
                ..valid_account.clone()
            }
            .encode_to_vec(),
        ));
    }

    // Truncated bytes and varints fail in the Connect protobuf decoder.
    requests.extend([
        ("GetAccount", vec![0x0a, 0x20, 0x00]),
        ("GetBlock", vec![0x08, 0x80]),
        ("GetTransaction", vec![0x0a, 0x20, 0x00]),
        ("Search", vec![0x0a, 0x20, 0x00]),
    ]);
    for (method, bytes) in requests {
        let (status, body) = post(&router, method, bytes).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{method}: {body:?}");
        let error = serde_json::from_slice::<Value>(&body).expect("Connect error must be JSON");
        assert_eq!(error["code"], "invalid_argument", "{method}: {error}");
    }
    assert!(store.requests().is_empty());
    store.shutdown().await;
}
