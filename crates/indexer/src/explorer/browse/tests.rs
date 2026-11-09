use super::*;
use crate::{
    publisher::{
        fixture::{Scheme, threshold},
        sql::{
            AccountMetaRow, BlockMetaRow, TxMetaRow, encode_account_meta_row,
            encode_block_meta_row, encode_tx_meta_row,
        },
    },
    store::store_client,
};
use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    http::header::CONTENT_TYPE,
    middleware::{self, Next},
    response::Response,
};
use commonware_codec::Encode;
use commonware_consensus::{
    marshal::coding::types::coding_config_for_participants,
    simplex::types::{Context as SimplexContext, Finalization, Finalize, Proposal},
    types::{Epoch, Round, View},
};
use commonware_cryptography::{Committable as _, Digest as _, Digested, Signer as _};
use commonware_cryptography_curve25519::signing as ed25519;
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig,
    merkle::{Family as _, mem::Mem},
    qmdb::{current::unordered::fixed::Db, floor::Proportional},
    translator::TwoCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, iter::NonEmpty, non_empty_range};
use constantinople_application::consensus::TransactionHistoryOperation;
use constantinople_engine::types::{EngineBlock, EngineCodedBlock};
use constantinople_primitives::{
    Block, Header as BlockHeader, Nonce, Sealable, StateSyncProof, TRANSACTION_NAMESPACE,
    TransactionHistoryEntry, TransactionPublicKey,
};
use exoware_sdk::StoreWriteBatch;
use exoware_simulator::{AppState, RocksStore, connect_stack};
use futures::StreamExt;
use rand::{SeedableRng, rngs::StdRng};
use std::{
    num::NonZeroU64,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tokio::sync::Notify;

#[derive(Default)]
struct Reads {
    floor: AtomicU64,
    sql_floors: Mutex<Vec<Option<u64>>>,
    hold_sql: AtomicBool,
    sql_started: Notify,
    release_sql: Notify,
}

struct Fixture {
    client: StoreClient,
    explorer: Arc<Explorer>,
    reads: Arc<Reads>,
    server: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn open() -> Self {
        let store = Arc::new(RocksStore::open_owned(tempfile::tempdir().unwrap(), None).unwrap());
        let reads = Arc::new(Reads::default());
        let app = Router::new()
            .fallback_service(connect_stack(AppState::new(store)))
            .layer(middleware::from_fn_with_state(reads.clone(), observe));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client =
            store_client(&format!("http://{}", listener.local_addr().unwrap()), None).unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let explorer = Arc::new(Explorer::new(&client).unwrap());
        Self {
            client,
            explorer,
            reads,
            server,
        }
    }

    async fn rows(&self, chain: &Chain, heights: impl IntoIterator<Item = u64>) {
        let schema = build_meta_schema(sql_meta_client(&self.client).unwrap()).unwrap();
        let mut writer = schema.batch_writer();
        for height in heights {
            let header = chain.header(height);
            let row = encode_block_meta_row(BlockMetaRow {
                height,
                digest: header.seal().as_ref().try_into().unwrap(),
                tx_count: u64::MAX,
                transactions_root: header.transactions_root.as_ref().try_into().unwrap(),
                transactions_tip: header.transactions_range.end(),
                view: height,
                finalized_ts_micros: 0,
            });
            writer.insert(row.table, row.values).unwrap();
        }
        writer.flush().await.unwrap();
    }

    async fn evidence(
        &self,
        chain: &Chain,
        headers: impl IntoIterator<Item = u64>,
        certificates: impl IntoIterator<Item = u64>,
    ) {
        let simplex = simplex_client(&self.client).unwrap();
        let mut batch = StoreWriteBatch::new();
        for height in headers {
            let header = chain.header(height);
            batch
                .push(
                    &simplex,
                    &keys::header_by_digest(header.seal()),
                    &header.encode(),
                )
                .unwrap();
        }
        for height in certificates {
            batch
                .push(
                    &simplex,
                    &keys::finalized_by_height(Height::new(height)),
                    &chain.certificate(height),
                )
                .unwrap();
        }
        batch.commit(&self.client).await.unwrap();
    }

    async fn publish(&self, chain: &Chain, heights: impl IntoIterator<Item = u64>) -> u64 {
        let targets = publication_target_client(&self.client).unwrap();
        let mut batch = StoreWriteBatch::new();
        for height in heights {
            batch
                .push(
                    &targets,
                    &publication_target_key(height),
                    chain.header(height).seal().as_ref(),
                )
                .unwrap();
        }
        let sequence = batch.commit(&self.client).await.unwrap();
        self.reads.floor.store(sequence, Ordering::SeqCst);
        sequence
    }

    async fn close(self) {
        self.server.abort();
        let _ = self.server.await;
    }
}

struct Chain {
    headers: Vec<Header>,
    commitments: Vec<EngineCommitment<Sha256, VerifyingKey>>,
    schemes: Vec<Scheme>,
    verifier: Scheme,
}

// Append the exact operations whose canonical root is sealed into each header.
fn append_root<Op: Encode>(
    memory: &mut Mem<mmr::Family, Digest>,
    operations: &[Op],
    end: u64,
    floor: u64,
) -> Digest {
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    let mut batch = memory.new_batch();
    for operation in operations {
        batch = batch.add(&hasher, &operation.encode());
    }
    let batch = batch.merkleize(memory, &hasher);
    let root = batch
        .root(
            &hasher,
            mmr::Family::inactive_peaks(Location::new(end), Location::new(floor)),
        )
        .unwrap();
    memory.apply_batch(&batch).unwrap();
    root
}

fn state_boundaries(
    counts: &[u64],
    account: AccountKey,
) -> Vec<(Digest, u64, u64, StateSyncProof<Digest>)> {
    let counts = counts.to_vec();
    deterministic::Runner::default().start(|context| async move {
        let page_cache = CacheRef::new(NZU16!(88), NZUsize!(8));
        let mut db =
            Db::<mmr::Family, _, AccountKey, Account, Sha256, TwoCap, 32, Sequential>::init(
                context,
                commonware_storage::qmdb::current::Config {
                    merkle_config: commonware_storage::merkle::full::Config {
                        journal_partition: "browse-state-merkle".into(),
                        metadata_partition: "browse-state-merkle-meta".into(),
                        items_per_blob: NZU64!(11),
                        write_buffer: NZUsize!(1024),
                        replay_buffer: NZUsize!(1024),
                        strategy: Sequential,
                        page_cache: page_cache.clone(),
                    },
                    journal_config: JournalConfig {
                        partition: "browse-state-operations".into(),
                        items_per_blob: NZU64!(7),
                        page_cache,
                        write_buffer: NZUsize!(1024),
                        replay_buffer: NZUsize!(1024),
                    },
                    grafted_metadata_partition: "browse-state-grafted-meta".into(),
                    translator: TwoCap,
                    init_cache: None,
                    init_buffer: NZUsize!(4096),
                    init_concurrency: (),
                },
                None,
            )
            .await
            .unwrap();
        let mut boundaries = Vec::with_capacity(counts.len());
        let mut nonce = 0;
        for count in counts {
            nonce += count;
            let mut batch = db.new_batch();
            if count > 0 {
                batch = batch.write(
                    account,
                    Some(Account {
                        balance: 100,
                        nonce: Nonce::new(nonce, 0),
                        tx_count: nonce,
                    }),
                );
            }
            let batch = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
            let state_sync = StateSyncProof {
                ops_root: batch.ops_root(),
                witness: batch.ops_root_witness().clone(),
            };
            db = db.apply_batch(batch).await.unwrap();
            let bounds = db.bounds();
            boundaries.push((
                db.root(),
                db.sync_boundary().as_u64(),
                bounds.end.as_u64(),
                state_sync,
            ));
        }
        db.destroy().await.unwrap();
        boundaries
    })
}

impl Chain {
    async fn new(counts: impl IntoIterator<Item = u64>) -> Self {
        let counts = counts.into_iter().collect::<Vec<_>>();
        let mut rng = StdRng::from_seed([42; 32]);
        let (schemes, verifier) = threshold(&mut rng, b"constantinople_CONSENSUS", 4);
        let coding = coding_config_for_participants(schemes.len() as u16);
        let signer = ed25519::SigningKey::from_seed(7);
        let sender = TransactionPublicKey::ed25519(signer.public_key());
        let account = AccountKey::from_public_key(&sender);
        let leader = ed25519::SigningKey::from_seed(9).public_key();

        // The deterministic runner must not inherit this Tokio task's cooperative budget.
        let state_counts = counts.clone();
        let states = tokio::task::spawn_blocking(move || state_boundaries(&state_counts, account))
            .await
            .unwrap();
        let mut transactions = Mem::<mmr::Family, Digest>::new();
        append_root(
            &mut transactions,
            &[TransactionHistoryOperation::<Sha256>::Commit(
                None,
                Location::new(0),
            )],
            1,
            0,
        );
        let mut transaction_end = 1;
        let mut parent_transaction_start = 0;
        let mut nonce = 0;
        let mut headers: Vec<Header> = Vec::new();
        let mut commitments = Vec::new();
        let mut parent = Digest::EMPTY;
        let mut parent_commitment = EngineCommitment::<Sha256, VerifyingKey>::from((
            Digest::EMPTY,
            Digest::EMPTY,
            Digest::EMPTY,
            coding,
        ));
        for (index, (count, (state_root, state_start, state_end, state_sync))) in
            counts.into_iter().zip(states).enumerate()
        {
            let height = index as u64 + 1;
            let floor = parent_transaction_start;
            parent_transaction_start = transaction_end;
            let body = (0..count)
                .map(|_| {
                    let transaction = Transaction::<Digest>::new(
                        sender.clone(),
                        sender.clone(),
                        NonZeroU64::MIN,
                        nonce,
                    )
                    .seal_and_sign(
                        &signer,
                        TRANSACTION_NAMESPACE,
                        &mut Sha256::default(),
                    );
                    nonce += 1;
                    transaction
                })
                .collect::<Vec<_>>();
            let mut operations = body
                .iter()
                .map(|transaction| {
                    TransactionHistoryOperation::<Sha256>::Append(TransactionHistoryEntry {
                        digest: *transaction.message_digest(),
                        sender_index: transaction.value().nonce,
                        recipient_index: transaction.value().nonce,
                    })
                })
                .collect::<Vec<_>>();
            operations.push(TransactionHistoryOperation::<Sha256>::Commit(
                None,
                Location::new(floor),
            ));
            transaction_end += operations.len() as u64;
            let transactions_root =
                append_root(&mut transactions, &operations, transaction_end, floor);
            let header = BlockHeader {
                context: SimplexContext {
                    round: Round::new(Epoch::zero(), View::new(height)),
                    leader: leader.clone(),
                    parent: (View::new(height - 1), parent_commitment),
                },
                parent,
                height,
                timestamp: (height - 1) / 2,
                state_root,
                state_range: non_empty_range!(state_start, state_end),
                transactions_root,
                transactions_range: non_empty_range!(floor, transaction_end),
            };
            let block: EngineBlock<Sha256, VerifyingKey> = Block::new(header, body, state_sync)
                .seal(&mut Sha256::default())
                .into();
            let coded = EngineCodedBlock::encode(
                Digested::precomputed(block.clone(), *block.seal()),
                coding,
                &Sequential,
            )
            .await;
            parent_commitment = coded.commitment();
            parent = *block.seal();
            headers.push(crate::simplex_block::encode_simplex_block_parts(&block).0);
            commitments.push(parent_commitment);
        }
        Self {
            headers,
            commitments,
            schemes,
            verifier,
        }
    }

    fn header(&self, height: u64) -> &Header {
        &self.headers[height as usize - 1]
    }

    fn certificate(&self, height: u64) -> Bytes {
        let header = self.header(height);
        let commitment = self.commitments[height as usize - 1];
        let proposal = Proposal::new(header.context.round, header.context.parent.0, commitment);
        let votes = self
            .schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect::<Vec<_>>();
        let proof = Finalization::from_finalizes(
            &self.verifier,
            NonEmpty::try_new(votes.iter()).unwrap(),
            &Sequential,
        )
        .unwrap();
        let certified =
            CertifiedHeader::<Sha256, VerifyingKey>::decode((commitment, header.clone()).encode())
                .unwrap();
        Certificate::new(proof, certified).unwrap().encode()
    }

    fn assert_batch(&self, response: &proto::WatchBlocksResponse, head: u64, lowest: u64) {
        let certificate =
            Certificate::decode_cfg(Bytes::copy_from_slice(&response.certificate), &((), ()))
                .unwrap();
        assert!(certificate.proof.verify(
            &mut StdRng::from_seed([43; 32]),
            &self.verifier,
            &Sequential
        ));
        assert_eq!(
            certificate.proof.proposal.payload,
            self.commitments[head as usize - 1]
        );
        assert_eq!(certificate.header.header(), self.header(head));
        let expected = (lowest..head)
            .rev()
            .map(|height| self.header(height).encode().to_vec())
            .collect::<Vec<_>>();
        assert_eq!(response.headers, expected);
        let mut child = certificate.header.header().clone();
        for encoded in &response.headers {
            let parent = Header::decode(Bytes::copy_from_slice(encoded)).unwrap();
            assert_eq!(parent.height + 1, child.height);
            assert_eq!(child.parent, *parent.seal());
            assert_eq!(child.context.parent.1.block(), *parent.seal());
            child = parent;
        }
    }
}

fn feed_json(batch: &proto::WatchBlocksResponse) -> serde_json::Value {
    serde_json::json!({
        "certificate": hex(&batch.certificate),
        "headers": batch.headers.iter().map(|header| hex(header)).collect::<Vec<_>>(),
        "sequenceNumber": batch.sequence_number.to_string(),
    })
}

// The fixture uses the explorer's uncompressed read client. Reading the wire
// floor independently makes the visibility assertion fail if its session is lost.
fn varint(bytes: &mut &[u8]) -> u64 {
    let mut value = 0;
    for shift in (0..70).step_by(7) {
        let byte = bytes[0];
        *bytes = &bytes[1..];
        value |= u64::from(byte & 127) << shift;
        if byte < 128 {
            return value;
        }
    }
    panic!("invalid fixture protobuf varint");
}

async fn observe(State(reads): State<Arc<Reads>>, request: Request, next: Next) -> Response {
    let path = request.uri().path().to_string();
    if !path.starts_with("/store.query.v1.Service/") {
        return next.run(request).await;
    }
    assert!(!request.headers().contains_key("content-encoding"));
    assert!(!request.headers().contains_key("connect-content-encoding"));
    let streamed = request.headers()[CONTENT_TYPE] == "application/connect+proto";
    let (parts, body) = request.into_parts();
    // A sparse certificate can request 4096 prefixed header keys in one GetMany.
    let body = to_bytes(body, 256 * 1024).await.unwrap();
    let mut bytes = if streamed { &body[5..] } else { &body[..] };
    let floor_field = if path.ends_with("/Range") { 6 } else { 2 };
    let mut sql = false;
    let mut floor = None;
    while !bytes.is_empty() {
        let tag = varint(&mut bytes);
        match tag & 7 {
            0 => {
                let value = varint(&mut bytes);
                if tag >> 3 == floor_field {
                    floor = Some(value);
                }
            }
            2 => {
                let len = usize::try_from(varint(&mut bytes)).unwrap();
                if tag >> 3 == 1 {
                    sql |= bytes.first() == Some(&3);
                }
                bytes = &bytes[len..];
            }
            wire => panic!("unexpected query wire type {wire}"),
        }
    }
    if sql && reads.floor.load(Ordering::SeqCst) > 0 {
        reads.sql_floors.lock().unwrap().push(floor);
        if reads.hold_sql.load(Ordering::SeqCst) {
            reads.sql_started.notify_one();
            reads.release_sql.notified().await;
        }
    }
    next.run(Request::from_parts(parts, Body::from(body))).await
}

fn rpc(
    fixture: &Fixture,
) -> proto::ExplorerServiceClient<connectrpc::client::ServiceTransport<Router>> {
    proto::ExplorerServiceClient::new(
        connectrpc::client::ServiceTransport::new(router(&fixture.client, None).unwrap()),
        connectrpc::client::ClientConfig::new("http://localhost".parse().unwrap()),
    )
}

#[tokio::test]
async fn shared_publication_batch_catches_up_by_certified_height_without_losing_overlap() {
    let fixture = Fixture::open().await;
    let chain = Chain::new(std::iter::repeat_n(0, 4163)).await;
    fixture.rows(&chain, 1..=4163).await;
    let certificates = (64..=4096)
        .step_by(64)
        .chain([4160, 4163])
        .collect::<Vec<_>>();
    fixture.evidence(&chain, 1..=4163, certificates).await;
    assert!(
        fixture
            .explorer
            .block_event(Some(0))
            .await
            .unwrap()
            .is_none()
    );
    let sequence = fixture.publish(&chain, 1..=4163).await;
    let (head, latest) = fixture.explorer.block_event(None).await.unwrap().unwrap();
    assert_eq!(head, 4163);
    chain.assert_batch(&latest, head, head - 1);

    let mut after = 0;
    let mut delivered = Vec::new();
    while after < 4163 {
        let (head, event) = fixture
            .explorer
            .block_event(Some(after))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(head, (after + 64).min(4163));
        chain.assert_batch(&event, head, after.max(1));
        assert_eq!(event.sequence_number, sequence);
        if after > 0 {
            assert_eq!(
                event.headers.last().unwrap(),
                &chain.header(after).encode().to_vec()
            );
        }
        let certificate =
            Certificate::decode_cfg(Bytes::copy_from_slice(&event.certificate), &((), ())).unwrap();
        let rows = event
            .headers
            .iter()
            .rev()
            .map(|bytes| {
                Header::decode(Bytes::copy_from_slice(bytes))
                    .unwrap()
                    .height
            })
            .chain([certificate.header.header().height]);
        delivered.extend(rows.filter(|height| *height > after));
        after = head;
    }
    assert_eq!(delivered, (1..=4163).collect::<Vec<_>>());
    let (head, resumed) = fixture
        .explorer
        .block_event(Some(32))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head, 64);
    chain.assert_batch(&resumed, head, 32);
    for after in [4163, u64::MAX] {
        assert!(
            fixture
                .explorer
                .block_event(Some(after))
                .await
                .unwrap()
                .is_none()
        );
    }
    let floors = fixture.reads.sql_floors.lock().unwrap().clone();
    assert!(!floors.is_empty());
    assert!(
        floors
            .iter()
            .all(|floor| floor.is_some_and(|floor| floor >= sequence)),
        "{floors:?}"
    );
    fixture.close().await;
}

#[tokio::test]
async fn bootstrap_and_resume_ignore_sql_counts_and_preserve_advancing_floors() {
    let fixture = Fixture::open().await;
    let chain = Chain::new([3, 0, 2, 1]).await;
    fixture.rows(&chain, 1..=4).await;
    fixture.evidence(&chain, 1..=4, [4]).await;
    fixture.publish(&chain, [1]).await;
    assert!(fixture.explorer.block_event(None).await.unwrap().is_none());
    fixture.evidence(&chain, [], [1]).await;
    for after in [None, Some(0)] {
        let (head, event) = fixture.explorer.block_event(after).await.unwrap().unwrap();
        assert_eq!(head, 1);
        chain.assert_batch(&event, 1, 1);
        assert!(event.headers.is_empty());
    }
    let (_, first) = fixture.explorer.block_event(None).await.unwrap().unwrap();
    fixture.publish(&chain, 2..=3).await;
    let (head, latest) = fixture.explorer.block_event(None).await.unwrap().unwrap();
    assert_eq!(head, 1);
    chain.assert_batch(&latest, 1, 1);
    assert!(
        fixture
            .explorer
            .block_event(Some(1))
            .await
            .unwrap()
            .is_none()
    );
    let first_sequence = fixture.reads.floor.load(Ordering::SeqCst);
    let sequence = fixture.publish(&chain, [4]).await;
    assert!(sequence > first_sequence);
    let (head, event) = fixture
        .explorer
        .block_event(Some(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head, 4);
    chain.assert_batch(&event, 4, 1);
    assert_eq!(event.sequence_number, sequence);
    assert_eq!(chain.header(1).timestamp, chain.header(2).timestamp);
    let certificate =
        Certificate::decode_cfg(Bytes::copy_from_slice(&event.certificate), &((), ())).unwrap();
    let mut returned = event
        .headers
        .iter()
        .rev()
        .map(|bytes| Header::decode(Bytes::copy_from_slice(bytes)).unwrap())
        .collect::<Vec<_>>();
    returned.push(certificate.header.header().clone());
    let mut previous_end = 1;
    for (header, count) in returned.iter().zip([3, 0, 2, 1]) {
        assert_eq!(header.transactions_range.end() - previous_end - 1, count);
        previous_end = header.transactions_range.end();
    }
    assert_eq!(
        returned
            .iter()
            .map(|header| header.transactions_range.start())
            .collect::<Vec<_>>(),
        [0, 1, 5, 6]
    );
    assert!(chain.header(4).transactions_range.start() > chain.header(1).transactions_range.end());
    assert_ne!(
        chain.header(4).transactions_range.end() - chain.header(4).transactions_range.start() - 1,
        1
    );
    let floors = fixture.reads.sql_floors.lock().unwrap().clone();
    assert!(floors.iter().any(|floor| *floor == Some(sequence)));
    if let Some(path) = std::env::var_os("EXPLORER_FEED_FIXTURE_PATH") {
        let (_, after_zero) = fixture
            .explorer
            .block_event(Some(0))
            .await
            .unwrap()
            .unwrap();
        let (_, bootstrap) = fixture.explorer.block_event(None).await.unwrap().unwrap();
        chain.assert_batch(&after_zero, 4, 1);
        chain.assert_batch(&bootstrap, 4, 3);
        let empty = Chain::new([0]).await;
        let conflicting = Chain::new([1]).await;
        assert_eq!(
            empty.verifier.identity().encode(),
            chain.verifier.identity().encode()
        );
        assert_eq!(
            conflicting.verifier.identity().encode(),
            chain.verifier.identity().encode()
        );
        let empty_first = proto::WatchBlocksResponse {
            certificate: empty.certificate(1).to_vec(),
            ..Default::default()
        };
        let conflicting_first = proto::WatchBlocksResponse {
            certificate: conflicting.certificate(1).to_vec(),
            ..Default::default()
        };
        empty.assert_batch(&empty_first, 1, 1);
        conflicting.assert_batch(&conflicting_first, 1, 1);
        assert_ne!(first.certificate, conflicting_first.certificate);
        let export = serde_json::json!({
            "verificationMaterial": hex(&chain.verifier.identity().encode()),
            "afterZero": feed_json(&after_zero),
            "bootstrap": feed_json(&bootstrap),
            "resumed": feed_json(&event),
            "first": feed_json(&first),
            "emptyFirst": feed_json(&empty_first),
            "conflictingFirst": feed_json(&conflicting_first),
        });
        std::fs::write(path, serde_json::to_vec_pretty(&export).unwrap())
            .expect("requested browser feed fixture must be writable");
    }
    fixture.close().await;
}

#[tokio::test]
async fn sparse_certificates_enforce_the_4096_height_gap() {
    let chain = Chain::new(std::iter::repeat_n(0, 4098)).await;
    for (head, allowed) in [(4097, true), (4098, false)] {
        let fixture = Fixture::open().await;
        fixture.rows(&chain, 1..=4098).await;
        fixture.evidence(&chain, 1..=4098, head..=4098).await;
        fixture.publish(&chain, 1..=4098).await;
        let result = fixture.explorer.block_event(Some(1)).await;
        if allowed {
            let (height, event) = result.unwrap().unwrap();
            assert_eq!(height, head);
            chain.assert_batch(&event, head, 1);
            assert_eq!(event.headers.len(), 4096);
        } else {
            assert_eq!(result.unwrap_err().0, ErrorCode::ResourceExhausted);
        }
        fixture.close().await;
    }
}

#[tokio::test]
async fn missing_or_wrong_ancestors_and_mismatched_publications_fail_closed() {
    let chain = Chain::new([0, 0, 0]).await;
    let fixture = Fixture::open().await;
    fixture.rows(&chain, [1]).await;
    fixture.evidence(&chain, [1], [3]).await;
    fixture.publish(&chain, 1..=3).await;
    assert_eq!(
        fixture.explorer.block_event(Some(1)).await.unwrap_err().0,
        ErrorCode::Unavailable
    );
    fixture.rows(&chain, [2, 3]).await;
    assert_eq!(
        fixture.explorer.block_event(Some(1)).await.unwrap_err().0,
        ErrorCode::Unavailable
    );

    let simplex = simplex_client(&fixture.client).unwrap();
    let mut batch = StoreWriteBatch::new();
    batch
        .push(
            &simplex,
            &keys::header_by_digest(chain.header(2).seal()),
            &chain.header(1).encode(),
        )
        .unwrap();
    batch.commit(&fixture.client).await.unwrap();
    assert_eq!(
        fixture.explorer.block_event(Some(1)).await.unwrap_err().0,
        ErrorCode::Internal
    );

    fixture.evidence(&chain, [2], []).await;
    let mut batch = StoreWriteBatch::new();
    batch
        .push(
            &simplex,
            &keys::finalized_by_height(Height::new(3)),
            &chain.certificate(2),
        )
        .unwrap();
    batch.commit(&fixture.client).await.unwrap();
    assert_eq!(
        fixture.explorer.block_event(Some(1)).await.unwrap_err().0,
        ErrorCode::Internal
    );

    fixture.evidence(&chain, [], [3]).await;
    let targets = publication_target_client(&fixture.client).unwrap();
    let mut batch = StoreWriteBatch::new();
    batch
        .push(
            &targets,
            &publication_target_key(3),
            chain.header(2).seal().as_ref(),
        )
        .unwrap();
    batch.commit(&fixture.client).await.unwrap();
    assert_eq!(
        fixture.explorer.block_event(None).await.unwrap_err().0,
        ErrorCode::Internal
    );
    fixture.close().await;
}

#[tokio::test]
async fn oversized_certificates_and_ancestor_headers_are_rejected_before_decoding() {
    let chain = Chain::new([0, 0]).await;
    let fixture = Fixture::open().await;
    fixture.rows(&chain, 1..=2).await;
    fixture.evidence(&chain, [1], [2]).await;
    fixture.publish(&chain, 1..=2).await;
    let simplex = simplex_client(&fixture.client).unwrap();

    let mut certificate = chain.certificate(2).to_vec();
    certificate.resize(MAX_CERTIFICATE_BYTES + 1, 0);
    let mut batch = StoreWriteBatch::new();
    batch
        .push(
            &simplex,
            &keys::finalized_by_height(Height::new(2)),
            certificate,
        )
        .unwrap();
    batch.commit(&fixture.client).await.unwrap();
    assert_eq!(
        fixture.explorer.block_event(Some(1)).await.unwrap_err().0,
        ErrorCode::ResourceExhausted
    );

    fixture.evidence(&chain, [], [2]).await;
    let mut header = chain.header(1).encode().to_vec();
    header.resize(MAX_HEADER_BYTES + 1, 0);
    let mut batch = StoreWriteBatch::new();
    batch
        .push(
            &simplex,
            &keys::header_by_digest(chain.header(1).seal()),
            header,
        )
        .unwrap();
    batch.commit(&fixture.client).await.unwrap();
    assert_eq!(
        fixture.explorer.block_event(Some(1)).await.unwrap_err().0,
        ErrorCode::ResourceExhausted
    );
    fixture.close().await;
}

#[tokio::test]
async fn generated_stream_follows_publication_resumes_and_drops_pending_reads() {
    let fixture = Fixture::open().await;
    let chain = Chain::new(std::iter::repeat_n(0, 135)).await;
    fixture.rows(&chain, 1..=135).await;
    fixture.evidence(&chain, 1..=135, [64, 128, 134, 135]).await;
    fixture.publish(&chain, 1..=134).await;
    let client = rpc(&fixture);
    let mut latest = client
        .watch_blocks(proto::WatchBlocksRequest::default())
        .await
        .unwrap();
    let event = tokio::time::timeout(Duration::from_secs(2), latest.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .to_owned_message();
    chain.assert_batch(&event, 134, 133);
    drop(latest);
    let mut resumed = client
        .watch_blocks(proto::WatchBlocksRequest {
            after: Some(32),
            ..Default::default()
        })
        .await
        .unwrap();
    for (head, overlap) in [(64, 32), (128, 64), (134, 128)] {
        let event = tokio::time::timeout(Duration::from_secs(2), resumed.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .to_owned_message();
        chain.assert_batch(&event, head, overlap);
    }
    drop(resumed);
    let mut live = client
        .watch_blocks(proto::WatchBlocksRequest {
            after: Some(134),
            ..Default::default()
        })
        .await
        .unwrap();
    fixture.publish(&chain, [135]).await;
    let event = tokio::time::timeout(Duration::from_secs(2), live.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .to_owned_message();
    chain.assert_batch(&event, 135, 134);
    drop(live);

    // The generated response body owns the pending read and its Explorer.
    let explorer = Arc::new(Explorer::new(&fixture.client).unwrap());
    let weak = Arc::downgrade(&explorer);
    fixture.reads.hold_sql.store(true, Ordering::SeqCst);
    let client = proto::ExplorerServiceClient::new(
        connectrpc::client::ServiceTransport::new(
            super::super::rpc::router(explorer, None).unwrap(),
        ),
        connectrpc::client::ClientConfig::new("http://localhost".parse().unwrap()),
    );
    let mut stream = client
        .watch_blocks(proto::WatchBlocksRequest {
            after: Some(0),
            ..Default::default()
        })
        .await
        .unwrap();
    drop(client);
    let pending = tokio::spawn(async move { stream.message().await });
    tokio::time::timeout(Duration::from_secs(2), fixture.reads.sql_started.notified())
        .await
        .unwrap();
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    assert!(weak.upgrade().is_none());
    fixture.reads.hold_sql.store(false, Ordering::SeqCst);
    fixture.reads.release_sql.notify_one();
    fixture.close().await;
}

#[tokio::test]
async fn generated_search_returns_one_match_and_validates_byte_width() {
    let fixture = Fixture::open().await;
    let schema = build_meta_schema(sql_meta_client(&fixture.client).unwrap()).unwrap();
    let mut writer = schema.batch_writer();
    for row in [
        encode_account_meta_row(AccountMetaRow {
            account: [0xab; 32],
            balance: 1,
            nonce_base: 0,
            nonce_bitmap: 0,
            qmdb_location: 1,
            tx_count: 0,
            write_height: 1,
        }),
        encode_tx_meta_row(TxMetaRow {
            digest: [0xcd; 32],
            qmdb_location: 1,
            body: Bytes::new(),
            height: 1,
            sender_index: 0,
            recipient_index: 0,
        }),
    ] {
        writer.insert(row.table, row.values).unwrap();
    }
    writer.flush().await.unwrap();
    let client = rpc(&fixture);
    for (value, kind) in [(0xab, SearchKind::Account), (0xcd, SearchKind::Transaction)] {
        let result = client
            .search(proto::SearchRequest {
                value: vec![value; 32],
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert_eq!(result.kind, kind);
        assert_eq!(result.value, [value; 32]);
    }
    let absent = client
        .search(proto::SearchRequest {
            value: vec![0; 32],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(absent.code, ErrorCode::NotFound);
    for len in [0, 1, 31, 33] {
        let invalid = client
            .search(proto::SearchRequest {
                value: vec![0; len],
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(invalid.code, ErrorCode::InvalidArgument);
    }
    fixture.close().await;
}

#[tokio::test]
async fn upstream_failure_closes_the_feed_and_search_remains_retryable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let client = crate::store_client(&format!("http://{address}"), None).unwrap();
    let explorer = Arc::new(Explorer::new(&client).unwrap());
    let mut stream = Box::pin(events(explorer, Some(1)));
    let failed = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .unwrap();
    assert_eq!(failed.unwrap().unwrap_err().code, ErrorCode::Unavailable);
    assert!(stream.next().await.is_none());
    let rpc = proto::ExplorerServiceClient::new(
        connectrpc::client::ServiceTransport::new(router(&client, None).unwrap()),
        connectrpc::client::ClientConfig::new("http://localhost".parse().unwrap()),
    );
    let error = rpc
        .search(proto::SearchRequest {
            value: vec![0; 32],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Unavailable);
}
