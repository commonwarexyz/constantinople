use std::marker::PhantomData;

use bytes::Bytes;
use commonware_codec::{DecodeExt, FixedSize};
use commonware_cryptography::{Digest, Hasher};
use commonware_macros::boxed;
use commonware_storage::merkle::{
    self, hasher::Hasher as _, storage::Storage as MerkleStorage, Family, Graftable, Location,
    Position,
};
use commonware_storage::qmdb::current::grafting;
use exoware_sdk::{RangeMode, SerializableReadSession};

use crate::codec::{chunk_index_for_location, encode_grafted_node_key, encode_node_key};

pub(crate) struct KvMerkleStorage<'a, F: Family, D: Digest> {
    pub(crate) session: &'a SerializableReadSession,
    pub(crate) size: Position<F>,
    pub(crate) _marker: PhantomData<D>,
}

impl<F: Family, D: Digest> MerkleStorage<F> for KvMerkleStorage<'_, F, D> {
    type Digest = D;

    fn size(&self) -> Position<F> {
        self.size
    }

    async fn get_node(&self, position: Position<F>) -> Result<Option<D>, merkle::Error<F>> {
        let key = encode_node_key(position);
        let bytes = self.session.get(&key).await.map_err(|error| {
            crate::error::store_read_error(error, "exoware-qmdb node fetch failed")
        })?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        Self::decode_node(bytes.as_ref()).map(Some)
    }

    async fn get_nodes(&self, positions: &[Position<F>]) -> Result<Vec<D>, merkle::Error<F>> {
        assert!(
            positions.is_sorted_by(|a, b| a < b),
            "positions must be strictly increasing"
        );
        let nodes = self.load_nodes(positions).await?;
        positions
            .iter()
            .zip(nodes)
            .map(|(&position, node)| {
                let bytes = node.ok_or(merkle::Error::ElementPruned(position))?;
                Self::decode_node(bytes.as_ref())
            })
            .collect()
    }
}

impl<F: Family, D: Digest> KvMerkleStorage<'_, F, D> {
    fn decode_node(bytes: &[u8]) -> Result<D, merkle::Error<F>> {
        if bytes.len() != D::SIZE {
            return Err(merkle::Error::DataCorrupted(
                "exoware-qmdb node digest has invalid length",
            ));
        }
        D::decode(commonware_codec::Copying(bytes))
            .map_err(|_| merkle::Error::DataCorrupted("exoware-qmdb node digest decode failed"))
    }

    async fn load_nodes(
        &self,
        positions: &[Position<F>],
    ) -> Result<Vec<Option<Bytes>>, merkle::Error<F>> {
        if positions.is_empty() {
            return Ok(Vec::new());
        }
        let keys = positions
            .iter()
            .map(|&position| encode_node_key(position))
            .collect::<Vec<_>>();
        let refs = keys.iter().collect::<Vec<_>>();
        let rows = self
            .session
            .get_many(&refs, u32::try_from(keys.len()).unwrap_or(u32::MAX))
            .await
            .map_err(|error| {
                crate::error::store_read_error(error, "exoware-qmdb node fetch failed")
            })?
            .collect()
            .await
            .map_err(|error| {
                crate::error::store_read_error(error, "exoware-qmdb node fetch failed")
            })?;

        // Leave decoding to callers so a later malformed node cannot mask an earlier missing node.
        Ok(keys.iter().map(|key| rows.get(key).cloned()).collect())
    }
}

pub(crate) struct KvCurrentStorage<'a, F: Graftable, H: Hasher, const N: usize> {
    pub(crate) session: &'a SerializableReadSession,
    pub(crate) watermark: Location<F>,
    pub(crate) pruned_chunks: u64,
    pub(crate) size: Position<F>,
    pub(crate) _marker: PhantomData<H>,
}

impl<F: Graftable, H: Hasher, const N: usize> MerkleStorage<F> for KvCurrentStorage<'_, F, H, N> {
    type Digest = H::Digest;

    fn size(&self) -> Position<F> {
        self.size
    }

    async fn get_node(&self, position: Position<F>) -> Result<Option<H::Digest>, merkle::Error<F>> {
        self.get_node_inner(position).await
    }

    async fn get_nodes(
        &self,
        positions: &[Position<F>],
    ) -> Result<Vec<H::Digest>, merkle::Error<F>> {
        assert!(
            positions.is_sorted_by(|a, b| a < b),
            "positions must be strictly increasing"
        );
        let grafting_height = grafting::height::<N>();
        let (ops_positions, current_positions): (Vec<_>, Vec<_>) = positions
            .iter()
            .copied()
            .partition(|position| F::pos_to_height(*position) < grafting_height);
        let ops = KvMerkleStorage::<F, H::Digest> {
            session: self.session,
            size: self.size,
            _marker: PhantomData,
        };
        let (ops_nodes, current_nodes) = futures::try_join!(
            ops.load_nodes(&ops_positions),
            futures::future::try_join_all(
                current_positions
                    .iter()
                    .map(|&position| self.get_node_inner(position))
            ),
        )?;
        let mut ops_nodes = ops_nodes.into_iter().map(|bytes| {
            bytes
                .map(|bytes| KvMerkleStorage::<F, H::Digest>::decode_node(bytes.as_ref()))
                .transpose()
        });
        let mut current_nodes = current_nodes.into_iter().map(Ok);

        // Resolve absent nodes in request order after all independent reads complete
        positions
            .iter()
            .map(|&position| {
                let node = if F::pos_to_height(position) < grafting_height {
                    ops_nodes.next()
                } else {
                    current_nodes.next()
                }
                .expect("one result per requested position")?;
                node.ok_or(merkle::Error::ElementPruned(position))
            })
            .collect()
    }
}

impl<F: Graftable, H: Hasher, const N: usize> KvCurrentStorage<'_, F, H, N> {
    #[boxed]
    async fn get_node_inner(
        &self,
        position: Position<F>,
    ) -> Result<Option<H::Digest>, merkle::Error<F>> {
        let ops = KvMerkleStorage::<F, H::Digest> {
            session: self.session,
            size: self.size,
            _marker: PhantomData,
        };
        let grafting_height = grafting::height::<N>();
        let ops_height = F::pos_to_height(position);
        if ops_height < grafting_height {
            return ops.get_node(position).await;
        }

        let grafted_position = grafting::ops_to_grafted_pos::<F>(position, grafting_height);
        let grafted_height = F::pos_to_height(grafted_position);
        let leftmost = F::leftmost_leaf(grafted_position, grafted_height);
        let covered_chunks = 1u64.checked_shl(grafted_height).ok_or_else(|| {
            merkle::Error::DataCorrupted("exoware-qmdb current grafted height overflow")
        })?;
        if (*leftmost).saturating_add(covered_chunks) <= self.pruned_chunks {
            return ops.get_node(position).await;
        }

        // A parent can cover both discarded all-zero chunks and retained chunks with active bits
        // Activity changes before pruning can change its hash
        // Pruning itself preserves the root
        // Boundary deltas omit discarded chunks, so only wholly retained nodes reuse stored current hashes
        if *leftmost >= self.pruned_chunks {
            let start = encode_grafted_node_key(grafted_position, Location::new(0));
            let end = encode_grafted_node_key(grafted_position, self.watermark);
            let rows = self
                .session
                .range_with_mode(&start, &end, 1, RangeMode::Reverse)
                .await
                .map_err(|error| {
                    crate::error::store_read_error(
                        error,
                        "exoware-qmdb current grafted node fetch failed",
                    )
                })?;
            if let Some((_, bytes)) = rows.into_iter().next() {
                if bytes.len() != H::Digest::SIZE {
                    return Err(merkle::Error::DataCorrupted(
                        "exoware-qmdb current grafted node has invalid length",
                    ));
                }
                return H::Digest::decode(commonware_codec::Copying(bytes.as_ref())).map(Some).map_err(|_| {
                    merkle::Error::DataCorrupted("exoware-qmdb current grafted node decode failed")
                });
            }
        }

        // Grafted leaves require bitmap data and cannot be reconstructed from operation children
        if grafted_height == 0 {
            return Ok(None);
        }

        // Rebuild parents spanning the pruning boundary and absent delayed-merge parents from children
        let (left, right) = F::children(position, ops_height);
        let Some(left) = self.get_node_inner(left).await? else {
            return Ok(None);
        };
        let Some(right) = self.get_node_inner(right).await? else {
            return Ok(None);
        };
        let hasher = commonware_storage::qmdb::hasher::<H>();
        Ok(Some(hasher.node_digest(position, &left, &right)))
    }
}

/// Bitmap metadata and the chunks consumed by one native current proof
pub(crate) struct ProofBitmap<const N: usize> {
    len: u64,
    complete_chunks: usize,
    last_chunk: usize,
    pub(crate) pruned_chunks: usize,
    chunks: std::collections::BTreeMap<usize, [u8; N]>,
}

impl<const N: usize> ProofBitmap<N> {
    pub(crate) async fn load<F, Load, Fut>(
        watermark: Location<F>,
        pruned_chunks: u64,
        location: Option<Location<F>>,
        mut load: Load,
    ) -> Result<Self, crate::QmdbError>
    where
        F: Graftable,
        Load: FnMut(u64) -> Fut,
        Fut: std::future::Future<Output = Result<[u8; N], crate::QmdbError>>,
    {
        let len = crate::codec::op_count_for_watermark(watermark)?.as_u64();
        let chunk_bits = crate::codec::bitmap_chunk_bits::<N>();
        let complete = len / chunk_bits;
        let graftable = grafting::graftable_chunks::<F>(len, grafting::height::<N>()).min(complete);
        if pruned_chunks > graftable || complete - graftable > 1 {
            return Err(crate::QmdbError::CorruptData(
                "invalid current bitmap window".into(),
            ));
        }
        let index = |value| {
            usize::try_from(value).map_err(|_| {
                crate::QmdbError::CorruptData("current bitmap chunk index exceeds usize".into())
            })
        };
        // Current proof construction reads the partial trailing chunk (`last_chunk`, only when
        // the length is not chunk-aligned), the pending chunk (if any) and the queried chunk
        // (`get_chunk`). Upstream rejects a queried location in a pruned chunk before reading it.
        let last = chunk_index_for_location::<F, N>(watermark);
        let mut required = std::collections::BTreeSet::new();
        if len % chunk_bits != 0 {
            required.insert(last);
        }
        if complete > graftable {
            required.insert(graftable);
        }
        if let Some(location) = location {
            if location > watermark {
                return Err(crate::QmdbError::CorruptData(
                    "current proof location exceeds watermark".into(),
                ));
            }
            let chunk = chunk_index_for_location::<F, N>(location);
            if chunk >= pruned_chunks {
                required.insert(chunk);
            }
        }
        let required = required.into_iter().collect::<Vec<_>>();
        let loaded =
            futures::future::try_join_all(required.iter().map(|chunk| load(*chunk))).await?;
        let chunks = required
            .into_iter()
            .zip(loaded)
            .map(|(chunk, data)| Ok((index(chunk)?, data)))
            .collect::<Result<_, crate::QmdbError>>()?;
        Ok(Self {
            len,
            complete_chunks: index(complete)?,
            last_chunk: index(last)?,
            pruned_chunks: index(pruned_chunks)?,
            chunks,
        })
    }
}

impl<const N: usize> commonware_utils::bitmap::Readable<N> for ProofBitmap<N> {
    fn complete_chunks(&self) -> usize {
        self.complete_chunks
    }

    fn get_chunk(&self, chunk: usize) -> [u8; N] {
        *self
            .chunks
            .get(&chunk)
            .expect("current proof requested an unloaded bitmap chunk")
    }

    fn last_chunk(&self) -> ([u8; N], u64) {
        let bits = (self.len - 1) % crate::codec::bitmap_chunk_bits::<N>() + 1;
        (self.get_chunk(self.last_chunk), bits)
    }

    fn pruned_chunks(&self) -> usize {
        self.pruned_chunks
    }

    fn len(&self) -> u64 {
        self.len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_storage::merkle::{mem::Mem, mmb, mmr, verification};
    use connectrpc::{ConnectError, ConnectRpcService, RequestContext, ServiceRequest};
    use exoware_sdk::{
        common::kv::v1::Entry,
        keys::Key,
        store::query::v1::{
            Detail, GetManyEntry, GetManyFrame, GetManyRequest, GetRequest, GetResponse,
            RangeFrame, RangeRequest, ReduceRequest, ReduceResponse, Service, ServiceServer,
        },
        PrefixedStoreClient, StoreClient, StoreKeyPrefix,
    };
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };

    use commonware_utils::bitmap::Readable as _;

    // N = 1 gives eight-bit chunks (grafting height 3)
    fn load<F: Graftable>(
        watermark: u64,
        pruned_chunks: u64,
        location: Option<u64>,
    ) -> Result<(ProofBitmap<1>, Vec<u64>), crate::QmdbError> {
        let mut requested = Vec::new();
        let bitmap = futures::executor::block_on(ProofBitmap::<1>::load(
            Location::<F>::new(watermark),
            pruned_chunks,
            location.map(Location::<F>::new),
            |chunk| {
                requested.push(chunk);
                async move { Ok([chunk as u8]) }
            },
        ))?;
        Ok((bitmap, requested))
    }

    #[test]
    fn test_loads_last_chunk_only_for_partial_lengths() {
        let (bitmap, requested) = load::<mmr::Family>(12, 0, None).unwrap();
        assert_eq!(requested, [1]);
        assert_eq!(bitmap.last_chunk(), ([1], 5));
        assert_eq!(bitmap.complete_chunks(), 1);

        // An aligned MMR bitmap has neither a partial nor a pending chunk
        let (bitmap, requested) = load::<mmr::Family>(15, 0, None).unwrap();
        assert!(requested.is_empty());
        assert_eq!(bitmap.complete_chunks(), 2);
        assert_eq!(bitmap.len(), 16);

        // Pruning every complete chunk of an aligned bitmap leaves nothing to read
        let (bitmap, requested) = load::<mmr::Family>(15, 2, None).unwrap();
        assert!(requested.is_empty());
        assert_eq!(bitmap.pruned_chunks(), 2);
    }

    #[test]
    fn test_loads_queried_chunk_and_skips_pruned_locations() {
        let (bitmap, requested) = load::<mmr::Family>(20, 0, Some(3)).unwrap();
        assert_eq!(requested, [0, 2]);
        assert_eq!(bitmap.get_chunk(0), [0]);
        assert_eq!(bitmap.get_chunk(2), [2]);

        // Upstream rejects a pruned location before reading its chunk
        let (bitmap, requested) = load::<mmr::Family>(20, 1, Some(3)).unwrap();
        assert_eq!(requested, [2]);
        assert_eq!(bitmap.pruned_chunks(), 1);

        // The queried chunk and the partial chunk coincide
        let (_, requested) = load::<mmr::Family>(20, 0, Some(19)).unwrap();
        assert_eq!(requested, [2]);
    }

    #[test]
    fn test_loads_pending_chunk_for_mmb() {
        // Chunk 0 of an MMB is graftable once 11 leaves exist, so 17 leaves leave chunk 1 pending
        let (bitmap, requested) = load::<mmb::Family>(16, 0, None).unwrap();
        assert_eq!(requested, [1, 2]);
        assert_eq!(bitmap.get_chunk(1), [1]);
        assert_eq!(bitmap.last_chunk(), ([2], 1));

        // An aligned MMB bitmap still needs its pending chunk
        let (bitmap, requested) = load::<mmb::Family>(15, 0, None).unwrap();
        assert_eq!(requested, [1]);
        assert_eq!(bitmap.get_chunk(1), [1]);

        // A queried location inside the pending chunk does not load it twice
        let (_, requested) = load::<mmb::Family>(16, 0, Some(8)).unwrap();
        assert_eq!(requested, [1, 2]);
    }

    #[test]
    fn test_readable_view_matches_commonware_prunable_bitmap() {
        use commonware_utils::bitmap::{Prunable, Readable};
        for (watermark, pruned) in [(12u64, 0usize), (15, 0), (20, 1), (23, 2)] {
            let mut prunable = Prunable::<1>::new_with_pruned_chunks(pruned).unwrap();
            while Readable::len(&prunable) <= watermark {
                prunable.push(false);
            }
            let (bitmap, _) = load::<mmr::Family>(watermark, pruned as u64, None).unwrap();
            assert_eq!(bitmap.len(), Readable::len(&prunable));
            assert_eq!(
                bitmap.complete_chunks(),
                Readable::complete_chunks(&prunable)
            );
            assert_eq!(bitmap.pruned_chunks(), Readable::pruned_chunks(&prunable));
            if !prunable.is_chunk_aligned() {
                assert_eq!(bitmap.last_chunk().1, Readable::last_chunk(&prunable).1);
            }
        }
    }

    #[test]
    fn test_rejects_invalid_windows() {
        assert!(load::<mmr::Family>(12, 2, None).is_err());
        assert!(load::<mmr::Family>(12, 0, Some(13)).is_err());
        assert!(load::<mmb::Family>(9, 1, None).is_err());
    }

    #[derive(Clone, Default)]
    struct NodeQueries {
        rows: BTreeMap<Key, Bytes>,
        calls: Arc<Mutex<Vec<(&'static str, usize)>>>,
        range_barrier: Option<Arc<tokio::sync::Barrier>>,
        requests: Arc<Mutex<Vec<GetManyRequest>>>,
        sequence: Option<u64>,
        fail_stream: bool,
    }

    #[allow(refining_impl_trait)]
    impl Service for NodeQueries {
        async fn get(
            &self,
            _: RequestContext,
            request: ServiceRequest<'_, GetRequest>,
        ) -> connectrpc::ServiceResult<GetResponse> {
            self.calls.lock().unwrap().push(("get", 1));
            connectrpc::Response::ok(GetResponse {
                value: self.rows.get(request.key).cloned(),
                detail: Some(Detail {
                    sequence_number: 1,
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            })
        }

        async fn get_many(
            &self,
            _: RequestContext,
            request: ServiceRequest<'_, GetManyRequest>,
        ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<GetManyFrame>> {
            self.calls
                .lock()
                .unwrap()
                .push(("many", request.keys.len()));
            self.requests
                .lock()
                .unwrap()
                .push(request.to_owned_message());
            let sequence = self
                .sequence
                .map(|sequence| sequence.max(request.min_sequence_number.unwrap_or_default()));

            // Legal out-of-order frames require the adapter to recover requested slot order
            let mut frames = request
                .keys
                .iter()
                .rev()
                .map(|key| {
                    Ok(GetManyFrame {
                        results: vec![GetManyEntry {
                            key: key.to_vec(),
                            value: self.rows.get(*key).cloned(),
                            ..Default::default()
                        }],
                        detail: Some(Detail {
                            sequence_number: sequence.map_or(1, |sequence| sequence + 1),
                            ..Default::default()
                        })
                        .into(),
                        ..Default::default()
                    })
                })
                .collect::<Vec<_>>();
            if self.fail_stream {
                frames.push(Err(ConnectError::unavailable("test stream failure")));
            }
            Ok(connectrpc::Response::stream(futures::stream::iter(frames)))
        }

        async fn range(
            &self,
            _: RequestContext,
            request: ServiceRequest<'_, RangeRequest>,
        ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<RangeFrame>> {
            self.calls.lock().unwrap().push(("range", 1));
            if let Some(barrier) = &self.range_barrier {
                barrier.wait().await;
            }
            let results = self
                .rows
                .iter()
                .rev()
                .filter(|(key, _)| key.as_ref() >= request.start && key.as_ref() <= request.end)
                .take(1)
                .map(|(key, value)| Entry {
                    key: key.to_vec(),
                    value: value.clone(),
                    ..Default::default()
                })
                .collect();
            Ok(connectrpc::Response::stream(futures::stream::iter([Ok(
                RangeFrame {
                    results,
                    detail: Some(Detail {
                        sequence_number: 1,
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                },
            )])))
        }

        async fn reduce(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, ReduceRequest>,
        ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<ReduceResponse>> {
            Err(ConnectError::unimplemented("node read test"))
        }
    }

    async fn serve(queries: NodeQueries) -> (PrefixedStoreClient, tokio::task::JoinHandle<()>) {
        let service = ConnectRpcService::new(ServiceServer::new(queries));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, axum::Router::new().fallback_service(service))
                .await
                .unwrap();
        });
        (PrefixedStoreClient::empty(StoreClient::new(&url)), task)
    }

    async fn assert_batched_proofs<F: Family + PartialEq>() {
        let hasher = commonware_storage::qmdb::hasher::<Sha256>();
        let mut memory = Mem::<F, Digest>::new();
        let operations = (0u64..64)
            .map(|index| index.to_be_bytes().to_vec())
            .collect::<Vec<_>>();
        let mut batch = memory.new_batch();
        for operation in &operations {
            batch = batch.add(&hasher, operation);
        }
        let batch = batch.merkleize(&memory, &hasher);
        memory.apply_batch(&batch).unwrap();
        let queries = NodeQueries {
            rows: (0..*memory.size())
                .map(|raw| {
                    let position = Position::new(raw);
                    (
                        encode_node_key(position),
                        Bytes::copy_from_slice(memory.get_node(position).unwrap().as_ref()),
                    )
                })
                .collect(),
            ..Default::default()
        };
        let calls = queries.calls.clone();
        let (client, server) = serve(queries).await;
        let session = client.create_session_with_sequence(1);
        let storage = KvMerkleStorage::<F, Digest> {
            session: &session,
            size: memory.size(),
            _marker: PhantomData,
        };
        let range = Location::new(7)..Location::new(10);
        let proof = verification::historical_range_proof(
            &hasher,
            &storage,
            Location::new(64),
            range.clone(),
            0,
        )
        .await
        .unwrap();
        assert_eq!(proof, memory.range_proof(&hasher, range, 0).unwrap());
        let requested = calls.lock().unwrap().clone();
        assert_eq!(requested.len(), 1, "one bulk node request: {requested:?}");
        assert_eq!(requested[0].0, "many");
        assert!(requested[0].1 > 1);

        calls.lock().unwrap().clear();
        let locations = [Location::new(3), Location::new(19), Location::new(55)];
        let proof = verification::multi_proof(&storage, 0, hasher.root_bagging(), &locations)
            .await
            .unwrap();
        let expected = verification::multi_proof(&memory, 0, hasher.root_bagging(), &locations)
            .await
            .unwrap();
        assert_eq!(proof, expected);
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert_eq!(calls.lock().unwrap()[0].0, "many");

        calls.lock().unwrap().clear();
        assert!(storage.get_nodes(&[]).await.unwrap().is_empty());
        assert!(calls.lock().unwrap().is_empty());
        let missing = memory.size();
        assert!(
            matches!(storage.get_nodes(&[Position::new(0), missing, missing + 1]).await,
        Err(merkle::Error::ElementPruned(position)) if position == missing)
        );
        server.abort();
    }

    #[tokio::test]
    async fn test_merkle_proofs_batch_node_reads() {
        assert_batched_proofs::<mmr::Family>().await;
        assert_batched_proofs::<mmb::Family>().await;
    }

    async fn assert_current_nodes(positions: &[u64], expected_calls: &[(&str, usize)]) {
        let positions = positions
            .iter()
            .copied()
            .map(Position::<mmr::Family>::new)
            .collect::<Vec<_>>();
        let digests = positions
            .iter()
            .map(|position| Sha256::hash(&[&position.as_u64().to_be_bytes()]))
            .collect::<Vec<_>>();
        let watermark = Location::new(15);
        let queries = NodeQueries {
            rows: positions
                .iter()
                .zip(&digests)
                .map(|(&position, digest)| {
                    let key = if mmr::Family::pos_to_height(position) < grafting::height::<1>() {
                        encode_node_key(position)
                    } else {
                        encode_grafted_node_key(
                            grafting::ops_to_grafted_pos(position, grafting::height::<1>()),
                            watermark,
                        )
                    };
                    (key, Bytes::copy_from_slice(digest.as_ref()))
                })
                .collect(),
            range_barrier: Some(Arc::new(tokio::sync::Barrier::new(2))),
            ..Default::default()
        };
        let calls = queries.calls.clone();
        let (client, server) = serve(queries).await;
        let session = client.create_session_with_sequence(1);
        let storage = KvCurrentStorage::<mmr::Family, Sha256, 1> {
            session: &session,
            watermark,
            pruned_chunks: 0,
            size: Position::new(31),
            _marker: PhantomData,
        };
        // The watchdog reports a stalled sequential reader, without measuring request latency
        let nodes = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            storage.get_nodes(&positions),
        )
        .await
        .expect("grafted reads must reach the barrier concurrently")
        .unwrap();
        assert_eq!(nodes, digests);
        let mut requested = calls.lock().unwrap().clone();
        requested.sort();
        assert_eq!(requested, expected_calls);
        server.abort();
    }

    #[tokio::test]
    async fn test_current_nodes_batch_operations_and_overlap_grafted_reads() {
        assert_current_nodes(&[0, 14, 15, 29], &[("many", 2), ("range", 1), ("range", 1)]).await;
        assert_current_nodes(&[14, 29], &[("range", 1), ("range", 1)]).await;
    }

    impl NodeQueries {
        fn prefix() -> StoreKeyPrefix {
            StoreKeyPrefix::new("proof/").unwrap()
        }

        fn key<F: Family>(position: u64) -> Key {
            Self::prefix()
                .encode_key(&encode_node_key(Position::<F>::new(position)))
                .unwrap()
        }

        async fn session(&self) -> (SerializableReadSession, tokio::task::JoinHandle<()>) {
            let (client, task) = serve(self.clone()).await;
            (
                client
                    .client()
                    .prefixed(Self::prefix())
                    .create_session_with_sequence(17),
                task,
            )
        }
    }

    fn storage<F: Family>(session: &SerializableReadSession) -> KvMerkleStorage<'_, F, Digest> {
        KvMerkleStorage {
            session,
            size: Position::new(100),
            _marker: PhantomData,
        }
    }

    #[tokio::test]
    async fn batches_nodes_in_order_and_tracks_the_observed_sequence() {
        let positions = [0, 3, 8].map(Position::<mmr::Family>::new);
        let digests = [1, 2, 3]
            .map(|byte| Digest::decode(commonware_codec::Copying(&[byte; 32])).unwrap());
        let store = NodeQueries {
            sequence: Some(40),
            rows: positions
                .iter()
                .zip(&digests)
                .map(|(position, digest)| {
                    (
                        NodeQueries::key::<mmr::Family>(**position),
                        Bytes::copy_from_slice(digest.as_ref()),
                    )
                })
                .collect(),
            ..Default::default()
        };
        let (session, server) = store.session().await;
        let storage = storage::<mmr::Family>(&session);

        assert_eq!(storage.get_nodes(&positions).await.unwrap(), digests);
        assert_eq!(session.evaluated_sequence(), Some(41));
        assert_eq!(session.fixed_sequence(), Some(41));
        {
            let requests = store.requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].min_sequence_number, Some(17));
            assert_eq!(requests[0].batch_size, 3);
            assert_eq!(
                requests[0].keys,
                positions.map(|position| NodeQueries::key::<mmr::Family>(*position).to_vec())
            );
        }

        assert_eq!(
            storage.get_nodes(&positions[..1]).await.unwrap(),
            digests[..1]
        );
        assert_eq!(
            store.requests.lock().unwrap()[1].min_sequence_number,
            Some(41)
        );
        assert_eq!(session.evaluated_sequence(), Some(42));
        server.abort();
    }

    #[tokio::test]
    async fn reports_the_first_missing_or_malformed_node_in_request_order() {
        let positions = [0, 3, 8].map(Position::<mmr::Family>::new);
        for malformed in [None, Some(0), Some(3)] {
            let store = NodeQueries {
                rows: malformed
                    .map(|position| {
                        (
                            NodeQueries::key::<mmr::Family>(position),
                            Bytes::from_static(b"invalid digest"),
                        )
                    })
                    .into_iter()
                    .collect(),
                ..Default::default()
            };
            let (session, server) = store.session().await;
            let error = storage::<mmr::Family>(&session)
                .get_nodes(&positions)
                .await
                .unwrap_err();
            if malformed == Some(0) {
                assert!(matches!(
                    error,
                    merkle::Error::DataCorrupted("exoware-qmdb node digest has invalid length")
                ));
            } else {
                assert!(
                    matches!(error, merkle::Error::ElementPruned(position) if position == positions[0])
                );
            }
            assert_eq!(store.requests.lock().unwrap().len(), 1);
            server.abort();
        }
    }

    #[tokio::test]
    async fn preserves_fetch_errors_after_streamed_results() {
        let store = NodeQueries {
            fail_stream: true,
            ..Default::default()
        };
        let (session, server) = store.session().await;
        let error = storage::<mmr::Family>(&session)
            .get_nodes(&[Position::new(0)])
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            merkle::Error::DataCorrupted("exoware-qmdb node fetch failed")
        ));
        assert_eq!(store.requests.lock().unwrap().len(), 1);
        server.abort();
    }
}
