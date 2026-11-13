use super::*;
use crate::{
    mmb, mmr,
    qmdb::{
        current::{tests::fixed_config, unordered::fixed},
        floor::{Hold, Proportional},
    },
    translator::OneCap,
};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_macros::test_traced;
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
use std::collections::BTreeMap;

type TestDb<F, const N: usize> = fixed::Db<
    F,
    deterministic::Context,
    Digest,
    Digest,
    Sha256,
    OneCap,
    N,
    Sequential,
>;

struct Published<F: Graftable, const N: usize> {
    chunks: BTreeMap<u64, [u8; N]>,
    nodes: BTreeMap<Position<F>, Digest>,
}

impl<F: Graftable, const N: usize> Published<F, N> {
    fn from_db(db: &TestDb<F, N>) -> Self {
        let bitmap = db.bitmap();
        let chunks = (bitmap.pruned_chunks() as u64..bitmap.len().div_ceil((N * 8) as u64))
            .map(|idx| (idx, bitmap.get_chunk(idx as usize)))
            .collect();
        let nodes = (0..*db.grafted_tree.size())
            .filter_map(|pos| {
                db.grafted_tree.get_node(Position::new(pos)).map(|digest| {
                    (
                        grafting::grafted_to_ops_pos::<F>(
                            Position::new(pos),
                            grafting::height::<N>(),
                        ),
                        digest,
                    )
                })
            })
            .collect();
        Self { chunks, nodes }
    }

    fn apply(&mut self, boundary: &Boundary<F, Digest, N>) {
        self.chunks.extend(boundary.chunks.iter().copied());
        self.nodes.extend(boundary.grafted_nodes.iter().copied());
    }

    async fn check(&self, db: &TestDb<F, N>, boundary: &Boundary<F, Digest, N>) {
        assert_eq!(boundary.root, db.root());
        assert!(boundary.witness.verify::<Sha256>(&db.ops_root(), &db.root()));
        assert_eq!(boundary.pruned_chunks, db.bitmap().pruned_chunks() as u64);
        let bitmap = PublishedBitmap {
            chunks: &self.chunks,
            len: *db.bounds().end,
            pruned: boundary.pruned_chunks as usize,
        };
        for idx in bitmap.pruned_chunks()..bitmap.len().div_ceil((N * 8) as u64) as usize {
            assert_eq!(bitmap.get_chunk(idx), db.bitmap().get_chunk(idx));
        }
        for raw_pos in 0..*db.grafted_tree.size() {
            let pos = Position::new(raw_pos);
            if let Some(expected) = db.grafted_tree.get_node(pos) {
                let ops_pos = grafting::grafted_to_ops_pos::<F>(pos, grafting::height::<N>());
                assert_eq!(self.nodes.get(&ops_pos), Some(&expected));
            }
        }
        let grafted = PublishedNodes::<F, N> {
            nodes: &self.nodes,
            size: db.grafted_tree.size(),
        };
        let storage = grafting::Storage::<F, Sha256, _, _>::new(
            &grafted,
            grafting::height::<N>(),
            &db.any.log.merkle,
        );
        let witness = compute_ops_root_witness::<F, Sha256, _, _, N>(
            &bitmap,
            &storage,
            db.bounds().end,
            db.any.inactivity_floor_loc,
        )
        .await
        .unwrap();
        assert_eq!(witness.grafted_root, boundary.witness.grafted_root);
        assert_eq!(
            witness.pending_chunk_digest,
            boundary.witness.pending_chunk_digest,
        );
        assert_eq!(witness.partial_chunk, boundary.witness.partial_chunk);
        assert_eq!(witness.root::<Sha256>(&db.ops_root()), boundary.root);
    }
}

struct PublishedBitmap<'a, const N: usize> {
    chunks: &'a BTreeMap<u64, [u8; N]>,
    len: u64,
    pruned: usize,
}

impl<const N: usize> bitmap::Readable<N> for PublishedBitmap<'_, N> {
    fn complete_chunks(&self) -> usize {
        (self.len / (N * 8) as u64) as usize
    }

    fn get_chunk(&self, idx: usize) -> [u8; N] {
        *self.chunks.get(&(idx as u64)).expect("published chunk")
    }

    fn last_chunk(&self) -> ([u8; N], u64) {
        let remainder = self.len % (N * 8) as u64;
        let bits = if remainder == 0 {
            (N * 8) as u64
        } else {
            remainder
        };
        let idx = (self.len - 1) / (N * 8) as u64;
        (self.get_chunk(idx as usize), bits)
    }

    fn pruned_chunks(&self) -> usize {
        self.pruned
    }

    fn len(&self) -> u64 {
        self.len
    }
}

struct PublishedNodes<'a, F: Graftable, const N: usize> {
    nodes: &'a BTreeMap<Position<F>, Digest>,
    size: Position<F>,
}

impl<F: Graftable, const N: usize> Readable for PublishedNodes<'_, F, N> {
    type Family = F;
    type Digest = Digest;

    fn size(&self) -> Position<F> {
        self.size
    }

    fn get_node(&self, pos: Position<F>) -> Option<Digest> {
        self.nodes
            .get(&grafting::grafted_to_ops_pos::<F>(pos, grafting::height::<N>()))
            .copied()
    }
}

async fn replay<F: Graftable, const N: usize>(ctx: deterministic::Context) {
    let mut db = TestDb::<F, N>::init(
        ctx.child("storage"),
        fixed_config::<OneCap>("publication"),
        None,
    )
    .await
    .unwrap();
    let initial = db.to_batch();
    let boundary = initial.boundary();
    assert!(boundary.chunks.is_empty());
    assert!(boundary.grafted_nodes.is_empty());
    let mut published = Published::from_db(&db);
    published.check(&db, &boundary).await;
    let count = (N * 16 + 5) as u64;
    for round in 0..3u64 {
        let mut batch = db.new_batch();
        for key in 0..count {
            batch = batch.write(
                Sha256::hash(&[&key.to_be_bytes()]),
                Some(Sha256::hash(&[&round.to_be_bytes()])),
            );
        }
        let batch = batch.merkleize(&db, None, &mut Hold).await.unwrap();
        let boundary = batch.boundary();
        assert_eq!(
            batch.ops_pinned_nodes(&db).unwrap(),
            batch.inner.pinned_nodes(&db.any).unwrap(),
        );
        db = db.apply_batch(batch).await.unwrap();
        published.apply(&boundary);
        published.check(&db, &boundary).await;
    }
    // Replacing every value makes old complete chunks zero. Their identity digests must overwrite
    // previously published nonzero grafts, even though no bitmap contribution remains.
    let zero = published
        .chunks
        .iter()
        .find(|(idx, chunk)| {
            **idx < db.bitmap().complete_chunks() as u64 && **chunk == [0; N]
        })
        .map(|(&idx, _)| idx)
        .expect("inactive complete chunk");
    let pos = F::subtree_root_position(
        Location::new(zero * (N * 8) as u64),
        grafting::height::<N>(),
    );
    let raw = db.any.log.merkle.get_node(pos).await.unwrap().unwrap();
    assert_eq!(published.nodes.get(&pos), Some(&raw));
    let root = db.root();
    let witness = db.ops_root_witness().await.unwrap();
    db = db.sync().await.unwrap();
    drop(db);
    let db = TestDb::<F, N>::init(
        ctx.child("reopen"),
        fixed_config::<OneCap>("publication"),
        None,
    )
    .await
    .unwrap();
    assert_eq!(db.root(), root);
    let reopened = db.to_batch().boundary();
    assert_eq!(reopened.witness.grafted_root, witness.grafted_root);
    assert_eq!(reopened.witness.pending_chunk_digest, witness.pending_chunk_digest);
    assert_eq!(reopened.witness.partial_chunk, witness.partial_chunk);
    published.check(&db, &reopened).await;
    db.destroy().await.unwrap();
}

#[test_traced]
fn test_publication_replays_mmr_and_mmb() {
    deterministic::Runner::default().start(|ctx| async move {
        replay::<mmr::Family, 32>(ctx.child("mmr")).await;
        replay::<mmb::Family, 32>(ctx.child("mmb")).await;
    });
}

#[test_traced]
fn test_publication_pending_chunk_becomes_graftable_without_bitmap_write() {
    deterministic::Runner::default().start(|ctx| async move {
        let mut db = TestDb::<mmb::Family, 32>::init(
            ctx.child("pending"),
            fixed_config::<OneCap>("pending"),
            None,
        )
        .await
        .unwrap();
        let mut published = Published::from_db(&db);
        let height = grafting::height::<32>();
        let chunk_root = mmb::Family::subtree_root_position(Location::new(0), height);
        let graftable_at = mmb::Family::peak_birth_size(chunk_root, height);

        // Genesis and the parent commit add two operations; two more commits reach the first graft.
        let mut batch = db.new_batch();
        for key in 0..graftable_at - 4 {
            batch = batch.write(Sha256::hash(&[&key.to_be_bytes()]), Some(Digest::from([0; 32])));
        }
        let parent = batch.merkleize(&db, None, &mut Hold).await.unwrap();
        assert_eq!(*parent.bounds().tip.size, graftable_at - 2);
        assert!(parent.ops_root_witness().pending_chunk_digest.is_some());
        assert!(parent.ops_root_witness().partial_chunk.is_some());
        let boundary = parent.boundary();
        db = db.apply_batch(Arc::clone(&parent)).await.unwrap();
        published.apply(&boundary);
        published.check(&db, &boundary).await;
        let child = parent
            .new_batch::<Sha256>()
            .merkleize(&db, None, &mut Hold)
            .await
            .unwrap();
        let transition = child
            .new_batch::<Sha256>()
            .merkleize(&db, None, &mut Hold)
            .await
            .unwrap();
        assert_eq!(*transition.bounds().tip.size, graftable_at);
        assert!(transition.ops_root_witness().pending_chunk_digest.is_none());
        let child_boundary = child.boundary();
        db = db.apply_batch(Arc::clone(&child)).await.unwrap();
        published.apply(&child_boundary);
        published.check(&db, &child_boundary).await;
        let boundary = transition.boundary();
        assert!(!boundary.chunks.iter().any(|(idx, _)| *idx == 0));
        assert_eq!(boundary.grafted_nodes.len(), 1);
        assert!(published.nodes.is_empty());
        db = db.apply_batch(transition).await.unwrap();
        published.apply(&boundary);
        published.check(&db, &boundary).await;
        db.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_publication_survives_apply_prune_and_stale_ancestors() {
    deterministic::Runner::default().start(|ctx| async move {
        let mut db = TestDb::<mmr::Family, 32>::init(
            ctx.child("lifecycle"),
            fixed_config::<OneCap>("lifecycle"),
            None,
        )
        .await
        .unwrap();
        for round in 0..4u64 {
            let mut batch = db.new_batch();
            for key in 0..256u64 {
                batch = batch.write(
                    Sha256::hash(&[&key.to_be_bytes()]),
                    Some(Sha256::hash(&[&round.to_be_bytes()])),
                );
            }
            let batch = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
            db = db.apply_batch(batch).await.unwrap();
        }
        let parent = db
            .new_batch()
            .merkleize(&db, None, &mut Proportional)
            .await
            .unwrap();
        let child = parent
            .new_batch::<Sha256>()
            .merkleize(&db, None, &mut Hold)
            .await
            .unwrap();
        let saved = child.boundary();
        let saved_parent = parent.boundary();
        let mut published = Published::from_db(&db);
        assert_eq!(saved.pruned_chunks, 0);
        db = db.apply_batch(Arc::clone(&parent)).await.unwrap();
        published.apply(&saved_parent);
        published.check(&db, &saved_parent).await;
        let boundary = db.sync_boundary();
        assert!(*boundary >= 256);
        db = db.prune(boundary).await.unwrap();
        assert!(db.bitmap().pruned_chunks() > 0);
        assert_eq!(child.boundary(), saved);
        assert_eq!(parent.boundary(), saved_parent);
        let post_prune = parent
            .new_batch::<Sha256>()
            .merkleize(&db, None, &mut Hold)
            .await
            .unwrap();
        assert_eq!(post_prune.root(), child.root());
        assert_eq!(
            post_prune.boundary().pruned_chunks,
            db.bitmap().pruned_chunks() as u64,
        );
        assert_ne!(post_prune.boundary().pruned_chunks, saved.pruned_chunks);
        assert_eq!(post_prune.ops_root_witness(), child.ops_root_witness());
        let pins = child.ops_pinned_nodes(&db).unwrap();
        assert_eq!(pins, child.inner.pinned_nodes(&db.any).unwrap());
        let post_boundary = post_prune.boundary();
        db = db.apply_batch(Arc::clone(&post_prune)).await.unwrap();
        published.apply(&post_boundary);
        published.check(&db, &post_boundary).await;
        let successor = db
            .new_batch()
            .merkleize(&db, None, &mut Hold)
            .await
            .unwrap();
        db = db.apply_batch(successor).await.unwrap();
        assert!(matches!(child.ops_pinned_nodes(&db), Err(Error::StaleRead)));
        drop(parent);
        drop(post_prune);
        db.destroy().await.unwrap();
        assert_eq!(child.boundary(), saved);
    });
}
