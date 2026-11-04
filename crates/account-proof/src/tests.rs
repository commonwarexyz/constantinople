use super::*;
use commonware_codec::Encode;
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig,
    merkle::{Location, full::Config as MerkleConfig},
    qmdb::{current::ordered::fixed::Db, floor::Proportional},
    translator::TwoCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use constantinople_primitives::Nonce;

type TestDb = Db<
    mmr::Family,
    deterministic::Context,
    AccountKey,
    Account,
    Sha256,
    TwoCap,
    ACCOUNT_CHUNK_BYTES,
    Sequential,
>;

fn key(value: u64) -> AccountKey {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    AccountKey::decode(Copying(&bytes)).unwrap()
}

const fn account(value: u64) -> Account {
    Account {
        balance: value,
        nonce: Nonce::new(value + 1, value + 2),
        tx_count: value + 3,
    }
}

async fn database(context: deterministic::Context) -> TestDb {
    let page_cache = CacheRef::new(NZU16!(88), NZUsize!(8));
    TestDb::init(
        context,
        commonware_storage::qmdb::current::Config {
            merkle_config: MerkleConfig {
                journal_partition: "proof-merkle".into(),
                metadata_partition: "proof-merkle-meta".into(),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            journal_config: JournalConfig {
                partition: "proof-operations".into(),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            grafted_metadata_partition: "proof-grafted-meta".into(),
            translator: TwoCap,
            init_cache: None,
            init_buffer: NZUsize!(4096),
            init_concurrency: (),
        },
        None,
    )
    .await
    .unwrap()
}

async fn write(db: TestDb, entries: &[(AccountKey, Option<Account>)]) -> TestDb {
    let mut batch = db.new_batch();
    for &(key, value) in entries {
        batch = batch.write(key, value);
    }
    let batch = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
    db.apply_batch(batch).await.unwrap()
}

struct Lookup {
    proof: Vec<u8>,
    root: Vec<u8>,
    key: Vec<u8>,
    tip: u64,
    operation: Option<Vec<u8>>,
}

impl Lookup {
    fn verify(&self) -> Result<VerifiedAccountLookup, Error> {
        self.verify_bytes(&self.proof)
    }

    /// The verified absence as (key, bracketing span), checking the excluding operation sits
    /// within the certified boundary.
    fn absent(&self) -> Result<(AccountKey, Option<(AccountKey, AccountKey)>), Error> {
        match self.verify()? {
            VerifiedAccountLookup::Absent {
                key,
                location,
                span,
            } => {
                assert!(location <= self.tip);
                Ok((key, span))
            }
            present => panic!("expected absence, got {present:?}"),
        }
    }

    fn verify_bytes(&self, proof: &[u8]) -> Result<VerifiedAccountLookup, Error> {
        verify_current_account_lookup(
            proof,
            &self.root,
            &self.key,
            self.tip,
            self.operation.clone(),
            self.operation.is_none(),
        )
    }
}

async fn inclusion(db: &TestDb, requested: AccountKey) -> Lookup {
    let proof = db.key_value_proof(requested).await.unwrap();
    let (_, update) = db.get_span(&requested).await.unwrap().unwrap();
    Lookup {
        proof: proof.proof.encode().to_vec(),
        root: db.root().as_ref().to_vec(),
        key: requested.as_ref().to_vec(),
        tip: db.bounds().end.as_u64() - 1,
        operation: Some(AccountOperation::Update(update).encode().to_vec()),
    }
}

async fn exclusion(db: &TestDb, requested: AccountKey) -> Lookup {
    Lookup {
        proof: db
            .exclusion_proof(&requested)
            .await
            .unwrap()
            .encode()
            .to_vec(),
        root: db.root().as_ref().to_vec(),
        key: requested.as_ref().to_vec(),
        tip: db.bounds().end.as_u64() - 1,
        operation: None,
    }
}

#[test]
fn inclusion_rejects_wrong_context_and_malformed_encodings() {
    deterministic::Runner::default().start(|context| async move {
        let db = write(database(context).await, &[(key(10), Some(account(7)))]).await;
        let mut lookup = inclusion(&db, key(10)).await;
        assert!(matches!(
            lookup.verify().unwrap(),
            VerifiedAccountLookup::Present { key: found, account: value, .. }
                if found == key(10) && value == account(7)
        ));
        assert_eq!(lookup.operation.as_ref().unwrap().len(), 97);
        for end in 0..lookup.proof.len() {
            assert!(lookup.verify_bytes(&lookup.proof[..end]).is_err());
        }
        let mut trailing = lookup.proof.clone();
        trailing.push(0);
        assert_eq!(lookup.verify_bytes(&trailing), Err(Error::InvalidEncoding));
        assert_eq!(
            lookup.verify_bytes(&vec![0; MAX_PROOF_BYTES + 1]),
            Err(Error::ProofTooLarge)
        );

        lookup.key = key(11).as_ref().to_vec();
        assert_eq!(lookup.verify(), Err(Error::WrongAccount));
        lookup.key = key(10).as_ref().to_vec();
        lookup.tip += 1;
        assert_eq!(lookup.verify(), Err(Error::WrongBoundary));
        lookup.tip -= 1;
        lookup.root[0] ^= 1;
        assert_eq!(lookup.verify(), Err(Error::VerificationFailed));
        lookup.root[0] ^= 1;

        assert_eq!(
            verify_current_account_lookup(
                &lookup.proof,
                &lookup.root,
                &lookup.key,
                lookup.tip,
                lookup.operation.clone(),
                true
            ),
            Err(Error::InvalidClaim)
        );
        assert_eq!(
            verify_current_account_lookup(
                &lookup.proof,
                &lookup.root,
                &lookup.key,
                lookup.tip,
                None,
                false
            ),
            Err(Error::InvalidClaim)
        );
        assert_eq!(
            verify_current_account_lookup(
                &lookup.proof,
                &lookup.root,
                &lookup.key,
                u64::MAX,
                lookup.operation.clone(),
                false
            ),
            Err(Error::WrongBoundary)
        );
        assert!(
            verify_current_account_lookup(
                &lookup.proof,
                &lookup.root[..31],
                &lookup.key,
                lookup.tip,
                lookup.operation.clone(),
                false
            )
            .is_err()
        );
        let mut trailing_root = lookup.root.clone();
        trailing_root.push(0);
        assert!(
            verify_current_account_lookup(
                &lookup.proof,
                &trailing_root,
                &lookup.key,
                lookup.tip,
                lookup.operation.clone(),
                false
            )
            .is_err()
        );
        assert!(
            verify_current_account_lookup(
                &lookup.proof,
                &lookup.root,
                &lookup.key[..31],
                lookup.tip,
                lookup.operation.clone(),
                false
            )
            .is_err()
        );
        let mut trailing_key = lookup.key.clone();
        trailing_key.push(0);
        assert!(
            verify_current_account_lookup(
                &lookup.proof,
                &lookup.root,
                &trailing_key,
                lookup.tip,
                lookup.operation.clone(),
                false
            )
            .is_err()
        );

        let operation = lookup.operation.as_mut().unwrap();
        operation[33] ^= 1;
        assert_eq!(lookup.verify(), Err(Error::VerificationFailed));
        lookup.operation.as_mut().unwrap()[33] ^= 1;
        lookup.operation.as_mut().unwrap()[65] ^= 1;
        assert_eq!(lookup.verify(), Err(Error::VerificationFailed));
        lookup.operation.as_mut().unwrap()[65] ^= 1;
        let mut proof = AccountOperationProof::decode_cfg(Copying(&lookup.proof), &122).unwrap();
        let bit = proof.loc.as_u64() % (ACCOUNT_CHUNK_BYTES as u64 * 8);
        proof.chunk[(bit / 8) as usize] &= !(1 << (bit % 8));
        assert_eq!(
            lookup.verify_bytes(&proof.encode()),
            Err(Error::VerificationFailed)
        );
        let mut proof = AccountOperationProof::decode_cfg(Copying(&lookup.proof), &122).unwrap();
        let other_bit = (bit + 1) % (ACCOUNT_CHUNK_BYTES as u64 * 8);
        proof.chunk[(other_bit / 8) as usize] ^= 1 << (other_bit % 8);
        assert_eq!(
            lookup.verify_bytes(&proof.encode()),
            Err(Error::VerificationFailed)
        );
        let mut proof = AccountOperationProof::decode_cfg(Copying(&lookup.proof), &122).unwrap();
        proof.range_proof.proof.inactive_peaks = usize::MAX;
        assert_eq!(
            lookup.verify_bytes(&proof.encode()),
            Err(Error::VerificationFailed)
        );
        let mut proof = AccountOperationProof::decode_cfg(Copying(&lookup.proof), &122).unwrap();
        proof.range_proof.ops_root = Digest::decode(Copying(&[0; 32])).unwrap();
        assert_eq!(
            lookup.verify_bytes(&proof.encode()),
            Err(Error::VerificationFailed)
        );
        proof.range_proof.proof.digests.resize(
            MAX_PROOF_DIGESTS_PER_ELEMENT + 1,
            proof.range_proof.ops_root,
        );
        assert_eq!(
            lookup.verify_bytes(&proof.encode()),
            Err(Error::InvalidEncoding)
        );

        let delete = AccountOperation::Delete(key(10)).encode().to_vec();
        lookup.operation = Some(delete.clone());
        assert_eq!(lookup.verify(), Err(Error::WrongAccount));
        let mut bad_padding = delete;
        *bad_padding.last_mut().unwrap() = 1;
        lookup.operation = Some(bad_padding);
        assert_eq!(lookup.verify(), Err(Error::InvalidEncoding));
        lookup.operation = Some(
            AccountOperation::CommitFloor(None, Location::new(0))
                .encode()
                .to_vec(),
        );
        assert_eq!(lookup.verify(), Err(Error::WrongAccount));
        db.destroy().await.unwrap();
    });
}

#[test]
fn exclusion_authenticates_cyclic_spans_singletons_and_empty_databases() {
    deterministic::Runner::default().start(|context| async move {
        let mut db = database(context).await;
        let empty = exclusion(&db, key(10)).await;
        assert_eq!(empty.absent(), Ok((key(10), None)));
        assert_eq!(empty.proof[0], 1);
        for end in 0..empty.proof.len() {
            assert!(empty.verify_bytes(&empty.proof[..end]).is_err());
        }
        let mut invalid_tag = empty.proof.clone();
        invalid_tag[0] = 2;
        assert_eq!(
            empty.verify_bytes(&invalid_tag),
            Err(Error::InvalidEncoding)
        );
        let mut trailing = empty.proof.clone();
        trailing.push(0);
        assert_eq!(empty.verify_bytes(&trailing), Err(Error::InvalidEncoding));

        let batch = db
            .new_batch()
            .merkleize(&db, Some(account(99)), &mut Proportional)
            .await
            .unwrap();
        db = db.apply_batch(batch).await.unwrap();
        let metadata = exclusion(&db, key(10)).await;
        assert_eq!(metadata.absent(), Ok((key(10), None)));

        db = write(db, &[(key(10), Some(account(1)))]).await;
        let singleton = exclusion(&db, key(20)).await;
        assert_eq!(singleton.absent(), Ok((key(20), Some((key(10), key(10))))));
        assert_eq!(singleton.proof[0], 0);
        assert!(
            verify_current_account_lookup(
                &singleton.proof,
                &singleton.root,
                key(10).as_ref(),
                singleton.tip,
                None,
                true
            )
            .is_err()
        );

        db = write(db, &[(key(30), Some(account(2)))]).await;
        for (missing, lower, upper) in [(0, 30, 10), (20, 10, 30), (40, 30, 10)] {
            let lookup = exclusion(&db, key(missing)).await;
            assert_eq!(
                lookup.absent(),
                Ok((key(missing), Some((key(lower), key(upper)))))
            );
            for endpoint in [10, 30] {
                assert!(
                    verify_current_account_lookup(
                        &lookup.proof,
                        &lookup.root,
                        key(endpoint).as_ref(),
                        lookup.tip,
                        None,
                        true
                    )
                    .is_err()
                );
            }
        }

        let mut span = exclusion(&db, key(20)).await;
        let mut decoded =
            AccountExclusionProof::decode_cfg(Copying(&span.proof), &(122, (), ())).unwrap();
        let AccountExclusionProof::KeyValue(_, update) = &mut decoded else {
            panic!("expected a key span")
        };
        update.next_key = key(40);
        assert_eq!(
            span.verify_bytes(&decoded.encode()),
            Err(Error::VerificationFailed)
        );
        span.root = empty.root;
        assert_eq!(span.verify(), Err(Error::VerificationFailed));

        db = write(db, &[(key(10), None), (key(30), None)]).await;
        let deleted = exclusion(&db, key(10)).await;
        assert_eq!(deleted.proof[0], 1);
        assert_eq!(deleted.absent(), Ok((key(10), None)));
        db.destroy().await.unwrap();
    });
}

#[test]
fn captured_proofs_remain_bound_to_their_historical_root_across_bitmap_chunks() {
    deterministic::Runner::default().start(|context| async move {
        let entries = (0..300)
            .map(|i| (key(i * 2), Some(account(i))))
            .collect::<Vec<_>>();
        let mut db = write(database(context).await, &entries).await;
        assert!(db.bounds().end.as_u64() > 256);
        let mut old = inclusion(&db, key(20)).await;
        let old_location = AccountOperationProof::decode_cfg(Copying(&old.proof), &122)
            .unwrap()
            .loc;
        let old_miss = exclusion(&db, key(21)).await;
        assert!(old.verify().is_ok());
        assert!(old_miss.verify().is_ok());
        db = write(
            db,
            &[(key(20), Some(account(999))), (key(21), Some(account(42)))],
        )
        .await;
        let (range_proof, operations, chunks) =
            db.range_proof(old_location, NZU64!(1)).await.unwrap();
        assert!(range_proof.verify::<Sha256, _, ACCOUNT_CHUNK_BYTES>(
            old_location,
            &operations,
            &chunks,
            &db.root(),
        ));
        let inactive = AccountOperationProof {
            loc: old_location,
            chunk: chunks[0],
            range_proof,
        };
        let current_tip = db.bounds().end.as_u64() - 1;
        assert_eq!(
            verify_current_account_lookup(
                &inactive.encode(),
                db.root().as_ref(),
                key(20).as_ref(),
                current_tip,
                Some(operations[0].encode().to_vec()),
                false,
            ),
            Err(Error::VerificationFailed)
        );
        let AccountOperation::Update(update) = &operations[0] else {
            panic!("expected the historical account update")
        };
        let stale_span = AccountExclusionProof::KeyValue(inactive, update.clone());
        assert_eq!(
            verify_current_account_lookup(
                &stale_span.encode(),
                db.root().as_ref(),
                key(21).as_ref(),
                current_tip,
                None,
                true,
            ),
            Err(Error::VerificationFailed)
        );
        assert!(old.verify().is_ok());
        assert!(old_miss.verify().is_ok());
        let current = inclusion(&db, key(20)).await;
        let original_root = old.root.clone();
        old.root.clone_from(&current.root);
        assert_eq!(old.verify(), Err(Error::VerificationFailed));
        old.tip = current.tip;
        assert_eq!(old.verify(), Err(Error::WrongBoundary));
        assert!(
            verify_current_account_lookup(
                &old_miss.proof,
                &current.root,
                &old_miss.key,
                old_miss.tip,
                None,
                true
            )
            .is_err()
        );
        assert_ne!(current.root, original_root);
        assert!(current.verify().is_ok());
        db.destroy().await.unwrap();
    });
}
