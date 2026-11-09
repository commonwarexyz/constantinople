//! Combined read responses carrying the evidence an explorer verifies locally.
//!
//! Each response anchors to one finalization certificate whose block matches a
//! publication target. SQL metadata supplies only hints (heights, indices,
//! locations, and digests). The client verifies every returned claim against
//! the certificate through parent headers and QMDB proofs.

use crate::{
    adapter::BoxError,
    namespaces::{
        STATE_PROOF_CHUNK_SIZE, publication_target_client, publication_target_key, simplex_client,
        sql_meta_client, state_qmdb_client, transactions_qmdb_client,
    },
    proto::{self, AccountProof, ProofBundle as Bundle, TransactionRow},
    publisher::certificate::CertifiedHeader,
    sql_schema::build_meta_schema,
};
use axum::Router;
use buffa::Message;
use bytes::Bytes;
use commonware_codec::{Decode, DecodeExt, Encode, FixedSize};
use commonware_consensus::types::Height;
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig,
    sha256::{Digest, Sha256},
};
use commonware_cryptography_curve25519::signing::VerifyingKey;
use commonware_storage::{
    merkle::{Location, mmr},
    qmdb::{
        any::{unordered, value::FixedEncoding},
        keyless,
    },
};
use commonware_utils::sequence::FixedBytes;
use connectrpc::{ConnectError, ErrorCode};
use constantinople_engine::{
    ThresholdScheme,
    types::{EngineCommitment, EngineHeader},
};
use constantinople_primitives::{
    Account, AccountKey, SignedTransaction, Transaction, TransactionHistoryEntry,
    TransactionSignature,
};
use datafusion::arrow::{
    array::{Array, BinaryArray, FixedSizeBinaryArray, UInt64Array},
    record_batch::RecordBatch,
};
use exoware_qmdb::{
    QmdbError,
    adapter::{Keyless, Unordered},
    proof::encode_operation_multi_proof,
};
use exoware_sdk::{ClientError, PrefixedStoreClient, RangeMode, ReadSession, StoreClient};
use exoware_simplex::{Finalized, keys};
use exoware_sql::SqlContext;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

mod browse;
mod rpc;

/// Maximum transactions returned on one account activity page.
const ACCOUNT_PAGE: usize = 10;

/// Maximum transactions returned on one block page.
const BLOCK_PAGE: u64 = 50;

/// Maximum parent headers linking a certificate to the requested block's parent.
const MAX_HEADERS: u64 = 4096;

/// Maximum encoded size accepted for one stored ancestor header.
const MAX_HEADER_BYTES: usize = 512;

/// Maximum encoded size accepted for one stored finalization certificate.
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;

/// Maximum encoded size of one QMDB proof in a response.
const MAX_PROOF_BYTES: usize = 1024 * 1024;

/// Largest signed transaction encoding the public codec accepts.
const MAX_TRANSACTION_BYTES: usize = Transaction::<Digest>::SIZE + TransactionSignature::MAX_SIZE;

/// Maximum encoded size of one protobuf response.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

type Header = EngineHeader<Sha256, VerifyingKey>;

/// Finalization certificate stored in the Simplex height index.
type Certificate = Finalized<
    CertifiedHeader<Sha256, VerifyingKey>,
    ThresholdScheme<VerifyingKey, MinSig>,
    EngineCommitment<Sha256, VerifyingKey>,
>;
type AccountValue = FixedBytes<{ Account::SIZE }>;
type StateLog = Unordered<
    mmr::Family,
    Sha256,
    AccountKey,
    AccountValue,
    STATE_PROOF_CHUNK_SIZE,
    FixedEncoding<AccountValue>,
>;
type HistoryEntry = TransactionHistoryEntry<Digest>;
type TransactionLog = Keyless<mmr::Family, Sha256, HistoryEntry, FixedEncoding<HistoryEntry>>;
type StateOperation = unordered::Operation<mmr::Family, AccountKey, FixedEncoding<AccountValue>>;
type TransactionOperation = keyless::Operation<mmr::Family, FixedEncoding<HistoryEntry>>;

/// Store clients shared by every explorer route.
struct Explorer {
    /// Publication targets keyed by big-endian height. The newest target bounds
    /// which certificates a response may use.
    targets: PrefixedStoreClient,
    /// Simplex certificates and headers.
    simplex: PrefixedStoreClient,
    /// Store namespace backing the SQL metadata tables.
    sql_store: PrefixedStoreClient,
    /// SQL metadata tables, read only for location and digest hints.
    sql: SqlContext,
    /// Account-state QMDB operation log.
    state: StateLog,
    /// Transaction-hash QMDB operation log.
    transactions: TransactionLog,
}

/// Builds the generated explorer application service.
pub fn router(client: &StoreClient, relayer_url: Option<&str>) -> Result<Router, BoxError> {
    rpc::router(Arc::new(Explorer::new(client)?), relayer_url)
}

impl Explorer {
    fn new(client: &StoreClient) -> Result<Self, BoxError> {
        // Register the metadata tables so hint queries resolve their table names.
        let sql_store = sql_meta_client(client)?;
        let sql = SqlContext::new(sql_store.clone());
        build_meta_schema(sql_store.clone())
            .map_err(std::io::Error::other)?
            .register_all(&sql)?;

        Ok(Self {
            targets: publication_target_client(client)?,
            simplex: simplex_client(client)?,
            sql_store,
            sql,
            state: StateLog::new(state_qmdb_client(client)?, ()),
            transactions: TransactionLog::new(transactions_qmdb_client(client)?, ()),
        })
    }
}

/// Error class shared by proof validation and the generated service.
#[derive(Debug)]
struct Failure(ErrorCode, String);

impl Failure {
    fn bad(message: impl Into<String>) -> Self {
        Self(ErrorCode::InvalidArgument, message.into())
    }

    fn pending(message: impl Into<String>) -> Self {
        Self(ErrorCode::Unavailable, message.into())
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self(ErrorCode::Internal, message.into())
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self(ErrorCode::NotFound, message.into())
    }

    fn limit(message: impl Into<String>) -> Self {
        Self(ErrorCode::ResourceExhausted, message.into())
    }
}

impl From<Failure> for ConnectError {
    fn from(error: Failure) -> Self {
        Self::new(error.0, error.1)
    }
}

/// Store client failures are retryable.
impl From<ClientError> for Failure {
    fn from(error: ClientError) -> Self {
        Self::pending(error.to_string())
    }
}

impl From<commonware_codec::Error> for Failure {
    fn from(error: commonware_codec::Error) -> Self {
        Self::invalid(error.to_string())
    }
}

impl From<QmdbError> for Failure {
    fn from(error: QmdbError) -> Self {
        // A requested location above the published QMDB watermark means
        // publication has not caught up, so it stays retryable.
        match error {
            QmdbError::Client(error) => error.into(),
            QmdbError::WatermarkTooLow { .. } => Self::pending(error.to_string()),
            _ => Self::invalid(error.to_string()),
        }
    }
}

/// Bounds a bundle before the transport encodes it.
fn response(bundle: Bundle) -> Result<Bundle, Failure> {
    if bundle.encoded_len() as usize > MAX_RESPONSE_BYTES {
        return Err(Failure::limit("aggregate response exceeds 8 MiB"));
    }
    Ok(bundle)
}

/// Validated account request.
struct AccountRequest {
    key: AccountKey,
    /// Exclusive history index at the top of this page.
    cursor: Option<Cursor>,
    /// Height and digest of the certificate shared by every page.
    snapshot: Option<(u64, Digest)>,
    /// Exact account update shared by every page.
    account_location: Option<u64>,
    activity: bool,
}

/// Exclusive account-history index encoded as eight big-endian bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Cursor(u64);

impl Cursor {
    fn parse(value: &[u8]) -> Result<Self, Failure> {
        Ok(Self(u64::from_be_bytes(fixed_bytes::<8>(value)?)))
    }

    fn encode(self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }
}

impl AccountRequest {
    fn parse(query: proto::GetAccountRequest) -> Result<Self, Failure> {
        let key = AccountKey::from(fixed_bytes::<32>(&query.account)?);
        let snapshot = match (query.at, query.digest) {
            (None, None) => None,
            (Some(height), Some(digest)) if height != 0 => {
                Some((height, Digest::from(fixed_bytes::<32>(&digest)?)))
            }
            _ => return Err(Failure::bad("positive at and digest must appear together")),
        };
        let cursor = query.cursor.as_deref().map(Cursor::parse).transpose()?;
        if (cursor.is_some() && query.account_location.is_none())
            || ((cursor.is_some() || query.account_location.is_some()) && snapshot.is_none())
        {
            return Err(Failure::bad(
                "account pages require a pinned snapshot and account location",
            ));
        }
        Ok(Self {
            key,
            cursor,
            snapshot,
            account_location: query.account_location,
            activity: query.activity.unwrap_or(true),
        })
    }
}

/// Account update and the block interval that contains it.
struct AccountEvidence {
    proof: AccountProof,
    value: Account,
    headers: Vec<Vec<u8>>,
    transaction_end: u64,
}

/// A current account value with its history boundary.
enum AccountLookup {
    Present(AccountEvidence),
}

/// Checks a fixed-width application identity or cursor before reading Store.
fn fixed_bytes<const N: usize>(value: &[u8]) -> Result<[u8; N], Failure> {
    value
        .try_into()
        .map_err(|_| Failure::bad(format!("expected {N} bytes")))
}

/// Encodes bytes as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

/// Certified snapshot that every read for one request is checked against.
struct Anchor {
    /// Encoded certificate returned to the client.
    raw: Bytes,
    /// Certified header whose roots and ranges bound every proof.
    header: Header,
    /// Read session shared by the request's Store reads, so its observed
    /// sequence covers all of them.
    session: ReadSession,
    /// SQL metadata tables read through the same session.
    sql: SqlContext,
}

/// Newest publication target and the session that observed it.
struct Published {
    /// Highest published block height.
    height: u64,
    /// Digest of the published block at that height.
    digest: Digest,
    /// Session to extend with the request's later reads.
    session: ReadSession,
}

impl Anchor {
    /// Highest Store sequence observed by the request's reads so far.
    fn floor(&self) -> Result<u64, Failure> {
        self.session
            .evaluated_sequence()
            .ok_or_else(|| Failure::invalid("Store omitted sequence metadata"))
    }

    /// Starts a bundle with the certificate and the current floor.
    fn bundle(&self) -> Result<Bundle, Failure> {
        Ok(Bundle {
            certificate: self.raw.to_vec(),
            headers: Vec::new(),
            sequence_number: self.floor()?,
            account: None.into(),
            transactions: Vec::new(),
            transactions_proof: None,
            next_cursor: None,
            ..Default::default()
        })
    }
}

impl Explorer {
    /// Reads the newest publication target, which bounds every certificate a
    /// response may use. An empty index has no published snapshot yet.
    async fn published(&self) -> Result<Option<Published>, Failure> {
        let targets = ReadSession::monotonic(self.targets.clone(), None);
        let latest = targets
            .range_with_mode(
                &Bytes::new(),
                &Bytes::from(vec![255; 9]),
                1,
                RangeMode::Reverse,
            )
            .await?;

        // Target keys are big-endian heights and values are block digests.
        let Some((key, digest)) = latest.first() else {
            return Ok(None);
        };
        let height = u64::from_be_bytes(
            key.as_ref()
                .try_into()
                .map_err(|_| Failure::invalid("invalid publication height"))?,
        );
        if height == 0 {
            return Err(Failure::invalid("invalid publication height"));
        }
        let digest = Digest::decode(digest.clone())?;
        Ok(Some(Published {
            height,
            digest,
            session: targets,
        }))
    }

    /// Selects a certificate under the newest publication target.
    async fn anchor(
        &self,
        first: u64,
        exact: Option<(u64, Digest)>,
        reverse: bool,
    ) -> Result<Anchor, Failure> {
        let published = self
            .published()
            .await?
            .ok_or_else(|| Failure::pending("publication is not ready"))?;
        self.anchor_at(&published, first, exact, reverse).await
    }

    /// Selects a finalization certificate between `first` and the publication
    /// height, or exactly at `exact`. A forward scan picks the lowest such
    /// certificate and a reverse scan picks the newest.
    async fn anchor_at(
        &self,
        published: &Published,
        first: u64,
        exact: Option<(u64, Digest)>,
        reverse: bool,
    ) -> Result<Anchor, Failure> {
        // A pinned snapshot fixes both bounds, and neither bound may pass the
        // publication boundary.
        let lower = exact.map_or(first, |(height, _)| height);
        let upper = exact.map_or(published.height, |(height, _)| height);
        if lower > published.height || upper > published.height {
            return Err(Failure::pending("requested publication is not ready"));
        }

        self.anchor_between(
            published,
            lower,
            upper,
            exact.map(|(_, digest)| digest),
            reverse,
        )
        .await?
        .ok_or_else(|| Failure::pending("finalization certificate is not ready"))
    }

    /// Selects one certificate within an inclusive published height interval.
    /// An empty interval or absent certificate leaves a live feed waiting.
    async fn anchor_between(
        &self,
        published: &Published,
        lower: u64,
        upper: u64,
        exact: Option<Digest>,
        reverse: bool,
    ) -> Result<Option<Anchor>, Failure> {
        if lower > upper {
            return Ok(None);
        }
        if upper > published.height {
            return Err(Failure::invalid("certificate bound exceeds publication"));
        }

        // Scan the Simplex height index for one certificate in the inclusive
        // bound. Appending a zero byte makes the exclusive end key include
        // `upper`.
        let session = published.session.with_client(self.simplex.clone());
        let start = keys::finalized_by_height(Height::new(lower));
        let mut end = keys::finalized_by_height(Height::new(upper)).to_vec();
        end.push(0);
        let mode = if reverse {
            RangeMode::Reverse
        } else {
            RangeMode::Forward
        };
        let rows = session
            .range_with_mode(&start, &Bytes::from(end), 1, mode)
            .await?;
        let Some((key, raw)) = rows.into_iter().next() else {
            return Ok(None);
        };
        let height = keys::finalized_height_from_key(&key)
            .ok_or_else(|| Failure::invalid("invalid certificate key"))?
            .get();

        // Bound and decode the stored certificate, then require the index key,
        // requested bound, and certified header to agree on its height.
        if raw.len() > MAX_CERTIFICATE_BYTES {
            return Err(Failure::limit("certificate exceeds 16 KiB"));
        }
        if height < lower || height > upper {
            return Err(Failure::invalid("certificate is outside requested bounds"));
        }
        let certificate = Certificate::decode_cfg(raw.clone(), &((), ()))?;
        let header = certificate.header.header().clone();
        if header.height != height || height == 0 {
            return Err(Failure::invalid("certificate height does not match index"));
        }

        // The certified block must be the published block at its height, which
        // keeps responses within the publication boundary. A pinned snapshot
        // must also name that block.
        let marker = if height == published.height {
            published.digest
        } else {
            let bytes = published
                .session
                .get(&publication_target_key(height))
                .await?
                .ok_or_else(|| Failure::pending("certificate publication is not ready"))?;
            Digest::decode(bytes)?
        };
        if marker != *header.seal() || exact.is_some_and(|digest| digest != *header.seal()) {
            return Err(Failure::invalid(
                "certificate does not match publication or requested digest",
            ));
        }

        // SQL reads join the request session, so they observe at least the
        // Store state that held the certificate.
        let sql = self
            .sql
            .with_read_session(session.with_client(self.sql_store.clone()));
        Ok(Some(Anchor {
            raw,
            header,
            session,
            sql,
        }))
    }

    /// Proves the account's value at the certified state boundary. An account with no active
    /// update there is reported as not found, without an absence proof.
    async fn account_proof(
        &self,
        anchor: &Anchor,
        request: &AccountRequest,
    ) -> Result<AccountLookup, Failure> {
        let start = anchor.header.state_range.start();
        let end = anchor.header.state_range.end();
        let tip = end
            .checked_sub(1)
            .ok_or_else(|| Failure::invalid("certified state range is empty"))?;
        let mut lookups = Box::pin(self.state.get_many_raw(
            Location::new(tip),
            &[request.key],
            Some(anchor.floor()?),
        ))
        .await?;
        if lookups.len() > 1 {
            return Err(Failure::invalid(
                "account lookup returned an invalid result count",
            ));
        }
        let (location, value, encoded, encoded_operation) = match lookups.pop() {
            None => {
                return Err(Failure::not_found(
                    "account has no update at the certified state boundary",
                ));
            }
            Some(raw) => {
                if raw.watermark.as_u64() != tip
                    || raw.root != anchor.header.state_root
                    || raw.proof.range_proof.proof.leaves.as_u64() != end
                {
                    return Err(Failure::invalid(
                        "account proof does not match certified root",
                    ));
                }
                let StateOperation::Update(update) = &raw.operation else {
                    return Err(Failure::invalid("account proof does not contain an update"));
                };
                if update.0 != request.key {
                    return Err(Failure::invalid("account proof names a different key"));
                }
                let location = raw.proof.loc.as_u64();
                if request
                    .account_location
                    .is_some_and(|pinned| pinned != location)
                {
                    return Err(Failure::pending("pinned account update is not available"));
                }
                let value = Account::decode(Bytes::copy_from_slice(update.1.as_ref()))?;
                (
                    location,
                    value,
                    raw.proof.encode().to_vec(),
                    raw.operation.encode().to_vec(),
                )
            }
        };
        bounded_proof(&encoded)?;

        // The authenticated update fixes the metadata row used for its write-height provenance.
        let query = format!(
            "SELECT qmdb_location, tx_count, write_height FROM account_meta WHERE account = X'{}' AND qmdb_location = {location} LIMIT 1",
            hex(request.key.as_ref())
        );
        let batches = query_rows(&anchor.sql, &query, 1).await?;
        let Some(batch) = batches.first() else {
            return Err(Failure::pending("account update metadata is not available"));
        };
        let metadata_location = uint(batch, 0, 0)?;
        let count = uint(batch, 1, 0)?;
        let write_height = uint(batch, 2, 0)?;
        if metadata_location != location
            || location < start
            || location >= end
            || write_height == 0
            || write_height > anchor.header.height
        {
            return Err(Failure::invalid("account metadata is outside the snapshot"));
        }

        if value.tx_count != count {
            return Err(Failure::invalid("account proof disagrees with metadata"));
        }

        // The parent's end separates this block's state appends from older
        // updates. Floor copies are included and carry their unchanged value.
        let (headers, writer, _, transaction_end) = self.ancestry(anchor, write_height).await?;
        let state_start = if write_height == 1 {
            1
        } else {
            let parent = Header::decode(Bytes::copy_from_slice(
                headers
                    .last()
                    .ok_or_else(|| Failure::invalid("account parent is missing"))?,
            ))?;
            parent.state_range.end()
        };
        if location < state_start || location >= writer.state_range.end() - 1 {
            return Err(Failure::invalid(
                "account update is outside its inclusion block",
            ));
        }
        Ok(AccountLookup::Present(AccountEvidence {
            proof: AccountProof {
                location,
                proof: encoded,
                write_height,
                claim: Some(proto::account_proof::Claim::EncodedOperation(
                    encoded_operation,
                )),
                ..Default::default()
            },
            value,
            headers,
            transaction_end,
        }))
    }

    /// Proves the complete contiguous page below the account's exclusive end.
    async fn activity(
        &self,
        anchor: &Anchor,
        request: &AccountRequest,
        account: &AccountEvidence,
    ) -> Result<(Vec<TransactionRow>, Option<Vec<u8>>, Option<Vec<u8>>), Failure> {
        let end = request
            .cursor
            .map_or(account.value.tx_count, |cursor| cursor.0);
        if end > account.value.tx_count {
            return Err(Failure::bad("cursor exceeds the proven account count"));
        }
        let lower = end.saturating_sub(ACCOUNT_PAGE as u64);
        let expected_count = (end - lower) as usize;
        let next = (lower > 0).then(|| Cursor(lower).encode());
        if expected_count == 0 {
            return Ok((Vec::new(), None, next));
        }
        let batches =
            activity_rows(&anchor.sql, request, lower, end, account.proof.write_height).await?;
        let mut hints = Vec::with_capacity(expected_count);
        for batch in &batches {
            for row in 0..batch.num_rows() {
                let index = uint(batch, 0, row)?;
                let height = uint(batch, 1, row)?;
                let block_index = uint(batch, 2, row)?;
                let role = uint(batch, 3, row)?;
                let digest = digest_at(batch, 4, row)?;
                let location = uint(batch, 5, row)?;
                if index != end - 1 - hints.len() as u64
                    || height == 0
                    || height > account.proof.write_height
                    || block_index > u64::from(u32::MAX)
                    || role > 1
                    || location >= account.transaction_end
                {
                    return Err(Failure::invalid(
                        "activity row violates account page bounds",
                    ));
                }
                hints.push((index, height, block_index, role, digest, location));
            }
        }
        if hints.len() != expected_count {
            return Err(Failure::invalid("account history page is incomplete"));
        }
        let expected = hints
            .iter()
            .map(|(_, _, _, _, digest, location)| (*location, *digest))
            .collect::<Vec<_>>();
        let (proof, entries, bodies) = self.transaction_evidence(anchor, &expected).await?;
        let mut seen = BTreeSet::new();
        let mut rows = Vec::with_capacity(expected_count);
        for (index, height, block_index, role, digest, location) in hints {
            if !seen.insert(location) {
                return Err(Failure::invalid("duplicate account transaction"));
            }
            let entry = entries[&location];
            let body = &bodies[&digest];
            let transaction = SignedTransaction::<Sha256>::decode(body.clone())?;
            let value = transaction.value();
            let sender = AccountKey::from_public_key(
                value
                    .sender()
                    .ok_or_else(|| Failure::invalid("invalid transaction sender"))?,
            );
            let recipient = value.to;
            if (sender == recipient && entry.sender_index != entry.recipient_index)
                || (role == 0 && (sender != request.key || entry.sender_index != index))
                || (role == 1
                    && (recipient != request.key
                        || sender == recipient
                        || entry.recipient_index != index))
            {
                return Err(Failure::invalid(
                    "transaction does not occupy the requested account index",
                ));
            }
            rows.push(TransactionRow {
                location,
                body: body.to_vec(),
                height,
                index: block_index as u32,
                role: Some((role as i32).into()),
                sender_index: entry.sender_index,
                recipient_index: entry.recipient_index,
                ..Default::default()
            });
        }
        Ok((rows, Some(proof), next))
    }

    /// Proves SQL-supplied (location, digest) pairs and fetches their bodies.
    /// The proven digests must equal the supplied ones exactly.
    async fn transaction_evidence(
        &self,
        anchor: &Anchor,
        expected: &[(u64, Digest)],
    ) -> Result<
        (
            Vec<u8>,
            BTreeMap<u64, HistoryEntry>,
            BTreeMap<Digest, Bytes>,
        ),
        Failure,
    > {
        // Collapse duplicate locations, rejecting two digests for one location.
        let mut locations = BTreeMap::new();
        for &(location, digest) in expected {
            if locations
                .insert(location, digest)
                .is_some_and(|previous| previous != digest)
            {
                return Err(Failure::invalid("conflicting transaction locations"));
            }
        }

        let (encoded, digests) = self
            .transaction_proof(anchor, &locations.keys().copied().collect::<Vec<_>>())
            .await?;
        if locations.len() != digests.len()
            || locations.iter().any(|(location, digest)| {
                digests
                    .get(location)
                    .is_none_or(|entry| entry.digest != *digest)
            })
        {
            return Err(Failure::invalid(
                "transaction proof disagrees with metadata",
            ));
        }
        let bodies = self
            .bodies(anchor, digests.values().map(|entry| entry.digest))
            .await?;
        Ok((encoded, digests, bodies))
    }

    /// Proves ascending `locations` against the certified transactions root and
    /// returns the encoded proof with each complete history entry.
    async fn transaction_proof(
        &self,
        anchor: &Anchor,
        locations: &[u64],
    ) -> Result<(Vec<u8>, BTreeMap<u64, HistoryEntry>), Failure> {
        // Only appends below the certified tip can hold transactions. The tip
        // itself is the block's commit operation.
        let range = &anchor.header.transactions_range;
        if locations
            .iter()
            .any(|location| *location >= range.end() - 1)
        {
            return Err(Failure::limit(
                "requested transactions are beyond the certified history",
            ));
        }

        // Request one multi-proof at the certified tip, reading QMDB at or
        // above the request floor.
        let requested = locations
            .iter()
            .copied()
            .map(Location::new)
            .collect::<Vec<_>>();
        let proof = self
            .transactions
            .operation_multi_proof(
                Location::new(range.end() - 1),
                &requested,
                Some(anchor.floor()?),
            )
            .await?;

        // The proof must verify against the certified root and cover exactly
        // the requested locations.
        if proof.ops_root != anchor.header.transactions_root
            || proof.operations.len() != locations.len()
            || !proof.verify::<Sha256>()
        {
            return Err(Failure::invalid(
                "transaction proof does not match certified root",
            ));
        }

        // Each append binds a digest and both participant indices.
        let mut digests = BTreeMap::new();
        for ((location, bytes), expected) in proof.operations.iter().zip(locations) {
            if location.as_u64() != *expected {
                return Err(Failure::invalid("transaction proof location mismatch"));
            }
            let TransactionOperation::Append(entry) =
                TransactionOperation::decode_cfg(Bytes::copy_from_slice(bytes), &())?
            else {
                return Err(Failure::invalid(
                    "requested transaction location is not an append",
                ));
            };
            digests.insert(*expected, entry);
        }

        let encoded = encode_operation_multi_proof(&proof);
        bounded_proof(&encoded)?;
        Ok((encoded.to_vec(), digests))
    }

    /// Fetches signed bodies for proven transaction digests. Bodies come from
    /// SQL, so each must decode and hash to its proven digest.
    async fn bodies(
        &self,
        anchor: &Anchor,
        digests: impl Iterator<Item = Digest>,
    ) -> Result<BTreeMap<Digest, Bytes>, Failure> {
        // Look up bodies by the digest primary key, at most one row per digest.
        let expected = digests.collect::<BTreeSet<_>>();
        let literals = expected
            .iter()
            .map(|digest| format!("X'{}'", hex(digest.as_ref())))
            .collect::<Vec<_>>()
            .join(",");
        let query = format!(
            "SELECT tx_digest, body FROM tx_meta WHERE tx_digest IN ({literals}) LIMIT {}",
            expected.len()
        );
        let batches = query_rows(&anchor.sql, &query, expected.len()).await?;

        // Accept each requested digest once, with a body that matches it.
        let mut bodies = BTreeMap::new();
        for batch in &batches {
            for row in 0..batch.num_rows() {
                let digest = digest_at(batch, 0, row)?;
                let body = array::<BinaryArray>(batch, 1, row)?.value(row);
                if !expected.contains(&digest) {
                    return Err(Failure::invalid("unexpected transaction body"));
                }
                let body = transaction_body(body, &digest)?;
                if bodies.insert(digest, body).is_some() {
                    return Err(Failure::invalid("duplicate transaction body"));
                }
            }
        }

        // A missing body means its SQL upload has not caught up.
        if bodies.len() != expected.len() {
            return Err(Failure::pending("transaction bodies are not ready"));
        }
        Ok(bodies)
    }

    /// Links the certified header down to the parent of the block at `height`.
    /// Returns the encoded parent headers, the block's header, and the block's own
    /// transaction interval [start, end).
    async fn ancestry(
        &self,
        anchor: &Anchor,
        height: u64,
    ) -> Result<(Vec<Vec<u8>>, Header, u64, u64), Failure> {
        // The chain must reach the requested block's parent, or block 1 itself,
        // within the ancestry bound.
        let lowest = height.saturating_sub(1).max(1);
        let count = anchor
            .header
            .height
            .checked_sub(lowest)
            .ok_or_else(|| Failure::invalid("certificate precedes block"))?;
        if count > MAX_HEADERS {
            return Err(Failure::limit("certificate ancestry exceeds 4096 headers"));
        }

        // The certified header may itself be the requested block.
        let mut headers = Vec::new();
        let mut current = anchor.header.clone();
        let mut block = (current.height == height).then(|| current.clone());
        if count > 0 {
            // Read one SQL digest hint per height below the certificate. Hints
            // only locate headers, since each header is verified below.
            let query = format!(
                "SELECT height, digest FROM block_meta WHERE height >= {lowest} AND height < {} ORDER BY height DESC LIMIT {count}",
                current.height
            );
            let batches = query_rows(&anchor.sql, &query, count as usize).await?;
            let mut hints = BTreeMap::new();
            for batch in &batches {
                for row in 0..batch.num_rows() {
                    let height = uint(batch, 0, row)?;
                    if height < lowest
                        || height >= current.height
                        || hints.insert(height, digest_at(batch, 1, row)?).is_some()
                    {
                        return Err(Failure::invalid("invalid ancestor metadata"));
                    }
                }
            }
            if hints.len() != count as usize {
                return Err(Failure::pending("ancestor metadata is not ready"));
            }

            // Fetch every hinted header in one batched Simplex read.
            let keys = hints
                .values()
                .map(keys::header_by_digest)
                .collect::<Vec<_>>();
            let key_refs = keys.iter().collect::<Vec<_>>();
            let raw = anchor
                .session
                .get_many(&key_refs, 128)
                .await?
                .collect()
                .await?;

            // Walk down from the certificate. Each header must have its height
            // and hinted digest, and its child must name it as both parent block
            // and consensus parent.
            for ancestor_height in (lowest..current.height).rev() {
                let digest = hints[&ancestor_height];
                let bytes = raw
                    .get(&keys::header_by_digest(&digest))
                    .ok_or_else(|| Failure::pending("ancestor header is not ready"))?;
                if bytes.len() > MAX_HEADER_BYTES {
                    return Err(Failure::limit("ancestor header exceeds 512 bytes"));
                }
                let ancestor = Header::decode(bytes.clone())?;
                if ancestor.height != ancestor_height
                    || ancestor.seal() != &digest
                    || current.parent != digest
                    || current.context.parent.1.block() != digest
                {
                    return Err(Failure::invalid("ancestor header linkage mismatch"));
                }
                if ancestor_height == height {
                    block = Some(ancestor.clone());
                }
                headers.push(bytes.to_vec());
                current = ancestor;
            }
        }

        // Block 1 has no parent header, so its interval starts after the
        // initial commit at the start of its range. Every later block starts
        // where its parent's range ends, and every interval ends before the
        // block's own commit.
        let block =
            block.ok_or_else(|| Failure::invalid("requested block is missing from ancestry"))?;
        let start = if height == 1 {
            block
                .transactions_range
                .start()
                .checked_add(1)
                .ok_or_else(|| Failure::invalid("transaction interval overflow"))?
        } else {
            current.transactions_range.end()
        };
        let end = block.transactions_range.end() - 1;
        if start > end {
            return Err(Failure::invalid("invalid own-block transaction interval"));
        }
        Ok((headers, block, start, end))
    }
}

/// Serves an account value and history page at one certified snapshot. An account with no active
/// update there is reported as not found.
async fn account(
    explorer: &Explorer,
    request: proto::GetAccountRequest,
) -> Result<Bundle, Failure> {
    let request = AccountRequest::parse(request)?;

    // Anchor to the newest certificate under the publication boundary, or to
    // the pinned snapshot.
    let anchor = explorer.anchor(1, request.snapshot, true).await?;
    let mut bundle = anchor.bundle()?;

    match explorer.account_proof(&anchor, &request).await? {
        AccountLookup::Present(account) => {
            if request.activity {
                let (transactions, proof, cursor) =
                    explorer.activity(&anchor, &request, &account).await?;
                bundle.transactions = transactions;
                bundle.transactions_proof = proof;
                bundle.next_cursor = cursor.map(proto::proof_bundle::NextCursor::ActivityCursor);
            }
            bundle.headers = account.headers;
            bundle.account = Some(account.proof).into();
        }
    }

    // Report the floor after every read, since each read can raise it.
    bundle.sequence_number = anchor.floor()?;
    response(bundle)
}

/// Serves one page of a block's transactions, proven through the lowest
/// certificate at or above the block.
async fn block(explorer: &Explorer, request: proto::GetBlockRequest) -> Result<Bundle, Failure> {
    let proto::GetBlockRequest { height, offset, .. } = request;
    if height == 0 {
        return Err(Failure::bad("height must be positive"));
    }

    // Link the lowest covering certificate down to the block's parent, which
    // fixes the block's own transaction interval.
    let anchor = explorer.anchor(height, None, false).await?;
    let (headers, _, start, end) = explorer.ancestry(&anchor, height).await?;

    // Offsets are block indices, and every returned index must fit in a `u32`.
    let count = end - start;
    if offset > count {
        return Err(Failure::bad("block offset exceeds transaction count"));
    }
    let page_end = offset.saturating_add(BLOCK_PAGE).min(count);
    if page_end > u64::from(u32::MAX) {
        return Err(Failure::limit("block index exceeds supported range"));
    }
    let mut bundle = anchor.bundle()?;
    bundle.headers = headers;

    // Prove the page's locations and fetch bodies for the proven digests.
    if offset < page_end {
        let locations = (start + offset..start + page_end).collect::<Vec<_>>();
        let (proof, digests) = explorer.transaction_proof(&anchor, &locations).await?;
        let bodies = explorer
            .bodies(&anchor, digests.values().map(|entry| entry.digest))
            .await?;
        bundle.transactions = digests
            .into_iter()
            .map(|(location, entry)| TransactionRow {
                location,
                body: bodies[&entry.digest].to_vec(),
                sender_index: entry.sender_index,
                recipient_index: entry.recipient_index,
                height,
                index: (location - start) as u32,
                role: None,
                ..Default::default()
            })
            .collect();
        bundle.transactions_proof = Some(proof);
    }

    // Return the next page's offset while transactions remain.
    bundle.next_cursor =
        (page_end < count).then_some(proto::proof_bundle::NextCursor::BlockOffset(page_end));

    // Report the floor after every read, since each read can raise it.
    bundle.sequence_number = anchor.floor()?;
    response(bundle)
}

/// Serves one transaction with its exact inclusion height and proof.
async fn transaction(
    explorer: &Explorer,
    request: proto::GetTransactionRequest,
) -> Result<Bundle, Failure> {
    let digest = Digest::from(fixed_bytes::<32>(&request.digest)?);

    // Discover the owning height under the published visibility floor, then bind
    // the location to that block's authenticated append interval.
    let published = explorer
        .published()
        .await?
        .ok_or_else(|| Failure::pending("publication is not ready"))?;
    let sql = explorer
        .sql
        .with_read_session(published.session.with_client(explorer.sql_store.clone()));
    let query = format!(
        "SELECT height, qmdb_location FROM tx_meta WHERE tx_digest = X'{}' LIMIT 1",
        hex(digest.as_ref())
    );
    let batches = query_rows(&sql, &query, 1).await?;
    let batch = batches
        .first()
        .ok_or_else(|| Failure::pending("transaction metadata is not ready"))?;
    let height = uint(batch, 0, 0)?;
    let location = uint(batch, 1, 0)?;
    if height == 0 {
        return Err(Failure::invalid("invalid transaction height"));
    }

    // The SQL height and location are hints. The certificate, ancestry, and
    // proof must confirm that the location lies in that block's interval.
    let anchor = explorer.anchor_at(&published, height, None, false).await?;
    let (headers, _, start, end) = explorer.ancestry(&anchor, height).await?;
    if location < start || location >= end {
        return Err(Failure::invalid(
            "transaction is outside its block interval",
        ));
    }
    let index = u32::try_from(location - start)
        .map_err(|_| Failure::limit("transaction index exceeds supported range"))?;

    // The proof must authenticate exactly this digest at the hinted location.
    let (proof, entries, bodies) = explorer
        .transaction_evidence(&anchor, &[(location, digest)])
        .await?;
    let mut bundle = anchor.bundle()?;
    bundle.headers = headers;
    bundle.transactions = vec![TransactionRow {
        location,
        body: bodies[&digest].to_vec(),
        height,
        index,
        role: None,
        sender_index: entries[&location].sender_index,
        recipient_index: entries[&location].recipient_index,
        ..Default::default()
    }];
    bundle.transactions_proof = Some(proof);

    // Report the floor after every read, since each read can raise it.
    bundle.sequence_number = anchor.floor()?;
    response(bundle)
}

/// Rejects an encoded proof larger than [`MAX_PROOF_BYTES`].
fn bounded_proof(bytes: &[u8]) -> Result<(), Failure> {
    if bytes.len() > MAX_PROOF_BYTES {
        return Err(Failure::limit("proof exceeds 1 MiB"));
    }
    Ok(())
}

/// Bounds and decodes a stored signed transaction, requiring its message digest
/// to equal the proven `digest`.
fn transaction_body(bytes: &[u8], digest: &Digest) -> Result<Bytes, Failure> {
    if bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(Failure::limit(
            "signed transaction exceeds codec size limit",
        ));
    }
    let bytes = Bytes::copy_from_slice(bytes);
    let transaction = SignedTransaction::<Sha256>::decode(bytes.clone())?;
    if transaction.message_digest() != digest {
        return Err(Failure::invalid("transaction body digest mismatch"));
    }
    Ok(bytes)
}

/// Reads exactly the requested account-index interval, newest first.
async fn activity_rows(
    sql: &SqlContext,
    request: &AccountRequest,
    lower: u64,
    end: u64,
    height: u64,
) -> Result<Vec<RecordBatch>, Failure> {
    let count = (end - lower) as usize;
    let query = format!(
        "SELECT account_index, height, index, role, tx_digest, qmdb_location FROM tx_activity WHERE account = X'{}' AND account_index >= {lower} AND account_index < {end} AND height <= {height} ORDER BY account_index DESC LIMIT {count}",
        hex(request.key.as_ref())
    );
    query_rows(sql, &query, count).await
}

/// Runs a SQL query, rejecting results with more than `max` rows and dropping
/// empty batches.
async fn query_rows(
    sql: &SqlContext,
    query: &str,
    max: usize,
) -> Result<Vec<RecordBatch>, Failure> {
    let batches = sql
        .sql(query)
        .await
        .map_err(sql_error)?
        .collect()
        .await
        .map_err(sql_error)?;
    let mut count = 0usize;
    let mut nonempty = Vec::new();
    for batch in batches {
        count = count
            .checked_add(batch.num_rows())
            .ok_or_else(|| Failure::invalid("SQL row count overflow"))?;
        if count > max {
            return Err(Failure::invalid("SQL query exceeded row limit"));
        }
        if batch.num_rows() > 0 {
            nonempty.push(batch);
        }
    }
    Ok(nonempty)
}

/// Maps a Store client error anywhere in the DataFusion source chain to a
/// retryable failure and anything else to invalid evidence.
fn sql_error(error: datafusion::error::DataFusionError) -> Failure {
    let mut source: &dyn std::error::Error = &error;
    loop {
        if let Some(error) = source.downcast_ref::<ClientError>() {
            return Failure::pending(error.to_string());
        }
        let Some(next) = source.source() else {
            break;
        };
        source = next;
    }
    Failure::invalid(error.to_string())
}

/// Returns a typed column, rejecting a wrong type or a missing or null value at
/// `row`.
fn array<A: Array + 'static>(
    batch: &RecordBatch,
    column: usize,
    row: usize,
) -> Result<&A, Failure> {
    let array = batch
        .columns()
        .get(column)
        .and_then(|column| column.as_any().downcast_ref::<A>())
        .ok_or_else(|| Failure::invalid("invalid SQL column type"))?;
    if row >= array.len() || array.is_null(row) {
        return Err(Failure::invalid("missing SQL value"));
    }
    Ok(array)
}

fn uint(batch: &RecordBatch, column: usize, row: usize) -> Result<u64, Failure> {
    Ok(array::<UInt64Array>(batch, column, row)?.value(row))
}

fn digest_at(batch: &RecordBatch, column: usize, row: usize) -> Result<Digest, Failure> {
    let bytes = array::<FixedSizeBinaryArray>(batch, column, row)?.value(row);
    Digest::try_from(bytes).map_err(|_| Failure::invalid("invalid SQL digest width"))
}

#[cfg(test)]
mod tests;
