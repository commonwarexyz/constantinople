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
    publisher::certificate::CertifiedHeader,
    sql_schema::build_meta_schema,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::get,
};
use bytes::Bytes;
use commonware_codec::{Decode, DecodeExt, FixedSize};
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
use constantinople_engine::{
    ThresholdScheme,
    types::{EngineCommitment, EngineHeader},
};
use constantinople_primitives::{
    Account, AccountKey, SignedTransaction, Transaction, TransactionSignature,
};
use datafusion::arrow::{
    array::{Array, BinaryArray, FixedSizeBinaryArray, UInt64Array},
    record_batch::RecordBatch,
};
use exoware_qmdb::{
    QmdbError,
    adapter::{Keyless, Unordered},
    proof::{encode_historical_multi_proof, encode_historical_operation_range_proof},
};
use exoware_sdk::{ClientError, PrefixedStoreClient, RangeMode, ReadSession, StoreClient};
use exoware_simplex::{Finalized, keys};
use exoware_sql::SqlContext;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

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

/// Maximum serialized size of one JSON response.
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
type TransactionLog = Keyless<mmr::Family, Sha256, Digest, FixedEncoding<Digest>>;
type StateOperation = unordered::Operation<mmr::Family, AccountKey, FixedEncoding<AccountValue>>;
type TransactionOperation = keyless::Operation<mmr::Family, FixedEncoding<Digest>>;

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

/// Build the bounded account, block, and transaction evidence routes.
pub fn router(client: &StoreClient) -> Result<Router, BoxError> {
    // Register the metadata tables so hint queries resolve their table names.
    let sql_store = sql_meta_client(client)?;
    let sql = SqlContext::new(sql_store.clone());
    build_meta_schema(sql_store.clone())
        .map_err(std::io::Error::other)?
        .register_all(&sql)?;

    // Every route reads through the same Store clients.
    let state = Arc::new(Explorer {
        targets: publication_target_client(client)?,
        simplex: simplex_client(client)?,
        sql_store,
        sql,
        state: StateLog::new(state_qmdb_client(client)?, ()),
        transactions: TransactionLog::new(transactions_qmdb_client(client)?, ()),
    });
    Ok(Router::new()
        .route("/explorer/accounts/{account}", get(account))
        .route("/explorer/blocks/{height}", get(block))
        .route("/explorer/transactions/{digest}", get(transaction))
        .with_state(state))
}

/// JSON response body shared by every explorer route.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Bundle {
    /// Hex finalization certificate that anchors every proof in the bundle.
    certificate: String,
    /// Hex parent headers, newest first, from below the certified header down
    /// to the requested block's parent.
    headers: Vec<String>,
    /// Store sequence floor covering every read behind the bundle.
    sequence_number: String,
    /// Proof of the account's latest update, on account routes.
    account: Option<AccountProof>,
    /// Returned transactions in page order.
    transactions: Vec<TransactionRow>,
    /// Hex multi-proof of every returned transaction against the certified
    /// transactions root, present when any transaction is returned.
    transactions_proof: Option<String>,
    /// Hex activity cursor or decimal block offset of the next page.
    next_cursor: Option<String>,
}

/// Proof of an account's latest update within the certified state range.
#[derive(Serialize)]
struct AccountProof {
    /// Account-state QMDB location of the update.
    location: String,
    /// Hex operation range proof for that location.
    proof: String,
}

/// One transaction with its proven QMDB location and signed body.
#[derive(Serialize)]
struct TransactionRow {
    /// Transaction-hash QMDB location covered by the bundle's proof.
    location: String,
    /// Hex signed transaction whose digest the proof authenticates.
    body: String,
    /// Block height, which is an unproven SQL hint on account rows.
    height: String,
    /// Index within the block, which is an unproven SQL hint on account rows.
    index: u32,
    /// Account role (0 sender, 1 receiver), present only on account rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<u8>,
}

/// Error response carrying the HTTP status of its failure class.
#[derive(Debug)]
struct Failure(StatusCode, String);

impl Failure {
    /// Malformed request.
    fn bad(message: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, message.into())
    }

    /// Publication or evidence that can appear once uploads catch up.
    fn pending(message: impl Into<String>) -> Self {
        Self(StatusCode::SERVICE_UNAVAILABLE, message.into())
    }

    /// Stored evidence that contradicts itself or the certified snapshot.
    fn invalid(message: impl Into<String>) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, message.into())
    }

    /// Valid request whose work exceeds the supported bounds.
    fn limit(message: impl Into<String>) -> Self {
        Self(StatusCode::UNPROCESSABLE_ENTITY, message.into())
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({"error": self.1}))).into_response()
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

/// Serializes a bundle, rejecting responses larger than [`MAX_RESPONSE_BYTES`].
fn response(bundle: Bundle) -> Result<Response, Failure> {
    let bytes = serde_json::to_vec(&bundle).map_err(|error| Failure::invalid(error.to_string()))?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(Failure::limit("aggregate response exceeds 8 MiB"));
    }
    Ok(([(CONTENT_TYPE, "application/json")], bytes).into_response())
}

/// Raw account query parameters, validated by [`AccountRequest::parse`].
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountQuery {
    mode: Option<String>,
    cursor: Option<String>,
    at: Option<String>,
    digest: Option<String>,
    activity: Option<String>,
}

/// Raw block query parameters.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockQuery {
    offset: Option<String>,
}

/// Validated account request.
struct AccountRequest {
    /// Account whose state and activity are read.
    key: AccountKey,
    /// Role filter (0 sent, 1 received), or `None` for all activity.
    mode: Option<u8>,
    /// Last row of the previous page, which this page excludes.
    cursor: Option<Cursor>,
    /// Height and digest that pin the certified snapshot across pages.
    snapshot: Option<(u64, Digest)>,
    /// Whether to return an activity page.
    activity: bool,
}

/// Position in an account's activity, encoded as 24 big-endian bytes.
///
/// Pages run newest first in the derived (height, index, role) order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Cursor {
    height: u64,
    index: u64,
    role: u64,
}

impl Cursor {
    fn parse(value: &str) -> Result<Self, Failure> {
        let bytes = hex_bytes::<24>(value)?;
        let cursor = Self {
            height: u64::from_be_bytes(bytes[..8].try_into().unwrap()),
            index: u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            role: u64::from_be_bytes(bytes[16..].try_into().unwrap()),
        };

        // Reject positions that no activity row can occupy.
        if cursor.height == 0 || cursor.index > u64::from(u32::MAX) || cursor.role > 1 {
            return Err(Failure::bad("invalid activity cursor"));
        }
        Ok(cursor)
    }

    fn encode(self) -> String {
        let mut bytes = [0; 24];
        bytes[..8].copy_from_slice(&self.height.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.index.to_be_bytes());
        bytes[16..].copy_from_slice(&self.role.to_be_bytes());
        hex(&bytes)
    }
}

impl AccountRequest {
    fn parse(account: &str, query: AccountQuery) -> Result<Self, Failure> {
        let key = AccountKey::from(hex_bytes::<32>(account)?);
        let mode = match query.mode.as_deref().unwrap_or("all") {
            "all" => None,
            "sent" => Some(0),
            "received" => Some(1),
            _ => return Err(Failure::bad("mode must be all, sent, or received")),
        };
        let snapshot = match (query.at, query.digest) {
            (None, None) => None,
            (Some(height), Some(digest)) => {
                Some((positive(&height)?, Digest::from(hex_bytes::<32>(&digest)?)))
            }
            _ => return Err(Failure::bad("at and digest must appear together")),
        };
        let cursor = query.cursor.as_deref().map(Cursor::parse).transpose()?;

        // A filtered page continues only from a cursor with the same role.
        if cursor.is_some_and(|cursor| mode.is_some_and(|role| cursor.role != u64::from(role))) {
            return Err(Failure::bad("cursor role does not match mode"));
        }
        let activity = match query.activity.as_deref() {
            None | Some("true") => true,
            Some("false") => false,
            _ => return Err(Failure::bad("activity must be true or false")),
        };
        Ok(Self {
            key,
            mode,
            cursor,
            snapshot,
            activity,
        })
    }
}

/// Parses a canonical decimal `u64`, rejecting the leading `+` that
/// [`str::parse`] accepts.
fn decimal(value: &str) -> Result<u64, Failure> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Failure::bad("expected decimal u64"));
    }
    value
        .parse()
        .map_err(|_| Failure::bad("decimal u64 overflow"))
}

/// Parses a decimal height, rejecting zero.
fn positive(value: &str) -> Result<u64, Failure> {
    let value = decimal(value)?;
    if value == 0 {
        return Err(Failure::bad("height must be positive"));
    }
    Ok(value)
}

/// Decodes exactly `N` bytes from hex digits of either case.
fn hex_bytes<const N: usize>(value: &str) -> Result<[u8; N], Failure> {
    if value.len() != N * 2 {
        return Err(Failure::bad(format!("expected {} hex characters", N * 2)));
    }
    let mut bytes = [0; N];
    for (pair, output) in value.as_bytes().chunks_exact(2).zip(bytes.iter_mut()) {
        let digit = |byte: u8| (byte as char).to_digit(16).map(|value| value as u8);
        *output = digit(pair[0])
            .zip(digit(pair[1]))
            .map(|(high, low)| high * 16 + low)
            .ok_or_else(|| Failure::bad("invalid hex"))?;
    }
    Ok(bytes)
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
            certificate: hex(&self.raw),
            headers: Vec::new(),
            sequence_number: self.floor()?.to_string(),
            account: None,
            transactions: Vec::new(),
            transactions_proof: None,
            next_cursor: None,
        })
    }
}

impl Explorer {
    /// Reads the newest publication target, which bounds every certificate a
    /// response may use.
    async fn published(&self) -> Result<Published, Failure> {
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
        let (key, digest) = latest
            .first()
            .ok_or_else(|| Failure::pending("publication is not ready"))?;
        let height = u64::from_be_bytes(
            key.as_ref()
                .try_into()
                .map_err(|_| Failure::invalid("invalid publication height"))?,
        );
        if height == 0 {
            return Err(Failure::invalid("invalid publication height"));
        }
        let digest = Digest::decode(digest.clone())?;
        Ok(Published {
            height,
            digest,
            session: targets,
        })
    }

    /// Selects a certificate under the newest publication target.
    async fn anchor(
        &self,
        first: u64,
        exact: Option<(u64, Digest)>,
        reverse: bool,
    ) -> Result<Anchor, Failure> {
        self.anchor_at(&self.published().await?, first, exact, reverse)
            .await
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
        let (key, raw) = rows
            .into_iter()
            .next()
            .ok_or_else(|| Failure::pending("finalization certificate is not ready"))?;
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
        if marker != *header.seal() || exact.is_some_and(|(_, digest)| digest != *header.seal()) {
            return Err(Failure::invalid(
                "certificate does not match publication or requested digest",
            ));
        }

        // SQL reads join the request session, so they observe at least the
        // Store state that held the certificate.
        let sql = self
            .sql
            .with_read_session(session.with_client(self.sql_store.clone()));
        Ok(Anchor {
            raw,
            header,
            session,
            sql,
        })
    }

    /// Proves the account's latest update inside the certified state range, or
    /// returns `None` when SQL holds no such update.
    async fn account_proof(
        &self,
        anchor: &Anchor,
        key: &AccountKey,
    ) -> Result<Option<AccountProof>, Failure> {
        // SQL supplies only a candidate location, which the proof below must
        // bind to the certified state root.
        let start = anchor.header.state_range.start();
        let end = anchor.header.state_range.end();
        let query = format!(
            "SELECT qmdb_location FROM account_meta WHERE account = X'{}' AND qmdb_location >= {start} AND qmdb_location < {end} ORDER BY qmdb_location DESC LIMIT 1",
            hex(key.as_ref())
        );
        let batches = query_rows(&anchor.sql, &query, 1).await?;
        let Some(batch) = batches.first() else {
            return Ok(None);
        };
        let location = uint(batch, 0, 0)?;
        if location < start || location >= end {
            return Err(Failure::invalid(
                "account location is outside certified range",
            ));
        }

        // Prove that location at the certified tip, reading QMDB at or above
        // the request floor.
        let proof = self
            .state
            .operation_range_checkpoint(
                Location::new(end - 1),
                Location::new(location),
                1,
                Some(anchor.floor()?),
            )
            .await?;

        // The proof must reproduce the certified root and contain exactly one
        // operation, an update of the requested account.
        if proof.canonical_root::<Sha256>() != anchor.header.state_root
            || proof.encoded_operations.len() != 1
        {
            return Err(Failure::invalid(
                "account proof does not match certified root",
            ));
        }
        let operation =
            StateOperation::decode_cfg(Bytes::copy_from_slice(&proof.encoded_operations[0]), &())?;
        if !matches!(operation, StateOperation::Update(update) if update.0 == *key) {
            return Err(Failure::invalid(
                "account proof does not contain requested update",
            ));
        }

        let encoded = encode_historical_operation_range_proof(&proof);
        bounded_proof(&encoded)?;
        Ok(Some(AccountProof {
            location: location.to_string(),
            proof: hex(&encoded),
        }))
    }

    /// Returns one activity page with its multi-proof and the next cursor.
    async fn activity(
        &self,
        anchor: &Anchor,
        request: &AccountRequest,
    ) -> Result<(Vec<TransactionRow>, Option<String>, Option<String>), Failure> {
        // SQL rows are untrusted hints. Each must lie within the certified
        // height, match the filter, follow the request cursor, and strictly
        // descend, so a page cannot repeat or reorder rows.
        let height = anchor.header.height;
        let batches = activity_rows(&anchor.sql, request, height).await?;
        let mut hints = Vec::new();
        for batch in &batches {
            for row in 0..batch.num_rows() {
                let cursor = Cursor {
                    height: uint(batch, 0, row)?,
                    index: uint(batch, 1, row)?,
                    role: uint(batch, 2, row)?,
                };
                let digest = digest_at(batch, 3, row)?;
                let location = uint(batch, 4, row)?;
                if cursor.height == 0
                    || cursor.height > height
                    || cursor.index > u64::from(u32::MAX)
                    || cursor.role > 1
                    || request
                        .mode
                        .is_some_and(|role| u64::from(role) != cursor.role)
                    || request.cursor.is_some_and(|bound| cursor >= bound)
                    || hints
                        .last()
                        .is_some_and(|(previous, _, _)| *previous <= cursor)
                {
                    return Err(Failure::invalid("activity row violates page bounds"));
                }
                hints.push((cursor, digest, location));
            }
        }

        // The extra row only signals another page. The next cursor is the
        // last returned row, which the following page excludes.
        let next = if hints.len() > ACCOUNT_PAGE {
            hints[ACCOUNT_PAGE - 1].0.encode().into()
        } else {
            None
        };
        hints.truncate(ACCOUNT_PAGE);
        if hints.is_empty() {
            return Ok((Vec::new(), None, next));
        }

        // The proof binds each location to its digest. Heights and indices
        // remain hints because no proof covers them.
        let expected = hints
            .iter()
            .map(|(_, digest, location)| (*location, *digest))
            .collect::<Vec<_>>();
        let (proof, bodies) = self.transaction_evidence(anchor, &expected).await?;
        let rows = hints
            .into_iter()
            .map(|(cursor, digest, location)| TransactionRow {
                location: location.to_string(),
                body: hex(&bodies[&digest]),
                height: cursor.height.to_string(),
                index: cursor.index as u32,
                role: Some(cursor.role as u8),
            })
            .collect();
        Ok((rows, Some(proof), next))
    }

    /// Proves SQL-supplied (location, digest) pairs and fetches their bodies.
    /// The proven digests must equal the supplied ones exactly.
    async fn transaction_evidence(
        &self,
        anchor: &Anchor,
        expected: &[(u64, Digest)],
    ) -> Result<(String, BTreeMap<Digest, Bytes>), Failure> {
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
        if locations != digests {
            return Err(Failure::invalid(
                "transaction proof disagrees with metadata",
            ));
        }
        let bodies = self.bodies(anchor, digests.values().copied()).await?;
        Ok((encoded, bodies))
    }

    /// Proves ascending `locations` against the certified transactions root and
    /// returns the encoded proof with each proven digest.
    async fn transaction_proof(
        &self,
        anchor: &Anchor,
        locations: &[u64],
    ) -> Result<(String, BTreeMap<u64, Digest>), Failure> {
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

        // Each proven operation must be an append, whose value is the
        // transaction digest.
        let mut digests = BTreeMap::new();
        for ((location, bytes), expected) in proof.operations.iter().zip(locations) {
            if location.as_u64() != *expected {
                return Err(Failure::invalid("transaction proof location mismatch"));
            }
            let TransactionOperation::Append(digest) =
                TransactionOperation::decode_cfg(Bytes::copy_from_slice(bytes), &())?
            else {
                return Err(Failure::invalid(
                    "requested transaction location is not an append",
                ));
            };
            digests.insert(*expected, digest);
        }

        let encoded = encode_historical_multi_proof(&proof);
        bounded_proof(&encoded)?;
        Ok((hex(&encoded), digests))
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
    /// Returns the hex parent headers, the block's header, and the block's own
    /// transaction interval [start, end).
    async fn ancestry(
        &self,
        anchor: &Anchor,
        height: u64,
    ) -> Result<(Vec<String>, Header, u64, u64), Failure> {
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
                headers.push(hex(bytes));
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

/// Serves an account's latest proven update and one activity page under a
/// single certified snapshot.
async fn account(
    State(explorer): State<Arc<Explorer>>,
    Path(account): Path<String>,
    Query(query): Query<AccountQuery>,
) -> Result<Response, Failure> {
    let request = AccountRequest::parse(&account, query)?;

    // Anchor to the newest certificate under the publication boundary, or to
    // the pinned snapshot.
    let anchor = explorer.anchor(1, request.snapshot, true).await?;
    let mut bundle = anchor.bundle()?;

    // Prove the account update and the activity page against the same anchor.
    let (account, activity) =
        tokio::try_join!(explorer.account_proof(&anchor, &request.key), async {
            if request.activity {
                explorer.activity(&anchor, &request).await
            } else {
                Ok((Vec::new(), None, None))
            }
        },)?;
    bundle.account = account;
    (
        bundle.transactions,
        bundle.transactions_proof,
        bundle.next_cursor,
    ) = activity;

    // Report the floor after every read, since each read can raise it.
    bundle.sequence_number = anchor.floor()?.to_string();
    response(bundle)
}

/// Serves one page of a block's transactions, proven through the lowest
/// certificate at or above the block.
async fn block(
    State(explorer): State<Arc<Explorer>>,
    Path(height): Path<String>,
    Query(query): Query<BlockQuery>,
) -> Result<Response, Failure> {
    let height = positive(&height)?;
    let offset = query
        .offset
        .as_deref()
        .map(decimal)
        .transpose()?
        .unwrap_or(0);

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
        let bodies = explorer.bodies(&anchor, digests.values().copied()).await?;
        bundle.transactions = digests
            .into_iter()
            .map(|(location, digest)| TransactionRow {
                location: location.to_string(),
                body: hex(&bodies[&digest]),
                height: height.to_string(),
                index: (location - start) as u32,
                role: None,
            })
            .collect();
        bundle.transactions_proof = Some(proof);
    }

    // Return the next page's offset while transactions remain.
    bundle.next_cursor = (page_end < count).then(|| page_end.to_string());

    // Report the floor after every read, since each read can raise it.
    bundle.sequence_number = anchor.floor()?.to_string();
    response(bundle)
}

/// Serves one transaction with its exact inclusion height and proof.
async fn transaction(
    State(explorer): State<Arc<Explorer>>,
    Path(digest): Path<String>,
) -> Result<Response, Failure> {
    let digest = Digest::from(hex_bytes::<32>(&digest)?);

    // Discover the owning height under the published visibility floor, then bind
    // the location to that block's authenticated append interval.
    let published = explorer.published().await?;
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
    let (proof, bodies) = explorer
        .transaction_evidence(&anchor, &[(location, digest)])
        .await?;
    let mut bundle = anchor.bundle()?;
    bundle.headers = headers;
    bundle.transactions = vec![TransactionRow {
        location: location.to_string(),
        body: hex(&bodies[&digest]),
        height: height.to_string(),
        index,
        role: None,
    }];
    bundle.transactions_proof = Some(proof);

    // Report the floor after every read, since each read can raise it.
    bundle.sequence_number = anchor.floor()?.to_string();
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

/// Reads at most one row beyond an activity page, newest first, after the
/// request cursor and at or below the certified `height`.
async fn activity_rows(
    sql: &SqlContext,
    request: &AccountRequest,
    height: u64,
) -> Result<Vec<RecordBatch>, Failure> {
    // A cursor above the certified height belongs to a later snapshot.
    if request.cursor.is_some_and(|cursor| cursor.height > height) {
        return Err(Failure::bad("cursor exceeds certified height"));
    }

    // Sent and received filters apply the role as a row predicate.
    let mut predicate = format!("account = X'{}'", hex(request.key.as_ref()));
    if let Some(role) = request.mode {
        predicate.push_str(&format!(" AND role = {role}"));
    }

    // Each cursor suffix is a separate key range, so the Store can seek past
    // earlier pages. The ranges are disjoint and ordered newest first.
    let mut ranges = Vec::with_capacity(3);
    if let Some(cursor) = request.cursor {
        if cursor.role == 1 && request.mode.is_none() {
            ranges.push(format!(
                "height = {} AND index = {} AND role = 0",
                cursor.height, cursor.index
            ));
        }
        if cursor.index > 0 {
            ranges.push(format!(
                "height = {} AND index < {}",
                cursor.height, cursor.index
            ));
        }
        if cursor.height > 1 {
            ranges.push(format!("height < {}", cursor.height));
        }
    } else {
        ranges.push(format!("height <= {height}"));
    }

    // Query the ranges in order, carrying the remaining budget so the total
    // stays within one page plus one row.
    let mut remaining = ACCOUNT_PAGE + 1;
    let mut batches = Vec::new();
    for range in ranges {
        let query = format!(
            "SELECT height, index, role, tx_digest, qmdb_location FROM tx_activity WHERE {predicate} AND {range} ORDER BY height DESC, index DESC, role DESC LIMIT {remaining}"
        );
        let next = query_rows(sql, &query, remaining).await?;
        remaining -= next.iter().map(RecordBatch::num_rows).sum::<usize>();
        batches.extend(next);
        if remaining == 0 {
            break;
        }
    }
    Ok(batches)
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
