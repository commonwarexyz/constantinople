//! Typed read-only wrapper over Simplex block storage and SQL transaction rows.
//!
//! Full blocks are stored in `exoware-simplex` as `{ header, body }` rows
//! keyed by the certified block-header digest. Height/latest reads go through
//! Simplex finalization indexes first, so callers can use the verified header
//! path without fetching the full body. Transaction bodies remain in SQL
//! `tx_meta` rows. Finalized publication targets bind each complete height to
//! its block digest and Store visibility sequence.

use crate::{
    codec,
    namespaces::{publication_target_client, simplex_client, sql_meta_client},
    publisher::certificate::CertifiedHeader,
    sql_schema::{
        BLOCK_META_DIGEST, BLOCK_META_HEIGHT, BLOCK_META_TABLE, BLOCK_META_TRANSACTIONS_TIP,
        TX_META_BODY, TX_META_DIGEST, TX_META_QMDB_LOCATION, TX_META_TABLE, build_meta_schema,
    },
};
use bytes::Bytes;
use commonware_codec::{FixedSize as _, Read};
use commonware_consensus::{
    Heightable,
    types::{Height, View},
};
use commonware_cryptography::{Digest, Hasher, PublicKey, certificate::Scheme};
use constantinople_engine::types::{EngineBlock, EngineCommitment, EngineHeader};
use constantinople_primitives::{BlockCfg, SignedTransaction, Transaction};
use datafusion::{
    arrow::{
        array::{Array, BinaryArray, FixedSizeBinaryArray, UInt64Array},
        record_batch::RecordBatch,
    },
    prelude::SessionContext,
};
use exoware_sdk::{ClientError, Key, PrefixedStoreClient, StoreClient};
use exoware_simplex::{Finalized, Notarized, SimplexClient, SimplexError};
use exoware_sql::query_context_with_min_sequence;

type CertifiedFinalization<H, P, S> = Finalized<CertifiedHeader<H, P>, S, EngineCommitment<H, P>>;
type CertifiedNotarization<H, P, S> = Notarized<CertifiedHeader<H, P>, S, EngineCommitment<H, P>>;
type FinalizationCfg<H, P, S> = <CertifiedFinalization<H, P, S> as Read>::Cfg;
type NotarizationCfg<H, P, S> = <CertifiedNotarization<H, P, S> as Read>::Cfg;

/// Errors returned when reading typed artifacts back out of the store.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// The underlying raw Store RPC failed.
    #[error("store error: {0}")]
    Store(#[from] ClientError),
    /// The underlying Simplex client failed.
    #[error("simplex error: {0}")]
    Simplex(#[from] SimplexError),
    /// SQL metadata schema registration failed.
    #[error("failed to configure SQL metadata schema: {0}")]
    SqlSchema(String),
    /// The underlying SQL/DataFusion query failed.
    #[error("SQL query error: {0}")]
    Sql(#[from] datafusion::error::DataFusionError),
    /// A SQL row did not match the expected `tx_meta` layout.
    #[error("SQL row shape error: {0}")]
    SqlRow(String),
    /// A hex-encoded SQL payload was malformed.
    #[error("malformed hex payload: {0}")]
    Hex(String),
    /// Decoding failed.
    #[error("decode error: {0}")]
    Codec(#[from] commonware_codec::Error),
    /// A publication target did not contain one complete digest.
    #[error("publication target digest has length {actual}. expected {expected}")]
    PublicationTargetDigestLength { expected: usize, actual: usize },
    /// A publication target read did not report its Store visibility sequence.
    #[error("publication target read did not report a Store sequence")]
    PublicationTargetSequence,
}

/// Digest-keyed finalized transaction metadata from the SQL lookup tables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionMetadata {
    /// Finalized block height containing the transaction.
    pub height: u64,
    /// Transaction-hash QMDB append location.
    pub qmdb_location: u64,
    /// Encoded signed transaction bytes.
    pub body: Bytes,
}

/// A finalized height whose complete index is visible through Store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizedPublicationTarget<D> {
    /// Finalized block height.
    pub height: u64,
    /// Certified block-header digest at this height.
    pub block_digest: D,
    /// Store sequence at which this target read was evaluated.
    pub store_sequence_number: u64,
}

/// Typed read client over finalized targets, Simplex blocks, and SQL rows.
///
/// | Field     | Families served                                        |
/// | --------- | ------------------------------------------------------ |
/// | `blocks`  | Simplex headers, blocks, notarizations, finals         |
/// | `targets` | Finalized height, digest, and Store visibility barrier |
/// | `sql`     | Transaction bodies and proof lookup metadata           |
#[derive(Clone)]
pub struct IndexerClient {
    blocks: SimplexClient,
    targets: PrefixedStoreClient,
    sql_store: PrefixedStoreClient,
    sql: SessionContext,
}

impl std::fmt::Debug for IndexerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexerClient")
            .field("blocks", &self.blocks)
            .field("targets", &self.targets)
            .field("sql_store", &self.sql_store)
            .field("sql", &"SessionContext")
            .finish()
    }
}

impl IndexerClient {
    /// Wrap existing [`StoreClient`]s for block and finalized index families.
    pub fn new(blocks: StoreClient, metadata: StoreClient) -> Self {
        Self::try_new(blocks, metadata).expect("metadata SQL schema should register")
    }

    /// Wrap existing [`StoreClient`]s for block and finalized index families.
    pub fn try_new(blocks: StoreClient, metadata: StoreClient) -> Result<Self, ReadError> {
        let sql = SessionContext::new();
        let sql_store = sql_meta_client(&metadata).map_err(ClientError::from)?;
        build_meta_schema(sql_store.clone())
            .map_err(ReadError::SqlSchema)?
            .register_all(&sql)?;
        Ok(Self {
            blocks: SimplexClient::new(simplex_client(&blocks).map_err(ClientError::from)?),
            targets: publication_target_client(&metadata).map_err(ClientError::from)?,
            sql_store,
            sql,
        })
    }

    /// Borrow the Simplex block client.
    pub const fn blocks(&self) -> &SimplexClient {
        &self.blocks
    }

    /// Borrow the finalized publication-target Store client.
    pub const fn publication_targets(&self) -> &PrefixedStoreClient {
        &self.targets
    }

    /// Borrow the SQL metadata context used for transaction lookups.
    pub const fn sql(&self) -> &SessionContext {
        &self.sql
    }

    /// Fetch the finalized publication target for `height`.
    ///
    /// Presence means the writer atomically published this target with both
    /// QMDB watermarks. Callers can carry `store_sequence_number` as the
    /// minimum sequence for subsequent Store-backed reads.
    pub async fn publication_target<H>(
        &self,
        height: u64,
    ) -> Result<Option<FinalizedPublicationTarget<H::Digest>>, ReadError>
    where
        H: Hasher,
    {
        let session = self.targets.create_session();
        let Some(block_digest) = session.get(&publication_target_key(height)).await? else {
            return Ok(None);
        };
        let store_sequence_number = session
            .evaluated_sequence()
            .ok_or(ReadError::PublicationTargetSequence)?;

        Ok(Some(decode_publication_target::<H::Digest>(
            height,
            &block_digest,
            store_sequence_number,
        )?))
    }

    /// Fetch the encoded Simplex `{ header, body }` envelope for `digest`.
    pub async fn block_bytes_by_digest<D: Digest>(
        &self,
        digest: &D,
    ) -> Result<Option<Bytes>, ReadError> {
        Ok(self.blocks.get_block_raw(digest).await?)
    }

    /// Fetch and decode the certified block header for `digest`.
    pub async fn header_by_digest<H, P>(
        &self,
        digest: &H::Digest,
    ) -> Result<Option<EngineHeader<H, P>>, ReadError>
    where
        H: Hasher,
        P: PublicKey,
    {
        Ok(self.blocks.get_header(digest, &()).await?)
    }

    /// Decode and return the full block for `digest`.
    ///
    /// This is the body-fetching path. Header-only callers should use
    /// [`Self::header_by_digest`] or the certified height/latest helpers.
    pub async fn block_by_digest<H, P>(
        &self,
        digest: &H::Digest,
        cfg: &BlockCfg,
    ) -> Result<Option<EngineBlock<H, P>>, ReadError>
    where
        H: Hasher,
        P: PublicKey,
    {
        let Some(data) = self
            .blocks
            .get_block::<EngineHeader<H, P>, H::Digest>(digest, &())
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(crate::simplex_block::decode_simplex_block_parts(
            data.header,
            data.body,
            cfg,
        )?))
    }

    /// Decode the certified header at `height`.
    pub async fn certified_header_by_height<H, P, S>(
        &self,
        height: u64,
        cfg: &FinalizationCfg<H, P, S>,
    ) -> Result<Option<CertifiedHeader<H, P>>, ReadError>
    where
        H: Hasher,
        P: PublicKey,
        S: Scheme,
        <S::Certificate as Read>::Cfg: Clone,
    {
        Ok(self
            .blocks
            .get_finalized_by_height::<CertifiedHeader<H, P>, S, EngineCommitment<H, P>>(
                Height::new(height),
                cfg,
            )
            .await?
            .map(|finalized| finalized.header))
    }

    /// Fetch the certified block-header digest at `height`.
    pub async fn digest_by_height<H, P, S>(
        &self,
        height: u64,
        cfg: &FinalizationCfg<H, P, S>,
    ) -> Result<Option<H::Digest>, ReadError>
    where
        H: Hasher,
        P: PublicKey,
        S: Scheme,
        <S::Certificate as Read>::Cfg: Clone,
    {
        Ok(self
            .certified_header_by_height::<H, P, S>(height, cfg)
            .await?
            .map(|header| header.block_digest()))
    }

    /// Decode and return the certified full block at `height`.
    pub async fn block_by_height<H, P, S>(
        &self,
        height: u64,
        block_cfg: &BlockCfg,
        cert_cfg: &FinalizationCfg<H, P, S>,
    ) -> Result<Option<EngineBlock<H, P>>, ReadError>
    where
        H: Hasher,
        P: PublicKey,
        S: Scheme,
        <S::Certificate as Read>::Cfg: Clone,
    {
        let Some(digest) = self.digest_by_height::<H, P, S>(height, cert_cfg).await? else {
            return Ok(None);
        };
        self.block_by_digest::<H, P>(&digest, block_cfg).await
    }

    /// Latest finalized block header, decoded from the Simplex finalization
    /// height index without fetching the block body.
    pub async fn latest_certified_header<H, P, S>(
        &self,
        cfg: &FinalizationCfg<H, P, S>,
    ) -> Result<Option<CertifiedHeader<H, P>>, ReadError>
    where
        H: Hasher,
        P: PublicKey,
        S: Scheme,
        <S::Certificate as Read>::Cfg: Clone,
    {
        Ok(self
            .blocks
            .latest_finalized::<CertifiedHeader<H, P>, S, EngineCommitment<H, P>>(cfg)
            .await?
            .map(|finalized| finalized.header))
    }

    /// Latest finalized height from the certified Simplex finalization index.
    pub async fn latest_height<H, P, S>(
        &self,
        cfg: &FinalizationCfg<H, P, S>,
    ) -> Result<Option<u64>, ReadError>
    where
        H: Hasher,
        P: PublicKey,
        S: Scheme,
        <S::Certificate as Read>::Cfg: Clone,
    {
        Ok(self
            .latest_certified_header::<H, P, S>(cfg)
            .await?
            .map(|header| header.height().get()))
    }

    /// Latest finalized full block. This fetches the body by digest after
    /// decoding the latest certified header.
    pub async fn latest_block<H, P, S>(
        &self,
        block_cfg: &BlockCfg,
        cert_cfg: &FinalizationCfg<H, P, S>,
    ) -> Result<Option<EngineBlock<H, P>>, ReadError>
    where
        H: Hasher,
        P: PublicKey,
        S: Scheme,
        <S::Certificate as Read>::Cfg: Clone,
    {
        let Some(header) = self.latest_certified_header::<H, P, S>(cert_cfg).await? else {
            return Ok(None);
        };
        self.block_by_digest::<H, P>(&header.block_digest(), block_cfg)
            .await
    }

    /// Fetch the encoded signed transaction for `digest`, or `None` if absent.
    pub async fn transaction_bytes<H>(&self, digest: &H::Digest) -> Result<Option<Bytes>, ReadError>
    where
        H: Hasher,
    {
        Ok(self
            .transaction_metadata::<H>(digest)
            .await?
            .map(|metadata| metadata.body))
    }

    /// Fetch the finalized metadata for `digest`, or `None` if absent.
    ///
    /// The row is accepted only when every value has the canonical non-null
    /// SQL type and the transaction body hashes back to `digest`.
    pub async fn transaction_metadata<H>(
        &self,
        digest: &H::Digest,
    ) -> Result<Option<TransactionMetadata>, ReadError>
    where
        H: Hasher,
    {
        let digest_hex = hex_lower(digest.as_ref());
        let hint_sql = format!(
            "SELECT {TX_META_QMDB_LOCATION} FROM {TX_META_TABLE} WHERE {TX_META_DIGEST} = X'{digest_hex}' LIMIT 1"
        );
        let batches = self.sql.sql(&hint_sql).await?.collect().await?;
        let mut location_hint = None;
        for batch in batches {
            if batch.num_rows() == 0 {
                continue;
            }
            location_hint = Some(required_u64(&batch, 0, TX_META_QMDB_LOCATION)?);
            break;
        }
        let Some(location_hint) = location_hint else {
            return Ok(None);
        };
        let height_hint = transaction_containing_height(&self.sql, location_hint).await?;
        let Some(target) = self.publication_target::<H>(height_hint).await? else {
            return Ok(None);
        };

        let query = format!(
            "SELECT {TX_META_DIGEST}, {TX_META_QMDB_LOCATION}, {TX_META_BODY} FROM {TX_META_TABLE} WHERE {TX_META_DIGEST} = X'{digest_hex}' LIMIT 1"
        );
        let sql = query_context_with_min_sequence(
            &self.sql,
            &self.sql_store,
            target.store_sequence_number,
        );
        let batches = sql.sql(&query).await?.collect().await?;
        for batch in batches {
            if batch.num_rows() == 0 {
                continue;
            }
            let (qmdb_location, body) = decode_transaction_row::<H>(&batch, digest)?;
            let height = transaction_containing_height(&sql, qmdb_location).await?;
            validate_transaction_height(height, target.height)?;
            validate_target_block_digest(&sql, height, target.block_digest.as_ref()).await?;
            return Ok(Some(TransactionMetadata {
                height,
                qmdb_location,
                body,
            }));
        }
        Ok(None)
    }

    /// Decode and return the transaction for `digest`, or `None` if absent.
    pub async fn transaction<H>(
        &self,
        digest: &H::Digest,
    ) -> Result<Option<SignedTransaction<H>>, ReadError>
    where
        H: Hasher,
    {
        let Some(bytes) = self.transaction_bytes::<H>(digest).await? else {
            return Ok(None);
        };
        Ok(Some(codec::from_bytes::<SignedTransaction<H>>(
            &bytes,
            &(),
        )?))
    }

    /// Fetch the encoded Simplex finalization artifact for `view`.
    pub async fn finalization_bytes(&self, view: u64) -> Result<Option<Bytes>, ReadError> {
        Ok(self
            .blocks
            .get_finalized_by_view_raw(View::new(view))
            .await?)
    }

    /// Decode the Simplex finalization artifact for `view`.
    pub async fn finalization_by_view<H, P, S>(
        &self,
        view: u64,
        cfg: &FinalizationCfg<H, P, S>,
    ) -> Result<Option<CertifiedFinalization<H, P, S>>, ReadError>
    where
        H: Hasher,
        P: PublicKey,
        S: Scheme,
        <S::Certificate as Read>::Cfg: Clone,
    {
        Ok(self
            .blocks
            .get_finalized_by_view::<CertifiedHeader<H, P>, S, EngineCommitment<H, P>>(
                View::new(view),
                cfg,
            )
            .await?)
    }

    /// Fetch the encoded Simplex notarization artifact for `view`.
    pub async fn notarization_bytes(&self, view: u64) -> Result<Option<Bytes>, ReadError> {
        Ok(self.blocks.get_notarized_raw(View::new(view)).await?)
    }

    /// Decode the Simplex notarization artifact for `view`.
    pub async fn notarization_by_view<H, P, S>(
        &self,
        view: u64,
        cfg: &NotarizationCfg<H, P, S>,
    ) -> Result<Option<CertifiedNotarization<H, P, S>>, ReadError>
    where
        H: Hasher,
        P: PublicKey,
        S: Scheme,
        <S::Certificate as Read>::Cfg: Clone,
    {
        Ok(self
            .blocks
            .get_notarized::<CertifiedHeader<H, P>, S, EngineCommitment<H, P>>(View::new(view), cfg)
            .await?)
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn publication_target_key(height: u64) -> Key {
    Key::from(Bytes::copy_from_slice(&height.to_be_bytes()))
}

fn decode_publication_target<D>(
    height: u64,
    block_digest: &[u8],
    store_sequence_number: u64,
) -> Result<FinalizedPublicationTarget<D>, ReadError>
where
    D: Digest,
{
    if block_digest.len() != D::SIZE {
        return Err(ReadError::PublicationTargetDigestLength {
            expected: D::SIZE,
            actual: block_digest.len(),
        });
    }

    Ok(FinalizedPublicationTarget {
        height,
        block_digest: codec::from_bytes(block_digest, &())?,
        store_sequence_number,
    })
}

fn decode_transaction_row<H>(
    batch: &RecordBatch,
    digest: &H::Digest,
) -> Result<(u64, Bytes), ReadError>
where
    H: Hasher,
{
    let stored_digest = batch
        .column(0)
        .as_any()
        .downcast_ref::<FixedSizeBinaryArray>()
        .ok_or_else(|| ReadError::SqlRow("tx_meta.tx_digest must be FixedSizeBinary(32)".into()))?;
    if stored_digest.is_null(0) {
        return Err(ReadError::SqlRow(
            "tx_meta.tx_digest must not be null".into(),
        ));
    }
    if stored_digest.value(0) != digest.as_ref() {
        return Err(ReadError::SqlRow(
            "tx_meta.tx_digest does not match the requested digest".into(),
        ));
    }

    let qmdb_location = required_u64(batch, 1, TX_META_QMDB_LOCATION)?;
    let body = verified_transaction_body::<H>(batch, 2, digest)?;
    Ok((qmdb_location, body))
}

fn required_u64(batch: &RecordBatch, column: usize, name: &str) -> Result<u64, ReadError> {
    let values = batch
        .column(column)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or_else(|| ReadError::SqlRow(format!("tx_meta.{name} must be UInt64")))?;
    if values.is_null(0) {
        return Err(ReadError::SqlRow(format!(
            "tx_meta.{name} must not be null"
        )));
    }
    Ok(values.value(0))
}

fn validate_transaction_height(actual: u64, target: u64) -> Result<(), ReadError> {
    if actual != target {
        return Err(ReadError::SqlRow(format!(
            "tx_meta.height {actual} does not match publication target height {target}"
        )));
    }
    Ok(())
}

async fn transaction_containing_height(
    sql: &SessionContext,
    qmdb_location: u64,
) -> Result<u64, ReadError> {
    let batches = sql
        .sql(&transaction_height_predecessor_sql(qmdb_location))
        .await?
        .collect()
        .await?;
    let mut predecessor_height = None;
    for batch in batches {
        if batch.num_rows() == 0 {
            continue;
        }
        let block_height = batch
            .column(0)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or_else(|| ReadError::SqlRow("block_meta.height must be UInt64".to_string()))?;
        if block_height.is_null(0) {
            return Err(ReadError::SqlRow(
                "block_meta.height must not be null".to_string(),
            ));
        }
        predecessor_height = Some(block_height.value(0));
        break;
    }
    containing_block_height(predecessor_height)
}

async fn validate_target_block_digest(
    sql: &SessionContext,
    height: u64,
    target_digest: &[u8],
) -> Result<(), ReadError> {
    let query = format!(
        "SELECT {BLOCK_META_DIGEST} FROM {BLOCK_META_TABLE} WHERE {BLOCK_META_HEIGHT} = {height} LIMIT 1"
    );
    let batches = sql.sql(&query).await?.collect().await?;
    for batch in batches {
        if batch.num_rows() == 0 {
            continue;
        }
        let digest = batch
            .column(0)
            .as_any()
            .downcast_ref::<FixedSizeBinaryArray>()
            .ok_or_else(|| {
                ReadError::SqlRow("block_meta.digest must be FixedSizeBinary(32)".to_string())
            })?;
        if digest.is_null(0) {
            return Err(ReadError::SqlRow(
                "block_meta.digest must not be null".to_string(),
            ));
        }
        if digest.value(0) != target_digest {
            return Err(ReadError::SqlRow(
                "block_meta.digest does not match the publication target".to_string(),
            ));
        }
        return Ok(());
    }
    Err(ReadError::SqlRow(format!(
        "block_meta row is missing for publication target height {height}"
    )))
}

fn containing_block_height(predecessor_height: Option<u64>) -> Result<u64, ReadError> {
    let Some(height) = predecessor_height else {
        return Ok(0);
    };
    height.checked_add(1).ok_or_else(|| {
        ReadError::SqlRow("transaction containing block height overflows u64".to_string())
    })
}

fn transaction_height_predecessor_sql(qmdb_location: u64) -> String {
    format!(
        "SELECT {BLOCK_META_HEIGHT} FROM {BLOCK_META_TABLE} WHERE {BLOCK_META_TRANSACTIONS_TIP} <= {qmdb_location} ORDER BY {BLOCK_META_HEIGHT} DESC LIMIT 1"
    )
}

fn verified_transaction_body<H>(
    batch: &RecordBatch,
    column: usize,
    digest: &H::Digest,
) -> Result<Bytes, ReadError>
where
    H: Hasher,
{
    let body = batch
        .column(column)
        .as_any()
        .downcast_ref::<BinaryArray>()
        .ok_or_else(|| ReadError::SqlRow("tx_meta.body must be Binary".to_string()))?;
    if body.is_null(0) {
        return Err(ReadError::SqlRow(
            "tx_meta.body must not be null".to_string(),
        ));
    }
    let body = Bytes::copy_from_slice(body.value(0));
    verify_signed_transaction_digest::<H>(&body, digest)?;
    Ok(body)
}

fn verify_signed_transaction_digest<H>(bytes: &[u8], digest: &H::Digest) -> Result<(), ReadError>
where
    H: Hasher,
{
    let body_len = Transaction::<H::Digest>::SIZE;
    if bytes.len() < body_len {
        return Err(ReadError::SqlRow(format!(
            "tx_meta.body_hex signed transaction is {} bytes, shorter than {body_len}-byte transaction body",
            bytes.len()
        )));
    }

    let actual = H::hash(&[&bytes[..body_len]]);
    if actual.as_ref() != digest.as_ref() {
        return Err(ReadError::SqlRow(
            "tx_meta.body_hex transaction body does not match tx_digest".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{sha256, sha256::Sha256};
    use exoware_sql::CellValue;

    #[test]
    fn publication_target_uses_big_endian_height_key() {
        let height = 0x0102_0304_0506_0708;

        assert_eq!(
            publication_target_key(height).as_ref(),
            &[1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn decodes_publication_target_with_store_sequence() {
        let digest = Sha256::hash(&[b"finalized block"]);

        let target = decode_publication_target::<sha256::Digest>(19, digest.as_ref(), 41)
            .expect("publication target should decode");

        assert_eq!(
            target,
            FinalizedPublicationTarget {
                height: 19,
                block_digest: digest,
                store_sequence_number: 41,
            }
        );
    }

    #[test]
    fn rejects_publication_target_with_wrong_digest_length() {
        let error = decode_publication_target::<sha256::Digest>(19, &[0; 31], 41)
            .expect_err("short publication target digest should be rejected");

        assert!(matches!(
            error,
            ReadError::PublicationTargetDigestLength {
                expected: 32,
                actual: 31,
            }
        ));
    }

    #[test]
    fn rejects_transaction_height_that_differs_from_publication_target() {
        let error = validate_transaction_height(8, 7)
            .expect_err("a later visible row must not satisfy the selected target");

        assert!(
            matches!(error, ReadError::SqlRow(message) if message.contains("does not match publication target height"))
        );
    }

    #[test]
    fn containing_block_height_rejects_overflow() {
        let error = containing_block_height(Some(u64::MAX)).expect_err("height should overflow");
        assert!(matches!(error, ReadError::SqlRow(message) if message.contains("overflows")));
    }

    #[test]
    fn transaction_height_query_scans_backward_from_the_newest_block() {
        assert_eq!(
            transaction_height_predecessor_sql(42),
            "SELECT height FROM block_meta WHERE transactions_tip <= 42 ORDER BY height DESC LIMIT 1"
        );
    }

    #[tokio::test]
    async fn transaction_metadata_waits_for_its_exact_publication_target() {
        let (simulator, url) = exoware_simulator::open_temp()
            .await
            .expect("spawn simulator");
        let store = StoreClient::new(&url);
        let schema = build_meta_schema(sql_meta_client(&store).expect("SQL metadata namespace"))
            .expect("build SQL metadata schema");
        let body = vec![7u8; Transaction::<sha256::Digest>::SIZE + 1];
        let digest = digest_transaction_body(&body);
        let block_digest = Sha256::hash(&[b"second block"]);
        let mut writer = schema.batch_writer();
        for (height, transactions_tip) in [(0, 2), (1, 3), (2, 5)] {
            writer
                .insert(
                    BLOCK_META_TABLE,
                    vec![
                        CellValue::UInt64(height),
                        CellValue::FixedBinary(if height == 2 {
                            block_digest.as_ref().to_vec()
                        } else {
                            vec![height as u8; 32]
                        }),
                        CellValue::UInt64(1),
                        CellValue::FixedBinary(vec![transactions_tip as u8; 32]),
                        CellValue::UInt64(transactions_tip),
                        CellValue::UInt64(0),
                        CellValue::Timestamp(i64::try_from(height).expect("height fits i64")),
                    ],
                )
                .expect("stage block metadata");
        }
        writer
            .insert(
                TX_META_TABLE,
                vec![
                    CellValue::FixedBinary(digest.as_ref().to_vec()),
                    CellValue::UInt64(4),
                    CellValue::Binary(body.clone()),
                ],
            )
            .expect("stage out-of-order transaction metadata");
        writer
            .flush()
            .await
            .expect("persist out-of-order transaction metadata");

        let client = IndexerClient::new(store.clone(), store.clone());
        assert_eq!(
            client
                .transaction_metadata::<Sha256>(&digest)
                .await
                .expect("ungated metadata query succeeds"),
            None
        );
        assert_eq!(
            client
                .transaction_bytes::<Sha256>(&digest)
                .await
                .expect("ungated body query succeeds"),
            None
        );

        let targets = publication_target_client(&store).expect("publication target namespace");
        let second_key = publication_target_key(2);
        targets
            .ingest()
            .put(&[(&second_key, block_digest.as_ref())])
            .await
            .expect("publish exact target");

        let metadata = client
            .transaction_metadata::<Sha256>(&digest)
            .await
            .expect("published metadata query succeeds")
            .expect("metadata becomes visible after its exact target");
        assert_eq!(metadata.height, 2);
        assert_eq!(metadata.qmdb_location, 4);
        assert_eq!(metadata.body, Bytes::from(body));

        simulator.abort();
        let _ = simulator.await;
    }

    #[test]
    fn verifies_signed_transaction_bytes_against_digest() {
        let mut bytes = vec![7u8; Transaction::<sha256::Digest>::SIZE + 1];
        let digest = digest_transaction_body(&bytes);

        verify_signed_transaction_digest::<Sha256>(&bytes, &digest).expect("digest matches");

        bytes[0] ^= 1;
        let error = verify_signed_transaction_digest::<Sha256>(&bytes, &digest)
            .expect_err("mutated body should be rejected");
        assert!(matches!(error, ReadError::SqlRow(message) if message.contains("does not match")));
    }

    #[test]
    fn rejects_signed_transaction_bytes_without_full_body() {
        let bytes = vec![0u8; Transaction::<sha256::Digest>::SIZE - 1];
        let digest = digest_transaction_body(&bytes);

        let error = verify_signed_transaction_digest::<Sha256>(&bytes, &digest)
            .expect_err("truncated body should be rejected");
        assert!(matches!(error, ReadError::SqlRow(message) if message.contains("shorter")));
    }

    fn digest_transaction_body(bytes: &[u8]) -> sha256::Digest {
        let body_len = Transaction::<sha256::Digest>::SIZE.min(bytes.len());
        Sha256::hash(&[&bytes[..body_len]])
    }
}
