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
    namespaces::{
        publication_target_client, publication_target_key, simplex_client, sql_meta_client,
    },
    publisher::certificate::CertifiedHeader,
    sql_schema::{
        BLOCK_META_DIGEST, BLOCK_META_HEIGHT, BLOCK_META_TABLE, TX_META_BODY, TX_META_DIGEST,
        TX_META_HEIGHT, TX_META_QMDB_LOCATION, TX_META_TABLE, build_meta_schema,
    },
};
use bytes::Bytes;
use commonware_codec::{DecodeExt, FixedSize as _, Read};
use commonware_consensus::{
    Heightable,
    types::{Epoch, Height, Round, View},
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
use exoware_sdk::{ClientError, PrefixedStoreClient, StoreClient};
use exoware_simplex::{Finalized, SimplexError, SimplexReader};
use exoware_sql::with_read_session;

type CertifiedFinalization<H, P, S> = Finalized<CertifiedHeader<H, P>, S, EngineCommitment<H, P>>;
type FinalizationCfg<H, P, S> = <CertifiedFinalization<H, P, S> as Read>::Cfg;

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
    /// Block-header digest at this height.
    pub block_digest: D,
    /// Store sequence at which this target read was evaluated.
    pub store_sequence_number: u64,
}

/// Typed read client over finalized targets, Simplex blocks, and SQL rows.
///
/// | Field     | Families served                                        |
/// | --------- | ------------------------------------------------------ |
/// | `blocks`  | Simplex headers, blocks, finalizations                 |
/// | `targets` | Finalized height, digest, and Store visibility barrier |
/// | `sql`     | Transaction bodies and proof lookup metadata           |
#[derive(Clone)]
pub struct IndexerClient {
    blocks: SimplexReader,
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
            blocks: SimplexReader::new(simplex_client(&blocks).map_err(ClientError::from)?),
            targets: publication_target_client(&metadata).map_err(ClientError::from)?,
            sql_store,
            sql,
        })
    }

    /// Borrow the Simplex block client.
    pub const fn blocks(&self) -> &SimplexReader {
        &self.blocks
    }

    /// Borrow the SQL metadata context used for transaction lookups.
    pub const fn sql(&self) -> &SessionContext {
        &self.sql
    }

    /// Fetch the finalized publication target for `height`.
    ///
    /// Presence means the complete index for this height is visible. Use
    /// `store_sequence_number` as the minimum sequence for subsequent reads.
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

        Ok(Some(FinalizedPublicationTarget {
            height,
            block_digest: H::Digest::decode(block_digest)?,
            store_sequence_number,
        }))
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
    ///
    /// Returns `None` for heights without their own finalization certificate.
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
    ///
    /// Returns `None` for heights without their own finalization certificate.
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
    ///
    /// Returns `None` for heights without their own finalization certificate.
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

    /// Latest block header with its own finalization certificate.
    ///
    /// Heights finalized through a descendant are omitted.
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

    /// Latest height with its own finalization certificate.
    ///
    /// Heights finalized through a descendant are omitted.
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

    /// Latest full block with its own finalization certificate.
    ///
    /// Heights finalized through a descendant are omitted.
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
        let query = format!(
            "SELECT {TX_META_QMDB_LOCATION}, {TX_META_BODY}, {TX_META_HEIGHT} FROM {TX_META_TABLE} WHERE {TX_META_DIGEST} = X'{digest_hex}' LIMIT 1"
        );
        let batches = self.sql.sql(&query).await?.collect().await?;
        let Some(batch) = first_row(batches) else {
            return Ok(None);
        };
        let qmdb_location = column::<UInt64Array>(&batch, 0, "tx_meta.qmdb_location")?.value(0);
        let body = verified_transaction_body::<H>(&batch, 1, digest)?;
        let height = column::<UInt64Array>(&batch, 2, "tx_meta.height")?.value(0);
        let Some(target) = self.publication_target::<H>(height).await? else {
            return Ok(None);
        };
        let sql = with_read_session(
            &self.sql,
            self.sql_store
                .create_session_with_sequence(target.store_sequence_number),
        );
        validate_target_block_digest(&sql, height, target.block_digest.as_ref()).await?;
        Ok(Some(TransactionMetadata {
            height,
            qmdb_location,
            body,
        }))
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
        Ok(Some(codec::from_bytes::<SignedTransaction<H>>(bytes, &())?))
    }

    /// Fetch the encoded Simplex finalization artifact for `view`.
    pub async fn finalization_bytes(&self, view: u64) -> Result<Option<Bytes>, ReadError> {
        Ok(self
            .blocks
            .get_finalized_by_round_raw(Round::new(Epoch::zero(), View::new(view)))
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
            .get_finalized_by_round::<CertifiedHeader<H, P>, S, EngineCommitment<H, P>>(
                Round::new(Epoch::zero(), View::new(view)),
                cfg,
            )
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

fn first_row(batches: Vec<RecordBatch>) -> Option<RecordBatch> {
    batches.into_iter().find(|batch| batch.num_rows() > 0)
}

fn column<'a, A: Array + 'static>(
    batch: &'a RecordBatch,
    index: usize,
    label: &str,
) -> Result<&'a A, ReadError> {
    let values = batch
        .column(index)
        .as_any()
        .downcast_ref::<A>()
        .ok_or_else(|| ReadError::SqlRow(format!("{label} has an unexpected SQL type")))?;
    if values.is_null(0) {
        return Err(ReadError::SqlRow(format!("{label} must not be null")));
    }
    Ok(values)
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
    let batch = first_row(batches).ok_or_else(|| {
        ReadError::SqlRow(format!(
            "block_meta row is missing for publication target height {height}"
        ))
    })?;
    let digest = column::<FixedSizeBinaryArray>(&batch, 0, "block_meta.digest")?;
    if digest.value(0) != target_digest {
        return Err(ReadError::SqlRow(
            "block_meta.digest does not match the publication target".to_string(),
        ));
    }
    Ok(())
}

fn verified_transaction_body<H>(
    batch: &RecordBatch,
    index: usize,
    digest: &H::Digest,
) -> Result<Bytes, ReadError>
where
    H: Hasher,
{
    let body = column::<BinaryArray>(batch, index, "tx_meta.body")?;
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

    #[tokio::test]
    async fn transaction_metadata_waits_for_its_exact_publication_target() {
        for (height, qmdb_location) in [(1, 1), (2, 4)] {
            let (simulator, url) = exoware_simulator::open_temp()
                .await
                .expect("spawn simulator");
            let store = StoreClient::new(&url);
            let schema =
                build_meta_schema(sql_meta_client(&store).expect("SQL metadata namespace"))
                    .expect("build SQL metadata schema");
            let body = vec![7u8; Transaction::<sha256::Digest>::SIZE + 1];
            let digest = digest_transaction_body(&body);
            let block_digest = Sha256::hash(&[b"containing block"]);
            let mut writer = schema.batch_writer();
            for (block_height, transactions_tip) in [(1, 3), (2, 5)] {
                writer
                    .insert(
                        BLOCK_META_TABLE,
                        vec![
                            CellValue::UInt64(block_height),
                            CellValue::FixedBinary(if block_height == height {
                                block_digest.as_ref().to_vec()
                            } else {
                                vec![block_height as u8; 32]
                            }),
                            CellValue::UInt64(1),
                            CellValue::FixedBinary(vec![transactions_tip as u8; 32]),
                            CellValue::UInt64(transactions_tip),
                            CellValue::UInt64(0),
                            CellValue::Timestamp(
                                i64::try_from(block_height).expect("height fits i64"),
                            ),
                        ],
                    )
                    .expect("stage block metadata");
            }
            writer
                .insert(
                    TX_META_TABLE,
                    vec![
                        CellValue::FixedBinary(digest.as_ref().to_vec()),
                        CellValue::UInt64(qmdb_location),
                        CellValue::Binary(body.clone()),
                        CellValue::UInt64(height),
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
            let key = publication_target_key(height);
            targets
                .ingest()
                .put(&[(&key, block_digest.as_ref())])
                .await
                .expect("publish exact target");

            let metadata = client
                .transaction_metadata::<Sha256>(&digest)
                .await
                .expect("published metadata query succeeds")
                .expect("metadata becomes visible after its exact target");
            assert_eq!(metadata.height, height);
            assert_eq!(metadata.qmdb_location, qmdb_location);
            assert_eq!(metadata.body, Bytes::from(body));

            simulator.abort();
            let _ = simulator.await;
        }
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
