//! Typed read-only wrapper over Simplex block storage and SQL transaction rows.
//!
//! Full blocks are stored in `exoware-simplex` as `{ header, body }` rows
//! keyed by the certified block-header digest. Height/latest reads go through
//! Simplex finalization indexes first, so callers can use the verified header
//! path without fetching the full body. Transaction bodies and lookup metadata
//! are stored in SQL `tx_meta` rows.

use crate::{
    codec,
    namespaces::{simplex_client, sql_meta_client},
    publisher::certificate::CertifiedHeader,
    sql_schema::build_meta_schema,
};
use bytes::Bytes;
use commonware_codec::{FixedSize as _, Read};
use commonware_consensus::{
    Heightable,
    types::{Height, View, coding::Commitment},
};
use commonware_cryptography::{Digest, Hasher, PublicKey, certificate::Scheme};
use constantinople_engine::types::{EngineBlock, EngineHeader};
use constantinople_primitives::{BlockCfg, SignedTransaction, Transaction};
use datafusion::{
    arrow::array::{Array, BinaryArray},
    prelude::SessionContext,
};
use exoware_sdk::{ClientError, StoreClient};
use exoware_simplex::{Finalized, Notarized, SimplexClient, SimplexError};

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
}

/// Typed read client over Simplex block rows and SQL transaction rows.
///
/// | Field          | Families served                                  |
/// | -------------- | ------------------------------------------------ |
/// | `blocks`       | Simplex headers, blocks, notarizations, finals   |
/// | `sql`          | `tx_meta` transaction bodies and lookup metadata |
#[derive(Clone)]
pub struct IndexerClient {
    blocks: SimplexClient,
    sql: SessionContext,
}

impl std::fmt::Debug for IndexerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexerClient")
            .field("blocks", &self.blocks)
            .field("sql", &"SessionContext")
            .finish()
    }
}

impl IndexerClient {
    /// Wrap existing [`StoreClient`]s for block and SQL metadata families.
    pub fn new(blocks: StoreClient, metadata: StoreClient) -> Self {
        Self::try_new(blocks, metadata).expect("metadata SQL schema should register")
    }

    /// Wrap existing [`StoreClient`]s for block and SQL metadata families.
    pub fn try_new(blocks: StoreClient, metadata: StoreClient) -> Result<Self, ReadError> {
        let sql = SessionContext::new();
        build_meta_schema(sql_meta_client(&metadata).map_err(ClientError::from)?)
            .map_err(ReadError::SqlSchema)?
            .register_all(&sql)?;
        Ok(Self {
            blocks: SimplexClient::new(simplex_client(&blocks).map_err(ClientError::from)?),
            sql,
        })
    }

    /// Borrow the Simplex block client.
    pub const fn blocks(&self) -> &SimplexClient {
        &self.blocks
    }

    /// Borrow the SQL metadata context used for transaction lookups.
    pub const fn sql(&self) -> &SessionContext {
        &self.sql
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
        cfg: &<Finalized<CertifiedHeader<H, P>, S, Commitment> as Read>::Cfg,
    ) -> Result<Option<CertifiedHeader<H, P>>, ReadError>
    where
        H: Hasher,
        P: PublicKey,
        S: Scheme,
        <S::Certificate as Read>::Cfg: Clone,
    {
        Ok(self
            .blocks
            .get_finalized_by_height::<CertifiedHeader<H, P>, S, Commitment>(
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
        cfg: &<Finalized<CertifiedHeader<H, P>, S, Commitment> as Read>::Cfg,
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
        cert_cfg: &<Finalized<CertifiedHeader<H, P>, S, Commitment> as Read>::Cfg,
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
        cfg: &<Finalized<CertifiedHeader<H, P>, S, Commitment> as Read>::Cfg,
    ) -> Result<Option<CertifiedHeader<H, P>>, ReadError>
    where
        H: Hasher,
        P: PublicKey,
        S: Scheme,
        <S::Certificate as Read>::Cfg: Clone,
    {
        Ok(self
            .blocks
            .latest_finalized::<CertifiedHeader<H, P>, S, Commitment>(cfg)
            .await?
            .map(|finalized| finalized.header))
    }

    /// Latest finalized height from the certified Simplex finalization index.
    pub async fn latest_height<H, P, S>(
        &self,
        cfg: &<Finalized<CertifiedHeader<H, P>, S, Commitment> as Read>::Cfg,
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
        cert_cfg: &<Finalized<CertifiedHeader<H, P>, S, Commitment> as Read>::Cfg,
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
    ///
    /// SQL bytes are accepted only if the fixed transaction body prefix hashes
    /// back to `digest`.
    pub async fn transaction_bytes<H>(&self, digest: &H::Digest) -> Result<Option<Bytes>, ReadError>
    where
        H: Hasher,
    {
        let sql = format!(
            "SELECT body FROM tx_meta WHERE tx_digest = X'{}' LIMIT 1",
            hex_lower(digest.as_ref())
        );
        let batches = self.sql.sql(&sql).await?.collect().await?;
        for batch in batches {
            if batch.num_rows() == 0 {
                continue;
            }
            let body = batch
                .column(0)
                .as_any()
                .downcast_ref::<BinaryArray>()
                .ok_or_else(|| ReadError::SqlRow("tx_meta.body must be Binary".to_string()))?;
            if body.is_null(0) {
                return Err(ReadError::SqlRow(
                    "tx_meta.body must not be null".to_string(),
                ));
            }
            let bytes = body.value(0).to_vec();
            verify_signed_transaction_digest::<H>(&bytes, digest)?;
            return Ok(Some(Bytes::from(bytes)));
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
        cfg: &<Finalized<CertifiedHeader<H, P>, S, Commitment> as Read>::Cfg,
    ) -> Result<Option<Finalized<CertifiedHeader<H, P>, S, Commitment>>, ReadError>
    where
        H: Hasher,
        P: PublicKey,
        S: Scheme,
        <S::Certificate as Read>::Cfg: Clone,
    {
        Ok(self
            .blocks
            .get_finalized_by_view::<CertifiedHeader<H, P>, S, Commitment>(View::new(view), cfg)
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
        cfg: &<Notarized<CertifiedHeader<H, P>, S, Commitment> as Read>::Cfg,
    ) -> Result<Option<Notarized<CertifiedHeader<H, P>, S, Commitment>>, ReadError>
    where
        H: Hasher,
        P: PublicKey,
        S: Scheme,
        <S::Certificate as Read>::Cfg: Clone,
    {
        Ok(self
            .blocks
            .get_notarized::<CertifiedHeader<H, P>, S, Commitment>(View::new(view), cfg)
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

    let mut hasher = H::new();
    hasher.update(&bytes[..body_len]);
    let actual = hasher.finalize();
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
        let mut hasher = Sha256::new();
        hasher.update(&bytes[..body_len]);
        hasher.finalize()
    }
}
