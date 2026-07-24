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
use bytes::{Buf as _, Bytes};
use commonware_codec::{Read, ReadExt as _};
use commonware_consensus::{
    Heightable,
    types::{Height, View, coding::Commitment},
};
use commonware_cryptography::{
    Digest, Hasher, Signer, bls12381::primitives::variant::Variant, certificate::Scheme,
};
use constantinople_engine::types::{EngineBlock, EngineBlockCfg, EngineHeader};
use constantinople_primitives::{SignedTransaction, Transaction};
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
    pub async fn header_by_digest<H, C, V>(
        &self,
        digest: &H::Digest,
        cfg: &<EngineHeader<H, C, V> as Read>::Cfg,
    ) -> Result<Option<EngineHeader<H, C, V>>, ReadError>
    where
        H: Hasher,
        C: Signer,
        V: Variant,
    {
        Ok(self.blocks.get_header(digest, cfg).await?)
    }

    /// Decode and return the full block for `digest`.
    ///
    /// This is the body-fetching path. Header-only callers should use
    /// [`Self::header_by_digest`] or the certified height/latest helpers.
    pub async fn block_by_digest<H, C, V>(
        &self,
        digest: &H::Digest,
        cfg: &EngineBlockCfg<C, V>,
    ) -> Result<Option<EngineBlock<H, C, V>>, ReadError>
    where
        H: Hasher,
        C: Signer,
        V: Variant,
    {
        let Some(data) = self
            .blocks
            .get_block::<EngineHeader<H, C, V>, H::Digest>(digest, &cfg.payload)
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
    pub async fn certified_header_by_height<H, C, V, S>(
        &self,
        height: u64,
        cfg: &<Finalized<CertifiedHeader<H, C, V>, S, Commitment> as Read>::Cfg,
    ) -> Result<Option<CertifiedHeader<H, C, V>>, ReadError>
    where
        H: Hasher,
        C: Signer,
        V: Variant,
        S: Scheme,
        <S::Certificate as Read>::Cfg: Clone,
    {
        Ok(self
            .blocks
            .get_finalized_by_height::<CertifiedHeader<H, C, V>, S, Commitment>(
                Height::new(height),
                cfg,
            )
            .await?
            .map(|finalized| finalized.header))
    }

    /// Fetch the certified block-header digest at `height`.
    pub async fn digest_by_height<H, C, V, S>(
        &self,
        height: u64,
        cfg: &<Finalized<CertifiedHeader<H, C, V>, S, Commitment> as Read>::Cfg,
    ) -> Result<Option<H::Digest>, ReadError>
    where
        H: Hasher,
        C: Signer,
        V: Variant,
        S: Scheme,
        <S::Certificate as Read>::Cfg: Clone,
    {
        Ok(self
            .certified_header_by_height::<H, C, V, S>(height, cfg)
            .await?
            .map(|header| header.block_digest()))
    }

    /// Decode and return the certified full block at `height`.
    pub async fn block_by_height<H, C, V, S>(
        &self,
        height: u64,
        block_cfg: &EngineBlockCfg<C, V>,
        cert_cfg: &<Finalized<CertifiedHeader<H, C, V>, S, Commitment> as Read>::Cfg,
    ) -> Result<Option<EngineBlock<H, C, V>>, ReadError>
    where
        H: Hasher,
        C: Signer,
        V: Variant,
        S: Scheme,
        <S::Certificate as Read>::Cfg: Clone,
    {
        let Some(digest) = self
            .digest_by_height::<H, C, V, S>(height, cert_cfg)
            .await?
        else {
            return Ok(None);
        };
        self.block_by_digest::<H, C, V>(&digest, block_cfg).await
    }

    /// Latest finalized block header, decoded from the Simplex finalization
    /// height index without fetching the block body.
    pub async fn latest_certified_header<H, C, V, S>(
        &self,
        cfg: &<Finalized<CertifiedHeader<H, C, V>, S, Commitment> as Read>::Cfg,
    ) -> Result<Option<CertifiedHeader<H, C, V>>, ReadError>
    where
        H: Hasher,
        C: Signer,
        V: Variant,
        S: Scheme,
        <S::Certificate as Read>::Cfg: Clone,
    {
        Ok(self
            .blocks
            .latest_finalized::<CertifiedHeader<H, C, V>, S, Commitment>(cfg)
            .await?
            .map(|finalized| finalized.header))
    }

    /// Latest finalized height from the certified Simplex finalization index.
    pub async fn latest_height<H, C, V, S>(
        &self,
        cfg: &<Finalized<CertifiedHeader<H, C, V>, S, Commitment> as Read>::Cfg,
    ) -> Result<Option<u64>, ReadError>
    where
        H: Hasher,
        C: Signer,
        V: Variant,
        S: Scheme,
        <S::Certificate as Read>::Cfg: Clone,
    {
        Ok(self
            .latest_certified_header::<H, C, V, S>(cfg)
            .await?
            .map(|header| header.height().get()))
    }

    /// Latest finalized full block. This fetches the body by digest after
    /// decoding the latest certified header.
    pub async fn latest_block<H, C, V, S>(
        &self,
        block_cfg: &EngineBlockCfg<C, V>,
        cert_cfg: &<Finalized<CertifiedHeader<H, C, V>, S, Commitment> as Read>::Cfg,
    ) -> Result<Option<EngineBlock<H, C, V>>, ReadError>
    where
        H: Hasher,
        C: Signer,
        V: Variant,
        S: Scheme,
        <S::Certificate as Read>::Cfg: Clone,
    {
        let Some(header) = self.latest_certified_header::<H, C, V, S>(cert_cfg).await? else {
            return Ok(None);
        };
        self.block_by_digest::<H, C, V>(&header.block_digest(), block_cfg)
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
    pub async fn finalization_by_view<H, C, V, S>(
        &self,
        view: u64,
        cfg: &<Finalized<CertifiedHeader<H, C, V>, S, Commitment> as Read>::Cfg,
    ) -> Result<Option<Finalized<CertifiedHeader<H, C, V>, S, Commitment>>, ReadError>
    where
        H: Hasher,
        C: Signer,
        V: Variant,
        S: Scheme,
        <S::Certificate as Read>::Cfg: Clone,
    {
        Ok(self
            .blocks
            .get_finalized_by_view::<CertifiedHeader<H, C, V>, S, Commitment>(View::new(view), cfg)
            .await?)
    }

    /// Fetch the encoded Simplex notarization artifact for `view`.
    pub async fn notarization_bytes(&self, view: u64) -> Result<Option<Bytes>, ReadError> {
        Ok(self.blocks.get_notarized_raw(View::new(view)).await?)
    }

    /// Decode the Simplex notarization artifact for `view`.
    pub async fn notarization_by_view<H, C, V, S>(
        &self,
        view: u64,
        cfg: &<Notarized<CertifiedHeader<H, C, V>, S, Commitment> as Read>::Cfg,
    ) -> Result<Option<Notarized<CertifiedHeader<H, C, V>, S, Commitment>>, ReadError>
    where
        H: Hasher,
        C: Signer,
        V: Variant,
        S: Scheme,
        <S::Certificate as Read>::Cfg: Clone,
    {
        Ok(self
            .blocks
            .get_notarized::<CertifiedHeader<H, C, V>, S, Commitment>(View::new(view), cfg)
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
    let mut remaining = Bytes::copy_from_slice(bytes);
    Transaction::<H::Digest>::read(&mut remaining).map_err(|error| {
        ReadError::SqlRow(format!(
            "tx_meta.body signed transaction does not contain a valid transaction body: {error}"
        ))
    })?;
    let body_len = bytes.len() - remaining.remaining();

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
    use commonware_cryptography::sha256::Sha256;

    #[test]
    fn verifies_variable_transaction_body_against_digest() {
        let mut bytes = committee_signed_transaction_golden();
        let digest = Sha256::hash(&[&bytes[..85]]);

        verify_signed_transaction_digest::<Sha256>(&bytes, &digest).expect("digest matches");

        bytes[77] = 0;
        let error = verify_signed_transaction_digest::<Sha256>(&bytes, &digest)
            .expect_err("mutated body should be rejected");
        assert!(matches!(error, ReadError::SqlRow(message) if message.contains("does not match")));

        bytes[77] = 1;
        bytes[85] ^= 1;
        verify_signed_transaction_digest::<Sha256>(&bytes, &digest)
            .expect("signature bytes are outside the transaction digest");
    }

    #[test]
    fn rejects_signed_transaction_bytes_without_full_variable_body() {
        let bytes = committee_signed_transaction_golden()[..84].to_vec();
        let digest = Sha256::hash(&[&bytes]);

        let error = verify_signed_transaction_digest::<Sha256>(&bytes, &digest)
            .expect_err("truncated body should be rejected");
        assert!(
            matches!(error, ReadError::SqlRow(message) if message.contains("valid transaction body"))
        );
    }

    fn committee_signed_transaction_golden() -> Vec<u8> {
        let sender = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let peer = [
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b,
            0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1,
            0x2a, 0xf4, 0x66, 0x0c,
        ];
        let mut signed = Vec::with_capacity(85 + 65);
        signed.push(0);
        signed.extend_from_slice(&sender);
        signed.push(0);
        signed.extend_from_slice(&7u64.to_be_bytes());
        signed.push(1);
        signed.extend_from_slice(&[0xac, 0x02]);
        signed.extend_from_slice(&peer);
        signed.push(1);
        signed.extend_from_slice(&[4, 192, 0, 2, 1, 0x1f, 0x90]);
        assert_eq!(signed.len(), 85);
        assert_eq!(
            Sha256::hash(&[&signed]).to_string(),
            "bfc66b7fd66a059d12a6805444f6120de1a4b927846ba6dc4395b8148ecb1a32"
        );
        signed.extend_from_slice(&[0; 65]);
        signed
    }
}
