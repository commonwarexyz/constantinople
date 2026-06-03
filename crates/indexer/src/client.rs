//! Typed read-only wrapper over Simplex block storage and raw transaction KV.
//!
//! Full blocks are stored in `exoware-simplex` as `{ header, body }` rows
//! keyed by the certified block-header digest. Height/latest reads go through
//! Simplex finalization indexes first, so callers can use the verified header
//! path without fetching the full body. Transaction bodies and secondary
//! transaction indexes remain in the raw KV families.

use crate::{codec, keys, publisher::certificate::CertifiedHeader};
use bytes::Bytes;
use commonware_codec::Read;
use commonware_consensus::{
    Heightable,
    types::{Height, View, coding::Commitment},
};
use commonware_cryptography::{Digest, Hasher, PublicKey, certificate::Scheme};
use constantinople_engine::types::{EngineBlock, EngineHeader};
use constantinople_primitives::{BlockCfg, SignedTransaction};
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
    /// Decoding failed.
    #[error("decode error: {0}")]
    Codec(#[from] commonware_codec::Error),
}

/// Typed read client over Simplex block rows and raw transaction KV rows.
///
/// | Field          | Families served                                  |
/// | -------------- | ------------------------------------------------ |
/// | `blocks`       | Simplex headers, blocks, notarizations, finals   |
/// | `transactions` | `TX`, `TX_BY_H`, `TX_BY_SENDER`                  |
#[derive(Clone, Debug)]
pub struct IndexerClient {
    blocks: SimplexClient,
    transactions: StoreClient,
}

impl IndexerClient {
    /// Wrap existing [`StoreClient`]s for block and transaction families.
    pub fn new(blocks: StoreClient, transactions: StoreClient) -> Self {
        Self {
            blocks: SimplexClient::from_client(blocks),
            transactions,
        }
    }

    /// Borrow the Simplex block client.
    pub const fn blocks(&self) -> &SimplexClient {
        &self.blocks
    }

    /// Borrow the transaction-family [`StoreClient`] for raw access.
    pub const fn transactions(&self) -> &StoreClient {
        &self.transactions
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

    /// Fetch the encoded transaction for `digest`, or `None` if absent.
    pub async fn transaction_bytes<D: Digest>(
        &self,
        digest: &D,
    ) -> Result<Option<Bytes>, ReadError> {
        let key = keys::tx(digest.as_ref()).expect("tx digest fits family payload");
        Ok(self.transactions.query().get(&key).await?)
    }

    /// Decode and return the transaction for `digest`, or `None` if absent.
    pub async fn transaction<H>(
        &self,
        digest: &H::Digest,
    ) -> Result<Option<SignedTransaction<H>>, ReadError>
    where
        H: Hasher,
    {
        let Some(bytes) = self.transaction_bytes(digest).await? else {
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
