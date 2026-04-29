//! Typed read-only wrapper around three [`StoreClient`]s.
//!
//! Constantinople fans its data out across three independent exoware stores:
//! one for blocks + consensus certificates, one for transactions, and one for
//! metadata. `IndexerClient` is the canonical way for tests and library
//! consumers to pull artifacts back out of those stores; it routes each query
//! to the store that owns the relevant key family.
//!
//! The struct does not own any sockets beyond the underlying [`StoreClient`]s,
//! so it is cheap to clone.

use crate::{codec, keys};
use bytes::Bytes;
use commonware_codec::Read;
use commonware_consensus::simplex::types::{Finalization, Notarization};
use commonware_cryptography::{Digest, Hasher, PublicKey, certificate::Scheme};
use constantinople_engine::types::EngineBlock;
use constantinople_primitives::{BlockCfg, SignedTransaction};
use exoware_sdk::{ClientError, RangeMode, StoreClient, keys::Key};

/// Errors returned when reading typed artifacts back out of the store.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// The underlying RPC failed.
    #[error("store error: {0}")]
    Store(#[from] ClientError),
    /// Decoding failed.
    #[error("decode error: {0}")]
    Codec(#[from] commonware_codec::Error),
    /// Stored value did not match the family's expected size.
    #[error("malformed value: expected {expected} bytes, got {got}")]
    Malformed { expected: usize, got: usize },
}

/// Typed read client over the three exoware [`StoreClient`]s that back the
/// indexer.
///
/// | Field          | Families served                                |
/// | -------------- | ---------------------------------------------- |
/// | `blocks`       | BLOCK, BLOCK_BY_H, FINALIZED, NOTARIZED        |
/// | `transactions` | TX, TX_BY_H                                    |
/// | `meta`         | META                                           |
#[derive(Clone, Debug)]
pub struct IndexerClient {
    blocks: StoreClient,
    transactions: StoreClient,
    meta: StoreClient,
}

impl IndexerClient {
    /// Wrap three existing [`StoreClient`]s, one per backing store.
    pub const fn new(blocks: StoreClient, transactions: StoreClient, meta: StoreClient) -> Self {
        Self {
            blocks,
            transactions,
            meta,
        }
    }

    /// Borrow the blocks-store [`StoreClient`] for raw access (e.g. streams).
    pub const fn blocks(&self) -> &StoreClient {
        &self.blocks
    }

    /// Borrow the transactions-store [`StoreClient`] for raw access.
    pub const fn transactions(&self) -> &StoreClient {
        &self.transactions
    }

    /// Borrow the meta-store [`StoreClient`] for raw access.
    pub const fn meta(&self) -> &StoreClient {
        &self.meta
    }

    /// Fetch the encoded block for `digest`, or `None` if absent.
    pub async fn block_bytes_by_digest<D: Digest>(
        &self,
        digest: &D,
    ) -> Result<Option<Bytes>, ReadError> {
        let key = keys::block(digest.as_ref()).expect("block digest fits family payload");
        Ok(self.blocks.query().get(&key).await?)
    }

    /// Decode and return the block for `digest`, or `None` if absent.
    pub async fn block_by_digest<H, P, D>(
        &self,
        digest: &D,
        cfg: &BlockCfg,
    ) -> Result<Option<EngineBlock<H, P>>, ReadError>
    where
        H: Hasher,
        P: PublicKey,
        D: Digest,
    {
        let Some(bytes) = self.block_bytes_by_digest(digest).await? else {
            return Ok(None);
        };
        Ok(Some(codec::from_bytes::<EngineBlock<H, P>>(&bytes, cfg)?))
    }

    /// Fetch the block digest at `height`, or `None` if absent.
    pub async fn digest_by_height<D: Digest>(&self, height: u64) -> Result<Option<D>, ReadError> {
        let key = keys::block_by_height(height).expect("u64 height fits family payload");
        let Some(bytes) = self.blocks.query().get(&key).await? else {
            return Ok(None);
        };
        Ok(Some(decode_digest::<D>(&bytes)?))
    }

    /// Decode and return the block at `height`, or `None` if absent.
    pub async fn block_by_height<H, P>(
        &self,
        height: u64,
        cfg: &BlockCfg,
    ) -> Result<Option<EngineBlock<H, P>>, ReadError>
    where
        H: Hasher,
        P: PublicKey,
    {
        let Some(digest) = self.digest_by_height::<H::Digest>(height).await? else {
            return Ok(None);
        };
        self.block_by_digest::<H, P, _>(&digest, cfg).await
    }

    /// Latest finalized block height stored in the META family, if any.
    pub async fn latest_height(&self) -> Result<Option<u64>, ReadError> {
        let key = keys::meta_latest_height().expect("meta key fits family payload");
        let Some(bytes) = self.meta.query().get(&key).await? else {
            return Ok(None);
        };
        if bytes.len() != 8 {
            return Err(ReadError::Malformed {
                expected: 8,
                got: bytes.len(),
            });
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes);
        Ok(Some(u64::from_be_bytes(buf)))
    }

    /// Latest indexed block, decoded.
    pub async fn latest_block<H, P>(
        &self,
        cfg: &BlockCfg,
    ) -> Result<Option<EngineBlock<H, P>>, ReadError>
    where
        H: Hasher,
        P: PublicKey,
    {
        let Some(height) = self.latest_height().await? else {
            return Ok(None);
        };
        self.block_by_height::<H, P>(height, cfg).await
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
    pub async fn transaction<H, P>(
        &self,
        digest: &H::Digest,
    ) -> Result<Option<SignedTransaction<P, H>>, ReadError>
    where
        H: Hasher,
        P: PublicKey,
    {
        let Some(bytes) = self.transaction_bytes(digest).await? else {
            return Ok(None);
        };
        Ok(Some(codec::from_bytes::<SignedTransaction<P, H>>(
            &bytes,
            &(),
        )?))
    }

    /// Fetch the encoded finalization certificate for `view`, or `None` if absent.
    pub async fn finalization_bytes(&self, view: u64) -> Result<Option<Bytes>, ReadError> {
        let key = keys::finalized(view).expect("u64 view fits family payload");
        Ok(self.blocks.query().get(&key).await?)
    }

    /// Decode and return the finalization certificate for `view`.
    pub async fn finalization<S, D>(
        &self,
        view: u64,
        cfg: &<Finalization<S, D> as Read>::Cfg,
    ) -> Result<Option<Finalization<S, D>>, ReadError>
    where
        S: Scheme,
        D: Digest,
    {
        let Some(bytes) = self.finalization_bytes(view).await? else {
            return Ok(None);
        };
        Ok(Some(codec::from_bytes::<Finalization<S, D>>(&bytes, cfg)?))
    }

    /// Fetch the encoded notarization certificate for `view`, or `None` if absent.
    pub async fn notarization_bytes(&self, view: u64) -> Result<Option<Bytes>, ReadError> {
        let key = keys::notarized(view).expect("u64 view fits family payload");
        Ok(self.blocks.query().get(&key).await?)
    }

    /// Decode and return the notarization certificate for `view`.
    pub async fn notarization<S, D>(
        &self,
        view: u64,
        cfg: &<Notarization<S, D> as Read>::Cfg,
    ) -> Result<Option<Notarization<S, D>>, ReadError>
    where
        S: Scheme,
        D: Digest,
    {
        let Some(bytes) = self.notarization_bytes(view).await? else {
            return Ok(None);
        };
        Ok(Some(codec::from_bytes::<Notarization<S, D>>(&bytes, cfg)?))
    }

    /// Stream every block stored under the `BLOCK_BY_H` family in ascending
    /// height order, returning `(height, digest)` pairs. Useful for backfill.
    pub async fn list_block_heights<D: Digest>(
        &self,
        limit: usize,
    ) -> Result<Vec<(u64, D)>, ReadError> {
        let (lo, hi) = keys::block_by_height_bounds();
        let rows = self
            .blocks
            .query()
            .range_with_mode(&lo, &hi, limit, RangeMode::Forward)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for (key, value) in rows {
            let height = decode_height(&key)?;
            let digest = decode_digest::<D>(&value)?;
            out.push((height, digest));
        }
        Ok(out)
    }
}

/// Decode an `H::Digest` from a stored 32-byte (or `D::SIZE`-byte) value.
fn decode_digest<D: Digest>(bytes: &[u8]) -> Result<D, ReadError> {
    let mut buf = bytes;
    D::read_cfg(&mut buf, &()).map_err(ReadError::from)
}

/// Decode the height from a `BLOCK_BY_H` key. The high bits hold the family
/// prefix, so we only look at the trailing 8 bytes of the key payload.
fn decode_height(key: &Key) -> Result<u64, ReadError> {
    let payload = keys::BLOCK_BY_H
        .decode(key, 8)
        .map_err(|_| ReadError::Malformed {
            expected: 8,
            got: key.len(),
        })?;
    if payload.len() != 8 {
        return Err(ReadError::Malformed {
            expected: 8,
            got: payload.len(),
        });
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&payload);
    Ok(u64::from_be_bytes(buf))
}
