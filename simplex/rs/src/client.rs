use bytes::Bytes;
use commonware_codec::{Decode, Encode};
use commonware_consensus::{Block, Viewable};
use commonware_cryptography::{certificate, Digest};
use exoware_sdk::keys::Key;
use exoware_sdk::{
    ClientError, Namespace, PrefixedStoreClient, RangeMode, StoreBatchUpload, StoreClient,
    StoreWriteBatch,
};
use futures::future::BoxFuture;

use crate::error::SimplexError;
use crate::keys::{self, RecordKind};
use crate::types::{
    encode_block_data, BlockData, Finalized, Notarized, UploadReceipt, UploadSummary,
};

#[derive(Clone, Debug)]
pub struct PreparedEntry {
    pub key: Key,
    pub value: Bytes,
}

#[derive(Clone, Debug, Default)]
#[must_use]
pub struct PreparedUpload {
    entries: Vec<PreparedEntry>,
    summary: UploadSummary,
}

impl PreparedUpload {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn summary(&self) -> UploadSummary {
        self.summary
    }

    pub fn entries(&self) -> &[PreparedEntry] {
        &self.entries
    }

    pub fn extend(&mut self, other: PreparedUpload) {
        self.summary.headers += other.summary.headers;
        self.summary.blocks += other.summary.blocks;
        self.summary.notarizations += other.summary.notarizations;
        self.summary.finalizations += other.summary.finalizations;
        self.summary.finalized_height_indexes += other.summary.finalized_height_indexes;
        self.entries.extend(other.entries);
    }

    fn push(&mut self, key: Key, value: Bytes) {
        self.entries.push(PreparedEntry { key, value });
    }
}

/// Store-backed writer for Commonware Simplex blocks and certificates.
///
/// The writer stores five logical indexes:
///
/// - header bytes by header digest
/// - full `{ header, body }` bytes by header digest
/// - notarized `{ proof, header }` bytes by Simplex view
/// - finalized `{ proof, header }` bytes by Simplex view
/// - finalized `{ proof, header }` bytes by header height
#[derive(Clone, Debug)]
pub struct SimplexClient {
    client: StoreClient,
}

impl SimplexClient {
    /// Build a client over the canonical [`Namespace::Simplex`] keyspace — the
    /// safe default when the Store is co-tenanted with SQL/QMDB. Use
    /// [`Self::unprefixed`] only for a Store simplex owns exclusively.
    pub fn new(client: StoreClient) -> Self {
        Self::prefixed(client.for_namespace(Namespace::Simplex))
    }

    /// Build a client over a caller-chosen namespace.
    pub fn prefixed(client: PrefixedStoreClient) -> Self {
        Self::unprefixed(client.into_client())
    }

    /// Build a client over a raw, un-namespaced client — escape hatch for a
    /// Store simplex owns exclusively.
    pub fn unprefixed(client: StoreClient) -> Self {
        Self { client }
    }

    pub fn store_client(&self) -> &StoreClient {
        &self.client
    }

    pub fn into_store_client(self) -> StoreClient {
        self.client
    }

    pub fn prepare_header<B>(&self, header: &B) -> PreparedUpload
    where
        B: Block,
    {
        let mut prepared = PreparedUpload::new();
        prepared.summary.headers = 1;
        prepared.push(keys::header_by_digest(&header.digest()), header.encode());
        prepared
    }

    pub fn prepare_block<B>(&self, header: &B, body: impl Into<Bytes>) -> PreparedUpload
    where
        B: Block,
    {
        let body = body.into();
        let mut prepared = self.prepare_header(header);
        prepared.summary.blocks = 1;
        prepared.push(
            keys::block_by_digest(&header.digest()),
            encode_block_data(header, &body),
        );
        prepared
    }

    pub fn prepare_block_data<B>(&self, data: &BlockData<B>) -> PreparedUpload
    where
        B: Block,
    {
        self.prepare_block(&data.header, data.body.clone())
    }

    pub fn prepare_notarized<B, S, D>(
        &self,
        notarized: &Notarized<B, S, D>,
    ) -> Result<PreparedUpload, SimplexError>
    where
        B: Block<Digest = D>,
        S: certificate::Scheme,
        D: Digest,
    {
        if notarized.proof.proposal.payload != notarized.header.digest() {
            return Err(SimplexError::ProofBlockMismatch);
        }

        let mut prepared = self.prepare_header(&notarized.header);
        prepared.summary.notarizations = 1;
        prepared.push(
            keys::notarization_by_view(notarized.proof.view()),
            notarized.encode(),
        );
        Ok(prepared)
    }

    pub fn prepare_finalized<B, S, D>(
        &self,
        finalized: &Finalized<B, S, D>,
    ) -> Result<PreparedUpload, SimplexError>
    where
        B: Block<Digest = D>,
        S: certificate::Scheme,
        D: Digest,
    {
        if finalized.proof.proposal.payload != finalized.header.digest() {
            return Err(SimplexError::ProofBlockMismatch);
        }

        let mut prepared = self.prepare_header(&finalized.header);
        let encoded = finalized.encode();
        prepared.summary.finalizations = 1;
        prepared.summary.finalized_height_indexes = 1;
        prepared.push(
            keys::finalization_by_view(finalized.proof.view()),
            encoded.clone(),
        );
        prepared.push(
            keys::finalized_by_height(finalized.header.height()),
            encoded,
        );
        Ok(prepared)
    }

    pub fn stage_upload(
        &self,
        prepared: &PreparedUpload,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), SimplexError> {
        if prepared.is_empty() {
            return Err(SimplexError::EmptyUpload);
        }
        for entry in prepared.entries() {
            batch.push(&self.client, &entry.key, entry.value.clone())?;
        }
        Ok(())
    }

    pub async fn mark_upload_persisted(
        &self,
        prepared: PreparedUpload,
        sequence_number: u64,
    ) -> UploadReceipt {
        UploadReceipt {
            store_sequence_number: sequence_number,
            summary: prepared.summary,
        }
    }

    pub async fn mark_upload_failed(&self, _prepared: PreparedUpload, _err: impl ToString) {}

    pub async fn upload_header<B>(&self, header: &B) -> Result<UploadReceipt, SimplexError>
    where
        B: Block,
    {
        let prepared = self.prepare_header(header);
        self.commit_upload(&self.client, prepared).await
    }

    pub async fn upload_block<B>(
        &self,
        header: &B,
        body: impl Into<Bytes>,
    ) -> Result<UploadReceipt, SimplexError>
    where
        B: Block,
    {
        let prepared = self.prepare_block(header, body);
        self.commit_upload(&self.client, prepared).await
    }

    pub async fn upload_notarized<B, S, D>(
        &self,
        notarized: &Notarized<B, S, D>,
    ) -> Result<UploadReceipt, SimplexError>
    where
        B: Block<Digest = D>,
        S: certificate::Scheme,
        D: Digest,
    {
        let prepared = self.prepare_notarized(notarized)?;
        self.commit_upload(&self.client, prepared).await
    }

    pub async fn upload_finalized<B, S, D>(
        &self,
        finalized: &Finalized<B, S, D>,
    ) -> Result<UploadReceipt, SimplexError>
    where
        B: Block<Digest = D>,
        S: certificate::Scheme,
        D: Digest,
    {
        let prepared = self.prepare_finalized(finalized)?;
        self.commit_upload(&self.client, prepared).await
    }

    pub async fn get_header_raw<D: Digest>(
        &self,
        digest: &D,
    ) -> Result<Option<Bytes>, SimplexError> {
        self.get_raw(keys::header_by_digest(digest)).await
    }

    pub async fn get_block_raw<D: Digest>(
        &self,
        digest: &D,
    ) -> Result<Option<Bytes>, SimplexError> {
        self.get_raw(keys::block_by_digest(digest)).await
    }

    pub async fn get_notarized_raw(
        &self,
        view: commonware_consensus::types::View,
    ) -> Result<Option<Bytes>, SimplexError> {
        self.get_raw(keys::notarization_by_view(view)).await
    }

    pub async fn get_finalized_by_view_raw(
        &self,
        view: commonware_consensus::types::View,
    ) -> Result<Option<Bytes>, SimplexError> {
        self.get_raw(keys::finalization_by_view(view)).await
    }

    pub async fn get_finalized_by_height_raw(
        &self,
        height: commonware_consensus::types::Height,
    ) -> Result<Option<Bytes>, SimplexError> {
        self.get_raw(keys::finalized_by_height(height)).await
    }

    pub async fn latest_finalized_raw(&self) -> Result<Option<Bytes>, SimplexError> {
        self.latest_raw(RecordKind::FinalizedByHeight).await
    }

    pub async fn get_header<B, D>(
        &self,
        digest: &D,
        cfg: &<B as commonware_codec::Read>::Cfg,
    ) -> Result<Option<B>, SimplexError>
    where
        B: Block<Digest = D>,
        D: Digest,
    {
        self.decode_optional(self.get_header_raw(digest).await?, cfg)
    }

    pub async fn get_block<B, D>(
        &self,
        digest: &D,
        cfg: &<BlockData<B> as commonware_codec::Read>::Cfg,
    ) -> Result<Option<BlockData<B>>, SimplexError>
    where
        B: Block<Digest = D>,
        D: Digest,
    {
        self.decode_optional(self.get_block_raw(digest).await?, cfg)
    }

    pub async fn get_notarized<B, S, D>(
        &self,
        view: commonware_consensus::types::View,
        cfg: &<Notarized<B, S, D> as commonware_codec::Read>::Cfg,
    ) -> Result<Option<Notarized<B, S, D>>, SimplexError>
    where
        B: Block<Digest = D>,
        S: certificate::Scheme,
        D: Digest,
        <S::Certificate as commonware_codec::Read>::Cfg: Clone,
    {
        self.decode_optional(self.get_notarized_raw(view).await?, cfg)
    }

    pub async fn get_finalized_by_height<B, S, D>(
        &self,
        height: commonware_consensus::types::Height,
        cfg: &<Finalized<B, S, D> as commonware_codec::Read>::Cfg,
    ) -> Result<Option<Finalized<B, S, D>>, SimplexError>
    where
        B: Block<Digest = D>,
        S: certificate::Scheme,
        D: Digest,
        <S::Certificate as commonware_codec::Read>::Cfg: Clone,
    {
        self.decode_optional(self.get_finalized_by_height_raw(height).await?, cfg)
    }

    pub async fn get_finalized_by_view<B, S, D>(
        &self,
        view: commonware_consensus::types::View,
        cfg: &<Finalized<B, S, D> as commonware_codec::Read>::Cfg,
    ) -> Result<Option<Finalized<B, S, D>>, SimplexError>
    where
        B: Block<Digest = D>,
        S: certificate::Scheme,
        D: Digest,
        <S::Certificate as commonware_codec::Read>::Cfg: Clone,
    {
        self.decode_optional(self.get_finalized_by_view_raw(view).await?, cfg)
    }

    pub async fn latest_finalized<B, S, D>(
        &self,
        cfg: &<Finalized<B, S, D> as commonware_codec::Read>::Cfg,
    ) -> Result<Option<Finalized<B, S, D>>, SimplexError>
    where
        B: Block<Digest = D>,
        S: certificate::Scheme,
        D: Digest,
        <S::Certificate as commonware_codec::Read>::Cfg: Clone,
    {
        self.decode_optional(self.latest_finalized_raw().await?, cfg)
    }

    async fn get_raw(&self, key: Key) -> Result<Option<Bytes>, SimplexError> {
        Ok(self.client.query().get(&key).await?)
    }

    async fn latest_raw(&self, kind: RecordKind) -> Result<Option<Bytes>, SimplexError> {
        let (start, end) = keys::range_for_kind(kind);
        let rows = self
            .client
            .query()
            .range_with_mode(&start, &end, 1, RangeMode::Reverse)
            .await?;
        Ok(rows.into_iter().next().map(|(_, value)| value))
    }

    fn decode_optional<T: Decode>(
        &self,
        value: Option<Bytes>,
        cfg: &T::Cfg,
    ) -> Result<Option<T>, SimplexError> {
        value
            .map(|bytes| T::decode_cfg(bytes, cfg).map_err(SimplexError::from))
            .transpose()
    }
}

impl StoreBatchUpload for SimplexClient {
    type Prepared = PreparedUpload;
    type Receipt = UploadReceipt;
    type Error = SimplexError;

    fn stage_upload(
        &self,
        prepared: &mut Self::Prepared,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), Self::Error> {
        SimplexClient::stage_upload(self, prepared, batch)
    }

    fn commit_error(&self, error: ClientError) -> Self::Error {
        SimplexError::Client(error)
    }

    fn mark_upload_persisted<'a>(
        &'a self,
        prepared: Self::Prepared,
        sequence_number: u64,
    ) -> BoxFuture<'a, Self::Receipt>
    where
        Self: Sync + 'a,
        Self::Prepared: 'a,
    {
        Box::pin(async move {
            SimplexClient::mark_upload_persisted(self, prepared, sequence_number).await
        })
    }

    fn mark_upload_failed<'a>(
        &'a self,
        prepared: Self::Prepared,
        error: String,
    ) -> BoxFuture<'a, ()>
    where
        Self: Sync + 'a,
        Self::Prepared: 'a,
    {
        Box::pin(async move {
            SimplexClient::mark_upload_failed(self, prepared, error).await;
        })
    }
}
