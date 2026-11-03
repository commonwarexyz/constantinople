//! Publication-gated certificate ancestry and indexed navigation hints.

use super::*;
use crate::proto::{SearchKind, SearchResponse, WatchBlocksResponse};
use commonware_codec::Encode;
use futures::{Stream, stream};
use std::time::Duration;

const TARGET_PAGE: u64 = 64;
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const MAX_WATCH_RESPONSE_BYTES: usize = 3 * 1024 * 1024;

struct Feed {
    explorer: Arc<Explorer>,
    after: Option<u64>,
}

impl Feed {
    async fn next(&mut self) -> Result<WatchBlocksResponse, Failure> {
        loop {
            let next = tokio::time::timeout(READ_TIMEOUT, self.explorer.block_event(self.after))
                .await
                .map_err(|_| Failure::pending("block stream read timed out"))??;
            if let Some((height, batch)) = next {
                self.after = Some(height);
                return Ok(batch);
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
}

pub(super) fn events(
    explorer: Arc<Explorer>,
    after: Option<u64>,
) -> impl Stream<Item = Result<WatchBlocksResponse, ConnectError>> + Send + 'static {
    // The response owns the read future and bounded batch. Disconnecting drops
    // both, including any in-flight Store or SQL request.
    stream::try_unfold(Feed { explorer, after }, |mut feed| async move {
        let block = feed.next().await.map_err(ConnectError::from)?;
        Ok(Some((block, feed)))
    })
}

impl Explorer {
    async fn block_event(
        &self,
        after: Option<u64>,
    ) -> Result<Option<(u64, WatchBlocksResponse)>, Failure> {
        if after == Some(u64::MAX) {
            return Ok(None);
        }
        let Some(published) = self.published().await? else {
            return Ok(None);
        };
        let anchor = if let Some(height) = after {
            if height >= published.height {
                return Ok(None);
            }
            // Height bounds survive grouped Store publication. Prefer a full
            // small batch, but let a sparse certificate bridge a larger gap.
            let upper = height.saturating_add(TARGET_PAGE).min(published.height);
            match self
                .anchor_between(&published, height + 1, upper, None, true)
                .await?
            {
                Some(anchor) => Some(anchor),
                None if upper < published.height => {
                    self.anchor_between(&published, upper + 1, published.height, None, false)
                        .await?
                }
                None => None,
            }
        } else {
            self.anchor_between(&published, 1, published.height, None, true)
                .await?
        };
        let Some(anchor) = anchor else {
            return Ok(None);
        };
        let height = anchor.header.height;
        if after.is_some_and(|after| height - after > MAX_HEADERS) {
            return Err(Failure::limit("certificate gap exceeds 4096 heights"));
        }
        if anchor.header.encode().len() > MAX_HEADER_BYTES {
            return Err(Failure::limit("certified header exceeds 512 bytes"));
        }

        // A resumed batch includes the prior verified header as overlap. For
        // genesis, ancestry stops at height 1 because height 0 has no ordinary
        // certificate or uploaded header. Bootstrap needs only the head's parent.
        let first = after.map_or(height, |after| after + 1);
        let (headers, _, _, _) = self.ancestry(&anchor, first).await?;
        let batch = WatchBlocksResponse {
            sequence_number: anchor.floor()?,
            certificate: anchor.raw.to_vec(),
            headers,
            ..Default::default()
        };
        if batch.encoded_len() as usize > MAX_WATCH_RESPONSE_BYTES {
            return Err(Failure::limit("block batch exceeds 3 MiB"));
        }
        Ok(Some((height, batch)))
    }

    pub(super) async fn search(&self, value: [u8; 32]) -> Result<SearchResponse, Failure> {
        let literal = hex(&value);
        for (table, column, kind) in [
            ("account_meta", "account", SearchKind::Account),
            ("tx_meta", "tx_digest", SearchKind::Transaction),
        ] {
            let query =
                format!("SELECT {column} FROM {table} WHERE {column} = X'{literal}' LIMIT 1");
            if !query_rows(&self.sql, &query, 1).await?.is_empty() {
                return Ok(SearchResponse {
                    kind: kind.into(),
                    value: value.to_vec(),
                    ..Default::default()
                });
            }
        }
        Err(Failure(ErrorCode::NotFound, "no indexed match".to_string()))
    }
}

#[cfg(test)]
mod tests;
