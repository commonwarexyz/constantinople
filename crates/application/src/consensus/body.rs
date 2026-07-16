//! Block body preparation and signature verification.

use super::{INVALID_SIGNATURE, Result};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, telemetry::traces::TracedExt as _};
use constantinople_primitives::{
    LazySignedTransaction, PublicKeyCache, preload_transaction_slice, verify_transaction_batch,
};
use rand::CryptoRng;
use std::{future::Future, sync::Arc};
use tracing::info_span;

pub(super) type PreparedBody<H> = Arc<Vec<LazySignedTransaction<H>>>;

/// Starts signature verification on the strategy's pool, returning a future
/// that resolves to the outcome.
pub(super) fn verify_signatures<E, H, St>(
    mut rng: E,
    namespace: &'static [u8],
    public_key_cache: PublicKeyCache,
    body: PreparedBody<H>,
    strategy: &St,
) -> impl Future<Output = Result<()>> + Send + 'static
where
    E: CryptoRng + Send + 'static,
    H: Hasher,
    St: Strategy,
{
    let span = info_span!("application.verify.signatures", txs = body.len().traced());
    strategy.spawn(move |strategy| {
        span.in_scope(|| {
            let transactions = body.as_ref().as_slice();
            (preload_transaction_slice(transactions, &strategy)
                && verify_transaction_batch::<H, _>(
                    namespace,
                    &mut rng,
                    &public_key_cache,
                    transactions,
                    &strategy,
                ))
            .then_some(())
            .ok_or(INVALID_SIGNATURE)
        })
    })
}

#[tracing::instrument(name = "application.verify.wait", level = "info", skip_all)]
pub(super) async fn wait_for_timestamp<E>(runtime: E, deadline: std::time::SystemTime) -> Result<()>
where
    E: Clock,
{
    runtime.sleep_until(deadline).await;
    Ok(())
}
