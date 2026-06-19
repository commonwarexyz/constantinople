//! Block body preparation and signature verification.

use super::{INVALID_SIGNATURE, Result, SIGNATURE_TASK_CLOSED};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Spawner, telemetry::traces::TracedExt as _};
use constantinople_primitives::{
    LazySignedTransaction, PublicKeyCache, preload_transaction_slice, verify_transaction_batch,
};
use rand_core::CryptoRngCore;
use std::sync::Arc;
use tracing::{Instrument, info_span};

pub(super) type PreparedBody<H> = Arc<Vec<LazySignedTransaction<H>>>;

pub(super) async fn verify_signatures<E, H, St>(
    runtime: E,
    namespace: &'static [u8],
    public_key_cache: PublicKeyCache,
    body: PreparedBody<H>,
    strategy: St,
) -> Result<()>
where
    E: Spawner + CryptoRngCore,
    H: Hasher,
    St: Strategy,
{
    let (result_tx, result_rx) = futures::channel::oneshot::channel();
    let transaction_count = body.len();
    let _handle = runtime.shared(true).spawn(move |mut runtime| {
        async move {
            let transactions = body.as_ref().as_slice();
            let result = (preload_transaction_slice(transactions, &strategy)
                && verify_transaction_batch::<H, _>(
                    namespace,
                    &mut runtime,
                    &public_key_cache,
                    transactions,
                    &strategy,
                ))
            .then_some(())
            .ok_or(INVALID_SIGNATURE);
            let _ = result_tx.send(result);
        }
        .instrument(info_span!(
            "application.verify.signatures",
            txs = transaction_count.traced()
        ))
    });

    result_rx.await.map_err(|_| SIGNATURE_TASK_CLOSED)?
}

#[tracing::instrument(name = "application.verify.wait", level = "info", skip_all)]
pub(super) async fn wait_for_timestamp<E>(runtime: E, deadline: std::time::SystemTime) -> Result<()>
where
    E: Clock,
{
    runtime.sleep_until(deadline).await;
    Ok(())
}
