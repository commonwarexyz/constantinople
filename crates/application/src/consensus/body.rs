//! Block body preparation and signature verification.

use super::{
    INVALID_SIGNATURE, MALFORMED_TRANSACTION, MATERIALIZE_TASK_CLOSED, Result,
    SIGNATURE_TASK_CLOSED,
};
use commonware_codec::types::lazy::Lazy;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Spawner};
use constantinople_primitives::{
    SignedTransaction, materialize_transaction_chunks, preload_transaction_chunks,
    verify_transaction_batch,
};
use rand_core::CryptoRngCore;
use std::{sync::Arc, time::Instant};
use tracing::{Instrument, info_span};

pub(super) type PreparedBody<H> = Arc<Vec<Lazy<SignedTransaction<H>>>>;

pub(super) async fn verify_signatures<E, H, SigSt, HashSt>(
    runtime: E,
    signature_strategy: SigSt,
    hash_strategy: HashSt,
    namespace: &'static [u8],
    body: PreparedBody<H>,
) -> Result<u128>
where
    E: Spawner + CryptoRngCore,
    H: Hasher,
    SigSt: Strategy + Send + Sync + 'static,
    HashSt: Strategy + Send + Sync + 'static,
{
    let (result_tx, result_rx) = futures::channel::oneshot::channel();
    let transaction_count = body.len();
    let _handle = runtime.shared(true).spawn(move |mut runtime| {
        async move {
            let started_at = Instant::now();
            let result = preload_transaction_chunks(&hash_strategy, body.as_ref().clone())
                .filter(|transactions| {
                    verify_transaction_batch::<H, _>(
                        &signature_strategy,
                        namespace,
                        &mut runtime,
                        transactions,
                    )
                })
                .map(|_| started_at.elapsed().as_millis())
                .ok_or(INVALID_SIGNATURE);
            let _ = result_tx.send(result);
        }
        .instrument(info_span!(
            "application.verify.signatures",
            txs = transaction_count
        ))
    });

    result_rx.await.map_err(|_| SIGNATURE_TASK_CLOSED)?
}

pub(super) async fn materialize_body<E, H, HashSt>(
    runtime: E,
    hash_strategy: HashSt,
    transactions: Vec<Lazy<SignedTransaction<H>>>,
) -> Result<Vec<SignedTransaction<H>>>
where
    E: Spawner,
    H: Hasher,
    HashSt: Strategy + Send + Sync + 'static,
{
    let (result_tx, result_rx) = futures::channel::oneshot::channel();
    let transaction_count = transactions.len();
    let _handle = runtime.shared(true).spawn(move |_| {
        async move {
            let result = materialize_transaction_chunks(&hash_strategy, transactions)
                .ok_or(MALFORMED_TRANSACTION);
            let _ = result_tx.send(result);
        }
        .instrument(info_span!(
            "application.apply.materialize_body",
            txs = transaction_count
        ))
    });

    result_rx.await.map_err(|_| MATERIALIZE_TASK_CLOSED)?
}

pub(super) async fn wait_for_timestamp<E>(
    runtime: E,
    deadline: std::time::SystemTime,
) -> Result<u128>
where
    E: Clock,
{
    let started_at = Instant::now();
    runtime.sleep_until(deadline).await;
    Ok(started_at.elapsed().as_millis())
}
