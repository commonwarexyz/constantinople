//! Block body preparation and signature verification.

use super::{
    INVALID_SIGNATURE, MALFORMED_TRANSACTION, MATERIALIZE_TASK_CLOSED, Result,
    SIGNATURE_TASK_CLOSED,
};
use commonware_codec::types::lazy::Lazy;
use commonware_cryptography::{BatchVerifier, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Spawner};
use constantinople_primitives::{
    SignedTransaction, materialize_transaction_chunks, verify_transaction_chunks,
};
use rand_core::CryptoRngCore;
use std::{sync::Arc, time::Instant};
use tracing::{Instrument, info_span};

pub(super) type PreparedBody<P, H> = Arc<Vec<Lazy<SignedTransaction<P, H>>>>;

pub(super) async fn verify_signatures<E, P, H, B, SigSt, HashSt>(
    runtime: E,
    signature_strategy: SigSt,
    hash_strategy: HashSt,
    namespace: &'static [u8],
    body: PreparedBody<P, H>,
) -> Result<u128>
where
    E: Spawner + CryptoRngCore,
    P: PublicKey,
    H: Hasher,
    B: BatchVerifier<PublicKey = P> + Send + Sync + 'static,
    SigSt: Strategy + Send + Sync + 'static,
    HashSt: Strategy + Send + Sync + 'static,
{
    let (result_tx, result_rx) = futures::channel::oneshot::channel();
    let transaction_count = body.len();
    let _handle = runtime.shared(true).spawn(move |mut runtime| {
        async move {
            let started_at = Instant::now();
            let result = verify_transaction_chunks::<P, H, B, _, _>(
                &signature_strategy,
                &hash_strategy,
                namespace,
                &mut runtime,
                body.as_ref().clone(),
            )
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

pub(super) async fn materialize_body<E, P, H, HashSt>(
    runtime: E,
    hash_strategy: HashSt,
    transactions: Vec<Lazy<SignedTransaction<P, H>>>,
) -> Result<Vec<SignedTransaction<P, H>>>
where
    E: Spawner,
    P: PublicKey,
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
