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

/// Starts signature verification, returning a future that resolves to the
/// outcome. The strategy may run the work inline.
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
    let work_size = body.len();
    strategy.spawn(work_size, move |strategy| {
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt as _, FixedSize as _, Write as _};
    use commonware_cryptography::sha256::Sha256;
    use commonware_parallel::{Rayon, rayon::ThreadPoolBuilder};
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::NZUsize;
    use rand::{SeedableRng as _, rngs::StdRng};
    use std::{
        sync::mpsc,
        time::{Duration, Instant},
    };

    #[test]
    fn cancelled_signature_wait_keeps_queued_body_alive() {
        deterministic::Runner::default().start(|context| async move {
            let pool = Arc::new(ThreadPoolBuilder::new().num_threads(2).build().unwrap());
            let strategy = Rayon::with_pool(Arc::clone(&pool));
            let (entered_tx, entered_rx) = mpsc::channel();
            let mut releases = Vec::new();
            for _ in 0..2 {
                let entered = entered_tx.clone();
                let (release_tx, release_rx) = mpsc::channel();
                releases.push(release_tx);
                pool.spawn(move || {
                    let _ = entered.send(());
                    let _ = release_rx.recv_timeout(Duration::from_secs(5));
                });
            }
            for _ in 0..2 {
                entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            }

            let payload_size = constantinople_primitives::Transaction::<
                commonware_cryptography::sha256::Digest,
            >::SIZE
                + constantinople_primitives::TransactionSignature::MIN_SIZE;
            let mut encoded = Vec::new();
            payload_size.write(&mut encoded);
            encoded.resize(encoded.len() + payload_size, 0xff);
            let body = Arc::new(vec![
                LazySignedTransaction::<Sha256>::decode(encoded).unwrap(),
            ]);
            let weak = Arc::downgrade(&body);
            let future = verify_signatures(
                StdRng::from_seed([13; 32]),
                b"queued-body-test",
                PublicKeyCache::new(context, NZUsize!(1)),
                Arc::clone(&body),
                &strategy,
            );

            drop(body);
            drop(future);

            assert_eq!(weak.strong_count(), 1);
            for release in releases {
                release.send(()).unwrap();
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            while weak.strong_count() != 0 && Instant::now() < deadline {
                std::thread::yield_now();
            }
            assert!(weak.upgrade().is_none());
        });
    }
}
