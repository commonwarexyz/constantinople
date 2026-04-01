use crate::shared::{accept_transaction, build_signed_transaction_bytes, tx_url};
use clap::Args as ClapArgs;
use commonware_cryptography::{Sha256, Signer, ed25519};
use commonware_utils::hex;
use constantinople_primitives::Address;
use std::{
    collections::VecDeque,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    num::{NonZeroU32, NonZeroUsize},
    time::Duration,
};
use tokio::{
    task::JoinSet,
    time,
};

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Number of accounts to create.
    #[arg(long)]
    count: NonZeroUsize,
    /// Validator HTTP endpoint (e.g. http://localhost:8080).
    #[arg(long)]
    endpoint: String,
    /// Starting seed for deterministic key generation.
    #[arg(long, default_value_t = 0)]
    seed_start: u64,
    /// Starting nonce for every sender.
    #[arg(long, default_value_t = 0)]
    nonce: u64,
    /// Fixed submission rate in transactions per second.
    #[arg(long)]
    tps: NonZeroU32,
}

#[derive(Debug)]
struct RingTransfer {
    sender_index: usize,
    from: Address,
    to: Address,
    nonce: u64,
    tx_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct RingAccount {
    key: ed25519::PrivateKey,
    from: Address,
    to: Address,
    next_nonce: u64,
}

fn build_ring_accounts(count: NonZeroUsize, seed_start: u64, nonce: u64) -> Vec<RingAccount> {
    let count = count.get();

    let keys = (0..count)
        .map(|index| {
            let seed = seed_start + u64::try_from(index).expect("ring size exceeded u64");
            ed25519::PrivateKey::from_seed(seed)
        })
        .collect::<Vec<_>>();
    let addresses = keys
        .iter()
        .map(|key| Address::from_public_key(&mut Sha256::default(), &key.public_key()))
        .collect::<Vec<_>>();

    let mut accounts = Vec::with_capacity(count);
    for (index, key) in keys.iter().enumerate() {
        let from = addresses[index];
        let to = addresses[(index + 1) % count];
        accounts.push(RingAccount {
            key: key.clone(),
            from,
            to,
            next_nonce: nonce,
        });
    }

    accounts
}

fn next_ring_transfer(accounts: &[RingAccount], ready: &mut VecDeque<usize>) -> Option<RingTransfer> {
    let sender_index = ready.pop_front()?;
    let sender = &accounts[sender_index];

    Some(RingTransfer {
        sender_index,
        from: sender.from,
        to: sender.to,
        nonce: sender.next_nonce,
        tx_bytes: build_signed_transaction_bytes(&sender.key, sender.to, 1, sender.next_nonce),
    })
}

fn handle_submission_result(
    accounts: &mut [RingAccount],
    ready: &mut VecDeque<usize>,
    sender_index: usize,
    submission: Result<(), String>,
    completed: &mut usize,
    failed: &mut usize,
    from: Address,
    to: Address,
    nonce: u64,
) {
    *completed += 1;
    ready.push_back(sender_index);

    if submission.is_ok() {
        accounts[sender_index].next_nonce = nonce
            .checked_add(1)
            .expect("sender nonce overflowed");
        return;
    }

    *failed += 1;
    let from = hex(from.as_ref());
    let to = hex(to.as_ref());
    let err = submission.expect_err("failed submission should carry an error");
    eprintln!("{from} -> {to} nonce={nonce}: {err}");
}

fn drain_completed_submissions(
    accounts: &mut [RingAccount],
    ready: &mut VecDeque<usize>,
    tasks: &mut JoinSet<(usize, Address, Address, u64, Result<(), String>)>,
    completed: &mut usize,
    failed: &mut usize,
) {
    while let Some(result) = tasks.try_join_next() {
        let (sender_index, from, to, nonce, submission) =
            result.expect("spam task panicked");
        handle_submission_result(
            accounts,
            ready,
            sender_index,
            submission,
            completed,
            failed,
            from,
            to,
            nonce,
        );
    }
}

async fn stop_spammer(
    tasks: &mut JoinSet<(usize, Address, Address, u64, Result<(), String>)>,
) {
    println!("stopping spammer...");
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

async fn run_with_stop_flag<Submit, SubmitFuture>(
    args: Args,
    should_stop: Arc<AtomicBool>,
    submit: Submit,
) -> Result<(), String>
where
    Submit: Fn(reqwest::Client, String, Vec<u8>) -> SubmitFuture + Send + Sync + Clone + 'static,
    SubmitFuture: Future<Output = Result<(), String>> + Send + 'static,
{
    let mut accounts = build_ring_accounts(args.count, args.seed_start, args.nonce);
    let mut ready = (0..accounts.len()).collect::<VecDeque<_>>();
    let client = reqwest::Client::new();
    let url = tx_url(&args.endpoint);
    let mut tasks = JoinSet::new();
    let mut completed = 0usize;
    let mut failed = 0usize;
    let mut dispatched = 0u64;
    let started = time::Instant::now();
    let tps = u64::from(args.tps.get());

    println!(
        "submitting ring transfers to {url} at {} tx/s. Press Ctrl-C to stop.",
        args.tps
    );

    loop {
        drain_completed_submissions(
            &mut accounts,
            &mut ready,
            &mut tasks,
            &mut completed,
            &mut failed,
        );

        if should_stop.load(Ordering::Relaxed) {
            stop_spammer(&mut tasks).await;
            break;
        }

        let target = ((started.elapsed().as_nanos() * u128::from(tps)) / 1_000_000_000) as u64;
        let mut submitted = false;
        let mut stop_requested = false;

        while dispatched < target {
            if should_stop.load(Ordering::Relaxed) {
                stop_requested = true;
                break;
            }

            let Some(transfer) = next_ring_transfer(&accounts, &mut ready) else {
                break;
            };

            submitted = true;
            dispatched += 1;

            let client = client.clone();
            let endpoint = args.endpoint.clone();
            let submit = submit.clone();

            tasks.spawn(async move {
                let RingTransfer {
                    sender_index,
                    from,
                    to,
                    nonce,
                    tx_bytes,
                } = transfer;
                let result = submit(client, endpoint, tx_bytes).await;
                (sender_index, from, to, nonce, result)
            });
        }

        if stop_requested {
            stop_spammer(&mut tasks).await;
            break;
        }

        if submitted {
            tokio::task::yield_now().await;
            if should_stop.load(Ordering::Relaxed) {
                stop_spammer(&mut tasks).await;
                break;
            }
            continue;
        }

        if tasks.is_empty() {
            if should_stop.load(Ordering::Relaxed) {
                stop_spammer(&mut tasks).await;
                break;
            }
            time::sleep(Duration::from_millis(1)).await;
            continue;
        }

        tokio::select! {
            Some(result) = tasks.join_next() => {
                let (sender_index, from, to, nonce, submission) =
                    result.expect("spam task panicked");
                handle_submission_result(
                    &mut accounts,
                    &mut ready,
                    sender_index,
                    submission,
                    &mut completed,
                    &mut failed,
                    from,
                    to,
                    nonce,
                );
            }
            _ = time::sleep(Duration::from_millis(1)) => {}
        }

        if should_stop.load(Ordering::Relaxed) {
            stop_spammer(&mut tasks).await;
            break;
        }
    }

    println!("completed: {completed}");
    println!("failed: {failed}");

    if failed == 0 {
        return Ok(());
    }

    Err(format!("failed: {failed}"))
}

pub async fn run(args: Args) -> Result<(), String> {
    let should_stop = Arc::new(AtomicBool::new(false));
    let signal = should_stop.clone();
    tokio::spawn(async move {
        loop {
            let _ = tokio::signal::ctrl_c().await;
            signal.store(true, Ordering::Relaxed);
            break;
        }
    });

    run_with_stop_flag(args, should_stop, |client, endpoint, tx_bytes| async move {
        accept_transaction(&client, &endpoint, tx_bytes).await
    })
    .await
}

#[cfg(test)]
async fn run_until_stopped<Submit, SubmitFuture>(
    args: Args,
    should_stop: Arc<AtomicBool>,
    submit: Submit,
) -> Result<(), String>
where
    Submit: Fn(reqwest::Client, String, Vec<u8>) -> SubmitFuture + Send + Sync + Clone + 'static,
    SubmitFuture: Future<Output = Result<(), String>> + Send + 'static,
{
    run_with_stop_flag(args, should_stop, submit).await
}

#[cfg(test)]
fn start_stop_timer(delay: Duration, should_stop: Arc<AtomicBool>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        time::sleep(delay).await;
        should_stop.store(true, Ordering::Relaxed);
    })
}

#[cfg(test)]
fn test_args(tps: u32) -> Args {
    Args {
        count: NonZeroUsize::new(1).expect("count should be non-zero"),
        endpoint: "http://127.0.0.1:8080".to_string(),
        seed_start: 0,
        nonce: 0,
        tps: NonZeroU32::new(tps).expect("tps should be non-zero"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RingAccount, build_ring_accounts, next_ring_transfer, run_until_stopped,
        start_stop_timer, test_args,
    };
    use crate::shared::Digest;
    use commonware_codec::Read;
    use commonware_cryptography::{Sha256, ed25519};
    use constantinople_primitives::{Signed, Transaction, TransactionCfg};
    use std::{
        collections::VecDeque,
        num::NonZeroUsize,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::time;

    #[test]
    fn ring_accounts_wrap_back_to_the_first_account() {
        let accounts = build_ring_accounts(NonZeroUsize::new(3).unwrap(), 11, 7);

        assert_eq!(accounts.len(), 3);
        assert_eq!(accounts[0].to, accounts[1].from);
        assert_eq!(accounts[1].to, accounts[2].from);
        assert_eq!(accounts[2].to, accounts[0].from);
    }

    #[test]
    fn next_ring_transfer_increments_sender_nonce() {
        let accounts = build_ring_accounts(NonZeroUsize::new(2).unwrap(), 11, 7);
        let mut ready = VecDeque::from(vec![0usize, 1]);

        let first = next_ring_transfer(&accounts, &mut ready).expect("first transfer should exist");
        let second =
            next_ring_transfer(&accounts, &mut ready).expect("second transfer should exist");

        let first_decoded = Signed::<
            Transaction<Digest, ed25519::PublicKey>,
            Sha256,
            ed25519::Signature,
        >::read_cfg(
            &mut &first.tx_bytes[..], &TransactionCfg::default()
        )
        .expect("first ring transfer should decode");
        assert_eq!(first_decoded.value().nonce, 7);
        assert_eq!(first_decoded.value().value.get(), 1);

        let second_decoded = Signed::<
            Transaction<Digest, ed25519::PublicKey>,
            Sha256,
            ed25519::Signature,
        >::read_cfg(
            &mut &second.tx_bytes[..], &TransactionCfg::default()
        )
        .expect("second ring transfer should decode");
        assert_eq!(second_decoded.value().nonce, 7);

        let mut accounts = accounts;
        accounts[0].next_nonce = 8;
        ready.push_back(0);

        let third = next_ring_transfer(&accounts, &mut ready).expect("third transfer should exist");
        let third_decoded = Signed::<
            Transaction<Digest, ed25519::PublicKey>,
            Sha256,
            ed25519::Signature,
        >::read_cfg(
            &mut &third.tx_bytes[..], &TransactionCfg::default()
        )
        .expect("third ring transfer should decode");
        assert_eq!(third.from, first.from);
        assert_eq!(third_decoded.value().nonce, 8);
    }

    #[test]
    fn next_ring_transfer_skips_busy_senders() {
        let accounts: Vec<RingAccount> = build_ring_accounts(NonZeroUsize::new(3).unwrap(), 11, 7);
        let mut ready = VecDeque::from(vec![1usize, 2]);

        let first = next_ring_transfer(&accounts, &mut ready).expect("first transfer should exist");
        let second =
            next_ring_transfer(&accounts, &mut ready).expect("second transfer should exist");

        assert_ne!(first.sender_index, 0);
        assert_ne!(second.sender_index, 0);
        assert!(next_ring_transfer(&accounts, &mut ready).is_none());
    }

    #[tokio::test]
    async fn run_stops_promptly_while_submitting() {
        let should_stop = Arc::new(AtomicBool::new(false));
        let stopper = start_stop_timer(Duration::from_millis(10), should_stop.clone());
        let result = time::timeout(
            Duration::from_millis(100),
            run_until_stopped(test_args(100_000), should_stop, |_client, _endpoint, _tx_bytes| async {
                Ok(())
            }),
        )
        .await;

        stopper.await.expect("shutdown task should finish");

        assert!(result.is_ok(), "spammer should observe shutdown promptly");
        assert!(
            result
                .expect("spammer should finish before the timeout")
                .is_ok(),
            "spammer should stop cleanly"
        );
    }

    #[tokio::test]
    async fn run_submits_transactions_before_shutdown() {
        let should_stop = Arc::new(AtomicBool::new(false));
        let submissions = Arc::new(AtomicUsize::new(0));
        let stopper = start_stop_timer(Duration::from_millis(10), should_stop.clone());
        let submit_count = submissions.clone();

        let result = time::timeout(
            Duration::from_millis(100),
            run_until_stopped(
                test_args(100_000),
                should_stop,
                move |_client, _endpoint, _tx_bytes| {
                    let submissions = submit_count.clone();
                    async move {
                        submissions.fetch_add(1, Ordering::Relaxed);
                        Ok(())
                    }
                },
            ),
        )
        .await;

        stopper.await.expect("shutdown task should finish");

        assert!(result.is_ok(), "spammer should finish before the timeout");
        assert!(
            submissions.load(Ordering::Relaxed) > 0,
            "spammer should submit at least one transaction before shutdown"
        );
    }
}
