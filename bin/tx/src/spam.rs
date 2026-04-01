use crate::shared::{accept_transaction, build_signed_transaction_bytes, tx_url};
use commonware_cryptography::{Sha256, Signer, ed25519};
use commonware_utils::hex;
use constantinople_primitives::Address;
use std::{
    collections::VecDeque,
    future::Future,
    num::{NonZeroU32, NonZeroUsize},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{task::JoinSet, time};

#[derive(Debug)]
pub struct Args {
    count: NonZeroUsize,
    endpoints: Vec<String>,
    seed_start: u64,
    nonce: u64,
    tps: NonZeroU32,
}

impl Args {
    pub(crate) fn new(
        count: usize,
        endpoints: Vec<String>,
        seed_start: u64,
        nonce: u64,
        tps: u32,
    ) -> Result<Self, String> {
        let count = NonZeroUsize::new(count).ok_or_else(|| "count must be non-zero".to_string())?;
        let tps = NonZeroU32::new(tps).ok_or_else(|| "tps must be non-zero".to_string())?;

        if endpoints.is_empty() {
            return Err("at least one endpoint is required".to_string());
        }

        Ok(Self {
            count,
            endpoints,
            seed_start,
            nonce,
            tps,
        })
    }

    #[cfg(test)]
    pub(crate) fn endpoints(&self) -> &[String] {
        &self.endpoints
    }

    #[cfg(test)]
    pub(crate) const fn count(&self) -> NonZeroUsize {
        self.count
    }

    #[cfg(test)]
    pub(crate) const fn tps(&self) -> NonZeroU32 {
        self.tps
    }

    #[cfg(test)]
    pub(crate) const fn seed_start(&self) -> u64 {
        self.seed_start
    }

    #[cfg(test)]
    pub(crate) const fn nonce(&self) -> u64 {
        self.nonce
    }
}

#[derive(Debug)]
struct RingTransfer {
    sender_index: usize,
    endpoint_index: usize,
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
    endpoint_index: usize,
    next_nonce: u64,
}

#[derive(Debug)]
struct EndpointState {
    endpoint: String,
    ready: VecDeque<usize>,
    dispatched: u64,
    completed: usize,
    failed: usize,
}

impl EndpointState {
    fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            ready: VecDeque::new(),
            dispatched: 0,
            completed: 0,
            failed: 0,
        }
    }
}

fn build_ring_accounts(
    count: NonZeroUsize,
    seed_start: u64,
    nonce: u64,
    endpoint_count: usize,
) -> Vec<RingAccount> {
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
            endpoint_index: index % endpoint_count,
            next_nonce: nonce,
        });
    }

    accounts
}

fn build_endpoint_states(endpoints: Vec<String>) -> Vec<EndpointState> {
    endpoints.into_iter().map(EndpointState::new).collect()
}

fn assign_accounts_to_endpoints(accounts: &[RingAccount], endpoints: &mut [EndpointState]) {
    for (sender_index, account) in accounts.iter().enumerate() {
        endpoints[account.endpoint_index]
            .ready
            .push_back(sender_index);
    }
}

fn endpoint_tps(total_tps: u64, endpoint_count: usize, endpoint_index: usize) -> u64 {
    let endpoint_count = u64::try_from(endpoint_count).expect("endpoint count exceeded u64");
    let base = total_tps / endpoint_count;
    let remainder = total_tps % endpoint_count;
    if u64::try_from(endpoint_index).expect("endpoint index exceeded u64") < remainder {
        return base + 1;
    }

    base
}

fn next_ring_transfer(
    accounts: &[RingAccount],
    ready: &mut VecDeque<usize>,
) -> Option<RingTransfer> {
    let sender_index = ready.pop_front()?;
    let sender = &accounts[sender_index];

    Some(RingTransfer {
        sender_index,
        endpoint_index: sender.endpoint_index,
        from: sender.from,
        to: sender.to,
        nonce: sender.next_nonce,
        tx_bytes: build_signed_transaction_bytes(&sender.key, sender.to, 1, sender.next_nonce),
    })
}

fn handle_submission_result(
    accounts: &mut [RingAccount],
    endpoints: &mut [EndpointState],
    sender_index: usize,
    endpoint_index: usize,
    submission: Result<(), String>,
    from: Address,
    to: Address,
    nonce: u64,
) {
    let endpoint = &mut endpoints[endpoint_index];
    endpoint.completed += 1;
    endpoint.ready.push_back(sender_index);

    if submission.is_ok() {
        accounts[sender_index].next_nonce = nonce.checked_add(1).expect("sender nonce overflowed");
        return;
    }

    endpoint.failed += 1;
    let from = hex(from.as_ref());
    let to = hex(to.as_ref());
    let err = submission.expect_err("failed submission should carry an error");
    eprintln!("{} {from} -> {to} nonce={nonce}: {err}", endpoint.endpoint);
}

fn drain_completed_submissions(
    accounts: &mut [RingAccount],
    endpoints: &mut [EndpointState],
    tasks: &mut JoinSet<(usize, usize, Address, Address, u64, Result<(), String>)>,
) {
    while let Some(result) = tasks.try_join_next() {
        let (sender_index, endpoint_index, from, to, nonce, submission) =
            result.expect("spam task panicked");
        handle_submission_result(
            accounts,
            endpoints,
            sender_index,
            endpoint_index,
            submission,
            from,
            to,
            nonce,
        );
    }
}

async fn stop_spammer(
    tasks: &mut JoinSet<(usize, usize, Address, Address, u64, Result<(), String>)>,
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
    let endpoint_count = args.endpoints.len();
    let mut accounts = build_ring_accounts(args.count, args.seed_start, args.nonce, endpoint_count);
    let mut endpoints = build_endpoint_states(args.endpoints);
    assign_accounts_to_endpoints(&accounts, &mut endpoints);
    let client = reqwest::Client::new();
    let mut tasks = JoinSet::new();
    let started = time::Instant::now();
    let tps = u64::from(args.tps.get());

    if endpoint_count == 1 {
        println!(
            "submitting ring transfers to {} at {} tx/s. Press Ctrl-C to stop.",
            tx_url(&endpoints[0].endpoint),
            args.tps
        );
    } else {
        println!(
            "submitting ring transfers across {endpoint_count} validators at {} tx/s. Press Ctrl-C to stop.",
            args.tps
        );
        for (endpoint_index, endpoint) in endpoints.iter().enumerate() {
            println!(
                "endpoint[{endpoint_index}] {} target_tps={}",
                tx_url(&endpoint.endpoint),
                endpoint_tps(tps, endpoint_count, endpoint_index)
            );
        }
    }

    loop {
        drain_completed_submissions(&mut accounts, &mut endpoints, &mut tasks);

        if should_stop.load(Ordering::Relaxed) {
            stop_spammer(&mut tasks).await;
            break;
        }

        let mut submitted = false;
        let mut stop_requested = false;

        for endpoint_index in 0..endpoint_count {
            let target = ((started.elapsed().as_nanos()
                * u128::from(endpoint_tps(tps, endpoint_count, endpoint_index)))
                / 1_000_000_000) as u64;

            while endpoints[endpoint_index].dispatched < target {
                if should_stop.load(Ordering::Relaxed) {
                    stop_requested = true;
                    break;
                }

                let Some(transfer) =
                    next_ring_transfer(&accounts, &mut endpoints[endpoint_index].ready)
                else {
                    break;
                };

                submitted = true;
                endpoints[endpoint_index].dispatched += 1;

                let client = client.clone();
                let endpoint = endpoints[endpoint_index].endpoint.clone();
                let submit = submit.clone();

                tasks.spawn(async move {
                    let RingTransfer {
                        sender_index,
                        endpoint_index,
                        from,
                        to,
                        nonce,
                        tx_bytes,
                    } = transfer;
                    let result = submit(client, endpoint, tx_bytes).await;
                    (sender_index, endpoint_index, from, to, nonce, result)
                });
            }

            if stop_requested {
                break;
            }
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
                let (sender_index, endpoint_index, from, to, nonce, submission) =
                    result.expect("spam task panicked");
                handle_submission_result(
                    &mut accounts,
                    &mut endpoints,
                    sender_index,
                    endpoint_index,
                    submission,
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

    let completed = endpoints
        .iter()
        .map(|endpoint| endpoint.completed)
        .sum::<usize>();
    let failed = endpoints
        .iter()
        .map(|endpoint| endpoint.failed)
        .sum::<usize>();
    println!("completed: {completed}");
    println!("failed: {failed}");
    for (endpoint_index, endpoint) in endpoints.iter().enumerate() {
        println!(
            "endpoint[{endpoint_index}] {} completed={} failed={}",
            tx_url(&endpoint.endpoint),
            endpoint.completed,
            endpoint.failed
        );
    }

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
    Args::new(1, vec!["http://127.0.0.1:8080".to_string()], 0, 0, tps)
        .expect("test args should be valid")
}

#[cfg(test)]
mod tests {
    use super::{
        Args, RingAccount, build_ring_accounts, next_ring_transfer, run_until_stopped,
        start_stop_timer, test_args,
    };
    use crate::shared::Digest;
    use commonware_codec::ReadExt;
    use commonware_cryptography::{Sha256, ed25519};
    use constantinople_primitives::{Signed, Transaction};
    use std::{
        collections::{HashSet, VecDeque},
        num::{NonZeroU32, NonZeroUsize},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::time;

    #[test]
    fn ring_accounts_wrap_back_to_the_first_account() {
        let accounts = build_ring_accounts(NonZeroUsize::new(3).unwrap(), 11, 7, 2);

        assert_eq!(accounts.len(), 3);
        assert_eq!(accounts[0].to, accounts[1].from);
        assert_eq!(accounts[1].to, accounts[2].from);
        assert_eq!(accounts[2].to, accounts[0].from);
    }

    #[test]
    fn next_ring_transfer_increments_sender_nonce() {
        let accounts = build_ring_accounts(NonZeroUsize::new(2).unwrap(), 11, 7, 1);
        let mut ready = VecDeque::from(vec![0usize, 1]);

        let first = next_ring_transfer(&accounts, &mut ready).expect("first transfer should exist");
        let second =
            next_ring_transfer(&accounts, &mut ready).expect("second transfer should exist");

        let first_decoded =
            Signed::<Transaction<Digest, ed25519::PublicKey>, Sha256, ed25519::Signature>::read(
                &mut &first.tx_bytes[..],
            )
            .expect("first ring transfer should decode");
        assert_eq!(first_decoded.value().nonce, 7);
        assert_eq!(first_decoded.value().value.get(), 1);

        let second_decoded =
            Signed::<Transaction<Digest, ed25519::PublicKey>, Sha256, ed25519::Signature>::read(
                &mut &second.tx_bytes[..],
            )
            .expect("second ring transfer should decode");
        assert_eq!(second_decoded.value().nonce, 7);

        let mut accounts = accounts;
        accounts[0].next_nonce = 8;
        ready.push_back(0);

        let third = next_ring_transfer(&accounts, &mut ready).expect("third transfer should exist");
        let third_decoded =
            Signed::<Transaction<Digest, ed25519::PublicKey>, Sha256, ed25519::Signature>::read(
                &mut &third.tx_bytes[..],
            )
            .expect("third ring transfer should decode");
        assert_eq!(third.from, first.from);
        assert_eq!(third_decoded.value().nonce, 8);
    }

    #[test]
    fn next_ring_transfer_skips_busy_senders() {
        let accounts: Vec<RingAccount> =
            build_ring_accounts(NonZeroUsize::new(3).unwrap(), 11, 7, 1);
        let mut ready = VecDeque::from(vec![1usize, 2]);

        let first = next_ring_transfer(&accounts, &mut ready).expect("first transfer should exist");
        let second =
            next_ring_transfer(&accounts, &mut ready).expect("second transfer should exist");

        assert_ne!(first.sender_index, 0);
        assert_ne!(second.sender_index, 0);
        assert!(next_ring_transfer(&accounts, &mut ready).is_none());
    }

    #[test]
    fn ring_accounts_are_sharded_across_endpoints() {
        let accounts = build_ring_accounts(NonZeroUsize::new(5).unwrap(), 11, 7, 2);

        assert_eq!(accounts[0].endpoint_index, 0);
        assert_eq!(accounts[1].endpoint_index, 1);
        assert_eq!(accounts[2].endpoint_index, 0);
        assert_eq!(accounts[3].endpoint_index, 1);
        assert_eq!(accounts[4].endpoint_index, 0);
    }

    #[test]
    fn single_account_ring_self_sends_correctly() {
        let accounts = build_ring_accounts(NonZeroUsize::new(1).unwrap(), 11, 7, 1);
        let mut ready = VecDeque::from(vec![0usize]);

        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].from, accounts[0].to);

        let transfer =
            next_ring_transfer(&accounts, &mut ready).expect("self-send transfer should exist");
        assert_eq!(transfer.from, transfer.to);
        assert_eq!(transfer.endpoint_index, 0);

        let decoded =
            Signed::<Transaction<Digest, ed25519::PublicKey>, Sha256, ed25519::Signature>::read(
                &mut &transfer.tx_bytes[..],
            )
            .expect("self-send transfer should decode");
        assert_eq!(decoded.value().to, transfer.from);
        assert_eq!(decoded.value().nonce, 7);
        assert_eq!(decoded.value().value.get(), 1);
    }

    #[tokio::test]
    async fn run_stops_promptly_while_submitting() {
        let should_stop = Arc::new(AtomicBool::new(false));
        let stopper = start_stop_timer(Duration::from_millis(10), should_stop.clone());
        let result = time::timeout(
            Duration::from_millis(100),
            run_until_stopped(
                test_args(100_000),
                should_stop,
                |_client, _endpoint, _tx_bytes| async { Ok(()) },
            ),
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

    #[tokio::test]
    async fn run_submits_to_multiple_endpoints() {
        let should_stop = Arc::new(AtomicBool::new(false));
        let stopper = start_stop_timer(Duration::from_millis(10), should_stop.clone());
        let seen_endpoints = Arc::new(Mutex::new(HashSet::new()));
        let seen = seen_endpoints.clone();
        let args = Args {
            count: NonZeroUsize::new(4).expect("count should be non-zero"),
            endpoints: vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
            ],
            seed_start: 0,
            nonce: 0,
            tps: NonZeroU32::new(100_000).expect("tps should be non-zero"),
        };

        let result = time::timeout(
            Duration::from_millis(100),
            run_until_stopped(args, should_stop, move |_client, endpoint, _tx_bytes| {
                let seen = seen.clone();
                async move {
                    seen.lock()
                        .expect("endpoint set lock should succeed")
                        .insert(endpoint);
                    Ok(())
                }
            }),
        )
        .await;

        stopper.await.expect("shutdown task should finish");

        assert!(result.is_ok(), "spammer should finish before the timeout");
        assert_eq!(
            seen_endpoints
                .lock()
                .expect("endpoint set lock should succeed")
                .len(),
            2,
            "spammer should use more than one endpoint"
        );
    }
}
