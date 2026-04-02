use crate::shared::{
    TransactionState, accept_transaction, build_signed_transaction_bytes,
    fetch_transaction_statuses, transaction_hash_hex, tx_url,
};
use commonware_cryptography::{Sha256, Signer, ed25519};
use commonware_utils::hex;
use constantinople_primitives::Address;
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, VecDeque},
    future::Future,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{task::JoinSet, time};

const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const INITIAL_RETRY_BACKOFF: Duration = Duration::from_millis(100);
const MEMPOOL_FULL_RETRY_BACKOFF: Duration = Duration::from_secs(1);
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(5);
const STATUS_POLL_INTERVAL: Duration = Duration::from_secs(1);
const STATUS_POLL_BATCH_SIZE: usize = 32_768;
const MAX_SUBMISSION_TASKS_PER_ENDPOINT: usize = 256;

#[derive(Debug)]
pub struct Args {
    count: NonZeroUsize,
    endpoints: Vec<String>,
    seed_start: u64,
    nonce: u64,
}

impl Args {
    pub(crate) fn new(
        count: usize,
        endpoints: Vec<String>,
        seed_start: u64,
        nonce: u64,
    ) -> Result<Self, String> {
        let count = NonZeroUsize::new(count).ok_or_else(|| "count must be non-zero".to_string())?;
        if endpoints.is_empty() {
            return Err("at least one endpoint is required".to_string());
        }

        Ok(Self {
            count,
            endpoints,
            seed_start,
            nonce,
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
    pub(crate) const fn seed_start(&self) -> u64 {
        self.seed_start
    }

    #[cfg(test)]
    pub(crate) const fn nonce(&self) -> u64 {
        self.nonce
    }
}

#[derive(Debug, Clone)]
struct RingAccount {
    seed: u64,
    from: Address,
    to: Address,
    endpoint_index: usize,
}

#[derive(Debug, Clone)]
enum SenderStatus {
    Ready,
    Submitting,
    Pending(String),
    Included,
}

#[derive(Debug, Clone)]
struct SenderState {
    account: RingAccount,
    retry_backoff: Duration,
    status: SenderStatus,
}

#[derive(Debug)]
struct EndpointState {
    endpoint: String,
    sender_indices: Vec<usize>,
    ready: VecDeque<usize>,
    delayed: BinaryHeap<Reverse<(time::Instant, usize)>>,
    submission_tasks: usize,
    completed: usize,
    failed: usize,
}

impl EndpointState {
    fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            sender_indices: Vec::new(),
            ready: VecDeque::new(),
            delayed: BinaryHeap::new(),
            submission_tasks: 0,
            completed: 0,
            failed: 0,
        }
    }
}

#[derive(Debug)]
struct SubmissionOutcome {
    sender_index: usize,
    tx_hash: String,
    nonce: u64,
    result: Result<(), String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubmissionErrorKind {
    RetryRejected,
    RetryCheckStatus,
    Fatal,
}

type FetchStatusesFuture = std::pin::Pin<
    Box<dyn Future<Output = Result<Vec<crate::shared::TransactionStatus>, String>> + Send>,
>;

fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .timeout(HTTP_REQUEST_TIMEOUT)
        .pool_max_idle_per_host(MAX_SUBMISSION_TASKS_PER_ENDPOINT)
        .build()
        .expect("spammer HTTP client should build")
}

fn build_ring_accounts(
    count: NonZeroUsize,
    seed_start: u64,
    endpoint_count: usize,
) -> Vec<RingAccount> {
    let count = count.get();
    let mut addresses = Vec::with_capacity(count);

    for index in 0..count {
        let seed = seed_start + u64::try_from(index).expect("ring size exceeded u64");
        let key = ed25519::PrivateKey::from_seed(seed);
        addresses.push(Address::from_public_key(
            &mut Sha256::default(),
            &key.public_key(),
        ));
    }

    let mut accounts = Vec::with_capacity(count);
    for index in 0..count {
        let seed = seed_start + u64::try_from(index).expect("ring size exceeded u64");
        accounts.push(RingAccount {
            seed,
            from: addresses[index],
            to: addresses[(index + 1) % count],
            endpoint_index: index % endpoint_count,
        });
    }

    accounts
}

fn build_sender_states(accounts: Vec<RingAccount>) -> Vec<SenderState> {
    accounts
        .into_iter()
        .map(|account| SenderState {
            account,
            retry_backoff: INITIAL_RETRY_BACKOFF,
            status: SenderStatus::Ready,
        })
        .collect()
}

fn build_round_transaction_bytes(sender: &SenderState, nonce: u64) -> Vec<u8> {
    let key = ed25519::PrivateKey::from_seed(sender.account.seed);
    build_signed_transaction_bytes(&key, sender.account.to, 1, nonce)
}

fn build_endpoint_states(endpoints: Vec<String>, senders: &[SenderState]) -> Vec<EndpointState> {
    let mut endpoint_states = endpoints
        .into_iter()
        .map(EndpointState::new)
        .collect::<Vec<_>>();

    for (sender_index, sender) in senders.iter().enumerate() {
        endpoint_states[sender.account.endpoint_index]
            .sender_indices
            .push(sender_index);
    }

    endpoint_states
}

fn next_retry_backoff(current: Duration, err: &str) -> Duration {
    let mut next = current.saturating_mul(2).min(MAX_RETRY_BACKOFF);
    if err.contains("error (503)")
        && err.contains("mempool full")
        && next < MEMPOOL_FULL_RETRY_BACKOFF
    {
        next = MEMPOOL_FULL_RETRY_BACKOFF;
    }
    next
}

fn classify_submission_error(err: &str) -> SubmissionErrorKind {
    if err.starts_with("request failed:") || err.starts_with("response body failed:") {
        return SubmissionErrorKind::RetryCheckStatus;
    }

    if ["408", "429", "500", "502", "503", "504"]
        .into_iter()
        .any(|code| err.contains(&format!("error ({code})")))
    {
        if err.contains("error (503)") && err.contains("mempool full") {
            return SubmissionErrorKind::RetryRejected;
        }

        return SubmissionErrorKind::RetryCheckStatus;
    }

    SubmissionErrorKind::Fatal
}

fn format_sender_failure(endpoint: &str, sender: &SenderState, nonce: u64, err: &str) -> String {
    let from = hex(sender.account.from.as_ref());
    let to = hex(sender.account.to.as_ref());
    format!("{endpoint} {from} -> {to} nonce={nonce}: {err}")
}

fn current_round_nonce(base_nonce: u64, round: u64) -> Result<u64, String> {
    base_nonce
        .checked_add(round)
        .ok_or_else(|| "round nonce overflowed".to_string())
}

fn sender_pending_hash(sender: &SenderState) -> Option<&str> {
    match &sender.status {
        SenderStatus::Pending(tx_hash) => Some(tx_hash),
        _ => None,
    }
}

fn start_round(endpoints: &mut [EndpointState], senders: &mut [SenderState]) {
    for sender in senders {
        sender.retry_backoff = INITIAL_RETRY_BACKOFF;
        sender.status = SenderStatus::Ready;
    }

    for endpoint in endpoints {
        endpoint.ready.clear();
        endpoint.delayed.clear();
        endpoint.submission_tasks = 0;

        for &sender_index in &endpoint.sender_indices {
            endpoint.ready.push_back(sender_index);
        }
    }
}

fn round_is_complete(senders: &[SenderState]) -> bool {
    senders
        .iter()
        .all(|sender| matches!(sender.status, SenderStatus::Included))
}

fn schedule_sender_retry(
    endpoints: &mut [EndpointState],
    senders: &mut [SenderState],
    sender_index: usize,
    ready_at: time::Instant,
) {
    senders[sender_index].status = SenderStatus::Ready;
    let endpoint_index = senders[sender_index].account.endpoint_index;
    endpoints[endpoint_index]
        .delayed
        .push(Reverse((ready_at, sender_index)));
}

fn activate_ready_senders(
    endpoints: &mut [EndpointState],
    senders: &[SenderState],
    now: time::Instant,
) {
    for endpoint in endpoints {
        while let Some(Reverse((ready_at, sender_index))) = endpoint.delayed.peek().copied() {
            if ready_at > now {
                break;
            }

            endpoint.delayed.pop();
            if !matches!(senders[sender_index].status, SenderStatus::Ready) {
                continue;
            }

            endpoint.ready.push_back(sender_index);
        }
    }
}

fn spawn_submissions<Submit, SubmitFuture>(
    endpoints: &mut [EndpointState],
    senders: &mut [SenderState],
    nonce: u64,
    tasks: &mut JoinSet<SubmissionOutcome>,
    client: &reqwest::Client,
    submit: &Submit,
) where
    Submit: Fn(reqwest::Client, String, Vec<u8>) -> SubmitFuture + Send + Sync + Clone + 'static,
    SubmitFuture: Future<Output = Result<String, String>> + Send + 'static,
{
    for endpoint in endpoints {
        while endpoint.submission_tasks < MAX_SUBMISSION_TASKS_PER_ENDPOINT {
            let Some(sender_index) = endpoint.ready.pop_front() else {
                break;
            };
            if !matches!(senders[sender_index].status, SenderStatus::Ready) {
                continue;
            }

            senders[sender_index].status = SenderStatus::Submitting;
            let tx_bytes = build_round_transaction_bytes(&senders[sender_index], nonce);
            let tx_hash =
                transaction_hash_hex(&tx_bytes).expect("generated tx bytes should decode");
            let endpoint_url = endpoint.endpoint.clone();
            let client = client.clone();
            let submit = submit.clone();

            endpoint.submission_tasks += 1;
            tasks.spawn(async move {
                let result = submit(client, endpoint_url, tx_bytes)
                    .await
                    .map(|returned_hash| {
                        if returned_hash == tx_hash {
                            returned_hash
                        } else {
                            tx_hash.clone()
                        }
                    });
                SubmissionOutcome {
                    sender_index,
                    tx_hash,
                    nonce,
                    result: result.map(|_| ()),
                }
            });
        }
    }
}

fn handle_submission_completion(
    endpoints: &mut [EndpointState],
    senders: &mut [SenderState],
    outcome: SubmissionOutcome,
    now: time::Instant,
) -> Result<(), String> {
    let SubmissionOutcome {
        sender_index,
        tx_hash,
        nonce,
        result,
    } = outcome;
    let endpoint_index = senders[sender_index].account.endpoint_index;
    endpoints[endpoint_index].submission_tasks = endpoints[endpoint_index]
        .submission_tasks
        .checked_sub(1)
        .expect("submission task counter underflowed");

    match result {
        Ok(()) => {
            senders[sender_index].retry_backoff = INITIAL_RETRY_BACKOFF;
            senders[sender_index].status = SenderStatus::Pending(tx_hash);
            Ok(())
        }
        Err(err) => match classify_submission_error(&err) {
            SubmissionErrorKind::Fatal => {
                endpoints[endpoint_index].failed += 1;
                Err(format_sender_failure(
                    &endpoints[endpoint_index].endpoint,
                    &senders[sender_index],
                    nonce,
                    &err,
                ))
            }
            SubmissionErrorKind::RetryRejected => {
                let retry_backoff = next_retry_backoff(senders[sender_index].retry_backoff, &err);
                senders[sender_index].retry_backoff = retry_backoff;
                schedule_sender_retry(endpoints, senders, sender_index, now + retry_backoff);
                Ok(())
            }
            SubmissionErrorKind::RetryCheckStatus => {
                let retry_backoff = next_retry_backoff(senders[sender_index].retry_backoff, &err);
                senders[sender_index].retry_backoff = retry_backoff;
                senders[sender_index].status = SenderStatus::Pending(tx_hash);
                Ok(())
            }
        },
    }
}

async fn poll_pending_statuses(
    endpoints: &mut [EndpointState],
    senders: &mut [SenderState],
    client: reqwest::Client,
    fetch_statuses: impl Fn(reqwest::Client, String, Vec<String>) -> FetchStatusesFuture + Clone,
    now: time::Instant,
) -> Result<(), String> {
    let mut retries = Vec::new();

    for endpoint in endpoints.iter_mut() {
        let pending_senders = endpoint
            .sender_indices
            .iter()
            .copied()
            .filter(|sender_index| sender_pending_hash(&senders[*sender_index]).is_some())
            .collect::<Vec<_>>();

        for chunk in pending_senders.chunks(STATUS_POLL_BATCH_SIZE) {
            let tx_hashes = chunk
                .iter()
                .map(|sender_index| {
                    sender_pending_hash(&senders[*sender_index])
                        .expect("pending sender must carry a tx hash")
                        .to_string()
                })
                .collect::<Vec<_>>();
            let statuses =
                match fetch_statuses(client.clone(), endpoint.endpoint.clone(), tx_hashes).await {
                    Ok(statuses) => statuses,
                    Err(err) => match classify_submission_error(&err) {
                        SubmissionErrorKind::Fatal => {
                            return Err(format!("{} status poll failed: {err}", endpoint.endpoint));
                        }
                        SubmissionErrorKind::RetryRejected
                        | SubmissionErrorKind::RetryCheckStatus => {
                            continue;
                        }
                    },
                };
            if statuses.len() != chunk.len() {
                return Err(format!(
                    "{} returned {} statuses for {} requested hashes",
                    endpoint.endpoint,
                    statuses.len(),
                    chunk.len()
                ));
            }

            for (sender_index, status) in chunk.iter().copied().zip(statuses) {
                let Some(current_hash) = sender_pending_hash(&senders[sender_index]) else {
                    continue;
                };
                if current_hash != status.tx_hash {
                    return Err(format!(
                        "{} returned mismatched tx hash {} for sender {}",
                        endpoint.endpoint, status.tx_hash, sender_index
                    ));
                }

                match status.state {
                    TransactionState::Pending => {}
                    TransactionState::Included => {
                        senders[sender_index].retry_backoff = INITIAL_RETRY_BACKOFF;
                        senders[sender_index].status = SenderStatus::Included;
                        endpoint.completed += 1;
                    }
                    TransactionState::Rejected => {
                        let retry_backoff =
                            next_retry_backoff(senders[sender_index].retry_backoff, "rejected");
                        senders[sender_index].retry_backoff = retry_backoff;
                        retries.push((sender_index, now + retry_backoff));
                    }
                    TransactionState::Unknown => {
                        let retry_backoff = senders[sender_index].retry_backoff;
                        retries.push((sender_index, now + retry_backoff));
                    }
                }
            }
        }
    }

    for (sender_index, ready_at) in retries {
        schedule_sender_retry(endpoints, senders, sender_index, ready_at);
    }

    Ok(())
}

fn print_startup(endpoints: &[EndpointState], sender_count: usize) {
    if endpoints.len() == 1 {
        println!(
            "running ring spammer with {sender_count} senders against {}. Press Ctrl-C to stop.",
            tx_url(&endpoints[0].endpoint)
        );
    } else {
        println!(
            "running ring spammer with {sender_count} senders across {} validators. Press Ctrl-C to stop.",
            endpoints.len()
        );
    }

    for (index, endpoint) in endpoints.iter().enumerate() {
        println!(
            "endpoint[{index}] {} senders={}",
            tx_url(&endpoint.endpoint),
            endpoint.sender_indices.len()
        );
    }
}

fn print_summary(endpoints: &[EndpointState], completed_rounds: u64) -> Result<(), String> {
    let completed = endpoints
        .iter()
        .map(|endpoint| endpoint.completed)
        .sum::<usize>();
    let failed = endpoints
        .iter()
        .map(|endpoint| endpoint.failed)
        .sum::<usize>();

    println!("rounds completed: {completed_rounds}");
    println!("completed: {completed}");
    println!("failed: {failed}");
    for (index, endpoint) in endpoints.iter().enumerate() {
        println!(
            "endpoint[{index}] {} senders={} completed={} failed={}",
            tx_url(&endpoint.endpoint),
            endpoint.sender_indices.len(),
            endpoint.completed,
            endpoint.failed
        );
    }

    if failed == 0 {
        return Ok(());
    }

    Err(format!("failed: {failed}"))
}

async fn stop_spammer(tasks: &mut JoinSet<SubmissionOutcome>) {
    println!("stopping spammer...");
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

async fn run_with_stop_flag<Submit, SubmitFuture>(
    args: Args,
    should_stop: Arc<AtomicBool>,
    submit: Submit,
    fetch_statuses: impl Fn(reqwest::Client, String, Vec<String>) -> FetchStatusesFuture
    + Send
    + Sync
    + Clone
    + 'static,
) -> Result<(), String>
where
    Submit: Fn(reqwest::Client, String, Vec<u8>) -> SubmitFuture + Send + Sync + Clone + 'static,
    SubmitFuture: Future<Output = Result<String, String>> + Send + 'static,
{
    let accounts = build_ring_accounts(args.count, args.seed_start, args.endpoints.len());
    let mut senders = build_sender_states(accounts);
    let mut endpoints = build_endpoint_states(args.endpoints, &senders);
    let client = build_http_client();
    let mut tasks = JoinSet::new();
    let mut next_status_poll = time::Instant::now();
    let mut completed_rounds = 0_u64;

    start_round(&mut endpoints, &mut senders);
    print_startup(&endpoints, args.count.get());

    loop {
        while let Some(result) = tasks.try_join_next() {
            let outcome = result.expect("submission task panicked");
            let now = time::Instant::now();
            handle_submission_completion(&mut endpoints, &mut senders, outcome, now)?;
        }

        let round_nonce = current_round_nonce(args.nonce, completed_rounds)?;
        let now = time::Instant::now();
        activate_ready_senders(&mut endpoints, &senders, now);

        if now >= next_status_poll {
            poll_pending_statuses(
                &mut endpoints,
                &mut senders,
                client.clone(),
                fetch_statuses.clone(),
                now,
            )
            .await?;
            next_status_poll = now + STATUS_POLL_INTERVAL;
        }

        if round_is_complete(&senders) {
            completed_rounds = completed_rounds
                .checked_add(1)
                .expect("completed round counter overflowed");
            println!("completed round {completed_rounds}");

            if should_stop.load(Ordering::Relaxed) {
                stop_spammer(&mut tasks).await;
                break;
            }

            start_round(&mut endpoints, &mut senders);
            next_status_poll = time::Instant::now();
            continue;
        }

        spawn_submissions(
            &mut endpoints,
            &mut senders,
            round_nonce,
            &mut tasks,
            &client,
            &submit,
        );

        if should_stop.load(Ordering::Relaxed) {
            stop_spammer(&mut tasks).await;
            break;
        }

        tokio::select! {
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                let outcome = result.expect("submission task panicked");
                let now = time::Instant::now();
                handle_submission_completion(&mut endpoints, &mut senders, outcome, now)?;
            }
            _ = time::sleep(Duration::from_millis(10)) => {}
        }
    }

    print_summary(&endpoints, completed_rounds)
}

async fn run_with_default_status_fetch<Submit, SubmitFuture>(
    args: Args,
    should_stop: Arc<AtomicBool>,
    submit: Submit,
) -> Result<(), String>
where
    Submit: Fn(reqwest::Client, String, Vec<u8>) -> SubmitFuture + Send + Sync + Clone + 'static,
    SubmitFuture: Future<Output = Result<String, String>> + Send + 'static,
{
    run_with_stop_flag(args, should_stop, submit, |client, endpoint, tx_hashes| {
        Box::pin(async move { fetch_transaction_statuses(&client, &endpoint, &tx_hashes).await })
    })
    .await
}

pub async fn run(args: Args) -> Result<(), String> {
    let should_stop = Arc::new(AtomicBool::new(false));
    let signal = should_stop.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        signal.store(true, Ordering::Relaxed);
    });

    run_with_default_status_fetch(args, should_stop, |client, endpoint, tx_bytes| async move {
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
    SubmitFuture: Future<Output = Result<String, String>> + Send + 'static,
{
    run_with_default_status_fetch(args, should_stop, submit).await
}

#[cfg(test)]
async fn run_until_stopped_with_statuses<Submit, SubmitFuture, Fetch>(
    args: Args,
    should_stop: Arc<AtomicBool>,
    submit: Submit,
    fetch_statuses: Fetch,
) -> Result<(), String>
where
    Submit: Fn(reqwest::Client, String, Vec<u8>) -> SubmitFuture + Send + Sync + Clone + 'static,
    SubmitFuture: Future<Output = Result<String, String>> + Send + 'static,
    Fetch: Fn(reqwest::Client, String, Vec<String>) -> FetchStatusesFuture
        + Send
        + Sync
        + Clone
        + 'static,
{
    run_with_stop_flag(args, should_stop, submit, fetch_statuses).await
}

#[cfg(test)]
fn start_stop_timer(delay: Duration, should_stop: Arc<AtomicBool>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        time::sleep(delay).await;
        should_stop.store(true, Ordering::Relaxed);
    })
}

#[cfg(test)]
fn test_args(count: usize) -> Args {
    Args::new(count, vec!["http://127.0.0.1:8080".to_string()], 0, 0)
        .expect("test args should be valid")
}

#[cfg(test)]
mod tests {
    use super::{
        Args, MAX_SUBMISSION_TASKS_PER_ENDPOINT, build_ring_accounts,
        build_round_transaction_bytes, build_sender_states, classify_submission_error,
        next_retry_backoff, run_until_stopped, run_until_stopped_with_statuses, start_stop_timer,
        test_args,
    };
    use crate::shared::{TransactionState, TransactionStatus, transaction_hash_hex};
    use commonware_codec::{Encode, ReadExt};
    use commonware_cryptography::{Sha256, ed25519};
    use commonware_utils::hex;
    use constantinople_primitives::{Signed, Transaction};
    use std::{
        collections::{HashMap, HashSet},
        num::NonZeroUsize,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::time;

    fn decode_sender_and_nonce(tx_bytes: &[u8]) -> (String, u64) {
        let decoded: Signed<
            Transaction<crate::shared::Digest, ed25519::PublicKey>,
            Sha256,
            ed25519::Signature,
        > = Signed::read(&mut &tx_bytes[..]).expect("ring transfer should decode");
        (hex(&decoded.value().sender.encode()), decoded.value().nonce)
    }

    fn is_retryable_submission_error(err: &str) -> bool {
        !matches!(
            classify_submission_error(err),
            super::SubmissionErrorKind::Fatal
        )
    }

    #[test]
    fn ring_accounts_wrap_back_to_the_first_account() {
        let accounts = build_ring_accounts(NonZeroUsize::new(3).unwrap(), 11, 2);

        assert_eq!(accounts.len(), 3);
        assert_eq!(accounts[0].to, accounts[1].from);
        assert_eq!(accounts[1].to, accounts[2].from);
        assert_eq!(accounts[2].to, accounts[0].from);
    }

    #[test]
    fn ring_accounts_are_sharded_across_endpoints() {
        let accounts = build_ring_accounts(NonZeroUsize::new(5).unwrap(), 11, 2);

        assert_eq!(accounts[0].endpoint_index, 0);
        assert_eq!(accounts[1].endpoint_index, 1);
        assert_eq!(accounts[2].endpoint_index, 0);
        assert_eq!(accounts[3].endpoint_index, 1);
        assert_eq!(accounts[4].endpoint_index, 0);
    }

    #[test]
    fn transaction_hash_matches_generated_bytes() {
        let senders =
            build_sender_states(build_ring_accounts(NonZeroUsize::new(1).unwrap(), 11, 1));
        let sender = &senders[0];
        let tx_bytes = build_round_transaction_bytes(sender, 7);
        let tx_hash = transaction_hash_hex(&tx_bytes).expect("tx hash should decode");
        let (_sender, nonce) = decode_sender_and_nonce(&tx_bytes);

        assert!(!tx_hash.is_empty());
        assert_eq!(nonce, 7);
    }

    #[test]
    fn retries_network_and_server_overload_errors() {
        assert!(is_retryable_submission_error("request failed: timed out"));
        assert!(is_retryable_submission_error("error (503): mempool full"));
        assert!(!is_retryable_submission_error(
            "error (400): bad transaction"
        ));
    }

    #[test]
    fn mempool_full_backoff_has_minimum_floor() {
        assert_eq!(
            next_retry_backoff(Duration::from_millis(100), "error (503): mempool full"),
            Duration::from_secs(1)
        );
    }

    #[tokio::test]
    async fn run_stops_promptly_while_submitting() {
        let should_stop = Arc::new(AtomicBool::new(false));
        let stopper = start_stop_timer(Duration::from_millis(10), should_stop.clone());
        let result = time::timeout(
            Duration::from_millis(200),
            run_until_stopped(
                test_args(4),
                should_stop,
                |_client, _endpoint, _tx_bytes| async {
                    time::sleep(Duration::from_secs(60)).await;
                    Ok(String::new())
                },
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
    async fn run_submits_to_multiple_endpoints() {
        let should_stop = Arc::new(AtomicBool::new(false));
        let seen_endpoints = Arc::new(Mutex::new(HashSet::new()));
        let seen = seen_endpoints.clone();
        let signal = should_stop.clone();
        let args = Args::new(
            4,
            vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
            ],
            0,
            0,
        )
        .expect("args should be valid");

        let result = time::timeout(
            Duration::from_millis(500),
            run_until_stopped(args, should_stop, move |_client, endpoint, _tx_bytes| {
                let seen = seen.clone();
                let signal = signal.clone();
                async move {
                    let count = {
                        let mut seen = seen.lock().expect("endpoint set lock should succeed");
                        seen.insert(endpoint);
                        seen.len()
                    };
                    if count == 2 {
                        signal.store(true, Ordering::Relaxed);
                    }
                    Ok("hash".to_string())
                }
            }),
        )
        .await;

        assert!(result.is_ok(), "spammer should finish before the timeout");
        assert_eq!(
            seen_endpoints
                .lock()
                .expect("endpoint set lock should succeed")
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn run_waits_for_full_round_before_advancing_nonce() {
        let should_stop = Arc::new(AtomicBool::new(false));
        let round_zero_submissions = Arc::new(AtomicUsize::new(0));
        let round_one_submissions = Arc::new(AtomicUsize::new(0));
        let round_zero_included = Arc::new(AtomicBool::new(false));
        let saw_premature_round_one = Arc::new(AtomicBool::new(false));
        let nonce_by_hash = Arc::new(Mutex::new(HashMap::<String, u64>::new()));
        let signal = should_stop.clone();
        let round_zero_submissions_for_submit = round_zero_submissions.clone();
        let round_zero_submissions_for_status = round_zero_submissions.clone();
        let round_one_submissions_for_submit = round_one_submissions.clone();
        let round_zero_included_for_submit = round_zero_included.clone();
        let round_zero_included_for_status = round_zero_included.clone();
        let saw_premature_round_one_for_submit = saw_premature_round_one.clone();
        let nonce_by_hash_for_submit = nonce_by_hash.clone();
        let nonce_by_hash_for_status = nonce_by_hash.clone();

        let result = time::timeout(
            Duration::from_secs(2),
            run_until_stopped_with_statuses(
                test_args(2),
                should_stop,
                move |_client, _endpoint, tx_bytes| {
                    let round_zero_submissions = round_zero_submissions_for_submit.clone();
                    let round_one_submissions = round_one_submissions_for_submit.clone();
                    let round_zero_included = round_zero_included_for_submit.clone();
                    let saw_premature_round_one = saw_premature_round_one_for_submit.clone();
                    let nonce_by_hash = nonce_by_hash_for_submit.clone();
                    let signal = signal.clone();
                    async move {
                        let (_sender, nonce) = decode_sender_and_nonce(&tx_bytes);
                        let hash = transaction_hash_hex(&tx_bytes).expect("tx hash should decode");
                        nonce_by_hash
                            .lock()
                            .expect("nonce map lock should succeed")
                            .insert(hash.clone(), nonce);

                        match nonce {
                            0 => {
                                round_zero_submissions.fetch_add(1, Ordering::SeqCst);
                            }
                            1 => {
                                if !round_zero_included.load(Ordering::SeqCst) {
                                    saw_premature_round_one.store(true, Ordering::SeqCst);
                                }
                                let count =
                                    round_one_submissions.fetch_add(1, Ordering::SeqCst) + 1;
                                if count == 2 {
                                    signal.store(true, Ordering::Relaxed);
                                }
                            }
                            other => panic!("unexpected nonce submitted in test: {other}"),
                        }

                        Ok(hash)
                    }
                },
                move |_client, _endpoint, tx_hashes| {
                    let round_zero_submissions = round_zero_submissions_for_status.clone();
                    let round_zero_included = round_zero_included_for_status.clone();
                    let nonce_by_hash = nonce_by_hash_for_status.clone();
                    Box::pin(async move {
                        let nonce_by_hash =
                            nonce_by_hash.lock().expect("nonce map lock should succeed");
                        let statuses = tx_hashes
                            .into_iter()
                            .map(|tx_hash| {
                                let nonce = nonce_by_hash
                                    .get(&tx_hash)
                                    .copied()
                                    .expect("every pending hash should be recorded");
                                let state = if nonce == 0 {
                                    if round_zero_submissions.load(Ordering::SeqCst) == 2 {
                                        round_zero_included.store(true, Ordering::SeqCst);
                                        TransactionState::Included
                                    } else {
                                        TransactionState::Pending
                                    }
                                } else if round_zero_included.load(Ordering::SeqCst) {
                                    TransactionState::Included
                                } else {
                                    TransactionState::Pending
                                };

                                TransactionStatus {
                                    tx_hash,
                                    state,
                                    height: 1,
                                }
                            })
                            .collect::<Vec<_>>();
                        Ok(statuses)
                    })
                },
            ),
        )
        .await;

        assert!(result.is_ok(), "spammer should finish");
        assert!(round_zero_included.load(Ordering::SeqCst));
        assert!(!saw_premature_round_one.load(Ordering::SeqCst));
        assert_eq!(round_one_submissions.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn run_retries_same_nonce_until_round_tx_is_accepted() {
        let should_stop = Arc::new(AtomicBool::new(false));
        let attempts = Arc::new(Mutex::new(Vec::<u64>::new()));
        let signal = should_stop.clone();
        let attempts_for_submit = attempts.clone();

        let result = time::timeout(
            Duration::from_secs(4),
            run_until_stopped_with_statuses(
                test_args(1),
                should_stop,
                move |_client, _endpoint, tx_bytes| {
                    let attempts = attempts_for_submit.clone();
                    async move {
                        let (_sender, nonce) = decode_sender_and_nonce(&tx_bytes);
                        let attempt_number = {
                            let mut attempts =
                                attempts.lock().expect("attempt list lock should succeed");
                            attempts.push(nonce);
                            attempts.len()
                        };
                        if attempt_number == 1 {
                            return Err("error (503): mempool full".to_string());
                        }

                        transaction_hash_hex(&tx_bytes)
                    }
                },
                move |_client, _endpoint, tx_hashes| {
                    let signal = signal.clone();
                    Box::pin(async move {
                        signal.store(true, Ordering::Relaxed);
                        Ok(tx_hashes
                            .into_iter()
                            .map(|tx_hash| TransactionStatus {
                                tx_hash,
                                state: TransactionState::Included,
                                height: 1,
                            })
                            .collect())
                    })
                },
            ),
        )
        .await;

        assert!(result.is_ok(), "spammer should finish");
        assert_eq!(
            *attempts.lock().expect("attempt list lock should succeed"),
            vec![0, 0]
        );
    }

    #[tokio::test]
    async fn run_retries_same_nonce_after_mempool_rejection() {
        let should_stop = Arc::new(AtomicBool::new(false));
        let attempts = Arc::new(Mutex::new(Vec::<u64>::new()));
        let status_polls = Arc::new(AtomicUsize::new(0));
        let signal = should_stop.clone();
        let attempts_for_submit = attempts.clone();
        let status_polls_for_fetch = status_polls.clone();

        let result = time::timeout(
            Duration::from_secs(4),
            run_until_stopped_with_statuses(
                test_args(1),
                should_stop,
                move |_client, _endpoint, tx_bytes| {
                    let attempts = attempts_for_submit.clone();
                    async move {
                        let (_sender, nonce) = decode_sender_and_nonce(&tx_bytes);
                        attempts
                            .lock()
                            .expect("attempt list lock should succeed")
                            .push(nonce);
                        transaction_hash_hex(&tx_bytes)
                    }
                },
                move |_client, _endpoint, tx_hashes| {
                    let signal = signal.clone();
                    let status_polls = status_polls_for_fetch.clone();
                    Box::pin(async move {
                        let poll_number = status_polls.fetch_add(1, Ordering::SeqCst);
                        let state = if poll_number == 0 {
                            TransactionState::Rejected
                        } else {
                            signal.store(true, Ordering::Relaxed);
                            TransactionState::Included
                        };

                        Ok(tx_hashes
                            .into_iter()
                            .map(|tx_hash| TransactionStatus {
                                tx_hash,
                                state: state.clone(),
                                height: 1,
                            })
                            .collect())
                    })
                },
            ),
        )
        .await;

        assert!(result.is_ok(), "spammer should finish");
        assert_eq!(
            *attempts.lock().expect("attempt list lock should succeed"),
            vec![0, 0]
        );
    }

    #[tokio::test]
    async fn run_retries_status_poll_failures_without_exiting() {
        let should_stop = Arc::new(AtomicBool::new(false));
        let status_polls = Arc::new(AtomicUsize::new(0));
        let signal = should_stop.clone();
        let status_polls_for_fetch = status_polls.clone();

        let result = time::timeout(
            Duration::from_secs(4),
            run_until_stopped_with_statuses(
                test_args(1),
                should_stop,
                move |_client, _endpoint, tx_bytes| async move { transaction_hash_hex(&tx_bytes) },
                move |_client, _endpoint, tx_hashes| {
                    let signal = signal.clone();
                    let status_polls = status_polls_for_fetch.clone();
                    Box::pin(async move {
                        let poll_number = status_polls.fetch_add(1, Ordering::SeqCst);
                        if poll_number == 0 {
                            return Err("request failed: timed out".to_string());
                        }

                        signal.store(true, Ordering::Relaxed);
                        Ok(tx_hashes
                            .into_iter()
                            .map(|tx_hash| TransactionStatus {
                                tx_hash,
                                state: TransactionState::Included,
                                height: 1,
                            })
                            .collect())
                    })
                },
            ),
        )
        .await;

        assert!(result.is_ok(), "spammer should finish");
        assert_eq!(status_polls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn run_bounds_concurrent_submissions_per_endpoint() {
        let should_stop = Arc::new(AtomicBool::new(false));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicBool::new(false));
        let signal = should_stop.clone();
        let max_in_flight_for_submit = max_in_flight.clone();

        let result = time::timeout(
            Duration::from_secs(2),
            run_until_stopped(
                test_args(MAX_SUBMISSION_TASKS_PER_ENDPOINT * 4),
                should_stop,
                move |_client, _endpoint, _tx_bytes| {
                    let in_flight = in_flight.clone();
                    let max_in_flight = max_in_flight_for_submit.clone();
                    let released = released.clone();
                    let signal = signal.clone();
                    async move {
                        let current = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        max_in_flight.fetch_max(current, Ordering::SeqCst);

                        if current >= MAX_SUBMISSION_TASKS_PER_ENDPOINT {
                            released.store(true, Ordering::SeqCst);
                            signal.store(true, Ordering::Relaxed);
                        }

                        while !released.load(Ordering::SeqCst) {
                            time::sleep(Duration::from_millis(5)).await;
                        }

                        in_flight.fetch_sub(1, Ordering::SeqCst);
                        Ok("hash".to_string())
                    }
                },
            ),
        )
        .await;

        assert!(result.is_ok(), "spammer should finish");
        assert_eq!(
            max_in_flight.load(Ordering::SeqCst),
            MAX_SUBMISSION_TASKS_PER_ENDPOINT
        );
    }
}
