use crate::shared::{
    TransactionState, TransactionStatus, accept_transaction_batch, build_signed_transaction_bytes,
    transaction_hash_hex, tx_url, wait_transaction_batch,
};
use commonware_cryptography::{Sha256, Signer, ed25519};
use constantinople_primitives::Address;
use std::{
    future::Future,
    num::NonZeroUsize,
    pin::Pin,
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
const MAX_TRANSACTIONS_PER_BATCH: usize = 4_096;
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(50);

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
    #[cfg(test)]
    from: Address,
    to: Address,
    endpoint_index: usize,
}

#[derive(Debug, Clone)]
struct RoundTransaction {
    endpoint_index: usize,
    tx_bytes: Vec<u8>,
    tx_hash: String,
}

#[derive(Debug, Clone)]
struct RoundChunk {
    endpoint: String,
    nonce: u64,
    tx_hashes: Vec<String>,
    body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubmissionErrorKind {
    RetryRejected,
    RetryCheckStatus,
    Fatal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitProgress {
    Included,
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoundProgress {
    Completed,
    Stopped,
}

type SubmitBatchFuture = Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send>>;
type WaitBatchFuture = Pin<Box<dyn Future<Output = Result<Vec<TransactionStatus>, String>> + Send>>;

fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .timeout(HTTP_REQUEST_TIMEOUT)
        .pool_max_idle_per_host(MAX_TRANSACTIONS_PER_BATCH)
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
            #[cfg(test)]
            from: addresses[index],
            to: addresses[(index + 1) % count],
            endpoint_index: index % endpoint_count,
        });
    }

    accounts
}

fn build_round_transactions(accounts: &[RingAccount], nonce: u64) -> Vec<RoundTransaction> {
    accounts
        .iter()
        .map(|account| {
            let key = ed25519::PrivateKey::from_seed(account.seed);
            let tx_bytes = build_signed_transaction_bytes(&key, account.to, 1, nonce);
            let tx_hash =
                transaction_hash_hex(&tx_bytes).expect("generated tx bytes should decode");
            RoundTransaction {
                endpoint_index: account.endpoint_index,
                tx_bytes,
                tx_hash,
            }
        })
        .collect()
}

fn build_round_chunks(
    endpoints: &[String],
    transactions: Vec<RoundTransaction>,
    nonce: u64,
) -> Vec<RoundChunk> {
    let mut per_endpoint = vec![Vec::new(); endpoints.len()];
    for transaction in transactions {
        per_endpoint[transaction.endpoint_index].push(transaction);
    }

    let mut chunks = Vec::new();
    for (endpoint_index, endpoint_transactions) in per_endpoint.into_iter().enumerate() {
        for transaction_batch in endpoint_transactions.chunks(MAX_TRANSACTIONS_PER_BATCH) {
            let total_bytes = transaction_batch
                .iter()
                .map(|transaction| transaction.tx_bytes.len())
                .sum();
            let mut body = Vec::with_capacity(total_bytes);
            let mut tx_hashes = Vec::with_capacity(transaction_batch.len());
            for transaction in transaction_batch {
                body.extend_from_slice(&transaction.tx_bytes);
                tx_hashes.push(transaction.tx_hash.clone());
            }
            chunks.push(RoundChunk {
                endpoint: endpoints[endpoint_index].clone(),
                nonce,
                tx_hashes,
                body,
            });
        }
    }

    chunks
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

fn current_round_nonce(base_nonce: u64, round: u64) -> Result<u64, String> {
    base_nonce
        .checked_add(round)
        .ok_or_else(|| "round nonce overflowed".to_string())
}

fn validate_submission_hashes(
    endpoint: &str,
    nonce: u64,
    expected_hashes: &[String],
    returned_hashes: Vec<String>,
) -> Result<(), String> {
    if returned_hashes.len() != expected_hashes.len() {
        return Err(format!(
            "{} nonce={} returned {} hashes for {} submitted transactions",
            tx_url(endpoint),
            nonce,
            returned_hashes.len(),
            expected_hashes.len(),
        ));
    }

    for (expected, returned) in expected_hashes.iter().zip(returned_hashes.iter()) {
        if expected != returned {
            return Err(format!(
                "{} nonce={} returned mismatched tx hash {} for {}",
                tx_url(endpoint),
                nonce,
                returned,
                expected,
            ));
        }
    }

    Ok(())
}

fn inspect_wait_statuses(
    endpoint: &str,
    nonce: u64,
    expected_hashes: &[String],
    statuses: Vec<TransactionStatus>,
) -> Result<WaitProgress, String> {
    if statuses.len() != expected_hashes.len() {
        return Err(format!(
            "{} nonce={} returned {} statuses for {} requested hashes",
            tx_url(endpoint),
            nonce,
            statuses.len(),
            expected_hashes.len(),
        ));
    }

    let mut all_included = true;
    for (expected_hash, status) in expected_hashes.iter().zip(statuses) {
        if status.tx_hash != *expected_hash {
            return Err(format!(
                "{} nonce={} returned mismatched tx hash {} for {}",
                tx_url(endpoint),
                nonce,
                status.tx_hash,
                expected_hash,
            ));
        }

        match status.state {
            TransactionState::Included => {}
            TransactionState::Pending => {
                all_included = false;
            }
            TransactionState::Rejected => {
                let hint = if nonce == 0 {
                    "check that the validator state is fresh or that the configured base nonce matches the chain"
                } else {
                    "check that the configured base nonce and sender balances still match the chain"
                };
                return Err(format!(
                    "{} nonce={} transaction {} was rejected; {hint}",
                    tx_url(endpoint),
                    nonce,
                    expected_hash,
                ));
            }
            TransactionState::Unknown => {
                return Ok(WaitProgress::Pending);
            }
        }
    }

    if all_included {
        Ok(WaitProgress::Included)
    } else {
        Ok(WaitProgress::Pending)
    }
}

async fn wait_for_chunk_terminal<Wait>(
    client: reqwest::Client,
    chunk: &RoundChunk,
    wait_batch: Arc<Wait>,
) -> Result<WaitProgress, String>
where
    Wait: Fn(reqwest::Client, String, Vec<String>) -> WaitBatchFuture + Send + Sync + 'static,
{
    loop {
        let statuses = match wait_batch(
            client.clone(),
            chunk.endpoint.clone(),
            chunk.tx_hashes.clone(),
        )
        .await
        {
            Ok(statuses) => statuses,
            Err(err) => match classify_submission_error(&err) {
                SubmissionErrorKind::Fatal => {
                    return Err(format!(
                        "{} nonce={}: {err}",
                        tx_url(&chunk.endpoint),
                        chunk.nonce,
                    ));
                }
                SubmissionErrorKind::RetryRejected | SubmissionErrorKind::RetryCheckStatus => {
                    time::sleep(INITIAL_RETRY_BACKOFF).await;
                    continue;
                }
            },
        };

        match inspect_wait_statuses(&chunk.endpoint, chunk.nonce, &chunk.tx_hashes, statuses)? {
            WaitProgress::Included => return Ok(WaitProgress::Included),
            WaitProgress::Pending => continue,
        }
    }
}

async fn drive_chunk<Submit, Wait>(
    client: reqwest::Client,
    chunk: RoundChunk,
    submit_batch: Arc<Submit>,
    wait_batch: Arc<Wait>,
) -> Result<(), String>
where
    Submit: Fn(reqwest::Client, String, Vec<u8>) -> SubmitBatchFuture + Send + Sync + 'static,
    Wait: Fn(reqwest::Client, String, Vec<String>) -> WaitBatchFuture + Send + Sync + 'static,
{
    let mut submit_retry_backoff = INITIAL_RETRY_BACKOFF;

    loop {
        match submit_batch(client.clone(), chunk.endpoint.clone(), chunk.body.clone()).await {
            Ok(returned_hashes) => {
                validate_submission_hashes(
                    &chunk.endpoint,
                    chunk.nonce,
                    &chunk.tx_hashes,
                    returned_hashes,
                )?;
                break;
            }
            Err(err) => match classify_submission_error(&err) {
                SubmissionErrorKind::Fatal => {
                    return Err(format!(
                        "{} nonce={}: {err}",
                        tx_url(&chunk.endpoint),
                        chunk.nonce,
                    ));
                }
                SubmissionErrorKind::RetryRejected | SubmissionErrorKind::RetryCheckStatus => {
                    time::sleep(submit_retry_backoff).await;
                    submit_retry_backoff = next_retry_backoff(submit_retry_backoff, &err);
                }
            },
        }
    }

    let _ = wait_for_chunk_terminal(client, &chunk, wait_batch).await?;
    Ok(())
}

async fn stop_round(tasks: &mut JoinSet<Result<(), String>>) {
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

async fn run_round<Submit, Wait>(
    client: reqwest::Client,
    chunks: Vec<RoundChunk>,
    should_stop: Arc<AtomicBool>,
    submit_batch: Arc<Submit>,
    wait_batch: Arc<Wait>,
) -> Result<RoundProgress, String>
where
    Submit: Fn(reqwest::Client, String, Vec<u8>) -> SubmitBatchFuture + Send + Sync + 'static,
    Wait: Fn(reqwest::Client, String, Vec<String>) -> WaitBatchFuture + Send + Sync + 'static,
{
    let mut tasks = JoinSet::new();
    for chunk in chunks {
        let client = client.clone();
        let submit_batch = submit_batch.clone();
        let wait_batch = wait_batch.clone();
        tasks.spawn(async move { drive_chunk(client, chunk, submit_batch, wait_batch).await });
    }

    while !tasks.is_empty() {
        if should_stop.load(Ordering::Relaxed) {
            stop_round(&mut tasks).await;
            return Ok(RoundProgress::Stopped);
        }

        tokio::select! {
            Some(result) = tasks.join_next() => {
                let round_result = result.map_err(|err| format!("round task failed: {err}"))?;
                round_result?;
            }
            _ = time::sleep(STOP_POLL_INTERVAL) => {}
        }
    }

    Ok(RoundProgress::Completed)
}

fn print_startup(endpoints: &[String], accounts: &[RingAccount]) {
    if endpoints.len() == 1 {
        println!(
            "running ring spammer with {} accounts against {}. Press Ctrl-C to stop.",
            accounts.len(),
            tx_url(&endpoints[0]),
        );
    } else {
        println!(
            "running ring spammer with {} accounts across {} validators. Press Ctrl-C to stop.",
            accounts.len(),
            endpoints.len(),
        );
    }

    let mut per_endpoint = vec![0_usize; endpoints.len()];
    for account in accounts {
        per_endpoint[account.endpoint_index] += 1;
    }

    for (index, endpoint) in endpoints.iter().enumerate() {
        println!(
            "endpoint[{index}] {} accounts={}",
            tx_url(endpoint),
            per_endpoint[index],
        );
    }
}

fn print_summary(rounds_completed: u64) {
    println!("rounds completed: {rounds_completed}");
}

async fn run_with_stop_flag<Submit, Wait>(
    args: Args,
    should_stop: Arc<AtomicBool>,
    submit_batch: Submit,
    wait_batch: Wait,
) -> Result<(), String>
where
    Submit: Fn(reqwest::Client, String, Vec<u8>) -> SubmitBatchFuture + Send + Sync + 'static,
    Wait: Fn(reqwest::Client, String, Vec<String>) -> WaitBatchFuture + Send + Sync + 'static,
{
    let submit_batch = Arc::new(submit_batch);
    let wait_batch = Arc::new(wait_batch);
    let accounts = build_ring_accounts(args.count, args.seed_start, args.endpoints.len());
    let client = build_http_client();
    let mut completed_rounds = 0_u64;

    print_startup(&args.endpoints, &accounts);

    loop {
        if should_stop.load(Ordering::Relaxed) {
            break;
        }

        let round_nonce = current_round_nonce(args.nonce, completed_rounds)?;
        let transactions = build_round_transactions(&accounts, round_nonce);
        let chunks = build_round_chunks(&args.endpoints, transactions, round_nonce);
        match run_round(
            client.clone(),
            chunks,
            should_stop.clone(),
            submit_batch.clone(),
            wait_batch.clone(),
        )
        .await?
        {
            RoundProgress::Completed => {
                completed_rounds = completed_rounds
                    .checked_add(1)
                    .expect("completed round counter overflowed");
                println!("completed round {completed_rounds}");
            }
            RoundProgress::Stopped => break,
        }
    }

    print_summary(completed_rounds);
    Ok(())
}

pub async fn run(args: Args) -> Result<(), String> {
    let should_stop = Arc::new(AtomicBool::new(false));
    let signal = should_stop.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        signal.store(true, Ordering::Relaxed);
    });

    run_with_stop_flag(
        args,
        should_stop,
        |client, endpoint, body| {
            Box::pin(async move { accept_transaction_batch(&client, &endpoint, body).await })
        },
        |client, endpoint, tx_hashes| {
            Box::pin(async move { wait_transaction_batch(&client, &endpoint, &tx_hashes).await })
        },
    )
    .await
}

#[cfg(test)]
async fn run_until_stopped<Submit>(
    args: Args,
    should_stop: Arc<AtomicBool>,
    submit_batch: Submit,
) -> Result<(), String>
where
    Submit: Fn(reqwest::Client, String, Vec<u8>) -> SubmitBatchFuture + Send + Sync + 'static,
{
    run_with_stop_flag(
        args,
        should_stop,
        submit_batch,
        |_client, _endpoint, tx_hashes| {
            Box::pin(async move {
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
    )
    .await
}

#[cfg(test)]
async fn run_until_stopped_with_wait<Submit, Wait>(
    args: Args,
    should_stop: Arc<AtomicBool>,
    submit_batch: Submit,
    wait_batch: Wait,
) -> Result<(), String>
where
    Submit: Fn(reqwest::Client, String, Vec<u8>) -> SubmitBatchFuture + Send + Sync + 'static,
    Wait: Fn(reqwest::Client, String, Vec<String>) -> WaitBatchFuture + Send + Sync + 'static,
{
    run_with_stop_flag(args, should_stop, submit_batch, wait_batch).await
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
        Args, MAX_TRANSACTIONS_PER_BATCH, build_ring_accounts, build_round_chunks,
        build_round_transactions, classify_submission_error, next_retry_backoff, run_until_stopped,
        run_until_stopped_with_wait, start_stop_timer, test_args,
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

    fn decode_batch_transactions(body: &[u8]) -> Vec<(String, u64, String)> {
        let mut remaining = body;
        let mut decoded = Vec::new();
        while !remaining.is_empty() {
            let transaction: Signed<
                Transaction<crate::shared::Digest, ed25519::PublicKey>,
                Sha256,
                ed25519::Signature,
            > = Signed::read(&mut remaining).expect("ring transfer should decode");
            decoded.push((
                hex(&transaction.value().sender.encode()),
                transaction.value().nonce,
                hex(transaction.message_digest().as_ref()),
            ));
        }
        decoded
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
    fn round_transactions_use_the_round_nonce() {
        let accounts = build_ring_accounts(NonZeroUsize::new(2).unwrap(), 11, 1);
        let transactions = build_round_transactions(&accounts, 7);
        let chunks = build_round_chunks(&["http://127.0.0.1:8080".to_string()], transactions, 7);

        assert_eq!(chunks.len(), 1);
        let decoded = decode_batch_transactions(&chunks[0].body);
        assert_eq!(decoded.len(), 2);
        assert!(decoded.iter().all(|(_, nonce, _)| *nonce == 7));
    }

    #[test]
    fn transaction_hash_matches_generated_bytes() {
        let accounts = build_ring_accounts(NonZeroUsize::new(1).unwrap(), 11, 1);
        let transaction = build_round_transactions(&accounts, 7)
            .into_iter()
            .next()
            .expect("round should produce one transaction");
        let tx_hash = transaction_hash_hex(&transaction.tx_bytes).expect("tx hash should decode");
        let decoded = decode_batch_transactions(&transaction.tx_bytes);

        assert_eq!(tx_hash, transaction.tx_hash);
        assert_eq!(decoded[0].1, 7);
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

    #[test]
    fn rounds_are_chunked_for_batch_submission() {
        let accounts = build_ring_accounts(
            NonZeroUsize::new(MAX_TRANSACTIONS_PER_BATCH + 1).unwrap(),
            11,
            1,
        );
        let transactions = build_round_transactions(&accounts, 0);
        let chunks = build_round_chunks(&["http://127.0.0.1:8080".to_string()], transactions, 0);

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].tx_hashes.len(), MAX_TRANSACTIONS_PER_BATCH);
        assert_eq!(chunks[1].tx_hashes.len(), 1);
    }

    #[tokio::test]
    async fn run_stops_promptly_while_submitting() {
        let should_stop = Arc::new(AtomicBool::new(false));
        let stopper = start_stop_timer(Duration::from_millis(10), should_stop.clone());
        let result = time::timeout(
            Duration::from_millis(200),
            run_until_stopped(test_args(4), should_stop, |_client, _endpoint, _body| {
                Box::pin(async move {
                    time::sleep(Duration::from_secs(60)).await;
                    Ok(Vec::new())
                })
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
    async fn run_submits_batches_to_multiple_endpoints() {
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
            run_until_stopped(args, should_stop, move |_client, endpoint, body| {
                let seen = seen.clone();
                let signal = signal.clone();
                Box::pin(async move {
                    let returned_hashes = decode_batch_transactions(&body)
                        .into_iter()
                        .map(|(_, _, tx_hash)| tx_hash)
                        .collect();
                    let count = {
                        let mut seen = seen.lock().expect("endpoint set lock should succeed");
                        seen.insert(endpoint);
                        seen.len()
                    };
                    if count == 2 {
                        signal.store(true, Ordering::Relaxed);
                    }
                    Ok(returned_hashes)
                })
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
        let round_zero_included = Arc::new(AtomicBool::new(false));
        let saw_premature_round_one = Arc::new(AtomicBool::new(false));
        let nonce_by_hash = Arc::new(Mutex::new(HashMap::<String, u64>::new()));
        let signal = should_stop.clone();
        let round_zero_included_for_submit = round_zero_included.clone();
        let round_zero_included_for_wait = round_zero_included.clone();
        let saw_premature_round_one_for_submit = saw_premature_round_one.clone();
        let nonce_by_hash_for_submit = nonce_by_hash.clone();
        let nonce_by_hash_for_wait = nonce_by_hash.clone();

        let result = time::timeout(
            Duration::from_secs(2),
            run_until_stopped_with_wait(
                test_args(2),
                should_stop,
                move |_client, _endpoint, body| {
                    let round_zero_included = round_zero_included_for_submit.clone();
                    let saw_premature_round_one = saw_premature_round_one_for_submit.clone();
                    let nonce_by_hash = nonce_by_hash_for_submit.clone();
                    Box::pin(async move {
                        let mut hashes = Vec::new();
                        for (_sender, nonce, tx_hash) in decode_batch_transactions(&body) {
                            hashes.push(tx_hash.clone());
                            nonce_by_hash
                                .lock()
                                .expect("nonce map lock should succeed")
                                .insert(tx_hash, nonce);
                            if nonce == 1 && !round_zero_included.load(Ordering::SeqCst) {
                                saw_premature_round_one.store(true, Ordering::SeqCst);
                            }
                        }
                        Ok(hashes)
                    })
                },
                move |_client, _endpoint, tx_hashes| {
                    let round_zero_included = round_zero_included_for_wait.clone();
                    let nonce_by_hash = nonce_by_hash_for_wait.clone();
                    let signal = signal.clone();
                    Box::pin(async move {
                        let nonce_by_hash =
                            nonce_by_hash.lock().expect("nonce map lock should succeed");
                        let statuses = tx_hashes
                            .into_iter()
                            .map(|tx_hash| {
                                let nonce =
                                    nonce_by_hash.get(&tx_hash).copied().unwrap_or_default();
                                if nonce == 0 {
                                    round_zero_included.store(true, Ordering::SeqCst);
                                } else {
                                    signal.store(true, Ordering::Relaxed);
                                }
                                TransactionStatus {
                                    tx_hash,
                                    state: TransactionState::Included,
                                    height: nonce + 1,
                                }
                            })
                            .collect();
                        Ok(statuses)
                    })
                },
            ),
        )
        .await;

        assert!(result.is_ok(), "spammer should finish before the timeout");
        assert!(!saw_premature_round_one.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn ambiguous_submission_retries_the_exact_same_batch_bytes() {
        let should_stop = Arc::new(AtomicBool::new(false));
        let first_body = Arc::new(Mutex::new(None::<Vec<u8>>));
        let submit_calls = Arc::new(AtomicUsize::new(0));
        let wait_calls = Arc::new(AtomicUsize::new(0));
        let first_body_for_submit = first_body.clone();
        let submit_calls_for_submit = submit_calls.clone();
        let wait_calls_for_wait = wait_calls.clone();
        let signal = should_stop.clone();

        let result = run_until_stopped_with_wait(
            test_args(1),
            should_stop,
            move |_client, _endpoint, body| {
                let first_body = first_body_for_submit.clone();
                let submit_calls = submit_calls_for_submit.clone();
                Box::pin(async move {
                    let call = submit_calls.fetch_add(1, Ordering::SeqCst);
                    let expected_hash = transaction_hash_hex(&body).expect("tx hash should decode");
                    if call == 0 {
                        *first_body.lock().expect("body lock should succeed") = Some(body.clone());
                        return Err("request failed: timed out".to_string());
                    }

                    assert_eq!(
                        first_body
                            .lock()
                            .expect("body lock should succeed")
                            .clone()
                            .expect("first body should be recorded"),
                        body,
                    );
                    Ok(vec![expected_hash])
                })
            },
            move |_client, _endpoint, tx_hashes| {
                let wait_calls = wait_calls_for_wait.clone();
                let signal = signal.clone();
                Box::pin(async move {
                    if wait_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        return Ok(tx_hashes
                            .into_iter()
                            .map(|tx_hash| TransactionStatus {
                                tx_hash,
                                state: TransactionState::Unknown,
                                height: 0,
                            })
                            .collect());
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
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(submit_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn accepted_batch_is_not_resubmitted_while_waiting_for_inclusion() {
        let should_stop = Arc::new(AtomicBool::new(false));
        let submit_calls = Arc::new(AtomicUsize::new(0));
        let wait_calls = Arc::new(AtomicUsize::new(0));
        let submit_calls_for_submit = submit_calls.clone();
        let wait_calls_for_wait = wait_calls.clone();
        let signal = should_stop.clone();

        let result = run_until_stopped_with_wait(
            test_args(1),
            should_stop,
            move |_client, _endpoint, body| {
                let submit_calls = submit_calls_for_submit.clone();
                Box::pin(async move {
                    submit_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(vec![
                        transaction_hash_hex(&body).expect("tx hash should decode"),
                    ])
                })
            },
            move |_client, _endpoint, tx_hashes| {
                let wait_calls = wait_calls_for_wait.clone();
                let signal = signal.clone();
                Box::pin(async move {
                    if wait_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        return Ok(tx_hashes
                            .into_iter()
                            .map(|tx_hash| TransactionStatus {
                                tx_hash,
                                state: TransactionState::Unknown,
                                height: 0,
                            })
                            .collect());
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
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(submit_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rejected_transaction_fails_fast() {
        let should_stop = Arc::new(AtomicBool::new(false));

        let result = run_until_stopped_with_wait(
            test_args(1),
            should_stop,
            |_client, _endpoint, body| {
                Box::pin(async move {
                    Ok(vec![
                        transaction_hash_hex(&body).expect("tx hash should decode"),
                    ])
                })
            },
            |_client, _endpoint, tx_hashes| {
                Box::pin(async move {
                    Ok(tx_hashes
                        .into_iter()
                        .map(|tx_hash| TransactionStatus {
                            tx_hash,
                            state: TransactionState::Rejected,
                            height: 0,
                        })
                        .collect())
                })
            },
        )
        .await;

        assert!(result.is_err());
        assert!(
            result
                .expect_err("rejected run should fail")
                .contains("was rejected")
        );
    }
}
