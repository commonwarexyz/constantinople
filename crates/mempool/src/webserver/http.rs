//! HTTP handlers for the mempool webserver.

use super::{
    Mailbox,
    actor::{AccountReaderCell, IngestStatus},
    mailbox::SubmissionLane,
};
use crate::Candidate;
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{Method, StatusCode, header::CONTENT_TYPE},
    routing::{get, post},
};
use commonware_codec::{Copying, Decode, DecodeExt, EncodeSize, FixedSize, RangeCfg};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_formatting::from_hex;
use commonware_parallel::Strategy;
use commonware_runtime::telemetry::traces::TracedExt as _;
use commonware_utils::{Participant, sys_rng};
use constantinople_auth::{Mac, PrivateKey, SharedKey, SharedKeys, Submission, Tags, tag_bits};
use constantinople_primitives::{
    Account, LazySignedTransaction, Nonce, PublicKeyCache, SignedTransaction, TransactionPublicKey,
    TransactionSignature, verify_transaction_chunks,
};
use std::{fmt::Display, num::NonZeroUsize, sync::Arc};
use tokio::sync::Semaphore;
use tower_http::cors::{Any, CorsLayer};
use tracing::info_span;

/// Maximum bytes needed to encode the batch-length prefix.
///
/// `commonware-codec` encodes `Vec` lengths as `u32` varints, which fit in at
/// most 5 bytes.
const MAX_BATCH_LENGTH_PREFIX_BYTES: usize = 5;

/// Minimum bytes needed to encode the batch-length prefix.
const MIN_BATCH_LENGTH_PREFIX_BYTES: usize = 1;

/// Minimum bytes needed to encode a `u64` varint.
const MIN_U64_VARINT_BYTES: usize = 1;

/// Minimum and maximum bytes needed to encode a validator's index.
const MIN_PARTICIPANT_BYTES: usize = 1;
const MAX_PARTICIPANT_BYTES: usize = 5;

/// Maximum ingress batches admitted to CPU verification concurrently, shared
/// across all POST endpoints.
///
/// Ingress decode and verification run on the strategy's worker pool, which
/// consensus execution and block verification also share. Admitting one
/// batch at a time keeps a burst of relayer posts from queueing CPU bursts
/// ahead of consensus-critical work; excess requests wait cheaply on the
/// semaphore in the async layer instead. The owned permit is acquired in
/// `verify_body` -- after the request body is buffered, before the pool job
/// dispatches -- and moves into the job itself, so slow uploads and mailbox
/// waits never hold it and a client disconnect cannot release it while the
/// job runs.
pub(super) const MAX_CONCURRENT_INGRESS: usize = 1;

/// What a validator needs to admit transactions authenticated by tags.
pub struct Admission {
    /// This validator's index among the validators.
    pub validator: Participant,
    /// Number of validators.
    pub validators: u32,
    /// This validator's X25519 secret.
    pub secret: PrivateKey,
    /// Number of senders whose shared key is kept. A miss costs one
    /// Diffie-Hellman.
    pub key_cache_size: NonZeroUsize,
}

/// Checks submissions of transactions authenticated by tags.
pub(super) struct Admitter {
    admission: Admission,
    /// The key this validator shares with the senders seen lately.
    keys: SharedKeys,
}

impl Admitter {
    pub(super) fn new(admission: Admission) -> Arc<Self> {
        let keys = SharedKeys::new(admission.secret.clone(), admission.key_cache_size);
        Arc::new(Self { admission, keys })
    }

    const fn validators(&self) -> usize {
        self.admission.validators as usize
    }

    /// The sender of a submission's transaction, if it is one that
    /// authenticates its transactions by tags.
    fn sender<H: Hasher>(
        submission: &Submission<SignedTransaction<H>>,
    ) -> Option<constantinople_auth::PublicKey> {
        if !submission.transaction.is_mac() {
            return None;
        }
        submission.transaction.value().sender()?.as_x25519()
    }

    /// Admits every submission of a batch, or none: see [`Self::admit`].
    ///
    /// The keys of all the senders are looked up at once and the submissions
    /// are then checked on `strategy`. A lookup for each submission from
    /// every thread of the pool would have the threads queue on the cache.
    fn admit_all<H: Hasher>(
        &self,
        namespace: &[u8],
        submissions: Vec<Submission<SignedTransaction<H>>>,
        strategy: &impl Strategy,
    ) -> Option<Vec<Candidate<H>>> {
        let senders = submissions
            .iter()
            .map(Self::sender)
            .collect::<Option<Vec<_>>>()?;
        let keys = self.keys.resolve(namespace, &senders, strategy);
        strategy
            .map_collect_vec(submissions.into_iter().zip(keys), |(submission, key)| {
                self.admit(submission, &key?)
            })
            .into_iter()
            .collect()
    }

    /// Admits `submission` if it names this validator as proposer, its sender
    /// authenticated it to this validator under `key`, the key the two share,
    /// and its tag for this validator is right.
    fn admit<H: Hasher>(
        &self,
        submission: Submission<SignedTransaction<H>>,
        key: &SharedKey,
    ) -> Option<Candidate<H>> {
        submission
            .admit(
                self.admission.validator,
                key,
                submission.transaction.message_digest().as_ref(),
                self.validators(),
            )
            .ok()?;
        Some(Candidate {
            transaction: submission.transaction,
            authenticator: Some(submission.authenticator),
        })
    }
}

/// Shared state for HTTP handlers.
pub(super) struct AppState<C, P, H, St>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    pub mailbox: Mailbox<C, P, H>,
    pub namespace: &'static [u8],
    pub max_batch_bytes: usize,
    pub strategy: St,
    pub public_key_cache: PublicKeyCache,
    pub admission: Option<Arc<Admitter>>,
    pub account_reader: AccountReaderCell,
    pub ingress_permits: Arc<Semaphore>,
}

type SharedState<C, P, H, St> = Arc<AppState<C, P, H, St>>;

/// Builds the axum [`Router`] for the mempool HTTP API.
pub(super) fn router<C, P, H, St>(state: SharedState<C, P, H, St>) -> Router
where
    C: Digest + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Display + Send + Sync,
    St: Strategy + Send + Sync + 'static,
{
    let max_request_bytes = state.admission.as_ref().map_or_else(
        || max_request_bytes(state.max_batch_bytes),
        |admitter| max_submission_request_bytes(state.max_batch_bytes, admitter.validators()),
    );
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE]);

    Router::new()
        .route("/transactions", post(submit_batch::<C, P, H, St>))
        .route(
            "/transactions/background",
            post(submit_background_batch::<C, P, H, St>),
        )
        .route("/transactions/ingest", post(ingest_batch::<C, P, H, St>))
        .route("/transactions/{batch_id}", get(fetch_status::<C, P, H, St>))
        .route("/submissions", post(submit_tagged_batch::<C, P, H, St>))
        .route(
            "/submissions/background",
            post(submit_tagged_background_batch::<C, P, H, St>),
        )
        .route("/account/{public_key}", get(fetch_account::<C, P, H, St>))
        .layer(DefaultBodyLimit::max(max_request_bytes))
        .layer(cors)
        .with_state(state)
}

const fn max_request_bytes(max_batch_bytes: usize) -> usize {
    max_batch_bytes.saturating_add(MAX_BATCH_LENGTH_PREFIX_BYTES)
}

const fn min_signed_transaction_bytes() -> usize {
    TransactionPublicKey::SIZE
        + TransactionPublicKey::SIZE
        + MIN_U64_VARINT_BYTES
        + MIN_U64_VARINT_BYTES
        + TransactionSignature::MIN_SIGNED_SIZE
}

/// Smallest encoding of a submission to a committee of `validators`.
fn min_submission_bytes(validators: usize) -> usize {
    let bits = tag_bits(validators as u32);
    MIN_PARTICIPANT_BYTES + min_signed_transaction_bytes() - TransactionSignature::MIN_SIGNED_SIZE
        + Tags::encoded_size(bits, validators)
        + Mac::SIZE
}

/// Largest request that holds submissions whose transactions fit
/// `max_batch_bytes`. A submission carries a proposer, one tag per validator
/// and a MAC on top of its transaction.
pub fn max_submission_request_bytes(max_batch_bytes: usize, validators: usize) -> usize {
    let transaction = min_signed_transaction_bytes() - TransactionSignature::MIN_SIGNED_SIZE;
    let overhead = min_submission_bytes(validators) - transaction - MIN_PARTICIPANT_BYTES
        + MAX_PARTICIPANT_BYTES;
    (max_batch_bytes / transaction)
        .saturating_mul(overhead)
        .saturating_add(max_request_bytes(max_batch_bytes))
}

fn max_submission_count(body_len: usize, validators: usize) -> Option<usize> {
    let payload_len = body_len.saturating_sub(MIN_BATCH_LENGTH_PREFIX_BYTES);
    let max_submissions = payload_len / min_submission_bytes(validators);
    (max_submissions > 0).then_some(max_submissions)
}

fn max_transaction_count(body_len: usize) -> Option<usize> {
    let payload_len = body_len.saturating_sub(MIN_BATCH_LENGTH_PREFIX_BYTES);
    let max_transactions = payload_len / min_signed_transaction_bytes();
    (max_transactions > 0).then_some(max_transactions)
}

/// Serializes a JSON response body, mapping the (practically impossible)
/// serialization failure to a 500 instead of panicking.
fn ok_json<T: serde::Serialize>(value: &T) -> (StatusCode, String) {
    serde_json::to_string(value)
        .map_or((StatusCode::INTERNAL_SERVER_ERROR, String::new()), |body| {
            (StatusCode::OK, body)
        })
}

/// Accepts a batch of signed transactions as a commonware-codec length-prefixed
/// vector.
///
/// Signatures are verified in parallel using the configured [`Strategy`].
/// Blocks until the batch is fully finalized, partially finalized, or dropped.
///
/// Returns:
/// - `200 OK` with JSON status on finalization or drop.
/// - `400 Bad Request` if the body is empty, any transaction fails to decode,
///   or any signature is invalid.
/// - `413 Payload Too Large` if the batch exceeds the transaction byte budget
///   derived from the server's encoded-block limit.
/// - `503 Service Unavailable` if the pool is full.
async fn submit_batch<C, P, H, St>(
    State(state): State<SharedState<C, P, H, St>>,
    body: Bytes,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    submit_in_lane(state, body, SubmissionLane::Foreground).await
}

/// Accepts a verified transaction batch without waiting for finalization.
///
/// This endpoint is intended for relayers. It uses the same body format and
/// validation path as [`submit_batch`], but returns an empty `202 Accepted`
/// as soon as the actor has accepted the batch for proposal; callers derive
/// transaction digests locally from the batch they signed.
async fn ingest_batch<C, P, H, St>(
    State(state): State<SharedState<C, P, H, St>>,
    body: Bytes,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    let batch = match verify_body::<P, H, _>(&state, body).await {
        Ok(batch) => batch,
        Err(status) => return (status, String::new()),
    };

    let Some(result_rx) =
        state
            .mailbox
            .try_ingest(batch.batch_id, batch.digests, batch.transactions)
    else {
        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
    };

    match result_rx.await {
        Ok(IngestStatus::Accepted) => (StatusCode::ACCEPTED, String::new()),
        Ok(IngestStatus::Dropped) => (StatusCode::SERVICE_UNAVAILABLE, String::new()),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, String::new()),
    }
}

/// Accepts a batch through the background lane and waits for its outcome.
async fn submit_background_batch<C, P, H, St>(
    State(state): State<SharedState<C, P, H, St>>,
    body: Bytes,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    submit_in_lane(state, body, SubmissionLane::Background).await
}

async fn submit_in_lane<C, P, H, St>(
    state: SharedState<C, P, H, St>,
    body: Bytes,
    lane: SubmissionLane,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    let batch = verify_body::<P, H, _>(&state, body).await;
    await_outcome(&state, batch, lane).await
}

/// Accepts a batch of submissions as a commonware-codec length-prefixed
/// vector. A submission is a transaction of an X25519 account with one tag per
/// validator and a MAC, all computed for this validator as proposer.
///
/// Blocks until the outcome of every transaction is known, like
/// [`submit_batch`]. Returns `404 Not Found` if this validator does not admit
/// submissions, and `400 Bad Request` if any submission names another
/// validator, was not authenticated by its sender, or carries a wrong tag for
/// this validator.
async fn submit_tagged_batch<C, P, H, St>(
    State(state): State<SharedState<C, P, H, St>>,
    body: Bytes,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    let batch = admit_body::<P, H, _>(&state, body).await;
    await_outcome(&state, batch, SubmissionLane::Foreground).await
}

/// Accepts a batch of submissions through the background lane and waits for
/// its outcome.
async fn submit_tagged_background_batch<C, P, H, St>(
    State(state): State<SharedState<C, P, H, St>>,
    body: Bytes,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    let batch = admit_body::<P, H, _>(&state, body).await;
    await_outcome(&state, batch, SubmissionLane::Background).await
}

/// Hands an admitted batch to the pool and waits for its outcome.
async fn await_outcome<C, P, H, St>(
    state: &AppState<C, P, H, St>,
    batch: Result<VerifiedBatch<H>, StatusCode>,
    lane: SubmissionLane,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    let batch = match batch {
        Ok(batch) => batch,
        Err(status) => return (status, String::new()),
    };

    let Some(result_rx) =
        state
            .mailbox
            .try_submit_in_lane(lane, batch.batch_id, batch.digests, batch.transactions)
    else {
        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
    };

    result_rx.await.map_or_else(
        |_| (StatusCode::INTERNAL_SERVER_ERROR, String::new()),
        |status| ok_json(&status),
    )
}

struct VerifiedBatch<H>
where
    H: Hasher,
{
    batch_id: String,
    transactions: Vec<Candidate<H>>,
    digests: Vec<H::Digest>,
}

async fn verify_body<P, H, St>(
    state: &AppState<impl Digest, P, H, St>,
    body: Bytes,
) -> Result<VerifiedBatch<H>, StatusCode>
where
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    if body.len() > max_request_bytes(state.max_batch_bytes) {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let Some(max_transactions) = max_transaction_count(body.len()) else {
        return Err(StatusCode::BAD_REQUEST);
    };

    // Admission control: the owned permit moves into the pool job below, so
    // it is held for exactly the job's lifetime -- a client disconnect drops
    // the handler future but cannot release the permit while the
    // (uncancellable) job still occupies the pool.
    let Ok(permit) = state.ingress_permits.clone().acquire_owned().await else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    // Cheap decode failures must not train the scheduler to run expensive
    // valid batches on the async worker. Force the outer handoff while
    // retaining adaptive scheduling inside signature verification.
    // Pool threads have an empty tracing context, so capture the caller's span explicitly.
    let parent = tracing::Span::current();
    let max_batch_bytes = state.max_batch_bytes;
    let namespace = state.namespace;
    let public_key_cache = state.public_key_cache.clone();
    let work_size = body.len();
    let strategy = state.strategy.clone();
    let verified = state.strategy.manual().spawn(work_size, move |_| {
        let _permit = permit;
        let batch_id = H::hash(&[body.as_ref()]).to_string();

        let decode = info_span!(
            parent: &parent,
            "mempool.ingress.decode",
            bytes = body.len().traced(),
            txs = tracing::field::Empty,
        )
        .entered();

        // Retained fields must not keep the entire request allocation alive.
        let cfg = (RangeCfg::new(1..=max_transactions), ());
        let signed = Vec::<SignedTransaction<H>>::decode_cfg(Copying(body.as_ref()), &cfg)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        decode.record("txs", signed.len().traced());
        drop(decode);

        // A transaction without a signature needs tags, which only a
        // submission carries.
        if signed.iter().any(SignedTransaction::is_mac) {
            return Err(StatusCode::BAD_REQUEST);
        }

        let total_bytes: usize = signed.iter().map(EncodeSize::encode_size).sum();
        if total_bytes > max_batch_bytes {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }

        let verify = info_span!(
            parent: &parent,
            "mempool.ingress.verify",
            txs = signed.len().traced(),
            bytes = total_bytes.traced(),
        )
        .entered();
        let signed_lazy = signed
            .into_iter()
            .map(LazySignedTransaction::new)
            .collect::<Vec<_>>();
        let transactions = verify_transaction_chunks::<H, _>(
            namespace,
            &mut sys_rng(),
            &public_key_cache,
            signed_lazy,
            &strategy,
        )
        .ok_or(StatusCode::BAD_REQUEST)?;
        drop(verify);

        let digests = transactions
            .iter()
            .map(|transaction| *transaction.message_digest())
            .collect();

        Ok(VerifiedBatch {
            batch_id,
            transactions: transactions.into_iter().map(Candidate::from).collect(),
            digests,
        })
    });
    verified.await
}

/// Decodes a batch of submissions and checks each one, as [`verify_body`]
/// does for signed transactions.
async fn admit_body<P, H, St>(
    state: &AppState<impl Digest, P, H, St>,
    body: Bytes,
) -> Result<VerifiedBatch<H>, StatusCode>
where
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    let Some(admitter) = state.admission.clone() else {
        return Err(StatusCode::NOT_FOUND);
    };
    let validators = admitter.validators();
    if body.len() > max_submission_request_bytes(state.max_batch_bytes, validators) {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let Some(max_submissions) = max_submission_count(body.len(), validators) else {
        return Err(StatusCode::BAD_REQUEST);
    };

    // The permit bounds ingress CPU on the shared pool, as in `verify_body`.
    let Ok(permit) = state.ingress_permits.clone().acquire_owned().await else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    let parent = tracing::Span::current();
    let max_batch_bytes = state.max_batch_bytes;
    let namespace = state.namespace;
    let work_size = body.len();
    let strategy = state.strategy.clone();
    let admitted = state.strategy.manual().spawn(work_size, move |_| {
        let _permit = permit;
        let batch_id = H::hash(&[body.as_ref()]).to_string();

        let decode = info_span!(
            parent: &parent,
            "mempool.ingress.decode",
            bytes = body.len().traced(),
            txs = tracing::field::Empty,
        )
        .entered();
        let cfg = (RangeCfg::new(1..=max_submissions), ((), validators));
        let submissions =
            Vec::<Submission<SignedTransaction<H>>>::decode_cfg(Copying(body.as_ref()), &cfg)
                .map_err(|_| StatusCode::BAD_REQUEST)?;
        decode.record("txs", submissions.len().traced());
        drop(decode);

        let total_bytes: usize = submissions
            .iter()
            .map(|submission| submission.transaction.encode_size())
            .sum();
        if total_bytes > max_batch_bytes {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }

        let admit = info_span!(
            parent: &parent,
            "mempool.ingress.admit",
            txs = submissions.len().traced(),
            bytes = total_bytes.traced(),
        )
        .entered();
        let transactions = admitter
            .admit_all(namespace, submissions, &strategy)
            .ok_or(StatusCode::BAD_REQUEST)?;
        drop(admit);

        let digests = transactions
            .iter()
            .map(|candidate| *candidate.transaction.message_digest())
            .collect();

        Ok(VerifiedBatch {
            batch_id,
            transactions,
            digests,
        })
    });
    admitted.await
}

/// Returns the latest known status for a submitted batch.
async fn fetch_status<C, P, H, St>(
    State(state): State<SharedState<C, P, H, St>>,
    Path(batch_id): Path<String>,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    let Some(status) = state.mailbox.query_status(batch_id).await else {
        return (StatusCode::NOT_FOUND, String::new());
    };

    // Hex-encoding digest lists (partially finalized batches only) is O(txs)
    // formatting, so it runs on the strategy's pool. Every other status is
    // constant-size.
    if let Some(work_size) = status.digest_list_len() {
        return state
            .strategy
            .spawn(work_size, move |_| ok_json(&status.to_wire()))
            .await;
    }
    ok_json(&status.to_wire())
}

/// Returns the committed account for the hex-encoded public key.
///
/// Responds with:
/// - `200 OK` and account JSON if the account exists.
/// - `404 Not Found` if the account has not been written.
/// - `400 Bad Request` if the path is not a valid public key hex string.
/// - `503 Service Unavailable` if the state database has not been attached yet.
async fn fetch_account<C, P, H, St>(
    State(state): State<SharedState<C, P, H, St>>,
    Path(public_key): Path<String>,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    let Some(bytes) = from_hex(&public_key) else {
        return (StatusCode::BAD_REQUEST, String::new());
    };
    if bytes.len() != TransactionPublicKey::SIZE {
        return (StatusCode::BAD_REQUEST, String::new());
    }
    let public_key = match TransactionPublicKey::decode(bytes) {
        Ok(public_key) => public_key,
        Err(_) => return (StatusCode::BAD_REQUEST, String::new()),
    };

    let Some(reader) = state.account_reader.get() else {
        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
    };

    reader.get(public_key).await.map_or_else(
        || (StatusCode::NOT_FOUND, String::new()),
        |account| ok_json(&AccountResponse::from(account)),
    )
}

#[derive(serde::Serialize)]
struct AccountResponse {
    balance: u64,
    nonce: NonceResponse,
}

#[derive(serde::Serialize)]
struct NonceResponse {
    base: u64,
    bitmap: u64,
}

impl From<Account> for AccountResponse {
    fn from(account: Account) -> Self {
        Self {
            balance: account.balance,
            nonce: NonceResponse::from(account.nonce),
        }
    }
}

impl From<Nonce> for NonceResponse {
    fn from(nonce: Nonce) -> Self {
        Self {
            base: nonce.base,
            bitmap: nonce.bitmap,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            TxStatus,
            mailbox::{Message, SubmissionLane},
        },
        Admission, Admitter, AppState, MAX_CONCURRENT_INGRESS, PublicKeyCache, Semaphore, router,
    };
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode, header},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{Signer, ed25519, sha256};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Metrics, Runner as _, Supervisor as _};
    use commonware_utils::{NZUsize, Participant};
    use constantinople_auth::{PrivateKey, Submission};
    use constantinople_primitives::{SignedTransaction, Transaction, TransactionPublicKey};
    use core::num::NonZeroU64;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tower::ServiceExt;

    const HTTP_TEST_NAMESPACE: &[u8] = b"mempool-http-test";

    type TestMessage = Message<sha256::Digest, ed25519::PublicKey, sha256::Sha256>;

    fn test_router_with_receiver(
        context: impl Metrics,
        max_batch_bytes: usize,
    ) -> (axum::Router, mpsc::Receiver<TestMessage>) {
        admitting_router(context, max_batch_bytes, None)
    }

    const VALIDATORS: u32 = 6;
    const VALIDATOR: u32 = 2;

    fn validator_secret(validator: u32) -> PrivateKey {
        PrivateKey::from([100 + validator as u8; 32])
    }

    fn admission() -> Admission {
        Admission {
            validator: Participant::new(VALIDATOR),
            validators: VALIDATORS,
            secret: validator_secret(VALIDATOR),
            key_cache_size: NZUsize!(16),
        }
    }

    /// A submission to validator `proposer` of a transfer by the X25519 account
    /// with secret `[seed; 32]`.
    fn submission(seed: u8, proposer: u32) -> Submission<SignedTransaction<sha256::Sha256>> {
        let sender = PrivateKey::from([seed; 32]);
        let transaction = Transaction::new(
            TransactionPublicKey::x25519(sender.public_key()),
            TransactionPublicKey::ed25519(ed25519::PrivateKey::from_seed(2).public_key()),
            NonZeroU64::new(1).expect("non-zero"),
            0,
        )
        .seal_for_mac(&mut sha256::Sha256::default());
        let keys: Vec<_> = (0..VALIDATORS)
            .map(|validator| {
                sender
                    .with_validator(
                        HTTP_TEST_NAMESPACE,
                        &validator_secret(validator).public_key(),
                    )
                    .expect("validator key is not low order")
            })
            .collect();
        let digest = *transaction.message_digest();
        Submission::new(
            &keys,
            Participant::new(proposer),
            transaction,
            digest.as_ref(),
        )
    }

    async fn post(app: axum::Router, uri: &str, body: bytes::Bytes) -> StatusCode {
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .body(Body::from(body))
            .expect("request should build");
        app.oneshot(request)
            .await
            .expect("router should respond")
            .status()
    }

    fn admitting_router(
        context: impl Metrics,
        max_batch_bytes: usize,
        admission: Option<Admission>,
    ) -> (axum::Router, mpsc::Receiver<TestMessage>) {
        let (sender, receiver) = mpsc::channel(1);
        let state = Arc::new(AppState {
            mailbox: super::super::mailbox::Mailbox::new(sender),
            namespace: HTTP_TEST_NAMESPACE,
            max_batch_bytes,
            strategy: Sequential,
            admission: admission.map(Admitter::new),
            public_key_cache: PublicKeyCache::new(context, NZUsize!(16)),
            account_reader: std::sync::Arc::new(std::sync::OnceLock::new()),
            ingress_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_INGRESS)),
        });

        (
            router::<sha256::Digest, ed25519::PublicKey, sha256::Sha256, Sequential>(state),
            receiver,
        )
    }

    fn test_router(context: impl Metrics, max_batch_bytes: usize) -> axum::Router {
        test_router_with_receiver(context, max_batch_bytes).0
    }

    fn signed_body(count: usize) -> bytes::Bytes {
        let signer = ed25519::PrivateKey::from_seed(1);
        let recipient = ed25519::PrivateKey::from_seed(2).public_key();
        let transaction = Transaction::new(
            TransactionPublicKey::ed25519(signer.public_key()),
            TransactionPublicKey::ed25519(recipient),
            NonZeroU64::new(1).expect("non-zero"),
            0,
        )
        .seal_and_sign(&signer, HTTP_TEST_NAMESPACE, &mut sha256::Sha256::default());
        vec![transaction; count].encode()
    }

    #[test]
    fn verified_transaction_does_not_retain_request_body() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (app, mut receiver) = test_router_with_receiver(context, 4 * 1024 * 1024);
            let body: Arc<[u8]> = signed_body(128).as_ref().into();
            let owner = Arc::downgrade(&body);
            let request = Request::builder()
                .method("POST")
                .uri("/transactions")
                .body(Body::from(bytes::Bytes::from_owner(body)))
                .expect("request should build");
            let request_task =
                tokio::spawn(
                    async move { app.oneshot(request).await.expect("router should respond") },
                );

            let Message::Submit {
                mut transactions,
                result,
                ..
            } = receiver.recv().await.expect("submission should arrive")
            else {
                panic!("expected submission");
            };

            // A surviving transaction must not retain the rest of its submission.
            assert_eq!(transactions.len(), 128);
            let transaction = transactions.pop().unwrap();
            drop(transactions);
            result
                .expect("blocking submission should have a waiter")
                .send(TxStatus::Finalized { height: 7 })
                .expect("handler should await the result");
            let response = request_task.await.expect("request task should finish");

            assert_eq!(response.status(), StatusCode::OK);
            assert!(
                owner.upgrade().is_none(),
                "transaction retained request body"
            );
            assert!(transaction.transaction.value().sender().is_some());
        });
    }

    #[test]
    fn router_accepts_requests_above_axum_default_limit() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let app = test_router(context, 4 * 1024 * 1024);
            let request = Request::builder()
                .method("POST")
                .uri("/transactions")
                .body(Body::from(vec![0u8; 2 * 1024 * 1024 + 1]))
                .expect("request should build");

            let response = app.oneshot(request).await.expect("router should respond");

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        });
    }

    #[test]
    fn router_rejects_malformed_length_prefix_without_panicking() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let app = test_router(context, 4 * 1024 * 1024);
            let request = Request::builder()
                .method("POST")
                .uri("/transactions")
                .body(Body::from(u32::MAX.encode()))
                .expect("request should build");

            // A panic here (rather than a clean rejection) would fail the test.
            let response = app.oneshot(request).await.expect("router should respond");

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        });
    }

    #[test]
    fn background_endpoint_routes_blocking_submission() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (app, mut receiver) = test_router_with_receiver(context, 4 * 1024 * 1024);
            let request = Request::builder()
                .method("POST")
                .uri("/transactions/background")
                .body(Body::from(signed_body(1)))
                .expect("request should build");
            let request_task =
                tokio::spawn(
                    async move { app.oneshot(request).await.expect("router should respond") },
                );

            let message = receiver.recv().await.expect("submission should arrive");
            match message {
                Message::Submit {
                    lane,
                    result,
                    ingest_result,
                    ..
                } => {
                    assert_eq!(lane, SubmissionLane::Background);
                    assert!(ingest_result.is_none());
                    result
                        .expect("blocking submission should have a waiter")
                        .send(TxStatus::Finalized { height: 7 })
                        .expect("handler should await the result");
                }
                _ => panic!("expected submission"),
            }

            let response = request_task.await.expect("request task should finish");
            assert_eq!(response.status(), StatusCode::OK);
        });
    }

    #[test]
    fn submission_endpoint_admits_a_submission_to_this_validator() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            for (uri, expected) in [
                ("/submissions", SubmissionLane::Foreground),
                ("/submissions/background", SubmissionLane::Background),
            ] {
                let (app, mut receiver) = admitting_router(
                    context.child(expected_label(expected)),
                    4096,
                    Some(admission()),
                );
                let submissions = vec![submission(1, VALIDATOR), submission(2, VALIDATOR)];
                let body = submissions.encode();
                let request = tokio::spawn(async move { post(app, uri, body).await });

                let Some(Message::Submit {
                    lane,
                    digests,
                    transactions,
                    result,
                    ..
                }) = receiver.recv().await
                else {
                    panic!("expected submission");
                };
                assert_eq!(lane, expected);
                assert_eq!(digests.len(), 2);
                for (candidate, submission) in transactions.iter().zip(&submissions) {
                    assert_eq!(candidate.transaction, submission.transaction);
                    assert_eq!(
                        candidate.authenticator.as_ref(),
                        Some(&submission.authenticator)
                    );
                }
                result
                    .expect("blocking submission should have a waiter")
                    .send(TxStatus::Rejected { height: 7 })
                    .expect("handler should await the result");
                assert_eq!(request.await.expect("request finishes"), StatusCode::OK);
            }
        });
    }

    /// A batch from more senders than the key cache holds is admitted whole,
    /// each submission under its own sender's key and in the order sent.
    #[test]
    fn submission_endpoint_admits_more_senders_than_it_caches() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let admission = admission();
            let senders = 3 * admission.key_cache_size.get() as u8;
            let (app, mut receiver) =
                admitting_router(context.child("many"), 1 << 20, Some(admission));
            let submissions: Vec<_> = (1..=senders)
                .map(|seed| submission(seed, VALIDATOR))
                .collect();

            // The same batch twice: the second time some keys are cached and
            // the others were evicted by the first.
            for _ in 0..2 {
                let body = submissions.encode();
                let app = app.clone();
                let request = tokio::spawn(async move { post(app, "/submissions", body).await });
                let Some(Message::Submit {
                    transactions,
                    result,
                    ..
                }) = receiver.recv().await
                else {
                    panic!("expected submission");
                };
                assert_eq!(transactions.len(), submissions.len());
                for (candidate, submission) in transactions.iter().zip(&submissions) {
                    assert_eq!(candidate.transaction, submission.transaction);
                }
                result
                    .expect("blocking submission should have a waiter")
                    .send(TxStatus::Rejected { height: 7 })
                    .expect("handler should await the result");
                assert_eq!(request.await.expect("request finishes"), StatusCode::OK);
            }
        });
    }

    const fn expected_label(lane: SubmissionLane) -> &'static str {
        match lane {
            SubmissionLane::Foreground => "foreground",
            SubmissionLane::Background => "background",
        }
    }

    #[test]
    fn submission_endpoint_refuses_what_its_sender_did_not_address_to_this_validator() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let refused = |label: &'static str, body: bytes::Bytes| {
                let (app, mut receiver) =
                    admitting_router(context.child(label), 4096, Some(admission()));
                async move {
                    assert_eq!(
                        post(app, "/submissions", body).await,
                        StatusCode::BAD_REQUEST,
                        "{label}"
                    );
                    assert!(receiver.try_recv().is_err(), "{label}");
                }
            };

            // Addressed to another validator.
            refused("proposer", vec![submission(1, VALIDATOR + 1)].encode()).await;

            // The tags of a submission to another validator, renamed.
            let mut renamed = submission(1, VALIDATOR + 1);
            renamed.proposer = Participant::new(VALIDATOR);
            refused("renamed", vec![renamed].encode()).await;

            // Another sender's MAC.
            let mut forged = submission(1, VALIDATOR);
            forged.mac = submission(2, VALIDATOR).mac;
            refused("mac", vec![forged].encode()).await;

            // A wrong tag for this validator, under a MAC that covers it.
            let sender = PrivateKey::from([1; 32]);
            let mut keys: Vec<_> = (0..VALIDATORS)
                .map(|validator| {
                    sender
                        .with_validator(
                            HTTP_TEST_NAMESPACE,
                            &validator_secret(validator).public_key(),
                        )
                        .expect("validator key is not low order")
                })
                .collect();
            keys[VALIDATOR as usize].tag = keys[0].tag.clone();
            let honest = submission(1, VALIDATOR);
            let digest = *honest.transaction.message_digest();
            let mistagged = Submission::new(
                &keys,
                Participant::new(VALIDATOR),
                honest.transaction.clone(),
                digest.as_ref(),
            );
            refused("tag", vec![mistagged].encode()).await;

            // One bad submission refuses the batch.
            refused("batch", vec![honest, submission(2, VALIDATOR + 1)].encode()).await;
        });
    }

    #[test]
    fn transactions_without_tags_or_signature_are_refused() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            // A validator that admits no submissions has no such endpoint.
            let (app, _receiver) = admitting_router(context.child("signed_only"), 4096, None);
            let body = vec![submission(1, VALIDATOR)].encode();
            assert_eq!(post(app, "/submissions", body).await, StatusCode::NOT_FOUND);

            // A transaction of an X25519 account carries no signature, so the
            // endpoint for signed transactions has nothing to check it by.
            let (app, mut receiver) =
                admitting_router(context.child("unsigned"), 4096, Some(admission()));
            let body = vec![submission(1, VALIDATOR).transaction].encode();
            assert_eq!(
                post(app, "/transactions", body).await,
                StatusCode::BAD_REQUEST
            );
            assert!(receiver.try_recv().is_err());
        });
    }

    #[test]
    fn router_allows_explorer_account_preflight() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let app = test_router(context, 4 * 1024 * 1024);
            let request = Request::builder()
                .method(Method::OPTIONS)
                .uri("/account/00")
                .header(header::ORIGIN, "http://127.0.0.1:5173")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .body(Body::empty())
                .expect("request should build");

            let response = app.oneshot(request).await.expect("router should respond");

            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
                Some(&header::HeaderValue::from_static("*")),
            );
        });
    }
}
