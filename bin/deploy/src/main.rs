//! Deployment generator for Constantinople.

mod local;
mod ports;
mod remote;

use clap::{Args, Parser, Subcommand};
use commonware_allocator::mimalloc::{Config, MiMalloc, Purge, Reserve};
use commonware_codec::{Copying, Encode, Read as CodecRead};
use commonware_cryptography::{
    Signer,
    bls12381::{
        dkg::feldman_desmedt as dkg,
        primitives::{
            group::Share,
            sharing::{Mode, ModeVersion},
            variant::MinSig,
        },
    },
};
use commonware_cryptography_curve25519::signing as ed25519;
use commonware_formatting::{from_hex, hex};
use commonware_math::algebra::Random;
use commonware_utils::{N3f1, NZU32, NZUsize, TryCollect};
use constantinople_primitives::proposal::{MAXIMUM_BLOCK_SIZE, max_transaction_bytes};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    num::{NonZeroU32, NonZeroUsize},
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::Level;
use tracing_subscriber::fmt;
use url::Url;

/// Pins a 2 GiB arena that is never purged. Other arenas keep freed memory for ten seconds.
#[global_allocator]
static ALLOC: MiMalloc = MiMalloc::new(Config {
    purge: Purge::After(Duration::from_secs(10)),
    reserve: Some(Reserve::pinned(2 << 30)),
    ..Config::DEFAULT
});

const STORAGE_CLASS: &str = "gp3";
const DEFAULT_CHAIN_INDEXER_INSTANCE_TYPE: &str = "c8gb.4xlarge";
const DEFAULT_CHAIN_INDEXER_STORAGE_SIZE: i32 = 500;
const CHAIN_INDEXER_STORAGE_CLASS: &str = "io2";
const DEFAULT_CHAIN_INDEXER_STORAGE_IOPS: i32 = 16_000;
const EXOWARE_AVAILABILITY_ZONE_GROUP: &str = "exoware";
const DASHBOARD_FILE: &str = "dashboard.json";
const DEPLOYER_CONFIG_FILE: &str = "config.yaml";
const PEERS_CONFIG_FILE: &str = "peers.yaml";
const VALIDATOR_BINARY_FILE: &str = "validator";
const SPAMMER_BINARY_FILE: &str = "spammer";
const SPAMMER_CONFIG_FILE: &str = "spammer.yaml";
const CHAIN_INDEXER_BINARY_FILE: &str = "chain-indexer";
const CHAIN_INDEXER_CONFIG_FILE: &str = "chain-indexer.yaml";
const CHAIN_INDEXER_DATA_DIR: &str = "chain-indexer";
const CHAIN_INDEXER_HOST: &str = "chain-indexer";
const EXPLORER_INDEXER_BINARY_FILE: &str = "explorer-indexer";
const EXPLORER_INDEXER_CONFIG_FILE: &str = "explorer-indexer.yaml";
const EXPLORER_INDEXER_HOST: &str = "explorer-indexer";
const SPAMMER_HOST: &str = "spammer";
const SIMPLEX_VERIFICATION_MATERIAL_FILE: &str = "simplex-verification-material.hex";
const DEFAULT_CHAIN_INDEXER_PORT: u16 = 8090;
const DEFAULT_EXPLORER_INDEXER_PORT: u16 = 8092;
const DEFAULT_BOOTSTRAPPERS: usize = 3;
const INDEXER_UPLOAD_MAX_IN_FLIGHT: usize = 64;
const INDEXER_UPLOAD_BUDGET_BYTES: u64 = 3 * 1024 * 1024 * 1024;
const DEFAULT_SPAMMER_PRESIGNED_BATCHES: usize = 16;
const DEFAULT_SPAMMER_RAYON_THREADS: usize = 2;
const DEFAULT_PUBLIC_KEY_CACHE_SIZE: usize = 100_000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StartupModeConfig {
    #[default]
    MarshalSync,
    StateSync,
}

/// EC2 bandwidth weighting, which shifts an instance's bandwidth between
/// network traffic and EBS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum BandwidthWeighting {
    /// The instance type's standard split.
    Default,
    /// Network bandwidth at the expense of EBS bandwidth.
    #[value(name = "vpc-1")]
    Vpc1,
    /// EBS bandwidth at the expense of network bandwidth.
    #[value(name = "ebs-1")]
    Ebs1,
}

#[derive(Parser)]
#[command(name = "constantinople-deploy")]
struct Cli {
    /// Subcommand to run.
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Generate(Box<GenerateArgs>),
    SimplexVerificationMaterial(SimplexVerificationMaterialArgs),
}

#[derive(Debug, Args)]
struct SimplexVerificationMaterialArgs {
    /// Generated validator or secondary YAML containing `dkg_output`.
    #[arg(long)]
    config: PathBuf,
}

#[derive(Args)]
pub(crate) struct GenerateArgs {
    /// Number of primary (voting) validators.
    #[arg(long)]
    validators: u32,
    /// Include the full indexer secondary and shared indexer services.
    #[arg(long, default_value_t = false)]
    indexer: bool,
    /// Include a transaction relayer secondary.
    #[arg(long, default_value_t = false)]
    relayer: bool,
    /// Directory to write the generated deployment into.
    #[arg(long)]
    output_dir: PathBuf,
    /// Logging verbosity (e.g. info, debug, trace).
    #[arg(long, default_value = "info")]
    log_level: String,
    /// Tokio worker threads per validator runtime.
    #[arg(long, default_value_t = 2)]
    worker_threads: usize,
    /// Rayon threads per validator for parallel verification.
    #[arg(long, default_value_t = 2)]
    rayon_threads: usize,
    /// Override Tokio worker threads for the indexer secondary.
    #[arg(long)]
    indexer_worker_threads: Option<NonZeroUsize>,
    /// Override engine Rayon threads for the indexer secondary.
    #[arg(long)]
    indexer_rayon_threads: Option<NonZeroUsize>,
    /// Rayon threads reserved for index publication.
    #[arg(long, default_value_t = default_publisher_rayon_threads())]
    indexer_publisher_rayon_threads: NonZeroUsize,
    /// Capacity of each node's decompressed secp256r1 (WebAuthn) public key cache.
    #[arg(long, default_value_t = DEFAULT_PUBLIC_KEY_CACHE_SIZE)]
    public_key_cache_size: usize,
    /// Maximum encoded block bytes, including framing. At most 16 MiB.
    /// Submission budgets reserve space for block encoding overhead.
    #[arg(long = "max-propose-bytes", default_value_t = default_max_propose_bytes())]
    max_propose_bytes: usize,
    /// Maximum mempool size in bytes.
    #[arg(long = "max-pool-bytes", default_value_t = default_max_pool_bytes())]
    max_pool_bytes: usize,
    /// Capacity in bytes of each validator's state QMDB page cache.
    #[arg(long = "state-page-cache-bytes", default_value_t = default_state_page_cache_bytes())]
    state_page_cache_bytes: usize,
    /// Capacity in bytes of each validator's history page cache, shared by
    /// the block, finalization, and marshal archives, transaction history,
    /// and the simplex vote journal.
    #[arg(long = "history-page-cache-bytes", default_value_t = default_history_page_cache_bytes())]
    history_page_cache_bytes: usize,
    /// Startup sync mode for the generated validators.
    #[arg(long, value_enum, default_value_t = StartupModeConfig::MarshalSync)]
    startup: StartupModeConfig,
    /// Views per leader term. One rotates the leader every view.
    #[arg(long, default_value_t = NZU32!(1))]
    leader_term_length: NonZeroU32,
    /// Views a stable leader may run ahead of certified ancestry.
    #[arg(long, default_value_t = 16)]
    leader_optimistic_views: u64,
    /// Serve mempool proposal requests ahead of other queued messages.
    #[arg(long, default_value_t = false)]
    mempool_propose_priority: bool,
    /// End a proposal build after a selection round that drops nothing.
    #[arg(long, default_value_t = false)]
    propose_skip_final_refill: bool,

    /// Include a spammer instance in the deployment.
    #[arg(long, default_value_t = false)]
    spammer: bool,
    /// Number of spam accounts per relayer submitter.
    #[arg(long, default_value_t = 10)]
    spammer_accounts: u32,
    /// Transfer value per spam transaction.
    #[arg(long, default_value_t = 1)]
    spammer_value: u64,
    /// Seed offset for deterministic spam accounts. Omit for fresh accounts.
    #[arg(long)]
    spammer_seed_offset: Option<u64>,
    /// Number of rayon threads for spammer parallel signing.
    #[arg(long, default_value_t = DEFAULT_SPAMMER_RAYON_THREADS)]
    spammer_rayon_threads: usize,
    /// Fractional account-count jitter per spammer batch.
    ///
    /// `0.2` submits `spammer_accounts + rand(0..=floor(spammer_accounts * 0.2))`
    /// txs per batch.
    #[arg(long, default_value_t = 0.0, value_parser = parse_accounts_jitter)]
    spammer_accounts_jitter: f64,
    /// Concurrent spammer submitters. Defaults to the validator count.
    /// Set explicitly to keep offered load independent of validator count.
    #[arg(long = "spammer-submitters")]
    spammer_submitters: Option<usize>,
    /// Fully signed local batches to keep ready per spammer submitter.
    #[arg(long, default_value_t = DEFAULT_SPAMMER_PRESIGNED_BATCHES)]
    spammer_presigned_batches: usize,

    /// Deployment target (local or remote).
    #[command(subcommand)]
    target: GenerateTarget,
}

#[derive(Subcommand)]
#[expect(
    clippy::large_enum_variant,
    reason = "constructed once per invocation, so the size imbalance is harmless"
)]
enum GenerateTarget {
    Local(LocalArgs),
    Remote(RemoteArgs),
}

#[derive(Debug, Args)]
pub(crate) struct LocalArgs {
    /// Base p2p listen port; each validator is offset from this.
    #[arg(long, default_value_t = 9000)]
    base_port: u16,
    /// Base HTTP port; each validator is offset from this.
    #[arg(long, default_value_t = 8080)]
    base_http_port: u16,
    /// Base metrics port; each validator is offset from this.
    #[arg(long, default_value_t = 9090)]
    base_metrics_port: u16,
    /// Local `chain-indexer` Store port.
    #[arg(long = "chain-indexer-port", default_value_t = DEFAULT_CHAIN_INDEXER_PORT)]
    chain_indexer_port: u16,
    /// RocksDB parallelism for the local `chain-indexer` store. Omitted
    /// leaves RocksDB's stock parallelism.
    #[arg(long = "chain-indexer-db-parallelism")]
    chain_indexer_db_parallelism: Option<i32>,
    /// Local `explorer-indexer` HTTP port.
    #[arg(long = "explorer-indexer-port", default_value_t = DEFAULT_EXPLORER_INDEXER_PORT)]
    explorer_indexer_port: u16,
}

#[derive(Args)]
pub(crate) struct RemoteArgs {
    /// AWS regions to spread validators across (comma-separated).
    #[arg(long, value_delimiter = ',')]
    regions: Vec<String>,
    /// EC2 instance type for validators.
    #[arg(long)]
    instance_type: String,
    /// EC2 instance type for the indexer secondary. Defaults to --instance-type.
    #[arg(long)]
    indexer_instance_type: Option<String>,
    /// Validator EBS volume size in GiB.
    #[arg(long)]
    storage_size: i32,
    /// Provisioned IOPS for validator gp3 volumes (EBS default when unset).
    #[arg(long = "storage-iops")]
    storage_iops: Option<i32>,
    /// Provisioned throughput (MiB/s) for validator gp3 volumes (EBS default
    /// when unset). Validators write ~4x the raw block per view; the gp3
    /// default of 125 MiB/s throttles the cluster before either the NIC or
    /// consensus does.
    #[arg(long = "storage-throughput")]
    storage_throughput: Option<i32>,
    /// Absolute HTTP or HTTPS URL of an external exoware store that supports reads and writes.
    /// The URL is used verbatim by every store consumer. Providing it replaces
    /// the simulator-backed chain-indexer. No chain-indexer instance, binary,
    /// config, or port rule is generated.
    #[arg(long = "store-url", value_parser = parse_service_url)]
    store_url: Option<String>,
    /// Origin of an already-running explorer indexer backed by the external store.
    #[arg(long = "indexer-url", requires = "store_url", value_parser = parse_service_url)]
    indexer_url: Option<String>,
    /// Store writer credential for the validator indexer secondary.
    #[arg(
        long = "store-api-key",
        env = "CONSTANTINOPLE_STORE_API_KEY",
        hide_env_values = true,
        requires = "store_url"
    )]
    store_api_key: Option<String>,
    /// Store read credential for the managed explorer service.
    #[arg(
        long = "adapter-store-api-key",
        env = "CONSTANTINOPLE_ADAPTER_STORE_API_KEY",
        hide_env_values = true,
        requires = "store_url"
    )]
    adapter_store_api_key: Option<String>,
    /// Instance type for the shared chain-indexer instance.
    #[arg(long = "chain-indexer-instance-type", default_value = DEFAULT_CHAIN_INDEXER_INSTANCE_TYPE)]
    chain_indexer_instance_type: String,
    /// Storage size (GiB) for the shared chain-indexer instance.
    #[arg(long = "chain-indexer-storage-size", default_value_t = DEFAULT_CHAIN_INDEXER_STORAGE_SIZE)]
    chain_indexer_storage_size: i32,
    /// Provisioned IOPS for the shared chain-indexer io2 volume.
    #[arg(long = "chain-indexer-storage-iops", default_value_t = DEFAULT_CHAIN_INDEXER_STORAGE_IOPS)]
    chain_indexer_storage_iops: i32,
    /// EC2 instance type for the monitoring instance.
    #[arg(long)]
    monitoring_instance_type: String,
    /// Monitoring instance EBS volume size in GiB.
    #[arg(long)]
    monitoring_storage_size: i32,
    /// Grafana dashboard JSON to provision on the monitoring instance.
    #[arg(long)]
    dashboard: PathBuf,
    /// Validator p2p listen port.
    #[arg(long, default_value_t = 9000)]
    listen_port: u16,
    /// Validator HTTP port.
    #[arg(long, default_value_t = 8080)]
    http_port: u16,
    /// CIDR ranges allowed to reach the validator HTTP port (comma-separated).
    #[arg(long = "http-cidr", value_delimiter = ',')]
    http_cidrs: Vec<String>,
    /// Shared `chain-indexer` Store port.
    #[arg(long = "chain-indexer-port", default_value_t = DEFAULT_CHAIN_INDEXER_PORT)]
    chain_indexer_port: u16,
    /// RocksDB parallelism for the shared `chain-indexer` store. Omitted
    /// leaves RocksDB's stock parallelism.
    #[arg(long = "chain-indexer-db-parallelism")]
    chain_indexer_db_parallelism: Option<i32>,
    /// Shared `explorer-indexer` HTTP port.
    #[arg(long = "explorer-indexer-port", default_value_t = DEFAULT_EXPLORER_INDEXER_PORT)]
    explorer_indexer_port: u16,
    /// Enable validator CPU profiling.
    #[arg(long, default_value_t = false)]
    profiling: bool,
    /// Trace sampling rate (0.0..=1.0) for validator uploads to the monitoring
    /// instance; 0.0 disables uploads.
    #[arg(long, default_value_t = 0.0, value_parser = parse_sampling_rate)]
    traces: f64,
    /// Instance type for the spammer (defaults to --instance-type).
    #[arg(long)]
    spammer_instance_type: Option<String>,
    /// Storage size (GiB) for the spammer instance.
    #[arg(long, default_value_t = 25)]
    spammer_storage_size: i32,
    /// EC2 bandwidth weighting for the primary validators, the relayer, and the
    /// spammer. Other instances keep the instance type's standard split.
    #[arg(long, value_enum, default_value_t = BandwidthWeighting::Default)]
    bandwidth_weighting: BandwidthWeighting,
}

/// Spammer configuration, written as YAML by deploy and read by the spammer binary.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct SpammerConfig {
    /// Number of spam accounts per submitter.
    pub accounts: u32,
    /// Transfer value per spam transaction.
    pub value: u64,
    /// Explicit seed offset for reproducible spam account keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_offset: Option<u64>,
    /// Number of rayon threads used for parallel signing.
    #[serde(default = "default_spammer_rayon_threads")]
    pub rayon_threads: usize,
    /// Local HTTP port the spammer serves on.
    pub http_port: u16,
    /// Relayer URL used for transaction submission.
    pub relayer_url: String,
    /// Independent target-leader streams to run when submitting through a relayer.
    #[serde(default, skip_serializing_if = "usize_is_zero")]
    pub relayer_submitters: usize,
    /// Fully signed local batches to keep ready per submitter.
    #[serde(default = "default_spammer_presigned_batches")]
    pub presigned_batches: usize,
    /// Hex-encoded ed25519 public keys of primary (voting) validators.
    ///
    /// In `--hosts` mode the spammer cannot distinguish primaries from
    /// secondaries by host name alone, because both use hex pubkeys. This list
    /// lets the spammer target only primaries.
    #[serde(default)]
    pub primary_validators: Vec<String>,
    /// Fractional account-count jitter per submitted batch.
    ///
    /// `0.2` submits `accounts + rand(0..=floor(accounts * 0.2))` txs per batch.
    #[serde(default)]
    pub accounts_jitter: f64,
}

/// Relayer configuration written into the relayer secondary's YAML.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct RelayerConfig {
    /// Per-leader relayer endpoints.
    pub leaders: Vec<RelayerLeaderConfig>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct RelayerLeaderConfig {
    /// Hex-encoded ed25519 public key of the target leader.
    pub public_key: String,
    /// Relayer URL for submitting to this leader.
    pub url: String,
}

fn parse_service_url(value: &str) -> Result<String, &'static str> {
    const ERROR: &str = "expected an absolute HTTP or HTTPS service base without credentials, a query, or a fragment";

    // Do not let URL normalization hide whitespace or a pasted byte-order mark.
    if value
        .chars()
        .any(|character| character.is_whitespace() || character == '\u{feff}')
    {
        return Err(ERROR);
    }

    // Match the Store client's parser so invalid endpoints fail before deployment.
    let uri = value.parse::<http::Uri>().map_err(|_| ERROR)?;
    if uri.authority().is_none() || !matches!(uri.scheme_str(), Some("http" | "https")) {
        return Err(ERROR);
    }

    let parsed = Url::parse(value).map_err(|_| ERROR)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed
            .password()
            .is_some_and(|password| !password.is_empty())
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ERROR);
    }

    // Consumers must receive the operator's base path without URL normalization.
    Ok(value.to_owned())
}

fn parse_accounts_jitter(value: &str) -> Result<f64, String> {
    let parsed = value
        .parse::<f64>()
        .map_err(|error| format!("invalid jitter: {error}"))?;
    if !(0.0..=1.0).contains(&parsed) {
        return Err("jitter must be between 0 and 1".to_string());
    }
    Ok(parsed)
}

fn parse_sampling_rate(value: &str) -> Result<f64, String> {
    let parsed = value
        .parse::<f64>()
        .map_err(|error| format!("invalid sampling rate: {error}"))?;
    if !(0.0..=1.0).contains(&parsed) {
        return Err("sampling rate must be between 0 and 1".to_string());
    }
    Ok(parsed)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct NamedBootstrapperEntry {
    /// Hex-encoded ed25519 public key of the bootstrapper.
    public_key: String,
    /// Host name used to resolve the bootstrapper's address.
    name: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ValidatorConfig {
    /// Hex-encoded ed25519 private key.
    private_key: String,
    /// Hex-encoded DKG output (threshold public material).
    dkg_output: String,
    /// Hex-encoded DKG share for this validator. Empty string `""` indicates
    /// a secondary (non-voting) validator that holds no share.
    dkg_share: String,
    /// Startup sync mode.
    startup: StartupModeConfig,
    /// p2p listen port.
    listen_port: u16,
    /// Hex-encoded ed25519 public key of the genesis leader.
    genesis_leader: String,
    /// Storage partition prefix for this validator.
    partition_prefix: String,
    /// Number of primary validators (DKG participant count).
    num_validators: u32,
    /// Hex-encoded ed25519 public keys of the primary (voting) validators,
    /// in DKG order. Must be identical across every validator config in the
    /// deployment so all peers agree on the discovery bitvec ordering.
    primary_validators: Vec<String>,
    /// Hex-encoded ed25519 public keys of the secondary (non-voting) validators.
    /// Must be identical across every validator config in the deployment.
    secondary_validators: Vec<String>,
    /// Logging verbosity.
    log_level: String,
    /// Tokio worker threads.
    worker_threads: usize,
    /// Rayon threads for parallel verification.
    rayon_threads: usize,
    /// HTTP service port.
    http_port: u16,
    /// Prometheus metrics port.
    metrics_port: u16,
    /// Maximum encoded block bytes, including framing. At most 16 MiB.
    max_propose_bytes: usize,
    /// Views per leader term. One rotates the leader every view.
    leader_term_length: NonZeroU32,
    /// Views a stable leader may run ahead of certified ancestry.
    leader_optimistic_views: u64,
    /// Whether the mempool serves proposal requests ahead of other queued
    /// messages.
    mempool_propose_priority: bool,
    /// Whether a proposal build ends after a selection round that drops
    /// nothing.
    propose_skip_final_refill: bool,
    /// Maximum mempool size in bytes.
    max_pool_bytes: usize,
    /// Capacity in bytes of the engine's state QMDB page cache.
    state_page_cache_bytes: usize,
    /// Capacity in bytes of the engine's history page cache, shared by the
    /// block, finalization, and marshal archives, transaction history, and
    /// the simplex vote journal.
    history_page_cache_bytes: usize,
    /// Capacity of the decompressed secp256r1 (WebAuthn) public key cache.
    #[serde(default = "default_public_key_cache_size")]
    public_key_cache_size: usize,
    /// Trace sampling rate (0.0..=1.0); 0.0 disables uploads.
    #[serde(default)]
    traces: f64,
    /// Bootstrapper peers used for initial p2p discovery.
    bootstrappers: Vec<NamedBootstrapperEntry>,
    /// Optional indexer wiring. Set on secondary validators only when the
    /// local or remote deploy job enables the shared `chain-indexer` stack.
    /// Primaries always leave this unset; the validator runtime ignores it for
    /// primaries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    indexer: Option<IndexerConfig>,
    /// Optional relayer wiring for the generated relayer secondary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    relayer: Option<RelayerConfig>,
}

/// Indexer wiring serialized into a secondary validator's YAML.
///
/// Mirrors the schema in `bin/validator/src/config.rs::IndexerConfig`. The
/// shared Store backs raw KV rows, SQL metadata rows, QMDB
/// operation logs, and simplex artifacts.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct IndexerConfig {
    /// URL of the Store receiving finalized uploads.
    pub store_url: String,
    /// Store writer credential used by the indexer secondary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// Rayon threads reserved for index publication.
    #[serde(default = "default_publisher_rayon_threads")]
    pub publisher_rayon_threads: NonZeroUsize,
    /// Caps concurrent uploads after byte admission.
    pub upload_max_in_flight: usize,
    /// Bounds estimated memory held across upload stages.
    pub upload_budget_bytes: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ChainIndexerConfig {
    /// Store port the chain-indexer listens on.
    pub port: u16,
    /// Directory for chain-indexer data.
    pub data_dir: PathBuf,
    /// RocksDB parallelism (background compaction/flush jobs). Omitted
    /// leaves RocksDB's stock parallelism.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_parallelism: Option<i32>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ExplorerIndexerConfig {
    /// Optional separate metrics listener.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics_port: Option<u16>,
    /// Port the explorer API listens on.
    pub port: u16,
    /// URL of the Store to read from.
    pub store_url: String,
    /// Store read credential used by the explorer API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// Transaction admission origin, excluding the /transactions path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relayer_url: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct PeerEntry {
    /// Host name (hex-encoded public key).
    name: String,
    /// p2p socket address.
    p2p: String,
    /// HTTP socket address.
    http: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct PeersConfig {
    /// Primary validator peers.
    pub validators: Vec<PeerEntry>,
    /// Secondary (non-voting) validator peers.
    #[serde(default)]
    pub secondaries: Vec<PeerEntry>,
}

#[derive(Debug, Deserialize)]
struct SimplexMaterialConfig {
    /// Hex-encoded DKG output.
    dkg_output: String,
    /// Number of primary validators.
    num_validators: u32,
}

pub(crate) struct ClusterMaterial {
    /// Primary (voting) validator private keys.
    pub signers: Vec<ed25519::SigningKey>,
    /// Primary (voting) validator public keys, in DKG order.
    pub public_keys: Vec<ed25519::VerifyingKey>,
    /// Secondary (non-voting) validator private keys.
    pub secondary_signers: Vec<ed25519::SigningKey>,
    /// Secondary (non-voting) validator public keys.
    pub secondary_public_keys: Vec<ed25519::VerifyingKey>,
    /// DKG output over the primary validators.
    pub dkg_output: dkg::Output<MinSig, ed25519::VerifyingKey>,
    /// DKG share per primary validator.
    pub shares: BTreeMap<ed25519::VerifyingKey, Share>,
    /// Hex-encoded genesis leader public key.
    pub genesis_leader: String,
}

impl ClusterMaterial {
    pub fn primary_hex(&self) -> Vec<String> {
        self.public_keys
            .iter()
            .map(|pk| hex(&pk.encode()))
            .collect()
    }

    pub fn secondary_hex(&self) -> Vec<String> {
        self.secondary_public_keys
            .iter()
            .map(|pk| hex(&pk.encode()))
            .collect()
    }

    pub fn simplex_verification_material_hex(&self) -> String {
        hex(&self.dkg_output.public().public().encode())
    }
}

const fn usize_is_zero(value: &usize) -> bool {
    *value == 0
}

const fn default_spammer_presigned_batches() -> usize {
    DEFAULT_SPAMMER_PRESIGNED_BATCHES
}

const fn default_spammer_rayon_threads() -> usize {
    DEFAULT_SPAMMER_RAYON_THREADS
}

const fn default_publisher_rayon_threads() -> NonZeroUsize {
    NZUsize!(2)
}

fn main() -> ExitCode {
    init_tracing();
    let cli = Cli::parse();

    let result = match &cli.command {
        Command::Generate(args) => match &args.target {
            GenerateTarget::Local(local_args) => local::generate(args, local_args),
            GenerateTarget::Remote(remote_args) => remote::generate(args, remote_args),
        },
        Command::SimplexVerificationMaterial(args) => {
            println!(
                "{}",
                simplex_verification_material_from_config(&args.config)
            );
            Ok(())
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Secondary ed25519 seeds are drawn from this offset onward to guarantee
/// disjointness from the primary seed range (which uses raw validator indices).
const SECONDARY_SEED_OFFSET: u64 = 1_000_000;

fn init_tracing() {
    fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .without_time()
        .compact()
        .init();
}

pub(crate) fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }

    std::env::current_dir()
        .expect("failed to read current directory")
        .join(path)
}

pub(crate) fn ensure_output_dir_missing(output_dir: &Path) {
    if fs::metadata(output_dir).is_ok() {
        panic!("output directory already exists: {}", output_dir.display());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecondaryRole {
    Indexer,
    Relayer,
}

pub(crate) fn secondary_roles(args: &GenerateArgs) -> Vec<SecondaryRole> {
    let mut roles = Vec::with_capacity(args.indexer as usize + args.relayer as usize);
    if args.indexer {
        roles.push(SecondaryRole::Indexer);
    }
    if args.relayer {
        roles.push(SecondaryRole::Relayer);
    }
    roles
}

pub(crate) fn total_secondaries(args: &GenerateArgs) -> u32 {
    secondary_roles(args).len() as u32
}

pub(crate) fn secondary_runtime_threads(
    args: &GenerateArgs,
    role: SecondaryRole,
) -> (usize, usize) {
    match role {
        SecondaryRole::Indexer => (
            args.indexer_worker_threads
                .map_or(args.worker_threads, NonZeroUsize::get),
            args.indexer_rayon_threads
                .map_or(args.rayon_threads, NonZeroUsize::get),
        ),
        SecondaryRole::Relayer => (args.worker_threads, args.rayon_threads),
    }
}

pub(crate) const fn indexer_enabled(args: &GenerateArgs) -> bool {
    args.indexer
}

pub(crate) fn validate_generate_args(args: &GenerateArgs) {
    assert!(
        !args.indexer || args.startup != StartupModeConfig::StateSync,
        "--indexer cannot be combined with --startup state-sync"
    );
    assert!(
        !args.spammer || args.relayer,
        "--spammer requires --relayer"
    );
    assert!(args.validators >= 4, "--validators must be at least 4");
    u16::try_from(args.validators).expect("--validators must be at most 65535");
    assert!(
        args.max_propose_bytes <= MAXIMUM_BLOCK_SIZE,
        "--max-propose-bytes {} exceeds encoded block limit {MAXIMUM_BLOCK_SIZE}",
        args.max_propose_bytes,
    );
    assert!(
        max_transaction_bytes(args.max_propose_bytes).is_some(),
        "--max-propose-bytes {} is too small for an encoded empty block",
        args.max_propose_bytes,
    );
    assert!(
        args.spammer_submitters != Some(0),
        "--spammer-submitters must be at least 1"
    );
}

pub(crate) fn generate_local_cluster_material(
    validators: u32,
    secondaries: u32,
) -> ClusterMaterial {
    let signers = (0..validators)
        .map(|index| ed25519::SigningKey::from_seed(index.into()))
        .collect::<Vec<_>>();
    let secondary_signers = (0..secondaries)
        .map(|index| ed25519::SigningKey::from_seed(SECONDARY_SEED_OFFSET + u64::from(index)))
        .collect::<Vec<_>>();
    build_cluster_material(
        signers,
        secondary_signers,
        &mut commonware_utils::test_rng(),
    )
}

pub(crate) fn generate_remote_cluster_material(
    validators: u32,
    secondaries: u32,
) -> ClusterMaterial {
    let mut rng = UnwrapErr(SysRng);
    let mut signers = (0..validators)
        .map(|_| ed25519::SigningKey::random(rng))
        .collect::<Vec<_>>();
    signers.sort_by_key(Signer::public_key);
    let mut secondary_signers = (0..secondaries)
        .map(|_| ed25519::SigningKey::random(rng))
        .collect::<Vec<_>>();
    secondary_signers.sort_by_key(Signer::public_key);
    build_cluster_material(signers, secondary_signers, &mut rng)
}

fn build_cluster_material(
    signers: Vec<ed25519::SigningKey>,
    secondary_signers: Vec<ed25519::SigningKey>,
    rng: &mut impl rand::CryptoRng,
) -> ClusterMaterial {
    let public_keys = signers.iter().map(Signer::public_key).collect::<Vec<_>>();
    let secondary_public_keys = secondary_signers
        .iter()
        .map(Signer::public_key)
        .collect::<Vec<_>>();

    // DKG runs over primary validators only; secondaries hold ed25519 identities
    // but no threshold share. The resulting polynomial's total must equal the
    // primary count or `threshold_scheme` will panic at validator load.
    let participants = public_keys.clone().into_iter().try_collect().unwrap();
    let (dkg_output, raw_shares) =
        dkg::deal::<MinSig, _, N3f1>(rng, Mode::NonZeroCounter, participants)
            .expect("DKG deal failed");
    let shares = raw_shares.into_iter().collect();
    let genesis_leader = hex(&public_keys[0].encode());

    ClusterMaterial {
        signers,
        public_keys,
        secondary_signers,
        secondary_public_keys,
        dkg_output,
        shares,
        genesis_leader,
    }
}

pub(crate) fn write_yaml_config<T: Serialize>(path: &Path, config: &T) {
    let raw = serde_yaml::to_string(config).expect("failed to serialize config");
    fs::write(path, raw).expect("failed to write config");
}

pub(crate) fn write_simplex_verification_material(output_dir: &Path, material: &ClusterMaterial) {
    fs::write(
        output_dir.join(SIMPLEX_VERIFICATION_MATERIAL_FILE),
        material.simplex_verification_material_hex(),
    )
    .expect("failed to write simplex verification material");
}

fn simplex_verification_material_from_config(config_path: &Path) -> String {
    let raw = fs::read_to_string(config_path).expect("failed to read validator config");
    let config: SimplexMaterialConfig =
        serde_yaml::from_str(&raw).expect("failed to parse validator config");
    let bytes = from_hex(&config.dkg_output).expect("bad dkg_output hex");
    let dkg_output = dkg::Output::<MinSig, ed25519::VerifyingKey>::read_cfg(
        &mut Copying(&bytes),
        &(NZU32!(config.num_validators), ModeVersion::v0()),
    )
    .expect("failed to decode dkg_output");
    hex(&dkg_output.public().public().encode())
}

pub(crate) fn default_bootstrappers(
    public_keys: &[ed25519::VerifyingKey],
) -> Vec<NamedBootstrapperEntry> {
    public_keys
        .iter()
        .take(DEFAULT_BOOTSTRAPPERS.min(public_keys.len()))
        .map(|public_key| {
            let name = hex(&public_key.encode());
            NamedBootstrapperEntry {
                public_key: name.clone(),
                name,
            }
        })
        .collect()
}

pub(crate) const fn default_max_propose_bytes() -> usize {
    8 * 1024 * 1024
}

pub(crate) const fn default_max_pool_bytes() -> usize {
    64 * 1024 * 1024
}

// Sized so operation-log pages stay cached, or at least in Clock2Q+ ghost
// history, until floor advancement reuses them.
pub(crate) const fn default_state_page_cache_bytes() -> usize {
    6 * 1024 * 1024 * 1024
}

pub(crate) const fn default_history_page_cache_bytes() -> usize {
    2 * 1024 * 1024 * 1024
}

pub(crate) const fn default_public_key_cache_size() -> usize {
    DEFAULT_PUBLIC_KEY_CACHE_SIZE
}

pub(crate) fn generate_deployer_tag() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    let process_id = std::process::id();
    format!("{timestamp:x}-{process_id:x}")
}

#[cfg(test)]
mod tests {
    use super::{
        BandwidthWeighting, Cli, Command, DEPLOYER_CONFIG_FILE, EXPLORER_INDEXER_CONFIG_FILE,
        ExplorerIndexerConfig, GenerateTarget, IndexerConfig, SIMPLEX_VERIFICATION_MATERIAL_FILE,
        VALIDATOR_BINARY_FILE, ValidatorConfig, generate_local_cluster_material, remote,
        simplex_verification_material_from_config, write_simplex_verification_material,
    };
    use clap::{CommandFactory, FromArgMatches, Parser, error::ErrorKind};
    use commonware_codec::Encode;
    use commonware_deployer::aws;
    use commonware_formatting::hex;
    use std::{
        fs,
        panic::{AssertUnwindSafe, catch_unwind},
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    // Ordinary parser cases must not inherit the operator's deployment credentials.
    fn parse_cli(
        args: impl IntoIterator<Item = impl Into<std::ffi::OsString> + Clone>,
    ) -> Result<Cli, clap::Error> {
        let command = Cli::command().mut_subcommand("generate", |command| {
            command.mut_subcommand("remote", |mut command| {
                for name in ["store_api_key", "adapter_store_api_key"] {
                    command = command.mut_arg(name, |argument| argument.env(None::<&str>));
                }
                command
            })
        });
        let matches = command.try_get_matches_from(args)?;
        Cli::from_arg_matches(&matches)
    }

    fn remote_cli_args() -> Vec<&'static str> {
        vec![
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
            "remote",
            "--regions",
            "us-east-1,us-west-2",
            "--instance-type",
            "c8g.large",
            "--storage-size",
            "25",
            "--monitoring-instance-type",
            "c8g.2xlarge",
            "--monitoring-storage-size",
            "100",
            "--dashboard",
            "dashboard.json",
        ]
    }

    #[test]
    fn cache_budgets_default_independently_and_allow_overrides() {
        let cli = parse_cli(remote_cli_args()).unwrap();
        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };
        assert_eq!(generate.state_page_cache_bytes, 6 * 1024 * 1024 * 1024);
        assert_eq!(generate.history_page_cache_bytes, 2 * 1024 * 1024 * 1024);

        let mut args = remote_cli_args();
        args.splice(
            2..2,
            [
                "--state-page-cache-bytes",
                "67108864",
                "--history-page-cache-bytes",
                "33554432",
            ],
        );
        let cli = parse_cli(args).unwrap();
        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };
        assert_eq!(generate.state_page_cache_bytes, 64 * 1024 * 1024);
        assert_eq!(generate.history_page_cache_bytes, 32 * 1024 * 1024);
    }

    #[test]
    fn remote_parses_bandwidth_weighting() {
        for (options, expected) in [
            (&[][..], BandwidthWeighting::Default),
            (
                &["--bandwidth-weighting", "default"][..],
                BandwidthWeighting::Default,
            ),
            (
                &["--bandwidth-weighting", "vpc-1"][..],
                BandwidthWeighting::Vpc1,
            ),
            (
                &["--bandwidth-weighting", "ebs-1"][..],
                BandwidthWeighting::Ebs1,
            ),
        ] {
            let mut args = remote_cli_args();
            args.extend_from_slice(options);
            let Command::Generate(generate) = parse_cli(args).unwrap().command else {
                panic!("expected generate command");
            };
            let GenerateTarget::Remote(remote) = generate.target else {
                panic!("expected remote target");
            };
            assert_eq!(remote.bandwidth_weighting, expected);
        }

        let mut args = remote_cli_args();
        args.extend_from_slice(&["--bandwidth-weighting", "vpc-2"]);
        let error = parse_cli(args)
            .err()
            .expect("unknown weighting should be rejected");
        assert_eq!(error.kind(), ErrorKind::InvalidValue);
    }

    #[test]
    fn remote_parses_http_cidrs() {
        let cli = parse_cli([
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
            "remote",
            "--regions",
            "us-east-1,us-west-2",
            "--instance-type",
            "c8g.large",
            "--storage-size",
            "25",
            "--monitoring-instance-type",
            "c8g.2xlarge",
            "--monitoring-storage-size",
            "100",
            "--dashboard",
            "dashboard.json",
            "--http-cidr",
            "10.0.0.0/8,198.51.100.4/32",
        ])
        .expect("remote invocation should parse");

        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };
        let generate = *generate;
        let GenerateTarget::Remote(remote) = generate.target else {
            panic!("expected remote target");
        };

        assert_eq!(
            remote.http_cidrs,
            vec!["10.0.0.0/8".to_string(), "198.51.100.4/32".to_string()]
        );
    }

    #[test]
    fn remote_parses_indexer_origin_and_credentials() {
        let mut args = remote_cli_args();
        args.extend([
            "--store-url",
            "https://store.example.com",
            "--indexer-url",
            "https://explorer.example.com",
            "--store-api-key",
            "writer-key",
            "--adapter-store-api-key",
            "reader-key",
        ]);

        let cli = parse_cli(args).expect("remote invocation should parse");
        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };
        let generate = *generate;
        let GenerateTarget::Remote(remote) = generate.target else {
            panic!("expected remote target");
        };

        assert_eq!(
            remote.store_url.as_deref(),
            Some("https://store.example.com")
        );
        assert_eq!(
            remote.indexer_url.as_deref(),
            Some("https://explorer.example.com")
        );
        assert_eq!(remote.store_api_key.as_deref(), Some("writer-key"));
        assert_eq!(remote.adapter_store_api_key.as_deref(), Some("reader-key"));
    }

    #[test]
    fn remote_service_urls_reject_invalid_values() {
        for flag in ["--store-url", "--indexer-url"] {
            for value in [
                "",
                "service.example.com",
                "https:store.example.com",
                "https:/store.example.com",
                "https:///store.example.com",
                "https://store.example.com\\path",
                "/service",
                "ftp://service.example.com",
                "https://#fragment",
                "http://?query",
                "https://[invalid]",
                "https://service.example.com:65536",
                "https://user:password@service.example.com",
                "https://user@service.example.com",
                "https://:password@service.example.com",
                "https://service.example.com/path?query",
                "https://service.example.com/path#fragment",
                "https://service.example.com/path with space",
                " https://service.example.com",
                "https://service.example.com\n",
                "https://service.example.com/\tpath",
                "https://service.example.com/\u{a0}path",
                "https://service.example.com/\u{85}path",
                "https://service.example.com/\u{feff}path",
                "https://service.example.com/base?",
                "https://service.example.com/base#",
                "https://service.example.com/base?#",
            ] {
                let mut args = remote_cli_args();
                if flag != "--store-url" {
                    args.extend(["--store-url", "https://store.example.com"]);
                }
                args.extend([flag, value]);

                let error = parse_cli(args)
                    .err()
                    .unwrap_or_else(|| panic!("{flag} accepted {value:?}"));
                assert_eq!(error.kind(), ErrorKind::ValueValidation, "{flag} {value:?}");
            }
        }
    }

    #[test]
    fn remote_service_urls_preserve_accepted_values() {
        for value in [
            "http://localhost:8090",
            "https://service.example.com",
            "https://service.example.com/base/",
            "HTTPS://Service.Example.COM:443/a/../base/%2f",
            "http://127.0.0.1:8090/base",
            "https://[::1]:8090/base",
            "https://service.example.com/path%20with%20space",
            "https://service.example.com/path%3F%23",
        ] {
            let mut args = remote_cli_args();
            for flag in ["--store-url", "--indexer-url"] {
                args.extend([flag, value]);
            }
            let cli = parse_cli(args).expect("service bases should parse");
            let Command::Generate(generate) = cli.command else {
                panic!("expected generate command");
            };
            let GenerateTarget::Remote(remote) = generate.target else {
                panic!("expected remote target");
            };

            assert_eq!(remote.store_url.as_deref(), Some(value));
            assert_eq!(remote.indexer_url.as_deref(), Some(value));
        }
    }

    #[test]
    fn remote_generator_preserves_parsed_store_base() {
        let store_url = "HTTPS://Store.Example.COM:443/a/../base/%2f/";
        let mut args = remote_cli_args();
        args.insert(2, "--indexer");
        args.extend(["--store-url", store_url]);
        let cli = parse_cli(args).expect("external Store should parse");
        let Command::Generate(mut generate) = cli.command else {
            panic!("expected generate command");
        };
        let root = unique_temp_dir("remote-store-base");
        fs::create_dir_all(&root).expect("create temporary directory");
        let dashboard = root.join("dashboard.json");
        fs::write(&dashboard, "{}").expect("write dashboard");
        generate.output_dir = root.join("deployment");
        let GenerateTarget::Remote(remote) = &mut generate.target else {
            panic!("expected remote target");
        };
        remote.dashboard = dashboard;
        let GenerateTarget::Remote(remote) = &generate.target else {
            panic!("expected remote target");
        };

        remote::generate(&generate, remote).expect("generate remote deployment");

        let yaml = fs::read_to_string(generate.output_dir.join(EXPLORER_INDEXER_CONFIG_FILE))
            .expect("read generated explorer config");
        let config: ExplorerIndexerConfig =
            serde_yaml::from_str(&yaml).expect("decode explorer config");
        assert_eq!(config.store_url, store_url);

        let yaml = fs::read_to_string(generate.output_dir.join(DEPLOYER_CONFIG_FILE))
            .expect("read generated deployment config");
        let deployment: aws::Config =
            serde_yaml::from_str(&yaml).expect("decode deployment config");
        let indexers = deployment
            .instances
            .iter()
            .filter(|instance| instance.binary == VALIDATOR_BINARY_FILE)
            .filter_map(|instance| {
                let yaml = fs::read_to_string(generate.output_dir.join(&instance.config))
                    .expect("read generated validator config");
                let config: ValidatorConfig =
                    serde_yaml::from_str(&yaml).expect("decode validator config");
                config.indexer
            })
            .collect::<Vec<_>>();
        assert_eq!(indexers.len(), 1);
        assert_eq!(indexers[0].store_url, store_url);

        fs::remove_dir_all(root).expect("remove generated deployment");
    }

    #[test]
    fn remote_store_url_requires_indexer() {
        let mut args = remote_cli_args();
        args.extend([
            "--store-url",
            "https://store.example.com",
            "--store-api-key",
            "writer-key",
        ]);
        let cli = parse_cli(args).expect("external Store should parse");
        let Command::Generate(mut generate) = cli.command else {
            panic!("expected generate command");
        };
        assert!(!generate.indexer);
        let root = unique_temp_dir("remote-store-requires-indexer");
        fs::create_dir_all(&root).expect("create temporary directory");
        let dashboard = root.join("dashboard.json");
        fs::write(&dashboard, "{}").expect("write dashboard");
        generate.output_dir = root.join("deployment");
        let GenerateTarget::Remote(remote) = &mut generate.target else {
            panic!("expected remote target");
        };
        remote.dashboard = dashboard;
        let GenerateTarget::Remote(remote) = &generate.target else {
            panic!("expected remote target");
        };

        let result = catch_unwind(AssertUnwindSafe(|| remote::generate(&generate, remote)));
        let output_exists = generate.output_dir.exists();
        fs::remove_dir_all(root).expect("remove temporary directory");

        assert!(result.is_err(), "--store-url requires --indexer");
        assert!(!output_exists, "invalid arguments must not write a bundle");
    }

    #[test]
    fn remote_indexer_origin_requires_external_store() {
        let mut args = remote_cli_args();
        args.extend(["--indexer-url", "https://explorer.example.com"]);
        let error = parse_cli(args)
            .err()
            .expect("indexer origin requires an external Store");
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn remote_store_credentials_each_require_external_store() {
        for flag in ["--store-api-key", "--adapter-store-api-key"] {
            let mut args = remote_cli_args();
            args.extend([flag, "secret-key"]);
            let error = parse_cli(args)
                .err()
                .expect("Store credentials require an external Store");

            assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
        }
    }

    #[test]
    fn deployment_credentials_resolve_from_environment() {
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "tests::child_deployment_credentials_from_environment",
                "--exact",
                "--ignored",
            ])
            .env("CONSTANTINOPLE_STORE_API_KEY", "environment-writer")
            .env("CONSTANTINOPLE_ADAPTER_STORE_API_KEY", "environment-reader")
            .output()
            .expect("child test runs");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed"));
    }

    #[test]
    #[ignore = "run with isolated credentials by deployment_credentials_resolve_from_environment"]
    fn child_deployment_credentials_from_environment() {
        let mut args = remote_cli_args();
        assert!(Cli::try_parse_from(args.clone()).is_err());
        args.extend(["--store-url", "https://store.example.com"]);
        let cli = Cli::try_parse_from(args).expect("environment credentials parse");
        let Command::Generate(generate) = cli.command else {
            panic!("generate command")
        };
        let GenerateTarget::Remote(remote) = generate.target else {
            panic!("remote target")
        };
        assert_eq!(remote.store_api_key.as_deref(), Some("environment-writer"));
        assert_eq!(
            remote.adapter_store_api_key.as_deref(),
            Some("environment-reader")
        );

        let mut args = remote_cli_args();
        args.extend([
            "--store-url",
            "https://store.example.com",
            "--store-api-key",
            "explicit-writer",
        ]);
        let cli = Cli::try_parse_from(args).expect("explicit credential parses");
        let Command::Generate(generate) = cli.command else {
            panic!("generate command")
        };
        let GenerateTarget::Remote(remote) = generate.target else {
            panic!("remote target")
        };
        assert_eq!(remote.store_api_key.as_deref(), Some("explicit-writer"));
    }

    #[test]
    fn generated_indexer_api_keys_default_and_omit() {
        let indexer: IndexerConfig = serde_yaml::from_str(
            "store_url: https://store.example.com\nupload_max_in_flight: 64\nupload_budget_bytes: 1024\n",
        )
        .expect("indexer config without an API key should parse");
        let explorer: ExplorerIndexerConfig =
            serde_yaml::from_str("port: 8092\nstore_url: https://store.example.com\n")
                .expect("explorer config without an API key should parse");

        assert_eq!(indexer.api_key, None);
        assert_eq!(explorer.api_key, None);

        for raw in [
            serde_yaml::to_string(&indexer).expect("indexer config should serialize"),
            serde_yaml::to_string(&explorer).expect("explorer config should serialize"),
        ] {
            assert!(!raw.contains("api_key"));
        }
    }

    #[test]
    fn remote_parses_traces_sampling_rate() {
        let cli = parse_cli([
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
            "remote",
            "--regions",
            "us-east-1,us-west-2",
            "--instance-type",
            "c8g.large",
            "--storage-size",
            "25",
            "--monitoring-instance-type",
            "c8g.2xlarge",
            "--monitoring-storage-size",
            "100",
            "--dashboard",
            "dashboard.json",
            "--http-cidr",
            "10.0.0.0/8",
            "--traces",
            "0.5",
        ])
        .expect("remote invocation should parse");

        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };
        let generate = *generate;
        let GenerateTarget::Remote(remote) = generate.target else {
            panic!("expected remote target");
        };
        assert_eq!(remote.traces, 0.5);
    }

    #[test]
    fn rejects_traces_sampling_rate_above_one() {
        let error = parse_cli([
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
            "remote",
            "--regions",
            "us-east-1,us-west-2",
            "--instance-type",
            "c8g.large",
            "--storage-size",
            "25",
            "--monitoring-instance-type",
            "c8g.2xlarge",
            "--monitoring-storage-size",
            "100",
            "--dashboard",
            "dashboard.json",
            "--http-cidr",
            "10.0.0.0/8",
            "--traces",
            "1.5",
        ])
        .err()
        .expect("sampling rate above one should fail");

        assert!(error.to_string().contains("invalid value"));
    }

    #[test]
    fn parses_fractional_spammer_accounts_jitter() {
        let cli = parse_cli([
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
            "--spammer-accounts-jitter",
            "0.25",
            "local",
        ])
        .expect("local invocation should parse");

        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };
        let generate = *generate;
        assert_eq!(generate.spammer_accounts_jitter, 0.25);
    }

    #[test]
    fn parses_deterministic_spammer_seed_offset() {
        let cli = parse_cli([
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
            "--spammer-seed-offset",
            "2000",
            "local",
        ])
        .expect("local invocation should parse");

        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };
        let generate = *generate;
        assert_eq!(generate.spammer_seed_offset, Some(2000));
    }

    #[test]
    fn parses_spammer_presigned_batches() {
        let cli = parse_cli([
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
            "--spammer-presigned-batches",
            "32",
            "local",
        ])
        .expect("local invocation should parse");

        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };
        let generate = *generate;
        assert_eq!(generate.spammer_presigned_batches, 32);
    }

    #[test]
    fn parses_spammer_rayon_threads() {
        let cli = parse_cli([
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
            "--spammer-rayon-threads",
            "6",
            "local",
        ])
        .expect("local invocation should parse");

        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };
        let generate = *generate;
        assert_eq!(generate.spammer_rayon_threads, 6);
    }

    fn local_generate_args(options: &[&str]) -> Result<super::GenerateArgs, clap::Error> {
        let mut args = vec![
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
        ];
        args.extend_from_slice(options);
        args.push("local");
        let Command::Generate(generate) = parse_cli(args)?.command else {
            panic!("expected generate command");
        };
        Ok(*generate)
    }

    #[test]
    fn leader_options_default_to_rotation() {
        let generate = local_generate_args(&[]).expect("local invocation should parse");

        assert_eq!(generate.leader_term_length.get(), 1);
        assert_eq!(generate.leader_optimistic_views, 16);
        assert!(!generate.mempool_propose_priority);
        assert!(!generate.propose_skip_final_refill);
    }

    #[test]
    fn parses_stable_leader_options() {
        let generate = local_generate_args(&[
            "--leader-term-length",
            "1000000",
            "--leader-optimistic-views",
            "8",
            "--mempool-propose-priority",
            "--propose-skip-final-refill",
        ])
        .expect("local invocation should parse");

        assert_eq!(generate.leader_term_length.get(), 1_000_000);
        assert_eq!(generate.leader_optimistic_views, 8);
        assert!(generate.mempool_propose_priority);
        assert!(generate.propose_skip_final_refill);
    }

    #[test]
    fn rejects_zero_leader_term_length() {
        let error = local_generate_args(&["--leader-term-length", "0"])
            .err()
            .expect("zero term length should be rejected");

        assert_eq!(error.kind(), ErrorKind::ValueValidation);
    }

    /// Sets the stable-leader options that [`assert_stable_leader_config`] expects.
    pub(crate) fn set_stable_leader_args(args: &mut super::GenerateArgs) {
        args.leader_term_length = commonware_utils::NZU32!(1_000_000);
        args.leader_optimistic_views = 8;
        args.mempool_propose_priority = true;
        args.propose_skip_final_refill = true;
    }

    /// Asserts that a generated config carries [`set_stable_leader_args`] under
    /// the key names the validator reads.
    pub(crate) fn assert_stable_leader_config(config: &ValidatorConfig) {
        let yaml = serde_yaml::to_value(config).expect("config should serialize");

        assert_eq!(yaml["leader_term_length"].as_u64(), Some(1_000_000));
        assert_eq!(yaml["leader_optimistic_views"].as_u64(), Some(8));
        assert_eq!(yaml["mempool_propose_priority"].as_bool(), Some(true));
        assert_eq!(yaml["propose_skip_final_refill"].as_bool(), Some(true));
    }

    #[test]
    #[should_panic(expected = "--validators must be at least 4")]
    fn rejects_validator_count_below_coding_minimum() {
        let cli = parse_cli([
            "constantinople-deploy",
            "generate",
            "--validators",
            "3",
            "--output-dir",
            "out",
            "local",
        ])
        .expect("local invocation should parse");

        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };

        super::validate_generate_args(&generate);
    }

    fn proposal_args(validators: u32, budget: usize) -> super::GenerateArgs {
        let cli = Cli::try_parse_from([
            "constantinople-deploy",
            "generate",
            "--validators",
            &validators.to_string(),
            "--output-dir",
            "out",
            "--max-propose-bytes",
            &budget.to_string(),
            "local",
        ])
        .expect("local invocation should parse");

        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };
        *generate
    }

    #[test]
    fn accepts_maximum_proposal_budget_independent_of_validator_count() {
        for validators in [4, 7, u32::from(u16::MAX)] {
            let args = proposal_args(validators, super::MAXIMUM_BLOCK_SIZE);
            super::validate_generate_args(&args);
        }
    }

    #[test]
    fn rejects_oversized_proposal_budgets_independent_of_validator_count() {
        let maximum = super::MAXIMUM_BLOCK_SIZE;
        for validators in [4, 7] {
            for budget in [maximum + 1, usize::MAX] {
                let args = proposal_args(validators, budget);
                let error = std::panic::catch_unwind(|| super::validate_generate_args(&args))
                    .expect_err("oversized proposal budget should fail");
                let message = error.downcast_ref::<String>().expect("panic message");
                assert_eq!(
                    message,
                    &format!("--max-propose-bytes {budget} exceeds encoded block limit {maximum}"),
                );
            }
        }
    }

    #[test]
    fn validates_minimum_encoded_block_budget() {
        let minimum = (0..=super::MAXIMUM_BLOCK_SIZE)
            .find(|&budget| super::max_transaction_bytes(budget).is_some())
            .expect("empty block fits within the consensus limit");
        for budget in [0, 1, minimum - 1] {
            let args = proposal_args(4, budget);
            let error = std::panic::catch_unwind(|| super::validate_generate_args(&args))
                .expect_err("budget below empty block size should fail");
            let message = error.downcast_ref::<String>().expect("panic message");
            assert_eq!(
                message,
                &format!("--max-propose-bytes {budget} is too small for an encoded empty block"),
            );
        }
        super::validate_generate_args(&proposal_args(4, minimum));
    }

    #[test]
    #[should_panic(expected = "--validators must be at most 65535")]
    fn rejects_validator_count_above_coding_maximum() {
        let args = proposal_args(u32::from(u16::MAX) + 1, 0);
        super::validate_generate_args(&args);
    }

    #[test]
    #[should_panic(expected = "--indexer cannot be combined with --startup state-sync")]
    fn rejects_indexer_with_state_sync() {
        let cli = parse_cli([
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
            "--indexer",
            "--startup",
            "state-sync",
            "local",
        ])
        .expect("local invocation should parse");

        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };

        super::validate_generate_args(&generate);
    }

    #[test]
    #[should_panic(expected = "--spammer-submitters must be at least 1")]
    fn rejects_zero_spammer_submitters() {
        let cli = parse_cli([
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
            "--spammer-submitters",
            "0",
            "local",
        ])
        .expect("local invocation should parse");

        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };

        super::validate_generate_args(&generate);
    }

    #[test]
    fn rejects_spammer_accounts_jitter_above_one() {
        let error = parse_cli([
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
            "--spammer-accounts-jitter",
            "1.1",
            "local",
        ])
        .err()
        .expect("jitter above one should fail");

        assert!(error.to_string().contains("invalid value"));
    }

    #[test]
    fn writes_simplex_verification_material() {
        let material = generate_local_cluster_material(4, 1);
        let output_dir = unique_temp_dir("simplex-verification-material");
        fs::create_dir_all(&output_dir).expect("failed to create temp dir");

        write_simplex_verification_material(&output_dir, &material);

        let path = output_dir.join(SIMPLEX_VERIFICATION_MATERIAL_FILE);
        let written = fs::read_to_string(&path).expect("failed to read material");
        assert_eq!(written, material.simplex_verification_material_hex());

        fs::remove_file(path).expect("failed to remove material");
        fs::remove_dir(output_dir).expect("failed to remove temp dir");
    }

    #[test]
    fn extracts_simplex_verification_material_from_config() {
        let material = generate_local_cluster_material(4, 1);
        let output_dir = unique_temp_dir("extract-simplex-verification-material");
        fs::create_dir_all(&output_dir).expect("failed to create temp dir");
        let config_path = output_dir.join("validator.yaml");
        fs::write(
            &config_path,
            format!(
                "dkg_output: {}\nnum_validators: 4\n",
                hex(&material.dkg_output.encode())
            ),
        )
        .expect("failed to write config");

        let extracted = simplex_verification_material_from_config(&config_path);

        assert_eq!(extracted, material.simplex_verification_material_hex());

        fs::remove_file(config_path).expect("failed to remove config");
        fs::remove_dir(output_dir).expect("failed to remove temp dir");
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "constantinople-deploy-{name}-{}-{nanos}",
            std::process::id()
        ))
    }

    #[test]
    fn removed_read_service_options_are_rejected() {
        for flag in [
            "--metadata-indexer-url",
            "--qmdb-indexer-url",
            "--metadata-indexer-port",
            "--qmdb-indexer-port",
            "--sql-port",
            "--indexer-port",
        ] {
            let mut args = remote_cli_args();
            args.extend([flag, "8092"]);
            assert_eq!(
                parse_cli(args).err().unwrap().kind(),
                ErrorKind::UnknownArgument
            );
        }
    }

    #[test]
    fn local_explorer_options_replace_legacy_ports() {
        let base = [
            "constantinople-deploy",
            "generate",
            "--validators",
            "2",
            "--output-dir",
            "out",
            "local",
        ];
        for flag in [
            "--metadata-indexer-port",
            "--qmdb-indexer-port",
            "--sql-port",
            "--indexer-port",
        ] {
            let mut args = base.to_vec();
            args.extend([flag, "8092"]);
            assert_eq!(
                parse_cli(args).err().unwrap().kind(),
                ErrorKind::UnknownArgument
            );
        }
        let mut args = base.to_vec();
        args.extend([
            "--chain-indexer-port",
            "18090",
            "--explorer-indexer-port",
            "18092",
        ]);
        let cli = parse_cli(args).expect("custom service ports parse");
        let Command::Generate(generate) = cli.command else {
            panic!("generate command")
        };
        let GenerateTarget::Local(local) = generate.target else {
            panic!("local target")
        };
        assert_eq!(local.chain_indexer_port, 18090);
        assert_eq!(local.explorer_indexer_port, 18092);
    }
}
