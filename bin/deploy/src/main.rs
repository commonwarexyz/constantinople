//! Deployment generator for Constantinople.

mod local;
mod remote;

use clap::{Args, Parser, Subcommand};
use commonware_codec::{Encode, Read as CodecRead};
use commonware_cryptography::{
    Signer,
    bls12381::{
        dkg::feldman_desmedt as dkg,
        primitives::{group::Share, sharing::ModeVersion, variant::MinSig},
    },
    ed25519,
};
use commonware_formatting::{from_hex, hex};
use commonware_math::algebra::Random;
use commonware_utils::{N3f1, NZU32, TryCollect};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::Level;
use tracing_subscriber::fmt;

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
const METADATA_INDEXER_BINARY_FILE: &str = "metadata-indexer";
const METADATA_INDEXER_CONFIG_FILE: &str = "metadata-indexer.yaml";
const METADATA_INDEXER_HOST: &str = "metadata-indexer";
const QMDB_INDEXER_BINARY_FILE: &str = "qmdb-indexer";
const QMDB_INDEXER_CONFIG_FILE: &str = "qmdb-indexer.yaml";
const QMDB_INDEXER_HOST: &str = "qmdb-indexer";
const SIMPLEX_VERIFICATION_MATERIAL_FILE: &str = "simplex-verification-material.hex";
const DEFAULT_CHAIN_INDEXER_PORT: u16 = 8090;
const DEFAULT_METADATA_INDEXER_PORT: u16 = 8091;
const DEFAULT_QMDB_INDEXER_PORT: u16 = 8092;
const DEFAULT_BOOTSTRAPPERS: usize = 3;
const INDEXER_UPLOAD_BUFFER: usize = 64;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StartupModeConfig {
    #[default]
    MarshalSync,
    StateSync,
}

#[derive(Debug, Parser)]
#[command(name = "constantinople-deploy")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
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

#[derive(Debug, Args)]
pub(crate) struct GenerateArgs {
    #[arg(long)]
    validators: u32,
    /// Include the full indexer secondary and shared indexer services.
    #[arg(long, default_value_t = false)]
    indexer: bool,
    /// Include a transaction relayer secondary.
    #[arg(long, default_value_t = false)]
    relayer: bool,
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long, default_value = "info")]
    log_level: String,
    #[arg(long, default_value_t = 2)]
    worker_threads: usize,
    #[arg(long, default_value_t = 2)]
    rayon_threads: usize,
    #[arg(long, value_enum, default_value_t = StartupModeConfig::MarshalSync)]
    startup: StartupModeConfig,

    /// Include a spammer instance in the deployment.
    #[arg(long, default_value_t = false)]
    spammer: bool,
    /// Number of spam accounts per validator.
    #[arg(long, default_value_t = 10)]
    spammer_accounts: u32,
    /// Transfer value per spam transaction.
    #[arg(long, default_value_t = 1)]
    spammer_value: u64,
    /// Seed offset for spam account keys.
    #[arg(long, default_value_t = 1000)]
    spammer_seed_offset: u64,
    /// Fractional account-count jitter per spammer batch.
    ///
    /// `0.2` submits `spammer_accounts + rand(0..=floor(spammer_accounts * 0.2))`
    /// txs per batch.
    #[arg(long, default_value_t = 0.0, value_parser = parse_accounts_jitter)]
    spammer_accounts_jitter: f64,

    #[command(subcommand)]
    target: GenerateTarget,
}

#[derive(Debug, Subcommand)]
enum GenerateTarget {
    Local(LocalArgs),
    Remote(RemoteArgs),
}

#[derive(Debug, Args)]
pub(crate) struct LocalArgs {
    #[arg(long, default_value_t = 9000)]
    base_port: u16,
    #[arg(long, default_value_t = 8080)]
    base_http_port: u16,
    #[arg(long, default_value_t = 9090)]
    base_metrics_port: u16,
    /// Local `chain-indexer` Store port.
    #[arg(long = "chain-indexer-port", alias = "indexer-port", default_value_t = DEFAULT_CHAIN_INDEXER_PORT)]
    chain_indexer_port: u16,
    /// Local `metadata-indexer` read-service port.
    /// The explorer reads from this port via `VITE_SQL_URL`.
    #[arg(long = "metadata-indexer-port", alias = "sql-port", default_value_t = DEFAULT_METADATA_INDEXER_PORT)]
    metadata_indexer_port: u16,
    /// Local `qmdb-indexer` read-service port.
    #[arg(long = "qmdb-indexer-port", default_value_t = DEFAULT_QMDB_INDEXER_PORT)]
    qmdb_indexer_port: u16,
}

#[derive(Debug, Args)]
pub(crate) struct RemoteArgs {
    #[arg(long, value_delimiter = ',')]
    regions: Vec<String>,
    #[arg(long)]
    instance_type: String,
    #[arg(long)]
    storage_size: i32,
    /// Instance type for the shared chain-indexer instance.
    #[arg(long = "chain-indexer-instance-type", default_value = DEFAULT_CHAIN_INDEXER_INSTANCE_TYPE)]
    chain_indexer_instance_type: String,
    /// Storage size (GiB) for the shared chain-indexer instance.
    #[arg(long = "chain-indexer-storage-size", default_value_t = DEFAULT_CHAIN_INDEXER_STORAGE_SIZE)]
    chain_indexer_storage_size: i32,
    /// Provisioned IOPS for the shared chain-indexer io2 volume.
    #[arg(long = "chain-indexer-storage-iops", default_value_t = DEFAULT_CHAIN_INDEXER_STORAGE_IOPS)]
    chain_indexer_storage_iops: i32,
    #[arg(long)]
    monitoring_instance_type: String,
    #[arg(long)]
    monitoring_storage_size: i32,
    #[arg(long)]
    dashboard: PathBuf,
    #[arg(long, default_value_t = 9000)]
    listen_port: u16,
    #[arg(long, default_value_t = 8080)]
    http_port: u16,
    #[arg(long = "http-cidr", value_delimiter = ',')]
    http_cidrs: Vec<String>,
    /// Shared `chain-indexer` Store port.
    #[arg(long = "chain-indexer-port", default_value_t = DEFAULT_CHAIN_INDEXER_PORT)]
    chain_indexer_port: u16,
    /// Shared `metadata-indexer` query/stream port.
    #[arg(long = "metadata-indexer-port", default_value_t = DEFAULT_METADATA_INDEXER_PORT)]
    metadata_indexer_port: u16,
    /// Shared `qmdb-indexer` query facade port.
    #[arg(long = "qmdb-indexer-port", default_value_t = DEFAULT_QMDB_INDEXER_PORT)]
    qmdb_indexer_port: u16,
    #[arg(long, default_value_t = false)]
    profiling: bool,
    /// Instance type for the spammer (defaults to --instance-type).
    #[arg(long)]
    spammer_instance_type: Option<String>,
    /// Storage size (GiB) for the spammer instance.
    #[arg(long, default_value_t = 25)]
    spammer_storage_size: i32,
}

/// Spammer configuration, written as YAML by deploy and read by the spammer binary.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct SpammerConfig {
    pub accounts: u32,
    pub value: u64,
    pub seed_offset: u64,
    pub http_port: u16,
    /// Relayer URL used for transaction submission.
    pub relayer_url: String,
    /// Independent nonce-ordered streams to run when submitting through a relayer.
    #[serde(default, skip_serializing_if = "usize_is_zero")]
    pub relayer_submitters: usize,
    /// Hex-encoded ed25519 public keys of primary (voting) validators.
    ///
    /// In `--hosts` mode the spammer cannot distinguish primaries from
    /// secondaries by host name alone — both use hex pubkeys. This list lets
    /// the spammer target only primaries.
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
    pub leaders: Vec<RelayerLeaderConfig>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct RelayerLeaderConfig {
    pub public_key: String,
    pub url: String,
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct NamedBootstrapperEntry {
    public_key: String,
    name: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ValidatorConfig {
    private_key: String,
    dkg_output: String,
    /// Hex-encoded DKG share for this validator. Empty string `""` indicates
    /// a secondary (non-voting) validator that holds no share.
    dkg_share: String,
    startup: StartupModeConfig,
    listen_port: u16,
    genesis_leader: String,
    partition_prefix: String,
    num_validators: u32,
    /// Hex-encoded ed25519 public keys of the primary (voting) validators,
    /// in DKG order. Must be identical across every validator config in the
    /// deployment so all peers agree on the discovery bitvec ordering.
    primary_validators: Vec<String>,
    /// Hex-encoded ed25519 public keys of the secondary (non-voting) validators.
    /// Must be identical across every validator config in the deployment.
    secondary_validators: Vec<String>,
    log_level: String,
    worker_threads: usize,
    rayon_threads: usize,
    http_port: u16,
    metrics_port: u16,
    max_propose_bytes: usize,
    max_pool_bytes: usize,
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
/// shared `chain-indexer` store backs raw KV rows, SQL metadata rows, QMDB
/// operation logs, and simplex artifacts.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct IndexerConfig {
    pub chain_indexer_url: String,
    pub upload_buffer: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ChainIndexerConfig {
    pub port: u16,
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct MetadataIndexerConfig {
    pub port: u16,
    pub chain_indexer_url: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct QmdbIndexerConfig {
    pub port: u16,
    pub chain_indexer_url: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct PeerEntry {
    name: String,
    p2p: String,
    http: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct PeersConfig {
    pub validators: Vec<PeerEntry>,
    #[serde(default)]
    pub secondaries: Vec<PeerEntry>,
}

#[derive(Debug, Deserialize)]
struct SimplexMaterialConfig {
    dkg_output: String,
    num_validators: u32,
}

pub(crate) struct ClusterMaterial {
    pub signers: Vec<ed25519::PrivateKey>,
    pub public_keys: Vec<ed25519::PublicKey>,
    pub secondary_signers: Vec<ed25519::PrivateKey>,
    pub secondary_public_keys: Vec<ed25519::PublicKey>,
    pub dkg_output: dkg::Output<MinSig, ed25519::PublicKey>,
    pub shares: BTreeMap<ed25519::PublicKey, Share>,
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

fn main() {
    init_tracing();
    let cli = Cli::parse();

    match &cli.command {
        Command::Generate(args) => match &args.target {
            GenerateTarget::Local(local_args) => local::generate(args, local_args),
            GenerateTarget::Remote(remote_args) => remote::generate(args, remote_args),
        },
        Command::SimplexVerificationMaterial(args) => {
            println!(
                "{}",
                simplex_verification_material_from_config(&args.config)
            );
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

pub(crate) const fn indexer_enabled(args: &GenerateArgs) -> bool {
    args.indexer
}

pub(crate) fn validate_generate_args(args: &GenerateArgs) {
    assert!(
        !args.spammer || args.relayer,
        "--spammer requires --relayer"
    );
}

pub(crate) fn generate_local_cluster_material(
    validators: u32,
    secondaries: u32,
) -> ClusterMaterial {
    let signers = (0..validators)
        .map(|index| ed25519::PrivateKey::from_seed(index.into()))
        .collect::<Vec<_>>();
    let secondary_signers = (0..secondaries)
        .map(|index| ed25519::PrivateKey::from_seed(SECONDARY_SEED_OFFSET + u64::from(index)))
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
    let mut signers = (0..validators)
        .map(|_| ed25519::PrivateKey::random(&mut OsRng))
        .collect::<Vec<_>>();
    signers.sort_by_key(Signer::public_key);
    let mut secondary_signers = (0..secondaries)
        .map(|_| ed25519::PrivateKey::random(&mut OsRng))
        .collect::<Vec<_>>();
    secondary_signers.sort_by_key(Signer::public_key);
    build_cluster_material(signers, secondary_signers, &mut OsRng)
}

fn build_cluster_material(
    signers: Vec<ed25519::PrivateKey>,
    secondary_signers: Vec<ed25519::PrivateKey>,
    rng: &mut impl rand_core::CryptoRngCore,
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
        dkg::deal::<MinSig, _, N3f1>(rng, Default::default(), participants)
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
    let dkg_output = dkg::Output::<MinSig, ed25519::PublicKey>::read_cfg(
        &mut &bytes[..],
        &(NZU32!(config.num_validators), ModeVersion::v0()),
    )
    .expect("failed to decode dkg_output");
    hex(&dkg_output.public().public().encode())
}

pub(crate) fn default_bootstrappers(
    public_keys: &[ed25519::PublicKey],
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
    4 * 1024 * 1024
}

pub(crate) const fn default_max_pool_bytes() -> usize {
    64 * 1024 * 1024
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
        Cli, Command, GenerateTarget, SIMPLEX_VERIFICATION_MATERIAL_FILE,
        generate_local_cluster_material, simplex_verification_material_from_config,
        write_simplex_verification_material,
    };
    use clap::Parser;
    use commonware_codec::Encode;
    use commonware_formatting::hex;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn remote_parses_http_cidrs() {
        let cli = Cli::try_parse_from([
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
    fn parses_fractional_spammer_accounts_jitter() {
        let cli = Cli::try_parse_from([
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
    fn rejects_spammer_accounts_jitter_above_one() {
        let error = Cli::try_parse_from([
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
        .expect_err("jitter above one should fail");

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
}
