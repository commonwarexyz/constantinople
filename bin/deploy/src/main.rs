//! Deployment generator for Constantinople.

mod local;
mod remote;

use clap::{Args, Parser, Subcommand};
use commonware_codec::Encode;
use commonware_cryptography::{
    Signer,
    bls12381::{
        dkg,
        primitives::{group::Share, variant::MinSig},
    },
    ed25519,
};
use commonware_math::algebra::Random;
use commonware_utils::{N3f1, TryCollect, hex};
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
const DASHBOARD_FILE: &str = "dashboard.json";
const DEPLOYER_CONFIG_FILE: &str = "config.yaml";
const PEERS_CONFIG_FILE: &str = "peers.yaml";
const VALIDATOR_BINARY_FILE: &str = "validator";
const SPAMMER_BINARY_FILE: &str = "spammer";
const SPAMMER_CONFIG_FILE: &str = "spammer.yaml";
const DEFAULT_BOOTSTRAPPERS: usize = 3;

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
    Generate(GenerateArgs),
}

#[derive(Debug, Args)]
pub(crate) struct GenerateArgs {
    #[arg(long)]
    validators: u32,
    /// Number of secondary (non-voting) validators to include in the deployment.
    ///
    /// Secondaries receive an ed25519 identity and run the validator binary but
    /// do not hold a DKG share; they bootstrap through the primary validators.
    #[arg(long, default_value_t = 0)]
    secondaries: u32,
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
}

#[derive(Debug, Args)]
pub(crate) struct RemoteArgs {
    #[arg(long, value_delimiter = ',')]
    regions: Vec<String>,
    #[arg(long)]
    instance_type: String,
    #[arg(long)]
    storage_size: i32,
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
    /// Hex-encoded ed25519 public keys of primary (voting) validators.
    ///
    /// In `--hosts` mode the spammer cannot distinguish primaries from
    /// secondaries by host name alone — both use hex pubkeys. This list lets
    /// the spammer target only primaries.
    #[serde(default)]
    pub primary_validators: Vec<String>,
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
}

fn main() {
    init_tracing();
    let cli = Cli::parse();

    match &cli.command {
        Command::Generate(args) => match &args.target {
            GenerateTarget::Local(local_args) => local::generate(args, local_args),
            GenerateTarget::Remote(remote_args) => remote::generate(args, remote_args),
        },
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
    use super::{Cli, Command, GenerateTarget};
    use clap::Parser;

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

        let Command::Generate(generate) = cli.command;
        let GenerateTarget::Remote(remote) = generate.target else {
            panic!("expected remote target");
        };

        assert_eq!(
            remote.http_cidrs,
            vec!["10.0.0.0/8".to_string(), "198.51.100.4/32".to_string()]
        );
    }
}
