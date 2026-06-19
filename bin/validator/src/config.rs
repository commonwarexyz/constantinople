//! YAML-serializable validator configuration.

use ahash::AHashMap;
use commonware_codec::{Encode, Read as CodecRead, ReadExt};
use commonware_cryptography::{
    Signer,
    bls12381::{
        dkg::feldman_desmedt as dkg,
        primitives::{group::Share, sharing::ModeVersion, variant::MinSig},
    },
    ed25519,
};
use commonware_deployer::aws::Hosts;
use commonware_formatting::{from_hex, hex};
use commonware_p2p::{Ingress, authenticated::discovery::Bootstrapper};
use commonware_utils::NZU32;
use serde::Deserialize;
use std::{net::SocketAddr, path::Path};

pub(crate) const fn default_rayon_threads() -> usize {
    2
}

pub(crate) const fn default_metrics_port() -> u16 {
    9090
}

pub(crate) const fn default_upload_buffer() -> usize {
    64
}

pub(crate) const fn default_max_propose_bytes() -> usize {
    8 * 1024 * 1024
}

pub(crate) const fn default_max_pool_bytes() -> usize {
    64 * 1024 * 1024
}

pub(crate) const fn default_relayer_retry_views() -> u64 {
    8
}

pub(crate) const fn default_public_key_cache_size() -> usize {
    100_000
}

/// Indexer wiring for a secondary validator.
///
/// Primary (voting) validators ignore this section; secondaries with
/// indexer wiring upload finalized blocks, transactions, consensus
/// certificates, and QMDB operation logs into the shared `chain-indexer`
/// store.
///
/// The latest-finalized-height cursor that earlier versions of the
/// indexer wrote to a separate `META` KV family now lives in
/// `block_meta`; consumers query `MAX(height) FROM block_meta`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IndexerConfig {
    /// URL of the shared chain-indexer store.
    pub chain_indexer_url: String,
    /// Number of blocks buffered before upload.
    #[serde(default = "default_upload_buffer")]
    pub upload_buffer: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupModeConfig {
    #[default]
    MarshalSync,
    StateSync,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ValidatorConfig {
    /// Hex-encoded ed25519 private key.
    pub private_key: String,
    /// Hex-encoded DKG output (threshold public material).
    pub dkg_output: String,
    /// Hex-encoded DKG share for this validator. Empty string `""` indicates
    /// a secondary (non-voting) validator that holds no share.
    pub dkg_share: String,
    /// Startup sync mode.
    #[serde(default)]
    pub startup: StartupModeConfig,
    /// p2p listen port.
    pub listen_port: u16,
    /// Hex-encoded ed25519 public key of the genesis leader.
    pub genesis_leader: String,
    /// Storage partition prefix for this validator.
    pub partition_prefix: String,
    /// Number of primary validators (DKG participant count).
    pub num_validators: u32,
    /// Hex-encoded ed25519 public keys of the primary (voting) validators,
    /// in DKG order. Must be identical across every validator config in the
    /// deployment so all peers agree on the discovery bitvec ordering.
    pub primary_validators: Vec<String>,
    /// Hex-encoded ed25519 public keys of the secondary (non-voting) validators.
    /// Must be identical across every validator config in the deployment.
    pub secondary_validators: Vec<String>,
    /// Logging verbosity.
    pub log_level: String,
    /// Tokio worker threads.
    pub worker_threads: usize,
    /// Rayon threads for parallel verification.
    #[serde(default = "default_rayon_threads")]
    pub rayon_threads: usize,
    /// HTTP service port.
    pub http_port: u16,
    /// Prometheus metrics port.
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
    /// Maximum bytes proposed per block.
    #[serde(default = "default_max_propose_bytes")]
    pub max_propose_bytes: usize,
    /// Maximum mempool size in bytes.
    #[serde(default = "default_max_pool_bytes")]
    pub max_pool_bytes: usize,
    /// Capacity of the decompressed public key cache.
    #[serde(default = "default_public_key_cache_size")]
    pub public_key_cache_size: usize,
    /// Trace sampling rate (0.0..=1.0); 0.0 disables uploads. Only honored in
    /// deployer mode, where the hosts file names a monitoring instance.
    #[serde(default)]
    pub traces: f64,
    /// Bootstrapper peers used for initial p2p discovery.
    pub bootstrappers: Vec<NamedBootstrapperEntry>,
    /// Optional indexer wiring. Honored only for secondary (non-voting)
    /// validators when this section is present.
    #[serde(default)]
    pub indexer: Option<IndexerConfig>,
    /// Optional relayer wiring. Honored only for secondary validators.
    #[serde(default)]
    pub relayer: Option<RelayerConfig>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelayerConfig {
    /// Views to retry a submission before giving up.
    #[serde(default = "default_relayer_retry_views")]
    pub max_retry_views: u64,
    /// Per-leader relayer endpoints.
    pub leaders: Vec<RelayerLeaderConfig>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelayerLeaderConfig {
    /// Hex-encoded ed25519 public key of the target leader.
    pub public_key: String,
    /// Relayer URL for submitting to this leader.
    pub url: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct NamedBootstrapperEntry {
    /// Hex-encoded ed25519 public key of the bootstrapper.
    pub public_key: String,
    /// Host name used to resolve the bootstrapper's address.
    pub name: String,
}

#[derive(Debug, Deserialize)]
struct PeerEntry {
    /// Host name (hex-encoded public key).
    name: String,
    /// p2p socket address.
    p2p: String,
    /// HTTP socket address.
    http: String,
}

#[derive(Debug, Deserialize)]
struct PeersFile {
    /// Primary validator peers.
    validators: Vec<PeerEntry>,
    /// Secondary (non-voting) validator peers.
    #[serde(default)]
    secondaries: Vec<PeerEntry>,
}

/// Decoded key material and network info ready for use by the engine.
pub struct DecodedConfig {
    /// This validator's ed25519 private key.
    pub signer: ed25519::PrivateKey,
    /// This validator's ed25519 public key.
    pub public_key: ed25519::PublicKey,
    /// Decoded DKG output (threshold public material).
    pub dkg_output: dkg::Output<MinSig, ed25519::PublicKey>,
    /// DKG share for this validator. `None` for secondary (non-voting) validators.
    pub share: Option<Share>,
    /// Genesis leader public key.
    pub genesis_leader: ed25519::PublicKey,
    /// Local p2p bind address.
    pub listen_bind: SocketAddr,
    /// Advertised p2p address other peers dial.
    pub listen_advertise: SocketAddr,
    /// Primary (voting) validators in DKG order.
    pub primary_participants: Vec<ed25519::PublicKey>,
    /// Secondary (non-voting) validators.
    pub secondary_participants: Vec<ed25519::PublicKey>,
    /// Bootstrapper peers with resolved addresses.
    pub bootstrappers: Vec<Bootstrapper<ed25519::PublicKey>>,
    /// Storage partition prefix for this validator.
    pub partition_prefix: String,
}

pub struct LoadedConfig {
    /// Decoded key material and network info.
    pub decoded: DecodedConfig,
    /// Startup sync mode.
    pub startup: StartupModeConfig,
    /// Logging verbosity.
    pub log_level: String,
    /// Tokio worker threads.
    pub worker_threads: usize,
    /// Rayon threads for parallel verification.
    pub rayon_threads: usize,
    /// HTTP service bind address.
    pub http_listen: SocketAddr,
    /// Prometheus metrics bind address.
    pub metrics_listen: SocketAddr,
    /// Maximum bytes proposed per block.
    pub max_propose_bytes: usize,
    /// Maximum mempool size in bytes.
    pub max_pool_bytes: usize,
    /// Capacity of the decompressed public key cache.
    pub public_key_cache_size: usize,
    /// OTLP traces endpoint and sampling rate, when trace uploads are enabled.
    pub otel: Option<(String, f64)>,
    /// Whether logs are emitted as JSON.
    pub json_logs: bool,
    /// Whether this node is managed by the deployer.
    pub deployer_managed: bool,
    /// Optional indexer wiring (secondaries only).
    pub indexer: Option<IndexerConfig>,
    /// Optional relayer wiring (secondaries only).
    pub relayer: Option<RelayerConfig>,
}

fn decode_hex(field_name: &str, hex_str: &str) -> Vec<u8> {
    from_hex(hex_str).unwrap_or_else(|| panic!("bad {field_name} hex"))
}

fn decode_private_key(hex_str: &str) -> ed25519::PrivateKey {
    let bytes = decode_hex("private_key", hex_str);
    ed25519::PrivateKey::read(&mut &bytes[..]).expect("failed to decode private key")
}

fn decode_dkg_output(
    hex_str: &str,
    num_validators: u32,
) -> dkg::Output<MinSig, ed25519::PublicKey> {
    let bytes = decode_hex("dkg_output", hex_str);
    dkg::Output::read_cfg(
        &mut &bytes[..],
        &(NZU32!(num_validators), ModeVersion::v0()),
    )
    .expect("failed to decode DKG output")
}

/// Decode an optional DKG share. Returns `None` for the empty string, which is
/// how secondary validators are marked in the YAML schema.
fn decode_share_opt(hex_str: &str) -> Option<Share> {
    if hex_str.is_empty() {
        return None;
    }
    let bytes = decode_hex("dkg_share", hex_str);
    Some(Share::read(&mut &bytes[..]).expect("failed to decode DKG share"))
}

fn decode_public_key(field_name: &str, hex_str: &str) -> ed25519::PublicKey {
    let bytes = decode_hex(field_name, hex_str);
    ed25519::PublicKey::read(&mut &bytes[..]).expect("failed to decode public key")
}

fn load_validator_config(path: &Path) -> ValidatorConfig {
    let raw = std::fs::read_to_string(path).expect("failed to read config file");
    serde_yaml::from_str(&raw).expect("failed to parse config")
}

fn parse_socket(name: &str, socket: &str) -> SocketAddr {
    socket
        .parse()
        .unwrap_or_else(|_| panic!("failed to parse {name} socket"))
}

fn resolve_named_http_url(url: &str, hosts_by_name: &AHashMap<&str, std::net::IpAddr>) -> String {
    let Some(rest) = url.strip_prefix("http://") else {
        return url.to_string();
    };
    let (authority, suffix) = match rest.split_once('/') {
        Some((authority, suffix)) => (authority, format!("/{suffix}")),
        None => (rest, String::new()),
    };
    let Some((host, port)) = authority.rsplit_once(':') else {
        return url.to_string();
    };
    let Some(ip) = hosts_by_name.get(host) else {
        return url.to_string();
    };

    format!("http://{ip}:{port}{suffix}")
}

fn decode_with_network(
    config: ValidatorConfig,
    public_listen: SocketAddr,
    primary_participants: Vec<ed25519::PublicKey>,
    secondary_participants: Vec<ed25519::PublicKey>,
    bootstrappers: Vec<Bootstrapper<ed25519::PublicKey>>,
    otel: Option<(String, f64)>,
    json_logs: bool,
) -> LoadedConfig {
    let signer = decode_private_key(&config.private_key);
    let public_key = signer.public_key();
    let dkg_output = decode_dkg_output(&config.dkg_output, config.num_validators);
    let share = decode_share_opt(&config.dkg_share);
    if share.is_some() && config.relayer.is_some() {
        panic!("relayer config is only valid on secondary validators");
    }
    if config.indexer.is_some() && config.relayer.is_some() {
        panic!("relayer and indexer configs cannot be enabled on the same secondary");
    }
    let genesis_leader = decode_public_key("genesis_leader", &config.genesis_leader);
    let listen_bind: SocketAddr = format!("0.0.0.0:{}", config.listen_port)
        .parse()
        .expect("bad listen port");
    let http_listen: SocketAddr = format!("0.0.0.0:{}", config.http_port)
        .parse()
        .expect("bad HTTP listen port");
    let metrics_listen: SocketAddr = format!("0.0.0.0:{}", config.metrics_port)
        .parse()
        .expect("bad metrics listen port");

    LoadedConfig {
        decoded: DecodedConfig {
            signer,
            public_key,
            dkg_output,
            share,
            genesis_leader,
            listen_bind,
            listen_advertise: public_listen,
            primary_participants,
            secondary_participants,
            bootstrappers,
            partition_prefix: config.partition_prefix,
        },
        startup: config.startup,
        log_level: config.log_level,
        worker_threads: config.worker_threads,
        rayon_threads: config.rayon_threads,
        http_listen,
        metrics_listen,
        max_propose_bytes: config.max_propose_bytes,
        max_pool_bytes: config.max_pool_bytes,
        public_key_cache_size: config.public_key_cache_size,
        otel,
        json_logs,
        deployer_managed: json_logs,
        indexer: config.indexer,
        relayer: config.relayer,
    }
}

/// Decode the primary/secondary hex lists from the YAML. Panics if `self_key`
/// is absent from both lists — every node must be explicitly declared.
fn decode_participants(
    primary_hex: &[String],
    secondary_hex: &[String],
    self_key: &ed25519::PublicKey,
) -> (Vec<ed25519::PublicKey>, Vec<ed25519::PublicKey>) {
    let primary = primary_hex
        .iter()
        .map(|hex_str| decode_public_key("primary_validators", hex_str))
        .collect::<Vec<_>>();
    let secondary = secondary_hex
        .iter()
        .map(|hex_str| decode_public_key("secondary_validators", hex_str))
        .collect::<Vec<_>>();
    if !primary.contains(self_key) && !secondary.contains(self_key) {
        let self_hex = hex(&self_key.encode());
        panic!(
            "self public key '{self_hex}' not listed in primary_validators or secondary_validators"
        );
    }
    (primary, secondary)
}

pub fn load_local_config(peers_path: &Path, config_path: &Path) -> LoadedConfig {
    let config = load_validator_config(config_path);
    let signer = decode_private_key(&config.private_key);
    let self_public_key = signer.public_key();
    let self_name = hex(&self_public_key.encode());
    let raw_peers = std::fs::read_to_string(peers_path).expect("failed to read peers file");
    let peers: PeersFile = serde_yaml::from_str(&raw_peers).expect("failed to parse peers file");

    let (primary_participants, secondary_participants) = decode_participants(
        &config.primary_validators,
        &config.secondary_validators,
        &self_public_key,
    );

    // Self lookup must succeed against either the primary or secondary sections.
    let peers_by_name = peers
        .validators
        .into_iter()
        .chain(peers.secondaries)
        .map(|peer| {
            let name = peer.name.clone();
            (name, peer)
        })
        .collect::<AHashMap<_, _>>();

    let self_peer = peers_by_name
        .get(&self_name)
        .unwrap_or_else(|| panic!("missing self peer '{self_name}'"));
    let public_listen = parse_socket("self p2p", &self_peer.p2p);
    let _self_http = parse_socket("self http", &self_peer.http);

    let bootstrappers = config
        .bootstrappers
        .iter()
        .map(|bootstrapper| {
            let public_key = decode_public_key("bootstrapper public_key", &bootstrapper.public_key);
            let peer = peers_by_name
                .get(&bootstrapper.name)
                .unwrap_or_else(|| panic!("missing bootstrapper peer '{}'", bootstrapper.name));
            let address = parse_socket("bootstrapper p2p", &peer.p2p);
            (public_key, Ingress::Socket(address))
        })
        .collect();

    decode_with_network(
        config,
        public_listen,
        primary_participants,
        secondary_participants,
        bootstrappers,
        None,
        false,
    )
}

pub fn load_deployer_config(hosts_path: &Path, config_path: &Path) -> LoadedConfig {
    let mut config = load_validator_config(config_path);
    let signer = decode_private_key(&config.private_key);
    let self_public_key = signer.public_key();
    let self_name = hex(&self_public_key.encode());
    let raw_hosts = std::fs::read_to_string(hosts_path).expect("failed to read hosts file");
    let hosts: Hosts = serde_yaml::from_str(&raw_hosts).expect("failed to parse hosts file");

    let (primary_participants, secondary_participants) = decode_participants(
        &config.primary_validators,
        &config.secondary_validators,
        &self_public_key,
    );

    let hosts_by_name = hosts
        .hosts
        .iter()
        .map(|host| (host.name.as_str(), host.ip))
        .collect::<AHashMap<_, _>>();

    if let Some(indexer) = config.indexer.as_mut() {
        indexer.chain_indexer_url =
            resolve_named_http_url(&indexer.chain_indexer_url, &hosts_by_name);
    }
    if let Some(relayer) = config.relayer.as_mut() {
        for leader in &mut relayer.leaders {
            leader.url = resolve_named_http_url(&leader.url, &hosts_by_name);
        }
    }

    let self_ip = hosts_by_name
        .get(self_name.as_str())
        .unwrap_or_else(|| panic!("missing self host '{self_name}'"));
    let public_listen = SocketAddr::new(*self_ip, config.listen_port);

    let bootstrappers = config
        .bootstrappers
        .iter()
        .map(|bootstrapper| {
            let public_key = decode_public_key("bootstrapper public_key", &bootstrapper.public_key);
            let ip = hosts_by_name
                .get(bootstrapper.name.as_str())
                .unwrap_or_else(|| panic!("missing bootstrapper host '{}'", bootstrapper.name));
            let address = SocketAddr::new(*ip, config.listen_port);
            (public_key, Ingress::Socket(address))
        })
        .collect();

    let otel = (config.traces > 0.0).then(|| {
        (
            format!("http://{}:4318/v1/traces", hosts.monitoring.private),
            config.traces,
        )
    });

    decode_with_network(
        config,
        public_listen,
        primary_participants,
        secondary_participants,
        bootstrappers,
        otel,
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        IndexerConfig, NamedBootstrapperEntry, StartupModeConfig, ValidatorConfig,
        default_max_pool_bytes, default_max_propose_bytes, default_public_key_cache_size,
        default_upload_buffer, load_deployer_config, load_local_config,
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{
        Signer,
        bls12381::{
            dkg::feldman_desmedt as dkg,
            primitives::{group::Share, variant::MinSig},
        },
        ed25519,
    };
    use commonware_formatting::hex;
    use commonware_utils::{N3f1, TryCollect};
    use std::{
        collections::BTreeMap,
        fs,
        net::SocketAddr,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static TEMP_PATH_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_path(prefix: &str, suffix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let counter = TEMP_PATH_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("{prefix}-{unique}-{counter}{suffix}"))
    }

    /// Test fixture: a validator cluster with `primary_count` primaries and
    /// `secondary_count` secondaries. Primary seeds 0..primary_count, secondary
    /// seeds 1_000_000..1_000_000+secondary_count (matches deploy-side offsets).
    struct Cluster {
        primary_signers: Vec<ed25519::PrivateKey>,
        primary_keys: Vec<ed25519::PublicKey>,
        secondary_signers: Vec<ed25519::PrivateKey>,
        secondary_keys: Vec<ed25519::PublicKey>,
        dkg_output_hex: String,
        shares: BTreeMap<ed25519::PublicKey, Share>,
    }

    impl Cluster {
        fn new(primary_count: u64, secondary_count: u64) -> Self {
            let primary_signers = (0..primary_count)
                .map(ed25519::PrivateKey::from_seed)
                .collect::<Vec<_>>();
            let primary_keys = primary_signers
                .iter()
                .map(Signer::public_key)
                .collect::<Vec<_>>();
            let secondary_signers = (0..secondary_count)
                .map(|i| ed25519::PrivateKey::from_seed(1_000_000 + i))
                .collect::<Vec<_>>();
            let secondary_keys = secondary_signers
                .iter()
                .map(Signer::public_key)
                .collect::<Vec<_>>();

            let participants = primary_keys.clone().into_iter().try_collect().unwrap();
            let mut rng = commonware_utils::test_rng();
            let (dkg_output, raw_shares) =
                dkg::deal::<MinSig, _, N3f1>(&mut rng, Default::default(), participants)
                    .expect("DKG deal failed");
            let shares = raw_shares.into_iter().collect();

            Self {
                primary_signers,
                primary_keys,
                secondary_signers,
                secondary_keys,
                dkg_output_hex: hex(&dkg_output.encode()),
                shares,
            }
        }

        fn primary_hex_list(&self) -> Vec<String> {
            self.primary_keys
                .iter()
                .map(|pk| hex(&pk.encode()))
                .collect()
        }

        fn secondary_hex_list(&self) -> Vec<String> {
            self.secondary_keys
                .iter()
                .map(|pk| hex(&pk.encode()))
                .collect()
        }

        /// Build a [`ValidatorConfig`] for primary slot `index`, with the given bootstrapper list.
        fn primary_config(
            &self,
            index: usize,
            startup: StartupModeConfig,
            bootstrappers: Vec<NamedBootstrapperEntry>,
        ) -> ValidatorConfig {
            let signer = &self.primary_signers[index];
            let share = self.shares.get(&self.primary_keys[index]).expect("share");
            ValidatorConfig {
                private_key: hex(&signer.encode()),
                dkg_output: self.dkg_output_hex.clone(),
                dkg_share: hex(&share.encode()),
                startup,
                listen_port: 9000,
                genesis_leader: hex(&self.primary_keys[0].encode()),
                partition_prefix: format!("validator-{index}"),
                num_validators: self.primary_keys.len() as u32,
                primary_validators: self.primary_hex_list(),
                secondary_validators: self.secondary_hex_list(),
                log_level: "info".to_string(),
                worker_threads: 2,
                rayon_threads: 2,
                http_port: 8080,
                metrics_port: 9090,
                max_propose_bytes: default_max_propose_bytes(),
                max_pool_bytes: default_max_pool_bytes(),
                public_key_cache_size: default_public_key_cache_size(),
                traces: 0.0,
                bootstrappers,
                indexer: None,
                relayer: None,
            }
        }

        /// Build a [`ValidatorConfig`] for secondary slot `index` (no share).
        fn secondary_config(
            &self,
            index: usize,
            startup: StartupModeConfig,
            bootstrappers: Vec<NamedBootstrapperEntry>,
        ) -> ValidatorConfig {
            let signer = &self.secondary_signers[index];
            ValidatorConfig {
                private_key: hex(&signer.encode()),
                dkg_output: self.dkg_output_hex.clone(),
                dkg_share: String::new(),
                startup,
                listen_port: 9000,
                genesis_leader: hex(&self.primary_keys[0].encode()),
                partition_prefix: format!("secondary-{index}"),
                num_validators: self.primary_keys.len() as u32,
                primary_validators: self.primary_hex_list(),
                secondary_validators: self.secondary_hex_list(),
                log_level: "info".to_string(),
                worker_threads: 2,
                rayon_threads: 2,
                http_port: 8080,
                metrics_port: 9090,
                max_propose_bytes: default_max_propose_bytes(),
                max_pool_bytes: default_max_pool_bytes(),
                public_key_cache_size: default_public_key_cache_size(),
                traces: 0.0,
                bootstrappers,
                indexer: None,
                relayer: None,
            }
        }
    }

    fn bootstrapper_entry(public_key: &ed25519::PublicKey) -> NamedBootstrapperEntry {
        let name = hex(&public_key.encode());
        NamedBootstrapperEntry {
            public_key: name.clone(),
            name,
        }
    }

    #[test]
    fn local_config_resolves_bootstrapper_peers() {
        let cluster = Cluster::new(2, 0);
        let self_key = &cluster.primary_keys[0];
        let peer_key = &cluster.primary_keys[1];
        let config_path = temp_path("validator-config", ".yaml");
        let peers_path = temp_path("validator-peers", ".yaml");

        let mut config = cluster.primary_config(
            0,
            StartupModeConfig::MarshalSync,
            vec![bootstrapper_entry(peer_key)],
        );
        config.max_propose_bytes = 1_234_567;
        config.max_pool_bytes = 9_876_543;
        fs::write(
            &config_path,
            serde_yaml::to_string(&config).expect("config should serialize"),
        )
        .expect("config should write");
        fs::write(
            &peers_path,
            format!(
                r#"validators:
  - name: "{self_name}"
    p2p: "127.0.0.1:9000"
    http: "127.0.0.1:8080"
  - name: "{peer_name}"
    p2p: "127.0.0.1:9001"
    http: "127.0.0.1:8081"
"#,
                self_name = hex(&self_key.encode()),
                peer_name = hex(&peer_key.encode()),
            ),
        )
        .expect("peers should write");

        let loaded = load_local_config(&peers_path, &config_path);

        assert!(!loaded.json_logs);
        assert!(!loaded.deployer_managed);
        assert_eq!(loaded.startup, StartupModeConfig::MarshalSync);
        assert_eq!(loaded.http_listen, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(loaded.metrics_listen, "0.0.0.0:9090".parse().unwrap());
        assert_eq!(loaded.max_propose_bytes, 1_234_567);
        assert_eq!(loaded.max_pool_bytes, 9_876_543);
        assert_eq!(loaded.decoded.listen_bind, "0.0.0.0:9000".parse().unwrap());
        assert_eq!(
            loaded.decoded.listen_advertise,
            "127.0.0.1:9000".parse::<SocketAddr>().unwrap()
        );
        assert!(loaded.decoded.share.is_some());
        assert_eq!(loaded.decoded.primary_participants.len(), 2);
        assert!(loaded.decoded.primary_participants.contains(self_key));
        assert!(loaded.decoded.primary_participants.contains(peer_key));
        assert!(loaded.decoded.secondary_participants.is_empty());
        assert_eq!(
            loaded.decoded.bootstrappers[0].1,
            commonware_p2p::Ingress::Socket("127.0.0.1:9001".parse().unwrap())
        );

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(peers_path);
    }

    #[test]
    fn deployer_config_resolves_bootstrapper_hosts() {
        let cluster = Cluster::new(2, 0);
        let self_key = &cluster.primary_keys[0];
        let peer_key = &cluster.primary_keys[1];
        let self_name = hex(&self_key.encode());
        let peer_name = hex(&peer_key.encode());
        let config_path = temp_path("validator-config", ".yaml");
        let hosts_path = temp_path("validator-hosts", ".yaml");

        let mut config = cluster.primary_config(
            0,
            StartupModeConfig::MarshalSync,
            vec![bootstrapper_entry(peer_key)],
        );
        config.max_propose_bytes = 1_234_567;
        config.max_pool_bytes = 9_876_543;
        fs::write(
            &config_path,
            serde_yaml::to_string(&config).expect("config should serialize"),
        )
        .expect("config should write");
        fs::write(
            &hosts_path,
            format!(
                r#"monitoring:
  public: 10.0.0.1
  private: 10.0.0.2
hosts:
  - name: "{self_name}"
    region: us-east-1
    ip: 203.0.113.1
  - name: "{peer_name}"
    region: us-west-2
    ip: 203.0.113.2
"#,
            ),
        )
        .expect("hosts should write");

        let loaded = load_deployer_config(&hosts_path, &config_path);

        assert!(loaded.json_logs);
        assert!(loaded.deployer_managed);
        assert_eq!(loaded.startup, StartupModeConfig::MarshalSync);
        assert_eq!(loaded.http_listen, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(loaded.metrics_listen, "0.0.0.0:9090".parse().unwrap());
        assert_eq!(loaded.max_propose_bytes, 1_234_567);
        assert_eq!(loaded.max_pool_bytes, 9_876_543);
        assert_eq!(loaded.decoded.listen_bind, "0.0.0.0:9000".parse().unwrap());
        assert_eq!(
            loaded.decoded.listen_advertise,
            "203.0.113.1:9000".parse::<SocketAddr>().unwrap()
        );
        assert!(loaded.decoded.share.is_some());
        assert_eq!(loaded.decoded.primary_participants.len(), 2);
        assert!(loaded.decoded.primary_participants.contains(self_key));
        assert!(loaded.decoded.primary_participants.contains(peer_key));
        assert!(loaded.decoded.secondary_participants.is_empty());
        assert_eq!(
            loaded.decoded.bootstrappers[0].1,
            commonware_p2p::Ingress::Socket("203.0.113.2:9000".parse().unwrap())
        );
        assert!(loaded.otel.is_none());

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(hosts_path);
    }

    #[test]
    fn deployer_config_enables_traces_with_sampling_rate() {
        let cluster = Cluster::new(2, 0);
        let self_key = &cluster.primary_keys[0];
        let peer_key = &cluster.primary_keys[1];
        let self_name = hex(&self_key.encode());
        let peer_name = hex(&peer_key.encode());
        let config_path = temp_path("validator-config", ".yaml");
        let hosts_path = temp_path("validator-hosts", ".yaml");

        let mut config = cluster.primary_config(
            0,
            StartupModeConfig::MarshalSync,
            vec![bootstrapper_entry(peer_key)],
        );
        config.traces = 0.25;
        fs::write(
            &config_path,
            serde_yaml::to_string(&config).expect("config should serialize"),
        )
        .expect("config should write");
        fs::write(
            &hosts_path,
            format!(
                r#"monitoring:
  public: 10.0.0.1
  private: 10.0.0.2
hosts:
  - name: "{self_name}"
    region: us-east-1
    ip: 203.0.113.1
  - name: "{peer_name}"
    region: us-west-2
    ip: 203.0.113.2
"#,
            ),
        )
        .expect("hosts should write");

        let loaded = load_deployer_config(&hosts_path, &config_path);
        assert_eq!(
            loaded.otel,
            Some(("http://10.0.0.2:4318/v1/traces".to_string(), 0.25))
        );

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(hosts_path);
    }

    #[test]
    fn deployer_config_tracks_all_participants_not_only_bootstrappers() {
        let cluster = Cluster::new(3, 0);
        let self_key = &cluster.primary_keys[0];
        let bootstrapper_key = &cluster.primary_keys[1];
        let third_key = &cluster.primary_keys[2];
        let self_name = hex(&self_key.encode());
        let bootstrapper_name = hex(&bootstrapper_key.encode());
        let third_name = hex(&third_key.encode());
        let config_path = temp_path("validator-config", ".yaml");
        let hosts_path = temp_path("validator-hosts", ".yaml");

        let config = cluster.primary_config(
            0,
            StartupModeConfig::MarshalSync,
            vec![bootstrapper_entry(bootstrapper_key)],
        );
        fs::write(
            &config_path,
            serde_yaml::to_string(&config).expect("config should serialize"),
        )
        .expect("config should write");
        fs::write(
            &hosts_path,
            format!(
                r#"monitoring:
  public: 10.0.0.1
  private: 10.0.0.2
hosts:
  - name: "{self_name}"
    region: us-east-1
    ip: 203.0.113.1
  - name: "{bootstrapper_name}"
    region: us-west-2
    ip: 203.0.113.2
  - name: "{third_name}"
    region: eu-west-1
    ip: 203.0.113.3
"#,
            ),
        )
        .expect("hosts should write");

        let loaded = load_deployer_config(&hosts_path, &config_path);

        assert_eq!(loaded.decoded.primary_participants.len(), 3);
        assert!(loaded.decoded.primary_participants.contains(self_key));
        assert!(
            loaded
                .decoded
                .primary_participants
                .contains(bootstrapper_key)
        );
        assert!(loaded.decoded.primary_participants.contains(third_key));
        assert_eq!(loaded.decoded.bootstrappers.len(), 1);

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(hosts_path);
    }

    #[test]
    fn deployer_config_ignores_non_validator_hosts() {
        let cluster = Cluster::new(2, 0);
        let self_key = &cluster.primary_keys[0];
        let peer_key = &cluster.primary_keys[1];
        let self_name = hex(&self_key.encode());
        let peer_name = hex(&peer_key.encode());
        let config_path = temp_path("validator-config", ".yaml");
        let hosts_path = temp_path("validator-hosts", ".yaml");

        let config = cluster.primary_config(
            0,
            StartupModeConfig::MarshalSync,
            vec![bootstrapper_entry(peer_key)],
        );
        fs::write(
            &config_path,
            serde_yaml::to_string(&config).expect("config should serialize"),
        )
        .expect("config should write");
        fs::write(
            &hosts_path,
            format!(
                r#"monitoring:
  public: 10.0.0.1
  private: 10.0.0.2
hosts:
  - name: "{self_name}"
    region: us-east-1
    ip: 203.0.113.1
  - name: "{peer_name}"
    region: us-west-2
    ip: 203.0.113.2
  - name: "spammer"
    region: us-east-1
    ip: 203.0.113.9
"#,
            ),
        )
        .expect("hosts should write");

        let loaded = load_deployer_config(&hosts_path, &config_path);

        assert_eq!(loaded.decoded.primary_participants.len(), 2);
        assert!(loaded.decoded.primary_participants.contains(self_key));
        assert!(loaded.decoded.primary_participants.contains(peer_key));
        assert!(loaded.decoded.secondary_participants.is_empty());

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(hosts_path);
    }

    #[test]
    fn local_config_honors_state_sync_startup() {
        let cluster = Cluster::new(2, 0);
        let self_key = &cluster.primary_keys[0];
        let peer_key = &cluster.primary_keys[1];
        let config_path = temp_path("validator-config", ".yaml");
        let peers_path = temp_path("validator-peers", ".yaml");

        let config = cluster.primary_config(
            0,
            StartupModeConfig::StateSync,
            vec![bootstrapper_entry(peer_key)],
        );
        fs::write(
            &config_path,
            serde_yaml::to_string(&config).expect("config should serialize"),
        )
        .expect("config should write");
        fs::write(
            &peers_path,
            format!(
                r#"validators:
  - name: "{self_name}"
    p2p: "127.0.0.1:9000"
    http: "127.0.0.1:8080"
  - name: "{peer_name}"
    p2p: "127.0.0.1:9001"
    http: "127.0.0.1:8081"
"#,
                self_name = hex(&self_key.encode()),
                peer_name = hex(&peer_key.encode()),
            ),
        )
        .expect("peers should write");

        let loaded = load_local_config(&peers_path, &config_path);

        assert_eq!(loaded.startup, StartupModeConfig::StateSync);

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(peers_path);
    }

    #[test]
    fn deployer_config_resolves_named_chain_indexer_url() {
        let cluster = Cluster::new(2, 1);
        let self_key = &cluster.secondary_keys[0];
        let primary0_key = &cluster.primary_keys[0];
        let primary1_key = &cluster.primary_keys[1];
        let self_name = hex(&self_key.encode());
        let primary0_name = hex(&primary0_key.encode());
        let primary1_name = hex(&primary1_key.encode());
        let config_path = temp_path("validator-config", ".yaml");
        let hosts_path = temp_path("validator-hosts", ".yaml");

        let mut config = cluster.secondary_config(
            0,
            StartupModeConfig::MarshalSync,
            vec![bootstrapper_entry(primary0_key)],
        );
        config.indexer = Some(IndexerConfig {
            chain_indexer_url: "http://chain-indexer:8090".to_string(),
            upload_buffer: default_upload_buffer(),
        });
        fs::write(
            &config_path,
            serde_yaml::to_string(&config).expect("config should serialize"),
        )
        .expect("config should write");
        fs::write(
            &hosts_path,
            format!(
                r#"monitoring:
  public: 10.0.0.1
  private: 10.0.0.2
hosts:
  - name: "{primary0_name}"
    region: us-east-1
    ip: 203.0.113.1
  - name: "{primary1_name}"
    region: us-west-2
    ip: 203.0.113.2
  - name: "{self_name}"
    region: eu-west-1
    ip: 203.0.113.3
  - name: "chain-indexer"
    region: us-east-1
    ip: 203.0.113.9
"#,
            ),
        )
        .expect("hosts should write");

        let loaded = load_deployer_config(&hosts_path, &config_path);

        let indexer = loaded
            .indexer
            .expect("secondary should keep indexer config");
        assert_eq!(indexer.chain_indexer_url, "http://203.0.113.9:8090");

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(hosts_path);
    }

    /// Secondary validator: empty `dkg_share` must decode to `None`.
    #[test]
    fn deployer_config_secondary_has_no_share() {
        let cluster = Cluster::new(2, 1);
        let self_key = &cluster.secondary_keys[0];
        let primary0_key = &cluster.primary_keys[0];
        let primary1_key = &cluster.primary_keys[1];
        let self_name = hex(&self_key.encode());
        let primary0_name = hex(&primary0_key.encode());
        let primary1_name = hex(&primary1_key.encode());
        let config_path = temp_path("validator-config", ".yaml");
        let hosts_path = temp_path("validator-hosts", ".yaml");

        let config = cluster.secondary_config(
            0,
            StartupModeConfig::MarshalSync,
            vec![bootstrapper_entry(primary0_key)],
        );
        fs::write(
            &config_path,
            serde_yaml::to_string(&config).expect("config should serialize"),
        )
        .expect("config should write");
        fs::write(
            &hosts_path,
            format!(
                r#"monitoring:
  public: 10.0.0.1
  private: 10.0.0.2
hosts:
  - name: "{primary0_name}"
    region: us-east-1
    ip: 203.0.113.1
  - name: "{primary1_name}"
    region: us-west-2
    ip: 203.0.113.2
  - name: "{self_name}"
    region: eu-west-1
    ip: 203.0.113.3
"#,
            ),
        )
        .expect("hosts should write");

        let loaded = load_deployer_config(&hosts_path, &config_path);

        // Secondary node: no share.
        assert!(loaded.decoded.share.is_none());
        // Primary set has the 2 primaries, secondary set has the one secondary.
        assert_eq!(loaded.decoded.primary_participants.len(), 2);
        assert!(loaded.decoded.primary_participants.contains(primary0_key));
        assert!(loaded.decoded.primary_participants.contains(primary1_key));
        assert_eq!(loaded.decoded.secondary_participants.len(), 1);
        assert!(loaded.decoded.secondary_participants.contains(self_key));
        // Self IP resolved from hosts file via the secondary's hex name.
        assert_eq!(
            loaded.decoded.listen_advertise,
            "203.0.113.3:9000".parse::<SocketAddr>().unwrap()
        );

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(hosts_path);
    }

    /// Explicit YAML lists populate both `primary_participants` and
    /// `secondary_participants` correctly, regardless of host ordering.
    #[test]
    fn deployer_config_populates_primary_and_secondary_lists() {
        let cluster = Cluster::new(2, 2);
        let primary0_key = &cluster.primary_keys[0];
        let primary1_key = &cluster.primary_keys[1];
        let secondary0_key = &cluster.secondary_keys[0];
        let secondary1_key = &cluster.secondary_keys[1];
        let primary0_name = hex(&primary0_key.encode());
        let primary1_name = hex(&primary1_key.encode());
        let secondary0_name = hex(&secondary0_key.encode());
        let secondary1_name = hex(&secondary1_key.encode());
        let config_path = temp_path("validator-config", ".yaml");
        let hosts_path = temp_path("validator-hosts", ".yaml");

        // Load from the perspective of primary[0].
        let config = cluster.primary_config(
            0,
            StartupModeConfig::MarshalSync,
            vec![bootstrapper_entry(primary1_key)],
        );
        fs::write(
            &config_path,
            serde_yaml::to_string(&config).expect("config should serialize"),
        )
        .expect("config should write");
        fs::write(
            &hosts_path,
            format!(
                r#"monitoring:
  public: 10.0.0.1
  private: 10.0.0.2
hosts:
  - name: "{primary0_name}"
    region: us-east-1
    ip: 203.0.113.1
  - name: "{primary1_name}"
    region: us-west-2
    ip: 203.0.113.2
  - name: "{secondary0_name}"
    region: eu-west-1
    ip: 203.0.113.3
  - name: "{secondary1_name}"
    region: ap-south-1
    ip: 203.0.113.4
"#,
            ),
        )
        .expect("hosts should write");

        let loaded = load_deployer_config(&hosts_path, &config_path);

        assert_eq!(loaded.decoded.primary_participants.len(), 2);
        assert!(loaded.decoded.primary_participants.contains(primary0_key));
        assert!(loaded.decoded.primary_participants.contains(primary1_key));
        assert_eq!(loaded.decoded.secondary_participants.len(), 2);
        assert!(
            loaded
                .decoded
                .secondary_participants
                .contains(secondary0_key)
        );
        assert!(
            loaded
                .decoded
                .secondary_participants
                .contains(secondary1_key)
        );
        // Primary has a share.
        assert!(loaded.decoded.share.is_some());
    }

    /// Non-validator hosts (spammer, monitoring) and unlisted hex-named hosts
    /// must not leak into `primary_participants` or `secondary_participants`.
    /// The explicit YAML lists are the only source of truth.
    #[test]
    fn deployer_config_only_explicit_yaml_lists_determine_participants() {
        // Primary cluster: the full consensus set.
        let cluster = Cluster::new(2, 1);
        let primary0_key = &cluster.primary_keys[0];
        let primary1_key = &cluster.primary_keys[1];
        let secondary0_key = &cluster.secondary_keys[0];
        // An extra ed25519 host present in hosts.yaml but listed in neither
        // primary_validators nor secondary_validators — must be ignored.
        let stranger = ed25519::PrivateKey::from_seed(9_999_999).public_key();

        let primary0_name = hex(&primary0_key.encode());
        let primary1_name = hex(&primary1_key.encode());
        let secondary0_name = hex(&secondary0_key.encode());
        let stranger_name = hex(&stranger.encode());
        let config_path = temp_path("validator-config", ".yaml");
        let hosts_path = temp_path("validator-hosts", ".yaml");

        let config = cluster.primary_config(
            0,
            StartupModeConfig::MarshalSync,
            vec![bootstrapper_entry(primary1_key)],
        );
        fs::write(
            &config_path,
            serde_yaml::to_string(&config).expect("config should serialize"),
        )
        .expect("config should write");
        fs::write(
            &hosts_path,
            format!(
                r#"monitoring:
  public: 10.0.0.1
  private: 10.0.0.2
hosts:
  - name: "{primary0_name}"
    region: us-east-1
    ip: 203.0.113.1
  - name: "{primary1_name}"
    region: us-west-2
    ip: 203.0.113.2
  - name: "{secondary0_name}"
    region: eu-west-1
    ip: 203.0.113.3
  - name: "spammer"
    region: us-east-1
    ip: 203.0.113.8
  - name: "{stranger_name}"
    region: eu-central-1
    ip: 203.0.113.9
"#,
            ),
        )
        .expect("hosts should write");

        let loaded = load_deployer_config(&hosts_path, &config_path);

        // Exactly the explicit YAML list entries, nothing else.
        assert_eq!(loaded.decoded.primary_participants.len(), 2);
        assert!(loaded.decoded.primary_participants.contains(primary0_key));
        assert!(loaded.decoded.primary_participants.contains(primary1_key));
        assert_eq!(loaded.decoded.secondary_participants.len(), 1);
        assert!(
            loaded
                .decoded
                .secondary_participants
                .contains(secondary0_key)
        );
        // The stranger (valid ed25519 hex name, unlisted) must not appear.
        assert!(!loaded.decoded.primary_participants.contains(&stranger));
        assert!(!loaded.decoded.secondary_participants.contains(&stranger));

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(hosts_path);
    }

    /// Local (peers.yaml) path: a secondary node resolves its own p2p address
    /// from the `secondaries:` block of the peers file.
    #[test]
    fn local_config_secondary_resolves_from_secondaries_block() {
        let cluster = Cluster::new(2, 1);
        let self_key = &cluster.secondary_keys[0];
        let primary0_key = &cluster.primary_keys[0];
        let primary1_key = &cluster.primary_keys[1];
        let config_path = temp_path("validator-config", ".yaml");
        let peers_path = temp_path("validator-peers", ".yaml");

        let config = cluster.secondary_config(
            0,
            StartupModeConfig::MarshalSync,
            vec![bootstrapper_entry(primary0_key)],
        );
        fs::write(
            &config_path,
            serde_yaml::to_string(&config).expect("config should serialize"),
        )
        .expect("config should write");
        fs::write(
            &peers_path,
            format!(
                r#"validators:
  - name: "{primary0_name}"
    p2p: "127.0.0.1:9000"
    http: "127.0.0.1:8080"
  - name: "{primary1_name}"
    p2p: "127.0.0.1:9001"
    http: "127.0.0.1:8081"
secondaries:
  - name: "{self_name}"
    p2p: "127.0.0.1:9100"
    http: "127.0.0.1:8180"
"#,
                primary0_name = hex(&primary0_key.encode()),
                primary1_name = hex(&primary1_key.encode()),
                self_name = hex(&self_key.encode()),
            ),
        )
        .expect("peers should write");

        let loaded = load_local_config(&peers_path, &config_path);

        assert!(loaded.decoded.share.is_none());
        assert_eq!(loaded.decoded.primary_participants.len(), 2);
        assert_eq!(loaded.decoded.secondary_participants.len(), 1);
        assert!(loaded.decoded.secondary_participants.contains(self_key));
        assert_eq!(
            loaded.decoded.listen_advertise,
            "127.0.0.1:9100".parse::<SocketAddr>().unwrap()
        );

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(peers_path);
    }
}
