//! YAML-serializable validator configuration.

use commonware_codec::{Encode, Read as CodecRead, ReadExt};
use commonware_cryptography::{
    Signer,
    bls12381::{
        dkg,
        primitives::{group::Share, sharing::ModeVersion, variant::MinSig},
    },
    ed25519,
};
use commonware_deployer::aws::Hosts;
use commonware_p2p::{Ingress, authenticated::discovery::Bootstrapper};
use commonware_utils::{NZU32, from_hex, hex};
use serde::Deserialize;
use std::{collections::HashMap, net::SocketAddr, path::Path};

pub(crate) const fn default_max_propose_bytes() -> usize {
    4 * 1024 * 1024 // 4 MiB
}

pub(crate) const fn default_max_pool_bytes() -> usize {
    64 * 1024 * 1024 // 64 MiB
}

pub(crate) const fn default_rayon_threads() -> usize {
    2
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ValidatorConfig {
    pub private_key: String,
    pub dkg_output: String,
    pub dkg_share: String,
    pub listen_port: u16,
    pub genesis_leader: String,
    pub partition_prefix: String,
    pub num_validators: u32,
    pub log_level: String,
    pub worker_threads: usize,
    #[serde(default = "default_rayon_threads")]
    pub rayon_threads: usize,
    pub http_port: u16,
    /// Max bytes of transactions per propose() call.
    #[serde(default = "default_max_propose_bytes")]
    pub max_propose_bytes: usize,
    /// Max bytes of pending transactions before rejecting.
    #[serde(default = "default_max_pool_bytes")]
    pub max_pool_bytes: usize,
    pub bootstrappers: Vec<NamedBootstrapperEntry>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct NamedBootstrapperEntry {
    pub public_key: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
struct PeerEntry {
    name: String,
    p2p: String,
    http: String,
}

#[derive(Debug, Deserialize)]
struct PeersFile {
    validators: Vec<PeerEntry>,
}

/// Decoded key material and network info ready for use by the engine.
pub struct DecodedConfig {
    pub signer: ed25519::PrivateKey,
    pub public_key: ed25519::PublicKey,
    pub dkg_output: dkg::Output<MinSig, ed25519::PublicKey>,
    pub share: Share,
    pub genesis_leader: ed25519::PublicKey,
    pub listen_bind: SocketAddr,
    pub listen_advertise: SocketAddr,
    pub bootstrappers: Vec<Bootstrapper<ed25519::PublicKey>>,
    pub partition_prefix: String,
}

pub struct LoadedConfig {
    pub decoded: DecodedConfig,
    pub log_level: String,
    pub worker_threads: usize,
    pub rayon_threads: usize,
    pub http_listen: SocketAddr,
    pub json_logs: bool,
    pub deployer_managed: bool,
    pub max_propose_bytes: usize,
    pub max_pool_bytes: usize,
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

fn decode_share(hex_str: &str) -> Share {
    let bytes = decode_hex("dkg_share", hex_str);
    Share::read(&mut &bytes[..]).expect("failed to decode DKG share")
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

fn decode_with_network(
    config: ValidatorConfig,
    public_listen: SocketAddr,
    bootstrappers: Vec<Bootstrapper<ed25519::PublicKey>>,
    json_logs: bool,
) -> LoadedConfig {
    let signer = decode_private_key(&config.private_key);
    let public_key = signer.public_key();
    let dkg_output = decode_dkg_output(&config.dkg_output, config.num_validators);
    let share = decode_share(&config.dkg_share);
    let genesis_leader = decode_public_key("genesis_leader", &config.genesis_leader);
    let listen_bind: SocketAddr = format!("0.0.0.0:{}", config.listen_port)
        .parse()
        .expect("bad listen port");
    let http_listen: SocketAddr = format!("0.0.0.0:{}", config.http_port)
        .parse()
        .expect("bad HTTP listen port");

    LoadedConfig {
        decoded: DecodedConfig {
            signer,
            public_key,
            dkg_output,
            share,
            genesis_leader,
            listen_bind,
            listen_advertise: public_listen,
            bootstrappers,
            partition_prefix: config.partition_prefix,
        },
        log_level: config.log_level,
        worker_threads: config.worker_threads,
        rayon_threads: config.rayon_threads,
        http_listen,
        json_logs,
        deployer_managed: json_logs,
        max_propose_bytes: config.max_propose_bytes,
        max_pool_bytes: config.max_pool_bytes,
    }
}

pub fn load_local_config(peers_path: &Path, config_path: &Path) -> LoadedConfig {
    let config = load_validator_config(config_path);
    let signer = decode_private_key(&config.private_key);
    let self_name = hex(&signer.public_key().encode());
    let raw_peers = std::fs::read_to_string(peers_path).expect("failed to read peers file");
    let peers: PeersFile = serde_yaml::from_str(&raw_peers).expect("failed to parse peers file");
    let peers_by_name = peers
        .validators
        .into_iter()
        .map(|peer| {
            let name = peer.name.clone();
            (name, peer)
        })
        .collect::<HashMap<_, _>>();

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

    decode_with_network(config, public_listen, bootstrappers, false)
}

pub fn load_deployer_config(hosts_path: &Path, config_path: &Path) -> LoadedConfig {
    let config = load_validator_config(config_path);
    let signer = decode_private_key(&config.private_key);
    let self_name = hex(&signer.public_key().encode());
    let raw_hosts = std::fs::read_to_string(hosts_path).expect("failed to read hosts file");
    let hosts: Hosts = serde_yaml::from_str(&raw_hosts).expect("failed to parse hosts file");
    let hosts_by_name = hosts
        .hosts
        .iter()
        .map(|host| (host.name.as_str(), host.ip))
        .collect::<HashMap<_, _>>();

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

    decode_with_network(config, public_listen, bootstrappers, true)
}

#[cfg(test)]
mod tests {
    use super::{NamedBootstrapperEntry, ValidatorConfig, load_deployer_config, load_local_config};
    use commonware_codec::Encode;
    use commonware_cryptography::{
        Signer,
        bls12381::{
            dkg,
            primitives::{group::Share, variant::MinSig},
        },
        ed25519,
    };
    use commonware_utils::{N3f1, TryCollect, hex};
    use std::{
        fs,
        net::SocketAddr,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_path(prefix: &str, suffix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{unique}{suffix}"))
    }

    #[test]
    fn local_config_resolves_bootstrapper_peers() {
        let validators = (0_u64..2)
            .map(ed25519::PrivateKey::from_seed)
            .collect::<Vec<_>>();
        let public_keys = validators
            .iter()
            .map(Signer::public_key)
            .collect::<Vec<_>>();
        let participants = public_keys.clone().into_iter().try_collect().unwrap();
        let mut rng = commonware_utils::test_rng();
        let (dkg_output, raw_shares) =
            dkg::deal::<MinSig, _, N3f1>(&mut rng, Default::default(), participants)
                .expect("DKG deal failed");
        let shares = raw_shares
            .into_iter()
            .collect::<std::collections::BTreeMap<_, Share>>();
        let signer = &validators[0];
        let public_key = signer.public_key();
        let share = shares.get(&public_key).expect("missing share");
        let peer_name = hex(&public_keys[1].encode());
        let config_path = temp_path("validator-config", ".yaml");
        let peers_path = temp_path("validator-peers", ".yaml");

        let config = ValidatorConfig {
            private_key: hex(&signer.encode()),
            dkg_output: hex(&dkg_output.encode()),
            dkg_share: hex(&share.encode()),
            listen_port: 9000,
            genesis_leader: hex(&public_key.encode()),
            partition_prefix: "validator-0".to_string(),
            num_validators: 2,
            log_level: "info".to_string(),
            worker_threads: 2,
            rayon_threads: 2,
            http_port: 8080,
            max_propose_bytes: super::default_max_propose_bytes(),
            max_pool_bytes: super::default_max_pool_bytes(),
            bootstrappers: vec![NamedBootstrapperEntry {
                public_key: peer_name.clone(),
                name: peer_name.clone(),
            }],
        };
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
                self_name = hex(&public_key.encode()),
            ),
        )
        .expect("peers should write");

        let loaded = load_local_config(&peers_path, &config_path);

        assert!(!loaded.json_logs);
        assert!(!loaded.deployer_managed);
        assert_eq!(loaded.http_listen, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(loaded.decoded.listen_bind, "0.0.0.0:9000".parse().unwrap());
        assert_eq!(
            loaded.decoded.listen_advertise,
            "127.0.0.1:9000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            loaded.decoded.bootstrappers[0].1,
            commonware_p2p::Ingress::Socket("127.0.0.1:9001".parse().unwrap())
        );

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(peers_path);
    }

    #[test]
    fn deployer_config_resolves_bootstrapper_hosts() {
        let validators = (0_u64..2)
            .map(ed25519::PrivateKey::from_seed)
            .collect::<Vec<_>>();
        let public_keys = validators
            .iter()
            .map(Signer::public_key)
            .collect::<Vec<_>>();
        let participants = public_keys.clone().into_iter().try_collect().unwrap();
        let mut rng = commonware_utils::test_rng();
        let (dkg_output, raw_shares) =
            dkg::deal::<MinSig, _, N3f1>(&mut rng, Default::default(), participants)
                .expect("DKG deal failed");
        let shares = raw_shares
            .into_iter()
            .collect::<std::collections::BTreeMap<_, Share>>();
        let signer = &validators[0];
        let public_key = signer.public_key();
        let share = shares.get(&public_key).expect("missing share");
        let peer_name = hex(&public_keys[1].encode());
        let self_name = hex(&public_key.encode());
        let config_path = temp_path("validator-config", ".yaml");
        let hosts_path = temp_path("validator-hosts", ".yaml");

        let config = ValidatorConfig {
            private_key: hex(&signer.encode()),
            dkg_output: hex(&dkg_output.encode()),
            dkg_share: hex(&share.encode()),
            listen_port: 9000,
            genesis_leader: hex(&public_key.encode()),
            partition_prefix: "validator-0".to_string(),
            num_validators: 2,
            log_level: "info".to_string(),
            worker_threads: 2,
            rayon_threads: 2,
            http_port: 8080,
            max_propose_bytes: super::default_max_propose_bytes(),
            max_pool_bytes: super::default_max_pool_bytes(),
            bootstrappers: vec![NamedBootstrapperEntry {
                public_key: peer_name.clone(),
                name: peer_name.clone(),
            }],
        };
        fs::write(
            &config_path,
            serde_yaml::to_string(&config).expect("config should serialize"),
        )
        .expect("config should write");
        fs::write(
            &hosts_path,
            format!(
                r#"monitoring: 10.0.0.1
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
        assert_eq!(loaded.http_listen, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(loaded.decoded.listen_bind, "0.0.0.0:9000".parse().unwrap());
        assert_eq!(
            loaded.decoded.listen_advertise,
            "203.0.113.1:9000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            loaded.decoded.bootstrappers[0].1,
            commonware_p2p::Ingress::Socket("203.0.113.2:9000".parse().unwrap())
        );

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(hosts_path);
    }
}
