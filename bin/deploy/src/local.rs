use crate::{
    CHAIN_INDEXER_BINARY_FILE, CHAIN_INDEXER_DATA_DIR, ClusterMaterial, GenerateArgs,
    INDEXER_UPLOAD_BUFFER, IndexerConfig, LocalArgs, METADATA_INDEXER_BINARY_FILE,
    PEERS_CONFIG_FILE, PeerEntry, PeersConfig, QMDB_INDEXER_BINARY_FILE, RelayerConfig,
    RelayerLeaderConfig, SecondaryRole, ValidatorConfig, absolute_path, eligible_peer_entries,
    ensure_output_dir_missing, generate_local_cluster_material, indexer_enabled, secondary_roles,
    total_secondaries, validate_generate_args, write_simplex_verification_material,
    write_yaml_config,
};
use commonware_codec::Encode;
use commonware_formatting::hex;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use tracing::info;

const MAX_LOCAL_VALIDATORS: u32 = 64;
const DEFAULT_EXPLORER_PORT: u16 = 5173;

struct GeneratedValidator {
    config_file: PathBuf,
    config: ValidatorConfig,
    peer: PeerEntry,
}

#[derive(Clone, Copy, Debug)]
struct LocalNodePorts {
    p2p: u16,
    http: u16,
    metrics: u16,
}

/// Complete loopback port allocation for one generated local deployment.
///
/// Validator and secondary base ranges are explicit operator choices, so they
/// must already be disjoint. Auxiliary services retain their existing
/// preferred ports when available and move upward deterministically when a
/// larger node range occupies those ports.
#[derive(Debug)]
struct LocalPortPlan {
    nodes: Vec<LocalNodePorts>,
    chain_indexer: Option<u16>,
    chain_indexer_metrics: Option<u16>,
    metadata_indexer: Option<u16>,
    qmdb_indexer: Option<u16>,
    explorer: Option<u16>,
    spammer_metrics: Option<u16>,
    relayer_http: Option<u16>,
}

impl LocalPortPlan {
    fn new(args: &GenerateArgs, local: &LocalArgs) -> Self {
        assert!(args.validators >= 1, "need at least one validator");
        assert!(
            args.validators <= MAX_LOCAL_VALIDATORS,
            "local deployments support at most {MAX_LOCAL_VALIDATORS} validators"
        );

        let validators =
            usize::try_from(args.validators).expect("local validator count must fit in usize");
        let secondaries = usize::try_from(total_secondaries(args))
            .expect("local secondary count must fit in usize");
        let node_count = validators
            .checked_add(secondaries)
            .expect("local node count overflow");
        let mut allocator = PortAllocator::default();
        let mut nodes = Vec::with_capacity(node_count);

        for index in 0..node_count {
            let p2p = offset_port(local.base_port, index, "node p2p");
            let http = offset_port(local.base_http_port, index, "node HTTP");
            let metrics = offset_port(local.base_metrics_port, index, "node metrics");
            allocator.reserve_exact(p2p, format!("node {index} p2p"));
            allocator.reserve_exact(http, format!("node {index} HTTP"));
            allocator.reserve_exact(metrics, format!("node {index} metrics"));
            nodes.push(LocalNodePorts { p2p, http, metrics });
        }

        let spammer_metrics = args.spammer.then(|| {
            let preferred = offset_port(local.base_metrics_port, node_count, "spammer metrics");
            allocator.reserve_preferred(preferred, "spammer metrics")
        });
        let chain_indexer_metrics = indexer_enabled(args).then(|| {
            let offset = node_count
                .checked_add(usize::from(args.spammer))
                .expect("chain-indexer metrics offset overflow");
            let preferred = offset_port(local.base_metrics_port, offset, "chain-indexer metrics");
            allocator.reserve_preferred(preferred, "chain-indexer metrics")
        });
        let chain_indexer = indexer_enabled(args).then(|| {
            allocator.reserve_preferred(local.chain_indexer_port, "chain-indexer service")
        });
        let metadata_indexer = indexer_enabled(args).then(|| {
            allocator.reserve_preferred(local.metadata_indexer_port, "metadata-indexer service")
        });
        let qmdb_indexer = indexer_enabled(args)
            .then(|| allocator.reserve_preferred(local.qmdb_indexer_port, "qmdb-indexer service"));
        let explorer = indexer_enabled(args)
            .then(|| allocator.reserve_preferred(DEFAULT_EXPLORER_PORT, "explorer service"));
        let relayer_http = args.relayer.then(|| {
            let secondary_index = usize::from(args.indexer);
            nodes[validators + secondary_index].http
        });

        Self {
            nodes,
            chain_indexer,
            chain_indexer_metrics,
            metadata_indexer,
            qmdb_indexer,
            explorer,
            spammer_metrics,
            relayer_http,
        }
    }

    fn validator(&self, index: u32) -> LocalNodePorts {
        self.nodes[index as usize]
    }

    fn secondary(&self, validators: u32, index: usize) -> LocalNodePorts {
        self.nodes[validators as usize + index]
    }
}

#[derive(Debug, Default)]
struct PortAllocator {
    reserved: BTreeMap<u16, String>,
}

impl PortAllocator {
    fn reserve_exact(&mut self, port: u16, owner: impl Into<String>) {
        let owner = owner.into();
        assert_ne!(port, 0, "local port for {owner} must be non-zero");
        if let Some(existing) = self.reserved.get(&port) {
            panic!("local port {port} is assigned to both {existing} and {owner}");
        }
        self.reserved.insert(port, owner);
    }

    fn reserve_preferred(&mut self, preferred: u16, owner: &'static str) -> u16 {
        assert_ne!(preferred, 0, "preferred local port for {owner} is zero");
        for port in preferred..=u16::MAX {
            if self.reserved.contains_key(&port) {
                continue;
            }
            self.reserved.insert(port, owner.to_string());
            return port;
        }
        panic!("no local port is available for {owner} at or above {preferred}");
    }
}

fn offset_port(base: u16, offset: usize, owner: &str) -> u16 {
    let offset = u16::try_from(offset)
        .unwrap_or_else(|_| panic!("local port offset for {owner} does not fit in u16"));
    base.checked_add(offset)
        .unwrap_or_else(|| panic!("local port range for {owner} overflows u16"))
}

pub(super) fn generate(args: &GenerateArgs, local: &LocalArgs) {
    validate_generate_args(args);
    let _port_plan = LocalPortPlan::new(args, local);

    let output_dir = absolute_path(&args.output_dir);
    ensure_output_dir_missing(&output_dir);

    let material = generate_local_cluster_material(args.validators, total_secondaries(args));
    let validators = build_validators(args, local, &output_dir, &material);
    let secondaries = build_secondaries(args, local, &output_dir, &material);
    let peers = PeersConfig {
        validators: validators
            .iter()
            .map(|validator| validator.peer.clone())
            .collect(),
        secondaries: secondaries
            .iter()
            .map(|secondary| secondary.peer.clone())
            .collect(),
    };

    fs::create_dir_all(&output_dir).expect("failed to create output directory");
    for validator in &validators {
        write_yaml_config(&validator.config_file, &validator.config);
    }
    for secondary in &secondaries {
        write_yaml_config(&secondary.config_file, &secondary.config);
    }
    write_yaml_config(&output_dir.join(PEERS_CONFIG_FILE), &peers);
    write_simplex_verification_material(&output_dir, &material);

    print_local_run_commands(
        &output_dir,
        args,
        local,
        &[],
        &material.simplex_verification_material_hex(),
    );
}

fn build_validators(
    args: &GenerateArgs,
    local: &LocalArgs,
    output_dir: &std::path::Path,
    material: &ClusterMaterial,
) -> Vec<GeneratedValidator> {
    let ports = LocalPortPlan::new(args, local);
    let mut validators = Vec::with_capacity(args.validators as usize);

    let eligible_peers = eligible_peer_entries(material);
    let primary_validators = material.primary_hex();
    let secondary_validators = material.secondary_hex();

    for index in 0..args.validators {
        let validator_index = index as usize;
        let public_key = &material.public_keys[validator_index];
        let public_key_hex = hex(&public_key.encode());
        let share = material
            .shares
            .get(public_key)
            .expect("missing share for validator");
        let node_ports = ports.validator(index);

        let config = ValidatorConfig {
            private_key: hex(&material.signers[validator_index].encode()),
            dkg_output: hex(&material.dkg_output.encode()),
            dkg_share: hex(&share.encode()),
            startup: args.startup,
            listen_port: node_ports.p2p,
            genesis_leader: material.genesis_leader.clone(),
            partition_prefix: format!("validator-{index}"),
            num_validators: args.validators,
            primary_validators: primary_validators.clone(),
            secondary_validators: secondary_validators.clone(),
            log_level: args.log_level.clone(),
            worker_threads: args.worker_threads,
            rayon_threads: args.rayon_threads,
            http_port: node_ports.http,
            metrics_port: node_ports.metrics,
            max_propose_bytes: args.max_propose_bytes,
            max_pool_bytes: args.max_pool_bytes,
            state_page_cache_bytes: args.state_page_cache_bytes,
            other_page_cache_bytes: args.other_page_cache_bytes,
            public_key_cache_size: args.public_key_cache_size,
            traces: 0.0,
            eligible_peers: eligible_peers.clone(),
            indexer: None,
            relayer: None,
        };

        validators.push(GeneratedValidator {
            config_file: output_dir.join(format!("validator-{index}.yaml")),
            config,
            peer: PeerEntry {
                name: public_key_hex,
                p2p: format!("127.0.0.1:{}", node_ports.p2p),
                http: format!("127.0.0.1:{}", node_ports.http),
            },
        });
    }

    validators
}

fn build_secondaries(
    args: &GenerateArgs,
    local: &LocalArgs,
    output_dir: &std::path::Path,
    material: &ClusterMaterial,
) -> Vec<GeneratedValidator> {
    let ports = LocalPortPlan::new(args, local);
    let roles = secondary_roles(args);
    let mut secondaries = Vec::with_capacity(roles.len());
    let eligible_peers = eligible_peer_entries(material);
    let primary_validators = material.primary_hex();
    let secondary_validators = material.secondary_hex();

    for (secondary_index, role) in roles.into_iter().enumerate() {
        let index = secondary_index as u32;
        let public_key = &material.secondary_public_keys[secondary_index];
        let public_key_hex = hex(&public_key.encode());
        let node_ports = ports.secondary(args.validators, secondary_index);

        let config = ValidatorConfig {
            private_key: hex(&material.secondary_signers[secondary_index].encode()),
            dkg_output: hex(&material.dkg_output.encode()),
            dkg_share: String::new(),
            startup: args.startup,
            listen_port: node_ports.p2p,
            genesis_leader: material.genesis_leader.clone(),
            partition_prefix: format!("secondary-{index}"),
            num_validators: args.validators,
            primary_validators: primary_validators.clone(),
            secondary_validators: secondary_validators.clone(),
            log_level: args.log_level.clone(),
            worker_threads: args.worker_threads,
            rayon_threads: args.rayon_threads,
            http_port: node_ports.http,
            metrics_port: node_ports.metrics,
            max_propose_bytes: args.max_propose_bytes,
            max_pool_bytes: args.max_pool_bytes,
            state_page_cache_bytes: args.state_page_cache_bytes,
            other_page_cache_bytes: args.other_page_cache_bytes,
            public_key_cache_size: args.public_key_cache_size,
            traces: 0.0,
            eligible_peers: eligible_peers.clone(),
            indexer: matches!(role, SecondaryRole::Indexer).then(|| {
                local_indexer_config(
                    ports
                        .chain_indexer
                        .expect("indexer role requires an allocated service port"),
                )
            }),
            relayer: matches!(role, SecondaryRole::Relayer)
                .then(|| local_relayer_config(&ports, material)),
        };

        secondaries.push(GeneratedValidator {
            config_file: output_dir.join(format!("secondary-{index}.yaml")),
            config,
            peer: PeerEntry {
                name: public_key_hex,
                p2p: format!("127.0.0.1:{}", node_ports.p2p),
                http: format!("127.0.0.1:{}", node_ports.http),
            },
        });
    }

    secondaries
}

fn local_relayer_config(ports: &LocalPortPlan, material: &ClusterMaterial) -> RelayerConfig {
    let leaders = material
        .public_keys
        .iter()
        .chain(&material.secondary_public_keys)
        .enumerate()
        .map(|(index, public_key)| RelayerLeaderConfig {
            public_key: hex(&public_key.encode()),
            url: format!("http://127.0.0.1:{}", ports.nodes[index].http),
        })
        .collect();

    RelayerConfig { leaders }
}

/// Build the full indexer wiring written into the owning secondary's YAML.
///
/// All rows go through the shared `chain-indexer` Store URL. Store prefixes
/// keep raw KV, SQL, and QMDB rows disjoint.
fn local_indexer_config(indexer_port: u16) -> IndexerConfig {
    let url = format!("http://127.0.0.1:{indexer_port}");
    IndexerConfig {
        chain_indexer_url: url,
        upload_buffer: INDEXER_UPLOAD_BUFFER,
    }
}

fn print_local_run_commands(
    output_dir: &Path,
    args: &GenerateArgs,
    local: &LocalArgs,
    relayer_targets: &[String],
    simplex_verification_material: &str,
) {
    let commands = local_run_commands(
        output_dir,
        args,
        local,
        relayer_targets,
        simplex_verification_material,
    );
    let mprocs = commands
        .iter()
        .map(|command| format!("\"{command}\""))
        .collect::<Vec<_>>()
        .join(" ");

    info!(
        output_dir = %output_dir.display(),
        validators = args.validators,
        indexer = args.indexer,
        relayer = args.relayer,
        "generated local deployment bundle"
    );
    info!(command = %format!("mprocs {mprocs}"), "start local deployment");
}

fn local_run_commands(
    output_dir: &Path,
    args: &GenerateArgs,
    local: &LocalArgs,
    relayer_targets: &[String],
    simplex_verification_material: &str,
) -> Vec<String> {
    let ports = LocalPortPlan::new(args, local);
    let peers_path = output_dir.join(PEERS_CONFIG_FILE);
    let mut commands: Vec<String> = (0..args.validators)
        .map(|index| {
            let path = output_dir.join(format!("validator-{index}.yaml"));
            format!(
                "cargo run --release --bin constantinople -- --config {} --peers {}",
                path.display(),
                peers_path.display()
            )
        })
        .collect();

    let total_secondaries = total_secondaries(args);
    for index in 0..total_secondaries {
        let path = output_dir.join(format!("secondary-{index}.yaml"));
        commands.push(format!(
            "cargo run --release --bin constantinople -- --config {} --peers {}",
            path.display(),
            peers_path.display()
        ));
    }

    if indexer_enabled(args) {
        let data_dir = output_dir.join(CHAIN_INDEXER_DATA_DIR);
        let chain_indexer_port = ports
            .chain_indexer
            .expect("indexer stack requires an allocated chain-indexer port");
        let chain_indexer_metrics_port = ports
            .chain_indexer_metrics
            .expect("indexer stack requires an allocated metrics port");
        let metadata_indexer_port = ports
            .metadata_indexer
            .expect("indexer stack requires an allocated metadata-indexer port");
        let qmdb_indexer_port = ports
            .qmdb_indexer
            .expect("indexer stack requires an allocated qmdb-indexer port");
        let explorer_port = ports
            .explorer
            .expect("indexer stack requires an allocated explorer port");
        let db_parallelism = local
            .chain_indexer_db_parallelism
            .map(|jobs| format!(" --db-parallelism {jobs}"))
            .unwrap_or_default();
        commands.push(format!(
            "cargo run --release -p constantinople-indexer --bin {} -- --port {} --metrics-port {} --data-dir {}{}",
            CHAIN_INDEXER_BINARY_FILE,
            chain_indexer_port,
            chain_indexer_metrics_port,
            data_dir.display(),
            db_parallelism,
        ));
        // `metadata-indexer`: exposes Constantinople's `block_meta` /
        // `tx_meta` tables over `store.sql.v1.Service`. The explorer
        // subscribes to this service (not the raw store) for live block
        // metadata.
        commands.push(format!(
            "cargo run --release -p constantinople-indexer --bin {} -- \
             --store-url http://127.0.0.1:{} --port {}",
            METADATA_INDEXER_BINARY_FILE, chain_indexer_port, metadata_indexer_port,
        ));
        commands.push(format!(
            "cargo run --release -p constantinople-indexer --bin {} -- \
             --store-url http://127.0.0.1:{} --port {}",
            QMDB_INDEXER_BINARY_FILE, chain_indexer_port, qmdb_indexer_port,
        ));
        // Bring up the React explorer dev server alongside the metadata and
        // QMDB facades so operators get a live view and browser-verified
        // submitted-transaction proofs.
        // The defaults in `explorer/src/App.tsx` match these ports, but pass
        // all URLs explicitly so relocated or non-default ports still work.
        let relayer_env = ports
            .relayer_http
            .map(|port| format!(" VITE_MEMPOOL_URL=http://127.0.0.1:{port}"))
            .unwrap_or_default();
        commands.push(format!(
            "VITE_SQL_URL=http://127.0.0.1:{} VITE_QMDB_URL=http://127.0.0.1:{} VITE_STORE_URL=http://127.0.0.1:{} VITE_SIMPLEX_VERIFICATION_MATERIAL={}{} npm --prefix explorer run dev -- --port {}",
            metadata_indexer_port,
            qmdb_indexer_port,
            chain_indexer_port,
            simplex_verification_material,
            relayer_env,
            explorer_port,
        ));
    }

    if args.spammer {
        let relayer_port = ports
            .relayer_http
            .expect("--spammer requires a relayer secondary");
        let mut network_source = format!(
            "--relayer-url http://127.0.0.1:{} --relayer-submitters {}",
            relayer_port, args.validators,
        );
        if !relayer_targets.is_empty() {
            network_source.push_str(&format!(" --relayer-targets {}", relayer_targets.join(",")));
        }

        let metrics_port = ports
            .spammer_metrics
            .expect("--spammer requires an allocated metrics port");
        commands.push(format!(
            "cargo run --release --bin constantinople-spammer -- \
             {network_source} \
             --accounts {} \
             --value {} \
             --seed-offset {} \
             --rayon-threads {} \
             --accounts-jitter {} \
             --presigned-batches {} \
             --metrics-port {metrics_port}",
            args.spammer_accounts,
            args.spammer_value,
            args.spammer_seed_offset,
            args.spammer_rayon_threads,
            args.spammer_accounts_jitter,
            args.spammer_presigned_batches,
        ));
    }

    commands
}

#[cfg(test)]
mod tests {
    use super::{LocalPortPlan, build_secondaries, build_validators, local_run_commands};
    use crate::{
        GenerateArgs, GenerateTarget, LocalArgs, StartupModeConfig, default_max_pool_bytes,
        default_max_propose_bytes, default_page_cache_bytes, default_public_key_cache_size,
        generate_local_cluster_material, total_secondaries,
    };
    use commonware_codec::Encode as _;
    use commonware_formatting::hex;
    use std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
    };

    const TEST_SIMPLEX_VERIFICATION_MATERIAL: &str = "abcdef";

    fn test_args(spammer: bool) -> GenerateArgs {
        GenerateArgs {
            validators: 2,
            indexer: false,
            relayer: false,
            output_dir: PathBuf::from("/tmp/configs"),
            log_level: "info".to_string(),
            worker_threads: 2,
            rayon_threads: 2,
            public_key_cache_size: default_public_key_cache_size(),
            max_propose_bytes: default_max_propose_bytes(),
            max_pool_bytes: default_max_pool_bytes(),
            state_page_cache_bytes: default_page_cache_bytes(),
            other_page_cache_bytes: default_page_cache_bytes(),
            startup: StartupModeConfig::MarshalSync,
            spammer,
            spammer_accounts: 10,
            spammer_value: 1,
            spammer_seed_offset: 1000,
            spammer_rayon_threads: crate::DEFAULT_SPAMMER_RAYON_THREADS,
            spammer_accounts_jitter: 0.0,
            spammer_presigned_batches: crate::DEFAULT_SPAMMER_PRESIGNED_BATCHES,
            target: GenerateTarget::Local(test_local_args()),
        }
    }

    fn test_local_args() -> LocalArgs {
        LocalArgs {
            base_port: 9000,
            base_http_port: 8080,
            base_metrics_port: 9090,
            chain_indexer_port: 8090,
            chain_indexer_db_parallelism: None,
            metadata_indexer_port: 8091,
            qmdb_indexer_port: 8092,
        }
    }

    /// Borrow the [`LocalArgs`] embedded in a [`GenerateArgs`] built by
    /// [`test_args`], avoiding duplicate construction in every test.
    fn local_args(args: &GenerateArgs) -> &LocalArgs {
        match &args.target {
            GenerateTarget::Local(local) => local,
            _ => panic!("test_args must construct a Local target"),
        }
    }

    fn command_flag_port(command: &str, flag: &str) -> u16 {
        let parts = command.split_whitespace().collect::<Vec<_>>();
        let flag_index = parts
            .iter()
            .position(|part| *part == flag)
            .unwrap_or_else(|| panic!("missing {flag} in command: {command}"));
        parts
            .get(flag_index + 1)
            .unwrap_or_else(|| panic!("missing value after {flag} in command: {command}"))
            .parse()
            .unwrap_or_else(|error| panic!("invalid port after {flag} in command: {error}"))
    }

    fn assert_unique_port(seen: &mut BTreeMap<u16, String>, port: u16, owner: impl Into<String>) {
        let owner = owner.into();
        if let Some(existing) = seen.insert(port, owner.clone()) {
            panic!("port {port} is assigned to both {existing} and {owner}");
        }
    }

    #[test]
    fn local_run_commands_only_start_validators() {
        let args = test_args(false);
        let commands = local_run_commands(
            Path::new("/tmp/configs"),
            &args,
            local_args(&args),
            &[],
            TEST_SIMPLEX_VERIFICATION_MATERIAL,
        );

        assert_eq!(commands.len(), 2);
        assert!(commands.iter().all(|command| !command.contains("spammer")));
    }

    #[test]
    fn local_run_commands_include_spammer_when_enabled() {
        let mut args = test_args(true);
        args.relayer = true;
        let commands = local_run_commands(
            Path::new("/tmp/configs"),
            &args,
            local_args(&args),
            &[],
            TEST_SIMPLEX_VERIFICATION_MATERIAL,
        );

        assert_eq!(commands.len(), 4);
        assert!(commands[2].contains("secondary-0.yaml"));
        assert!(commands[3].contains("constantinople-spammer"));
        assert!(commands[3].contains("--relayer-url http://127.0.0.1:8082"));
        assert!(commands[3].contains("--relayer-submitters 2"));
        assert!(!commands[3].contains("--relayer-targets"));
        assert!(commands[3].contains("--accounts 10"));
        assert!(commands[3].contains("--value 1"));
        assert!(commands[3].contains("--seed-offset 1000"));
        assert!(commands[3].contains("--rayon-threads 2"));
        assert!(commands[3].contains("--accounts-jitter 0"));
    }

    #[test]
    fn local_run_commands_include_relayer() {
        let mut args = test_args(false);
        args.relayer = true;
        let commands = local_run_commands(
            Path::new("/tmp/configs"),
            &args,
            local_args(&args),
            &[],
            TEST_SIMPLEX_VERIFICATION_MATERIAL,
        );

        assert_eq!(commands.len(), 3);
        assert!(commands[2].contains("constantinople"));
        assert!(commands[2].contains("secondary-0.yaml"));
    }

    #[test]
    fn local_relayer_catalog_covers_every_eligible_validator() {
        let mut args = test_args(false);
        args.relayer = true;
        let material = generate_local_cluster_material(args.validators, total_secondaries(&args));
        let ports = LocalPortPlan::new(&args, local_args(&args));
        let config = super::local_relayer_config(&ports, &material);
        let expected = material
            .public_keys
            .iter()
            .chain(&material.secondary_public_keys)
            .enumerate()
            .map(|(index, public_key)| {
                (
                    hex(&public_key.encode()),
                    format!("http://127.0.0.1:{}", 8080 + index),
                )
            })
            .collect::<Vec<_>>();
        let actual = config
            .leaders
            .into_iter()
            .map(|leader| (leader.public_key, leader.url))
            .collect::<Vec<_>>();

        assert_eq!(actual, expected);
    }

    #[test]
    fn local_spammer_uses_relayer() {
        let mut args = test_args(true);
        args.relayer = true;
        let targets = vec!["aa".to_string(), "bb".to_string()];
        let commands = local_run_commands(
            Path::new("/tmp/configs"),
            &args,
            local_args(&args),
            &targets,
            TEST_SIMPLEX_VERIFICATION_MATERIAL,
        );

        assert_eq!(commands.len(), 4);
        assert!(commands[2].contains("secondary-0.yaml"));
        assert!(commands[3].contains("constantinople-spammer"));
        assert!(commands[3].contains("--relayer-url http://127.0.0.1:8082"));
        assert!(commands[3].contains("--relayer-submitters 2"));
        assert!(commands[3].contains("--relayer-targets aa,bb"));
        assert!(commands[3].contains("--presigned-batches 16"));
        assert!(!commands[3].contains("--peers"));
    }

    #[test]
    fn local_run_commands_propagate_accounts_jitter_to_spammer() {
        let mut args = test_args(true);
        args.relayer = true;
        args.spammer_accounts_jitter = 0.25;
        let commands = local_run_commands(
            Path::new("/tmp/configs"),
            &args,
            local_args(&args),
            &[],
            TEST_SIMPLEX_VERIFICATION_MATERIAL,
        );

        assert!(commands[3].contains("--accounts-jitter 0.25"));
    }

    #[test]
    fn local_run_commands_propagate_presigned_batches_to_spammer() {
        let mut args = test_args(true);
        args.relayer = true;
        args.spammer_presigned_batches = 32;
        let commands = local_run_commands(
            Path::new("/tmp/configs"),
            &args,
            local_args(&args),
            &[],
            TEST_SIMPLEX_VERIFICATION_MATERIAL,
        );

        assert!(commands[3].contains("--presigned-batches 32"));
    }

    #[test]
    fn local_run_commands_propagate_rayon_threads_to_spammer() {
        let mut args = test_args(true);
        args.relayer = true;
        args.spammer_rayon_threads = 6;
        let commands = local_run_commands(
            Path::new("/tmp/configs"),
            &args,
            local_args(&args),
            &[],
            TEST_SIMPLEX_VERIFICATION_MATERIAL,
        );

        assert!(commands[3].contains("--rayon-threads 6"));
    }

    #[test]
    fn local_run_commands_include_indexer_and_relayer_stack() {
        let mut args = test_args(false);
        args.indexer = true;
        args.relayer = true;
        let commands = local_run_commands(
            Path::new("/tmp/configs"),
            &args,
            local_args(&args),
            &[],
            TEST_SIMPLEX_VERIFICATION_MATERIAL,
        );

        assert_eq!(commands.len(), 8);
        assert!(commands[2].contains("secondary-0.yaml"));
        assert!(commands[3].contains("secondary-1.yaml"));
    }

    #[test]
    fn local_run_commands_do_not_sleep() {
        let mut args = test_args(true);
        args.relayer = true;

        let commands = local_run_commands(
            Path::new("/tmp/configs"),
            &args,
            local_args(&args),
            &[],
            TEST_SIMPLEX_VERIFICATION_MATERIAL,
        );

        assert!(
            commands.iter().all(|command| !command.contains("sleep ")),
            "local commands should start directly: {commands:?}"
        );
    }

    fn set_local_ports(args: &mut GenerateArgs, chain: u16, metadata: u16, qmdb: u16) {
        let GenerateTarget::Local(ref mut local) = args.target else {
            panic!("test_args must construct a Local target");
        };
        local.chain_indexer_port = chain;
        local.metadata_indexer_port = metadata;
        local.qmdb_indexer_port = qmdb;
    }

    #[test]
    fn local_run_commands_include_indexer_stack() {
        let mut args = test_args(false);
        args.indexer = true;
        args.relayer = true;
        set_local_ports(&mut args, 8090, 8091, 8092);

        let commands = local_run_commands(
            Path::new("/tmp/configs"),
            &args,
            local_args(&args),
            &[],
            TEST_SIMPLEX_VERIFICATION_MATERIAL,
        );

        // 2 validators + 1 indexer secondary + 1 relayer secondary + store/sql/qmdb + explorer.
        assert_eq!(commands.len(), 8);
        let indexer_cmd = commands
            .iter()
            .find(|c| c.contains("--bin chain-indexer"))
            .expect("chain-indexer command should be present");
        assert!(indexer_cmd.contains("--port 8090"));
        assert!(indexer_cmd.contains("--metrics-port 9094"));
        assert!(indexer_cmd.contains("--data-dir /tmp/configs/chain-indexer"));
    }

    #[test]
    fn local_indexer_and_spammer_metrics_ports_do_not_overlap() {
        let mut args = test_args(true);
        args.validators = 4;
        args.indexer = true;
        args.relayer = true;
        let commands = local_run_commands(
            Path::new("/tmp/configs"),
            &args,
            local_args(&args),
            &[],
            TEST_SIMPLEX_VERIFICATION_MATERIAL,
        );

        let indexer = commands
            .iter()
            .find(|command| command.contains("--bin chain-indexer"))
            .expect("chain-indexer command should be present");
        let spammer = commands
            .iter()
            .find(|command| command.contains("constantinople-spammer"))
            .expect("spammer command should be present");
        assert!(indexer.contains("--metrics-port 9097"));
        assert!(spammer.contains("--metrics-port 9096"));
    }

    #[test]
    fn large_full_stack_ports_are_globally_unique() {
        let mut args = test_args(true);
        args.validators = 13;
        args.indexer = true;
        args.relayer = true;

        let material = generate_local_cluster_material(args.validators, total_secondaries(&args));
        let validators = build_validators(
            &args,
            local_args(&args),
            Path::new("/tmp/configs"),
            &material,
        );
        let secondaries = build_secondaries(
            &args,
            local_args(&args),
            Path::new("/tmp/configs"),
            &material,
        );
        let commands = local_run_commands(
            Path::new("/tmp/configs"),
            &args,
            local_args(&args),
            &[],
            TEST_SIMPLEX_VERIFICATION_MATERIAL,
        );

        let nodes = validators.iter().chain(&secondaries).collect::<Vec<_>>();
        let mut seen = BTreeMap::new();
        for (index, node) in nodes.iter().enumerate() {
            assert_unique_port(
                &mut seen,
                node.config.listen_port,
                format!("node {index} p2p"),
            );
            assert_unique_port(
                &mut seen,
                node.config.http_port,
                format!("node {index} HTTP"),
            );
            assert_unique_port(
                &mut seen,
                node.config.metrics_port,
                format!("node {index} metrics"),
            );
        }

        let chain_indexer = commands
            .iter()
            .find(|command| command.contains("--bin chain-indexer"))
            .expect("chain-indexer command should be present");
        let metadata_indexer = commands
            .iter()
            .find(|command| command.contains("--bin metadata-indexer"))
            .expect("metadata-indexer command should be present");
        let qmdb_indexer = commands
            .iter()
            .find(|command| command.contains("--bin qmdb-indexer"))
            .expect("qmdb-indexer command should be present");
        let explorer = commands
            .iter()
            .find(|command| command.contains("npm --prefix explorer"))
            .expect("explorer command should be present");
        let spammer = commands
            .iter()
            .find(|command| command.contains("constantinople-spammer"))
            .expect("spammer command should be present");

        let chain_indexer_port = command_flag_port(chain_indexer, "--port");
        let chain_indexer_metrics_port = command_flag_port(chain_indexer, "--metrics-port");
        let metadata_indexer_port = command_flag_port(metadata_indexer, "--port");
        let qmdb_indexer_port = command_flag_port(qmdb_indexer, "--port");
        let explorer_port = command_flag_port(explorer, "--port");
        let spammer_metrics_port = command_flag_port(spammer, "--metrics-port");
        for (port, owner) in [
            (chain_indexer_port, "chain-indexer service"),
            (chain_indexer_metrics_port, "chain-indexer metrics"),
            (metadata_indexer_port, "metadata-indexer service"),
            (qmdb_indexer_port, "qmdb-indexer service"),
            (explorer_port, "explorer service"),
            (spammer_metrics_port, "spammer metrics"),
        ] {
            assert_unique_port(&mut seen, port, owner);
        }

        assert_eq!(chain_indexer_port, 8095);
        assert_eq!(metadata_indexer_port, 8096);
        assert_eq!(qmdb_indexer_port, 8097);
        assert_eq!(explorer_port, 5173);
        assert_eq!(spammer_metrics_port, 9105);
        assert_eq!(chain_indexer_metrics_port, 9106);
        assert_eq!(seen.len(), nodes.len() * 3 + 6);

        let indexer = secondaries[0]
            .config
            .indexer
            .as_ref()
            .expect("indexer secondary should have indexer config");
        assert_eq!(
            indexer.chain_indexer_url,
            format!("http://127.0.0.1:{chain_indexer_port}")
        );
        let relayer = secondaries[1]
            .config
            .relayer
            .as_ref()
            .expect("relayer secondary should have relayer config");
        let expected_relayer_urls = nodes
            .iter()
            .map(|node| format!("http://127.0.0.1:{}", node.config.http_port))
            .collect::<Vec<_>>();
        let actual_relayer_urls = relayer
            .leaders
            .iter()
            .map(|leader| leader.url.clone())
            .collect::<Vec<_>>();
        assert_eq!(actual_relayer_urls, expected_relayer_urls);
        assert!(spammer.contains("--relayer-url http://127.0.0.1:8094"));
        assert!(explorer.contains("VITE_SQL_URL=http://127.0.0.1:8096"));
        assert!(explorer.contains("VITE_QMDB_URL=http://127.0.0.1:8097"));
        assert!(explorer.contains("VITE_STORE_URL=http://127.0.0.1:8095"));
        assert!(explorer.contains("VITE_MEMPOOL_URL=http://127.0.0.1:8094"));
    }

    #[test]
    #[should_panic(expected = "assigned to both")]
    fn local_port_plan_rejects_overlapping_node_ranges() {
        let mut args = test_args(false);
        let GenerateTarget::Local(ref mut local) = args.target else {
            panic!("test_args must construct a Local target");
        };
        local.base_metrics_port = local.base_port;

        let _ = LocalPortPlan::new(&args, local_args(&args));
    }

    #[test]
    fn local_run_commands_include_metadata_indexer_when_indexer_enabled() {
        let mut args = test_args(false);
        args.indexer = true;
        set_local_ports(&mut args, 8090, 8091, 8092);

        let commands = local_run_commands(
            Path::new("/tmp/configs"),
            &args,
            local_args(&args),
            &[],
            TEST_SIMPLEX_VERIFICATION_MATERIAL,
        );

        let metadata_cmd = commands
            .iter()
            .find(|c| c.contains("--bin metadata-indexer"))
            .expect("metadata-indexer command should be present");
        // The metadata service reads from the store and serves on its own port.
        assert!(metadata_cmd.contains("--store-url http://127.0.0.1:8090"));
        assert!(metadata_cmd.contains("--port 8091"));
    }

    #[test]
    fn local_run_commands_include_qmdb_indexer_when_indexer_enabled() {
        let mut args = test_args(false);
        args.indexer = true;
        set_local_ports(&mut args, 8090, 8091, 8092);

        let commands = local_run_commands(
            Path::new("/tmp/configs"),
            &args,
            local_args(&args),
            &[],
            TEST_SIMPLEX_VERIFICATION_MATERIAL,
        );

        let qmdb_cmd = commands
            .iter()
            .find(|c| c.contains("--bin qmdb-indexer"))
            .expect("qmdb-indexer command should be present");
        assert!(qmdb_cmd.contains("--store-url http://127.0.0.1:8090"));
        assert!(qmdb_cmd.contains("--port 8092"));
    }

    #[test]
    fn local_run_commands_include_explorer_when_indexer_enabled() {
        let mut args = test_args(false);
        args.indexer = true;
        set_local_ports(&mut args, 18_090, 18_091, 18_092);

        let commands = local_run_commands(
            Path::new("/tmp/configs"),
            &args,
            local_args(&args),
            &[],
            TEST_SIMPLEX_VERIFICATION_MATERIAL,
        );

        let explorer_cmd = commands
            .iter()
            .find(|c| c.contains("npm --prefix explorer"))
            .expect("explorer dev server command should be present");
        assert!(explorer_cmd.contains("VITE_SQL_URL=http://127.0.0.1:18091"));
        assert!(explorer_cmd.contains("VITE_QMDB_URL=http://127.0.0.1:18092"));
        assert!(explorer_cmd.contains("VITE_STORE_URL=http://127.0.0.1:18090"));
        assert!(explorer_cmd.contains("VITE_SIMPLEX_VERIFICATION_MATERIAL=abcdef"));
        assert!(!explorer_cmd.contains("VITE_INDEXER_URL"));
        assert!(explorer_cmd.contains("run dev -- --port 5173"));
    }

    #[test]
    fn local_run_commands_omit_explorer_without_indexer() {
        let args = test_args(false);

        let commands = local_run_commands(
            Path::new("/tmp/configs"),
            &args,
            local_args(&args),
            &[],
            TEST_SIMPLEX_VERIFICATION_MATERIAL,
        );

        assert!(
            commands
                .iter()
                .all(|c| !c.contains("npm --prefix explorer")),
            "explorer must only launch when indexer is enabled: {commands:?}"
        );
    }

    #[test]
    fn secondary_yaml_gets_full_indexer() {
        let mut args = test_args(false);
        args.indexer = true;
        args.relayer = true;
        set_local_ports(&mut args, 8090, 8091, 8092);

        let material = generate_local_cluster_material(args.validators, total_secondaries(&args));
        let validators = build_validators(
            &args,
            local_args(&args),
            Path::new("/tmp/configs"),
            &material,
        );
        let secondaries = build_secondaries(
            &args,
            local_args(&args),
            Path::new("/tmp/configs"),
            &material,
        );

        // Primaries never get indexer wiring.
        assert!(validators.iter().all(|v| v.config.indexer.is_none()));
        assert!(
            validators
                .iter()
                .all(|v| v.config.eligible_peers.len() == 4)
        );
        assert!(
            secondaries
                .iter()
                .all(|v| v.config.eligible_peers.len() == 4)
        );

        // Secondaries point at the configured shared store URL.
        let indexer = secondaries[0]
            .config
            .indexer
            .as_ref()
            .expect("secondary should have indexer config");
        assert_eq!(indexer.upload_buffer, 64);
        let expected_url = "http://127.0.0.1:8090".to_string();
        assert_eq!(indexer.chain_indexer_url, expected_url);
        assert!(
            secondaries[1].config.indexer.is_none(),
            "relayer secondary should not have indexer config"
        );
        assert!(
            secondaries[1].config.relayer.is_some(),
            "last secondary should run relayer"
        );
    }

    #[test]
    fn validators_only_has_no_indexer_configs() {
        let args = test_args(false);

        let material = generate_local_cluster_material(args.validators, total_secondaries(&args));
        let validators = build_validators(
            &args,
            local_args(&args),
            Path::new("/tmp/configs"),
            &material,
        );

        assert!(validators.iter().all(|v| v.config.indexer.is_none()));
    }

    #[test]
    fn startup_mode_defaults_to_marshal_sync() {
        assert_eq!(StartupModeConfig::default(), StartupModeConfig::MarshalSync);
    }
}
