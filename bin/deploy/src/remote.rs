use crate::{
    BandwidthWeighting, CHAIN_INDEXER_BINARY_FILE, CHAIN_INDEXER_CONFIG_FILE,
    CHAIN_INDEXER_DATA_DIR, CHAIN_INDEXER_HOST, CHAIN_INDEXER_STORAGE_CLASS, ChainIndexerConfig,
    ClusterMaterial, DASHBOARD_FILE, DEPLOYER_CONFIG_FILE, EXOWARE_AVAILABILITY_ZONE_GROUP,
    EXPLORER_INDEXER_BINARY_FILE, EXPLORER_INDEXER_CONFIG_FILE, EXPLORER_INDEXER_HOST,
    ExplorerIndexerConfig, GenerateArgs, INDEXER_UPLOAD_BUDGET_BYTES, INDEXER_UPLOAD_MAX_IN_FLIGHT,
    IndexerConfig, RelayerConfig, RelayerLeaderConfig, RemoteArgs, SPAMMER_BINARY_FILE,
    SPAMMER_CONFIG_FILE, SPAMMER_HOST, STORAGE_CLASS, SecondaryRole, SpammerConfig,
    VALIDATOR_BINARY_FILE, ValidatorConfig, absolute_path, default_bootstrappers,
    ensure_output_dir_missing, generate_deployer_tag, generate_remote_cluster_material,
    indexer_enabled, ports::Ports, secondary_roles, secondary_runtime_threads, total_secondaries,
    validate_generate_args, write_simplex_verification_material, write_yaml_config,
};
use clap::ValueEnum as _;
use commonware_codec::Encode;
use commonware_deployer::aws::{self, METRICS_PORT};
use commonware_formatting::hex;
use std::{
    fs,
    path::{Path, PathBuf},
};
use tracing::{info, warn};

struct GeneratedValidator {
    public_key_hex: String,
    config_name: String,
    config_file: PathBuf,
    config: ValidatorConfig,
}

pub(super) fn generate(args: &GenerateArgs, remote: &RemoteArgs) -> Result<(), String> {
    validate_generate_args(args);
    validate_ports(args, remote)?;
    assert!(
        indexer_enabled(args) || remote.store_url.is_none(),
        "--store-url requires --indexer"
    );
    assert!(!remote.regions.is_empty(), "need at least one region");
    assert!(
        remote.regions.len() <= args.validators as usize,
        "need at least one validator per region"
    );
    let output_dir = absolute_path(&args.output_dir);
    ensure_output_dir_missing(&output_dir);

    let dashboard = absolute_path(&remote.dashboard);
    let material = generate_remote_cluster_material(args.validators, total_secondaries(args));
    let validators = build_validators(args, remote, &output_dir, &material);
    let secondaries = build_secondaries(args, remote, &output_dir, &material);

    fs::create_dir_all(&output_dir).expect("failed to create output directory");
    for validator in &validators {
        write_yaml_config(&validator.config_file, &validator.config);
    }
    for secondary in &secondaries {
        write_yaml_config(&secondary.config_file, &secondary.config);
    }
    if let Some(config) = chain_indexer_config(args, remote) {
        write_yaml_config(&output_dir.join(CHAIN_INDEXER_CONFIG_FILE), &config);
    }
    if let Some(config) = explorer_indexer_config(args, remote, &material) {
        write_yaml_config(&output_dir.join(EXPLORER_INDEXER_CONFIG_FILE), &config);
    }
    if args.spammer {
        let spammer_config = remote_spammer_config(args, remote, &material);
        write_yaml_config(&output_dir.join(SPAMMER_CONFIG_FILE), &spammer_config);
    }
    write_simplex_verification_material(&output_dir, &material);

    let copied_dashboard = output_dir.join(DASHBOARD_FILE);
    fs::copy(&dashboard, &copied_dashboard).expect("failed to copy dashboard");
    let deployer_config = build_deployer_config(
        args,
        remote,
        VALIDATOR_BINARY_FILE,
        DASHBOARD_FILE,
        &validators,
        &secondaries,
    );
    let config_path = output_dir.join(DEPLOYER_CONFIG_FILE);
    let raw = deployer_config_yaml(&deployer_config, remote, &validators, &secondaries);
    fs::write(&config_path, raw).expect("failed to write deployer config");

    info!(
        output_dir = %output_dir.display(),
        validators = args.validators,
        indexer = args.indexer,
        relayer = args.relayer,
        "generated remote deployment bundle"
    );
    if indexer_enabled(args) {
        info!(
            store_url = %store_url(remote),
            indexer_url = ?remote.indexer_url,
            explorer_indexer_port = ?local_explorer_indexer(args, remote).then_some(remote.explorer_indexer_port),
            "configured shared remote indexer services"
        );
    }
    if local_explorer_indexer(args, remote)
        && !remote.http_cidrs.iter().any(|cidr| cidr == "0.0.0.0/0")
    {
        warn!(
            explorer_host = EXPLORER_INDEXER_HOST,
            admission_url = %admission_url(args, remote, &material),
            http_port = remote.http_port,
            "before submitting transactions, allow the explorer host's public IP to reach the admission HTTP port; operator access alone does not allow this hop. See bin/deploy/README.md: Peer HTTP access after creation. No ingress was added"
        );
    }
    let binaries = expected_binary_files(args, remote)
        .into_iter()
        .map(|binary| output_dir.join(binary).display().to_string())
        .collect::<Vec<_>>();
    info!(
        ?binaries,
        "build deployment binaries into the output directory before creating the remote deployment"
    );
    info!(
        command = %format!("cd {} && deployer aws create --config {}", output_dir.display(), DEPLOYER_CONFIG_FILE),
        "create remote deployment after building binaries"
    );

    Ok(())
}

fn validate_ports(args: &GenerateArgs, remote: &RemoteArgs) -> Result<(), String> {
    // Ingress rules apply to every binary host. Reusing service ports can expose
    // restricted listeners on other hosts or produce duplicate ingress rules.
    let mut ports = Ports::default();
    ports.insert("SSH", 22)?;
    ports.insert("Promtail", 9080)?;
    ports.insert("application metrics", METRICS_PORT)?;
    ports.insert("Node Exporter", 9100)?;
    ports.insert("validator P2P", remote.listen_port)?;
    ports.insert("validator HTTP", remote.http_port)?;
    if indexer_enabled(args) {
        ports.insert("chain-indexer", remote.chain_indexer_port)?;
        ports.insert("explorer-indexer", remote.explorer_indexer_port)?;
    }

    Ok(())
}

fn build_validators(
    args: &GenerateArgs,
    remote: &RemoteArgs,
    output_dir: &Path,
    material: &ClusterMaterial,
) -> Vec<GeneratedValidator> {
    let mut validators = Vec::with_capacity(args.validators as usize);
    let bootstrappers = default_bootstrappers(&material.public_keys);
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

        let config = ValidatorConfig {
            private_key: hex(&material.signers[validator_index].encode()),
            dkg_output: hex(&material.dkg_output.encode()),
            dkg_share: hex(&share.encode()),
            startup: args.startup,
            listen_port: remote.listen_port,
            genesis_leader: material.genesis_leader.clone(),
            partition_prefix: format!("validator-{index}"),
            num_validators: args.validators,
            primary_validators: primary_validators.clone(),
            secondary_validators: secondary_validators.clone(),
            log_level: args.log_level.clone(),
            worker_threads: args.worker_threads,
            rayon_threads: args.rayon_threads,
            http_port: remote.http_port,
            metrics_port: METRICS_PORT,
            max_propose_bytes: args.max_propose_bytes,
            leader_term_length: args.leader_term_length,
            leader_optimistic_views: args.leader_optimistic_views,
            mempool_propose_priority: args.mempool_propose_priority,
            propose_skip_final_refill: args.propose_skip_final_refill,
            max_pool_bytes: args.max_pool_bytes,
            state_page_cache_bytes: args.state_page_cache_bytes,
            history_page_cache_bytes: args.history_page_cache_bytes,
            public_key_cache_size: args.public_key_cache_size,
            traces: remote.traces,
            bootstrappers: bootstrappers.clone(),
            indexer: None,
            relayer: None,
        };

        let config_name = format!("{public_key_hex}.yaml");

        validators.push(GeneratedValidator {
            public_key_hex,
            config_name: config_name.clone(),
            config_file: output_dir.join(config_name),
            config,
        });
    }

    validators
}

fn build_secondaries(
    args: &GenerateArgs,
    remote: &RemoteArgs,
    output_dir: &Path,
    material: &ClusterMaterial,
) -> Vec<GeneratedValidator> {
    let roles = secondary_roles(args);
    let mut secondaries = Vec::with_capacity(roles.len());
    let bootstrappers = default_bootstrappers(&material.public_keys);
    let primary_validators = material.primary_hex();
    let secondary_validators = material.secondary_hex();
    for (secondary_index, role) in roles.into_iter().enumerate() {
        let index = secondary_index as u32;
        let public_key = &material.secondary_public_keys[secondary_index];
        let public_key_hex = hex(&public_key.encode());

        let (worker_threads, rayon_threads) = secondary_runtime_threads(args, role);
        let config = ValidatorConfig {
            private_key: hex(&material.secondary_signers[secondary_index].encode()),
            dkg_output: hex(&material.dkg_output.encode()),
            dkg_share: String::new(),
            startup: args.startup,
            listen_port: remote.listen_port,
            genesis_leader: material.genesis_leader.clone(),
            partition_prefix: format!("secondary-{index}"),
            num_validators: args.validators,
            primary_validators: primary_validators.clone(),
            secondary_validators: secondary_validators.clone(),
            log_level: args.log_level.clone(),
            worker_threads,
            rayon_threads,
            http_port: remote.http_port,
            metrics_port: METRICS_PORT,
            max_propose_bytes: args.max_propose_bytes,
            leader_term_length: args.leader_term_length,
            leader_optimistic_views: args.leader_optimistic_views,
            mempool_propose_priority: args.mempool_propose_priority,
            propose_skip_final_refill: args.propose_skip_final_refill,
            max_pool_bytes: args.max_pool_bytes,
            state_page_cache_bytes: args.state_page_cache_bytes,
            history_page_cache_bytes: args.history_page_cache_bytes,
            public_key_cache_size: args.public_key_cache_size,
            traces: remote.traces,
            bootstrappers: bootstrappers.clone(),
            indexer: matches!(role, SecondaryRole::Indexer)
                .then(|| remote_indexer_config(args, remote)),
            relayer: matches!(role, SecondaryRole::Relayer)
                .then(|| remote_relayer_config(remote, material)),
        };

        let config_name = format!("{public_key_hex}.yaml");

        secondaries.push(GeneratedValidator {
            public_key_hex,
            config_name: config_name.clone(),
            config_file: output_dir.join(config_name),
            config,
        });
    }

    secondaries
}

fn store_url(remote: &RemoteArgs) -> String {
    remote
        .store_url
        .clone()
        .unwrap_or_else(|| format!("http://{CHAIN_INDEXER_HOST}:{}", remote.chain_indexer_port))
}

const fn local_chain_indexer(args: &GenerateArgs, remote: &RemoteArgs) -> bool {
    indexer_enabled(args) && remote.store_url.is_none()
}

const fn local_explorer_indexer(args: &GenerateArgs, remote: &RemoteArgs) -> bool {
    indexer_enabled(args) && remote.indexer_url.is_none()
}

fn expected_binary_files(args: &GenerateArgs, remote: &RemoteArgs) -> Vec<&'static str> {
    let mut binaries = vec![VALIDATOR_BINARY_FILE];
    if local_chain_indexer(args, remote) {
        binaries.push(CHAIN_INDEXER_BINARY_FILE);
    }

    if local_explorer_indexer(args, remote) {
        binaries.push(EXPLORER_INDEXER_BINARY_FILE);
    }
    if args.spammer {
        binaries.push(SPAMMER_BINARY_FILE);
    }
    binaries
}

fn remote_indexer_config(args: &GenerateArgs, remote: &RemoteArgs) -> IndexerConfig {
    IndexerConfig {
        store_url: store_url(remote),
        api_key: remote.store_api_key.clone(),
        publisher_rayon_threads: args.indexer_publisher_rayon_threads,
        upload_max_in_flight: INDEXER_UPLOAD_MAX_IN_FLIGHT,
        upload_budget_bytes: INDEXER_UPLOAD_BUDGET_BYTES,
    }
}

fn remote_relayer_config(remote: &RemoteArgs, material: &ClusterMaterial) -> RelayerConfig {
    let leaders = material
        .primary_hex()
        .into_iter()
        .map(|public_key| RelayerLeaderConfig {
            url: format!("http://{public_key}:{}", remote.http_port),
            public_key,
        })
        .collect();

    RelayerConfig { leaders }
}

fn remote_spammer_config(
    args: &GenerateArgs,
    remote: &RemoteArgs,
    material: &ClusterMaterial,
) -> SpammerConfig {
    SpammerConfig {
        accounts: args.spammer_accounts,
        value: args.spammer_value,
        seed_offset: args.spammer_seed_offset,
        rayon_threads: args.spammer_rayon_threads,
        http_port: remote.http_port,
        relayer_url: admission_url(args, remote, material),
        relayer_submitters: args.spammer_submitters.unwrap_or(args.validators as usize),
        presigned_batches: args.spammer_presigned_batches,
        primary_validators: material.primary_hex(),
        accounts_jitter: args.spammer_accounts_jitter,
    }
}

fn admission_url(args: &GenerateArgs, remote: &RemoteArgs, material: &ClusterMaterial) -> String {
    let host = if args.relayer {
        let relayer_index = usize::from(args.indexer);
        hex(&material.secondary_public_keys[relayer_index].encode())
    } else {
        material.primary_hex()[0].clone()
    };
    format!("http://{host}:{}", remote.http_port)
}

fn chain_indexer_config(args: &GenerateArgs, remote: &RemoteArgs) -> Option<ChainIndexerConfig> {
    local_chain_indexer(args, remote).then(|| ChainIndexerConfig {
        port: remote.chain_indexer_port,
        data_dir: PathBuf::from(CHAIN_INDEXER_DATA_DIR),
        db_parallelism: remote.chain_indexer_db_parallelism,
    })
}

fn explorer_indexer_config(
    args: &GenerateArgs,
    remote: &RemoteArgs,
    material: &ClusterMaterial,
) -> Option<ExplorerIndexerConfig> {
    local_explorer_indexer(args, remote).then(|| ExplorerIndexerConfig {
        metrics_port: Some(METRICS_PORT),
        port: remote.explorer_indexer_port,
        store_url: store_url(remote),
        api_key: remote.adapter_store_api_key.clone(),
        relayer_url: Some(admission_url(args, remote, material)),
    })
}

fn build_deployer_config(
    args: &GenerateArgs,
    remote: &RemoteArgs,
    validator_binary: &str,
    dashboard: &str,
    validators: &[GeneratedValidator],
    secondaries: &[GeneratedValidator],
) -> aws::Config {
    let regions = &remote.regions;
    let indexer_enabled = indexer_enabled(args);
    let shared_indexer_region = regions[0].clone();
    let mut instances: Vec<aws::InstanceConfig> = validators
        .iter()
        .enumerate()
        .map(|(index, validator)| aws::InstanceConfig {
            name: validator.public_key_hex.clone(),
            region: regions[index % regions.len()].clone(),
            availability_zone_group: None,
            instance_type: remote.instance_type.clone(),
            storage_size: remote.storage_size,
            storage_class: STORAGE_CLASS.to_string(),
            storage_iops: remote.storage_iops,
            storage_throughput: remote.storage_throughput,
            binary: validator_binary.to_string(),
            config: validator.config_name.clone(),
            profiling: remote.profiling,
        })
        .collect();

    for (index, secondary) in secondaries.iter().enumerate() {
        let region = if indexer_enabled {
            shared_indexer_region.clone()
        } else {
            regions[index % regions.len()].clone()
        };

        instances.push(aws::InstanceConfig {
            name: secondary.public_key_hex.clone(),
            region,
            availability_zone_group: (secondary.config.indexer.is_some()
                && local_chain_indexer(args, remote))
            .then(|| EXOWARE_AVAILABILITY_ZONE_GROUP.to_string()),
            instance_type: secondary
                .config
                .indexer
                .as_ref()
                .and(remote.indexer_instance_type.clone())
                .unwrap_or_else(|| remote.instance_type.clone()),
            storage_size: remote.storage_size,
            storage_class: STORAGE_CLASS.to_string(),
            storage_iops: remote.storage_iops,
            storage_throughput: remote.storage_throughput,
            binary: validator_binary.to_string(),
            config: secondary.config_name.clone(),
            profiling: remote.profiling,
        });
    }

    if local_chain_indexer(args, remote) {
        instances.push(aws::InstanceConfig {
            name: CHAIN_INDEXER_HOST.to_string(),
            region: shared_indexer_region.clone(),
            availability_zone_group: Some(EXOWARE_AVAILABILITY_ZONE_GROUP.to_string()),
            instance_type: remote.chain_indexer_instance_type.clone(),
            storage_size: remote.chain_indexer_storage_size,
            storage_class: CHAIN_INDEXER_STORAGE_CLASS.to_string(),
            storage_iops: Some(remote.chain_indexer_storage_iops),
            storage_throughput: None,
            binary: CHAIN_INDEXER_BINARY_FILE.to_string(),
            config: CHAIN_INDEXER_CONFIG_FILE.to_string(),
            profiling: false,
        });
    }

    if local_explorer_indexer(args, remote) {
        instances.push(aws::InstanceConfig {
            name: EXPLORER_INDEXER_HOST.to_string(),
            region: shared_indexer_region,
            availability_zone_group: Some(EXOWARE_AVAILABILITY_ZONE_GROUP.to_string()),
            instance_type: remote.instance_type.clone(),
            storage_size: remote.storage_size,
            storage_class: STORAGE_CLASS.to_string(),
            storage_iops: None,
            storage_throughput: None,
            binary: EXPLORER_INDEXER_BINARY_FILE.to_string(),
            config: EXPLORER_INDEXER_CONFIG_FILE.to_string(),
            profiling: false,
        });
    }

    if args.spammer {
        instances.push(aws::InstanceConfig {
            name: SPAMMER_HOST.to_string(),
            region: regions[0].clone(),
            availability_zone_group: None,
            instance_type: remote
                .spammer_instance_type
                .clone()
                .unwrap_or_else(|| remote.instance_type.clone()),
            storage_size: remote.spammer_storage_size,
            storage_class: STORAGE_CLASS.to_string(),
            storage_iops: None,
            storage_throughput: None,
            binary: SPAMMER_BINARY_FILE.to_string(),
            config: SPAMMER_CONFIG_FILE.to_string(),
            profiling: false,
        });
    }

    aws::Config {
        tag: generate_deployer_tag(),
        monitoring: aws::MonitoringConfig {
            instance_type: remote.monitoring_instance_type.clone(),
            storage_size: remote.monitoring_storage_size,
            storage_class: STORAGE_CLASS.to_string(),
            storage_iops: None,
            storage_throughput: None,
            dashboard: dashboard.to_string(),
        },
        instances,
        ports: port_configs(args, remote),
    }
}

/// Serializes the deployer config, adding `bandwidth_weighting` to the primary
/// validators, the relayer, and the spammer, which carry consensus and
/// transaction traffic.
///
/// The pinned deployer crate has no field for the key, so it is added to the
/// serialized config.
fn deployer_config_yaml(
    config: &aws::Config,
    remote: &RemoteArgs,
    validators: &[GeneratedValidator],
    secondaries: &[GeneratedValidator],
) -> String {
    let mut yaml = serde_yaml::to_value(config).expect("failed to serialize deployer config");
    if remote.bandwidth_weighting != BandwidthWeighting::Default {
        let weighting = remote
            .bandwidth_weighting
            .to_possible_value()
            .expect("every bandwidth weighting has a value");
        let weighted = validators
            .iter()
            .chain(
                secondaries
                    .iter()
                    .filter(|secondary| secondary.config.relayer.is_some()),
            )
            .map(|generated| generated.public_key_hex.as_str())
            .chain([SPAMMER_HOST])
            .collect::<Vec<_>>();
        for instance in yaml["instances"]
            .as_sequence_mut()
            .expect("deployer config lists instances")
        {
            if instance["name"]
                .as_str()
                .is_some_and(|name| weighted.contains(&name))
            {
                instance
                    .as_mapping_mut()
                    .expect("deployer instance is a mapping")
                    .insert("bandwidth_weighting".into(), weighting.get_name().into());
            }
        }
    }
    serde_yaml::to_string(&yaml).expect("failed to serialize deployer config")
}

fn port_configs(args: &GenerateArgs, remote: &RemoteArgs) -> Vec<aws::PortConfig> {
    let mut ports = vec![aws::PortConfig {
        protocol: "tcp".to_string(),
        port: remote.listen_port,
        cidr: "0.0.0.0/0".to_string(),
    }];

    if local_chain_indexer(args, remote) {
        ports.push(aws::PortConfig {
            protocol: "tcp".to_string(),
            port: remote.chain_indexer_port,
            cidr: "0.0.0.0/0".to_string(),
        });
    }

    if local_explorer_indexer(args, remote) {
        ports.push(aws::PortConfig {
            protocol: "tcp".to_string(),
            port: remote.explorer_indexer_port,
            cidr: "0.0.0.0/0".to_string(),
        });
    }

    for cidr in &remote.http_cidrs {
        ports.push(aws::PortConfig {
            protocol: "tcp".to_string(),
            port: remote.http_port,
            cidr: cidr.clone(),
        });
    }

    ports
}

#[cfg(test)]
mod tests {
    use super::{
        build_deployer_config, build_secondaries, deployer_config_yaml, expected_binary_files,
        explorer_indexer_config, port_configs, remote_spammer_config, validate_ports,
    };
    use crate::{
        BandwidthWeighting, CHAIN_INDEXER_BINARY_FILE, CHAIN_INDEXER_STORAGE_CLASS,
        DEFAULT_CHAIN_INDEXER_INSTANCE_TYPE, DEFAULT_CHAIN_INDEXER_STORAGE_IOPS,
        DEFAULT_CHAIN_INDEXER_STORAGE_SIZE, EXOWARE_AVAILABILITY_ZONE_GROUP,
        EXPLORER_INDEXER_BINARY_FILE, GenerateArgs, GenerateTarget, LocalArgs, RemoteArgs,
        SPAMMER_HOST, STORAGE_CLASS, StartupModeConfig, VALIDATOR_BINARY_FILE, ValidatorConfig,
        default_history_page_cache_bytes, default_max_pool_bytes, default_max_propose_bytes,
        default_public_key_cache_size, default_publisher_rayon_threads,
        default_state_page_cache_bytes, generate_local_cluster_material, total_secondaries,
        validate_generate_args,
    };
    use commonware_codec::Encode;
    use commonware_formatting::hex;
    use std::path::{Path, PathBuf};

    fn generate_args() -> GenerateArgs {
        GenerateArgs {
            validators: 3,
            indexer: false,
            relayer: false,
            output_dir: PathBuf::from("artifacts"),
            log_level: "info".to_string(),
            worker_threads: 2,
            rayon_threads: 2,
            indexer_worker_threads: None,
            indexer_rayon_threads: None,
            indexer_publisher_rayon_threads: default_publisher_rayon_threads(),
            public_key_cache_size: default_public_key_cache_size(),
            max_propose_bytes: default_max_propose_bytes(),
            max_pool_bytes: default_max_pool_bytes(),
            state_page_cache_bytes: default_state_page_cache_bytes(),
            history_page_cache_bytes: default_history_page_cache_bytes(),
            startup: StartupModeConfig::MarshalSync,
            leader_term_length: commonware_utils::NZU32!(1),
            leader_optimistic_views: 16,
            mempool_propose_priority: false,
            propose_skip_final_refill: false,
            spammer: false,
            spammer_accounts: 10,
            spammer_value: 1,
            spammer_seed_offset: None,
            spammer_rayon_threads: crate::DEFAULT_SPAMMER_RAYON_THREADS,
            spammer_accounts_jitter: 0.0,
            spammer_submitters: None,
            spammer_presigned_batches: crate::DEFAULT_SPAMMER_PRESIGNED_BATCHES,
            target: GenerateTarget::Local(LocalArgs {
                base_port: 9000,
                base_http_port: 8080,
                base_metrics_port: 9090,
                chain_indexer_port: 8090,
                chain_indexer_db_parallelism: None,
                explorer_indexer_port: 8092,
            }),
        }
    }

    fn remote_args() -> RemoteArgs {
        RemoteArgs {
            regions: vec!["us-east-1".to_string(), "us-west-2".to_string()],
            instance_type: "c8g.large".to_string(),
            indexer_instance_type: Some("c8a.8xlarge".to_string()),
            storage_size: 25,
            storage_iops: None,
            storage_throughput: None,
            store_url: None,
            indexer_url: None,
            store_api_key: None,
            adapter_store_api_key: None,
            chain_indexer_instance_type: DEFAULT_CHAIN_INDEXER_INSTANCE_TYPE.to_string(),
            chain_indexer_storage_size: DEFAULT_CHAIN_INDEXER_STORAGE_SIZE,
            chain_indexer_storage_iops: DEFAULT_CHAIN_INDEXER_STORAGE_IOPS,
            monitoring_instance_type: "c8g.2xlarge".to_string(),
            monitoring_storage_size: 100,
            dashboard: PathBuf::from("dashboard.json"),
            listen_port: 9000,
            http_port: 8080,
            http_cidrs: vec!["198.51.100.4/32".to_string()],
            chain_indexer_port: 8090,
            chain_indexer_db_parallelism: None,
            explorer_indexer_port: 8092,
            profiling: true,
            traces: 0.0,
            spammer_instance_type: None,
            spammer_storage_size: 25,
            bandwidth_weighting: BandwidthWeighting::Default,
        }
    }

    #[test]
    fn remote_ports_accept_default_configuration() {
        let mut args = generate_args();
        let remote = remote_args();
        validate_ports(&args, &remote).unwrap();

        args.indexer = true;
        args.relayer = true;
        args.spammer = true;
        validate_ports(&args, &remote).unwrap();
    }

    #[test]
    fn remote_ports_reject_reserved_and_zero_ports() {
        let mut args = generate_args();
        args.indexer = true;
        for port in [0, 22, 9080, super::METRICS_PORT, 9100] {
            for service in 0..4 {
                let mut remote = remote_args();
                let ports = [
                    &mut remote.listen_port,
                    &mut remote.http_port,
                    &mut remote.chain_indexer_port,
                    &mut remote.explorer_indexer_port,
                ];
                *ports[service] = port;
                let error = validate_ports(&args, &remote)
                    .expect_err(&format!("service {service} must reject port {port}"));
                let expected = if port == 0 {
                    "nonzero".to_string()
                } else {
                    format!("port {port} collision")
                };
                assert!(error.contains(&expected), "{error}");
            }
        }
    }

    #[test]
    fn remote_ports_reject_overlapping_ingress_roles() {
        let mut args = generate_args();
        args.indexer = true;
        for first in 0..4 {
            for second in first + 1..4 {
                let mut remote = remote_args();
                remote.http_cidrs.clear();
                let ports = [
                    &mut remote.listen_port,
                    &mut remote.http_port,
                    &mut remote.chain_indexer_port,
                    &mut remote.explorer_indexer_port,
                ];
                *ports[second] = *ports[first];
                let error = validate_ports(&args, &remote).expect_err(&format!(
                    "services {first} and {second} must use distinct ports"
                ));
                assert!(error.contains("collision"), "{error}");
            }
        }
    }

    #[test]
    fn remote_ports_ignore_disabled_indexer_services() {
        let args = generate_args();
        let mut remote = remote_args();
        remote.chain_indexer_port = super::METRICS_PORT;
        remote.explorer_indexer_port = 0;
        validate_ports(&args, &remote).unwrap();
    }

    #[test]
    fn remote_ports_allow_separate_monitoring_and_binary_hosts() {
        let mut args = generate_args();
        args.validators = 100;
        args.indexer = true;
        args.relayer = true;
        args.spammer = true;
        let mut remote = remote_args();
        remote.listen_port = 3000;
        remote.chain_indexer_port = 3100;
        remote.explorer_indexer_port = 4318;
        validate_ports(&args, &remote).unwrap();
    }

    fn validator(index: u32) -> super::GeneratedValidator {
        super::GeneratedValidator {
            public_key_hex: format!("validator-{index}"),
            config_name: format!("validator-{index}.yaml"),
            config_file: PathBuf::from(format!("/tmp/validator-{index}.yaml")),
            config: ValidatorConfig {
                private_key: "private".to_string(),
                dkg_output: "output".to_string(),
                dkg_share: "share".to_string(),
                startup: StartupModeConfig::MarshalSync,
                listen_port: 9000,
                genesis_leader: "leader".to_string(),
                partition_prefix: format!("validator-{index}"),
                num_validators: 3,
                primary_validators: Vec::new(),
                secondary_validators: Vec::new(),
                log_level: "info".to_string(),
                worker_threads: 2,
                rayon_threads: 2,
                http_port: 8080,
                metrics_port: 9090,
                max_propose_bytes: default_max_propose_bytes(),
                leader_term_length: commonware_utils::NZU32!(1),
                leader_optimistic_views: 16,
                mempool_propose_priority: false,
                propose_skip_final_refill: false,
                max_pool_bytes: default_max_pool_bytes(),
                state_page_cache_bytes: default_state_page_cache_bytes(),
                history_page_cache_bytes: default_history_page_cache_bytes(),
                public_key_cache_size: default_public_key_cache_size(),
                traces: 0.0,
                bootstrappers: Vec::new(),
                indexer: None,
                relayer: None,
            },
        }
    }

    #[test]
    fn remote_deployer_config_only_includes_validators() {
        let args = generate_args();
        let remote = remote_args();
        let validators = vec![validator(0), validator(1), validator(2)];
        let config = build_deployer_config(
            &args,
            &remote,
            VALIDATOR_BINARY_FILE,
            "dashboard.json",
            &validators,
            &[],
        );

        assert!(!config.tag.is_empty());
        assert_eq!(config.instances.len(), args.validators as usize);
        assert_eq!(config.instances[0].region, "us-east-1");
        assert_eq!(config.instances[1].region, "us-west-2");
        assert_eq!(config.instances[2].region, "us-east-1");
        assert_eq!(config.instances[0].storage_class, STORAGE_CLASS);
        assert_eq!(config.instances[0].availability_zone_group, None);
        assert_eq!(config.instances[0].storage_iops, None);
        assert_eq!(config.instances[0].binary, VALIDATOR_BINARY_FILE);
        assert_eq!(config.instances[0].config, "validator-0.yaml");
        assert_eq!(config.monitoring.storage_iops, None);
        assert_eq!(config.monitoring.dashboard, "dashboard.json");
        assert_eq!(config.ports[0].port, 9000);
        assert_eq!(config.ports[1].port, 8080);
        assert_eq!(config.ports[1].cidr, "198.51.100.4/32");
    }

    #[test]
    fn remote_deployer_config_runs_relayer_as_secondary() {
        let mut args = generate_args();
        args.relayer = true;
        let remote = remote_args();
        let validators = vec![validator(0), validator(1), validator(2)];
        let material = generate_local_cluster_material(args.validators, total_secondaries(&args));
        let secondaries = build_secondaries(&args, &remote, Path::new("/tmp"), &material);
        let config = build_deployer_config(
            &args,
            &remote,
            VALIDATOR_BINARY_FILE,
            "dashboard.json",
            &validators,
            &secondaries,
        );

        assert_eq!(config.instances.len(), args.validators as usize + 1);
        let relayer = secondaries
            .iter()
            .find(|secondary| secondary.config.relayer.is_some())
            .expect("relayer secondary should be present");
        let instance = config
            .instances
            .iter()
            .find(|instance| instance.name == relayer.public_key_hex)
            .expect("relayer secondary instance should be present");
        assert_eq!(instance.binary, VALIDATOR_BINARY_FILE);
        assert_eq!(instance.config, relayer.config_name);
    }

    #[test]
    fn remote_spammer_config_propagates_deterministic_seed_offset() {
        let mut args = generate_args();
        args.spammer = true;
        args.relayer = true;
        args.spammer_seed_offset = Some(2000);
        let remote = remote_args();
        let material = generate_local_cluster_material(args.validators, total_secondaries(&args));

        let config = remote_spammer_config(&args, &remote, &material);
        let yaml = serde_yaml::to_value(&config).expect("spammer config should serialize");

        assert_eq!(config.seed_offset, Some(2000));
        assert_eq!(yaml["seed_offset"].as_u64(), Some(2000));
    }

    #[test]
    fn remote_spammer_requires_relayer() {
        let mut args = generate_args();
        args.spammer = true;

        let panic = std::panic::catch_unwind(|| validate_generate_args(&args))
            .expect_err("spammer without relayer should fail validation");
        let message = panic
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
            .expect("panic should carry validation message");
        assert!(message.contains("--spammer requires --relayer"));
    }

    #[test]
    fn remote_spammer_config_uses_relayer() {
        let mut args = generate_args();
        args.spammer = true;
        args.relayer = true;
        let remote = remote_args();
        let relayed_material =
            generate_local_cluster_material(args.validators, total_secondaries(&args));
        let relayed = remote_spammer_config(&args, &remote, &relayed_material);
        let relayer_key = hex(&relayed_material.secondary_public_keys[0].encode());

        assert_eq!(relayed.relayer_url, format!("http://{relayer_key}:8080"));
        assert_eq!(relayed.relayer_submitters, args.validators as usize);
        assert!(relayed.seed_offset.is_none());
        let yaml = serde_yaml::to_string(&relayed).expect("spammer config should serialize");
        assert!(!yaml.contains("seed_offset"));
        assert_eq!(relayed.rayon_threads, crate::DEFAULT_SPAMMER_RAYON_THREADS);
        assert_eq!(
            relayed.presigned_batches,
            crate::DEFAULT_SPAMMER_PRESIGNED_BATCHES
        );
    }

    #[test]
    fn remote_spammer_submitters_override_validator_count() {
        let mut args = generate_args();
        args.spammer = true;
        args.relayer = true;
        args.spammer_submitters = Some(50);
        let remote = remote_args();
        let material = generate_local_cluster_material(args.validators, total_secondaries(&args));

        let config = remote_spammer_config(&args, &remote, &material);

        assert_eq!(config.relayer_submitters, 50);
    }

    #[test]
    fn remote_deployer_config_includes_secondaries_and_indexers() {
        let mut args = generate_args();
        args.indexer = true;
        args.relayer = true;
        let remote = remote_args();
        let validators = vec![validator(0), validator(1), validator(2)];
        let mut indexer_secondary_config = validator(0).config;
        indexer_secondary_config.indexer = Some(super::remote_indexer_config(&args, &remote));
        let secondaries = vec![
            super::GeneratedValidator {
                public_key_hex: "secondary-0".to_string(),
                config_name: "secondary-0.yaml".to_string(),
                config_file: PathBuf::from("/tmp/secondary-0.yaml"),
                config: indexer_secondary_config,
            },
            super::GeneratedValidator {
                public_key_hex: "secondary-1".to_string(),
                config_name: "secondary-1.yaml".to_string(),
                config_file: PathBuf::from("/tmp/secondary-1.yaml"),
                config: validator(0).config,
            },
        ];
        let config = build_deployer_config(
            &args,
            &remote,
            VALIDATOR_BINARY_FILE,
            "dashboard.json",
            &validators,
            &secondaries,
        );

        // 3 primaries + 2 secondaries + shared Store and explorer indexer.
        assert_eq!(config.instances.len(), 7);
        assert_eq!(config.instances[3].name, "secondary-0");
        assert_eq!(config.instances[3].binary, VALIDATOR_BINARY_FILE);
        assert_eq!(config.instances[3].config, "secondary-0.yaml");
        assert_eq!(config.instances[3].instance_type, "c8a.8xlarge");
        assert_eq!(config.instances[4].name, "secondary-1");
        assert_eq!(config.instances[4].instance_type, "c8g.large");
    }

    #[test]
    fn remote_ports_only_open_http_for_explicit_cidrs() {
        let mut remote = remote_args();
        remote.http_cidrs.clear();

        let ports = port_configs(&generate_args(), &remote);

        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 9000);
    }

    #[test]
    fn leader_options_reach_every_remote_config() {
        let mut args = generate_args();
        args.indexer = true;
        args.relayer = true;
        crate::tests::set_stable_leader_args(&mut args);
        let remote = remote_args();

        let material = generate_local_cluster_material(args.validators, total_secondaries(&args));
        let output_dir = Path::new("/tmp/configs");
        let validators = super::build_validators(&args, &remote, output_dir, &material);
        let secondaries = build_secondaries(&args, &remote, output_dir, &material);

        assert_eq!(secondaries.len(), 2);
        for generated in validators.iter().chain(&secondaries) {
            crate::tests::assert_stable_leader_config(&generated.config);
        }
    }

    #[test]
    fn bandwidth_weighting_applies_only_to_traffic_instances() {
        let mut args = generate_args();
        args.indexer = true;
        args.relayer = true;
        args.spammer = true;
        let mut remote = remote_args();
        let material = generate_local_cluster_material(args.validators, total_secondaries(&args));
        let output_dir = Path::new("/tmp/configs");
        let validators = super::build_validators(&args, &remote, output_dir, &material);
        let secondaries = build_secondaries(&args, &remote, output_dir, &material);
        let config = build_deployer_config(
            &args,
            &remote,
            VALIDATOR_BINARY_FILE,
            "dashboard.json",
            &validators,
            &secondaries,
        );

        let raw = deployer_config_yaml(&config, &remote, &validators, &secondaries);
        assert_eq!(raw, serde_yaml::to_string(&config).unwrap());
        assert!(!raw.contains("bandwidth_weighting"));

        let relayer = secondaries
            .iter()
            .find(|secondary| secondary.config.relayer.is_some())
            .expect("relayer secondary should be present");
        let mut expected = validators
            .iter()
            .map(|validator| validator.public_key_hex.as_str())
            .collect::<Vec<_>>();
        expected.extend([relayer.public_key_hex.as_str(), SPAMMER_HOST]);
        for (weighting, value) in [
            (BandwidthWeighting::Vpc1, "vpc-1"),
            (BandwidthWeighting::Ebs1, "ebs-1"),
        ] {
            remote.bandwidth_weighting = weighting;
            let yaml: serde_yaml::Value = serde_yaml::from_str(&deployer_config_yaml(
                &config,
                &remote,
                &validators,
                &secondaries,
            ))
            .unwrap();
            let weighted = yaml["instances"]
                .as_sequence()
                .unwrap()
                .iter()
                .filter_map(|instance| {
                    let weighting = instance.get("bandwidth_weighting")?;
                    assert_eq!(weighting.as_str(), Some(value));
                    instance["name"].as_str()
                })
                .collect::<Vec<_>>();

            assert_eq!(weighted, expected);
            assert_eq!(config.instances.len(), expected.len() + 3);
            assert!(yaml["monitoring"].get("bandwidth_weighting").is_none());
        }
    }

    #[test]
    fn remote_secondaries_get_shared_chain_indexer_wiring() {
        let mut args = generate_args();
        args.indexer = true;
        args.relayer = true;
        args.worker_threads = 3;
        args.rayon_threads = 13;
        args.indexer_worker_threads = std::num::NonZeroUsize::new(8);
        args.indexer_rayon_threads = std::num::NonZeroUsize::new(12);
        args.indexer_publisher_rayon_threads = commonware_utils::NZUsize!(4);
        let remote = remote_args();
        let material = generate_local_cluster_material(args.validators, total_secondaries(&args));

        let secondaries = build_secondaries(&args, &remote, Path::new("/tmp/configs"), &material);
        let validators =
            super::build_validators(&args, &remote, Path::new("/tmp/configs"), &material);
        assert!(
            validators
                .iter()
                .all(|v| v.config.worker_threads == 3 && v.config.rayon_threads == 13)
        );
        assert_eq!(secondaries[0].config.worker_threads, 8);
        assert_eq!(secondaries[0].config.rayon_threads, 12);
        assert_eq!(secondaries[1].config.worker_threads, 3);
        assert_eq!(secondaries[1].config.rayon_threads, 13);

        let indexer = secondaries[0]
            .config
            .indexer
            .as_ref()
            .expect("secondary should have indexer wiring");
        assert_eq!(indexer.store_url, "http://chain-indexer:8090");
        assert_eq!(indexer.upload_max_in_flight, 64);
        assert_eq!(indexer.publisher_rayon_threads.get(), 4);
        assert_eq!(indexer.upload_budget_bytes, 3 * 1024 * 1024 * 1024);
        assert!(
            secondaries[1].config.indexer.is_none(),
            "relayer secondary should not have indexer wiring"
        );
        assert!(
            secondaries[1].config.relayer.is_some(),
            "last secondary should run relayer"
        );
    }

    #[test]
    fn remote_deployer_config_includes_shared_indexer_services() {
        let mut args = generate_args();
        args.indexer = true;
        args.relayer = true;
        let remote = remote_args();
        let validators = vec![validator(0), validator(1), validator(2)];
        let mut indexer_secondary_config = validator(0).config;
        indexer_secondary_config.indexer = Some(super::remote_indexer_config(&args, &remote));
        let secondaries = vec![
            super::GeneratedValidator {
                public_key_hex: "secondary-0".to_string(),
                config_name: "secondary-0.yaml".to_string(),
                config_file: PathBuf::from("/tmp/secondary-0.yaml"),
                config: indexer_secondary_config,
            },
            super::GeneratedValidator {
                public_key_hex: "secondary-1".to_string(),
                config_name: "secondary-1.yaml".to_string(),
                config_file: PathBuf::from("/tmp/secondary-1.yaml"),
                config: validator(0).config,
            },
        ];

        let config = build_deployer_config(
            &args,
            &remote,
            VALIDATOR_BINARY_FILE,
            "dashboard.json",
            &validators,
            &secondaries,
        );

        assert_eq!(config.instances.len(), 7);
        assert_eq!(config.instances[5].name, "chain-indexer");
        assert_eq!(config.instances[5].binary, CHAIN_INDEXER_BINARY_FILE);
        assert_eq!(
            config.instances[5].instance_type,
            DEFAULT_CHAIN_INDEXER_INSTANCE_TYPE
        );
        assert_eq!(
            config.instances[5].availability_zone_group.as_deref(),
            Some(EXOWARE_AVAILABILITY_ZONE_GROUP)
        );
        assert_eq!(
            config.instances[5].storage_class,
            CHAIN_INDEXER_STORAGE_CLASS
        );
        assert_eq!(
            config.instances[5].storage_size,
            DEFAULT_CHAIN_INDEXER_STORAGE_SIZE
        );
        assert_eq!(
            config.instances[5].storage_iops,
            Some(DEFAULT_CHAIN_INDEXER_STORAGE_IOPS)
        );
        assert_eq!(config.instances[6].name, "explorer-indexer");
        assert_eq!(config.instances[6].binary, EXPLORER_INDEXER_BINARY_FILE);
        assert_eq!(
            config.instances[6].availability_zone_group.as_deref(),
            Some(EXOWARE_AVAILABILITY_ZONE_GROUP)
        );
        assert_eq!(config.instances[3].region, config.instances[5].region);
        assert_eq!(config.instances[4].region, config.instances[5].region);
        assert_eq!(
            config.instances[3].availability_zone_group.as_deref(),
            Some(EXOWARE_AVAILABILITY_ZONE_GROUP)
        );
        assert_eq!(config.instances[4].availability_zone_group, None);
        assert!(config.ports.iter().any(|port| port.port == 8090));
        assert!(config.ports.iter().any(|port| port.port == 8092));
    }

    #[test]
    fn remote_explorer_topology_and_credentials() {
        for (external_store, external_indexer) in [(false, false), (true, false), (true, true)] {
            for relayer in [false, true] {
                let mut args = generate_args();
                args.indexer = true;
                args.relayer = relayer;
                let mut remote = remote_args();
                if external_store {
                    remote.store_url = Some("https://store.example.com/base".to_string());
                    remote.store_api_key = Some("writer-key".to_string());
                    remote.adapter_store_api_key = Some("reader-key".to_string());
                }
                if external_indexer {
                    remote.indexer_url = Some("https://explorer.example.com/base".to_string());
                }
                let material =
                    generate_local_cluster_material(args.validators, total_secondaries(&args));
                let secondaries =
                    build_secondaries(&args, &remote, Path::new("/tmp/configs"), &material);
                let validators = vec![validator(0), validator(1), validator(2)];
                let deployment = build_deployer_config(
                    &args,
                    &remote,
                    VALIDATOR_BINARY_FILE,
                    "dashboard.json",
                    &validators,
                    &secondaries,
                );
                let binaries = expected_binary_files(&args, &remote);
                assert_eq!(
                    binaries.contains(&CHAIN_INDEXER_BINARY_FILE),
                    !external_store
                );
                assert_eq!(
                    binaries.contains(&EXPLORER_INDEXER_BINARY_FILE),
                    !external_indexer
                );
                assert_eq!(
                    deployment.instances.len(),
                    validators.len()
                        + secondaries.len()
                        + usize::from(!external_store)
                        + usize::from(!external_indexer)
                );
                let ports = port_configs(&args, &remote);
                assert_eq!(
                    ports
                        .iter()
                        .any(|port| port.port == remote.chain_indexer_port),
                    !external_store
                );
                assert_eq!(
                    ports
                        .iter()
                        .any(|port| port.port == remote.explorer_indexer_port),
                    !external_indexer
                );
                let config = explorer_indexer_config(&args, &remote, &material);
                assert_eq!(config.is_none(), external_indexer);
                if let Some(config) = config {
                    assert_eq!(config.store_url, super::store_url(&remote));
                    assert_eq!(config.api_key, remote.adapter_store_api_key);
                    assert_eq!(config.metrics_port, Some(super::METRICS_PORT));
                    let admission_host = if relayer {
                        hex(&material.secondary_public_keys[1].encode())
                    } else {
                        material.primary_hex()[0].clone()
                    };
                    assert_eq!(
                        config.relayer_url,
                        Some(format!("http://{admission_host}:8080"))
                    );
                    let yaml = serde_yaml::to_string(&config).unwrap();
                    assert!(!yaml.contains("writer-key"));
                }
                let publisher = secondaries[0].config.indexer.as_ref().unwrap();
                assert_eq!(publisher.api_key, remote.store_api_key);
                assert_eq!(publisher.store_url, super::store_url(&remote));
            }
        }
    }
}
