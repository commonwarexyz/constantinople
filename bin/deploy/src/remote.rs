use crate::{
    AdapterConfig, CHAIN_INDEXER_BINARY_FILE, CHAIN_INDEXER_CONFIG_FILE, CHAIN_INDEXER_DATA_DIR,
    CHAIN_INDEXER_HOST, CHAIN_INDEXER_STORAGE_CLASS, ChainIndexerConfig, ClusterMaterial,
    DASHBOARD_FILE, DEPLOYER_CONFIG_FILE, EXOWARE_AVAILABILITY_ZONE_GROUP, GenerateArgs,
    INDEXER_UPLOAD_BUDGET_BYTES, INDEXER_UPLOAD_MAX_IN_FLIGHT, IndexerConfig,
    METADATA_INDEXER_BINARY_FILE, METADATA_INDEXER_CONFIG_FILE, QMDB_INDEXER_BINARY_FILE,
    QMDB_INDEXER_CONFIG_FILE, QMDB_INDEXER_HOST, RelayerConfig, RelayerLeaderConfig, RemoteArgs,
    SPAMMER_BINARY_FILE, SPAMMER_CONFIG_FILE, STORAGE_CLASS, SecondaryRole, SpammerConfig,
    VALIDATOR_BINARY_FILE, ValidatorConfig, absolute_path, default_bootstrappers,
    ensure_output_dir_missing, generate_deployer_tag, generate_remote_cluster_material,
    indexer_enabled, secondary_roles, total_secondaries, validate_generate_args,
    write_simplex_verification_material, write_yaml_config,
};
use commonware_codec::Encode;
use commonware_deployer::aws::{self, METRICS_PORT};
use commonware_formatting::hex;
use std::{
    fs,
    path::{Path, PathBuf},
};
use tracing::info;

struct GeneratedValidator {
    public_key_hex: String,
    config_name: String,
    config_file: PathBuf,
    config: ValidatorConfig,
}

pub(super) fn generate(args: &GenerateArgs, remote: &RemoteArgs) {
    validate_generate_args(args);
    assert!(args.validators >= 1, "need at least one validator");
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
    if let Some(config) = metadata_indexer_config(args, remote) {
        write_yaml_config(&output_dir.join(METADATA_INDEXER_CONFIG_FILE), &config);
    }
    if let Some(config) = qmdb_indexer_config(args, remote) {
        write_yaml_config(&output_dir.join(QMDB_INDEXER_CONFIG_FILE), &config);
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
    let raw = serde_yaml::to_string(&deployer_config).expect("failed to serialize deployer config");
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
            metadata_indexer_port = remote.metadata_indexer_port,
            qmdb_indexer_port = remote.qmdb_indexer_port,
            "configured shared remote indexer services"
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
            max_pool_bytes: args.max_pool_bytes,
            state_page_cache_bytes: args.state_page_cache_bytes,
            other_page_cache_bytes: args.other_page_cache_bytes,
            public_key_cache_size: args.public_key_cache_size,
            traces: remote.traces,
            bootstrappers: bootstrappers.clone(),
            indexer: None,
            relayer: None,
        };

        let config_name = format!("{public_key_hex}.yaml");

        validators.push(GeneratedValidator {
            public_key_hex: public_key_hex.clone(),
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
            worker_threads: args.worker_threads,
            rayon_threads: args.rayon_threads,
            http_port: remote.http_port,
            metrics_port: METRICS_PORT,
            max_propose_bytes: args.max_propose_bytes,
            max_pool_bytes: args.max_pool_bytes,
            state_page_cache_bytes: args.state_page_cache_bytes,
            other_page_cache_bytes: args.other_page_cache_bytes,
            public_key_cache_size: args.public_key_cache_size,
            traces: remote.traces,
            bootstrappers: bootstrappers.clone(),
            indexer: matches!(role, SecondaryRole::Indexer).then(|| remote_indexer_config(remote)),
            relayer: matches!(role, SecondaryRole::Relayer)
                .then(|| remote_relayer_config(remote, material)),
        };

        let config_name = format!("{public_key_hex}.yaml");

        secondaries.push(GeneratedValidator {
            public_key_hex: public_key_hex.clone(),
            config_name: config_name.clone(),
            config_file: output_dir.join(config_name),
            config,
        });
    }

    secondaries
}

fn store_url(remote: &RemoteArgs) -> String {
    remote
        .chain_indexer_url
        .clone()
        .unwrap_or_else(|| format!("http://{CHAIN_INDEXER_HOST}:{}", remote.chain_indexer_port))
}

const fn local_chain_indexer(args: &GenerateArgs, remote: &RemoteArgs) -> bool {
    indexer_enabled(args) && remote.chain_indexer_url.is_none()
}

const fn local_metadata_indexer(args: &GenerateArgs, remote: &RemoteArgs) -> bool {
    indexer_enabled(args) && remote.metadata_indexer_url.is_none()
}

const fn local_qmdb_indexer(args: &GenerateArgs, remote: &RemoteArgs) -> bool {
    indexer_enabled(args) && remote.qmdb_indexer_url.is_none()
}

fn expected_binary_files(args: &GenerateArgs, remote: &RemoteArgs) -> Vec<&'static str> {
    let mut binaries = vec![VALIDATOR_BINARY_FILE];
    if local_chain_indexer(args, remote) {
        binaries.push(CHAIN_INDEXER_BINARY_FILE);
    }
    if local_metadata_indexer(args, remote) {
        binaries.push(METADATA_INDEXER_BINARY_FILE);
    }
    if local_qmdb_indexer(args, remote) {
        binaries.push(QMDB_INDEXER_BINARY_FILE);
    }
    if args.spammer {
        binaries.push(SPAMMER_BINARY_FILE);
    }
    binaries
}

fn remote_indexer_config(remote: &RemoteArgs) -> IndexerConfig {
    IndexerConfig {
        chain_indexer_url: store_url(remote),
        api_key: remote.chain_indexer_api_key.clone(),
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
        relayer_url: relayer_url(args, remote, material),
        relayer_submitters: args.spammer_submitters.unwrap_or(args.validators as usize),
        presigned_batches: args.spammer_presigned_batches,
        primary_validators: material.primary_hex(),
        accounts_jitter: args.spammer_accounts_jitter,
    }
}

fn relayer_url(args: &GenerateArgs, remote: &RemoteArgs, material: &ClusterMaterial) -> String {
    let relayer_index = usize::from(args.indexer);
    let public_key = &material.secondary_public_keys[relayer_index];
    format!("http://{}:{}", hex(&public_key.encode()), remote.http_port)
}

fn chain_indexer_config(args: &GenerateArgs, remote: &RemoteArgs) -> Option<ChainIndexerConfig> {
    local_chain_indexer(args, remote).then(|| ChainIndexerConfig {
        port: remote.chain_indexer_port,
        data_dir: PathBuf::from(CHAIN_INDEXER_DATA_DIR),
        db_parallelism: remote.chain_indexer_db_parallelism,
    })
}

fn metadata_indexer_config(args: &GenerateArgs, remote: &RemoteArgs) -> Option<AdapterConfig> {
    local_metadata_indexer(args, remote).then(|| AdapterConfig {
        port: remote.metadata_indexer_port,
        chain_indexer_url: store_url(remote),
        api_key: remote.adapter_store_api_key.clone(),
    })
}

fn qmdb_indexer_config(args: &GenerateArgs, remote: &RemoteArgs) -> Option<AdapterConfig> {
    local_qmdb_indexer(args, remote).then(|| AdapterConfig {
        port: remote.qmdb_indexer_port,
        chain_indexer_url: store_url(remote),
        api_key: remote.adapter_store_api_key.clone(),
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
            availability_zone_group: secondary
                .config
                .indexer
                .is_some()
                .then(|| EXOWARE_AVAILABILITY_ZONE_GROUP.to_string()),
            instance_type: if secondary.config.indexer.is_some() {
                remote
                    .indexer_instance_type
                    .clone()
                    .unwrap_or_else(|| remote.instance_type.clone())
            } else {
                remote.instance_type.clone()
            },
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

    if local_metadata_indexer(args, remote) {
        instances.push(aws::InstanceConfig {
            name: crate::METADATA_INDEXER_HOST.to_string(),
            region: shared_indexer_region.clone(),
            availability_zone_group: Some(EXOWARE_AVAILABILITY_ZONE_GROUP.to_string()),
            instance_type: remote.instance_type.clone(),
            storage_size: remote.storage_size,
            storage_class: STORAGE_CLASS.to_string(),
            storage_iops: None,
            storage_throughput: None,
            binary: METADATA_INDEXER_BINARY_FILE.to_string(),
            config: METADATA_INDEXER_CONFIG_FILE.to_string(),
            profiling: false,
        });
    }

    if local_qmdb_indexer(args, remote) {
        instances.push(aws::InstanceConfig {
            name: QMDB_INDEXER_HOST.to_string(),
            region: shared_indexer_region,
            availability_zone_group: Some(EXOWARE_AVAILABILITY_ZONE_GROUP.to_string()),
            instance_type: remote.instance_type.clone(),
            storage_size: remote.storage_size,
            storage_class: STORAGE_CLASS.to_string(),
            storage_iops: None,
            storage_throughput: None,
            binary: QMDB_INDEXER_BINARY_FILE.to_string(),
            config: QMDB_INDEXER_CONFIG_FILE.to_string(),
            profiling: false,
        });
    }

    if args.spammer {
        instances.push(aws::InstanceConfig {
            name: "spammer".to_string(),
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

    if local_metadata_indexer(args, remote) {
        ports.push(aws::PortConfig {
            protocol: "tcp".to_string(),
            port: remote.metadata_indexer_port,
            cidr: "0.0.0.0/0".to_string(),
        });
    }

    if local_qmdb_indexer(args, remote) {
        ports.push(aws::PortConfig {
            protocol: "tcp".to_string(),
            port: remote.qmdb_indexer_port,
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
        build_deployer_config, build_secondaries, chain_indexer_config, expected_binary_files,
        metadata_indexer_config, port_configs, qmdb_indexer_config, remote_spammer_config,
    };
    use crate::{
        CHAIN_INDEXER_BINARY_FILE, CHAIN_INDEXER_STORAGE_CLASS,
        DEFAULT_CHAIN_INDEXER_INSTANCE_TYPE, DEFAULT_CHAIN_INDEXER_STORAGE_IOPS,
        DEFAULT_CHAIN_INDEXER_STORAGE_SIZE, EXOWARE_AVAILABILITY_ZONE_GROUP, GenerateArgs,
        GenerateTarget, LocalArgs, METADATA_INDEXER_BINARY_FILE, QMDB_INDEXER_BINARY_FILE,
        RemoteArgs, STORAGE_CLASS, StartupModeConfig, VALIDATOR_BINARY_FILE, ValidatorConfig,
        default_max_pool_bytes, default_max_propose_bytes, default_page_cache_bytes,
        default_public_key_cache_size, generate_local_cluster_material, total_secondaries,
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
            public_key_cache_size: default_public_key_cache_size(),
            max_propose_bytes: default_max_propose_bytes(),
            max_pool_bytes: default_max_pool_bytes(),
            state_page_cache_bytes: default_page_cache_bytes(),
            other_page_cache_bytes: default_page_cache_bytes(),
            startup: StartupModeConfig::MarshalSync,
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
                metadata_indexer_port: 8091,
                qmdb_indexer_port: 8092,
            }),
        }
    }

    fn remote_args() -> RemoteArgs {
        RemoteArgs {
            regions: vec!["us-east-1".to_string(), "us-west-2".to_string()],
            instance_type: "c8g.large".to_string(),
            indexer_instance_type: Some("c8g.2xlarge".to_string()),
            storage_size: 25,
            storage_iops: None,
            storage_throughput: None,
            chain_indexer_url: None,
            metadata_indexer_url: None,
            qmdb_indexer_url: None,
            chain_indexer_api_key: None,
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
            metadata_indexer_port: 8091,
            qmdb_indexer_port: 8092,
            profiling: true,
            traces: 0.0,
            spammer_instance_type: None,
            spammer_storage_size: 25,
        }
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
                max_pool_bytes: default_max_pool_bytes(),
                state_page_cache_bytes: default_page_cache_bytes(),
                other_page_cache_bytes: default_page_cache_bytes(),
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
        assert_eq!(relayed.rayon_threads, crate::DEFAULT_SPAMMER_RAYON_THREADS);
        assert_eq!(
            relayed.presigned_batches,
            crate::DEFAULT_SPAMMER_PRESIGNED_BATCHES
        );
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

        assert_eq!(config.seed_offset, Some(2000));
    }

    // Offered load is submitters x accounts per round trip, so the flag exists
    // to hold load constant when the validator count changes; the default keeps
    // the pre-flag coupling.
    #[test]
    fn remote_spammer_submitters_flag_overrides_validator_count() {
        let mut args = generate_args();
        args.spammer = true;
        args.relayer = true;
        args.spammer_submitters = Some(50);
        let remote = remote_args();
        let material = generate_local_cluster_material(args.validators, total_secondaries(&args));

        let relayed = remote_spammer_config(&args, &remote, &material);

        assert_eq!(relayed.relayer_submitters, 50);
    }

    #[test]
    fn remote_deployer_config_includes_secondaries_and_indexers() {
        let mut args = generate_args();
        args.indexer = true;
        args.relayer = true;
        let remote = remote_args();
        let validators = vec![validator(0), validator(1), validator(2)];
        let mut indexer_secondary_config = validator(0).config;
        indexer_secondary_config.indexer = Some(super::remote_indexer_config(&remote));
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

        // 3 primaries + 2 secondaries + shared chain/sql/qmdb indexers.
        assert_eq!(config.instances.len(), 8);
        assert_eq!(config.instances[3].name, "secondary-0");
        assert_eq!(config.instances[3].binary, VALIDATOR_BINARY_FILE);
        assert_eq!(config.instances[3].config, "secondary-0.yaml");
        assert_eq!(config.instances[3].instance_type, "c8g.2xlarge");
        assert_eq!(config.instances[4].name, "secondary-1");
        assert_eq!(config.instances[4].instance_type, "c8g.large");
    }

    #[test]
    fn remote_ports_only_open_http_for_explicit_cidrs() {
        let args = generate_args();
        let mut remote = remote_args();
        remote.http_cidrs.clear();

        let ports = port_configs(&args, &remote);

        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 9000);
    }

    // An external store must replace the chain-indexer wholesale: every consumer
    // dials the URL verbatim, and nothing that exists only to serve the local
    // simulator (instance, config, port rule) is generated.
    #[test]
    fn remote_external_store_url_replaces_chain_indexer() {
        let mut args = generate_args();
        args.indexer = true;
        args.relayer = true;
        let mut remote = remote_args();
        remote.chain_indexer_url = Some("https://store.example.xyz".to_string());
        let material = generate_local_cluster_material(args.validators, total_secondaries(&args));

        let secondaries = build_secondaries(&args, &remote, Path::new("/tmp/configs"), &material);
        let indexer = secondaries[0]
            .config
            .indexer
            .as_ref()
            .expect("secondary should have indexer wiring");
        assert_eq!(indexer.chain_indexer_url, "https://store.example.xyz");

        assert!(
            super::chain_indexer_config(&args, &remote).is_none(),
            "no chain-indexer config should be generated for an external store"
        );
        let metadata = super::metadata_indexer_config(&args, &remote)
            .expect("metadata indexer should still be generated");
        assert_eq!(metadata.chain_indexer_url, "https://store.example.xyz");
        let qmdb = super::qmdb_indexer_config(&args, &remote)
            .expect("qmdb indexer should still be generated");
        assert_eq!(qmdb.chain_indexer_url, "https://store.example.xyz");

        let validators = vec![validator(0), validator(1), validator(2)];
        let config = build_deployer_config(
            &args,
            &remote,
            VALIDATOR_BINARY_FILE,
            "dashboard.json",
            &validators,
            &secondaries,
        );

        // 3 primaries + 2 secondaries + metadata/qmdb indexers; no chain-indexer.
        assert_eq!(config.instances.len(), 7);
        assert!(
            config.instances.iter().all(|i| i.name != "chain-indexer"),
            "no chain-indexer instance should be provisioned for an external store"
        );

        let ports = port_configs(&args, &remote);
        assert!(
            ports.iter().all(|p| p.port != remote.chain_indexer_port),
            "the chain-indexer port should not be opened for an external store"
        );
    }

    #[test]
    fn remote_adapter_replacement_matrix_preserves_store_and_credentials() {
        const STORE_URL: &str = "https://store.example.xyz";
        const METADATA_URL: &str = "https://sql.example.xyz";
        const QMDB_URL: &str = "https://qmdb.example.xyz";
        const WRITER_KEY: &str = "writer-key";
        const READER_KEY: &str = "reader-key";

        struct Case {
            name: &'static str,
            remote_metadata: bool,
            remote_qmdb: bool,
        }

        let cases = [
            Case {
                name: "no remote adapters",
                remote_metadata: false,
                remote_qmdb: false,
            },
            Case {
                name: "metadata only",
                remote_metadata: true,
                remote_qmdb: false,
            },
            Case {
                name: "QMDB only",
                remote_metadata: false,
                remote_qmdb: true,
            },
            Case {
                name: "both adapters",
                remote_metadata: true,
                remote_qmdb: true,
            },
        ];

        for case in cases {
            let mut args = generate_args();
            args.indexer = true;
            args.relayer = true;

            let mut remote = remote_args();
            remote.chain_indexer_url = Some(STORE_URL.to_string());
            remote.metadata_indexer_url = case.remote_metadata.then(|| METADATA_URL.to_string());
            remote.qmdb_indexer_url = case.remote_qmdb.then(|| QMDB_URL.to_string());
            remote.chain_indexer_api_key = Some(WRITER_KEY.to_string());
            remote.adapter_store_api_key = Some(READER_KEY.to_string());

            let material =
                generate_local_cluster_material(args.validators, total_secondaries(&args));
            let secondaries =
                build_secondaries(&args, &remote, Path::new("/tmp/configs"), &material);
            let indexer = secondaries[0]
                .config
                .indexer
                .as_ref()
                .expect("the owning secondary should have indexer wiring");

            assert_eq!(indexer.chain_indexer_url, STORE_URL, "{}", case.name);
            assert_eq!(
                indexer.api_key.as_deref(),
                Some(WRITER_KEY),
                "{}",
                case.name
            );
            assert!(secondaries[1].config.indexer.is_none(), "{}", case.name);
            assert!(
                chain_indexer_config(&args, &remote).is_none(),
                "{}",
                case.name
            );

            let metadata = metadata_indexer_config(&args, &remote);
            let qmdb = qmdb_indexer_config(&args, &remote);
            assert_eq!(metadata.is_some(), !case.remote_metadata, "{}", case.name);
            assert_eq!(qmdb.is_some(), !case.remote_qmdb, "{}", case.name);

            if let Some(config) = &metadata {
                assert_eq!(config.chain_indexer_url, STORE_URL, "{}", case.name);
                assert_eq!(config.api_key.as_deref(), Some(READER_KEY), "{}", case.name);
            }
            if let Some(config) = &qmdb {
                assert_eq!(config.chain_indexer_url, STORE_URL, "{}", case.name);
                assert_eq!(config.api_key.as_deref(), Some(READER_KEY), "{}", case.name);
            }

            let validators = vec![validator(0), validator(1), validator(2)];
            let deployer = build_deployer_config(
                &args,
                &remote,
                VALIDATOR_BINARY_FILE,
                "dashboard.json",
                &validators,
                &secondaries,
            );
            let has_instance = |name: &str| {
                deployer
                    .instances
                    .iter()
                    .any(|instance| instance.name == name)
            };
            assert!(!has_instance("chain-indexer"), "{}", case.name);
            assert_eq!(
                has_instance("metadata-indexer"),
                !case.remote_metadata,
                "{}",
                case.name
            );
            assert_eq!(
                has_instance("qmdb-indexer"),
                !case.remote_qmdb,
                "{}",
                case.name
            );
            assert_eq!(
                deployer.instances.len(),
                validators.len()
                    + secondaries.len()
                    + usize::from(!case.remote_metadata)
                    + usize::from(!case.remote_qmdb),
                "{}",
                case.name
            );

            let mut binaries = vec![VALIDATOR_BINARY_FILE];
            if !case.remote_metadata {
                binaries.push(METADATA_INDEXER_BINARY_FILE);
            }
            if !case.remote_qmdb {
                binaries.push(QMDB_INDEXER_BINARY_FILE);
            }
            assert_eq!(
                expected_binary_files(&args, &remote),
                binaries,
                "{}",
                case.name
            );

            let ports = port_configs(&args, &remote);
            let has_port = |port| ports.iter().any(|config| config.port == port);
            assert!(!has_port(remote.chain_indexer_port), "{}", case.name);
            assert_eq!(
                has_port(remote.metadata_indexer_port),
                !case.remote_metadata,
                "{}",
                case.name
            );
            assert_eq!(
                has_port(remote.qmdb_indexer_port),
                !case.remote_qmdb,
                "{}",
                case.name
            );

            let mut validator_yamls = validators
                .iter()
                .map(|validator| {
                    serde_yaml::to_string(&validator.config)
                        .expect("validator config should serialize")
                })
                .collect::<Vec<_>>();
            validator_yamls.extend(secondaries.iter().map(|secondary| {
                serde_yaml::to_string(&secondary.config).expect("secondary config should serialize")
            }));
            assert_eq!(
                validator_yamls
                    .iter()
                    .map(|raw| raw.matches(WRITER_KEY).count())
                    .sum::<usize>(),
                1,
                "{}",
                case.name
            );
            assert!(
                validator_yamls.iter().all(|raw| !raw.contains(READER_KEY)),
                "{}",
                case.name
            );

            let mut generated_yamls = validator_yamls;
            if let Some(config) = &metadata {
                generated_yamls
                    .push(serde_yaml::to_string(config).expect("metadata config should serialize"));
            }
            if let Some(config) = &qmdb {
                generated_yamls
                    .push(serde_yaml::to_string(config).expect("QMDB config should serialize"));
            }
            generated_yamls
                .push(serde_yaml::to_string(&deployer).expect("deployer config should serialize"));

            assert_eq!(
                generated_yamls
                    .iter()
                    .map(|raw| raw.matches(WRITER_KEY).count())
                    .sum::<usize>(),
                1,
                "{}",
                case.name
            );
            assert_eq!(
                generated_yamls
                    .iter()
                    .map(|raw| raw.matches(READER_KEY).count())
                    .sum::<usize>(),
                usize::from(!case.remote_metadata) + usize::from(!case.remote_qmdb),
                "{}",
                case.name
            );
            assert!(
                generated_yamls
                    .iter()
                    .all(|raw| !raw.contains(METADATA_URL)),
                "{}",
                case.name
            );
            assert!(
                generated_yamls.iter().all(|raw| !raw.contains(QMDB_URL)),
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn remote_secondaries_get_shared_chain_indexer_wiring() {
        let mut args = generate_args();
        args.indexer = true;
        args.relayer = true;
        let remote = remote_args();
        let material = generate_local_cluster_material(args.validators, total_secondaries(&args));

        let secondaries = build_secondaries(&args, &remote, Path::new("/tmp/configs"), &material);

        let indexer = secondaries[0]
            .config
            .indexer
            .as_ref()
            .expect("secondary should have indexer wiring");
        assert_eq!(indexer.chain_indexer_url, "http://chain-indexer:8090");
        assert_eq!(indexer.upload_max_in_flight, 12);
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
        indexer_secondary_config.indexer = Some(super::remote_indexer_config(&remote));
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

        assert_eq!(config.instances.len(), 8);
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
        assert_eq!(config.instances[6].name, "metadata-indexer");
        assert_eq!(config.instances[6].binary, METADATA_INDEXER_BINARY_FILE);
        assert_eq!(
            config.instances[6].availability_zone_group.as_deref(),
            Some(EXOWARE_AVAILABILITY_ZONE_GROUP)
        );
        assert_eq!(config.instances[7].name, "qmdb-indexer");
        assert_eq!(config.instances[7].binary, QMDB_INDEXER_BINARY_FILE);
        assert_eq!(
            config.instances[7].availability_zone_group.as_deref(),
            Some(EXOWARE_AVAILABILITY_ZONE_GROUP)
        );
        assert_eq!(config.instances[3].region, config.instances[5].region);
        assert_eq!(config.instances[4].region, config.instances[5].region);
        assert_eq!(config.instances[6].region, config.instances[5].region);
        assert_eq!(config.instances[7].region, config.instances[5].region);
        assert_eq!(
            config.instances[3].availability_zone_group.as_deref(),
            Some(EXOWARE_AVAILABILITY_ZONE_GROUP)
        );
        assert_eq!(config.instances[4].availability_zone_group, None);
        assert!(config.ports.iter().any(|port| port.port == 8090));
        assert!(config.ports.iter().any(|port| port.port == 8091));
        assert!(config.ports.iter().any(|port| port.port == 8092));
    }
}
