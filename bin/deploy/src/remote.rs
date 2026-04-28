use crate::{
    ClusterMaterial, DASHBOARD_FILE, DEPLOYER_CONFIG_FILE, GenerateArgs, RemoteArgs,
    SPAMMER_BINARY_FILE, SPAMMER_CONFIG_FILE, STORAGE_CLASS, SpammerConfig, VALIDATOR_BINARY_FILE,
    ValidatorConfig, absolute_path, default_bootstrappers, default_max_pool_bytes,
    default_max_propose_bytes, ensure_output_dir_missing, generate_deployer_tag,
    generate_remote_cluster_material, write_yaml_config,
};
use commonware_codec::Encode;
use commonware_deployer::aws::{self, METRICS_PORT};
use commonware_utils::hex;
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
    assert!(args.validators >= 1, "need at least one validator");
    assert!(!remote.regions.is_empty(), "need at least one region");
    assert!(
        remote.regions.len() <= args.validators as usize,
        "need at least one validator per region"
    );

    let output_dir = absolute_path(&args.output_dir);
    ensure_output_dir_missing(&output_dir);

    let dashboard = absolute_path(&remote.dashboard);
    let material = generate_remote_cluster_material(args.validators, args.secondaries);
    let validators = build_validators(args, remote, &output_dir, &material);
    let secondaries = build_secondaries(args, remote, &output_dir, &material);

    fs::create_dir_all(&output_dir).expect("failed to create output directory");
    for validator in &validators {
        write_yaml_config(&validator.config_file, &validator.config);
    }
    for secondary in &secondaries {
        write_yaml_config(&secondary.config_file, &secondary.config);
    }

    if args.spammer {
        let spammer_config = SpammerConfig {
            accounts: args.spammer_accounts,
            value: args.spammer_value,
            seed_offset: args.spammer_seed_offset,
            http_port: remote.http_port,
            primary_validators: material.primary_hex(),
        };
        write_yaml_config(&output_dir.join(SPAMMER_CONFIG_FILE), &spammer_config);
    }

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
        secondaries = args.secondaries,
        "generated remote deployment bundle"
    );
    if args.spammer {
        info!(
            validator_binary = %output_dir.join(VALIDATOR_BINARY_FILE).display(),
            spammer_binary = %output_dir.join(SPAMMER_BINARY_FILE).display(),
            "build all binaries into the deployment directory before creating the remote deployment"
        );
    } else {
        info!(
            validator_binary = %output_dir.join(VALIDATOR_BINARY_FILE).display(),
            "build the validator binary into the deployment directory before creating the remote deployment"
        );
    }
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
            max_propose_bytes: default_max_propose_bytes(),
            max_pool_bytes: default_max_pool_bytes(),
            bootstrappers: bootstrappers.clone(),
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
    let mut secondaries = Vec::with_capacity(args.secondaries as usize);
    let bootstrappers = default_bootstrappers(&material.public_keys);
    let primary_validators = material.primary_hex();
    let secondary_validators = material.secondary_hex();

    for index in 0..args.secondaries {
        let secondary_index = index as usize;
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
            max_propose_bytes: default_max_propose_bytes(),
            max_pool_bytes: default_max_pool_bytes(),
            bootstrappers: bootstrappers.clone(),
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

fn build_deployer_config(
    args: &GenerateArgs,
    remote: &RemoteArgs,
    validator_binary: &str,
    dashboard: &str,
    validators: &[GeneratedValidator],
    secondaries: &[GeneratedValidator],
) -> aws::Config {
    let regions = &remote.regions;
    let mut instances: Vec<aws::InstanceConfig> = validators
        .iter()
        .enumerate()
        .map(|(index, validator)| aws::InstanceConfig {
            name: validator.public_key_hex.clone(),
            region: regions[index % regions.len()].clone(),
            instance_type: remote.instance_type.clone(),
            storage_size: remote.storage_size,
            storage_class: STORAGE_CLASS.to_string(),
            binary: validator_binary.to_string(),
            config: validator.config_name.clone(),
            profiling: remote.profiling,
        })
        .collect();

    // Spread secondary instances across regions independently of the primary
    // rotation so they don't all land in the same AZ as primary 0.
    for (index, secondary) in secondaries.iter().enumerate() {
        instances.push(aws::InstanceConfig {
            name: secondary.public_key_hex.clone(),
            region: regions[index % regions.len()].clone(),
            instance_type: remote.instance_type.clone(),
            storage_size: remote.storage_size,
            storage_class: STORAGE_CLASS.to_string(),
            binary: validator_binary.to_string(),
            config: secondary.config_name.clone(),
            profiling: remote.profiling,
        });
    }

    if args.spammer {
        instances.push(aws::InstanceConfig {
            name: "spammer".to_string(),
            region: regions[0].clone(),
            instance_type: remote
                .spammer_instance_type
                .clone()
                .unwrap_or_else(|| remote.instance_type.clone()),
            storage_size: remote.spammer_storage_size,
            storage_class: STORAGE_CLASS.to_string(),
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
            dashboard: dashboard.to_string(),
        },
        instances,
        ports: port_configs(remote),
    }
}

fn port_configs(remote: &RemoteArgs) -> Vec<aws::PortConfig> {
    let mut ports = vec![aws::PortConfig {
        protocol: "tcp".to_string(),
        port: remote.listen_port,
        cidr: "0.0.0.0/0".to_string(),
    }];

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
    use super::{build_deployer_config, port_configs};
    use crate::{
        GenerateArgs, GenerateTarget, LocalArgs, RemoteArgs, STORAGE_CLASS, StartupModeConfig,
        VALIDATOR_BINARY_FILE, ValidatorConfig, default_max_pool_bytes, default_max_propose_bytes,
    };
    use std::path::PathBuf;

    fn generate_args() -> GenerateArgs {
        GenerateArgs {
            validators: 3,
            secondaries: 0,
            output_dir: PathBuf::from("artifacts"),
            log_level: "info".to_string(),
            worker_threads: 2,
            rayon_threads: 2,
            startup: StartupModeConfig::MarshalSync,
            spammer: false,
            spammer_accounts: 10,
            spammer_value: 1,
            spammer_seed_offset: 1000,
            target: GenerateTarget::Local(LocalArgs {
                base_port: 9000,
                base_http_port: 8080,
                base_metrics_port: 9090,
            }),
        }
    }

    fn remote_args() -> RemoteArgs {
        RemoteArgs {
            regions: vec!["us-east-1".to_string(), "us-west-2".to_string()],
            instance_type: "c8g.large".to_string(),
            storage_size: 25,
            monitoring_instance_type: "c8g.2xlarge".to_string(),
            monitoring_storage_size: 100,
            dashboard: PathBuf::from("dashboard.json"),
            listen_port: 9000,
            http_port: 8080,
            http_cidrs: vec!["198.51.100.4/32".to_string()],
            profiling: true,
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
                bootstrappers: Vec::new(),
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
        assert_eq!(config.instances[0].binary, VALIDATOR_BINARY_FILE);
        assert_eq!(config.instances[0].config, "validator-0.yaml");
        assert_eq!(config.monitoring.dashboard, "dashboard.json");
        assert_eq!(config.ports[0].port, 9000);
        assert_eq!(config.ports[1].port, 8080);
        assert_eq!(config.ports[1].cidr, "198.51.100.4/32");
    }

    #[test]
    fn remote_deployer_config_includes_secondaries() {
        let mut args = generate_args();
        args.secondaries = 2;
        let remote = remote_args();
        let validators = vec![validator(0), validator(1), validator(2)];
        let secondaries = vec![
            super::GeneratedValidator {
                public_key_hex: "secondary-0".to_string(),
                config_name: "secondary-0.yaml".to_string(),
                config_file: PathBuf::from("/tmp/secondary-0.yaml"),
                config: validator(0).config,
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

        // 3 primaries + 2 secondaries, no spammer.
        assert_eq!(config.instances.len(), 5);
        assert_eq!(config.instances[3].name, "secondary-0");
        assert_eq!(config.instances[3].binary, VALIDATOR_BINARY_FILE);
        assert_eq!(config.instances[3].config, "secondary-0.yaml");
        assert_eq!(config.instances[4].name, "secondary-1");
    }

    #[test]
    fn remote_ports_only_open_http_for_explicit_cidrs() {
        let mut remote = remote_args();
        remote.http_cidrs.clear();

        let ports = port_configs(&remote);

        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 9000);
    }
}
