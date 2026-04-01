use crate::{
    ClusterMaterial, DASHBOARD_FILE, DEPLOYER_CONFIG_FILE, GenerateArgs, RemoteArgs,
    SPAMMER_CONFIG_FILE, SPAMMER_INSTANCE_NAME, STORAGE_CLASS, ValidatorConfig, absolute_path,
    build_spammer_config, default_max_pool_bytes, default_max_propose_bytes,
    ensure_output_dir_missing, generate_cluster_material, generate_deployer_tag,
    write_yaml_config,
};
use commonware_codec::Encode;
use commonware_deployer::aws;
use commonware_utils::hex;
use std::{
    fs,
    path::{Path, PathBuf},
};

struct GeneratedValidator {
    public_key_hex: String,
    config_file: PathBuf,
    config: ValidatorConfig,
}

struct SpammerDeployment {
    instance: aws::InstanceConfig,
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

    let validator_binary = absolute_path(&remote.validator_binary);
    let dashboard = absolute_path(&remote.dashboard);
    let material = generate_cluster_material(args.validators);
    let validators = build_validators(args, remote, &output_dir, &material);
    let spammer_config = build_spammer_config(
        args,
        validators
            .iter()
            .map(|validator| validator.public_key_hex.clone())
            .collect(),
        remote.http_port,
    );
    let spammer = build_spammer_deployment(args, remote, &output_dir);

    fs::create_dir_all(&output_dir).expect("failed to create output directory");
    for validator in &validators {
        write_yaml_config(&validator.config_file, &validator.config);
    }
    if let Some(spammer_config) = spammer_config.as_ref() {
        write_yaml_config(&output_dir.join(SPAMMER_CONFIG_FILE), spammer_config);
    }

    let copied_dashboard = output_dir.join(DASHBOARD_FILE);
    fs::copy(&dashboard, &copied_dashboard).expect("failed to copy dashboard");

    let deployer_config = build_deployer_config(
        remote,
        &validator_binary,
        &copied_dashboard,
        &validators,
        spammer,
    );
    let config_path = output_dir.join(DEPLOYER_CONFIG_FILE);
    let raw = serde_yaml::to_string(&deployer_config).expect("failed to serialize deployer config");
    fs::write(&config_path, raw).expect("failed to write deployer config");

    println!("deployer aws create --config {}", config_path.display());
}

fn build_validators(
    args: &GenerateArgs,
    remote: &RemoteArgs,
    output_dir: &Path,
    material: &ClusterMaterial,
) -> Vec<GeneratedValidator> {
    let mut validators = Vec::with_capacity(args.validators as usize);

    for index in 0..args.validators {
        let validator_index = index as usize;
        let public_key = &material.public_keys[validator_index];
        let public_key_hex = hex(&public_key.encode());
        let share = material
            .shares
            .get(public_key)
            .expect("missing share for validator");

        let bootstrappers = material
            .public_keys
            .iter()
            .enumerate()
            .filter(|(peer_index, _)| *peer_index != validator_index)
            .map(|(_, peer_key)| {
                let name = hex(&peer_key.encode());
                crate::NamedBootstrapperEntry {
                    public_key: name.clone(),
                    name,
                }
            })
            .collect();

        let config = ValidatorConfig {
            private_key: hex(&material.signers[validator_index].encode()),
            dkg_output: hex(&material.dkg_output.encode()),
            dkg_share: hex(&share.encode()),
            listen_port: remote.listen_port,
            genesis_leader: material.genesis_leader.clone(),
            partition_prefix: format!("validator-{index}"),
            num_validators: args.validators,
            log_level: args.log_level.clone(),
            worker_threads: args.worker_threads,
            http_port: remote.http_port,
            max_propose_bytes: default_max_propose_bytes(),
            max_pool_bytes: default_max_pool_bytes(),
            bootstrappers,
        };

        validators.push(GeneratedValidator {
            public_key_hex: public_key_hex.clone(),
            config_file: output_dir.join(format!("{public_key_hex}.yaml")),
            config,
        });
    }

    validators
}

fn build_spammer_deployment(
    args: &GenerateArgs,
    remote: &RemoteArgs,
    output_dir: &Path,
) -> Option<SpammerDeployment> {
    if !crate::spammer_enabled(args) {
        return None;
    }

    let binary = absolute_path(
        remote
            .spammer_binary
            .as_ref()
            .expect("spammer_binary is required when enabling the spammer"),
    );

    Some(SpammerDeployment {
        instance: aws::InstanceConfig {
            name: SPAMMER_INSTANCE_NAME.to_string(),
            region: remote
                .spammer_region
                .clone()
                .unwrap_or_else(|| remote.regions[0].clone()),
            instance_type: remote
                .spammer_instance_type
                .clone()
                .unwrap_or_else(|| remote.instance_type.clone()),
            storage_size: remote.spammer_storage_size.unwrap_or(remote.storage_size),
            storage_class: STORAGE_CLASS.to_string(),
            binary: binary.display().to_string(),
            config: output_dir.join(SPAMMER_CONFIG_FILE).display().to_string(),
            profiling: false,
        },
    })
}

fn build_deployer_config(
    remote: &RemoteArgs,
    validator_binary: &Path,
    dashboard: &Path,
    validators: &[GeneratedValidator],
    spammer: Option<SpammerDeployment>,
) -> aws::Config {
    let mut instances = validators
        .iter()
        .enumerate()
        .map(|(index, validator)| aws::InstanceConfig {
            name: validator.public_key_hex.clone(),
            region: remote.regions[index % remote.regions.len()].clone(),
            instance_type: remote.instance_type.clone(),
            storage_size: remote.storage_size,
            storage_class: STORAGE_CLASS.to_string(),
            binary: validator_binary.display().to_string(),
            config: validator.config_file.display().to_string(),
            profiling: remote.profiling,
        })
        .collect::<Vec<_>>();

    if let Some(spammer) = spammer {
        instances.push(spammer.instance);
    }

    aws::Config {
        tag: generate_deployer_tag(),
        monitoring: aws::MonitoringConfig {
            instance_type: remote.monitoring_instance_type.clone(),
            storage_size: remote.monitoring_storage_size,
            storage_class: STORAGE_CLASS.to_string(),
            dashboard: dashboard.display().to_string(),
        },
        instances,
        ports: vec![
            aws::PortConfig {
                protocol: "tcp".to_string(),
                port: remote.listen_port,
                cidr: "0.0.0.0/0".to_string(),
            },
            aws::PortConfig {
                protocol: "tcp".to_string(),
                port: remote.http_port,
                cidr: "0.0.0.0/0".to_string(),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::{build_deployer_config, build_spammer_deployment};
    use crate::{
        GenerateArgs, GenerateTarget, LocalArgs, RemoteArgs, SPAMMER_INSTANCE_NAME, STORAGE_CLASS,
        ValidatorConfig, default_max_pool_bytes, default_max_propose_bytes,
    };
    use std::{
        num::{NonZeroU32, NonZeroUsize},
        path::PathBuf,
    };

    fn generate_args() -> GenerateArgs {
        GenerateArgs {
            validators: 3,
            output_dir: PathBuf::from("artifacts"),
            log_level: "info".to_string(),
            worker_threads: 2,
            spammer_count: Some(NonZeroUsize::new(64).unwrap()),
            spammer_tps: Some(NonZeroU32::new(10_000).unwrap()),
            spammer_seed_start: 7,
            spammer_nonce: 11,
            target: GenerateTarget::Local(LocalArgs {
                base_port: 9000,
                base_http_port: 8080,
            }),
        }
    }

    fn remote_args() -> RemoteArgs {
        RemoteArgs {
            validator_binary: PathBuf::from("validator"),
            regions: vec!["us-east-1".to_string(), "us-west-2".to_string()],
            instance_type: "c8g.large".to_string(),
            storage_size: 25,
            monitoring_instance_type: "c8g.2xlarge".to_string(),
            monitoring_storage_size: 100,
            dashboard: PathBuf::from("dashboard.json"),
            listen_port: 9000,
            http_port: 8080,
            profiling: true,
            spammer_binary: Some(PathBuf::from("constantinople-spammer")),
            spammer_region: Some("us-west-2".to_string()),
            spammer_instance_type: Some("c8g.xlarge".to_string()),
            spammer_storage_size: Some(50),
        }
    }

    fn validator(index: u32) -> super::GeneratedValidator {
        super::GeneratedValidator {
            public_key_hex: format!("validator-{index}"),
            config_file: PathBuf::from(format!("/tmp/validator-{index}.yaml")),
            config: ValidatorConfig {
                private_key: "private".to_string(),
                dkg_output: "output".to_string(),
                dkg_share: "share".to_string(),
                listen_port: 9000,
                genesis_leader: "leader".to_string(),
                partition_prefix: format!("validator-{index}"),
                num_validators: 3,
                log_level: "info".to_string(),
                worker_threads: 2,
                http_port: 8080,
                max_propose_bytes: default_max_propose_bytes(),
                max_pool_bytes: default_max_pool_bytes(),
                bootstrappers: Vec::new(),
            },
        }
    }

    #[test]
    fn remote_spammer_defaults_to_validator_shape() {
        let args = generate_args();
        let remote = remote_args();
        let spammer = build_spammer_deployment(&args, &remote, &PathBuf::from("/tmp/out")).unwrap();

        assert_eq!(spammer.instance.name, SPAMMER_INSTANCE_NAME);
        assert_eq!(spammer.instance.region, "us-west-2");
        assert_eq!(spammer.instance.instance_type, "c8g.xlarge");
        assert_eq!(spammer.instance.storage_size, 50);
    }

    #[test]
    fn remote_deployer_config_includes_spammer_when_present() {
        let args = generate_args();
        let remote = remote_args();
        let validators = vec![validator(0), validator(1), validator(2)];
        let spammer = build_spammer_deployment(&args, &remote, &PathBuf::from("/tmp/out"));

        let config = build_deployer_config(
            &remote,
            PathBuf::from("/tmp/validator").as_path(),
            PathBuf::from("/tmp/dashboard.json").as_path(),
            &validators,
            spammer,
        );

        assert!(!config.tag.is_empty());
        assert_eq!(config.instances.len(), args.validators as usize + 1);
        assert_eq!(config.instances[0].region, "us-east-1");
        assert_eq!(config.instances[1].region, "us-west-2");
        assert_eq!(config.instances[2].region, "us-east-1");
        assert_eq!(config.instances[3].name, SPAMMER_INSTANCE_NAME);
        assert_eq!(config.instances[0].storage_class, STORAGE_CLASS);
        assert_eq!(config.ports[0].port, 9000);
        assert_eq!(config.ports[1].port, 8080);
    }
}
