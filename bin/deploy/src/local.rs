use crate::{
    ClusterMaterial, GenerateArgs, LocalArgs, PEERS_CONFIG_FILE, PeerEntry, PeersConfig,
    ValidatorConfig, absolute_path, default_bootstrappers, default_max_pool_bytes,
    default_max_propose_bytes, ensure_output_dir_missing, generate_local_cluster_material,
    write_yaml_config,
};
use commonware_codec::Encode;
use commonware_utils::hex;
use std::{
    fs,
    path::{Path, PathBuf},
};
use tracing::info;

struct GeneratedValidator {
    config_file: PathBuf,
    config: ValidatorConfig,
    peer: PeerEntry,
}

pub(super) fn generate(args: &GenerateArgs, local: &LocalArgs) {
    assert!(args.validators >= 1, "need at least one validator");

    let output_dir = absolute_path(&args.output_dir);
    ensure_output_dir_missing(&output_dir);

    let material = generate_local_cluster_material(args.validators);
    let validators = build_validators(args, local, &output_dir, &material);
    let peers = PeersConfig {
        validators: validators
            .iter()
            .map(|validator| validator.peer.clone())
            .collect(),
    };

    fs::create_dir_all(&output_dir).expect("failed to create output directory");
    for validator in &validators {
        write_yaml_config(&validator.config_file, &validator.config);
    }
    write_yaml_config(&output_dir.join(PEERS_CONFIG_FILE), &peers);

    print_local_run_commands(&output_dir, args);
}

fn build_validators(
    args: &GenerateArgs,
    local: &LocalArgs,
    output_dir: &std::path::Path,
    material: &ClusterMaterial,
) -> Vec<GeneratedValidator> {
    let mut validators = Vec::with_capacity(args.validators as usize);

    let bootstrappers = default_bootstrappers(&material.public_keys);

    for index in 0..args.validators {
        let validator_index = index as usize;
        let public_key = &material.public_keys[validator_index];
        let public_key_hex = hex(&public_key.encode());
        let share = material
            .shares
            .get(public_key)
            .expect("missing share for validator");
        let listen_port = local
            .base_port
            .checked_add(index as u16)
            .expect("listen port overflow");
        let http_port = local
            .base_http_port
            .checked_add(index as u16)
            .expect("http port overflow");
        let metrics_port = local
            .base_metrics_port
            .checked_add(index as u16)
            .expect("metrics port overflow");

        let config = ValidatorConfig {
            private_key: hex(&material.signers[validator_index].encode()),
            dkg_output: hex(&material.dkg_output.encode()),
            dkg_share: hex(&share.encode()),
            startup: args.startup,
            listen_port,
            genesis_leader: material.genesis_leader.clone(),
            partition_prefix: format!("validator-{index}"),
            num_validators: args.validators,
            log_level: args.log_level.clone(),
            worker_threads: args.worker_threads,
            rayon_threads: args.rayon_threads,
            http_port,
            metrics_port,
            max_propose_bytes: default_max_propose_bytes(),
            max_pool_bytes: default_max_pool_bytes(),
            bootstrappers: bootstrappers.clone(),
        };

        validators.push(GeneratedValidator {
            config_file: output_dir.join(format!("validator-{index}.yaml")),
            config,
            peer: PeerEntry {
                name: public_key_hex,
                p2p: format!("127.0.0.1:{listen_port}"),
                http: format!("127.0.0.1:{http_port}"),
            },
        });
    }

    validators
}

fn print_local_run_commands(output_dir: &Path, args: &GenerateArgs) {
    let commands = local_run_commands(output_dir, args);
    let mprocs = commands
        .iter()
        .map(|command| format!("\"{command}\""))
        .collect::<Vec<_>>()
        .join(" ");

    info!(output_dir = %output_dir.display(), validators = args.validators, "generated local deployment bundle");
    info!(command = %format!("mprocs {mprocs}"), "start local deployment");
}

fn local_run_commands(output_dir: &Path, args: &GenerateArgs) -> Vec<String> {
    let peers_path = output_dir.join(PEERS_CONFIG_FILE);
    let mut commands: Vec<String> = (0..args.validators)
        .map(|index| {
            let path = output_dir.join(format!("validator-{index}.yaml"));
            format!(
                "cargo run --bin constantinople -- --config {} --peers {}",
                path.display(),
                peers_path.display()
            )
        })
        .collect();

    if args.spammer {
        commands.push(format!(
            "sleep 10 && cargo run --release --bin constantinople-spammer -- \
             --peers {} \
             --accounts {} \
             --value {} \
             --seed-offset {}",
            peers_path.display(),
            args.spammer_accounts,
            args.spammer_value,
            args.spammer_seed_offset,
        ));
    }

    commands
}

#[cfg(test)]
mod tests {
    use super::local_run_commands;
    use crate::{GenerateArgs, GenerateTarget, LocalArgs, StartupModeConfig};
    use std::path::{Path, PathBuf};

    fn test_args(spammer: bool) -> GenerateArgs {
        GenerateArgs {
            validators: 2,
            output_dir: PathBuf::from("/tmp/configs"),
            log_level: "info".to_string(),
            worker_threads: 2,
            rayon_threads: 2,
            startup: StartupModeConfig::MarshalSync,
            spammer,
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

    #[test]
    fn local_run_commands_only_start_validators() {
        let args = test_args(false);
        let commands = local_run_commands(Path::new("/tmp/configs"), &args);

        assert_eq!(commands.len(), 2);
        assert!(commands.iter().all(|command| !command.contains("spammer")));
    }

    #[test]
    fn local_run_commands_include_spammer_when_enabled() {
        let args = test_args(true);
        let commands = local_run_commands(Path::new("/tmp/configs"), &args);

        assert_eq!(commands.len(), 3);
        assert!(commands[2].contains("constantinople-spammer"));
        assert!(commands[2].contains("--peers"));
        assert!(commands[2].contains("--accounts 10"));
        assert!(commands[2].contains("--value 1"));
        assert!(commands[2].contains("--seed-offset 1000"));
    }

    #[test]
    fn startup_mode_defaults_to_marshal_sync() {
        assert_eq!(StartupModeConfig::default(), StartupModeConfig::MarshalSync);
    }
}
