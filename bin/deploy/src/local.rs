use crate::{
    ClusterMaterial, GenerateArgs, IndexerConfig, LocalArgs, PEERS_CONFIG_FILE, PeerEntry,
    PeersConfig, ValidatorConfig, absolute_path, default_bootstrappers, default_max_pool_bytes,
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
    if local.indexer {
        assert!(
            args.secondaries >= 1,
            "--indexer requires at least one secondary; only secondaries upload",
        );
    }

    let output_dir = absolute_path(&args.output_dir);
    ensure_output_dir_missing(&output_dir);

    let material = generate_local_cluster_material(args.validators, args.secondaries);
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

    print_local_run_commands(&output_dir, args, local);
}

fn build_validators(
    args: &GenerateArgs,
    local: &LocalArgs,
    output_dir: &std::path::Path,
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
            primary_validators: primary_validators.clone(),
            secondary_validators: secondary_validators.clone(),
            log_level: args.log_level.clone(),
            worker_threads: args.worker_threads,
            rayon_threads: args.rayon_threads,
            http_port,
            metrics_port,
            max_propose_bytes: default_max_propose_bytes(),
            max_pool_bytes: default_max_pool_bytes(),
            bootstrappers: bootstrappers.clone(),
            indexer: None,
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

fn build_secondaries(
    args: &GenerateArgs,
    local: &LocalArgs,
    output_dir: &std::path::Path,
    material: &ClusterMaterial,
) -> Vec<GeneratedValidator> {
    let mut secondaries = Vec::with_capacity(args.secondaries as usize);
    let bootstrappers = default_bootstrappers(&material.public_keys);
    let primary_validators = material.primary_hex();
    let secondary_validators = material.secondary_hex();
    let indexer_config = local
        .indexer
        .then(|| local_indexer_config(local.indexer_port));

    // Secondary ports start after the primary range to avoid collisions on
    // the same loopback host.
    let primary_span = args.validators as u16;

    for index in 0..args.secondaries {
        let secondary_index = index as usize;
        let public_key = &material.secondary_public_keys[secondary_index];
        let public_key_hex = hex(&public_key.encode());
        let offset = primary_span
            .checked_add(index as u16)
            .expect("secondary port offset overflow");
        let listen_port = local
            .base_port
            .checked_add(offset)
            .expect("secondary listen port overflow");
        let http_port = local
            .base_http_port
            .checked_add(offset)
            .expect("secondary http port overflow");
        let metrics_port = local
            .base_metrics_port
            .checked_add(offset)
            .expect("secondary metrics port overflow");

        let config = ValidatorConfig {
            private_key: hex(&material.secondary_signers[secondary_index].encode()),
            dkg_output: hex(&material.dkg_output.encode()),
            dkg_share: String::new(),
            startup: args.startup,
            listen_port,
            genesis_leader: material.genesis_leader.clone(),
            partition_prefix: format!("secondary-{index}"),
            num_validators: args.validators,
            primary_validators: primary_validators.clone(),
            secondary_validators: secondary_validators.clone(),
            log_level: args.log_level.clone(),
            worker_threads: args.worker_threads,
            rayon_threads: args.rayon_threads,
            http_port,
            metrics_port,
            max_propose_bytes: default_max_propose_bytes(),
            max_pool_bytes: default_max_pool_bytes(),
            bootstrappers: bootstrappers.clone(),
            indexer: indexer_config.clone(),
        };

        secondaries.push(GeneratedValidator {
            config_file: output_dir.join(format!("secondary-{index}.yaml")),
            config,
            peer: PeerEntry {
                name: public_key_hex,
                p2p: format!("127.0.0.1:{listen_port}"),
                http: format!("127.0.0.1:{http_port}"),
            },
        });
    }

    secondaries
}

/// Build the indexer wiring written into every secondary's YAML when the
/// local deploy is started with `--indexer`. All three URLs point at the same
/// simulator; routing-by-family in the indexer client keeps writes correct
/// because key prefixes are disjoint (KV families occupy `0x10..=0x6F`, SQL
/// table prefixes occupy `0x00..=0x0F`). Splitting the simulator into
/// physically separate stores is deferred until we need it.
fn local_indexer_config(indexer_port: u16) -> IndexerConfig {
    let url = format!("http://127.0.0.1:{indexer_port}");
    IndexerConfig {
        enabled: true,
        blocks_url: url.clone(),
        transactions_url: url.clone(),
        sql_url: url,
        upload_buffer: 1024,
    }
}

fn print_local_run_commands(output_dir: &Path, args: &GenerateArgs, local: &LocalArgs) {
    let commands = local_run_commands(output_dir, args, local);
    let mprocs = commands
        .iter()
        .map(|command| format!("\"{command}\""))
        .collect::<Vec<_>>()
        .join(" ");

    info!(
        output_dir = %output_dir.display(),
        validators = args.validators,
        secondaries = args.secondaries,
        "generated local deployment bundle"
    );
    info!(command = %format!("mprocs {mprocs}"), "start local deployment");
}

fn local_run_commands(output_dir: &Path, args: &GenerateArgs, local: &LocalArgs) -> Vec<String> {
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

    for index in 0..args.secondaries {
        let path = output_dir.join(format!("secondary-{index}.yaml"));
        commands.push(format!(
            "cargo run --bin constantinople -- --config {} --peers {}",
            path.display(),
            peers_path.display()
        ));
    }

    if local.indexer {
        let data_dir = output_dir.join("indexer-data");
        commands.push(format!(
            "cargo run -p constantinople-indexer --bin indexer -- --port {} --data-dir {}",
            local.indexer_port,
            data_dir.display(),
        ));
        // SQL server: exposes Constantinople's `block_meta` / `tx_meta`
        // tables over `store.sql.v1.Service`. The explorer subscribes to
        // this server (NOT the raw exoware simulator) for live block
        // metadata. Sleep briefly so the simulator has bound its port
        // first; otherwise the SQL server's first GET races the bind.
        commands.push(format!(
            "sleep 2 && cargo run -p constantinople-indexer --bin sql -- \
             run --store-url http://127.0.0.1:{} --port {}",
            local.indexer_port, local.sql_port,
        ));
        // Bring up the React explorer dev server alongside the SQL server
        // so operators get a live view of streaming blocks for free.
        // `VITE_SQL_URL` is consumed by `explorer/src/App.tsx`; the
        // default there matches `--sql-port`, but we pass it explicitly
        // so a non-default port still works. The KV indexer URL is
        // intentionally NOT forwarded — the explorer only consumes the
        // SQL metadata path today.
        commands.push(format!(
            "VITE_SQL_URL=http://127.0.0.1:{} npm --prefix explorer run dev",
            local.sql_port,
        ));
    }

    if args.spammer {
        commands.push(format!(
            "sleep 10 && cargo run --release --bin constantinople-spammer -- \
             --peers {} \
             --accounts {} \
             --value {} \
             --seed-offset {} \
             --rounds-jitter {}",
            peers_path.display(),
            args.spammer_accounts,
            args.spammer_value,
            args.spammer_seed_offset,
            args.spammer_rounds_jitter,
        ));
    }

    commands
}

#[cfg(test)]
mod tests {
    use super::{build_secondaries, build_validators, local_run_commands};
    use crate::{
        GenerateArgs, GenerateTarget, LocalArgs, StartupModeConfig, generate_local_cluster_material,
    };
    use std::path::{Path, PathBuf};

    fn test_args(spammer: bool) -> GenerateArgs {
        GenerateArgs {
            validators: 2,
            secondaries: 0,
            output_dir: PathBuf::from("/tmp/configs"),
            log_level: "info".to_string(),
            worker_threads: 2,
            rayon_threads: 2,
            startup: StartupModeConfig::MarshalSync,
            spammer,
            spammer_accounts: 10,
            spammer_value: 1,
            spammer_seed_offset: 1000,
            spammer_rounds_jitter: 1,
            target: GenerateTarget::Local(test_local_args()),
        }
    }

    fn test_local_args() -> LocalArgs {
        LocalArgs {
            base_port: 9000,
            base_http_port: 8080,
            base_metrics_port: 9090,
            indexer: false,
            indexer_port: 8090,
            sql_port: 8091,
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

    #[test]
    fn local_run_commands_only_start_validators() {
        let args = test_args(false);
        let commands = local_run_commands(Path::new("/tmp/configs"), &args, local_args(&args));

        assert_eq!(commands.len(), 2);
        assert!(commands.iter().all(|command| !command.contains("spammer")));
    }

    #[test]
    fn local_run_commands_include_spammer_when_enabled() {
        let args = test_args(true);
        let commands = local_run_commands(Path::new("/tmp/configs"), &args, local_args(&args));

        assert_eq!(commands.len(), 3);
        assert!(commands[2].contains("constantinople-spammer"));
        assert!(commands[2].contains("--peers"));
        assert!(commands[2].contains("--accounts 10"));
        assert!(commands[2].contains("--value 1"));
        assert!(commands[2].contains("--seed-offset 1000"));
        assert!(commands[2].contains("--rounds-jitter 1"));
    }

    #[test]
    fn local_run_commands_propagate_rounds_jitter_to_spammer() {
        let mut args = test_args(true);
        args.spammer_rounds_jitter = 4;
        let commands = local_run_commands(Path::new("/tmp/configs"), &args, local_args(&args));

        assert!(commands[2].contains("--rounds-jitter 4"));
    }

    #[test]
    fn local_run_commands_include_secondaries() {
        let mut args = test_args(false);
        args.secondaries = 2;
        let commands = local_run_commands(Path::new("/tmp/configs"), &args, local_args(&args));

        assert_eq!(commands.len(), 4);
        assert!(commands[2].contains("secondary-0.yaml"));
        assert!(commands[3].contains("secondary-1.yaml"));
    }

    /// Mutate the [`LocalArgs`] embedded in the test [`GenerateArgs`] in a
    /// short-lived scope so the test can immutably re-borrow it later.
    fn enable_indexer(args: &mut GenerateArgs, port: u16) {
        let GenerateTarget::Local(ref mut local) = args.target else {
            panic!("test_args must construct a Local target");
        };
        local.indexer = true;
        local.indexer_port = port;
    }

    #[test]
    fn local_run_commands_include_indexer_when_enabled() {
        let mut args = test_args(false);
        args.secondaries = 1;
        enable_indexer(&mut args, 8090);

        let commands = local_run_commands(Path::new("/tmp/configs"), &args, local_args(&args));

        // 2 validators + 1 secondary + 1 indexer + 1 sql + 1 explorer = 6.
        assert_eq!(commands.len(), 6);
        let indexer_cmd = commands
            .iter()
            .find(|c| c.contains("--bin indexer"))
            .expect("indexer command should be present");
        assert!(indexer_cmd.contains("--port 8090"));
        assert!(indexer_cmd.contains("--data-dir /tmp/configs/indexer-data"));
    }

    #[test]
    fn local_run_commands_include_sql_server_when_indexer_enabled() {
        let mut args = test_args(false);
        args.secondaries = 1;
        enable_indexer(&mut args, 8090);

        let commands = local_run_commands(Path::new("/tmp/configs"), &args, local_args(&args));

        let sql_cmd = commands
            .iter()
            .find(|c| c.contains("--bin sql"))
            .expect("sql server command should be present");
        // The SQL server reads from the simulator and serves on its own port.
        assert!(sql_cmd.contains("--store-url http://127.0.0.1:8090"));
        assert!(sql_cmd.contains("--port 8091"));
    }

    #[test]
    fn local_run_commands_include_explorer_when_indexer_enabled() {
        let mut args = test_args(false);
        args.secondaries = 1;
        enable_indexer(&mut args, 8090);

        let commands = local_run_commands(Path::new("/tmp/configs"), &args, local_args(&args));

        let explorer_cmd = commands
            .iter()
            .find(|c| c.contains("npm --prefix explorer"))
            .expect("explorer dev server command should be present");
        // Explorer is wired to the SQL server only — the KV indexer URL
        // is intentionally not forwarded because the UI doesn't read it.
        assert!(explorer_cmd.contains("VITE_SQL_URL=http://127.0.0.1:8091"));
        assert!(!explorer_cmd.contains("VITE_INDEXER_URL"));
        assert!(explorer_cmd.contains("run dev"));
    }

    #[test]
    fn local_run_commands_omit_explorer_when_indexer_disabled() {
        // No `enable_indexer`; the explorer must stay out of the mprocs list.
        let mut args = test_args(false);
        args.secondaries = 1;

        let commands = local_run_commands(Path::new("/tmp/configs"), &args, local_args(&args));

        assert!(
            commands
                .iter()
                .all(|c| !c.contains("npm --prefix explorer")),
            "explorer must only launch when --indexer is enabled: {commands:?}"
        );
    }

    #[test]
    fn secondary_yaml_gets_indexer_when_enabled() {
        let mut args = test_args(false);
        args.secondaries = 1;
        enable_indexer(&mut args, 8090);

        let material = generate_local_cluster_material(args.validators, args.secondaries);
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

        // Secondaries point at the configured simulator URL on every URL field.
        let indexer = secondaries[0]
            .config
            .indexer
            .as_ref()
            .expect("secondary should have indexer config");
        assert!(indexer.enabled);
        let expected_url = "http://127.0.0.1:8090".to_string();
        assert_eq!(indexer.blocks_url, expected_url);
        assert_eq!(indexer.transactions_url, expected_url);
        assert_eq!(indexer.sql_url, expected_url);
    }

    #[test]
    fn secondary_yaml_has_no_indexer_when_disabled() {
        let mut args = test_args(false);
        args.secondaries = 1;

        let material = generate_local_cluster_material(args.validators, args.secondaries);
        let secondaries = build_secondaries(
            &args,
            local_args(&args),
            Path::new("/tmp/configs"),
            &material,
        );

        assert!(secondaries[0].config.indexer.is_none());
    }

    #[test]
    #[should_panic(expected = "--indexer requires at least one secondary")]
    fn indexer_requires_at_least_one_secondary() {
        let mut args = test_args(false);
        args.secondaries = 0;
        // Use a unique nonexistent output dir so `ensure_output_dir_missing`
        // does not fire before our intended assertion.
        args.output_dir = PathBuf::from("/tmp/constantinople-deploy-test-indexer-no-secondaries");
        enable_indexer(&mut args, 8090);

        super::generate(&args, local_args(&args));
    }

    #[test]
    fn startup_mode_defaults_to_marshal_sync() {
        assert_eq!(StartupModeConfig::default(), StartupModeConfig::MarshalSync);
    }
}
