use crate::{
    CHAIN_INDEXER_BINARY_FILE, CHAIN_INDEXER_DATA_DIR, ClusterMaterial, GenerateArgs,
    INDEXER_UPLOAD_BUFFER, IndexerConfig, LocalArgs, METADATA_INDEXER_BINARY_FILE,
    PEERS_CONFIG_FILE, PeerEntry, PeersConfig, QMDB_INDEXER_BINARY_FILE, RelayerConfig,
    RelayerLeaderConfig, SecondaryRole, ValidatorConfig, absolute_path, default_bootstrappers,
    ensure_output_dir_missing, generate_local_cluster_material, indexer_enabled, secondary_roles,
    total_secondaries, validate_generate_args, write_simplex_verification_material,
    write_yaml_config,
};
use commonware_codec::Encode;
use commonware_formatting::hex;
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
    validate_generate_args(args);

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
        &material.primary_hex(),
        &material.simplex_verification_material_hex(),
    );
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
            max_propose_bytes: args.max_propose_bytes,
            max_pool_bytes: args.max_pool_bytes,
            state_page_cache_bytes: args.state_page_cache_bytes,
            other_page_cache_bytes: args.other_page_cache_bytes,
            public_key_cache_size: args.public_key_cache_size,
            traces: 0.0,
            bootstrappers: bootstrappers.clone(),
            indexer: None,
            relayer: None,
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
    let roles = secondary_roles(args);
    let mut secondaries = Vec::with_capacity(roles.len());
    let bootstrappers = default_bootstrappers(&material.public_keys);
    let primary_validators = material.primary_hex();
    let secondary_validators = material.secondary_hex();
    // Secondary ports start after the primary range to avoid collisions on
    // the same loopback host.
    let primary_span = args.validators as u16;

    for (secondary_index, role) in roles.into_iter().enumerate() {
        let index = secondary_index as u32;
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
            max_propose_bytes: args.max_propose_bytes,
            max_pool_bytes: args.max_pool_bytes,
            state_page_cache_bytes: args.state_page_cache_bytes,
            other_page_cache_bytes: args.other_page_cache_bytes,
            public_key_cache_size: args.public_key_cache_size,
            traces: 0.0,
            bootstrappers: bootstrappers.clone(),
            indexer: matches!(role, SecondaryRole::Indexer)
                .then(|| local_indexer_config(local.chain_indexer_port)),
            relayer: matches!(role, SecondaryRole::Relayer)
                .then(|| local_relayer_config(local, material)),
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

fn local_relayer_config(local: &LocalArgs, material: &ClusterMaterial) -> RelayerConfig {
    let leaders = material
        .primary_hex()
        .into_iter()
        .enumerate()
        .map(|(index, public_key)| RelayerLeaderConfig {
            public_key,
            url: format!(
                "http://127.0.0.1:{}",
                local
                    .base_http_port
                    .checked_add(index as u16)
                    .expect("validator http port overflow")
            ),
        })
        .collect();

    RelayerConfig { leaders }
}

/// Build the full indexer wiring written into the owning secondary's YAML.
///
/// All rows go through the shared Store URL. Store prefixes
/// keep raw KV, SQL, and QMDB rows disjoint.
fn local_indexer_config(indexer_port: u16) -> IndexerConfig {
    let url = format!("http://127.0.0.1:{indexer_port}");
    IndexerConfig {
        store_url: url,
        api_key: None,
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
        let metrics_port = local_chain_indexer_metrics_port(args, local);
        let db_parallelism = local
            .chain_indexer_db_parallelism
            .map(|jobs| format!(" --db-parallelism {jobs}"))
            .unwrap_or_default();
        commands.push(format!(
            "cargo run --release -p constantinople-indexer --features chain-indexer --bin {} -- --port {} --metrics-port {} --data-dir {}{}",
            CHAIN_INDEXER_BINARY_FILE,
            local.chain_indexer_port,
            metrics_port,
            data_dir.display(),
            db_parallelism,
        ));
        // Adapters probe Store once at startup, but mprocs starts services together.
        let wait_for_store = format!(
            "until curl --fail --silent --output /dev/null --max-time 1 http://127.0.0.1:{}/ready; do sleep 1; done;",
            local.chain_indexer_port,
        );

        // `metadata-indexer` exposes Constantinople's `block_meta` and
        // `tx_meta` tables over `sql.v1.Service`. The explorer
        // subscribes to this service (not the raw store) for live block
        // metadata.
        commands.push(format!(
            "{wait_for_store} cargo run --release -p constantinople-indexer --bin {} -- \
             --store-url http://127.0.0.1:{} --port {}",
            METADATA_INDEXER_BINARY_FILE, local.chain_indexer_port, local.metadata_indexer_port,
        ));
        commands.push(format!(
            "{wait_for_store} cargo run --release -p constantinople-indexer --bin {} -- \
             --store-url http://127.0.0.1:{} --port {}",
            QMDB_INDEXER_BINARY_FILE, local.chain_indexer_port, local.qmdb_indexer_port,
        ));
        // Bring up the React explorer dev server alongside the metadata and
        // QMDB facades so operators get a live view and browser-verified
        // submitted-transaction proofs.
        // The defaults in `explorer/src/App.tsx` match these ports, but pass
        // both URLs explicitly so non-default deployer ports still work.
        let relayer_env = relayer_http_port(args, local)
            .map(|port| format!(" VITE_MEMPOOL_URL=http://127.0.0.1:{port}"))
            .unwrap_or_default();
        commands.push(format!(
            "VITE_SQL_URL=http://127.0.0.1:{} VITE_QMDB_URL=http://127.0.0.1:{} VITE_STORE_URL=http://127.0.0.1:{} VITE_SIMPLEX_VERIFICATION_MATERIAL={}{} npm --prefix explorer run dev",
            local.metadata_indexer_port,
            local.qmdb_indexer_port,
            local.chain_indexer_port,
            simplex_verification_material,
            relayer_env,
        ));
    }

    if args.spammer {
        let targets = relayer_targets.join(",");
        let relayer_port =
            relayer_http_port(args, local).expect("--spammer requires a relayer secondary");
        let seed_offset = args
            .spammer_seed_offset
            .map(|seed_offset| format!(" --seed-offset {seed_offset}"))
            .unwrap_or_default();
        let network_source = format!(
            "--relayer-url http://127.0.0.1:{} --relayer-submitters {} --relayer-targets {}",
            relayer_port,
            args.spammer_submitters.unwrap_or(args.validators as usize),
            targets,
        );

        // Place the spammer's metrics port past the primary and secondary ranges
        // so it does not collide with any validator on the loopback host.
        let metrics_port = local
            .base_metrics_port
            .checked_add(args.validators as u16 + total_secondaries as u16)
            .expect("spammer metrics port overflow");
        commands.push(format!(
            "cargo run --release --bin constantinople-spammer -- \
             {network_source} \
             --accounts {} \
             --value {}{} \
             --rayon-threads {} \
             --accounts-jitter {} \
             --presigned-batches {} \
             --metrics-port {metrics_port}",
            args.spammer_accounts,
            args.spammer_value,
            seed_offset,
            args.spammer_rayon_threads,
            args.spammer_accounts_jitter,
            args.spammer_presigned_batches,
        ));
    }

    commands
}

fn local_chain_indexer_metrics_port(args: &GenerateArgs, local: &LocalArgs) -> u16 {
    let validator_span = u16::try_from(args.validators).expect("validator count exceeds u16");
    let secondary_span =
        u16::try_from(total_secondaries(args)).expect("secondary count exceeds u16");
    let spammer_span = u16::from(args.spammer);
    let offset = validator_span
        .checked_add(secondary_span)
        .and_then(|offset| offset.checked_add(spammer_span))
        .expect("local metrics port offset overflow");
    local
        .base_metrics_port
        .checked_add(offset)
        .expect("chain-indexer metrics port overflow")
}

fn relayer_http_port(args: &GenerateArgs, local: &LocalArgs) -> Option<u16> {
    args.relayer.then(|| {
        let relayer_index = u16::from(args.indexer);
        local.base_http_port + args.validators as u16 + relayer_index
    })
}

#[cfg(test)]
mod tests {
    use super::{
        build_secondaries, build_validators, local_chain_indexer_metrics_port, local_run_commands,
    };
    use crate::{
        GenerateArgs, GenerateTarget, LocalArgs, StartupModeConfig, default_max_pool_bytes,
        default_max_propose_bytes, default_page_cache_bytes, default_public_key_cache_size,
        generate_local_cluster_material, total_secondaries,
    };
    use std::{
        fs,
        io::{BufRead, BufReader, ErrorKind, Write},
        net::{TcpListener, TcpStream},
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    use tempfile::TempDir;

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
            spammer_seed_offset: None,
            spammer_rayon_threads: crate::DEFAULT_SPAMMER_RAYON_THREADS,
            spammer_accounts_jitter: 0.0,
            spammer_submitters: None,
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
        assert!(commands[3].contains("--accounts 10"));
        assert!(commands[3].contains("--value 1"));
        assert!(!commands[3].contains("--seed-offset"));
        assert!(commands[3].contains("--rayon-threads 2"));
        assert!(commands[3].contains("--accounts-jitter 0"));
    }

    #[test]
    fn local_spammer_submitters_override_validator_count() {
        let mut args = test_args(true);
        args.relayer = true;
        args.spammer_submitters = Some(50);
        let commands = local_run_commands(
            Path::new("/tmp/configs"),
            &args,
            local_args(&args),
            &[],
            TEST_SIMPLEX_VERIFICATION_MATERIAL,
        );

        let spammer = commands
            .iter()
            .find(|command| command.contains("constantinople-spammer"))
            .expect("spammer command should be present");
        assert!(spammer.contains("--relayer-submitters 50"));
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
    fn local_run_commands_propagate_deterministic_seed_offset() {
        let mut args = test_args(true);
        args.relayer = true;
        args.spammer_seed_offset = Some(2000);
        let commands = local_run_commands(
            Path::new("/tmp/configs"),
            &args,
            local_args(&args),
            &[],
            TEST_SIMPLEX_VERIFICATION_MATERIAL,
        );

        assert!(commands[3].contains("--seed-offset 2000"));
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

    #[test]
    fn local_adapters_wait_for_store_readiness() {
        for binary in ["metadata-indexer", "qmdb-indexer"] {
            let listener = readiness_listener();
            let port = listener.local_addr().expect("Store address").port();
            let command = local_adapter_command(binary, port);
            let launcher = TestLauncher::spawn(&command);

            let probe = accept_readiness_probe(&listener);
            launcher.assert_not_started();
            respond_to_probe(probe, "503 Service Unavailable");

            let retry = accept_readiness_probe(&listener);
            launcher.assert_not_started();
            respond_to_probe(retry, "200 OK");

            let arguments = launcher.finish();
            assert!(
                arguments.contains(&format!("--bin\n{binary}\n")),
                "{arguments}"
            );
            assert!(
                arguments.contains(&format!("--store-url\nhttp://127.0.0.1:{port}\n")),
                "{arguments}"
            );
        }
    }

    fn local_adapter_command(binary: &str, store_port: u16) -> String {
        let mut args = test_args(false);
        args.indexer = true;
        set_local_ports(&mut args, store_port, 8091, 8092);
        local_run_commands(
            Path::new("/tmp/configs"),
            &args,
            local_args(&args),
            &[],
            TEST_SIMPLEX_VERIFICATION_MATERIAL,
        )
        .into_iter()
        .find(|command| command.contains(&format!("--bin {binary}")))
        .expect("adapter command")
    }

    fn readiness_listener() -> TcpListener {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Store listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        listener
    }

    fn accept_readiness_probe(listener: &TcpListener) -> TcpStream {
        let deadline = Instant::now() + Duration::from_secs(10);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "launcher did not probe Store readiness"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("Store accept failed: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("probe timeout");
        let mut request = BufReader::new(&mut stream);
        let mut line = String::new();
        request.read_line(&mut line).expect("request line");
        assert_eq!(line, "GET /ready HTTP/1.1\r\n");
        loop {
            line.clear();
            request.read_line(&mut line).expect("request header");
            if line == "\r\n" || line.is_empty() {
                break;
            }
        }
        stream
    }

    fn respond_to_probe(mut stream: TcpStream, status: &str) {
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("readiness response");
    }

    struct TestLauncher {
        child: Child,
        directory: TempDir,
    }

    impl TestLauncher {
        fn spawn(command: &str) -> Self {
            let directory = tempfile::tempdir().expect("launcher directory");

            // Record Cargo invocation without compiling or starting an adapter.
            let child = Command::new("sh")
                .args([
                    "-c",
                    &format!(
                        "cargo() {{ printf '%s\\n' \"$@\" > \"$TEST_ADAPTER_CARGO_ARGS\"; }}; {command}"
                    ),
                ])
                .env("TEST_ADAPTER_CARGO_ARGS", directory.path().join("cargo-args"))
                .stdin(Stdio::null())
                .spawn()
                .expect("local launcher");
            Self { child, directory }
        }

        fn assert_not_started(&self) {
            assert!(
                !self.directory.path().join("cargo-args").exists(),
                "Cargo ran before Store was ready"
            );
        }

        fn finish(mut self) -> String {
            let deadline = Instant::now() + Duration::from_secs(10);
            let status = loop {
                if let Some(status) = self.child.try_wait().expect("launcher status") {
                    break status;
                }
                assert!(
                    Instant::now() < deadline,
                    "launcher did not exit after Store became ready"
                );
                thread::sleep(Duration::from_millis(10));
            };
            assert!(status.success(), "launcher failed: {status}");
            fs::read_to_string(self.directory.path().join("cargo-args"))
                .expect("Cargo should run after Store becomes ready")
        }
    }

    impl Drop for TestLauncher {
        fn drop(&mut self) {
            // Failed assertions must not leave the polling shell running.
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
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
        assert!(indexer_cmd.contains("--features chain-indexer"));
        assert!(indexer_cmd.contains("--port 8090"));
        assert!(indexer_cmd.contains("--metrics-port 9094"));
        assert!(indexer_cmd.contains("--data-dir /tmp/configs/chain-indexer"));
    }

    #[test]
    fn local_indexer_metrics_port_follows_enabled_services() {
        for (validators, relayer, spammer, base_port, expected_port) in [
            (4, true, true, 9090, 9097),
            (2, false, false, 12000, 12003),
            (4, true, false, 12000, 12006),
        ] {
            let mut args = test_args(spammer);
            args.validators = validators;
            args.indexer = true;
            args.relayer = relayer;
            let GenerateTarget::Local(local) = &mut args.target else {
                panic!("test_args must construct a Local target");
            };
            local.base_metrics_port = base_port;
            let commands = local_run_commands(
                Path::new("/tmp/configs"),
                &args,
                local_args(&args),
                &[],
                TEST_SIMPLEX_VERIFICATION_MATERIAL,
            );
            let indexer_cmd = commands
                .iter()
                .find(|command| command.contains("--bin chain-indexer"))
                .expect("chain-indexer command should be present");

            assert!(indexer_cmd.contains(&format!("--metrics-port {expected_port}")));
        }
    }

    #[test]
    #[should_panic(expected = "chain-indexer metrics port overflow")]
    fn local_indexer_metrics_port_rejects_overflow() {
        let mut args = test_args(false);
        args.indexer = true;
        let mut local = test_local_args();
        local.base_metrics_port = u16::MAX;

        local_chain_indexer_metrics_port(&args, &local);
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
        assert!(explorer_cmd.contains("run dev"));
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

        // Secondaries point at the configured shared store URL.
        let indexer = secondaries[0]
            .config
            .indexer
            .as_ref()
            .expect("secondary should have indexer config");
        assert_eq!(indexer.upload_buffer, 64);
        let expected_url = "http://127.0.0.1:8090".to_string();
        assert_eq!(indexer.store_url, expected_url);
        assert_eq!(indexer.api_key, None);
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
