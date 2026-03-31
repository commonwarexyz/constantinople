//! `setup` subcommand — generates validator config files.

use crate::{
    cli::SetupArgs,
    config::{
        BootstrapperEntry, GenesisAllocation, GenesisFile, ValidatorConfig, default_max_pool_bytes,
        default_max_propose_bytes,
    },
};
use commonware_codec::Encode;
use commonware_cryptography::{
    Signer,
    bls12381::{dkg, primitives::variant::MinSig},
    ed25519,
};
use commonware_runtime::{
    Metrics as _, Runner as _,
    tokio::{
        Config as RuntimeConfig, Runner,
        telemetry::{self, Logging},
    },
};
use commonware_utils::{N3f1, TryCollect, hex};
use std::collections::BTreeMap;
use tracing::info;

pub fn setup(args: SetupArgs) {
    let runner = Runner::new(RuntimeConfig::new().with_worker_threads(args.worker_threads));

    runner.start(|context| async move {
        telemetry::init(
            context.with_label("telemetry"),
            Logging {
                level: args.log_level,
                json: false,
            },
            None,
            None,
        );

        assert!(args.validators >= 1, "need at least one validator");

        let genesis_allocations: Vec<GenesisAllocation> = match &args.genesis {
            Some(path) => {
                let raw = tokio::fs::read_to_string(path)
                    .await
                    .expect("failed to read genesis file");
                let parsed: GenesisFile =
                    toml::from_str(&raw).expect("failed to parse genesis file");
                parsed.allocations
            }
            None => Vec::new(),
        };
        tokio::fs::create_dir_all(&args.output_dir)
            .await
            .expect("failed to create output directory");

        // Generate keys.
        let signers: Vec<ed25519::PrivateKey> = (0..args.validators)
            .map(|i| ed25519::PrivateKey::from_seed(i.into()))
            .collect();
        let public_keys: Vec<ed25519::PublicKey> = signers.iter().map(Signer::public_key).collect();

        // Run DKG.
        let participants = public_keys.clone().into_iter().try_collect().unwrap();
        let mut rng = commonware_utils::test_rng();
        let (output, raw_shares) =
            dkg::deal::<MinSig, _, N3f1>(&mut rng, Default::default(), participants)
                .expect("DKG deal failed");
        let shares: BTreeMap<_, _> = raw_shares.into_iter().collect();

        let genesis_leader = hex(&public_keys[0].encode());

        for i in 0..args.validators {
            let idx = i as usize;
            let signer = &signers[idx];
            let pk = &public_keys[idx];
            let share = shares.get(pk).expect("missing share for validator");
            let listen = format!(
                "127.0.0.1:{}",
                args.base_port.checked_add(i as u16).expect("port overflow")
            );

            let bootstrappers: Vec<BootstrapperEntry> = public_keys
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != idx)
                .map(|(j, peer_pk)| BootstrapperEntry {
                    public_key: hex(&peer_pk.encode()),
                    address: format!(
                        "127.0.0.1:{}",
                        args.base_port.checked_add(j as u16).expect("port overflow")
                    ),
                })
                .collect();

            let config = ValidatorConfig {
                private_key: hex(&signer.encode()),
                dkg_output: hex(&output.encode()),
                dkg_share: hex(&share.encode()),
                listen,
                genesis_leader: genesis_leader.clone(),
                partition_prefix: format!("validator-{i}"),
                num_validators: args.validators,
                log_level: args.log_level.to_string(),
                worker_threads: args.worker_threads,
                http_port: args
                    .base_http_port
                    .checked_add(i as u16)
                    .expect("HTTP port overflow"),
                max_propose_bytes: default_max_propose_bytes(),
                max_pool_bytes: default_max_pool_bytes(),
                bootstrappers,
                genesis_allocations: genesis_allocations.clone(),
            };

            let path = args.output_dir.join(format!("validator-{i}.toml"));
            let toml = toml::to_string_pretty(&config).expect("failed to serialize config");
            tokio::fs::write(&path, toml)
                .await
                .expect("failed to write config file");
            info!(path = %path.display(), public_key = %hex(&pk.encode()), "wrote config");
        }

        info!(count = args.validators, "setup complete");

        // Print an mprocs command to run all validators.
        let cmds: Vec<String> = (0..args.validators)
            .map(|i| {
                let path = args.output_dir.join(format!("validator-{i}.toml"));
                format!(
                    "cargo run --bin constantinople -- run --config {}",
                    path.display()
                )
            })
            .collect();
        let mprocs = cmds
            .iter()
            .map(|c| format!("\"{}\"", c))
            .collect::<Vec<_>>()
            .join(" ");
        println!("\nmprocs {mprocs}");
    });
}
