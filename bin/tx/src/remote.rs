use crate::spam;
use commonware_deployer::aws::Hosts;
use serde::Deserialize;
use std::{collections::HashMap, path::PathBuf};

#[derive(Debug, Deserialize)]
struct RemoteSpamConfig {
    count: usize,
    validator_names: Vec<String>,
    http_port: u16,
    #[serde(default)]
    seed_start: u64,
    #[serde(default)]
    nonce: u64,
    tps: u32,
}

pub(crate) fn load_args(hosts_path: PathBuf, config_path: PathBuf) -> Result<spam::Args, String> {
    let raw_hosts = std::fs::read_to_string(hosts_path)
        .map_err(|err| format!("failed to read hosts: {err}"))?;
    let hosts: Hosts =
        serde_yaml::from_str(&raw_hosts).map_err(|err| format!("failed to parse hosts: {err}"))?;
    let raw_config = std::fs::read_to_string(config_path)
        .map_err(|err| format!("failed to read config: {err}"))?;
    let config: RemoteSpamConfig =
        toml::from_str(&raw_config).map_err(|err| format!("failed to parse config: {err}"))?;

    let hosts_by_name = hosts
        .hosts
        .into_iter()
        .map(|host| (host.name, host.ip))
        .collect::<HashMap<_, _>>();

    let mut endpoints = Vec::with_capacity(config.validator_names.len());
    for name in &config.validator_names {
        let ip = hosts_by_name
            .get(name)
            .ok_or_else(|| format!("missing validator host '{name}'"))?;
        endpoints.push(format!("http://{ip}:{}", config.http_port));
    }

    spam::Args::new(
        config.count,
        endpoints,
        config.seed_start,
        config.nonce,
        config.tps,
    )
}

#[cfg(test)]
mod tests {
    use super::load_args;
    use std::{
        fs,
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
    fn load_args_uses_validator_order_from_config() {
        let hosts_path = temp_path("hosts", ".yaml");
        let config_path = temp_path("spam", ".toml");

        fs::write(
            &hosts_path,
            r#"monitoring: 10.0.0.1
hosts:
  - name: validator-b
    region: us-west-2
    ip: 203.0.113.2
  - name: validator-a
    region: us-east-1
    ip: 203.0.113.1
"#,
        )
        .expect("failed to write hosts");
        fs::write(
            &config_path,
            r#"count = 8
validator_names = ["validator-a", "validator-b"]
http_port = 8080
seed_start = 3
nonce = 9
tps = 100
"#,
        )
        .expect("failed to write config");

        let args = load_args(hosts_path.clone(), config_path.clone()).expect("config should parse");

        assert_eq!(
            args.endpoints(),
            &["http://203.0.113.1:8080", "http://203.0.113.2:8080"]
        );
        assert_eq!(args.count().get(), 8);
        assert_eq!(args.tps().get(), 100);
        assert_eq!(args.seed_start(), 3);
        assert_eq!(args.nonce(), 9);

        let _ = fs::remove_file(hosts_path);
        let _ = fs::remove_file(config_path);
    }
}
