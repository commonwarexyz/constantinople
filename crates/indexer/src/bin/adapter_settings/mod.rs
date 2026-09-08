use ahash::AHashMap;
use clap::Args;
use commonware_deployer::aws::Hosts;
use serde::Deserialize;
use std::{
    fs, io,
    net::IpAddr,
    num::ParseIntError,
    path::{Path, PathBuf},
};
use thiserror::Error;

const STORE_URL_ENV: &str = "CONSTANTINOPLE_STORE_URL";
const PORT_ENV: &str = "CONSTANTINOPLE_PORT";

#[derive(Clone, Copy)]
pub(crate) struct Profile {
    pub(crate) name: &'static str,
    pub(crate) default_port: u16,
}

#[derive(Args, Debug)]
pub(crate) struct AdapterArgs {
    /// URL of the exoware Store to read from.
    #[arg(long)]
    store_url: Option<String>,
    /// Bind address.
    #[arg(long, default_value = "0.0.0.0")]
    host: IpAddr,
    /// Listen port.
    #[arg(long)]
    port: Option<u16>,
    /// Path to the deployer-generated hosts file.
    #[arg(long, requires = "config")]
    hosts: Option<PathBuf>,
    /// Path to the deployer-provided adapter config YAML.
    #[arg(long, requires = "hosts")]
    config: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct DeployerConfig {
    port: u16,
    chain_indexer_url: String,
    #[serde(default)]
    api_key: Option<String>,
}

#[derive(Debug)]
struct DeployerSettings {
    store_url: String,
    port: u16,
    api_key: Option<String>,
}

#[derive(Debug)]
pub(crate) struct Settings {
    pub(crate) store_url: String,
    pub(crate) host: IpAddr,
    pub(crate) port: u16,
    pub(crate) api_key: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct Environment {
    store_url: Option<String>,
    port: Option<String>,
}

impl Environment {
    pub(crate) fn read() -> Self {
        Self {
            store_url: std::env::var(STORE_URL_ENV).ok(),
            port: std::env::var(PORT_ENV).ok(),
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum SettingsError {
    #[error("deployer mode requires both --hosts and --config")]
    IncompleteDeployerMode,
    #[error("failed to read {adapter} config at {path}")]
    ReadConfig {
        adapter: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse {adapter} config at {path}")]
    ParseConfig {
        adapter: &'static str,
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("failed to read deployer hosts at {path}")]
    ReadHosts {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse deployer hosts at {path}")]
    ParseHosts {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error(
        "missing Store URL. Provide --store-url, a --hosts and --config pair, or {STORE_URL_ENV}"
    )]
    MissingStoreUrl,
    #[error("{PORT_ENV} must be a valid u16 but was {value:?}")]
    InvalidEnvironmentPort {
        value: String,
        #[source]
        source: ParseIntError,
    },
}

fn load_deployer_config(profile: Profile, path: &Path) -> Result<DeployerConfig, SettingsError> {
    let raw = fs::read_to_string(path).map_err(|source| SettingsError::ReadConfig {
        adapter: profile.name,
        path: path.to_path_buf(),
        source,
    })?;
    serde_yaml::from_str(&raw).map_err(|source| SettingsError::ParseConfig {
        adapter: profile.name,
        path: path.to_path_buf(),
        source,
    })
}

fn resolve_named_http_url(url: &str, hosts_by_name: &AHashMap<&str, IpAddr>) -> String {
    let Some(rest) = url.strip_prefix("http://") else {
        return url.to_string();
    };
    let (authority, suffix) = match rest.split_once('/') {
        Some((authority, suffix)) => (authority, format!("/{suffix}")),
        None => (rest, String::new()),
    };
    let Some((host, port)) = authority.rsplit_once(':') else {
        return url.to_string();
    };
    let Some(ip) = hosts_by_name.get(host) else {
        return url.to_string();
    };

    format!("http://{ip}:{port}{suffix}")
}

fn load_deployer_settings(
    profile: Profile,
    hosts_path: &Path,
    config_path: &Path,
) -> Result<DeployerSettings, SettingsError> {
    let config = load_deployer_config(profile, config_path)?;
    let raw_hosts = fs::read_to_string(hosts_path).map_err(|source| SettingsError::ReadHosts {
        path: hosts_path.to_path_buf(),
        source,
    })?;
    let hosts: Hosts =
        serde_yaml::from_str(&raw_hosts).map_err(|source| SettingsError::ParseHosts {
            path: hosts_path.to_path_buf(),
            source,
        })?;
    let hosts_by_name = hosts
        .hosts
        .iter()
        .map(|host| (host.name.as_str(), host.ip))
        .collect::<AHashMap<_, _>>();

    Ok(DeployerSettings {
        store_url: resolve_named_http_url(&config.chain_indexer_url, &hosts_by_name),
        port: config.port,
        api_key: config.api_key,
    })
}

pub(crate) fn load_settings(
    profile: Profile,
    args: AdapterArgs,
    environment: Environment,
) -> Result<Settings, SettingsError> {
    let deployer = match (&args.hosts, &args.config) {
        (Some(hosts), Some(config)) => Some(load_deployer_settings(profile, hosts, config)?),
        (None, None) => None,
        _ => return Err(SettingsError::IncompleteDeployerMode),
    };
    let store_url = args
        .store_url
        .or_else(|| deployer.as_ref().map(|settings| settings.store_url.clone()))
        .or(environment.store_url)
        .ok_or(SettingsError::MissingStoreUrl)?;
    let port = match args
        .port
        .or_else(|| deployer.as_ref().map(|settings| settings.port))
    {
        Some(port) => port,
        None => match environment.port {
            Some(value) => value
                .parse()
                .map_err(|source| SettingsError::InvalidEnvironmentPort { value, source })?,
            None => profile.default_port,
        },
    };
    let api_key = deployer.and_then(|settings| settings.api_key);

    Ok(Settings {
        store_url,
        host: args.host,
        port,
        api_key,
    })
}

#[cfg(test)]
mod tests {
    use super::{AdapterArgs, Environment, Profile, STORE_URL_ENV, SettingsError, load_settings};
    use clap::Parser;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    const PROFILES: [Profile; 2] = [
        Profile {
            name: "metadata-indexer",
            default_port: 8091,
        },
        Profile {
            name: "qmdb-indexer",
            default_port: 8092,
        },
    ];

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        adapter: AdapterArgs,
    }

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    fn parse(profile: Profile, args: &[String]) -> AdapterArgs {
        TestCli::try_parse_from(
            std::iter::once(profile.name.to_string()).chain(args.iter().cloned()),
        )
        .expect("adapter arguments should parse")
        .adapter
    }

    fn temp_path(prefix: &str, suffix: &str) -> PathBuf {
        let unique = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("{prefix}-{}-{unique}{suffix}", std::process::id()))
    }

    fn deployer_files(profile: Profile, api_key: Option<&str>) -> (PathBuf, PathBuf) {
        let config_path = temp_path(profile.name, ".yaml");
        let hosts_path = temp_path(&format!("{}-hosts", profile.name), ".yaml");
        let key = api_key
            .map(|key| format!("api_key: {key}\n"))
            .unwrap_or_default();
        fs::write(
            &config_path,
            format!(
                "port: {}\nchain_indexer_url: http://chain-indexer:8090\n{key}",
                profile.default_port + 10_000
            ),
        )
        .expect("config should write");
        fs::write(
            &hosts_path,
            "monitoring:\n  public: 10.0.0.1\n  private: 10.0.0.2\nhosts:\n  - name: \"chain-indexer\"\n    region: us-east-1\n    ip: 203.0.113.9\n",
        )
        .expect("hosts should write");
        (config_path, hosts_path)
    }

    #[test]
    fn environment_only_settings_use_each_profile() {
        for profile in PROFILES {
            let args = parse(profile, &[]);
            let settings = load_settings(
                profile,
                args,
                Environment {
                    store_url: Some("http://environment:8090".to_string()),
                    port: Some((profile.default_port + 10_000).to_string()),
                },
            )
            .expect("environment settings should load");

            assert_eq!(settings.store_url, "http://environment:8090");
            assert_eq!(settings.port, profile.default_port + 10_000);
            assert!(settings.api_key.is_none());
        }
    }

    #[test]
    fn default_ports_apply_after_environment() {
        for profile in PROFILES {
            let args = parse(profile, &[]);
            let settings = load_settings(
                profile,
                args,
                Environment {
                    store_url: Some("http://environment:8090".to_string()),
                    port: None,
                },
            )
            .expect("environment settings should load");

            assert_eq!(settings.port, profile.default_port);
        }
    }

    #[test]
    fn rejects_missing_and_invalid_environment_settings() {
        for profile in PROFILES {
            let args = parse(profile, &[]);
            let error = load_settings(profile, args, Environment::default())
                .expect_err("missing Store URL should fail");
            assert!(matches!(error, SettingsError::MissingStoreUrl));
            assert!(error.to_string().contains(STORE_URL_ENV));

            let args = parse(profile, &[]);
            let error = load_settings(
                profile,
                args,
                Environment {
                    store_url: Some("http://environment:8090".to_string()),
                    port: Some("invalid".to_string()),
                },
            )
            .expect_err("invalid environment port should fail");
            assert!(matches!(
                error,
                SettingsError::InvalidEnvironmentPort { .. }
            ));
        }
    }

    #[test]
    fn explicit_values_beat_deployer_and_environment() {
        for profile in PROFILES {
            let (config_path, hosts_path) = deployer_files(profile, Some("yaml-read-key"));
            let args = parse(
                profile,
                &[
                    "--store-url".to_string(),
                    "http://cli:8090".to_string(),
                    "--port".to_string(),
                    (profile.default_port + 11_000).to_string(),
                    "--hosts".to_string(),
                    hosts_path.to_string_lossy().into_owned(),
                    "--config".to_string(),
                    config_path.to_string_lossy().into_owned(),
                ],
            );
            let settings = load_settings(
                profile,
                args,
                Environment {
                    store_url: Some("http://environment:8090".to_string()),
                    port: Some("invalid".to_string()),
                },
            )
            .expect("settings should load");

            assert_eq!(settings.store_url, "http://cli:8090");
            assert_eq!(settings.port, profile.default_port + 11_000);
            assert_eq!(settings.api_key.as_deref(), Some("yaml-read-key"));

            let _ = fs::remove_file(config_path);
            let _ = fs::remove_file(hosts_path);
        }
    }

    #[test]
    fn deployer_values_beat_environment_and_resolve_hosts() {
        for profile in PROFILES {
            let (config_path, hosts_path) = deployer_files(profile, None);
            let args = parse(
                profile,
                &[
                    "--hosts".to_string(),
                    hosts_path.to_string_lossy().into_owned(),
                    "--config".to_string(),
                    config_path.to_string_lossy().into_owned(),
                ],
            );
            let settings = load_settings(
                profile,
                args,
                Environment {
                    store_url: Some("http://environment:8090".to_string()),
                    port: Some("invalid".to_string()),
                },
            )
            .expect("settings should load");

            assert_eq!(settings.store_url, "http://203.0.113.9:8090");
            assert_eq!(settings.port, profile.default_port + 10_000);
            assert!(settings.api_key.is_none());

            let _ = fs::remove_file(config_path);
            let _ = fs::remove_file(hosts_path);
        }
    }
}
