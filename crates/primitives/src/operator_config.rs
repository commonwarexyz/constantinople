//! Configuration shared by the operator runtime and deployment generator.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

/// Default HTTP port for the operator service.
pub const DEFAULT_HTTP_PORT: u16 = 8_093;
/// Default interface for the operator service.
pub const DEFAULT_LISTEN_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// Default deterministic key seed for the operator's settling key.
pub const DEFAULT_OPERATOR_SEED: u64 = 2_000_000_000;
/// Default minimum blocks required between registration and channel expiry.
pub const DEFAULT_MIN_RUNWAY: u64 = 20;
/// Default blocks before expiry at which settlement starts.
pub const DEFAULT_SETTLE_MARGIN: u64 = 10;

/// Operator configuration written by deploy and read by the operator binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorConfig {
    /// Local HTTP port the operator serves on.
    pub http_port: u16,
    /// HTTP bind address for the operator server.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: IpAddr,
    /// Relayer URL used for close transaction submission.
    pub relayer_url: String,
    /// Shared chain-indexer Store URL used for finalized transaction lookup.
    pub indexer_url: String,
    /// Shared QMDB facade URL used for transaction inclusion proofs.
    pub qmdb_url: String,
    /// Deterministic receiver key seed.
    #[serde(default = "default_operator_seed")]
    pub operator_seed: u64,
    /// Minimum blocks between registration and a channel's expiry.
    #[serde(default = "default_min_runway")]
    pub min_runway: u64,
    /// Blocks before expiry at which vouchers stop and settlement starts.
    #[serde(default = "default_settle_margin")]
    pub settle_margin: u64,
}

const fn default_listen_addr() -> IpAddr {
    DEFAULT_LISTEN_ADDR
}

const fn default_operator_seed() -> u64 {
    DEFAULT_OPERATOR_SEED
}

const fn default_min_runway() -> u64 {
    DEFAULT_MIN_RUNWAY
}

const fn default_settle_margin() -> u64 {
    DEFAULT_SETTLE_MARGIN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialization_uses_shared_defaults() {
        let config: OperatorConfig = serde_json::from_str(
            r#"{
                "http_port": 8093,
                "relayer_url": "http://127.0.0.1:8082",
                "indexer_url": "http://127.0.0.1:8090",
                "qmdb_url": "http://127.0.0.1:8092"
            }"#,
        )
        .expect("operator config should parse");

        assert_eq!(config.listen_addr, DEFAULT_LISTEN_ADDR);
        assert_eq!(config.operator_seed, DEFAULT_OPERATOR_SEED);
        assert_eq!(config.min_runway, DEFAULT_MIN_RUNWAY);
        assert_eq!(config.settle_margin, DEFAULT_SETTLE_MARGIN);
    }
}
