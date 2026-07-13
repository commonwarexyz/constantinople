//! Deployer-name resolution for HTTP URLs.
//!
//! commonware-deployer names hosts (e.g. `chain-indexer`) rather than
//! assigning them stable IPs, so deployer-generated configs reference
//! services as `http://<name>:<port>` and every binary rewrites those names
//! against the deployer's hosts file at startup. This module is the single
//! rewrite implementation; each caller supplies its own name-to-IP lookup
//! (built from `commonware_deployer::aws::Hosts`, which primitives
//! deliberately does not depend on).

use std::net::{IpAddr, SocketAddr};

/// Resolves a deployer-named `http://<name>:<port>[/<path>]` URL through
/// `lookup`, replacing the name with its IP.
///
/// URLs that are not plain `http://`, carry no explicit port, or name a host
/// `lookup` does not know are returned unchanged — literal addresses and
/// non-deployer URLs pass through untouched.
pub fn resolve_named_http_url(url: &str, lookup: impl Fn(&str) -> Option<IpAddr>) -> String {
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
    let Some(ip) = lookup(host) else {
        return url.to_string();
    };
    let Ok(port) = port.parse() else {
        return url.to_string();
    };

    format!("http://{}{suffix}", SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn hosts() -> BTreeMap<String, IpAddr> {
        BTreeMap::from([
            ("chain-indexer".to_string(), "203.0.113.9".parse().unwrap()),
            ("relayer-node".to_string(), "203.0.113.8".parse().unwrap()),
            ("ipv6-node".to_string(), "2001:db8::1".parse().unwrap()),
        ])
    }

    fn resolve(url: &str) -> String {
        let hosts = hosts();
        resolve_named_http_url(url, |name| hosts.get(name).copied())
    }

    #[test]
    fn named_host_resolves_to_its_ip() {
        assert_eq!(
            resolve("http://chain-indexer:8090"),
            "http://203.0.113.9:8090"
        );
    }

    #[test]
    fn path_suffix_is_preserved() {
        assert_eq!(
            resolve("http://relayer-node:8080/transactions"),
            "http://203.0.113.8:8080/transactions"
        );
    }

    #[test]
    fn ipv6_address_is_bracketed() {
        assert_eq!(
            resolve("http://ipv6-node:8090/transactions"),
            "http://[2001:db8::1]:8090/transactions"
        );
    }

    #[test]
    fn unknown_host_passes_through() {
        assert_eq!(resolve("http://unknown:8090"), "http://unknown:8090");
    }

    #[test]
    fn non_http_url_passes_through() {
        assert_eq!(
            resolve("https://chain-indexer:8090"),
            "https://chain-indexer:8090"
        );
    }

    #[test]
    fn url_without_port_passes_through() {
        assert_eq!(resolve("http://chain-indexer"), "http://chain-indexer");
    }

    #[test]
    fn invalid_port_passes_through() {
        assert_eq!(
            resolve("http://chain-indexer:not-a-port"),
            "http://chain-indexer:not-a-port"
        );
    }

    #[test]
    fn literal_address_resolves_only_when_listed() {
        // A literal IP is just an unknown "name" to the lookup: unchanged.
        assert_eq!(resolve("http://127.0.0.1:8090"), "http://127.0.0.1:8090");
    }
}
