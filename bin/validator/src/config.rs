//! TOML-serializable validator configuration.

use commonware_codec::{Read as CodecRead, ReadExt};
use commonware_cryptography::{
    Signer,
    bls12381::{
        dkg,
        primitives::{group::Share, sharing::ModeVersion, variant::MinSig},
    },
    ed25519,
};
use commonware_p2p::{Ingress, authenticated::discovery::Bootstrapper};
use commonware_utils::{NZU32, from_hex};
use constantinople_primitives::{Account, Address};
use std::net::SocketAddr;

const fn default_max_propose_bytes() -> usize {
    4 * 1024 * 1024 // 4 MiB
}

const fn default_max_pool_bytes() -> usize {
    64 * 1024 * 1024 // 64 MiB
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ValidatorConfig {
    pub private_key: String,
    pub dkg_output: String,
    pub dkg_share: String,
    pub listen: String,
    pub genesis_leader: String,
    pub partition_prefix: String,
    pub num_validators: u32,
    pub log_level: String,
    pub worker_threads: usize,
    pub http_port: u16,
    /// Max bytes of transactions per propose() call.
    #[serde(default = "default_max_propose_bytes")]
    pub max_propose_bytes: usize,
    /// Max bytes of pending transactions before rejecting.
    #[serde(default = "default_max_pool_bytes")]
    pub max_pool_bytes: usize,
    pub bootstrappers: Vec<BootstrapperEntry>,
    #[serde(default)]
    pub genesis_allocations: Vec<GenesisAllocation>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct BootstrapperEntry {
    pub public_key: String,
    pub address: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct GenesisAllocation {
    pub address: String,
    pub balance: u64,
}

/// Top-level structure of the genesis TOML file.
#[derive(serde::Deserialize)]
pub struct GenesisFile {
    #[serde(default)]
    pub allocations: Vec<GenesisAllocation>,
}

/// Decoded key material and network info ready for use by the engine.
pub struct DecodedConfig {
    pub signer: ed25519::PrivateKey,
    pub public_key: ed25519::PublicKey,
    pub dkg_output: dkg::Output<MinSig, ed25519::PublicKey>,
    pub share: Share,
    pub genesis_leader: ed25519::PublicKey,
    pub listen: SocketAddr,
    pub bootstrappers: Vec<Bootstrapper<ed25519::PublicKey>>,
    pub partition_prefix: String,
    pub genesis_allocations: Vec<(Address, Account)>,
}

fn decode_hex(field_name: &str, hex_str: &str) -> Vec<u8> {
    from_hex(hex_str).unwrap_or_else(|| panic!("bad {field_name} hex"))
}

impl ValidatorConfig {
    pub fn decode(&self) -> DecodedConfig {
        let pk_bytes = decode_hex("private_key", &self.private_key);
        let signer =
            ed25519::PrivateKey::read(&mut &pk_bytes[..]).expect("failed to decode private key");
        let public_key = signer.public_key();

        let dkg_bytes = decode_hex("dkg_output", &self.dkg_output);
        let dkg_output = dkg::Output::read_cfg(
            &mut &dkg_bytes[..],
            &(NZU32!(self.num_validators), ModeVersion::v0()),
        )
        .expect("failed to decode DKG output");

        let share_bytes = decode_hex("dkg_share", &self.dkg_share);
        let share = Share::read(&mut &share_bytes[..]).expect("failed to decode DKG share");

        let genesis_bytes = decode_hex("genesis_leader", &self.genesis_leader);
        let genesis_leader = ed25519::PublicKey::read(&mut &genesis_bytes[..])
            .expect("failed to decode genesis leader");

        let listen: SocketAddr = self.listen.parse().expect("bad listen address");

        let bootstrappers = self
            .bootstrappers
            .iter()
            .map(|b| {
                let bytes = decode_hex("bootstrapper public_key", &b.public_key);
                let pk = ed25519::PublicKey::read(&mut &bytes[..])
                    .expect("failed to decode bootstrapper public key");
                let addr: SocketAddr = b.address.parse().expect("bad bootstrapper address");
                (pk, Ingress::Socket(addr))
            })
            .collect();

        let genesis_allocations = self
            .genesis_allocations
            .iter()
            .map(|a| {
                let bytes = decode_hex("genesis allocation address", &a.address);
                let address =
                    Address::read(&mut &bytes[..]).expect("failed to decode genesis address");
                (
                    address,
                    Account {
                        balance: a.balance,
                        nonce: 0,
                    },
                )
            })
            .collect();

        DecodedConfig {
            signer,
            public_key,
            dkg_output,
            share,
            genesis_leader,
            listen,
            bootstrappers,
            partition_prefix: self.partition_prefix.clone(),
            genesis_allocations,
        }
    }
}

pub fn decode_public_key(hex_str: &str) -> ed25519::PublicKey {
    let bytes = decode_hex("public_key", hex_str);
    ed25519::PublicKey::read(&mut &bytes[..]).expect("failed to decode public key")
}
