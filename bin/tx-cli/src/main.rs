//! Transaction utility for Constantinople.

use bytes::Bytes;
use clap::Parser;
use commonware_codec::{Encode, ReadExt};
use commonware_cryptography::{Hasher, Sha256, Signer, ed25519};
use commonware_utils::{from_hex, hex};
use constantinople_primitives::{Address, Signable, Transaction};
use std::marker::PhantomData;

const TX_NAMESPACE: &[u8] = b"constantinople-tx";

type Digest = <Sha256 as Hasher>::Digest;

#[derive(Parser)]
#[command(name = "constantinople-tx")]
enum Cli {
    /// Generate an ed25519 keypair from a seed.
    Keygen {
        /// Integer seed for deterministic key generation.
        #[arg(long)]
        seed: u64,
    },
    /// Derive the address for a public key.
    Address {
        /// Hex-encoded ed25519 public key.
        #[arg(long)]
        pubkey: String,
    },
    /// Build, sign, and send a transfer transaction.
    Transfer {
        /// Hex-encoded ed25519 private key.
        #[arg(long)]
        key: String,
        /// Recipient address (hex).
        #[arg(long)]
        to: String,
        /// Amount to transfer.
        #[arg(long)]
        value: u64,
        /// Sender nonce.
        #[arg(long)]
        nonce: u64,
        /// Validator HTTP endpoint (e.g. http://localhost:8080).
        #[arg(long)]
        endpoint: String,
    },
}

fn parse_private_key(hex_str: &str) -> ed25519::PrivateKey {
    let bytes = from_hex(hex_str).expect("bad private key hex");
    ed25519::PrivateKey::read(&mut &bytes[..]).expect("failed to decode private key")
}

fn parse_address(hex_str: &str) -> Address {
    let bytes = from_hex(hex_str).expect("bad address hex");
    Address::read(&mut &bytes[..]).expect("failed to decode address")
}

fn build_transaction(
    key: &ed25519::PrivateKey,
    to: Address,
    value: u64,
    nonce: u64,
) -> Transaction<Digest, ed25519::PublicKey> {
    Transaction {
        sender: key.public_key(),
        to,
        input: Bytes::new(),
        value,
        nonce,
        _digest: PhantomData,
    }
}

#[tokio::main]
async fn main() {
    match Cli::parse() {
        Cli::Keygen { seed } => {
            let key = ed25519::PrivateKey::from_seed(seed);
            let pubkey = key.public_key();
            let address = Address::from_public_key(&mut Sha256::default(), &pubkey);
            println!("private_key: {}", hex(&key.encode()));
            println!("public_key:  {}", hex(&pubkey.encode()));
            println!("address:     {}", hex(address.as_ref()));
        }
        Cli::Address { pubkey } => {
            let bytes = from_hex(&pubkey).expect("bad pubkey hex");
            let pk = ed25519::PublicKey::read(&mut &bytes[..]).expect("bad pubkey");
            let address = Address::from_public_key(&mut Sha256::default(), &pk);
            println!("{}", hex(address.as_ref()));
        }
        Cli::Transfer {
            key,
            to,
            value,
            nonce,
            endpoint,
        } => {
            let key = parse_private_key(&key);
            let to = parse_address(&to);
            let client = reqwest::Client::new();

            let tx_bytes = build_transaction(&key, to, value, nonce)
                .seal_and_sign(&key, TX_NAMESPACE, &mut Sha256::default())
                .encode()
                .to_vec();
            let tx_hex = hex(&tx_bytes);

            let url = format!("{endpoint}/tx");
            println!("submitting to {url}...");
            let resp = client
                .post(&url)
                .body(tx_hex)
                .send()
                .await
                .expect("request failed");
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status.is_success() {
                println!("included: {body}");
            } else {
                eprintln!("error ({status}): {body}");
                std::process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Digest, build_transaction};
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{Sha256, Signer, ed25519};
    use constantinople_primitives::{Address, Signed, Transaction, TransactionCfg};

    #[test]
    fn simulation_probe_is_unsigned() {
        let key = ed25519::PrivateKey::from_seed(7);
        let to = Address::from_public_key(&mut Sha256::default(), &key.public_key());
        let probe = build_transaction(&key, to, 10, 3).encode().to_vec();

        let decoded = Transaction::<Digest, ed25519::PublicKey>::decode_cfg(
            probe.as_slice(),
            &TransactionCfg::default(),
        )
        .expect("probe should decode as an unsigned transaction");

        assert_eq!(decoded.sender, key.public_key());
        assert!(Signed::<
            Transaction<Digest, ed25519::PublicKey>,
            Sha256,
            ed25519::Signature,
        >::decode_cfg(probe.as_slice(), &TransactionCfg::default())
        .is_err());
    }
}
