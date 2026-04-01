use commonware_codec::Encode;
use commonware_cryptography::{Hasher, Sha256, Signer, ed25519};
use commonware_utils::hex;
use constantinople_primitives::{Address, Signable, Transaction};
use std::{marker::PhantomData, num::NonZeroU64};

pub const TX_NAMESPACE: &[u8] = b"constantinople-tx";

pub type Digest = <Sha256 as Hasher>::Digest;

pub fn build_transaction(
    key: &ed25519::PrivateKey,
    to: Address,
    value: u64,
    nonce: u64,
) -> Transaction<Digest, ed25519::PublicKey> {
    Transaction {
        sender: key.public_key(),
        to,
        value: NonZeroU64::new(value).expect("transfer value must be non-zero"),
        nonce,
        _digest: PhantomData,
    }
}

pub fn build_signed_transaction_bytes(
    key: &ed25519::PrivateKey,
    to: Address,
    value: u64,
    nonce: u64,
) -> Vec<u8> {
    build_transaction(key, to, value, nonce)
        .seal_and_sign(key, TX_NAMESPACE, &mut Sha256::default())
        .encode()
        .to_vec()
}

pub fn tx_url(endpoint: &str) -> String {
    format!("{}/tx", endpoint.trim_end_matches('/'))
}

pub fn accept_tx_url(endpoint: &str) -> String {
    format!("{}/tx/accept", endpoint.trim_end_matches('/'))
}

pub async fn accept_transaction(
    client: &reqwest::Client,
    endpoint: &str,
    tx_bytes: Vec<u8>,
) -> Result<(), String> {
    let resp = client
        .post(accept_tx_url(endpoint))
        .body(hex(&tx_bytes))
        .send()
        .await
        .map_err(|err| format!("request failed: {err}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|err| format!("response body failed: {err}"))?;

    if status.is_success() {
        return Ok(());
    }

    Err(format!("error ({status}): {body}"))
}

#[cfg(test)]
mod tests {
    use super::{Digest, build_transaction};
    use commonware_codec::{DecodeExt, Encode};
    use commonware_cryptography::{Sha256, Signer, ed25519};
    use constantinople_primitives::{Address, Signed, Transaction};

    #[test]
    fn simulation_probe_is_unsigned() {
        let key = ed25519::PrivateKey::from_seed(7);
        let to = Address::from_public_key(&mut Sha256::default(), &key.public_key());
        let probe = build_transaction(&key, to, 10, 3).encode().to_vec();

        let decoded = Transaction::<Digest, ed25519::PublicKey>::decode(probe.as_slice())
            .expect("probe should decode as an unsigned transaction");

        assert_eq!(decoded.sender, key.public_key());
        assert!(
            Signed::<Transaction<Digest, ed25519::PublicKey>, Sha256, ed25519::Signature>::decode(
                probe.as_slice()
            )
            .is_err()
        );
    }
}
