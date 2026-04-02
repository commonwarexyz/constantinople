use commonware_codec::{Encode, ReadExt};
use commonware_cryptography::{Hasher, Sha256, Signer, ed25519};
use commonware_utils::hex;
use constantinople_primitives::{Address, Signable, Signed, Transaction};
use serde::{Deserialize, Serialize};
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

pub fn accept_batch_url(endpoint: &str) -> String {
    format!("{}/tx/accept_batch", endpoint.trim_end_matches('/'))
}

pub fn wait_batch_url(endpoint: &str) -> String {
    format!("{}/tx/wait_batch", endpoint.trim_end_matches('/'))
}

#[derive(Debug, Deserialize)]
struct SubmissionBatchReceipt {
    tx_hashes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    Pending,
    Included,
    Rejected,
    Unknown,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TransactionStatus {
    pub tx_hash: String,
    pub state: TransactionState,
    pub height: u64,
}

#[derive(Debug, Serialize)]
struct WaitBatchRequest<'a> {
    tx_hashes: &'a [String],
}

#[derive(Debug, Deserialize)]
struct TransactionStatusResponse {
    statuses: Vec<TransactionStatus>,
}

pub fn transaction_hash_hex(tx_bytes: &[u8]) -> Result<String, String> {
    let signed =
        Signed::<Transaction<Digest, ed25519::PublicKey>, Sha256, ed25519::Signature>::read(
            &mut &tx_bytes[..],
        )
        .map_err(|err| format!("bad signed transaction bytes: {err}"))?;
    Ok(hex(signed.message_digest().as_ref()))
}

pub async fn accept_transaction_batch(
    client: &reqwest::Client,
    endpoint: &str,
    body: Vec<u8>,
) -> Result<Vec<String>, String> {
    let resp = client
        .post(accept_batch_url(endpoint))
        .header("content-type", "application/octet-stream")
        .body(body)
        .send()
        .await
        .map_err(|err| format!("request failed: {err}"))?;
    let status = resp.status();
    let body = resp
        .bytes()
        .await
        .map_err(|err| format!("response body failed: {err}"))?;

    if !status.is_success() {
        let body = String::from_utf8_lossy(&body);
        return Err(format!("error ({status}): {body}"));
    }

    let receipt: SubmissionBatchReceipt = serde_json::from_slice(&body)
        .map_err(|err| format!("bad submission batch receipt: {err}"))?;
    Ok(receipt.tx_hashes)
}

pub async fn wait_transaction_batch(
    client: &reqwest::Client,
    endpoint: &str,
    tx_hashes: &[String],
) -> Result<Vec<TransactionStatus>, String> {
    let resp = client
        .post(wait_batch_url(endpoint))
        .json(&WaitBatchRequest { tx_hashes })
        .send()
        .await
        .map_err(|err| format!("request failed: {err}"))?;
    let status = resp.status();
    let body = resp
        .bytes()
        .await
        .map_err(|err| format!("response body failed: {err}"))?;

    if !status.is_success() {
        let body = String::from_utf8_lossy(&body);
        return Err(format!("error ({status}): {body}"));
    }

    let response: TransactionStatusResponse =
        serde_json::from_slice(&body).map_err(|err| format!("bad wait response: {err}"))?;
    Ok(response.statuses)
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
