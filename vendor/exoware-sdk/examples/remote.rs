//! Round-trip a batch of keys against a deployed Exoware endpoint.
//!
//! ```bash
//! EXOWARE_URL=https://query.<deployment>.<domain> \
//!     EXOWARE_API_KEY=<token> \
//!     cargo run -p exoware-sdk --example remote
//! ```
//!
//! A public deployment requires a credential covering both scopes, obtained from whoever
//! operates it. The builder reads one from `EXOWARE_API_KEY`.
//!
//! Set `EXOWARE_WRITE_URL` as well to reach a deployment that serves its write path
//! on a separate origin. It defaults to `EXOWARE_URL`.

use std::process::ExitCode;

use bytes::Bytes;
use exoware_sdk::{Key, StoreClient, StoreKeyPrefix};

/// Everything written here lives under one prefix, so the demo stays separable
/// from other keys in a shared store.
const NAMESPACE: &[u8] = b"example/remote/";

#[tokio::main]
async fn main() -> ExitCode {
    let url = std::env::var("EXOWARE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let write_url = std::env::var("EXOWARE_WRITE_URL").unwrap_or_else(|_| url.clone());

    println!("read  {url}");
    println!("write {write_url}");

    match round_trip(&url, &write_url).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Display rather than the Debug that returning Err from main would print.
            eprintln!("\nfailed: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn round_trip(url: &str, write_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    // `health()` and `ready()` are plain `GET /health` and `GET /ready` against
    // health_url, which a path-routed deployment need not expose. This example
    // reaches the services directly instead of probing.
    let client = StoreClient::builder()
        .query_url(url)
        .stream_url(url)
        .health_url(url)
        .ingest_url(write_url)
        .prune_url(write_url)
        .retention_url(write_url)
        .build()?;
    let store = client.prefixed(StoreKeyPrefix::new(Bytes::from_static(NAMESPACE))?);

    let entries: Vec<(Key, &[u8])> = vec![
        (key(b"answer"), b"42".as_slice()),
        (key(b"greeting"), b"hello".as_slice()),
        (key(b"unit"), b"bytes".as_slice()),
    ];
    let batch: Vec<(&Key, &[u8])> = entries.iter().map(|(k, v)| (k, *v)).collect();

    // One commit for the whole batch, sequenced by the store.
    let sequence = store.ingest().put(&batch).await?;
    println!("\ncommitted {} entries at sequence {sequence}", batch.len());

    // Query replicas trail the write path, so pin each read to the sequence just
    // committed rather than racing it. Pinned there, a miss or a wrong value is the
    // deployment failing, so both reads below are checked rather than printed.
    let greeting = key(b"greeting");
    let value = store
        .query()
        .get_with_min_sequence_number(&greeting, sequence)
        .await?
        .ok_or_else(|| format!("greeting is absent at sequence {sequence}, which committed it"))?;
    println!("greeting = {}", String::from_utf8_lossy(&value));
    if value != b"hello".as_slice() {
        return Err(
            format!("greeting reads back as {value:?} rather than the \"hello\" written").into(),
        );
    }

    // Logical bounds spanning the namespace: the empty key up to 0xFF repeated to
    // fill whatever length the prefix leaves.
    let start = Key::new();
    let end = Key::from(vec![0xFF; store.key_prefix().max_logical_key_len()]);
    let scanned = store
        .query()
        .range_with_min_sequence_number(&start, &end, 16, sequence)
        .await?;

    println!("\nrange over {} keys:", scanned.len());
    for (k, value) in &scanned {
        println!(
            "  {} = {}",
            String::from_utf8_lossy(k),
            String::from_utf8_lossy(value)
        );
    }

    // Containment rather than an exact count, because the namespace may hold keys this
    // run did not write.
    for (expected_key, expected_value) in &entries {
        let name = String::from_utf8_lossy(expected_key);
        match scanned.iter().find(|(k, _)| k == expected_key) {
            Some((_, value)) if value == expected_value => {}
            Some((_, value)) => {
                return Err(format!(
                    "range returns {name} as {value:?} rather than {expected_value:?}"
                )
                .into())
            }
            None => return Err(format!("range over the namespace omits {name}").into()),
        }
    }

    Ok(())
}

fn key(bytes: &[u8]) -> Key {
    Bytes::copy_from_slice(bytes)
}
