# exoware-simplex

Store-backed upload helpers for Commonware Simplex artifacts.

The crate stores encoded artifacts in Exoware Store rows:

- header bytes by digest
- full `{ header, body }` block data by digest
- notarized `{ proof, header }` by Simplex round (epoch and view)
- finalized `{ proof, header }` by Simplex round (epoch and view)
- finalized `{ proof, header }` by block height

```rust
use exoware_simplex::{Finalized, SimplexClient};

# async fn example<B, S, D>(
#   store_url: &str,
#   proof: commonware_consensus::simplex::types::Finalization<S, D>,
#   header: B,
# ) -> Result<(), Box<dyn std::error::Error>>
# where
#   B: commonware_consensus::Block<Digest = D>,
#   S: commonware_cryptography::certificate::Scheme,
#   D: commonware_cryptography::Digest,
# {
let client = SimplexClient::new(
    exoware_sdk::StoreClient::new(store_url).prefixed(exoware_sdk::StoreKeyPrefix::identity()),
);
let finalized = Finalized::new(proof, header)?;
let receipt = client.upload_finalized(&finalized).await?;
println!("stored at sequence {}", receipt.store_sequence_number);
# Ok(())
# }
```

Use `prepare_header`, `prepare_block`, `prepare_notarized`, and
`prepare_finalized` when multiple Simplex artifacts should be staged into a
shared `StoreWriteBatch`.

Finalized records can be read back by round, by height, or as the latest
finalized height index. Header bytes can be read independently with
`get_header`, and the full `{ header, body }` envelope with `get_block`. The certificate wrappers validate that the certificate payload
digest matches the paired header's `Block::digest()` during construction and
decoding. If the body must be authenticated, make that commitment part of the
header format and store the full block separately with `upload_block` or
`prepare_block`.

For the sandbox, the `simplex` binary can seed deterministic threshold-VRF
MinSig finalizations into a running simulator:

```bash
cargo run --package exoware-simplex --bin simplex -- \
  seed --store-url http://127.0.0.1:8080 --interval-secs 2
```

The seeder prints the scheme, namespace, and encoded threshold verification
material used by the emitted certificates. Paste those values into the sandbox
Simplex panel before fetching or subscribing to verified certificates. By
default, seeding starts at a time-based height so restarting against a reused
simulator still advances the latest finalized height index. Pass
`--start-height` to override it.

Round indices encode epoch and view as two big-endian u64 fields. Typed reads
reject a record whose digest, height, or round does not match the requested
index.
Signature verification remains the caller's or Commonware Marshal's
responsibility.
