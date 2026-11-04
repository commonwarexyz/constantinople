# Account proof verifier

This crate verifies native Commonware current/ordered account proofs against an independently
certified root and operation count. It uses Constantinople's fixed account key and value types,
MMR, SHA-256, and 32-byte bitmap chunks. It does not infer absence from lookup results.

`verify_current_account_lookup(proof, root, key, expected_tip, encoded_operation, exclusion)`
accepts exactly one claim: an encoded update with `exclusion = false`, or no encoded operation
with `exclusion = true`. `expected_tip` is the certified state range's exclusive end minus one.
The function returns a verified account value and its update location, or verified absence.

The `wasm` feature exports the same function through wasm-bindgen. Its result is
`{type: "hit", location: bigint, key: Uint8Array, value: Uint8Array}` or
`{type: "miss", key: Uint8Array}`. Failures throw. Both the input tip and returned location use
JavaScript `bigint`. The generated web module has a default asynchronous initializer.

The native tests generate proofs from real current/ordered databases and cover inclusion,
cyclic exclusions, empty databases with and without metadata, later updates, bitmap chunks,
inconsistent claims, wrong roots, wrong boundaries, altered keys and values, truncation,
trailing data, oversized inputs, and excessive digest counts.

Run native tests through `just test -p constantinople-account-proof`. Web output targets
`wasm32-unknown-unknown` with `--features wasm` and uses wasm-bindgen 0.2.126 with
`--target web --out-name constantinople_account_proof`.
