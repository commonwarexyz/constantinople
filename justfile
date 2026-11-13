set positional-arguments

import 'docker/justfile'

alias f := fmt-fix
alias l := lint
alias t := test

# default recipe to display help information
default:
  @just --list

# Build the workspace
build *args='':
  cargo build --workspace --all-features $@

# Fixes the formatting of the workspace
fmt-fix:
  cargo +nightly fmt --all

# Check the formatting of the workspace
fmt-check:
  cargo +nightly fmt --all -- --check

# Nightly's next trait solver overflows on the recursive application bounds.
# Keep its use limited to coherence checks while running Clippy.
lint: fmt-check docs-check
  RUSTFLAGS="-Znext-solver=coherence" cargo +nightly clippy --workspace --all --all-features --all-targets -- -D warnings

# Run all tests
test *args='': docs-test deploy-script-test
  cargo nextest run --workspace --all --all-features $@

# Test deployment argument and topology selection.
deploy-script-test:
  bash ./deploy.test.sh

# Test the Rust documentation
docs-test *args='--all':
    cargo test --doc --locked $@

# Lint the Rust documentation
docs-check *args='':
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items $@

# Check for unused dependencies
udeps:
  cargo +nightly udeps --all-targets

# Test the Explorer submission and proof helpers.
explorer-test:
  npm --prefix explorer test

# Build the Explorer.
explorer-build:
  npm --prefix explorer run build

# Build the Exoware TypeScript packages the Explorer links, at the revision Cargo.toml pins.
explorer-exoware:
  bash explorer/scripts/build-exoware.sh

# Install the locked Explorer dependencies, including the Exoware packages they link.
explorer-install: explorer-exoware
  npm --prefix explorer ci

# Export native Explorer fixtures from the indexer tests into a directory.
explorer-fixtures out:
  #!/usr/bin/env bash
  set -euo pipefail
  mkdir -p "$1"
  out="$(cd "$1" && pwd)"
  EXPLORER_FIXTURE_PATH="$out/proofBundle.json" \
  EXPLORER_ACTIVITY_FIXTURE_PATH="$out/transactionActivityProof.json" \
  EXPLORER_FEED_FIXTURE_PATH="$out/blockFeed.json" \
    cargo nextest run --locked -p constantinople-indexer --all-features -E \
    'test(publisher_bundles_cover_descendants_empty_blocks_and_fixed_account_pages) | test(historical_transactions_below_inactivity_floor_remain_available) | test(bootstrap_and_resume_ignore_sql_counts_and_preserve_advancing_floors)'
  for name in proofBundle transactionActivityProof blockFeed; do
    test -s "$out/$name.json" || { echo "missing $out/$name.json" >&2; exit 1; }
  done

# Test the native fixed-account proof verifier.
account-proof-test *args='':
  cargo test -p constantinople-account-proof $@

# Build the browser verifier into a caller-owned output directory.
account-proof-wasm out target:
  RUSTFLAGS='' CARGO_ENCODED_RUSTFLAGS='' CARGO_TARGET_DIR="$2" cargo build --release --locked -p constantinople-account-proof --target wasm32-unknown-unknown --features wasm
  wasm-bindgen "$2/wasm32-unknown-unknown/release/constantinople_account_proof.wasm" --target web --out-name constantinople_account_proof --out-dir "$1"
