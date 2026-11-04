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

# Install Explorer dependencies.
explorer-install *args='':
  npm --prefix explorer install $@

# Test the native fixed-account proof verifier.
account-proof-test *args='':
  cargo test -p constantinople-account-proof $@

# Build the browser verifier into a caller-owned output directory.
account-proof-wasm out target:
  RUSTFLAGS='' CARGO_ENCODED_RUSTFLAGS='' CARGO_TARGET_DIR="$2" cargo build --release --locked -p constantinople-account-proof --target wasm32-unknown-unknown --features wasm
  wasm-bindgen "$2/wasm32-unknown-unknown/release/constantinople_account_proof.wasm" --target web --out-name constantinople_account_proof --out-dir "$1"
