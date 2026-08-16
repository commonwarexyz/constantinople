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
  cargo build --workspace --all $@

# Fixes the formatting of the workspace
fmt-fix:
  cargo +nightly fmt --all

# Check the formatting of the workspace
fmt-check:
  cargo +nightly fmt --all -- --check

# Lint the workspace
lint: fmt-check docs-check
  cargo +nightly clippy --workspace --all --all-features --all-targets -- -D warnings

# Run Rust tests
test *args='': docs-test
  cargo nextest run --workspace --all --all-features $@

# Run the production-shaped state/history cadence benchmark.
cadence:
  cargo bench -p constantinople-application --bench cadence

# Test the Rust documentation
docs-test *args='--all':
    cargo test --doc --locked $@

# Lint the Rust documentation
docs-check *args='':
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items $@

# Check for unused dependencies
udeps:
  cargo +nightly udeps --all-targets
