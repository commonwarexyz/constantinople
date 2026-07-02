set positional-arguments

import 'docker/justfile'

alias f := fmt-fix
alias l := lint
alias t := test
alias tf := test-fast

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

# Run Rust tests, skipping the multi-minute `_slow_` soak tests
test-fast *args='':
  cargo nextest run --workspace --all --all-features -E 'not test(/_slow_/)' $@

# Test the Rust documentation
docs-test *args='--all':
    cargo test --doc --locked $@

# Lint the Rust documentation
docs-check *args='':
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items $@

# Check for unused dependencies
udeps:
  cargo +nightly udeps --all-targets
