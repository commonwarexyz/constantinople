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

# Test the Rust documentation
docs-test *args='--all':
    cargo test --doc --locked $@

# Lint the Rust documentation
docs-check *args='':
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items $@

# Check for unused dependencies
udeps:
  cargo +nightly udeps --all-targets

# Test the handoff metrics comparison tool
test-handoff-comparison:
  python3 -m unittest discover -s scripts -p 'test_compare_handoffs.py'

# Test AWS handoff experiment orchestration without contacting AWS
test-aws-handoffs:
  python3 -m unittest discover -s scripts -p 'test_run_aws_handoffs.py'

# Run sequential handoff experiments on an existing deployment
run-aws-handoffs *args:
  python3 scripts/run_aws_handoffs.py "$@"

# Compare timing metrics from running handoff-mode chains
compare-handoffs *args:
  python3 scripts/compare_handoffs.py "$@"
