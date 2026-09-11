#!/usr/bin/env bash
set -euo pipefail
unset CONSTANTINOPLE_STORE_API_KEY CONSTANTINOPLE_ADAPTER_STORE_API_KEY
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./deploy.sh

fail() {
    echo "$1" >&2
    exit 1
}

assert_equal() {
    local expected=$1
    local actual=$2
    local description=$3
    [ "$actual" = "$expected" ] || fail "$description expected $expected but got $actual"
}

assert_contains() {
    local needle=$1
    shift
    local value
    for value in "$@"; do
        [ "$value" = "$needle" ] && return 0
    done
    fail "expected array to contain $needle"
}

assert_excludes() {
    local needle=$1
    shift
    local value
    for value in "$@"; do
        [ "$value" != "$needle" ] || fail "expected array to exclude $needle"
    done
}

assert_pair() {
    local flag=$1
    local expected=$2
    shift 2
    while [ "$#" -gt 0 ]; do
        if [ "$1" = "$flag" ]; then
            [ "${2:-}" = "$expected" ] || fail "$flag carried the wrong value"
            return 0
        fi
        shift
    done
    fail "expected arguments to contain $flag"
}

prepare_case() {
    reset_options
    parse_options "$@" || return $?
    prepare_deployment || return $?
}

prepare_case
assert_contains metadata-indexer-amd-binary "${BINARY_TARGETS[@]}"
assert_contains qmdb-indexer-amd-binary "${BINARY_TARGETS[@]}"
assert_contains --chain-indexer-instance-type "${REMOTE_ARGS[@]}"

prepare_case --store-url https://store.example.com
assert_pair --store-url https://store.example.com "${REMOTE_ARGS[@]}"
assert_equal https://store.example.com "$EXPLORER_STORE_URL" "Store explorer origin"
assert_contains metadata-indexer-amd-binary "${BINARY_TARGETS[@]}"
assert_contains qmdb-indexer-amd-binary "${BINARY_TARGETS[@]}"

prepare_case --store-url https://store.example.com/base
assert_pair --store-url https://store.example.com/base "${REMOTE_ARGS[@]}"
assert_equal https://store.example.com/base "$EXPLORER_STORE_URL" "path-prefixed Store origin"

prepare_case \
    --store-url https://store.example.com \
    --sql-url https://sql.example.com/base
assert_pair --metadata-indexer-url https://sql.example.com/base "${REMOTE_ARGS[@]}"
assert_equal https://sql.example.com/base "$EXPLORER_SQL_URL" "SQL explorer origin"
assert_excludes metadata-indexer-amd-binary "${BINARY_TARGETS[@]}"
assert_contains qmdb-indexer-amd-binary "${BINARY_TARGETS[@]}"

prepare_case \
    --store-url https://store.example.com \
    --qmdb-url https://qmdb.example.com/base
assert_pair --qmdb-indexer-url https://qmdb.example.com/base "${REMOTE_ARGS[@]}"
assert_equal https://qmdb.example.com/base "$EXPLORER_QMDB_URL" "QMDB explorer origin"
assert_contains metadata-indexer-amd-binary "${BINARY_TARGETS[@]}"
assert_excludes qmdb-indexer-amd-binary "${BINARY_TARGETS[@]}"

prepare_case \
    --store-url https://store.example.com \
    --sql-url https://sql.example.com \
    --qmdb-url https://qmdb.example.com \
    --store-api-key writer-key \
    --adapter-store-api-key reader-key
assert_equal writer-key "$STORE_API_KEY" "writer credential"
assert_equal reader-key "$ADAPTER_STORE_API_KEY" "reader credential"
assert_excludes writer-key "${REMOTE_ARGS[@]}"
assert_excludes reader-key "${REMOTE_ARGS[@]}"
assert_excludes --store-api-key "${REMOTE_ARGS[@]}"
assert_excludes --adapter-store-api-key "${REMOTE_ARGS[@]}"
assert_excludes metadata-indexer-amd-binary "${BINARY_TARGETS[@]}"
assert_excludes qmdb-indexer-amd-binary "${BINARY_TARGETS[@]}"
assert_equal 2 "${#BINARY_TARGETS[@]}" "remote adapter binary count"

if (prepare_case --sql-url https://sql.example.com) >/dev/null 2>&1; then
    fail "SQL origin without Store origin should fail"
fi

if (prepare_case --qmdb-url https://qmdb.example.com) >/dev/null 2>&1; then
    fail "QMDB origin without Store origin should fail"
fi

for option in --store-api-key --adapter-store-api-key; do
    if (prepare_case "$option" secret-key) >/dev/null 2>&1; then
        fail "Store credentials without a Store origin should fail"
    fi
done

(
    export CONSTANTINOPLE_STORE_API_KEY=environment-writer
    export CONSTANTINOPLE_ADAPTER_STORE_API_KEY=environment-reader
    prepare_case --store-url https://store.example.com
    assert_equal environment-writer "$STORE_API_KEY" "environment writer"
    assert_equal environment-reader "$ADAPTER_STORE_API_KEY" "environment reader"
    assert_excludes environment-writer "${REMOTE_ARGS[@]}"
    assert_excludes environment-reader "${REMOTE_ARGS[@]}"
    if (prepare_case) >/dev/null 2>&1; then
        fail "environment credentials require a Store origin"
    fi
)

for option in \
    --store-url \
    --sql-url \
    --qmdb-url \
    --store-api-key \
    --adapter-store-api-key \
    --validators \
    --regions \
    --spammer-accounts \
    --spammer-submitters \
    --max-pool-bytes \
    --storage-size
do
    if (reset_options; parse_options "$option") >/dev/null 2>&1; then
        fail "missing value should fail for $option"
    fi
    if (reset_options; parse_options "$option" "") >/dev/null 2>&1; then
        fail "empty value should fail for $option"
    fi
done

for mapping in \
    "--store-url STORE_URL" \
    "--sql-url SQL_URL" \
    "--qmdb-url QMDB_URL" \
    "--store-api-key STORE_API_KEY" \
    "--adapter-store-api-key ADAPTER_STORE_API_KEY" \
    "--validators VALIDATORS" \
    "--regions REGIONS" \
    "--spammer-accounts SPAMMER_ACCOUNTS" \
    "--spammer-submitters SPAMMER_SUBMITTERS" \
    "--max-pool-bytes MAX_POOL_BYTES" \
    "--storage-size STORAGE_SIZE"
do
    read -r option variable <<< "$mapping"
    reset_options
    parse_options "$option" "value with spaces"
    assert_equal "value with spaces" "${!variable}" "$option assignment"
done

if (reset_options; parse_options --unknown value) >/dev/null 2>&1; then
    fail "unknown option should fail"
fi

(
    deployment_test_dir=$(mktemp -d)
    trap 'rm -rf "$deployment_test_dir"' EXIT
    cd "$deployment_test_dir"
    prepare_case --store-url https://store.example.com
    mkdir deploy
    touch deploy/existing

    # A generator failure must preserve the active bundle, even after partial output.
    cargo() {
        local output_dir
        while [ "$#" -gt 0 ]; do
            if [ "$1" = "--output-dir" ]; then
                output_dir=$2
                break
            fi
            shift
        done
        mkdir -p "$output_dir"
        touch "$output_dir/generated"
        return "$generator_status"
    }

    generator_status=2
    if generate_deployment <<< y; then
        fail "generation failure should propagate"
    fi
    [ -f deploy/existing ] || fail "generation failure removed the existing bundle"

    generator_status=0
    if generate_deployment <<< n; then
        fail "declining replacement should stop deployment"
    fi
    [ -f deploy/existing ] || fail "declining replacement removed the existing bundle"

    generate_deployment <<< y
    [ -f deploy/generated ] || fail "successful generation was not installed"
    [ ! -f deploy/existing ] || fail "replacement retained the previous bundle"
    for path in deploy.*; do
        [ ! -e "$path" ] || fail "temporary deployment bundle was not cleaned up"
    done
)

echo "deploy script tests passed"
