#!/usr/bin/env bash
set -euo pipefail
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

assert_invalid_url() {
    local option=$1
    local value=$2
    local arguments=(--store-url https://store.example.com "$option" "$value")
    if [ "$option" = "--store-url" ]; then
        arguments=("$option" "$value")
    fi
    if (prepare_case "${arguments[@]}") >/dev/null 2>&1; then
        fail "invalid URL should fail for $option"
    fi
}

test_create_remote_deployment_command() (
    local temporary_directory
    local actual

    temporary_directory=$(mktemp -d)
    trap 'rm -rf "$temporary_directory"' EXIT
    REPO_ROOT=$temporary_directory
    mkdir -p "$REPO_ROOT/deploy"

    cargo() {
        printf '%s\n%s\n' "$PWD" "$*"
    }

    actual=$(create_remote_deployment)
    assert_equal \
        "$REPO_ROOT/deploy"$'\n'"run --manifest-path $REPO_ROOT/Cargo.toml --release --bin constantinople-deploy --features aws -- create --config config.yaml" \
        "$actual" \
        "remote deployment command"
)

test_create_remote_deployment_command

prepare_case
assert_contains metadata-indexer-amd-binary "${BINARY_TARGETS[@]}"
assert_contains qmdb-indexer-amd-binary "${BINARY_TARGETS[@]}"
assert_contains --chain-indexer-instance-type "${REMOTE_ARGS[@]}"

prepare_case --store-url https://store.example.com
assert_pair --chain-indexer-url https://store.example.com "${REMOTE_ARGS[@]}"
assert_equal https://store.example.com "$EXPLORER_STORE_URL" "Store explorer origin"
assert_contains metadata-indexer-amd-binary "${BINARY_TARGETS[@]}"
assert_contains qmdb-indexer-amd-binary "${BINARY_TARGETS[@]}"

prepare_case --store-url https://store.example.com/base
assert_pair --chain-indexer-url https://store.example.com/base "${REMOTE_ARGS[@]}"
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
assert_pair --chain-indexer-api-key writer-key "${REMOTE_ARGS[@]}"
assert_pair --adapter-store-api-key reader-key "${REMOTE_ARGS[@]}"
assert_excludes metadata-indexer-amd-binary "${BINARY_TARGETS[@]}"
assert_excludes qmdb-indexer-amd-binary "${BINARY_TARGETS[@]}"
assert_equal 2 "${#BINARY_TARGETS[@]}" "remote adapter binary count"

if (prepare_case --sql-url https://sql.example.com) >/dev/null 2>&1; then
    fail "SQL origin without Store origin should fail"
fi

if (prepare_case --qmdb-url https://qmdb.example.com) >/dev/null 2>&1; then
    fail "QMDB origin without Store origin should fail"
fi

for option in --store-url --sql-url --qmdb-url; do
    for value in \
        ftp://service.example.com \
        https://#fragment \
        http://?query \
        https://user:password@service.example.com \
        https://service.example.com/path?query \
        https://service.example.com/path#fragment \
        "https://service.example.com/path with space"
    do
        assert_invalid_url "$option" "$value"
    done
done

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

echo "deploy script tests passed"
