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

assert_count() {
    local needle=$1
    local expected=$2
    shift 2
    local count=0
    local value
    for value in "$@"; do
        [ "$value" != "$needle" ] || count=$((count + 1))
    done
    assert_equal "$expected" "$count" "occurrences of $needle"
}

prepare_case() {
    reset_options
    parse_options "$@" || return $?
    prepare_deployment || return $?
}

prepare_case
assert_contains explorer-indexer-amd-binary "${BINARY_TARGETS[@]}"
assert_contains --chain-indexer-instance-type "${REMOTE_ARGS[@]}"
assert_pair --indexer-instance-type c8a.8xlarge "${REMOTE_ARGS[@]}"
assert_pair --worker-threads 3 "${GENERATE_ARGS[@]}"
assert_pair --rayon-threads 13 "${GENERATE_ARGS[@]}"
assert_pair --indexer-worker-threads 8 "${GENERATE_ARGS[@]}"
assert_pair --indexer-rayon-threads 12 "${GENERATE_ARGS[@]}"
assert_pair --indexer-publisher-rayon-threads 4 "${GENERATE_ARGS[@]}"
assert_pair --leader-term-length 1 "${GENERATE_ARGS[@]}"
assert_pair --spammer-submitters 500 "${GENERATE_ARGS[@]}"
assert_pair --spammer-accounts 12700 "${GENERATE_ARGS[@]}"
assert_pair --max-propose-bytes 16777216 "${GENERATE_ARGS[@]}"
assert_excludes --leader-optimistic-views "${GENERATE_ARGS[@]}"
assert_excludes --mempool-propose-priority "${GENERATE_ARGS[@]}"
assert_excludes --propose-skip-final-refill "${GENERATE_ARGS[@]}"
assert_excludes --max-pool-bytes "${GENERATE_ARGS[@]}"
assert_pair --spammer-presigned-batches 2 "${GENERATE_ARGS[@]}"
assert_pair --bandwidth-weighting vpc-1 "${REMOTE_ARGS[@]}"
assert_excludes --chain-indexer-db-compaction-rate-limit "${REMOTE_ARGS[@]}"

prepare_case --chain-indexer-compaction-rate-limit 600
assert_pair --chain-indexer-db-compaction-rate-limit 600 "${REMOTE_ARGS[@]}"
assert_count --chain-indexer-db-compaction-rate-limit 1 "${REMOTE_ARGS[@]}"

if (prepare_case --store-url https://store.example.com --chain-indexer-compaction-rate-limit 600) >/dev/null 2>&1; then
    fail "compaction rate limit with an external Store should fail"
fi

prepare_case --leader stable
assert_pair --leader-term-length 1000000 "${GENERATE_ARGS[@]}"
assert_pair --leader-optimistic-views 16 "${GENERATE_ARGS[@]}"
assert_contains --mempool-propose-priority "${GENERATE_ARGS[@]}"
assert_contains --propose-skip-final-refill "${GENERATE_ARGS[@]}"
assert_pair --spammer-submitters 200 "${GENERATE_ARGS[@]}"
assert_pair --spammer-accounts 6300 "${GENERATE_ARGS[@]}"
assert_pair --max-propose-bytes 8388608 "${GENERATE_ARGS[@]}"

prepare_case --leader stable --max-propose-bytes 16777216
assert_pair --max-propose-bytes 16777216 "${GENERATE_ARGS[@]}"
assert_pair --spammer-accounts 12700 "${GENERATE_ARGS[@]}"
assert_pair --max-pool-bytes 536870912 "${GENERATE_ARGS[@]}"

prepare_case --leader stable --max-pool-bytes 1073741824
assert_pair --max-pool-bytes 1073741824 "${GENERATE_ARGS[@]}"
assert_count --max-pool-bytes 1 "${GENERATE_ARGS[@]}"

for leader in rotating stable; do
    prepare_case --leader "$leader" --spammer-submitters 90 --spammer-accounts 2048
    assert_pair --spammer-submitters 90 "${GENERATE_ARGS[@]}"
    assert_count --spammer-submitters 1 "${GENERATE_ARGS[@]}"
    assert_pair --spammer-accounts 2048 "${GENERATE_ARGS[@]}"
done

for mapping in "1048576 700" "2097152 1500" "4194304 3100" "8388608 6300" "16777216 12700"; do
    read -r cap accounts <<< "$mapping"
    prepare_case --max-propose-bytes "$cap"
    assert_pair --max-propose-bytes "$cap" "${GENERATE_ARGS[@]}"
    assert_pair --spammer-accounts "$accounts" "${GENERATE_ARGS[@]}"
done

prepare_case --max-propose-bytes 4194304 --spammer-accounts 9000
assert_pair --spammer-accounts 9000 "${GENERATE_ARGS[@]}"
assert_count --spammer-accounts 1 "${GENERATE_ARGS[@]}"

for cap in 0 4MiB -1; do
    if (prepare_case --max-propose-bytes "$cap") >/dev/null 2>&1; then
        fail "--max-propose-bytes $cap should fail"
    fi
done

if (prepare_case --leader sticky) >/dev/null 2>&1; then
    fail "unknown leader mode should fail"
fi

for weighting in default vpc-1 ebs-1; do
    prepare_case --bandwidth-weighting "$weighting"
    assert_pair --bandwidth-weighting "$weighting" "${REMOTE_ARGS[@]}"
done
if (prepare_case --bandwidth-weighting vpc-2) >/dev/null 2>&1; then
    fail "unknown bandwidth weighting should fail"
fi

prepare_case --store-url https://store.example.com/base
assert_pair --store-url https://store.example.com/base "${REMOTE_ARGS[@]}"
assert_contains explorer-indexer-amd-binary "${BINARY_TARGETS[@]}"

prepare_case \
    --store-url https://store.example.com \
    --indexer-url https://explorer.example.com/base \
    --store-api-key writer-key \
    --adapter-store-api-key reader-key
assert_pair --indexer-url https://explorer.example.com/base "${REMOTE_ARGS[@]}"
assert_equal https://explorer.example.com/base "$EXPLORER_INDEXER_URL" "explorer origin"
assert_equal writer-key "$STORE_API_KEY" "writer credential"
assert_equal reader-key "$ADAPTER_STORE_API_KEY" "reader credential"
assert_excludes writer-key "${REMOTE_ARGS[@]}"
assert_excludes reader-key "${REMOTE_ARGS[@]}"
assert_excludes --store-api-key "${REMOTE_ARGS[@]}"
assert_excludes --adapter-store-api-key "${REMOTE_ARGS[@]}"
assert_excludes explorer-indexer-amd-binary "${BINARY_TARGETS[@]}"
assert_equal 2 "${#BINARY_TARGETS[@]}" "external indexer binary count"

if (prepare_case --indexer-url https://explorer.example.com) >/dev/null 2>&1; then
    fail "indexer origin without Store origin should fail"
fi
for option in --sql-url --qmdb-url; do
    if (prepare_case "$option" https://old.example.com) >/dev/null 2>&1; then
        fail "removed option $option should fail"
    fi
done

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
    --indexer-url \
    --store-api-key \
    --adapter-store-api-key \
    --validators \
    --regions \
    --leader \
    --bandwidth-weighting \
    --spammer-accounts \
    --max-propose-bytes \
    --spammer-submitters \
    --max-pool-bytes \
    --storage-size \
    --chain-indexer-compaction-rate-limit
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
    "--indexer-url INDEXER_URL" \
    "--store-api-key STORE_API_KEY" \
    "--adapter-store-api-key ADAPTER_STORE_API_KEY" \
    "--validators VALIDATORS" \
    "--regions REGIONS" \
    "--leader LEADER" \
    "--bandwidth-weighting BANDWIDTH_WEIGHTING" \
    "--spammer-accounts SPAMMER_ACCOUNTS" \
    "--max-propose-bytes MAX_PROPOSE_BYTES" \
    "--spammer-submitters SPAMMER_SUBMITTERS" \
    "--max-pool-bytes MAX_POOL_BYTES" \
    "--storage-size STORAGE_SIZE" \
    "--chain-indexer-compaction-rate-limit CHAIN_INDEXER_COMPACTION_RATE_LIMIT"
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
