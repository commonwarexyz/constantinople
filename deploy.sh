#!/usr/bin/env bash
# Generate, build, deploy, and explore a remote Constantinople testnet.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

usage() {
    echo "usage $0 [options]" >&2
    echo "  --store-url <url>                       default managed chain-indexer" >&2
    echo "  --sql-url <url>                         default managed metadata-indexer" >&2
    echo "  --qmdb-url <url>                        default managed qmdb-indexer" >&2
    echo "  --store-api-key <key>                   validator Store writer credential" >&2
    echo "  --adapter-store-api-key <key>           local adapter Store read credential" >&2
    echo "  --validators <count>                    default 50" >&2
    echo "  --regions <comma-separated-regions>     default us-east-1,us-west-2" >&2
    echo "  --spammer-accounts <count>              default 4096" >&2
    echo "  --spammer-submitters <count>            default validator count" >&2
    echo "  --max-pool-bytes <bytes>                default deploy CLI value" >&2
    echo "  --storage-size <gib>                    default 150" >&2
}

reset_options() {
    STORE_URL=
    SQL_URL=
    QMDB_URL=
    STORE_API_KEY=
    ADAPTER_STORE_API_KEY=
    VALIDATORS=50
    REGIONS=us-east-1,us-west-2
    SPAMMER_ACCOUNTS=4096
    SPAMMER_SUBMITTERS=
    MAX_POOL_BYTES=
    STORAGE_SIZE=150
    GENERATE_ARGS=()
    REMOTE_ARGS=()
    BINARY_TARGETS=()
    EXPLORER_STORE_URL=
    EXPLORER_SQL_URL=
    EXPLORER_QMDB_URL=
}

parse_options() {
    local option
    local target
    while [ "$#" -gt 0 ]; do
        option=$1
        case "$option" in
            --store-url)
                target=STORE_URL
                ;;
            --sql-url)
                target=SQL_URL
                ;;
            --qmdb-url)
                target=QMDB_URL
                ;;
            --store-api-key)
                target=STORE_API_KEY
                ;;
            --adapter-store-api-key)
                target=ADAPTER_STORE_API_KEY
                ;;
            --validators)
                target=VALIDATORS
                ;;
            --regions)
                target=REGIONS
                ;;
            --spammer-accounts)
                target=SPAMMER_ACCOUNTS
                ;;
            --spammer-submitters)
                target=SPAMMER_SUBMITTERS
                ;;
            --max-pool-bytes)
                target=MAX_POOL_BYTES
                ;;
            --storage-size)
                target=STORAGE_SIZE
                ;;
            *)
                echo "unknown option $option" >&2
                usage
                return 2
                ;;
        esac

        if [ "$#" -lt 2 ] || [ -z "${2:-}" ]; then
            echo "missing value for $option" >&2
            return 2
        fi
        printf -v "$target" '%s' "$2"
        shift 2
    done
}

validate_http_url() {
    local name=$1
    local url=$2
    if ! node -e '
const value = process.argv[1];
if (/\s/.test(value)) process.exit(1);
const parsed = new URL(value);
if (
    !["http:", "https:"].includes(parsed.protocol) ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
) process.exit(1);
' "$url" >/dev/null 2>&1; then
        echo "$name must be an absolute HTTP or HTTPS service base without credentials, a query, or a fragment" >&2
        return 2
    fi
}

create_remote_deployment() {
    (
        cd "$REPO_ROOT/deploy"
        cargo run \
            --manifest-path "$REPO_ROOT/Cargo.toml" \
            --release \
            --bin constantinople-deploy \
            --features aws \
            -- create --config config.yaml
    )
}

prepare_deployment() {
    if { [ -n "$SQL_URL" ] || [ -n "$QMDB_URL" ]; } && [ -z "$STORE_URL" ]; then
        echo "--sql-url and --qmdb-url require --store-url" >&2
        return 2
    fi

    GENERATE_ARGS=(
        --validators "$VALIDATORS"
        --relayer
        --spammer
        --indexer
        --spammer-accounts "$SPAMMER_ACCOUNTS"
        --spammer-accounts-jitter 0.1
        --spammer-rayon-threads 14
        --output-dir ./deploy
        --worker-threads 3
        --rayon-threads 13
        --public-key-cache-size 5000000
        --max-propose-bytes 16777216
    )

    if [ -n "$SPAMMER_SUBMITTERS" ]; then
        GENERATE_ARGS+=(--spammer-submitters "$SPAMMER_SUBMITTERS")
    fi

    if [ -n "$MAX_POOL_BYTES" ]; then
        GENERATE_ARGS+=(--max-pool-bytes "$MAX_POOL_BYTES")
    fi

    if [ -n "$STORE_URL" ]; then
        validate_http_url "external Store URL" "$STORE_URL" || return $?
        EXPLORER_STORE_URL=$STORE_URL
        REMOTE_ARGS+=(--chain-indexer-url "$STORE_URL")
    else
        REMOTE_ARGS+=(
            --chain-indexer-instance-type c8id.4xlarge
            --chain-indexer-storage-size 50
            --chain-indexer-storage-iops 3000
            --chain-indexer-db-parallelism 12
        )
    fi

    if [ -n "$SQL_URL" ]; then
        validate_http_url "external SQL URL" "$SQL_URL" || return $?
        EXPLORER_SQL_URL=$SQL_URL
        REMOTE_ARGS+=(--metadata-indexer-url "$SQL_URL")
    fi

    if [ -n "$QMDB_URL" ]; then
        validate_http_url "external QMDB URL" "$QMDB_URL" || return $?
        EXPLORER_QMDB_URL=$QMDB_URL
        REMOTE_ARGS+=(--qmdb-indexer-url "$QMDB_URL")
    fi

    if [ -n "$STORE_API_KEY" ]; then
        REMOTE_ARGS+=(--chain-indexer-api-key "$STORE_API_KEY")
    fi

    if [ -n "$ADAPTER_STORE_API_KEY" ]; then
        REMOTE_ARGS+=(--adapter-store-api-key "$ADAPTER_STORE_API_KEY")
    fi

    BINARY_TARGETS=(validator-amd-binary spammer-amd-binary)
    if [ -z "$SQL_URL" ]; then
        BINARY_TARGETS+=(metadata-indexer-amd-binary)
    fi
    if [ -z "$QMDB_URL" ]; then
        BINARY_TARGETS+=(qmdb-indexer-amd-binary)
    fi
}

main() {
    if [ "${1:-}" = "--help" ]; then
        usage
        return 0
    fi

    reset_options
    parse_options "$@" || return $?
    prepare_deployment || return $?

    cd "$REPO_ROOT"

    # Generate the deployment bundle. The output directory must not exist.
    if [ -d ./deploy ]; then
        read -r -p "./deploy exists - remove and regenerate? [y/N] " answer
        [ "$answer" = "y" ] || return 1
        rm -rf ./deploy
    fi

    cargo run --bin constantinople-deploy -- generate "${GENERATE_ARGS[@]}" \
        remote \
        --http-cidr 0.0.0.0/0 --regions "$REGIONS" \
        --instance-type c8a.4xlarge --storage-size "$STORAGE_SIZE" --storage-throughput 500 \
        --monitoring-instance-type c8a.4xlarge --monitoring-storage-size 100 \
        "${REMOTE_ARGS[@]}" \
        --dashboard ./dashboard.json --traces 1

    # Build only the binaries represented in the generated deployment.
    just "${BINARY_TARGETS[@]}"

    # The managed chain-indexer uses Intel. Its build must remain last because
    # both indexer recipes write deploy/chain-indexer.
    if [ -z "$STORE_URL" ]; then
        just chain-indexer-intel-binary
    fi

    create_remote_deployment

    TAG=$(yq -r '.tag' deploy/config.yaml)
    HOSTS=$HOME/.commonware_deployer/$TAG/hosts.yaml

    REQUIRED_IPS=(RELAYER_IP)
    if [ -z "$SQL_URL" ]; then
        SQL_IP=$(yq -r '.hosts[] | select(.name=="metadata-indexer") | .ip' "$HOSTS")
        EXPLORER_SQL_URL=http://$SQL_IP:8091
        REQUIRED_IPS+=(SQL_IP)
    fi

    if [ -z "$QMDB_URL" ]; then
        QMDB_IP=$(yq -r '.hosts[] | select(.name=="qmdb-indexer") | .ip' "$HOSTS")
        EXPLORER_QMDB_URL=http://$QMDB_IP:8092
        REQUIRED_IPS+=(QMDB_IP)
    fi

    RELAYER_NAME=$(for f in deploy/*.yaml; do
        if yq -e '.relayer' "$f" >/dev/null 2>&1; then basename "$f" .yaml; fi
    done)
    RELAYER_IP=$(yq -r ".hosts[] | select(.name==\"$RELAYER_NAME\") | .ip" "$HOSTS")

    if [ -z "$STORE_URL" ]; then
        CHAIN_IP=$(yq -r '.hosts[] | select(.name=="chain-indexer") | .ip' "$HOSTS")
        EXPLORER_STORE_URL=http://$CHAIN_IP:8090
        REQUIRED_IPS+=(CHAIN_IP)
    fi

    for variable in "${REQUIRED_IPS[@]}"; do
        [ -n "${!variable}" ] || { echo "missing $variable in $HOSTS" >&2; return 1; }
    done

    SIMPLEX_VERIFICATION_MATERIAL=$(tr -d '[:space:]' < deploy/simplex-verification-material.hex)

    VITE_SQL_URL="$EXPLORER_SQL_URL" \
    VITE_QMDB_URL="$EXPLORER_QMDB_URL" \
    VITE_STORE_URL="$EXPLORER_STORE_URL" \
    VITE_MEMPOOL_URL=http://$RELAYER_IP:8080 \
    VITE_SIMPLEX_VERIFICATION_MATERIAL=$SIMPLEX_VERIFICATION_MATERIAL \
    npm --prefix explorer run dev
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
