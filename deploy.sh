#!/usr/bin/env bash
# Generate, build, deploy, and explore a remote Constantinople testnet.
set -euo pipefail

usage() {
    echo "usage $0 [options]" >&2
    echo "  --store-url <url>                       default managed chain-indexer" >&2
    echo "  --indexer-url <url>                     default managed explorer-indexer" >&2
    echo "  --store-api-key <key>                   validator Store writer credential" >&2
    echo "  --adapter-store-api-key <key>           explorer Store read credential" >&2
    echo "  Credentials may also use CONSTANTINOPLE_STORE_API_KEY and CONSTANTINOPLE_ADAPTER_STORE_API_KEY." >&2
    echo "  --validators <count>                    default 50" >&2
    echo "  --regions <comma-separated-regions>     default us-east-1,us-west-2" >&2
    echo "  --spammer-accounts <count>              default 4096" >&2
    echo "  --spammer-submitters <count>            default validator count" >&2
    echo "  --max-pool-bytes <bytes>                default deploy CLI value" >&2
    echo "  --storage-size <gib>                    default 150" >&2
}

reset_options() {
    STORE_URL=
    INDEXER_URL=
    STORE_API_KEY=${CONSTANTINOPLE_STORE_API_KEY:-}
    ADAPTER_STORE_API_KEY=${CONSTANTINOPLE_ADAPTER_STORE_API_KEY:-}
    VALIDATORS=50
    REGIONS=us-east-1,us-west-2
    SPAMMER_ACCOUNTS=4096
    SPAMMER_SUBMITTERS=
    MAX_POOL_BYTES=
    STORAGE_SIZE=150
    GENERATE_ARGS=()
    # The indexer runs the validator binary, which is built for the validators'
    # CPU model (see docker/docker-bake.hcl). Keep it on the same vendor.
    # Intel NVMe types such as c8id trap on AMD-only instructions.
    REMOTE_ARGS=(--indexer-instance-type c8a.8xlarge)
    BINARY_TARGETS=()
    EXPLORER_INDEXER_URL=
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
            --indexer-url)
                target=INDEXER_URL
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

prepare_deployment() {
    if { [ -n "$STORE_API_KEY" ] || [ -n "$ADAPTER_STORE_API_KEY" ]; } && [ -z "$STORE_URL" ]; then
        echo "Store credentials require --store-url" >&2
        return 2
    fi
    if [ -n "$INDEXER_URL" ] && [ -z "$STORE_URL" ]; then
        echo "--indexer-url requires --store-url" >&2
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
        --worker-threads 3
        --rayon-threads 13
        --indexer-worker-threads 8
        --indexer-rayon-threads 12
        --indexer-publisher-rayon-threads 4
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
        REMOTE_ARGS+=(--store-url "$STORE_URL")
    else
        REMOTE_ARGS+=(
            --chain-indexer-instance-type c8id.4xlarge
            --chain-indexer-storage-size 50
            --chain-indexer-storage-iops 3000
            --chain-indexer-db-parallelism 12
        )
    fi

    if [ -n "$INDEXER_URL" ]; then
        EXPLORER_INDEXER_URL=$INDEXER_URL
        REMOTE_ARGS+=(--indexer-url "$INDEXER_URL")
    fi

    BINARY_TARGETS=(validator-amd-binary spammer-amd-binary)
    if [ -z "$INDEXER_URL" ]; then
        BINARY_TARGETS+=(explorer-indexer-amd-binary)
    fi
}

generate_deployment() (
    local bundle_dir
    bundle_dir=$(mktemp -d ./deploy.XXXXXX) || return $?
    trap 'rm -rf "$bundle_dir"' EXIT

    # Keep the existing bundle until validation and generation both succeed.
    unset CONSTANTINOPLE_STORE_API_KEY CONSTANTINOPLE_ADAPTER_STORE_API_KEY
    if [ -n "$STORE_API_KEY" ]; then
        export CONSTANTINOPLE_STORE_API_KEY="$STORE_API_KEY"
    fi
    if [ -n "$ADAPTER_STORE_API_KEY" ]; then
        export CONSTANTINOPLE_ADAPTER_STORE_API_KEY="$ADAPTER_STORE_API_KEY"
    fi
    cargo run --bin constantinople-deploy -- generate "${GENERATE_ARGS[@]}" \
        --output-dir "$bundle_dir/bundle" \
        remote \
        --http-cidr 0.0.0.0/0 --regions "$REGIONS" \
        --instance-type c8a.4xlarge --storage-size "$STORAGE_SIZE" --storage-throughput 500 \
        --monitoring-instance-type c8a.4xlarge --monitoring-storage-size 100 \
        "${REMOTE_ARGS[@]}" \
        --dashboard ./dashboard.json --traces 1 || return $?

    if [ -d ./deploy ]; then
        local answer
        read -r -p "./deploy exists - replace with the new bundle? [y/N] " answer
        [ "$answer" = "y" ] || return 1
        rm -rf ./deploy || return $?
    fi
    mv "$bundle_dir/bundle" ./deploy
)

main() {
    if [ "${1:-}" = "--help" ]; then
        usage
        return 0
    fi

    reset_options
    parse_options "$@" || return $?
    prepare_deployment || return $?

    cd "$(dirname "${BASH_SOURCE[0]}")"

    generate_deployment || return $?

    # Build only the binaries represented in the generated deployment.
    just "${BINARY_TARGETS[@]}"

    # The managed chain-indexer uses Intel. Its build must remain last because
    # both indexer recipes write deploy/chain-indexer.
    if [ -z "$STORE_URL" ]; then
        just chain-indexer-intel-binary
    fi

    (cd deploy && deployer aws create --config config.yaml)

    TAG=$(yq -r '.tag' deploy/config.yaml)
    HOSTS=$HOME/.commonware_deployer/$TAG/hosts.yaml

    if [ -z "$INDEXER_URL" ]; then
        INDEXER_IP=$(yq -r '.hosts[] | select(.name=="explorer-indexer") | .ip' "$HOSTS")
        [ -n "$INDEXER_IP" ] || { echo "missing explorer-indexer IP in $HOSTS" >&2; return 1; }
        EXPLORER_INDEXER_URL=http://$INDEXER_IP:8092
    fi

    SIMPLEX_VERIFICATION_MATERIAL=$(tr -d '[:space:]' < deploy/simplex-verification-material.hex)

    VITE_INDEXER_URL="$EXPLORER_INDEXER_URL" \
    VITE_SIMPLEX_VERIFICATION_MATERIAL=$SIMPLEX_VERIFICATION_MATERIAL \
    npm --prefix explorer run dev
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
