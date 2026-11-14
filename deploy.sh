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
    echo "  --leader <rotating|stable>              default rotating" >&2
    echo "      rotating: a new leader every view" >&2
    echo "      stable: one leader per 1000000-view term with mempool proposal priority" >&2
    echo "  --bandwidth-weighting <default|vpc-1|ebs-1>" >&2
    echo "                                          default vpc-1 on validators, relayer, and spammer" >&2
    echo "  --max-propose-bytes <bytes>             default 16777216 rotating, 8388608 stable" >&2
    echo "  --spammer-accounts <count>              default derived from the block cap, 12700 at 16 MiB" >&2
    echo "  --spammer-submitters <count>            default 500 rotating, 200 stable" >&2
    echo "  --max-pool-bytes <bytes>                default deploy CLI value rotating, 536870912 stable" >&2
    echo "  --storage-size <gib>                    default 300" >&2
    echo "  --chain-indexer-compaction-rate-limit <mb/s>" >&2
    echo "                                          default unlimited, managed chain-indexer only" >&2
}

reset_options() {
    STORE_URL=
    INDEXER_URL=
    STORE_API_KEY=${CONSTANTINOPLE_STORE_API_KEY:-}
    ADAPTER_STORE_API_KEY=${CONSTANTINOPLE_ADAPTER_STORE_API_KEY:-}
    VALIDATORS=50
    REGIONS=us-east-1,us-west-2
    LEADER=rotating
    BANDWIDTH_WEIGHTING=vpc-1
    MAX_PROPOSE_BYTES=
    SPAMMER_ACCOUNTS=
    SPAMMER_SUBMITTERS=
    MAX_POOL_BYTES=
    # Validators retain up to about 10,500 blocks, which is 164 GiB of full
    # 16 MiB blocks, beside their state.
    STORAGE_SIZE=300
    CHAIN_INDEXER_COMPACTION_RATE_LIMIT=
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
            --leader)
                target=LEADER
                ;;
            --bandwidth-weighting)
                target=BANDWIDTH_WEIGHTING
                ;;
            --spammer-accounts)
                target=SPAMMER_ACCOUNTS
                ;;
            --max-propose-bytes)
                target=MAX_PROPOSE_BYTES
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
            --chain-indexer-compaction-rate-limit)
                target=CHAIN_INDEXER_COMPACTION_RATE_LIMIT
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
    if [ -n "$CHAIN_INDEXER_COMPACTION_RATE_LIMIT" ] && [ -n "$STORE_URL" ]; then
        echo "--chain-indexer-compaction-rate-limit requires the managed chain-indexer" >&2
        return 2
    fi

    # Each spammer stream holds one Tokio blocking thread for its presigner, and
    # the spammer runtime allows 512, so the defaults stay below that.
    local leader_args
    local default_submitters
    local default_max_propose_bytes
    local default_max_pool_bytes=
    case "$LEADER" in
        rotating)
            leader_args=(--leader-term-length 1)
            default_submitters=500
            default_max_propose_bytes=16777216
            ;;
        stable)
            leader_args=(
                --leader-term-length 1000000
                --leader-optimistic-views 16
                --mempool-propose-priority
                --propose-skip-final-refill
            )
            default_submitters=200
            # A stable leader gains no throughput from larger blocks, and
            # smaller ones finalize sooner.
            default_max_propose_bytes=8388608
            # Every stream sends to the one leader, whose pool must hold a
            # batch from each stream or it drops the rest on arrival.
            default_max_pool_bytes=536870912
            ;;
        *)
            echo "--leader must be rotating or stable" >&2
            usage
            return 2
            ;;
    esac

    case "$BANDWIDTH_WEIGHTING" in
        default|vpc-1|ebs-1)
            ;;
        *)
            echo "--bandwidth-weighting must be default, vpc-1, or ebs-1" >&2
            usage
            return 2
            ;;
    esac

    local max_propose_bytes=${MAX_PROPOSE_BYTES:-$default_max_propose_bytes}
    if ! [[ "$max_propose_bytes" =~ ^[1-9][0-9]*$ ]]; then
        echo "--max-propose-bytes must be a positive integer" >&2
        return 2
    fi

    # A block holds at least one spammer transfer per 150 bytes of its cap. The
    # default batch is the largest multiple of 100 accounts for which eight
    # batches at their largest jittered size, the accounts plus a tenth, fit in
    # one block.
    local block_transfers=$((max_propose_bytes / 150))
    local default_accounts=$((block_transfers / 8 * 10 / 11 / 100 * 100))

    # Two signed batches per stream bound the spammer's memory at these stream
    # counts.
    GENERATE_ARGS=(
        --validators "$VALIDATORS"
        --relayer
        --spammer
        --indexer
        "${leader_args[@]}"
        --spammer-accounts "${SPAMMER_ACCOUNTS:-$default_accounts}"
        --spammer-submitters "${SPAMMER_SUBMITTERS:-$default_submitters}"
        --spammer-accounts-jitter 0.1
        --spammer-presigned-batches 2
        --spammer-rayon-threads 14
        --worker-threads 3
        --rayon-threads 13
        --indexer-worker-threads 8
        --indexer-rayon-threads 12
        --indexer-publisher-rayon-threads 4
        --public-key-cache-size 5000000
        --max-propose-bytes "$max_propose_bytes"
    )

    local max_pool_bytes=${MAX_POOL_BYTES:-$default_max_pool_bytes}
    if [ -n "$max_pool_bytes" ]; then
        GENERATE_ARGS+=(--max-pool-bytes "$max_pool_bytes")
    fi

    REMOTE_ARGS+=(--bandwidth-weighting "$BANDWIDTH_WEIGHTING")

    if [ -n "$STORE_URL" ]; then
        REMOTE_ARGS+=(--store-url "$STORE_URL")
    else
        REMOTE_ARGS+=(
            --chain-indexer-instance-type c8id.4xlarge
            --chain-indexer-storage-size 50
            --chain-indexer-storage-iops 3000
            --chain-indexer-db-parallelism 12
        )
        if [ -n "$CHAIN_INDEXER_COMPACTION_RATE_LIMIT" ]; then
            REMOTE_ARGS+=(--chain-indexer-db-compaction-rate-limit "$CHAIN_INDEXER_COMPACTION_RATE_LIMIT")
        fi
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
