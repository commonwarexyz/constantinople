#!/usr/bin/env bash
# Generate, build, deploy, and explore a remote Constantinople testnet.
set -euo pipefail
cd "$(dirname "$0")"

usage() {
    echo "usage $0 [options]" >&2
    echo "  --store-url <url>                       default managed chain-indexer" >&2
    echo "  --validators <count>                    default 50" >&2
    echo "  --regions <comma-separated-regions>     default us-east-1,us-west-2" >&2
    echo "  --spammer-accounts <count>              default 4096" >&2
    echo "  --spammer-submitters <count>            default validator count" >&2
    echo "  --max-pool-bytes <bytes>                default deploy CLI value" >&2
    echo "  --storage-size <gib>                    default 150" >&2
}

if [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

STORE_URL=
EXTERNAL_STORE=false
VALIDATORS=50
REGIONS=us-east-1,us-west-2
SPAMMER_ACCOUNTS=4096
SPAMMER_SUBMITTERS=
MAX_POOL_BYTES=
STORAGE_SIZE=150

while [ "$#" -gt 0 ]; do
    case "$1" in
        --store-url)
            [ "$#" -ge 2 ] || { echo "missing value for $1" >&2; exit 2; }
            STORE_URL=$2
            EXTERNAL_STORE=true
            shift 2
            ;;
        --validators)
            [ "$#" -ge 2 ] || { echo "missing value for $1" >&2; exit 2; }
            VALIDATORS=$2
            shift 2
            ;;
        --regions)
            [ "$#" -ge 2 ] || { echo "missing value for $1" >&2; exit 2; }
            REGIONS=$2
            shift 2
            ;;
        --spammer-accounts)
            [ "$#" -ge 2 ] || { echo "missing value for $1" >&2; exit 2; }
            SPAMMER_ACCOUNTS=$2
            shift 2
            ;;
        --spammer-submitters)
            [ "$#" -ge 2 ] || { echo "missing value for $1" >&2; exit 2; }
            SPAMMER_SUBMITTERS=$2
            shift 2
            ;;
        --max-pool-bytes)
            [ "$#" -ge 2 ] || { echo "missing value for $1" >&2; exit 2; }
            MAX_POOL_BYTES=$2
            shift 2
            ;;
        --storage-size)
            [ "$#" -ge 2 ] || { echo "missing value for $1" >&2; exit 2; }
            STORAGE_SIZE=$2
            shift 2
            ;;
        *)
            echo "unknown option $1" >&2
            usage
            exit 2
            ;;
    esac
done

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

STORE_ARGS=()
if [ "$EXTERNAL_STORE" = true ]; then
    case "$STORE_URL" in
        http://?*|https://?*) EXPLORER_STORE_URL=$STORE_URL ;;
        *)
            echo "external store URL must start with http:// or https://" >&2
            exit 2
            ;;
    esac
    STORE_ARGS+=(--chain-indexer-url "$STORE_URL")
else
    STORE_ARGS+=(
        --chain-indexer-instance-type c8id.4xlarge
        --chain-indexer-storage-size 50
        --chain-indexer-storage-iops 3000
        --chain-indexer-db-parallelism 12
    )
fi

# 1. Generate the deployment bundle (./deploy must not exist).
if [ -d ./deploy ]; then
    read -r -p "./deploy exists — remove and regenerate? [y/N] " answer
    [ "$answer" = "y" ] || exit 1
    rm -rf ./deploy
fi

cargo run --bin constantinople-deploy -- generate "${GENERATE_ARGS[@]}" \
    remote \
    --http-cidr 0.0.0.0/0 --regions "$REGIONS" \
    --instance-type c8a.4xlarge --storage-size "$STORAGE_SIZE" --storage-throughput 500 \
    --monitoring-instance-type c8a.4xlarge --monitoring-storage-size 100 \
    "${STORE_ARGS[@]}" \
    --dashboard ./dashboard.json --traces 1

# 2. Build binaries into ./deploy.
just validator-amd-binary spammer-amd-binary metadata-indexer-amd-binary qmdb-indexer-amd-binary

# The managed chain-indexer uses Intel. Its build must remain last because
# both indexer recipes write deploy/chain-indexer.
if [ "$EXTERNAL_STORE" = false ]; then
    just chain-indexer-intel-binary
fi

# 3. Create the deployment.
(cd deploy && deployer aws create --config config.yaml)

# 4. Run the explorer against the live deployment.
TAG=$(yq -r '.tag' deploy/config.yaml)
HOSTS=$HOME/.commonware_deployer/$TAG/hosts.yaml

SQL_IP=$(yq -r '.hosts[] | select(.name=="metadata-indexer") | .ip' "$HOSTS")
QMDB_IP=$(yq -r '.hosts[] | select(.name=="qmdb-indexer") | .ip' "$HOSTS")

RELAYER_NAME=$(for f in deploy/*.yaml; do
    if yq -e '.relayer' "$f" >/dev/null 2>&1; then basename "$f" .yaml; fi
done)
RELAYER_IP=$(yq -r ".hosts[] | select(.name==\"$RELAYER_NAME\") | .ip" "$HOSTS")

REQUIRED_IPS=(SQL_IP QMDB_IP RELAYER_IP)
if [ "$EXTERNAL_STORE" = false ]; then
    CHAIN_IP=$(yq -r '.hosts[] | select(.name=="chain-indexer") | .ip' "$HOSTS")
    EXPLORER_STORE_URL=http://$CHAIN_IP:8090
    REQUIRED_IPS+=(CHAIN_IP)
fi

for v in "${REQUIRED_IPS[@]}"; do
    [ -n "${!v}" ] || { echo "missing $v in $HOSTS" >&2; exit 1; }
done

SIMPLEX_VERIFICATION_MATERIAL=$(tr -d '[:space:]' < deploy/simplex-verification-material.hex)

VITE_SQL_URL=http://$SQL_IP:8091 \
VITE_QMDB_URL=http://$QMDB_IP:8092 \
VITE_STORE_URL="$EXPLORER_STORE_URL" \
VITE_MEMPOOL_URL=http://$RELAYER_IP:8080 \
VITE_SIMPLEX_VERIFICATION_MATERIAL=$SIMPLEX_VERIFICATION_MATERIAL \
npm --prefix explorer run dev
