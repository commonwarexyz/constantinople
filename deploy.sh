#!/usr/bin/env bash
# Generate, build, deploy, and explore a remote Constantinople testnet.
set -euo pipefail
cd "$(dirname "$0")"

# 1. Generate the deployment bundle (./deploy must not exist).
if [ -d ./deploy ]; then
    read -r -p "./deploy exists — remove and regenerate? [y/N] " answer
    [ "$answer" = "y" ] || exit 1
    rm -rf ./deploy
fi
# ~49k spammer accounts reaches ~250k TPS (lowered to avoid overwhelming
# simulator)
cargo run --bin constantinople-deploy -- generate \
    --validators 50 --relayer --spammer --indexer \
    --spammer-accounts 4096 --spammer-accounts-jitter 0.1 \
    --spammer-rayon-threads 14 \
    --output-dir ./deploy --worker-threads 3 --rayon-threads 13 \
    --public-key-cache-size 5000000 \
    --max-propose-bytes 16777216 \
    remote \
    --http-cidr 0.0.0.0/0 --regions us-east-1,us-west-2 \
    --instance-type c8a.4xlarge --storage-size 150 --storage-throughput 500 \
    --monitoring-instance-type c8a.4xlarge --monitoring-storage-size 100 \
    --chain-indexer-instance-type c8id.4xlarge \
    --chain-indexer-storage-size 50 --chain-indexer-storage-iops 3000 \
    --chain-indexer-db-parallelism 12 \
    --dashboard ./dashboard.json --traces 1

# 2. Build binaries into ./deploy. The fleet is c8a (AMD/znver5); the
#    chain-indexer host is c8id (Intel Granite Rapids) so its store lives on
#    local NVMe instead of EBS. The intel chain-indexer build must come last:
#    both recipes write deploy/chain-indexer.
just validator-amd-binary spammer-amd-binary metadata-indexer-amd-binary qmdb-indexer-amd-binary
just chain-indexer-intel-binary

# 3. Create the deployment.
(cd deploy && deployer aws create --config config.yaml)

# 4. Run the explorer against the live deployment.
TAG=$(yq -r '.tag' deploy/config.yaml)
HOSTS=$HOME/.commonware_deployer/$TAG/hosts.yaml

CHAIN_IP=$(yq -r '.hosts[] | select(.name=="chain-indexer") | .ip' "$HOSTS")
SQL_IP=$(yq -r '.hosts[] | select(.name=="metadata-indexer") | .ip' "$HOSTS")
QMDB_IP=$(yq -r '.hosts[] | select(.name=="qmdb-indexer") | .ip' "$HOSTS")

RELAYER_NAME=$(for f in deploy/*.yaml; do
    if yq -e '.relayer' "$f" >/dev/null 2>&1; then basename "$f" .yaml; fi
done)
RELAYER_IP=$(yq -r ".hosts[] | select(.name==\"$RELAYER_NAME\") | .ip" "$HOSTS")

for v in CHAIN_IP SQL_IP QMDB_IP RELAYER_IP; do
    [ -n "${!v}" ] || { echo "missing $v in $HOSTS" >&2; exit 1; }
done

SIMPLEX_VERIFICATION_MATERIAL=$(tr -d '[:space:]' < deploy/simplex-verification-material.hex)

VITE_SQL_URL=http://$SQL_IP:8091 \
VITE_QMDB_URL=http://$QMDB_IP:8092 \
VITE_STORE_URL=http://$CHAIN_IP:8090 \
VITE_MEMPOOL_URL=http://$RELAYER_IP:8080 \
VITE_SIMPLEX_VERIFICATION_MATERIAL=$SIMPLEX_VERIFICATION_MATERIAL \
npm --prefix explorer run dev
