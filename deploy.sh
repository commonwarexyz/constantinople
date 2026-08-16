#!/usr/bin/env bash
# Generate, build, and deploy a remote Constantinople testnet.
set -euo pipefail
cd "$(dirname "$0")"

DEFAULT_COMMONWARE_CHECKOUT="$(dirname "$PWD")/monorepo-optimize-glue-sync-glue-tweaks-plus"
DEPLOYER_CHECKOUT="${DEPLOYER_CHECKOUT:-$DEFAULT_COMMONWARE_CHECKOUT}"
if [ ! -f "$DEPLOYER_CHECKOUT/Cargo.toml" ]; then
    echo "missing deployer checkout: $DEPLOYER_CHECKOUT" >&2
    exit 1
fi
DEPLOYER_MANIFEST="$(cd "$DEPLOYER_CHECKOUT" && pwd)/Cargo.toml"
COMMONWARE_CHECKOUT="${COMMONWARE_CHECKOUT:-$DEPLOYER_CHECKOUT}"
if [ ! -f "$COMMONWARE_CHECKOUT/Cargo.toml" ]; then
    echo "missing Commonware checkout: $COMMONWARE_CHECKOUT" >&2
    exit 1
fi
export COMMONWARE_CHECKOUT="$(cd "$COMMONWARE_CHECKOUT" && pwd)"

for tool in cargo just docker; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "missing required command: $tool" >&2
        exit 1
    fi
done
if ! docker info >/dev/null 2>&1; then
    echo "docker daemon is unavailable" >&2
    exit 1
fi
if ! docker buildx version >/dev/null 2>&1; then
    echo "docker buildx is unavailable" >&2
    exit 1
fi
if [ ! -f ./dashboard.json ]; then
    echo "missing dashboard.json" >&2
    exit 1
fi
cargo build --locked --release --manifest-path "$DEPLOYER_MANIFEST" \
    -p commonware-deployer --features aws

# 1. Generate the deployment bundle (./deploy must not exist).
if [ -d ./deploy ]; then
    read -r -p "./deploy exists — remove and regenerate? [y/N] " answer
    [ "$answer" = "y" ] || exit 1
    rm -rf ./deploy
fi
# One unpinned spammer stream rotates 50k-55k transaction batches across one
# million recurring accounts, with thirty-two ordered-refill batches in flight.
# Proposal starts are at least 100ms apart, which bounds empty-block bursts
# without delaying the slower full-block path. At maximum jitter, the in-flight
# transactions occupy about 246 MiB encoded, within the 256 MiB mempool cap.
# C8a.8xlarge exposes 32 vCPUs. Three Tokio workers, twenty engine workers,
# and nine isolated ingress workers keep long-lived pool concurrency at 32
# while transaction admission cannot queue
# ahead of consensus-critical work. Nine ingress workers leave headroom above
# the roughly seven cores of admission work modeled at 750k TPS.
# A 24 MiB proposal holds about three average spammer batches. With at least
# five finalized blocks per second, that operating point exceeds 750k TPS.
# Ed25519 verification batch-decompresses each block's unique keys directly.
# Paged storage uses 4 KiB physical pages with checksum-adjusted payloads.
# Page-size changes require fresh data directories, which this deployment creates.
# Marshal's three view caches plus finalized archive can transiently retain
# about 19,207 full blocks at section boundaries. Six hundred GiB volumes cover
# that 456 GiB benchmark envelope without changing pruning. This is not a
# lifetime bound for arbitrary certified-block repairs, so longer fault-heavy
# runs must monitor disk growth or provision more space. io2 Block Express
# removes gp3 latency and throughput as benchmark variables.
# Seven-region round-robin placement remains below both each region's c8a vCPU
# quota and its 100k aggregate io2 IOPS quota with 32-core validators.
DEPLOY_REGIONS="us-east-1,us-east-2,eu-west-1,eu-central-1,ap-northeast-1,eu-south-2,us-west-2"
# Sample traces without making telemetry part of the benchmark workload.
cargo run --locked --bin constantinople-deploy -- generate \
    --validators 50 --leader-term-length 1000000 --leader-delay-ms 100 --relayer --spammer \
    --spammer-accounts 1000000 --spammer-batch-size 50000 --spammer-accounts-jitter 0.1 \
    --spammer-rayon-threads 30 --spammer-in-flight-batches 32 \
    --output-dir ./deploy --worker-threads 3 --rayon-threads 20 --ingress-rayon-threads 9 \
    --max-propose-bytes 25165824 --max-pool-bytes 268435456 \
    --state-page-cache-bytes 2147483648 --other-page-cache-bytes 2147483648 \
    remote \
    --http-cidr 0.0.0.0/0 \
    --regions "$DEPLOY_REGIONS" \
    --instance-type c8a.8xlarge --storage-size 600 \
    --storage-class io2 --storage-iops 8000 \
    --spammer-instance-type c8a.8xlarge \
    --monitoring-instance-type c8a.4xlarge --monitoring-storage-size 100 \
    --dashboard ./dashboard.json --traces 0.01

for artifact in config.yaml spammer.yaml; do
    if [ ! -f "./deploy/$artifact" ]; then
        echo "deployment generator did not create deploy/$artifact" >&2
        exit 1
    fi
done

# 2. Build binaries into ./deploy. C8a validators and the spammer use the Zen 5 build.
just validator-amd-binary spammer-amd-binary
for artifact in validator spammer; do
    if [ ! -x "./deploy/$artifact" ]; then
        echo "build did not create executable deploy/$artifact" >&2
        exit 1
    fi
done

# 3. Create the deployment.
(
    cd deploy
    cargo run --locked --release --manifest-path "$DEPLOYER_MANIFEST" \
        -p commonware-deployer --features aws -- aws create --config config.yaml
)
