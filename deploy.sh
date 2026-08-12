#!/usr/bin/env bash
# Generate, build, and deploy a remote Constantinople testnet.
set -euo pipefail
cd "$(dirname "$0")"

for tool in cargo just docker deployer; do
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

# 1. Generate the deployment bundle (./deploy must not exist).
if [ -d ./deploy ]; then
    read -r -p "./deploy exists — remove and regenerate? [y/N] " answer
    [ "$answer" = "y" ] || exit 1
    rm -rf ./deploy
fi
# One unpinned spammer stream supplies the active stable leader with sixteen
# source-ordered batches in flight. Proposal starts are at least 100ms apart,
# which bounds empty-block bursts without delaying the slower full-block path.
# At maximum jitter, the in-flight transactions occupy about 123 MiB encoded,
# so the 256 MiB mempool leaves headroom for continuous admission.
# I7i.4xlarge exposes 16 SMT vCPUs. The three Tokio workers and thirteen
# Rayon workers keep long-lived pool concurrency at 16 total.
# Paged storage uses 4 KiB physical pages with checksum-adjusted payloads.
# Page-size changes require fresh data directories, which this deployment creates.
# Sample traces without making telemetry part of the benchmark workload.
cargo run --locked --bin constantinople-deploy -- generate \
    --validators 50 --leader-term-length 1000000 --leader-delay-ms 100 --relayer --spammer \
    --spammer-accounts 50000 --spammer-accounts-jitter 0.1 \
    --spammer-rayon-threads 14 --spammer-in-flight-batches 16 \
    --output-dir ./deploy --worker-threads 3 --rayon-threads 13 \
    --public-key-cache-size 5000000 \
    --max-propose-bytes 16777216 --max-pool-bytes 268435456 \
    --state-page-cache-bytes 2147483648 --other-page-cache-bytes 2147483648 \
    remote \
    --http-cidr 0.0.0.0/0 \
    --regions us-east-1,us-west-1,eu-west-1,ap-northeast-1,eu-north-1,ap-south-1,sa-east-1,eu-central-1,ap-northeast-2,ap-southeast-2 \
    --instance-type i7i.4xlarge --storage-size 150 \
    --storage-iops 5000 --storage-throughput 500 \
    --spammer-instance-type c8a.4xlarge \
    --monitoring-instance-type c8a.4xlarge --monitoring-storage-size 100 \
    --dashboard ./dashboard.json --traces 0.01

for artifact in config.yaml spammer.yaml; do
    if [ ! -f "./deploy/$artifact" ]; then
        echo "deployment generator did not create deploy/$artifact" >&2
        exit 1
    fi
done

# 2. Build binaries into ./deploy. I7i validators use an Emerald Rapids build;
# the C8a spammer retains its Zen 5 build.
just validator-i7i-binary spammer-amd-binary
for artifact in validator spammer; do
    if [ ! -x "./deploy/$artifact" ]; then
        echo "build did not create executable deploy/$artifact" >&2
        exit 1
    fi
done

# 3. Create the deployment.
(cd deploy && deployer aws create --config config.yaml)
