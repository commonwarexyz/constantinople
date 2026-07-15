# `constantinople-docker`

This directory contains the Docker build configuration used to compile Constantinople's deployable
binaries for AWS Graviton, AMD, and Intel instances.

## Install Dependencies

* `docker`: https://www.docker.com/get-started/
* `docker-buildx`: https://github.com/docker/buildx?tab=readme-ov-file#installing

## Building Locally

The `justfile` wraps the Docker build flow:

```sh
just build-graviton-image
```

This builds the ARM64 image for AWS Graviton (`linux/arm64`).

To build the Intel image, e.g. for `c8i` instances, run:

```sh
just build-intel-image
```

The Intel build uses `x86_64-unknown-linux-gnu` with `target-cpu=graniterapids`, which is the
closest Rust CPU target to AWS C8i's Intel Xeon 6 processors.

To build the AMD image, e.g. for `c8a` instances, run:

```sh
just build-amd-image
```

The AMD build uses `x86_64-unknown-linux-gnu` with `target-cpu=znver5`, which matches AWS C8a's
AMD EPYC 9R45 processors. Do not deploy the Intel build to C8a instances: the Granite Rapids
target can emit instructions that crash with `SIGILL` on AMD hosts.

All builder images are built for the local Docker host architecture and then cross-compile the
requested binary to the target triple. This avoids running `rustc` inside an emulated
`linux/amd64` container on Apple Silicon.

#### Build Deployable Binaries

To build the Graviton binary, run:

```sh
just validator-graviton-binary
```

To build the Intel validator binary, run:

```sh
just validator-intel-binary
```

To build the AMD validator binary, run:

```sh
just validator-amd-binary
```

To build the shared indexer binaries for Graviton, run:

```sh
just chain-indexer-graviton-binary
just metadata-indexer-graviton-binary
just qmdb-indexer-graviton-binary
```

To build the shared indexer binaries for Intel, run:

```sh
just chain-indexer-intel-binary
just metadata-indexer-intel-binary
just qmdb-indexer-intel-binary
```

To build the shared indexer binaries for AMD, run:

```sh
just chain-indexer-amd-binary
just metadata-indexer-amd-binary
just qmdb-indexer-amd-binary
```

`just graviton-binaries`, `just intel-binaries`, and `just amd-binaries` build the full
remote-deploy set:

* `deploy/validator`
* `deploy/validator-debug`
* `deploy/spammer`
* `deploy/spammer-debug`
* `deploy/chain-indexer`
* `deploy/chain-indexer-debug`
* `deploy/metadata-indexer`
* `deploy/metadata-indexer-debug`
* `deploy/qmdb-indexer`
* `deploy/qmdb-indexer-debug`

#### Troubleshooting

If you receive an error like the following:

```
ERROR: Multi-platform build is not supported for the docker driver.
Switch to a different driver, or turn on the containerd image store, and try again.
Learn more at https://docs.docker.com/go/build-multi-platform/
```

Create and activate a new builder and retry the bake command.

```sh
docker buildx create --name commonware-builder --use
```
