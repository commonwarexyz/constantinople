# `constantinople-docker`

This directory contains the Docker build configuration used to compile Constantinople's deployable
binaries for both AWS Graviton and Intel instances.

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

Both builder images are built for the local Docker host architecture and then cross-compile the
validator to the requested target triple. This avoids running `rustc` inside an emulated
`linux/amd64` container on Apple Silicon.

#### Build Validator Binary

To build the Graviton binary, run:

```sh
just validator-graviton-binary
```

To build the Intel validator binary, run:

```sh
just validator-intel-binary
```

Either command writes:

* `deploy/validator`
* `deploy/validator-debug`

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
