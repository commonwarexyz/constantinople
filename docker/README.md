# `commonware-docker`

This directory contains the Docker build configuration used to compile Constantinople's deployable
ARM64 binaries for AWS Graviton.

## Install Dependencies

* `docker`: https://www.docker.com/get-started/
* `docker-buildx`: https://github.com/docker/buildx?tab=readme-ov-file#installing

## Building Locally

To build a compiler image locally, use `docker buildx bake`:

```sh
export TARGET="<target_name>"

docker buildx bake \
  --progress plain \
  -f docker/docker-bake.hcl \
  $TARGET
```

Available targets:

* `constantinople-validator`
* `constantinople-spammer`

By default, these build ARM64 images for AWS Graviton (`linux/arm64`).

#### Build Validator Binary

```sh
docker buildx bake -f docker/docker-bake.hcl constantinople-validator
docker run --rm -v ${PWD}:/constantinople constantinople-validator-builder:local
```

This writes:

* `docker/validator`
* `docker/validator-debug`

#### Build Spammer Binary

```sh
docker buildx bake -f docker/docker-bake.hcl constantinople-spammer
docker run --rm -v ${PWD}:/constantinople constantinople-spammer-builder:local
```

This writes:

* `docker/spammer`
* `docker/spammer-debug`

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
