ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}

ARG RUST_TOOLCHAIN=stable
ARG TARGET_TRIPLE
ARG TARGET_CARGO_NAME
ARG TARGET_CC_NAME
ARG TARGET_CPU
ARG TARGET_LINKER
ARG TARGET_CXX
ARG TARGET_AR
ARG TARGET_STRIP

RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
    binutils-aarch64-linux-gnu \
    binutils-x86-64-linux-gnu \
    build-essential \
    ca-certificates \
    cmake \
    clang \
    llvm-dev \
    libclang-dev \
    curl \
    gcc-aarch64-linux-gnu \
    gcc-x86-64-linux-gnu \
    g++-aarch64-linux-gnu \
    g++-x86-64-linux-gnu \
    git \
    libc6-dev-arm64-cross \
    libc6-dev-amd64-cross \
    libgflags-dev \
    pkg-config \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain ${RUST_TOOLCHAIN} --profile minimal

ENV PATH="/root/.cargo/bin:${PATH}" \
    PACKAGE_NAME="constantinople-validator" \
    BINARY_NAME="constantinople" \
    OUTPUT_NAME="validator" \
    TARGET_TRIPLE="${TARGET_TRIPLE}" \
    TARGET_CARGO_NAME="${TARGET_CARGO_NAME}" \
    TARGET_CC_NAME="${TARGET_CC_NAME}" \
    TARGET_CPU="${TARGET_CPU}" \
    TARGET_LINKER="${TARGET_LINKER}" \
    TARGET_CXX="${TARGET_CXX}" \
    TARGET_AR="${TARGET_AR}" \
    TARGET_STRIP="${TARGET_STRIP}" \
    CARGO_PROFILE_RELEASE_DEBUG=true

RUN rustup target add ${TARGET_TRIPLE}

WORKDIR /constantinople

ENTRYPOINT ["/bin/bash", "-c"]
CMD ["set -euo pipefail && export CARGO_TARGET_${TARGET_CARGO_NAME}_LINKER=${TARGET_LINKER} && export CARGO_TARGET_${TARGET_CARGO_NAME}_RUSTFLAGS=\"-C target-cpu=${TARGET_CPU}\" && export CC_${TARGET_CC_NAME}=${TARGET_LINKER} && export CXX_${TARGET_CC_NAME}=${TARGET_CXX} && export AR_${TARGET_CC_NAME}=${TARGET_AR} && mkdir -p deploy && cargo build --locked --release --package ${PACKAGE_NAME} --bin ${BINARY_NAME} --target ${TARGET_TRIPLE} && cp target/${TARGET_TRIPLE}/release/${BINARY_NAME} deploy/${OUTPUT_NAME}-debug && ${TARGET_STRIP} -o deploy/${OUTPUT_NAME} deploy/${OUTPUT_NAME}-debug"]
