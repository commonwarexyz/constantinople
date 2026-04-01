# Use the same Ubuntu version as `commonware-deployer`.
FROM arm64v8/ubuntu:24.04

RUN apt-get update && apt-get install -y \
    binutils \
    build-essential \
    ca-certificates \
    curl \
    git \
    libssl-dev \
    pkg-config \
    protobuf-compiler

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"
ENV PKG_CONFIG_PATH="/usr/lib/aarch64-linux-gnu/pkgconfig"
ENV RUSTFLAGS="-C target-cpu=neoverse-v2"
ENV CARGO_PROFILE_RELEASE_DEBUG=true

RUN rustup default stable
RUN rustup target add aarch64-unknown-linux-gnu

ARG PACKAGE_NAME
ARG BINARY_NAME
ARG OUTPUT_NAME

ENV PACKAGE_NAME="${PACKAGE_NAME}"
ENV BINARY_NAME="${BINARY_NAME}"
ENV OUTPUT_NAME="${OUTPUT_NAME}"

WORKDIR /constantinople

ENTRYPOINT ["/bin/bash", "-c"]
CMD ["cargo build --locked --release --package ${PACKAGE_NAME} --bin ${BINARY_NAME} --target aarch64-unknown-linux-gnu && cp target/aarch64-unknown-linux-gnu/release/${BINARY_NAME} docker/${OUTPUT_NAME}-debug && strip -o docker/${OUTPUT_NAME} docker/${OUTPUT_NAME}-debug"]
