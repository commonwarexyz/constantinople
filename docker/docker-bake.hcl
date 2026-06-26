variable "REGISTRY" {
  default = "ghcr.io"
}

variable "REPOSITORY" {
  default = "commonwarexyz/constantinople"
}

variable "DEFAULT_TAG" {
  default = "local"
}

variable "BASE_IMAGE" {
  default = "ubuntu:24.04"
}

variable "RUST_TOOLCHAIN" {
  default = "stable"
}

target "graviton" {
  context = "."
  dockerfile = "docker/Dockerfile"
  tags = ["constantinople-builder:graviton-${DEFAULT_TAG}"]
  args = {
    BASE_IMAGE = BASE_IMAGE
    RUST_TOOLCHAIN = RUST_TOOLCHAIN
    TARGET_TRIPLE = "aarch64-unknown-linux-gnu"
    TARGET_CARGO_NAME = "AARCH64_UNKNOWN_LINUX_GNU"
    TARGET_CC_NAME = "aarch64_unknown_linux_gnu"
    TARGET_CPU = "neoverse-v2"
    TARGET_LINKER = "aarch64-linux-gnu-gcc"
    TARGET_CXX = "aarch64-linux-gnu-g++"
    TARGET_AR = "aarch64-linux-gnu-ar"
    TARGET_STRIP = "aarch64-linux-gnu-strip"
  }
}

target "intel" {
  context = "."
  dockerfile = "docker/Dockerfile"
  tags = ["constantinople-builder:intel-${DEFAULT_TAG}"]
  args = {
    BASE_IMAGE = BASE_IMAGE
    RUST_TOOLCHAIN = RUST_TOOLCHAIN
    TARGET_TRIPLE = "x86_64-unknown-linux-gnu"
    TARGET_CARGO_NAME = "X86_64_UNKNOWN_LINUX_GNU"
    TARGET_CC_NAME = "x86_64_unknown_linux_gnu"
    TARGET_CPU = "graniterapids"
    TARGET_LINKER = "x86_64-linux-gnu-gcc"
    TARGET_CXX = "x86_64-linux-gnu-g++"
    TARGET_AR = "x86_64-linux-gnu-ar"
    TARGET_STRIP = "x86_64-linux-gnu-strip"
  }
}

target "amd" {
  context = "."
  dockerfile = "docker/Dockerfile"
  tags = ["constantinople-builder:amd-${DEFAULT_TAG}"]
  args = {
    BASE_IMAGE = BASE_IMAGE
    RUST_TOOLCHAIN = RUST_TOOLCHAIN
    TARGET_TRIPLE = "x86_64-unknown-linux-gnu"
    TARGET_CARGO_NAME = "X86_64_UNKNOWN_LINUX_GNU"
    TARGET_CC_NAME = "x86_64_unknown_linux_gnu"
    TARGET_CPU = "znver5"
    TARGET_LINKER = "x86_64-linux-gnu-gcc"
    TARGET_CXX = "x86_64-linux-gnu-g++"
    TARGET_AR = "x86_64-linux-gnu-ar"
    TARGET_STRIP = "x86_64-linux-gnu-strip"
  }
}
