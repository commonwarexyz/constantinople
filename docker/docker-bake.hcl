variable "REGISTRY" {
  default = "ghcr.io"
}

variable "REPOSITORY" {
  default = "commonwarexyz/constantinople"
}

variable "DEFAULT_TAG" {
  default = "local"
}

variable "PLATFORMS" {
  default = "linux/arm64"
}

target "constantinople-validator" {
  context = "."
  dockerfile = "docker/Dockerfile"
  platforms = split(",", PLATFORMS)
  tags = ["constantinople-validator-builder:${DEFAULT_TAG}"]
  args = {
    PACKAGE_NAME = "constantinople-validator"
    BINARY_NAME = "constantinople"
    OUTPUT_NAME = "validator"
  }
}

target "constantinople-spammer" {
  context = "."
  dockerfile = "docker/Dockerfile"
  platforms = split(",", PLATFORMS)
  tags = ["constantinople-spammer-builder:${DEFAULT_TAG}"]
  args = {
    PACKAGE_NAME = "constantinople-spammer"
    BINARY_NAME = "constantinople-spammer"
    OUTPUT_NAME = "spammer"
  }
}
