<h1 align="center">
  <img src="./assets/banner.png" alt="Constantinople" width="35%" align="center">
</h1>

<h4 align="center">
    A high-throughput blockchain built on <a href="https://commonware.xyz"><code>commonware</code></a> primitives.
</h4>

<p align="center">
  <a href="https://github.com/commonwarexyz/constantinople/actions/workflows/tests.yaml"><img src="https://img.shields.io/github/actions/workflow/status/commonwarexyz/constantinople/tests.yaml?style=flat&labelColor=1C2C2E&label=ci&color=BEC5C9&logo=GitHub%20Actions&logoColor=BEC5C9" alt="CI"></a>
  <a href="https://app.codecov.io/gh/commonwarexyz/constantinople"><img src="https://img.shields.io/codecov/c/gh/commonwarexyz/constantinople?style=flat&labelColor=1C2C2E&logo=Codecov&color=BEC5C9&logoColor=BEC5C9" alt="Codecov"></a>
  <img src="https://img.shields.io/badge/License-MIT%20&%20Apache%202.0-d1d1f6.svg?style=flat&labelColor=1C2C2E&color=BEC5C9&logo=googledocs&label=license&logoColor=BEC5C9" alt="License">
  <a href="https://commonware.xyz"><img src="https://img.shields.io/badge/Commonware-854a15?style=flat&labelColor=1C2C2E&color=BEC5C9&logo=asterisk&logoColor=BEC5C9" alt="commonware"></a>
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#packages">Packages</a> •
  <a href="#demo">Demo</a> •
  <a href="#deployment">Deployment</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a>
</p>

## Overview

Constantinople is a high-throughput account-model blockchain example built on top of [`commonware`] primitives.

| Primitive                                                                                                    | Role                                                     |
|--------------------------------------------------------------------------------------------------------------|----------------------------------------------------------|
| [`commonware-consensus`](https://github.com/commonwarexyz/monorepo/tree/main/commonware-consensus) (simplex) | Single-epoch BFT consensus with BLS threshold signatures |
| [`commonware-consensus`](https://github.com/commonwarexyz/monorepo/tree/main/commonware-consensus) (marshal) | Erasure-coded broadcast and backfill of finalized blocks |
| [`commonware-storage`](https://github.com/commonwarexyz/monorepo/tree/main/commonware-storage) (QMDB)        | Merkleized key-value database for state and transactions |
| [`commonware-glue`](https://github.com/commonwarexyz/monorepo/tree/main/commonware-glue) (stateful)          | Speculative state management and sync                    |
| [`commonware-p2p`](https://github.com/commonwarexyz/monorepo/tree/main/commonware-p2p) (discovery)           | Authenticated peer-to-peer networking with discovery     |

## Packages

| Package                                               | Description                                                       |
|-------------------------------------------------------|-------------------------------------------------------------------|
| [`constantinople-indexer`](./crates/indexer/README.md) | Publishes finalized block artifacts and SQL metadata to exoware.  |
| [`constantinople-explorer`](./explorer/README.md)      | Streams indexer metadata into a live React block explorer.        |

## Demo

Generate a local four-validator network with the indexer secondary, relayer,
spammer, metadata indexer, QMDB indexer, and explorer:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 4 \
  --indexer \
  --relayer \
  --output-dir ./local \
  --spammer --spammer-accounts 4096 --spammer-accounts-jitter 0.1 \
  local
```

The command prints an `mprocs` invocation that starts the generated local
network. See [`bin/deploy/README.md`](./bin/deploy/README.md) for port and
service details.

## Deployment

See [`deploy/README.md`](./bin/deploy/README.md).

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## License

See [`LICENSE-MIT`](./LICENSE-MIT) & [`LICENSE-APACHE`](./LICENSE-APACHE).

<!-- Links -->

[`commonware`]: https://github.com/commonwarexyz/commonware
