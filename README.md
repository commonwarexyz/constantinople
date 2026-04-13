<h1 align="center">
  <img src="./assets/banner.png" alt="Constantinople" width="35%" align="center">
</h1>

<h4 align="center">
    A high-throughput blockchain built on <a href="https://commonware.xyz"><code>commonware</code></a> primitives.
</h4>

<p align="center">
  <a href="https://github.com/commonwarexyz/constantinople/actions/workflows/tests.yaml"><img src="https://img.shields.io/github/actions/workflow/status/commonwarexyz/constantinople/tests.yaml?style=flat&labelColor=1C2C2E&label=ci&color=BEC5C9&logo=GitHub%20Actions&logoColor=BEC5C9" alt="CI"></a>
  <a href="https://app.codecov.io/gh/commonwarexyz/constantinople"><img src="https://img.shields.io/codecov/c/gh/commonwarexyz/constantinople?style=flat&labelColor=1C2C2E&logo=Codecov&color=BEC5C9&logoColor=BEC5C9" alt="Codecov"></a>
  <a href="https://github.com/commonwarexyz/constantinople/blob/main/LICENSE.md"><img src="https://img.shields.io/badge/License-MIT-d1d1f6.svg?style=flat&labelColor=1C2C2E&color=BEC5C9&logo=googledocs&label=license&logoColor=BEC5C9" alt="License"></a>
  <a href="https://commonware.xyz"><img src="https://img.shields.io/badge/Commonware-854a15?style=flat&labelColor=1C2C2E&color=BEC5C9&logo=asterisk&logoColor=BEC5C9" alt="commonware"></a>
</p>

<p align="center">
  <a href="#overview">Overview</a> •
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
| [`commonware-p2p`](https://github.com/commonwarexyz/monorepo/tree/main/commonware-p2p)                       | Authenticated peer-to-peer networking with discovery     |

## Demo

> [!IMPORTANT]
> TODO.

## Deployment

See [`deploy/README.md`](./bin/deploy/README.md).

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## License

See [`LICENSE.md`](./LICENSE.md).

<!-- Links -->

[`commonware`]: https://github.com/commonwarexyz/commonware
