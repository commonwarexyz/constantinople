# @exowarexyz/sdk

[![npm](https://img.shields.io/npm/v/@exowarexyz/sdk.svg)](https://www.npmjs.com/package/@exowarexyz/sdk)

Interact with the Exoware API in TypeScript.

## Status

`@exowarexyz/sdk` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.

## Store Key Prefixes

Use `StoreKeyPrefix` when multiple logical QMDB, SQL, or raw KV instances share one Store database. The prefix is applied by the SDK, so higher-level clients keep using their normal logical keys:

```ts
import { Client, StoreKeyPrefix, StoreWriteBatch } from '@exowarexyz/sdk';

const base = new Client('http://localhost:10000').store();
const orders = base.withKeyPrefix(new StoreKeyPrefix(4, 1));
const accounts = base.withKeyPrefix(new StoreKeyPrefix(4, 2));

const batch = new StoreWriteBatch()
    .push(orders, orderKey, orderValue)
    .push(accounts, accountKey, accountValue);
const sequence = await batch.commit(base);
```

## Generated TypeScript (`gen/ts`)

Protobuf-ES output lives under **`src/gen/ts/`** (mirrors the repo [`proto/`](../../proto/) tree, e.g. `proto/store/v1/query.proto` → `src/gen/ts/store/v1/query_pb.ts`). To regenerate after proto changes, run `../../gen.sh` from the repo root.

Integration tests spawn the Rust simulator via `jest.globalSetup.ts` (`cargo build --package exoware-simulator`).
