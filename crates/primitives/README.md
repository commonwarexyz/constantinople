# `constantinople-primitives`

Core types for the `constantinople` blockchain.

Accounts encode a balance, nonce base, nonce bitmap, and transaction count as
four big-endian `u64` values (32 bytes). The count starts at zero and advances
once for every accepted transaction involving the account, including self-transfers.

`TransactionHistoryEntry<D>` encodes a sealed message digest followed by the
sender and recipient's zero-based history indices, each a big-endian `u64`.
For SHA-256 the value is 48 bytes. A self-transfer carries the same index in
both fields. The account count authenticates the length of its history;
the indexed entries bind its successive transactions to that length.
