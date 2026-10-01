# `constantinople-validator`

Validator binary for the constantinople blockchain.

The YAML `max_propose_bytes` setting limits the complete encoded block, including
framing. It defaults to 8 MiB and must not exceed the shared 16 MiB consensus cap.
Startup also rejects budgets too small for an empty block with the largest
supported header. The validator derives a signed-transaction byte budget by
reserving encoding overhead. Mempool selection, submission admission, and relayer
admission use that derived budget.

At least four DKG participants are required. The encoded block cap is independent
of participant count. Shard decoding derives its raw shard limit from the shared
cap and agreed participant count, so a smaller local proposal budget still
permits receiving valid peer blocks. Network messages remain capped at 32 MiB.
