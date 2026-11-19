# Plan: MAC-authenticated transactions in Constantinople

Implements the Simplex construction of "Short Signature-Free Transactions in Byzantine
Consensus" (papers/maced-tx, Sections 3-4) in this repository. Plan agreed point by point
on 19 Nov 2026. No code changed yet.

Terms follow the paper: tag, authenticator (a user's n tags), submission, column (the tags
of one block for one validator), report (a validator's yes/no per entry), R (the
notarisation of the parent carried by a block), status, Chk.

## 1. Decisions

| # | Question | Decision |
| --- | --- | --- |
| 1 | Commonware patch | Patch is fine; carried in this repo (section 3) |
| 2 | Signatures | Kept as a second mode next to MACs |
| 3 | When to notarize | Wait until the block is rebuilt from shards, then report and notarize |
| 4 | Validator DH key | Separate long-lived X25519 key |
| 5 | Chk key | (proposer, transaction), as in the paper, for now |
| 6 | Client reply | Only after execution |
| 7 | Staging | Indexer and explorer converted alongside the core |
| 8 | History log | A block's transaction digests are appended at inclusion |
| 9 | Outcomes | The next block carries one applied bit per entry of its parent |
| 10 | Explorer wallet | Passkey signatures only for now |

## 2. Facts that shape the design (pinned commonware rev 2fd3af8)

1. Simplex is hard-wired to N3f1 (scheme marker traits; batcher actor.rs:135, round.rs:70).
2. A vote's signature must be fixed-size (certificate::Scheme::Signature: CodecFixed;
   Attestation decodes through Lazy<T: FixedSize>).
3. The chain uses the BLS threshold scheme; its certificates hold no individual votes.
4. With coding marshal a validator notarizes once its own shard is valid; the application
   verifies the rebuilt block before the finalize vote.
5. glue::stateful apply(block) is given only that block. Marshal answers parent lookups
   locally first, stores the state-sync anchor block, and denies peer fetches at or below
   its processed height.
6. Votes are journaled before broadcast and replayed, not re-signed, after a restart.
7. The block digest is the header hash. Today the header pins the body through the
   post-execution transactions_root.
8. A sender's first MAC transaction costs each validator one Diffie-Hellman, about one
   signature verification. The saving is for senders whose key is cached.

## 3. Commonware patch, in this repo

- vendor/commonware-consensus and vendor/commonware-cryptography: copies of the two
  crates at the pinned rev with standalone manifests (workspace inheritance resolved,
  sibling crates as git dependencies at the same rev, the crates' lints kept).
- Cargo.toml: [patch] on the monorepo git source for these two crates, and
  exclude = ["vendor"] so they are not workspace members (not linted or tested with ours).
- Checked in a scratch clone: the whole graph, exoware crates included, resolves to the
  copies and constantinople-primitives compiles. Size: about 188k lines.
- The delta from upstream is also kept as a patch file next to the copies, for a later
  fork or upstream change.
- The patch itself:
  1. simplex takes its fault model from the scheme (S::Faults) instead of N3f1;
  2. attestation signatures may be variable-size; built-in schemes keep lazy decoding.
- Acceptance: the upstream tests of both crates pass with the patch.

## 4. Protocol mapping

| Paper | Here |
| --- | --- |
| processor p_i | validator, by index in the sorted participant set |
| iteration h, lead(h) | view, the elector's leader |
| block (h, H(c), Tr, R) | header (with simplex context) + R + outcomes of parent + Tr |
| vote for b with report | notarize vote whose attestation is (report, signature) |
| vote for the dummy block | nullify vote |
| (finalise, h) | finalize vote |
| last non-dummy block of c | context.parent |
| pair (b, column) | shards + one column message per validator |
| Apply | SelectiveExecutor rule, one outcome per entry |

## 5. Design

### 5.1 Two kinds of transactions
The sender's key type decides the mode.
- ed25519 or secp256r1 (passkey) sender: signature carried in the block, checked at block
  verification as today (an invalid signature makes the block invalid). Status always yes.
- X25519 sender: no signature. Tags travel outside the block. Status from R.
All entries of a block execute together, one block later.

### 5.2 Keys, tags, submissions (MAC mode)
- Each validator has an X25519 key next to its ed25519 identity. Public keys are listed
  in node, spammer and deploy config; a startup check catches a mismatched list.
- K(u,i) = KDF(DH(u,i), pk_u, pk_i), with separate tag and channel subkeys. Low-order
  points are rejected. Validators cache K(u,i) per sender.
- Tag = first t bits of keyed BLAKE3 over (proposer index, transaction digest).
  t is a function of n fixed in code (lambda = 128, Q = 2^40): n=6: 86; n=16: 45;
  n=50: 21; n=256: 7.
- Submission = (proposer, transaction, authenticator, full-length MAC under the channel
  key shared with the proposer). The proposer admits it only if it is named, the MAC
  verifies and its own tag is correct.

### 5.3 Votes
- New scheme: ed25519 keys, N5f1, attestation = (report, signature over namespace,
  subject, report). Nullify and finalize carry an empty report. Certificate = signer
  bitmap + attestations.
- Report: one bit per MAC entry of the block (signed entries need none). Encoded as a
  bitmap or a short list of rejected positions. A malformed report counts as all-no.
- Chk: one verdict per (proposer, transaction digest). "No" verdicts are durable and
  never recomputed; "yes" verdicts are recomputed on demand.

### 5.4 Proposal and notarize gate
- Leader: propose() takes submissions and signed transactions from the mempool,
  registers the columns and its own report under the block's commitment. When simplex
  relays the proposal, each validator gets its column on a new p2p channel.
- Validator: relays its shard at once, as today. It answers simplex's verify only when
  its shard is valid, the block is rebuilt, the leader's column has arrived and the tags
  are compared. No column or no block means no vote; the view times out.
- R, signatures, distinct entries, outcomes and roots are checked before the finalize
  vote, where block verification is today.

### 5.5 Blocks
- Block h = header + R (notarisation of h-1) + outcomes of h-1 + transactions.
- Header gains digests that pin R and the outcome bits. transactions_root pins the body.
- R comes from simplex's activity stream via a small cache. Without R for the parent the
  proposal fails and the view is nullified.
- The worst-case size of R and of the outcome bits is reserved in the block budget.

### 5.6 Execution
- Status of a MAC entry of block h-1: yes iff at least 2f+1 reports in block h's R say yes.
- Block h's state = parent state, then the yes entries of body(h-1) applied in order with
  the SelectiveExecutor rule. Outcome bit = applied or not.
- Block h's history log = parent log plus the digests of body(h).
- verify and propose take the parent body from the ancestry they receive; apply takes it
  from marshal (BlockProvider::subscribe_parent). A missing body waits. R's signatures
  are checked in verify only.

### 5.7 Mempool, relayer, spammer, clients
- Mempool: two admission paths (batch signature verification; channel MAC and own tag).
  A MAC submission that was selected but did not reach a finalized block returns to the
  pool. A reply is sent when the block carrying the outcome bit is finalized: applied,
  rejected, or dropped.
- Relayer: fan-out stays for signed transactions; MAC submissions go to the named
  proposer.
- Spammer: mode flag (signatures or MACs), for like-for-like comparison. In MAC mode it
  derives K(u,i) once per account and validator.

### 5.8 Config and deploy
- Validator config: no dkg_output, dkg_share, num_validators; adds the X25519 secret and
  the validators' X25519 public keys. Voting status from membership in primary_validators.
- Deploy tool: no DKG, at least 6 validators, emits the participant list as the
  explorer's verification material.

### 5.9 Indexer and explorer
- Indexer: new certificate type in the queue format (version bump, fresh index);
  transaction rows cover both kinds; an applied flag from the outcome bits; account rows
  lag by one block.
- Explorer: its own certificate verifier through the exoware verifier interface; header
  parser updated; outcome shown from the outcome bits; passkey wallet unchanged.

## 6. Differences from the paper
1. Commonware-style simplex: nullify votes, a certification step, certificates fetched
   on demand.
2. Validity conditions (i)-(iii) are checked before the finalize vote, not the notarize
   vote. A notarized block that fails is skipped like a dummy block.
3. The block reaches validators as shards, so the vote waits for the rebuilt block.
4. Chk stores only "no" verdicts durably.
5. Apply is this chain's rule (block-start balances, bitmap nonces).
6. Signed transactions coexist with MAC ones.
7. Section 5 (settling early) is not included.

## 7. Code layout
- vendor/: the two patched commonware crates.
- crates/auth (new): keys, key agreement, tags, authenticator, column, submission,
  report, status rule, tag-length table, the vote scheme, the Chk store.
- crates/primitives: transaction kinds, block with R and outcomes, budgets.
- crates/application: status-driven execution, R validation, parent-body lookup.
- crates/engine: scheme wiring, column channel, report book, notarize gate, R cache.
- crates/mempool, bin/validator, bin/spammer, bin/deploy, crates/indexer, explorer.

## 8. Order of work
Complete only when all four parts are in; just lint and just test green after each.
0. Vendor and patch commonware; upstream tests pass.
1. Core: crates/auth, primitives, application, engine. Deterministic multi-node tests:
   honest run with fast path; authenticator wrong for some validators; forged entry with
   random tags, retried; withheld columns; restart keeps "no" verdicts; leader without
   R; mixed signed and MAC blocks; apply on a non-voting node, after state sync, after a
   restart with pruning.
2. Network: mempool, relayer, validator config, spammer, deploy tool and its tests.
   A local network of 6+ validators runs under the spammer in both modes.
3. Indexer and explorer.

## 9. Risks to retire early
- R for the parent missing at a correct leader that learned the parent only through a
  finalization. Fallback: fetch the notarization from peers.
- Size limits: reports on the vote channel, R in the block budget, column messages.
- Throughput of the SelectiveExecutor path versus today's parallel verify path; measure
  with the existing benches.
- Reply latency: about 7 message delays for every transaction, signed ones included.

## 10. Later, not in this plan
Pre-execution of the parent's entries before the next block arrives; replies at status
time; pruning of "no" verdicts by spent nonce; MAC wallet in the explorer; moving the
patch to a fork or upstream.

