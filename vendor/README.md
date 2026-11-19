# Patched commonware crates

`commonware-consensus` and `commonware-cryptography` from
[commonwarexyz/monorepo](https://github.com/commonwarexyz/monorepo) at
`2fd3af88f2cdeb6424d82f45961f803d812d6c99`, the rev pinned in the root `Cargo.toml`, with
the changes in `commonware.patch`. The root manifest's `[patch]` section makes every crate
in the graph, the exoware ones included, use these copies.

## The patch

1. Simplex takes its fault model from the scheme. The marker traits
   `simplex::scheme::CertificateVerifier` and `Scheme` no longer require
   `Faults = N3f1`, and the batcher's quorums are `n - f` under the scheme's
   `Verifier::Faults`. The built-in schemes still use `N3f1`.
2. An attestation's signature may have a variable-size encoding.
   `certificate::Scheme::Signature` is bounded by `Codec` instead of `CodecFixed`, and
   `Attestation` reads it through the new `Scheme::read_signature`. The default decodes
   at once; the built-in schemes override it to keep decoding lazily, and their encodings
   are unchanged.

## Layout

- `commonware-consensus/`, `commonware-cryptography/`: upstream sources plus the patch.
  The manifests are generated: workspace inheritance is written out, the upstream lints
  are kept, and sibling commonware crates are git dependencies at the same rev.
- `commonware.patch`: the source changes, with upstream paths, so it also applies to a
  monorepo checkout (`git apply vendor/commonware.patch`).
- `Cargo.toml`, `Cargo.lock`, `clippy.toml`, `.config/nextest.toml`: a workspace of the
  two copies with upstream's profiles, lockfile, lint and test settings. The root
  workspace excludes `vendor`, so `just lint` and `just test` do not cover the copies.
- `vendor.py`: produces all of the above from a monorepo checkout.

## Upstream tests

Run from this directory, with the same commands as upstream:

```bash
cargo nextest run --workspace
```

```bash
cargo nextest run --workspace --profile conformance
```

## Changing the patch or the rev

Edit the copies, then rewrite the patch file from them:

```bash
vendor/vendor.py --diff <monorepo checkout at the pinned rev>
```

To move to another rev, update the rev in the root `Cargo.toml`, then regenerate the
copies from a checkout at that rev. This applies `commonware.patch` on top:

```bash
vendor/vendor.py <monorepo checkout>
```
