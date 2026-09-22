# Vendored Exoware codec compatibility

This directory contains four crates copied from their published crates.io
packages at version `2026.9.0`:

- `exoware-sdk` (crate checksum
  `abd524b8b4a473f7eda250b95d7afe81d3e4c56b022bb7d8b79889c3a7d1e08e`)
- `exoware-qmdb` (crate checksum
  `5fe6a70ce979a248e3f8a501a9469c096f13d6c66390fabcf1c35c4d1cf8dd77`)
- `exoware-simplex` (crate checksum
  `7a570253e9e5fd053a56b082cd7330d75bedfae0df8c78b3952d6f50d938ea2e`)
- `exoware-simulator` (crate checksum
  `32740192f65332d7e7f7bbd5332aba161bd33bd11fb9d38068642b1eed850b7f`)

The packages correspond to upstream Exoware tag `v2026.9.0` and commit
`1ebace29d6d2f6e1d99eea97087ec81ed20d72d8`. Registry extraction bookkeeping,
per-crate lockfiles, and original pre-normalization manifests are intentionally
omitted. Each directory retains the normalized published `Cargo.toml`, README,
and the project's MIT and Apache-2.0 license texts.

## Why these crates are vendored

Constantinople pins Commonware to commit
`8d5a87ecf49130dab67fb1a062d4413fd8663995`. That commit includes Commonware's
post-release ownership-preserving codec input API. Exoware 2026.9.0 still used
`bytes::Buf` directly, so its codec implementations and borrowed-slice decode
calls do not compile against the pinned Commonware revision.

The local changes are limited to that compatibility migration:

- Commonware `Read` implementations accept `commonware_codec::Buf`.
- Writers continue to accept `bytes::BufMut`.
- Borrowed byte slices are decoded through `commonware_codec::Copying`.
- Owned `bytes::Bytes` inputs remain owned so decoding can preserve shared
  storage without copying.
- Fixed-size current-QMDB proofs use Commonware's `proof::constant` modules,
  and ordered exclusion proofs call the proof object's standalone `verify`
  method instead of the removed database-associated verifier.

[`compatibility.patch`](compatibility.patch) is a review aid containing only
the Rust source delta from the four published crate archives. It does not
include vendored package contents, license files, or this documentation.

The remaining Exoware 2026.9.0 crates remain registry dependencies.
