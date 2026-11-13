#!/usr/bin/env bash
# Builds the @exowarexyz TypeScript packages the explorer depends on from the Exoware monorepo
# revision that the root Cargo.toml pins, so the browser verifiers match the Rust workspace.
# The packages land in .exoware at the repository root, which explorer/package.json links by
# path. The checkout sits outside the explorer so npm uses each package's own dependencies.
#
# Requires git, npm, rustup's wasm32-unknown-unknown target, wasm-pack, and a C compiler that
# targets wasm32 (Homebrew LLVM on macOS). A wasm-bindgen CLI matching the checkout's
# wasm-bindgen crate is installed into .exoware/bin unless one is already on PATH.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
dest="$root/.exoware"

revs="$(sed -n '/^exoware-[a-z-]* = .*github\.com\/exowarexyz\/monorepo/s/.*rev = "\([0-9a-f]\{40\}\)".*/\1/p' "$root/Cargo.toml" | sort -u)"
if [ -z "$revs" ] || [ "$(printf '%s\n' "$revs" | wc -l)" -ne 1 ]; then
    echo "Cargo.toml must pin every exoware crate to one monorepo revision, found: ${revs:-none}" >&2
    exit 1
fi
rev="$revs"

if [ "$(cat "$dest/.built-rev" 2>/dev/null)" = "$rev" ]; then
    echo "Exoware TypeScript packages at $rev are already built in $dest"
    exit 0
fi

rm -rf "$dest"
mkdir -p "$dest"
git -C "$dest" init --quiet
git -C "$dest" fetch --quiet --depth 1 https://github.com/exowarexyz/monorepo "$rev"
git -C "$dest" checkout --quiet --detach FETCH_HEAD

# Build with Exoware's own compiler settings, independent of this repository's Cargo config.
export RUSTFLAGS='' CARGO_ENCODED_RUSTFLAGS='' CARGO_TARGET_DIR="$dest/target"

bindgen="$(sed -n '/^name = "wasm-bindgen"$/{n;s/^version = "\(.*\)"$/\1/p;}' "$dest/Cargo.lock")"
if [ "$(wasm-bindgen --version 2>/dev/null)" != "wasm-bindgen $bindgen" ]; then
    cargo install --quiet --locked --root "$dest" wasm-bindgen-cli --version "$bindgen"
    export PATH="$dest/bin:$PATH"
fi

(cd "$dest/sdk/ts" && npm ci && npm run build)

# The generated protobuf code is checked in, so the QMDB package skips its buf step.
(cd "$dest/qmdb/ts" && npm ci && npm run build:wasm && npm run build:ts)
(cd "$dest/simplex/ts" && npm ci && npm run build)

rm -rf "$dest/target"
echo "$rev" > "$dest/.built-rev"
echo "Built Exoware TypeScript packages at $rev in $dest"
