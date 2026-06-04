These tarballs were packed from `exowarexyz/monorepo` commit
`839e9048df69674f2adc2c11bfde10a55acc5079`. The directory and tarball
filenames include the git revision so the vendored TypeScript artifacts stay
visibly tied to the Rust Exoware pin.

The Exoware TypeScript packages live in monorepo subdirectories, which npm
cannot install directly from a git commit. Keep these artifacts in sync with
the Cargo Exoware git revision in the workspace manifest.

When rebuilding the QMDB or Simplex wasm packages on macOS, use a clang with
WebAssembly target support, for example:
`CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang npm run build`.
