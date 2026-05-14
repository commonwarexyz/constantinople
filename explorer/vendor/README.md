# Exoware TypeScript Packages

The explorer uses these vendored TypeScript packages instead of the published
npm package so its generated SQL and Store clients stay aligned with the Rust
Exoware crates.

Source:

- Repository: `https://github.com/exowarexyz/monorepo`
- Revision: `296d6423634c2ea7b5f34133c79a7b7386c44f60`
- Packages: `sdk/ts`, `sql/ts`

When the Rust Exoware revision in the workspace changes, refresh these package
copies from the same Git revision.
