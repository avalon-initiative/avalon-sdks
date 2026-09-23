# avalon-sdks

Polyglot client SDKs for integrating with the Avalon Protocol network-facing
API, one directory per language under `languages/`.

- `languages/rust/` — the Rust reference SDK (`avalon-sdk`), moved here from
  `avalon-protocol`'s `crates/sdk`. No dependency on any other crate in
  that repo's workspace — only its own nested `schema-derive` proc-macro
  crate.
- `languages/csharp/` — the C# SDK (`AvalonSdk`, NuGet id `Avalon.Sdk`),
  moved here from `avalon-protocol`'s `bindings/csharp`. Unity-targeted
  (`netstandard2.1`). Not yet published to a NuGet registry — see
  `avalon-protocol`'s open NuGet packaging ticket for that plan.
- `languages/typescript/` — the TypeScript SDK, published as
  `@avalon-initiative/protocol-sdk` on GitHub Packages (private registry
  — this org's repos are still pre-public). Moved here from
  `avalon-protocol`'s `bindings/ts`. `avalon-protocol`'s `apps/hub`
  depends on the published package, not a local path.

**Status:** all three official SDKs' real source lives here.

## Vendored files

This repo has no live link back to `avalon-protocol` — two sets of files are
checked-in copies, kept in sync by hand whenever the upstream schema changes:

- `docs/generated/openapi.json` — `avalon-protocol`'s
  `docs/generated/openapi.json` (`make openapi` there). Each language's
  own codegen (`languages/rust/build.rs`, `languages/csharp/codegen`,
  `languages/typescript/scripts/generate-types.mjs`) generates its SDK's
  wire types from this same copy.
- `conformance/vectors/` — `avalon-protocol`'s `conformance/vectors/`.
  Each language's own conformance suite
  (`languages/rust/tests/conformance.rs`,
  `languages/csharp/AvalonSdk.Tests/ConformanceTests.cs`,
  `languages/typescript/test/conformance.test.ts`) asserts its SDK's
  signing logic against these; `avalon-protocol`'s own
  `crates/protocol/tests/conformance.rs` asserts the server side of the
  same files, so a real drift between the two repos fails a test on
  whichever side changed first, not silently.

Until real cross-repo tooling exists, resyncing any of these is a manual
copy from the corresponding path in `avalon-protocol`, then this repo's
own test suites (all three languages) to confirm nothing broke.

## Development

```bash
# Rust
cargo build --workspace
cargo test --workspace
cargo test --workspace -- --ignored   # needs a running avalon-server + Postgres, see avalon-protocol's own README
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all

# C#
cd languages/csharp && dotnet build AvalonSdk.sln && dotnet test AvalonSdk.sln

# TypeScript
cd languages/typescript && npm install && npm run lint && npm test
```

## Publishing (TypeScript)

`languages/typescript/` publishes to GitHub Packages
(`https://npm.pkg.github.com`), scoped `@avalon-initiative` — the scope
has to match this org exactly, GitHub Packages enforces it. Needs a token
with `write:packages` (e.g. `gh auth refresh -h github.com -s
write:packages,read:packages`, then `export NODE_AUTH_TOKEN=$(gh auth
token)`):

```bash
cd languages/typescript
npm publish
```

Bump `version` in `languages/typescript/package.json` first for anything
beyond the very first publish — GitHub Packages refuses to overwrite an
existing version. There's no CI-driven publish yet; every release is
manual.

## Trust anchors

There is no trust-anchor file in this repo. Each SDK fetches `avalon-protocol`'s
`docs/trusted-networks.json` at runtime from a single URL constant
(`TRUST_ANCHORS_URL` in Rust/TypeScript, `TrustAnchors.PublishedUrl` in C#); if
it can't be fetched, network verification and discovery fail rather than fall
back to a stale copy. A fork running its own network repoints that constant at
its own repo.
