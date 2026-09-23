# avalon-sdks

Polyglot client SDKs for integrating with the Avalon Protocol network-facing
API, one directory per language.

- `rust/` — the Rust reference SDK (`avalon-sdk`), moved here from
  `avalon-protocol`'s `crates/sdk` by epic #771 (issues #772-#775). It has
  no dependency on any other crate in that repo's workspace — only its own
  nested `rust/schema-derive` proc-macro crate.
- `csharp/` — the C# SDK (`AvalonSdk`, NuGet id `Avalon.Sdk`), moved here
  from `avalon-protocol`'s `bindings/csharp` (issue #775). Unity-targeted
  (`netstandard2.1`). Not yet published to a NuGet registry — see
  `avalon-protocol`'s open ticket #53 for that plan.
- `typescript/` — the TypeScript SDK, published as `@avalon-initiative/protocol-sdk`
  on GitHub Packages (private registry — this org's repos are still
  pre-public). Moved here from `avalon-protocol`'s `bindings/ts` (issue
  #775). `avalon-protocol`'s `apps/hub` depends on the published package,
  not a local path, as of this move.

**Status:** all three official SDKs' real source lives here as of
2026-09-23. `rust/` landed first (2026-09-22), `csharp/`/`typescript/`
followed the same day.

**Known follow-ups, not yet done:**
- These three language directories sitting flat at the repo root will get
  crowded as more of `avalon-protocol` epic #753's backlog languages (Go,
  Python, C++, Java/Kotlin, Swift, PHP, Ruby, Dart, C, GDScript, Lua) land
  — grouping them under a subfolder is planned, deliberately deferred to
  "the tail end" of the move rather than done mid-move.
- `docs/trusted-networks.json` below is a hand-copied duplicate of
  `avalon-protocol`'s canonical file, and it's **already drifted** once in
  practice. Decided direction: `typescript/`/`rust/`/`csharp/` should
  fetch trust anchors at runtime from a stable URL `avalon-protocol`
  publishes, instead of a baked-in compiled copy — not implemented yet.

## Vendored files

This repo has no live link back to `avalon-protocol` — three files are
checked-in copies, kept in sync by hand whenever the upstream schema or
trust-anchor list changes:

- `docs/generated/openapi.json` — `avalon-protocol`'s
  `docs/generated/openapi.json` (`make openapi` there). `rust/build.rs`,
  `csharp/codegen`, and `typescript/scripts/generate-types.mjs` all
  generate their SDK's wire types from this same copy.
- `docs/trusted-networks.json` — `avalon-protocol`'s
  `docs/trusted-networks.json`. `rust/src/network.rs` embeds it via
  `include_str!` — see the "known follow-ups" note above, this is the file
  that's already drifted once.
- `conformance/vectors/` — `avalon-protocol`'s `conformance/vectors/`
  (issue #727/#774). Each language's own conformance suite
  (`rust/tests/conformance.rs`, `csharp/AvalonSdk.Tests/ConformanceTests.cs`,
  `typescript/test/conformance.test.ts`) asserts its SDK's signing logic
  against these; `avalon-protocol`'s own
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
cd csharp && dotnet build AvalonSdk.sln && dotnet test AvalonSdk.sln

# TypeScript
cd typescript && npm install && npm run lint && npm test
```

## Publishing (TypeScript)

`typescript/` publishes to GitHub Packages (`https://npm.pkg.github.com`),
scoped `@avalon-initiative` — the scope has to match this org exactly,
GitHub Packages enforces it. Needs a token with `write:packages` (e.g.
`gh auth refresh -h github.com -s write:packages,read:packages`, then
`export NODE_AUTH_TOKEN=$(gh auth token)`):

```bash
cd typescript
npm publish
```

Bump `version` in `typescript/package.json` first for anything beyond the
very first publish — GitHub Packages refuses to overwrite an existing
version. There's no CI-driven publish yet; every release is manual.
