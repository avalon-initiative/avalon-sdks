# avalon-sdks

Polyglot client SDKs for integrating with the Avalon Protocol network-facing
API, one directory per language.

- `rust/` — the Rust reference SDK (`avalon-sdk`), moved here from
  `avalon-protocol`'s `crates/sdk` by epic #771 (issues #772-#775). It has
  no dependency on any other crate in that repo's workspace — only its own
  nested `rust/schema-derive` proc-macro crate.
- C# and TypeScript land here next, alongside `rust/`, once they move out
  of `avalon-protocol`'s `bindings/csharp`/`bindings/ts` (not yet done —
  see the org migration planning in that repo).

**Status:** first real code landed 2026-09-22 (`rust/`). C#/TS still live
in `avalon-protocol` pending their own move.

## Vendored files

This repo has no live link back to `avalon-protocol` — three files are
checked-in copies, kept in sync by hand whenever the upstream schema or
trust-anchor list changes:

- `docs/generated/openapi.json` — `avalon-protocol`'s
  `docs/generated/openapi.json` (`make openapi` there). `rust/build.rs`
  generates this crate's wire types from it at build time.
- `docs/trusted-networks.json` — `avalon-protocol`'s
  `docs/trusted-networks.json`. `rust/src/network.rs` embeds it via
  `include_str!`.
- `conformance/vectors/` — `avalon-protocol`'s `conformance/vectors/`
  (issue #727/#774). `rust/tests/conformance.rs` asserts this SDK's signing
  logic against these; `avalon-protocol`'s own
  `crates/protocol/tests/conformance.rs` asserts the server side of the
  same files, so a real drift between the two repos fails a test on
  whichever side changed first, not silently.

Until real cross-repo tooling exists, resyncing any of these is a manual
copy from the corresponding path in `avalon-protocol`, then
`cargo test --workspace` here to confirm nothing broke.

## Development

```bash
cargo build --workspace
cargo test --workspace
cargo test --workspace -- --ignored   # needs a running avalon-server + Postgres, see avalon-protocol's own README
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```
