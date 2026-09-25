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

## Node topology, probe and trace

All three SDKs expose the node's read-only topology view and its probe and trace
endpoints, typed from the generated schema (`GET /nodes/topology`,
`POST /nodes/probe`, `POST /nodes/trace`):

| | Topology | Probe | Trace |
| --- | --- | --- | --- |
| Rust | `AvalonClient::topology(node_url: Option<&str>)` | `probe(target, samples)` | `trace(target, ttl)` |
| C# | `TopologyAsync(nodeUrl?)` | `ProbeAsync(target, samples?)` | `TraceAsync(target, ttl?)` |
| TypeScript | `getTopology(nodeUrl, { limit? })` | `probeNode(nodeUrl, target, samples?)` | `traceRoute(nodeUrl, target, { ttl? })` |

Probe and trace run on the node the client points at (`target` must be in that node's
peer table for probe). Hop and latency data is self-reported by the nodes on the path
and is advisory, not verified. A rate-limited call surfaces through each SDK's existing
429 error with the server's `Retry-After`. Recorded real-node responses used by each
language's tests live in `conformance/fixtures/nodes/`.

### Walking the whole overlay

No node holds the whole graph, so each SDK also has a bounded, read-only walk helper that
follows a node's neighbors, mirror sources and known peers breadth-first, using the topology
call above:

| | Walk |
| --- | --- |
| Rust | `AvalonClient::walk_topology(&seeds, WalkOptions)` |
| C# | `WalkTopologyAsync(seeds, WalkOptions?, ct)` |
| TypeScript | `walkTopology(seeds, options)` |

All three return the same graph: nodes (`visited`, `unreachable` with a reason, or `unvisited`
when a limit or cancellation stopped the walk) and edges typed active link, mirror source or
known-only. Each edge is one observation by the reporting node, so latency is labeled as
observed by that node and a node reported by several neighbors keeps every observation.
URLs are deduplicated after normalization (lowercase scheme and host, default port and trailing
slash dropped). Options are max nodes (64), max depth (4), concurrency (4), per-request timeout
(10 s) and the longest `Retry-After` honored (10 s), each with a hard ceiling, and a progress
callback and cancellation (an `AbortSignal`, a `CancellationToken`, or a `watch` receiver in
Rust). A 429 is retried once after its `Retry-After` when that fits the budget, otherwise the
node is recorded as rate limited; timeouts, HTTP statuses, malformed bodies and connection
errors are recorded per node and never stop the walk. Cancelling returns the partial graph with
`cancelled` set.

## Development

```bash
make check          # offline checks for all three SDKs + the route-coverage check (what CI runs)
make check-rust     # fmt, clippy, tests
make check-csharp   # build and tests
make check-ts       # lint, type-check, tests, generated-types check
make help           # everything else
```

Per-language commands, if you want them directly:

```bash
# Rust
cargo build --workspace
cargo test --workspace
cargo test --workspace -- --ignored   # needs a running avalon-server + Postgres, see avalon-protocol's own README

# C#
cd languages/csharp && dotnet build AvalonSdk.sln && dotnet test AvalonSdk.sln

# TypeScript
cd languages/typescript && npm install && npm run lint && npm test
```

Live and integration tests need a running `avalon-server` and are never part of `make check` or CI.

## CI and releases

Pull requests run the checks above in parallel jobs (`.github/workflows/ci.yml`); the aggregate
`ci` job is the one required by the branch ruleset.

Each SDK versions and releases independently, with its own tag prefix:

```bash
make release-ts     VER=0.2.0 TITLE="Optional title"   # tag ts-v0.2.0-Optional-title
make release-csharp VER=0.2.0 TITLE="Optional title"   # tag csharp-v0.2.0-Optional-title
make release-rust   VER=0.2.0 TITLE="Optional title"   # tag rust-v0.2.0-Optional-title
git push origin main --follow-tags
```

Each target runs that SDK's checks first and changes nothing if they fail, then bumps only that
SDK's version files (`languages/typescript/package.json`, `AvalonSdk.csproj`, or the workspace
`Cargo.toml`), commits, and creates the annotated tag. Pushing the tag starts the release workflow,
which verifies the tag against the version files and that the commit is on `main`, reruns the
checks, and then:

| Tag | Publishes |
|---|---|
| `ts-v*` | `@avalon-initiative/protocol-sdk` to GitHub Packages (`https://npm.pkg.github.com`), plus a GitHub Release with the packed tarball |
| `csharp-v*` | `Avalon.Sdk` to the GitHub Packages NuGet feed, plus a GitHub Release with the `.nupkg` |
| `rust-v*` | a GitHub Release only; the crate is not on a registry yet (GitHub Packages has no cargo registry and the crate depends on its sibling `avalon-schema-derive` by path) |

Published versions are immutable: ship a fix as a new version. Installing a GitHub Packages
package needs a token with `read:packages`, even though the packages are public.

## Trust anchors

There is no trust-anchor file in this repo. Each SDK fetches `avalon-protocol`'s
`docs/trusted-networks.json` at runtime from a single URL constant
(`TRUST_ANCHORS_URL` in Rust/TypeScript, `TrustAnchors.PublishedUrl` in C#); if
it can't be fetched, network verification and discovery fail rather than fall
back to a stale copy. A fork running its own network repoints that constant at
its own repo.
