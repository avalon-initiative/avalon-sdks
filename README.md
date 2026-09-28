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

## Installing the Rust SDK

The Rust SDK is not on crates.io. The project is public but used internally for now, so it is
distributed through the organization's own channels (publishing to public registries is a later,
deliberate step tracked in [#64](https://github.com/avalon-initiative/avalon-sdks/issues/64)).
GitHub Packages carries the npm and NuGet packages only: it has no cargo registry, so the crates
cannot be published there. Use the release tag, or the `.crate` files attached to the release.

Use the tag of the release you want (`v0.1.3` below). Add the SDK as a pinned git dependency; cargo
finds `avalon-sdk` by name inside the repository and builds its `avalon-schema-derive` proc-macro
dependency from the same checkout:

```toml
[dependencies]
avalon-sdk = { git = "https://github.com/avalon-initiative/avalon-sdks", tag = "v0.1.3" }
```

#### From the `.crate` files on the release page

Releases after `v0.1.3` also attach `avalon-sdk-X.Y.Z.crate`, `avalon-schema-derive-X.Y.Z.crate`,
and a `SHA256SUMS` file covering every file on the release. `cargo` cannot install a `.crate` from a
URL, so for offline or vendored use unpack both and point cargo at them (replace `X.Y.Z` with the
release version):

```bash
gh release download vX.Y.Z --repo avalon-initiative/avalon-sdks --pattern '*.crate' --pattern SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
mkdir -p vendor && for c in *.crate; do tar xzf "$c" -C vendor; done
```

```toml
[dependencies]
avalon-sdk = { path = "vendor/avalon-sdk-X.Y.Z" }

# avalon-sdk depends on avalon-schema-derive by version, so resolve it from the unpacked copy.
[patch.crates-io]
avalon-schema-derive = { path = "vendor/avalon-schema-derive-X.Y.Z" }
```

Both crates build from the unpacked sources with no other repository files; the OpenAPI document the
build script reads is packaged inside `avalon-sdk`.

#### crates.io (not published yet)

```toml
avalon-sdk = "X.Y.Z"   # not published yet: tracked in #64
```

The npm and NuGet packages are installed from GitHub Packages (see "CI and releases" below).

## Vendored files

This repo has no live link back to `avalon-protocol` — two sets of files are
checked-in copies, kept in sync by hand whenever the upstream schema changes:

- `docs/generated/openapi.json` — `avalon-protocol`'s
  `docs/generated/openapi.json` (`make openapi` there;
  `languages/rust/openapi.json` is a symlink to it so the Rust crate packages its own copy). Each language's
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

## Shard names

A shard can bind a human-readable name (such as a domain it controls) to its
self-certifying id. All three SDKs expose the read calls and a pass-through for
submitting an already-signed claim (`GET /shards/name/{name}`,
`GET /shards/{id}/name-claims`, `POST /shards/{id}/name-claims`), typed from the
generated schema. Path values are percent-encoded. The SDKs do not sign claims yet:
`submit` takes a claim signed with the shard's own key, and the node checks the proof.

| | Resolve a name | List a shard's names | Submit a signed claim |
| --- | --- | --- | --- |
| Rust | `resolve_name(node_url, name)` | `list_shard_names(node_url, id)` | `submit_name_claim(node_url, &claim)` |
| C# | `ResolveNameAsync(name, nodeUrl?)` | `ListShardNamesAsync(id, nodeUrl?)` | `SubmitNameClaimAsync(claim, nodeUrl?)` |
| TypeScript | `resolveName(nodeUrl, name)` | `listShardNames(nodeUrl, id)` | `submitNameClaim(nodeUrl, claim)` |

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
429 error with the server's `Retry-After`. Recorded real-node responses (topology, probe, trace) used by each
language's tests live in `conformance/fixtures/nodes/`; `op-trace.json` there is synthetic, built
from the documented wire format, and also holds the shared invalid-header cases.

### Tracing a real call

A real SDK call can also report the path it took. Off by default: a call made outside the
wrapper below is unchanged. Inside it, each request carries `X-Avalon-Trace: <uuid>` and the
answer in `X-Avalon-Trace-Hops` (unpadded base64url JSON) is decoded next to the call's result:

| | Trace a real call |
| --- | --- |
| Rust | `with_trace(client.node_status()).await` returns `Traced { value, requests }` |
| C# | `AvalonTrace.WithTraceAsync(() => client.GetNodeStatusAsync())` returns `Traced<T>` (`Value`, `Requests`) |
| TypeScript | `withTrace(() => getNodeStatus(url))` resolves `{ value, requests }` |

`requests` has one entry per HTTP request sent while tracing was on. Each carries the id
sent, the decoded `trace` (`trace_id`, `branches`, `truncated`; a fan-out reports one branch per
target, and every branch is a list of hops shaped like the hops `trace()` returns, plus any field a
newer node adds, passed through unchanged) or a non-fatal `problem` (`missing`, `oversized`,
`malformed`, `trace_id_mismatch`). A missing, oversized or malformed header, or one the platform
does not expose, never fails the call. Only some operations report hops (a realtime relay
fan-out and a remote settlement submit); any other request comes back as `missing`. Hops are
self-reported by the nodes on the path and are advisory, not verified.

- The header goes to every URL requested through the client while tracing is on, including redirect
  targets and the trust-anchor fetch made by discovery; each such request adds an entry, usually
  `missing`. Keep traced operations to calls against nodes you intend to trace.
- At most 256 entries are kept per traced operation; when more requests are made, later ones are
  dropped and `requests_truncated` (`RequestsTruncated`, `requestsTruncated`) is set.
- A `trace_id` that is missing or not a UUID is `malformed`; `trace_id_mismatch` is only a valid
  UUID that differs from the one sent.
- Browsers: the node does not yet expose the response header to cross-origin pages, so a browser
  reads no hops, and a cross-origin request with the header needs the node to allow it. The
  TypeScript SDK therefore does not send the header in a browser unless `withTrace(fn, { sendHeader: true })`.
- Rust scopes tracing to the current task (requests made from a spawned task are not traced) and
  covers requests sent through the SDK's shared request path.
- C# traces requests sent through an `HttpClient` built on `AvalonTraceHandler`, which the SDK's
  own default clients use; wrap a caller-supplied client's handler with it
  (`new HttpClient(new AvalonTraceHandler(inner))`). Scope follows the async flow.
- TypeScript scopes to the async flow where `AsyncLocalStorage` is reachable through
  `process.getBuiltinModule` (Node 20.16+ and 22.3+); elsewhere (older Node, Workers, React Native)
  the scope is shared while any traced operation runs, so overlapping traced operations mix, but
  nothing stays active after the last one ends. `package.json` declares no `engines` range.
- An error thrown by the wrapped call propagates as usual (Rust returns the result inside
  `value`, so its `requests` are kept even on error).

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

All three SDKs share one version and ship in one release. A release is a PR that sets the version everywhere, then a tag on the merged commit:

```bash
make release-bump VER=0.2.0                              # sets all three SDKs' version files; commit and open a PR
make release-tag  VER=0.2.0 TITLE="Optional title"       # on up-to-date main after the merge: checks, then tag v0.2.0-Optional-title
git push origin v0.2.0-Optional-title
```

`release-tag` refuses to run unless `HEAD` is `origin/main`, every SDK's version matches the tag and the checks pass.
Pushing the tag starts the release workflow (`.github/workflows/release.yml`), which verifies the tag against all
three version files and that the commit is on `main`, reruns the checks, packs the npm and NuGet packages and the two Rust crates, and only then publishes:

| Published | Where |
|---|---|
| `@avalon-initiative/protocol-sdk` | GitHub Packages (`https://npm.pkg.github.com`) |
| `Avalon.Sdk` | the GitHub Packages NuGet feed |
| Rust SDK (`avalon-sdk`, `avalon-schema-derive`) | not on a registry: GitHub Packages has no cargo registry. Obtained from the release tag as a git dependency, or from the `.crate` files on the release (see "Installing the Rust SDK") |

One GitHub Release (`v0.2.0`) carries the packed npm tarball, the `.nupkg`, the two `.crate` files and a
`SHA256SUMS` file covering all of them. `scripts/release-assets.sh` builds that set (`cargo package
--workspace --locked`, copy, checksum) into `release-assets/`; the workflow runs it and so can you.

To exercise the pipeline without tagging, run the workflow manually (Actions, "Release SDKs", "Run
workflow", or `gh workflow run release.yml`). A manual run does the same checks and packs and uploads
the release files as the `release-files` workflow artifact; it never publishes, pushes a package or
creates a release. Only a `v*` tag push publishes.

Publishing the crates to crates.io is not part of the release and has no automation; the manual
procedure for when it is approved (tracked in
[#64](https://github.com/avalon-initiative/avalon-sdks/issues/64)) is in
[`docs/crates-io-publication.md`](docs/crates-io-publication.md).

Published versions are immutable: ship a fix as a new version. Installing a GitHub Packages
package needs a token with `read:packages`, even though the packages are public.

## Trust anchors

There is no trust-anchor file in this repo. Each SDK fetches `avalon-protocol`'s
`docs/trusted-networks.json` at runtime from a single URL constant
(`TRUST_ANCHORS_URL` in Rust/TypeScript, `TrustAnchors.PublishedUrl` in C#); if
it can't be fetched, network verification and discovery fail rather than fall
back to a stale copy. A fork running its own network repoints that constant at
its own repo.

### Witness-cosigned tree heads (TypeScript)

The TypeScript SDK can require that a tree head is also cosigned by a majority of a known
list of witnesses the caller supplies (`verifyCosignedTreeHead`, or the `knownWitnesses` option of
`verifyNetwork`). The list is never taken from the node being checked, cosignatures must be
fresh (default 600 seconds), and a list of zero or one witnesses is the plain trust-anchor check.
Building the list from discovery is not implemented. Shared vectors live in
`conformance/vectors/witness-cosigned-tree-head.json`.

### Automatic known list (TypeScript)

`verifyNetwork()`, `discover()` and `connect()` build the witness known list from discovery by default (once per call; `connect()` passes it to the returned client) and requires a cosigned majority when the list has two or more witnesses. The seeds in the trust-anchor entry are queried for `/nodes/discover`, adverts are proof-checked, candidates are probed for liveness and selected with a diversity-prefix rule (at most 2 per prefix, 2 anchor slots, 5 total). Pass `witnessPolicy: 'none'` (also accepted by `connect` and `discover`) to keep the plain author-signature check, or supply your own list. The prefix comes from URL text only, so many domains pointing at one machine look diverse; the seeds are the floor. A failed cosigned check reports the same `mismatch` status as before. Vectors: `conformance/vectors/witness-announce.json`, `known-list-selection.json`.

### Witness-cosigned tree heads (C#)

A verifier can require that the tree head it trusts was also cosigned by a majority of
witnesses it chose itself. In C#, `AvalonClient.GetCosignedTreeHeadAsync(shardId, treeSize)`
fetches a head with its cosignatures (`?witnesses=1`), `WitnessCosigning.VerifyCosignedTreeHead`
and `FindEquivocatingWitnesses` check heads against a known list of `KnownWitness` entries, and
`VerifyNetworkAsync(knownWitnesses, freshnessWindow)` applies the same check to network
verification. With two or more known witnesses a head is accepted only when the author signature
verifies and `n/2 + 1` distinct listed witnesses cosigned it within the freshness window
(default 600 seconds); a head that falls short is reported as `Mismatch`. With none or one, verification behaves as
before. The known list is the caller's own (or built by the SDK, see below) and is never taken from the node being
checked. This is
resistance to a single compromised author key, not proof: the guarantee is only as strong as the
independence of the witnesses on the list. Shared vectors live in
`conformance/vectors/witness-cosigned-tree-head.json`.

### Known list and default-on witness verification (C#)

By default `VerifyNetworkAsync` and `ConnectAsync` build the witness list themselves. Each seed node in
the network's trust-anchor entry is asked for `GET /nodes/discover`; a peer's witness advert is admitted
only when its proof verifies for exactly that base url and key, the network id matches and the advert is
within an hour of the local clock. Candidates are checked for liveness (`/ledger/sth/latest?shard_id=core`
must serve the same network), anchors (candidates at a seed url) come first in seed order, the rest are
shuffled with a cryptographic random source, and selection keeps at most 5 witnesses, 2 anchor slots and
2 per diversity prefix (`KnownListOptions` overrides these). The list is built once per client instance.
With fewer than two witnesses verification is the plain author check; with two or more a cosigned
majority is required and a head that falls short is reported as `Mismatch`, the same status as an
explicit list.

Pass `witnessPolicy: WitnessPolicy.None` to keep only the author check, or `knownWitnesses` /
`WitnessPolicy.Explicit(list)` to supply your own list. `KnownListBuilder.BuildKnownListAsync` builds a
list directly and `KnownListBuilder.CrossCheckHeadAsync` asks each listed node for the head at the
accepted tree size and reports author-signed heads with a different root; it only reports.

The diversity prefix is derived from the url text without DNS: IPv4 maps to its /24, IPv6 to its /48
and a hostname to its last two labels. Many domains pointing at one machine therefore look diverse; the
trust-anchor seeds are the floor. The list is never taken from the node being checked. Shared vectors:
`conformance/vectors/known-list-selection.json` and `conformance/vectors/witness-announce.json`.

### Witness-cosigned tree heads (Rust)

An author-signed tree head can also be checked against a witness list the caller supplies. With a
known list of two or more witnesses, a head is accepted only when the author signature verifies and a
majority (`n/2 + 1`, counting distinct witnesses) of the list has cosigned the same tree size, root,
network and author timestamp, with `observed_at` inside the freshness window (default 600 seconds,
future-dated cosignatures rejected). A known witness that holds the author's own key counts without a
cosignature. With zero or one known witness only the author signature is checked.

The SDK never takes the list from the node it is talking to (see the next section for the default,
discovery-built list). A cosigned head is resistance against a single
compromised author or node, not proof against a colluding majority of the list. Rust:
`AvalonClient::fetch_cosigned_tree_head` (`?witnesses=1`), `AvalonClient::verify_network_with_witnesses`
(a head that is not cosigned reports `Mismatch`), and `witness::{verify_cosigned_tree_head,
find_equivocating_witnesses}`. Behavior is pinned by `conformance/vectors/witness-cosigned-tree-head.json`.

### Discovery-built known list (Rust)

`AvalonClient::verify_network` builds its witness list by default, so a network that runs witness
cosigning is checked against a majority without any setup. The list comes only from the trust-anchor
entry's `seed_nodes`, never from the node the client is connected to: every seed's `GET /nodes/discover`
is queried (5 second timeout each, failed seeds skipped), and a peer's witness advert is admitted only
when it names the target network and its proof verifies for exactly that base url, key and time (within
one hour). Adverts relayed by any peer are fine because the proof binds the key to its address. Anchors
(candidates at a seed url) keep seed order and the rest are shuffled with a secure random source, each is
probed with `GET {base_url}/ledger/sth/latest?shard_id=core` (5 seconds, 4 in flight, at most
`3 * capacity`), and selection keeps at most 5 witnesses, 2 anchors and 2 per diversity prefix.
The list is built once per client and cached. A list of fewer than two is the plain author check; two
or more fail closed exactly as an explicit list does (`Mismatch`).

`discover`, `discover_ranked` and `AvalonClient::connect` apply the same policy to every candidate
during discovery (`discover_with_policy` / `discover_ranked_with_policy` take it explicitly; the plain
functions use `Auto`, `connect` uses `DiscoveryConfig::witness_policy`). A list of fewer than two is the
plain author check; otherwise a candidate whose head lacks the cosigned majority is recorded as a failed
attempt and skipped so the next verified candidate can win. The auto list is built once per discovery
and `connect` hands it to the returned client, whose `verify_network` reuses it.

Opt out with `WitnessPolicy::None` or pass your own list with `WitnessPolicy::Explicit`, either on
`AvalonClient::with_witness_policy`, `verify_network_with_policy` or `DiscoveryConfig::witness_policy`.
The prefix rule needs no DNS (IPv4 /24, IPv6 /48, or a hostname's last two labels), so it stops one
address block or registered domain from filling the list but not many domains pointing at one machine;
the trust-anchor seeds are the floor. `known_list::cross_check_head` asks each known witness for the
head at the accepted size and reports author-signed heads with a different root as evidence; it reports
only. Behavior is pinned by `conformance/vectors/witness-announce.json` and `known-list-selection.json`.

## Zero-URL connect

`connect()` (`AvalonClient.connect` in Rust/TypeScript, `AvalonClient.ConnectAsync` in C#) resolves a
target network to a node using only the candidates in the trust-anchor list. Verification comes
first: a candidate whose signed tree head or target check fails is never chosen, however fast. Of the
candidates that verify (at most 5), one `GET /nodes/status` each is timed in parallel and the lowest
round trip wins; a failed or timed-out probe ranks after measured ones, and ties keep list order.
With exactly one verified candidate no extra request is made. The extra time over
first-verified selection is bounded: verification continues for at most 2 seconds after the first
success, then probes run with a 2 second timeout, so at most about 4 seconds in total. The
`discover` variants (`discoverAmong`/`discover_ranked`/`DiscoverRankedAsync`) also return each
verified candidate's measured latency. A caller-supplied server URL skips all of this.
