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

## Documentation

How the SDKs fit into Avalon, and the language-agnostic design they share, is in the
[Avalon documentation](https://github.com/avalon-initiative/avalon-docs/blob/main/sdk/README.md).
Per-language guides live here: [Rust](docs/rust/README.md), [C#](docs/csharp/README.md),
[TypeScript](docs/typescript/README.md).

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
checked-in copies, synced with `make update-protocol` (`scripts/sync-protocol.sh update`) whenever the upstream schema changes:

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
  whichever side changed first, not silently. The directory is a byte-for-byte copy: runners load vectors by file name
  and gate on `supportedIn`, so protocol-only files (`identity-chain.json`, `node-request.json`) sit here unused.
  `make sync-protocol` (network; run by the vector-sync workflow, not by `make check`) fails when the vectors or `openapi.json` differ from protocol main.

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

## Identity ids and registration

An identity id is the 64 lowercase hex characters of `SHA-256("avalon-identity-id-v1" || key)`, where `key` is the
identity's first (inception) Ed25519 public key (32 raw bytes). It is not a UUID. Parsing is strict and never
normalises: uppercase, any other length, `id:` or `node:` prefixes, UUID text and surrounding whitespace are all
rejected. Each SDK has a validated type that rejects anything else, and the generated wire types still carry plain
strings that the hand-written layers parse with it.

| | Type | Parse | Derive from an inception key |
| --- | --- | --- | --- |
| Rust | `types::ids::IdentityId` (no longer `Copy`; pass `&IdentityId`) | `"...".parse::<IdentityId>()` | `IdentityId::derive(&key_bytes)` |
| C# | `IdentityId` (readonly struct; `default` is invalid) | `IdentityId.Parse` / `TryParse` | `IdentityId.Derive(key)` |
| TypeScript | `IdentityId` (branded string) | `parseIdentityId` / `isIdentityId` | `deriveIdentityId(key)` |

Registration generates the inception key first, derives the id, sends the base64 public key as
`event_signing_public_key` at `POST /identities/register/start`, then signs the v2 `identity.created` bytes. Those bytes are
`avalon:identity.created:v2:{len(network_id)}:{network_id}:{len(shard_id)}:{shard_id}:{ticket_id}:{identity_id}:{public_key_hex}:{display_name}`
with `len` the UTF-8 byte length; the network id, shard id and ticket come from the `register/start` response, so a copied
signature does not verify for another ticket, network or shard. `register/finish` no longer takes the key, and its response id
must equal the derived one. Rust and TypeScript implement `register`; C# does not (see its README), but it has the id type, the
derivation and every signing function below.

The `network_id` and `shard_id` in the signed bytes are supplied by the node answering `register/start` and are signed as given: the
client trusts the node it registers with and does not pin them. Stored credentials are checked on login: `login` / `account_login`
fail if the stored secret does not derive to the credentials' identity id. Approving a device grant also requires the requested key
to be strict canonical base64 of 32 bytes and acceptable (canonical, not small-order), and the grant, ticket and key ids that go
into signed bytes must be lowercase hyphenated UUID text.

A public key is lowercase hex inside every signing-byte string and standard base64 on the wire. Device grant approval signs
`avalon:device_grant.approved:v2:{grant_id}:{identity_id}:{requested_public_key_hex}`, and revoking a signing key
(`revoke_device` / `RevokeDeviceAsync` / `revokeDevice`) now signs
`avalon:identity.signing_key_revoked:v2:{identity_id}:{signing_key_id}:{revoked_by_signing_key_id}` with one of the
identity's active keys and sends it with `revoked_by_signing_key_id`; the call needs a local signing key and the server refuses
to revoke the last active key. The functions are public (`identity_signing` in Rust, `IdentitySigning` in C#, the top-level
exports in TypeScript), together with strict Ed25519 verification (S below the group order, no small-order key or R) and the
key-acceptability rule (canonical encoding, not of small order; a key with a torsion component such as y = 3 is accepted).
Shared vectors: `conformance/vectors/identity-id.json`, `identity-created-signing.json`, `device-grant-approval.json` and
`signing-key-revoked.json`; the attestation, cross-node-login, session-continuation and websocket-interest-claim vectors carry
hex ids.

## Integrator shards

`GET /integrations/{slug}/shards` lists an owner's sibling shards this node knows of and could verify a head for, plus the
ids it could not verify (`partial`, `missing_shard_ids`). It is public and advisory, and a family over 256 shards is refused
with 413. Rust `list_integrator_shards(slug)`, C# `ListIntegratorShardsAsync(slug)`, TypeScript `listIntegratorShards(serverUrl, slug)`.

## Self-certifying shard heads

A shard whose id is `node:<sha256-of-key>` is named by the hash of the Ed25519 public key that signs its
tree heads (lowercase hex SHA-256 of the raw 32 bytes). A node serves that key as the optional
`signing_public_key` on `GET /ledger/sth/latest?shard_id=...` and `GET /ledger/sth/{tree_size}?shard_id=...`; it is
not part of the signed bytes and older nodes omit it. All three SDKs verify such a head with only that key and the
id, with no trust anchor, registry or witness list: the key must be exactly 64 lowercase hex characters decoding to
a canonical Ed25519 point of non-small order, must hash to the id, and must have signed the head (the same signing
bytes as every other tree head). Signature verification is cofactorless with S below the group order and R compared
byte for byte, identically in all three SDKs and the server; in TypeScript this also applies to the `core` network
check, so signatures that only a cofactored verifier accepts no longer verify. The first failing check is reported as one of `not_self_certifying` (the id is not a valid `node:` id),
`missing_key`, `malformed_key`, `key_id_mismatch` or `bad_signature`. A separate dispatcher says which check a shard
id gets: `node:` ids use this one, `core` uses the network and witness verification (`verify_network`), and every
other id kind or malformed id is `unsupported` and never verifies here. Nothing existing changes: `verify_network`,
`connect()` and the existing tree-head types behave as before, and parsing tolerates the field being absent.

| | Fetch a shard's head | Verify | Which check applies |
| --- | --- | --- | --- |
| Rust | `AvalonClient::fetch_shard_tree_head(shard_id, tree_size)` | `self_certifying::verify_self_certifying_head(shard_id, &sth, key)` or `SelfCertifyingTreeHead::verify(shard_id)` | `self_certifying::shard_check(shard_id)` |
| C# | `GetShardTreeHeadAsync(shardId, treeSize?)` | `SelfCertifying.Verify(shardId, head, key?)` | `SelfCertifying.ShardCheckFor(shardId)` |
| TypeScript | `getShardTreeHead(nodeUrl, shardId, { treeSize? })` | `verifySelfCertifyingTreeHead(shardId, sth, key?)` | `shardCheck(shardId)` |

In C# and TypeScript `SigningPublicKey` / `signing_public_key` is an optional field on the existing tree-head type; in
Rust the existing `sth::SignedTreeHead` is unchanged and `self_certifying::SelfCertifyingTreeHead` carries the head plus
the key. A verified head proves the key holder signed it and that the key belongs to the id; it says nothing about
whether the shard is honest or current. Shared vectors: `conformance/vectors/self-certifying-tree-head.json`.

## Shard family head

A game, app or service can run sibling shards: `{namespace}:{slug}` and `{namespace}:{slug}/{instance}` (such as `game:x` and
`game:x/2`) share an owner, `game:x`. `GET /ledger/shard-family?owner=<owner>[&member=<shard id>]` serves the owner's
family head: a root over the member heads, the members it was computed from (sorted by shard id), whether the family is
`partial`, and with `member` an inclusion proof for that shard. The route is under `/ledger/*`, which the OpenAPI document
excludes, so all three SDKs hand-write the call and the pure helpers, pinned by `conformance/vectors/shard-family-head.json`.
A node does not sign the root: anyone recomputes it from the member heads, and a proof ties one head to it. Heads of any
other shard are ignored; `game:xy`, `core`, `node:<hash>` and invalid ids belong to no family.

| | Fetch | Recompute the root | Verify a proof | Owner of a shard id |
| --- | --- | --- | --- | --- |
| Rust | `AvalonClient::fetch_shard_family(owner, member)` | `shard_family::family_root(owner, &heads)` | `shard_family::verify_family_inclusion(owner, root, &proof, &head)` | `shard_family::shard_family_owner(id)` |
| C# | `GetShardFamilyAsync(owner, member?)` | `ShardFamily.Root(owner, heads)` | `ShardFamily.VerifyInclusion(owner, root, proof, head)` | `ShardFamily.OwnerOf(id)` |
| TypeScript | `getShardFamily(nodeUrl, owner, { member? })` | `familyRoot(owner, heads)` | `verifyFamilyInclusion(owner, root, proof, head)` | `shardFamilyOwner(id)` |

Each response also has `root_matches` / `RootMatches()` / `familyRootMatches(response)` (the served root equals the
recomputed one) and `proof_verifies` / `ProofVerifies()` / `familyProofVerifies(response)` (the served proof verifies for
its member). The membership helpers are `is_family_member(owner, id)` and `is_family_owner_id(id)` (`IsMember`, `IsOwnerId`,
`isFamilyMember`, `isFamilyOwnerId`). Verification returns false, never an error, for malformed input. A leaf commits to the
member's shard id, tree size, root hash, signing key id and signature text, so a head's own signature is not checked here:
verify member heads separately where that matters. The head itself is not authenticated by this call. A `partial`
response means a known family member has no head on that node; atomic writes across siblings do not exist.
In TypeScript a tree size beyond 2^53 is lost by `JSON.parse`; pass a `bigint` to the helpers if you hold one.

### Routing a write to a sibling

An integrator running sibling shards chooses which instance each write goes to. The SDKs give a small deterministic
helper for that: given the owner, a caller-supplied partition key (any string) and the sibling shard ids, it returns the
sibling the write for that key should go to, or nothing when no candidate is a member of the family.

| | Route | Weight | From a fetched family |
| --- | --- | --- | --- |
| Rust | `shard_family::route_write(owner, key, &siblings) -> Option<&str>` | `shard_family::route_weight(owner, key, id)` | `family.route_write(key)`, `family.sibling_ids()` |
| C# | `ShardFamily.RouteWrite(owner, key, siblings) -> string?` | `ShardFamily.RouteWeight(owner, key, id)` | `family.RouteWrite(key)`, `family.SiblingIds()` |
| TypeScript | `routeWrite(owner, key, siblings): string \| null` | `routeWeight(owner, key, id)` | `familyRouteWrite(family, key)`, `familySiblingIds(family)` |

The rule is rendezvous (highest-random-weight) hashing. The weight of a candidate shard id is SHA-256 of the bytes
`avalon-shard-route-v1` (UTF-8, no length) followed by the owner, the key and the shard id, each as a 4-byte big-endian
length of its UTF-8 bytes and then those bytes (no Unicode normalisation of the key). The candidate with the greatest
weight, compared as 32 big-endian bytes, wins. Candidates are first reduced to the unique ids that are members of the
owner's family (`is_family_member`), so other owners' ids, `core`, `node:` ids and malformed ids are ignored and the order
of the list does not matter. Equal weights can only come from equal ids, so the tie-break is the bytewise smaller id.
Adding a sibling moves only the keys that now win on it; removing one moves only the keys that were on it.

Limits: this is client-side routing only. The server does not route writes, and writes to different siblings are never
atomic together; there are no cross-sibling transactions. A `partial` family response omits siblings that have no head on
that node, so for routing prefer the sibling list you manage yourself. The family head is for verification, not for
choosing. Pinned by `conformance/vectors/shard-sibling-routing.json`.

## Node topology, probe and trace

`Connectivity` and `PathType` are open vocabularies: a value this SDK does not know decodes instead of failing the
whole response (Rust `Unknown(String)`, C# `Unknown`, TypeScript keeps the string).

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
