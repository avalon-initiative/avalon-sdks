# @avalon-initiative/protocol-sdk

TypeScript reference SDK for [Avalon Protocol](https://github.com/avalon-initiative) —
browser-facing, implementing both `AccountSession` (first-party identity
operations, auto-signed) and `IntegratorSession` (capability-gated
integrator access) against a real `avalon-server`.

Full design docs, guides, and the shared cross-language architecture
reference live in `avalon-protocol`'s
[`docs/projects/sdks/typescript/`](https://github.com/avalon-initiative/avalon-protocol/tree/main/docs/projects/sdks/typescript) —
this README is just the npm package landing page.

## Install

Published on GitHub Packages, not the public npm registry — add this to
`.npmrc` (or your CI's npm config) first:

```
@avalon-initiative:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NODE_AUTH_TOKEN}
```

`NODE_AUTH_TOKEN` needs a GitHub token with `read:packages` and access to
the `avalon-initiative` org. Then:

```bash
npm install @avalon-initiative/protocol-sdk
```

## Quick start

```ts
import { AvalonClient } from '@avalon-initiative/protocol-sdk'

const client = new AvalonClient({ serverUrl: 'https://your-avalon-node.example' })

// First-party account operations (drives a real WebAuthn ceremony):
const session = await client.register('display-name')

// Capability-gated integrator access:
const integratorSession = await client.authenticate({
  integratorCredentialKeyId: 'your-integrator-key-id',
})
```

## Shape of the API

- `AvalonClient` — the entry point: `register`/`login`/`resumeAccountSession`/
  `startAccountDeviceLogin` for `AccountSession`, `authenticate` for
  `IntegratorSession`.
- `AccountSession` — profile, passkeys, devices, guardian recovery,
  friends/blocks/presence/discovery, conversations, full guild
  administration. Every signature-required action signs itself
  automatically.
- `IntegratorSession` — capability-gated: every method checks its own
  required grant client-side before making a request (never the actual
  security boundary — the server enforces the same check independently).
- Typed errors, all subclasses of `AvalonSdkError`, carrying the HTTP `status` and, on 429 (`RateLimitedError`), `retryAfterSeconds` from a numeric `Retry-After`.

- Node topology, read-only and unauthenticated (plain `fetch`, no credentials, usable from a browser origin): `getTopology(nodeUrl, { limit? })`, `probeNode(nodeUrl, target, samples?)` and `traceRoute(nodeUrl, target, { ttl? })`, typed from the generated schema (`Topology`, `ProbeResult`, `TraceResult`, `TraceHop`). Every value is what a node reports about itself: trace hops are self-reported by the nodes on the path, so treat a path as advisory, not verified. Rate limits surface as `RateLimitedError` with `retryAfterSeconds`.

- Tracing a real call: `withTrace(() => getNodeStatus(url))` resolves `{ value, requests }`, where each request has `trace_id` and either a decoded `trace` (`branches` of `hops`, same hop shape as `traceRoute`, unknown fields kept) or a `problem` (`missing`, `oversized`, `malformed`, `trace_id_mismatch`). Opt-in; a missing or malformed header never fails the call. Hops are self-reported and advisory. In a browser the header is not sent unless `{ sendHeader: true }` and the response header is unreadable until the node exposes it, so browsers get no hops for now. See the root README.
- Zero-URL `connect(target)` verifies candidates from the trust-anchor list, then times `GET /nodes/status` on up to 5 verified ones in parallel and picks the fastest (unmeasured ranks last, ties keep list order; one verified candidate costs no extra request). Extra time is bounded at about 4 seconds: 2s of further verification after the first success plus a 2s probe timeout, tunable through `DiscoverOptions`. `discover` returns each verified candidate's `latencyMs`.
- Witness-cosigned tree heads: `getCosignedTreeHead(nodeUrl, { shardId?, treeSize? })` fetches a head with its cosignatures (`?witnesses=1`). `verifyCosignedTreeHead(authorKeyHex, head, knownList, freshnessCutoff, now)` accepts a head only when the author signature verifies and a majority of your own known list (`{ witnessKeyId, key }`, at least two entries) has a valid, fresh cosignature over that exact head; a known witness holding the author key counts without one. Lists of zero or one entries are the author check alone. `client.verifyNetwork({ knownWitnesses, freshnessSeconds })` applies the same rule (default freshness 600 seconds, fails closed as `mismatch`). Also exported: `verifyWitnessCosignature`, `witnessSigningMessage`, `majorityThreshold`, `isCosignedByMajority` and `findEquivocatingWitnesses`. The known list is never taken from the node being checked. A majority is resistance to a forged head, not proof, and cosignature timestamps are compared to whole-millisecond precision after parsing.
- Topology walk: `walkTopology(seeds, options)` follows `getTopology` outward breadth-first and resolves to a `TopologyGraph` of `nodes` (`visited`, `unreachable` with a `failure.reason` of `timeout`, `http_status`, `rate_limited`, `protocol_error` or `network`, or `unvisited`) and typed `edges` (`active`, `mirror`, `known`, each one observation by its `from` node, so `latency.observed_by` is the reporter). Read-only, browser-safe (plain `fetch`, `AbortSignal`), and bounded even with no options: `maxNodes` 64, `maxDepth` 4, `concurrency` 4, `requestTimeoutMs` 10000, `maxRetryAfterMs` 10000, each with a hard ceiling. A 429 is retried once after its `Retry-After` when within `maxRetryAfterMs`, otherwise recorded as `rate_limited`. `onProgress` receives `discovered` and `visited` events so a UI can draw while the walk runs; aborting `signal` resolves with the partial graph and `cancelled: true`.

  ```ts
  const graph = await walkTopology(['http://node.example:8080'], { maxNodes: 32, signal })
  ```

See the [full architecture doc](https://github.com/avalon-initiative/avalon-protocol/blob/main/docs/projects/sdks/architecture/sdk.md)
for the design that applies across every language's SDK, not just this
one.

## Source

[`avalon-initiative/avalon-sdks`](https://github.com/avalon-initiative/avalon-sdks),
`languages/typescript/`.

### Automatic known list (default on)

`client.verifyNetwork()` builds its own witness known list by default (`witnessPolicy: 'auto'`). It asks every `seed_nodes` URL in the network's trust-anchor entry for `GET /nodes/discover`, keeps peers of the same network whose witness advert proof verifies for exactly that address and a timestamp within an hour (`verifyWitnessAnnounce`), probes candidates for liveness (`GET /ledger/sth/latest?shard_id=core`, 5 s timeout, 4 in flight, at most 3 x capacity), then selects up to 5 with 2 anchor slots and at most 2 per diversity prefix (`diversityPrefixForUrl`, `selectKnownList`). Seed-node candidates are anchors and keep seed order; the rest are shuffled with `crypto.getRandomValues`. The list is built once per client instance. `AvalonClient.connect(target, options)` and `discover(target, options)` apply the same policy to every candidate node by default: the list is built once per call, never from a candidate, and a candidate that lacks a cosigned majority of a list of two or more is skipped like any other failed verification. `connect()` hands the list to the client it returns, so `verifyNetwork()` does not rebuild it. Opt out with `connect(target, { witnessPolicy: 'none' })` or pass your own list as `witnessPolicy: [...]`. With fewer than two entries the check is the plain author-signature check; with two or more a cosigned majority is required and failure reports `mismatch`, as with an explicit list. Opt out with `verifyNetwork({ witnessPolicy: 'none' })`, or pass your own list as `knownWitnesses` / `witnessPolicy: [...]`. Tuning goes in `knownListOptions` (capacity, anchorCapacity, maxPerPrefix, randomInt). `buildKnownList` and `crossCheckHead(authorKey, list, acceptedHead)` are exported; the latter asks each listed witness for the head at the same size and returns evidence of a conflicting author-signed head, without affecting verification.

The prefix rule uses URL text only (no DNS): many domains pointing at one machine look diverse, so the trust-anchor seeds are the floor. Shared vectors: `conformance/vectors/witness-announce.json` and `known-list-selection.json`.
