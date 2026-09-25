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

- Zero-URL `connect(target)` verifies candidates from the trust-anchor list, then times `GET /nodes/status` on up to 5 verified ones in parallel and picks the fastest (unmeasured ranks last, ties keep list order; one verified candidate costs no extra request). Extra time is bounded at about 4 seconds: 2s of further verification after the first success plus a 2s probe timeout, tunable through `DiscoverOptions`. `discover` returns each verified candidate's `latencyMs`.
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
