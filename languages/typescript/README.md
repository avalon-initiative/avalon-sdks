# @avalon-initiative/protocol-sdk

TypeScript reference SDK for [Avalon Protocol](https://github.com/avalon-initiative) —
browser-facing, implementing both `AccountSession` (first-party identity
operations, auto-signed) and `IntegratorSession` (capability-gated
integrator access) against a real `avalon-server`.

Full design docs, guides, and the shared cross-language architecture
reference live in `avalon-protocol`'s
[`docs/projects/sdks/typescript/`](https://github.com/LunarVagabond/avalon-protocol/tree/main/docs/projects/sdks/typescript) —
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

See the [full architecture doc](https://github.com/LunarVagabond/avalon-protocol/blob/main/docs/projects/sdks/architecture/sdk.md)
for the design that applies across every language's SDK, not just this
one.

## Source

[`avalon-initiative/avalon-sdks`](https://github.com/avalon-initiative/avalon-sdks),
`languages/typescript/`.
