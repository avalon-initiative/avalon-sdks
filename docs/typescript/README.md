# TypeScript SDK

The `typescript/` project in the `avalon-sdks` repo — the browser-facing
[Avalon SDK](https://github.com/avalon-initiative/avalon-docs/blob/main/sdk/README.md), implementing both `IntegratorSession`
(capability-gated, mirrors Rust/C#'s `Session`) and `AccountSession`
(first-party) from scratch. Lives in `avalon-sdks` (`languages/typescript/`). See [`avalon-docs: sdk/design.md`](https://github.com/avalon-initiative/avalon-docs/blob/main/sdk/design.md)
for the design that applies to every language's SDK — this page is the
TypeScript-specific "how," not the "why."

**Status:** real and shipped, not speculative — ES modules, `vitest` for
tests. Published as `@avalon-initiative/protocol-sdk` on GitHub Packages
(a GitHub-hosted npm registry that requires an authenticated token,
not the public npm registry). `avalon-hub/apps/hub` depends on the published
package now, not a local path — its entire data-fetching surface goes
through it.

Unlike the C# port (which scoped WebAuthn ceremony-driving out entirely)
and the Rust port (which drives a virtual/software authenticator, since it
has no browser to run in), this SDK is browser-facing and drives a real
WebAuthn ceremony via `@simplewebauthn/browser` — registration and login
are both implemented for real, not stubbed out.

## Shape of the API

- Identity ids are branded `IdentityId` strings (64 lowercase hex characters derived from the inception key):
  `parseIdentityId`, `deriveIdentityId`, and the v2 signing-bytes functions are exported. `register` generates the key
  first and derives the id; see the root README's "Identity ids and registration".

- `AvalonClient` — the entry point: `register(displayName)`,
  `login(credentials)`, `resumeAccountSession(token)`,
  `resumeAccountSessionWithSigningKey(token, seed)`,
  `startAccountDeviceLogin()`, `authenticate(...)` (for
  `IntegratorSession`).
- `AccountSession` — mirrors the Rust/C# `AccountSession` surface
  field-for-field: profile, passkeys, devices/grants/cross-device pairing
  approval, social recovery, friends/blocks/presence/discovery,
  conversations, full guild administration, and integrator
  connect/consent. Every signature-required action
  (`AccountSession.sign(actionTag, fields)`) signs itself automatically —
  callers never hand-construct `signing_key_id`/`signature`.
- `IntegratorSession` — the capability-gated model: every method checks
  its own `require(capability)` client-side before making a request, the
  same fast-fail convention every other SDK in this repo uses (never the
  actual security boundary — the server enforces the same thing
  independently).
- No implicit conversion between `AccountSession` and `IntegratorSession`
  anywhere in this package — no shared base class, no cast — this
  invariant holds at the type level here too, same as Rust/C#.
- Errors are typed subclasses of `AvalonSdkError`
  (`UnauthorizedError`/`CapabilityNotGrantedError`/`NotFoundError`/
  `ConflictError`/`RejectedError`/`UnavailableError`/`ProtocolError`/
  `NotConversationParticipantError`/`MissingIssuerCredentialsError`/
  `DeviceLoginDeniedError`/`DeviceLoginExpiredError`/
  `NoLocalSigningKeyError`), mapped from HTTP status + the server's own
  `{ error, code }` body.
- Shard family heads: `getShardFamily`, `familyRoot` and `verifyFamilyInclusion` fetch and check an owner's
  `GET /ledger/shard-family` head (`familyRootMatches` / `familyProofVerifies` on a response); `routeWrite` picks the sibling a
  write for a key goes to (no cross-sibling atomicity); see the root README.
- Self-certifying shard heads: `getShardTreeHead`,
  `verifySelfCertifyingTreeHead` and `shardCheck` verify a `node:<sha256-of-key>`
  shard's head from the served `signing_public_key` and the id alone; see
  [`avalon-docs: sdk/design.md`](https://github.com/avalon-initiative/avalon-docs/blob/main/sdk/design.md#self-certifying-shard-heads).

## No dedicated getting-started guide yet

Unlike the Rust SDK's `for-developers/` set, this SDK doesn't have its own
numbered guide series yet — noted honestly rather than left to look
finished. Until one exists, the most accurate reference is
[`avalon-docs: sdk/design.md`](https://github.com/avalon-initiative/avalon-docs/blob/main/sdk/design.md)'s TypeScript coverage,
plus the `*.test.ts` files under `avalon-sdks`' `languages/typescript/test/`, which
double as runnable usage examples for every domain.

## Related

- [`avalon-docs: sdk/README.md`](https://github.com/avalon-initiative/avalon-docs/blob/main/sdk/README.md) — the SDK project overview, and the other languages.
- [`../rust/README.md`](../rust/README.md) — the Rust SDK, reference implementation.
- [`../csharp/README.md`](../csharp/README.md) — the C# SDK.
- [`avalon-protocol: docs/projects/backend-server/README.md`](https://github.com/avalon-initiative/avalon-protocol/blob/main/docs/projects/backend-server/README.md) — what this SDK talks to.
