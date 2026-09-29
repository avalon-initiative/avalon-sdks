# For Developers

Documentation for developers integrating Avalon into their own game, app, or
service — the audience the SDKs (the Rust SDK, the C# SDK) exist for.

Start with [Integrations](https://github.com/avalon-initiative/avalon-docs/blob/main/integrations/README.md) in the Avalon docs for the case for
integrating your game, app, or service with Avalon at all. The pages below are the integration
guide, for the Rust SDK, the reference implementation.
The C# SDK (`avalon-sdks`' `languages/csharp/AvalonSdk`) mirrors most of that surface but doesn't have
its own parallel guide yet.

## Guides

1. [`getting-started.md`](getting-started.md) — add the crate,
   `AvalonClient::new`, `authenticate`, read a profile. Ten minutes.
2. [`capabilities.md`](capabilities.md) — the capability list, what each
   unlocks, how a player grants one, what `CapabilityNotGranted` means.
3. [`achievements.md`](achievements.md) — define, issue (signed with your
   own issuer key), read, verify, revoke.
4. [`guilds-and-friends.md`](guilds-and-friends.md) — reading rosters,
   friends, and presence, and their current visibility-scoping gaps.
5. [`errors-and-retries.md`](errors-and-retries.md) — the `SdkError`
   taxonomy and what's safe to retry.
6. [`local-development.md`](local-development.md) — running the whole
   vertical slice locally through `avalon-cli`, no game client needed.

These pages are about *doing* — they link into
[protocol concepts](https://github.com/avalon-initiative/avalon-docs/blob/main/protocol/README.md) for the concepts behind what you're
doing (the trust model, capability grants, revocation, visibility) rather
than restating it. Runnable examples for each guide's core flow live in
`languages/rust/examples/` (`authenticate.rs`, `issue_achievement.rs`,
`list_friends.rs`).

See also [`avalon-docs: sdk/design.md`](https://github.com/avalon-initiative/avalon-docs/blob/main/sdk/design.md) for the SDK
design principle (protocol capabilities, not infrastructure),
[`avalon-docs: protocol/trust-model.md`](https://github.com/avalon-initiative/avalon-docs/blob/main/protocol/trust-model.md) for what an
integrator is and isn't told about an attestation,
[`avalon-docs: architecture/design-proposal.md`](https://github.com/avalon-initiative/avalon-docs/blob/main/architecture/design-proposal.md)
for the intended developer experience, and the repository root `README.md`
for the current build status.
