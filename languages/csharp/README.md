# Avalon C# SDK

## Witness-cosigned tree heads

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
independence of the witnesses on the list. Shared vectors:
`conformance/vectors/witness-cosigned-tree-head.json`.

## Self-certifying shard heads

`AvalonClient.GetShardTreeHeadAsync(shardId, treeSize)` fetches a head of one shard; `SignedTreeHeadWire.SigningPublicKey`
holds the optional `signing_public_key` a node serves for `node:<sha256-of-key>` shards (absent from older nodes).
`SelfCertifying.Verify(shardId, head, key?)` verifies with only that key: it must be 64 lowercase hex characters
decoding to a canonical Ed25519 point of non-small order, hash to the id and have signed the head. The result is a `SelfCertifyingResult` with
`Verified` and, when false, the first `Failure` (`NotSelfCertifying`, `MissingKey`, `MalformedKey`, `KeyIdMismatch`,
`BadSignature`). `SelfCertifying.ShardCheckFor(shardId)` returns `ShardCheck.SelfCertifying`, `CoreNetwork` (use
`VerifyNetworkAsync`) or `Unsupported`; unsupported kinds never verify. No trust anchor or witness list is involved.
Shared vectors: `conformance/vectors/self-certifying-tree-head.json`.

## Tracing a real call

`AvalonTrace.WithTraceAsync(() => client.GetNodeStatusAsync())` runs any SDK call with `X-Avalon-Trace` on each request and returns `Traced<T>` (`Value`, `Requests`). Each `RequestTrace` has the `TraceId` sent and either a decoded `Trace` (`Branches` of `PathHop`, which extends the `TraceHop` that `TraceAsync` returns and keeps unknown fields in `Extra`) or a `Problem` (`Missing`, `Oversized`, `Malformed`, `TraceIdMismatch`). Opt-in and read-only; a missing or malformed header never fails the call. Hops are self-reported by the nodes on the path and are advisory. Requests are traced through an `HttpClient` built on `AvalonTraceHandler`, which the SDK's default clients use; for your own client, wrap its handler: `new HttpClient(new AvalonTraceHandler(inner))`. See the root README.

## Known list and default-on witness verification (C#)

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

