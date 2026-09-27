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

