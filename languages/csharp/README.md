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
before. The known list is always supplied by the caller and is never taken from the node being
checked. Building the list automatically from discovery is not implemented yet. This is
resistance to a single compromised author key, not proof: the guarantee is only as strong as the
independence of the witnesses on the list. Shared vectors:
`conformance/vectors/witness-cosigned-tree-head.json`.

