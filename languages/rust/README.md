# avalon-sdk (Rust)

## Install

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

### From the `.crate` files on the release page

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

### crates.io (not published yet)

```toml
avalon-sdk = "X.Y.Z"   # not published yet: tracked in #64
```

## Witness-cosigned tree heads

An author-signed tree head can also be checked against a witness list the caller supplies. With a
known list of two or more witnesses, a head is accepted only when the author signature verifies and a
majority (`n/2 + 1`, counting distinct witnesses) of the list has cosigned the same tree size, root,
network and author timestamp, with `observed_at` inside the freshness window (default 600 seconds,
future-dated cosignatures rejected). A known witness that holds the author's own key counts without a
cosignature. With zero or one known witness only the author signature is checked.

The SDK never takes the list from the node it is talking to. A cosigned head is resistance against a single
compromised author or node, not proof against a colluding majority of the list. Rust:
`AvalonClient::fetch_cosigned_tree_head` (`?witnesses=1`), `AvalonClient::verify_network_with_witnesses`
(a head that is not cosigned reports `Mismatch`), and `witness::{verify_cosigned_tree_head,
find_equivocating_witnesses}`. Behavior is pinned by `conformance/vectors/witness-cosigned-tree-head.json`.

## Self-certifying shard heads

`AvalonClient::fetch_shard_tree_head(shard_id, tree_size)` returns a `self_certifying::SelfCertifyingTreeHead`
(the `sth::SignedTreeHead` plus the optional `signing_public_key` a node serves for `node:<sha256-of-key>` shards).
`SelfCertifyingTreeHead::verify(shard_id)`, or `self_certifying::verify_self_certifying_head(shard_id, &sth, key)`,
returns `Ok(())` only when the key is 64 lowercase hex characters decoding to a valid Ed25519 point, hashes to the id
and signed the head; otherwise the first failure as a `SelfCertifyingFailure` (`NotSelfCertifying`, `MissingKey`,
`MalformedKey`, `KeyIdMismatch`, `BadSignature`). `self_certifying::shard_check(shard_id)` returns
`ShardCheck::SelfCertifying`, `CoreNetwork` (use `verify_network`) or `Unsupported`; unsupported kinds never verify.
No trust anchor or witness list is involved. Shared vectors: `conformance/vectors/self-certifying-tree-head.json`.

## Tracing a real call

`with_trace(fut).await` runs any SDK call with `X-Avalon-Trace` on each request it sends through the shared request path and returns `Traced { value, requests }`. Each `RequestTrace` has the `trace_id` sent and either a decoded `OperationTrace` (`branches` of `PathHop`, which derefs to the `TraceHop` that `trace()` returns and keeps unknown fields in `extra`) or a `TraceProblem` (`Missing`, `Oversized`, `Malformed`, `TraceIdMismatch`). Opt-in and read-only; a missing or malformed header never fails the call, and `value` is the call's own result unchanged. Hops are self-reported by the nodes on the path and are advisory. Tracing is scoped to the current task. See the root README.

## Discovery-built known list

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
