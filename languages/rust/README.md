# avalon-sdk (Rust)

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

Opt out with `WitnessPolicy::None` or pass your own list with `WitnessPolicy::Explicit`, either on
`AvalonClient::with_witness_policy`, `verify_network_with_policy` or `DiscoveryConfig::witness_policy`.
The prefix rule needs no DNS (IPv4 /24, IPv6 /48, or a hostname's last two labels), so it stops one
address block or registered domain from filling the list but not many domains pointing at one machine;
the trust-anchor seeds are the floor. `known_list::cross_check_head` asks each known witness for the
head at the accepted size and reports author-signed heads with a different root as evidence; it reports
only. Behavior is pinned by `conformance/vectors/witness-announce.json` and `known-list-selection.json`.
