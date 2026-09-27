# avalon-sdk (Rust)

## Witness-cosigned tree heads

An author-signed tree head can also be checked against a witness list the caller supplies. With a
known list of two or more witnesses, a head is accepted only when the author signature verifies and a
majority (`n/2 + 1`, counting distinct witnesses) of the list has cosigned the same tree size, root,
network and author timestamp, with `observed_at` inside the freshness window (default 600 seconds,
future-dated cosignatures rejected). A known witness that holds the author's own key counts without a
cosignature. With zero or one known witness only the author signature is checked.

The list is always explicit: the SDK never takes it from the node it is talking to, and building it
automatically from discovery is not implemented yet. A cosigned head is resistance against a single
compromised author or node, not proof against a colluding majority of the list. Rust:
`AvalonClient::fetch_cosigned_tree_head` (`?witnesses=1`), `AvalonClient::verify_network_with_witnesses`
(a head that is not cosigned reports `Mismatch`), and `witness::{verify_cosigned_tree_head,
find_equivocating_witnesses}`. Behavior is pinned by `conformance/vectors/witness-cosigned-tree-head.json`.

