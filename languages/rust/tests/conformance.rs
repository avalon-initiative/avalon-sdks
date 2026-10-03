//! Cross-SDK conformance suite (issue #727, epic #722) — loads the shared
//! test vectors under `conformance/vectors/` (this repo's root) and asserts
//! this crate's real implementation produces byte-for-byte identical
//! output. Pure, offline, no server/database needed — runs in
//! `cargo test -p avalon-sdk` same as every other non-`--ignored` test here.
//!
//! Client-side wire-shape codegen (#723-#726) already covers plain
//! request/response shapes; this suite exists for the "smart client"
//! behavior that codegen can't produce — a real signing algorithm, a real
//! derivation, a real multi-step handshake — see #714's own decision and
//! `conformance/vectors/SCHEMA.md` for the full rationale.
//!
//! Since issue #774 this crate no longer shares Rust source with
//! `avalon-protocol`, so the signing-byte constructions below are this
//! SDK's own independent implementations, exactly like the C# and
//! TypeScript SDKs'. These vectors are what proves they haven't drifted
//! from the server's; `crates/protocol/tests/conformance.rs` in
//! `avalon-protocol` asserts the *server* side of each of the same vector
//! files, so a divergence fails a test on whichever side moved.
//!
//! Issue #775 physically moved this crate into `avalon-sdks` — this repo's
//! `conformance/vectors/` is a vendored copy of `avalon-protocol`'s, kept in
//! sync by hand (same convention as `docs/generated/openapi.json`), not a live link across repos.
//!
//! When a vector's `supportedIn` doesn't list `"rust"`, this file asserts
//! nothing false: it prints an explicit, named skip rather than faking a
//! pass. See each vector file's own `notSupported.rust` entry for why.

use avalon_sdk::achievements::{
    attestation_signing_bytes, bulk_attestation_signing_bytes, revocation_signing_bytes,
};
use avalon_sdk::cross_node_login::signing_bytes as cross_node_login_signing_bytes;
use avalon_sdk::sth::signing_message as sth_signing_message;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::Value;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use uuid::Uuid;

fn vectors_dir() -> PathBuf {
    // languages/rust/ -> languages/ -> avalon-sdks repo root -> conformance/vectors
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("languages/rust/ sits two levels under the avalon-sdks repo root")
        .join("conformance/vectors")
}

fn load(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read conformance vector {}: {e}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()))
}

fn supported_in(doc: &Value, lang: &str) -> bool {
    doc["supportedIn"]
        .as_array()
        .expect("supportedIn must be an array")
        .iter()
        .any(|v| v.as_str() == Some(lang))
}

fn signing_key_from_seed_hex(hex_seed: &str) -> SigningKey {
    let bytes = hex::decode(hex_seed).expect("valid hex seed");
    let seed: [u8; 32] = bytes.try_into().expect("32-byte seed");
    SigningKey::from_bytes(&seed)
}

fn parse_uuid(v: &Value, field: &str) -> Uuid {
    Uuid::parse_str(
        v[field]
            .as_str()
            .unwrap_or_else(|| panic!("missing {field}")),
    )
    .unwrap_or_else(|e| panic!("invalid uuid in {field}: {e}"))
}

fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Asserts a vector's recorded signature both matches what this SDK
/// produces for `bytes` and still verifies against the file's shared
/// public key — the second half catches a vector file edited by hand to
/// match a broken implementation.
fn assert_signature_matches(
    name: &str,
    signing_key: &SigningKey,
    bytes: &[u8],
    expected_sig_hex: &str,
) {
    let signature = signing_key.sign(bytes);
    assert_eq!(
        to_hex(&signature.to_bytes()),
        expected_sig_hex,
        "[{name}] Ed25519 signature diverged from the shared vector — a payload signed by \
         the Rust SDK would not be interchangeable with one from another SDK for the same input"
    );

    let verifying_key = VerifyingKey::from_bytes(signing_key.verifying_key().as_bytes()).unwrap();
    let recorded_sig_bytes: [u8; 64] = hex::decode(expected_sig_hex)
        .expect("signatureHex must be valid hex")
        .try_into()
        .expect("signatureHex must be 64 bytes");
    verifying_key
        .verify_strict(
            bytes,
            &ed25519_dalek::Signature::from_bytes(&recorded_sig_bytes),
        )
        .unwrap_or_else(|e| panic!("[{name}] recorded vector signature does not verify: {e}"));
}

#[test]
fn cross_node_login_grant_signing_matches_shared_vectors() {
    let doc = load("cross-node-login.json");
    assert!(
        supported_in(&doc, "rust"),
        "cross-node-login.json must list rust in supportedIn — \
         avalon_sdk::cross_node_login::signing_bytes implements it"
    );

    let signing_key = signing_key_from_seed_hex(doc["signingKeySeedHex"].as_str().unwrap());
    let expected_pub = doc["signingPublicKeyHex"].as_str().unwrap();
    assert_eq!(
        to_hex(signing_key.verifying_key().as_bytes()),
        expected_pub,
        "the shared test keypair's derived public key must match the vector file"
    );

    for vector in doc["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap_or("<unnamed>");
        let input = &vector["input"];
        let issued_at =
            OffsetDateTime::from_unix_timestamp(input["issuedAtUnixSeconds"].as_i64().unwrap())
                .unwrap();
        let expires_at =
            OffsetDateTime::from_unix_timestamp(input["expiresAtUnixSeconds"].as_i64().unwrap())
                .unwrap();

        let bytes = cross_node_login_signing_bytes(
            parse_uuid(input, "identityId"),
            parse_uuid(input, "signingKeyId"),
            input["destinationBaseUrl"].as_str().unwrap(),
            input["requestingContext"].as_str().unwrap(),
            parse_uuid(input, "nonce"),
            issued_at,
            expires_at,
        );

        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            vector["expected"]["signingBytesUtf8"].as_str().unwrap(),
            "[{name}] signing bytes diverged from the shared vector"
        );
        assert_signature_matches(
            name,
            &signing_key,
            &bytes,
            vector["expected"]["signatureHex"].as_str().unwrap(),
        );
    }
}

/// Issue #774's own safety net: this crate builds attestation issuance,
/// bulk issuance, and revocation signing bytes itself rather than calling
/// the server's construction, so this is the test that would catch the two
/// drifting apart.
#[test]
fn attestation_signing_matches_shared_vectors() {
    let doc = load("attestation-signing.json");
    assert!(
        supported_in(&doc, "rust"),
        "attestation-signing.json must list rust in supportedIn — \
         avalon_sdk::achievements implements all three constructions"
    );

    let signing_key = signing_key_from_seed_hex(doc["signingKeySeedHex"].as_str().unwrap());
    assert_eq!(
        to_hex(signing_key.verifying_key().as_bytes()),
        doc["signingPublicKeyHex"].as_str().unwrap(),
        "the shared test keypair's derived public key must match the vector file"
    );

    for vector in doc["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap_or("<unnamed>");
        let input = &vector["input"];
        let operation = input["operation"].as_str().unwrap();
        let claim_kind = input["claimKind"].as_str().unwrap();
        let issuer_ref = input["issuerRef"].as_str().unwrap();

        let bytes = match operation {
            "issue" => attestation_signing_bytes(
                claim_kind,
                issuer_ref,
                parse_uuid(input, "subject"),
                input["achievement"].as_str().unwrap(),
            ),
            "bulk_issue" => {
                let achievements: Vec<String> = input["achievements"]
                    .as_array()
                    .expect("bulk_issue vectors carry an achievements array")
                    .iter()
                    .map(|v| v.as_str().unwrap().to_string())
                    .collect();
                bulk_attestation_signing_bytes(
                    claim_kind,
                    issuer_ref,
                    parse_uuid(input, "subject"),
                    &achievements,
                )
            }
            "revoke" => revocation_signing_bytes(
                claim_kind,
                issuer_ref,
                parse_uuid(input, "attestationId"),
                input["reasonCode"].as_str().unwrap(),
            ),
            other => panic!("[{name}] unknown operation {other}"),
        };

        assert_eq!(
            to_hex(&bytes),
            vector["expected"]["signingBytesHex"].as_str().unwrap(),
            "[{name}] signing bytes diverged from the shared vector"
        );
        if let Some(utf8) = vector["expected"]["signingBytesUtf8"].as_str() {
            assert_eq!(
                String::from_utf8(bytes.clone()).unwrap(),
                utf8,
                "[{name}] signing bytes diverged from the shared vector"
            );
        }
        assert_signature_matches(
            name,
            &signing_key,
            &bytes,
            vector["expected"]["signatureHex"].as_str().unwrap(),
        );
    }
}

/// `crate::sth` is the other construction #774 made independent — a node's
/// Signed Tree Head is what `avalon_sdk::network` verifies a network's
/// identity against, so a drift here would make every pinned trust anchor
/// reject a legitimate node.
#[test]
fn signed_tree_head_signing_matches_shared_vectors() {
    let doc = load("signed-tree-head.json");
    assert!(
        supported_in(&doc, "rust"),
        "signed-tree-head.json must list rust in supportedIn — \
         avalon_sdk::sth implements it"
    );

    let signing_key = signing_key_from_seed_hex(doc["signingKeySeedHex"].as_str().unwrap());
    assert_eq!(
        to_hex(signing_key.verifying_key().as_bytes()),
        doc["signingPublicKeyHex"].as_str().unwrap(),
        "the shared test keypair's derived public key must match the vector file"
    );

    for vector in doc["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap_or("<unnamed>");
        let input = &vector["input"];
        let created_at =
            OffsetDateTime::from_unix_timestamp(input["createdAtUnixSeconds"].as_i64().unwrap())
                .unwrap();
        let bytes = sth_signing_message(
            input["treeSize"].as_i64().unwrap(),
            input["rootHashHex"].as_str().unwrap(),
            input["networkId"].as_str().unwrap(),
            created_at,
        );

        assert_eq!(
            to_hex(&bytes),
            vector["expected"]["signingBytesHex"].as_str().unwrap(),
            "[{name}] signing bytes diverged from the shared vector"
        );
        assert_signature_matches(
            name,
            &signing_key,
            &bytes,
            vector["expected"]["signatureHex"].as_str().unwrap(),
        );
    }
}

#[test]
fn witness_cosigned_tree_head_matches_shared_vectors() {
    use avalon_sdk::sth::SignedTreeHead;
    use avalon_sdk::witness::{
        find_equivocating_witnesses, verify_cosigned_tree_head, CosignedTreeHead,
        WitnessCosignature,
    };
    let doc = load("witness-cosigned-tree-head.json");
    if !supported_in(&doc, "rust") {
        println!("skipping witness-cosigned-tree-head.json: rust not in supportedIn");
        return;
    }
    let ts = |secs: i64| OffsetDateTime::from_unix_timestamp(secs).unwrap();
    let key_of = |hex_key: &str| {
        let bytes: [u8; 32] = hex::decode(hex_key).unwrap().try_into().unwrap();
        VerifyingKey::from_bytes(&bytes).unwrap()
    };
    let keys = doc["witnessVerifyingKeysHex"].as_object().unwrap();
    let author_key = key_of(doc["authorVerifyingKeyHex"].as_str().unwrap());
    let network_id = doc["networkId"].as_str().unwrap();
    let head_of = |v: &Value| {
        let sth = &v["sth"];
        let tree_size = sth["treeSize"].as_i64().unwrap();
        let root = sth["rootHashHex"].as_str().unwrap();
        let created = ts(sth["createdAtUnixSeconds"].as_i64().unwrap());
        CosignedTreeHead {
            sth: SignedTreeHead {
                tree_size,
                root_hash: root.to_string(),
                network_id: network_id.to_string(),
                signing_key_id: "author".to_string(),
                signature: sth["signatureHex"].as_str().unwrap().to_string(),
                created_at: created,
            },
            cosignatures: v["cosignatures"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| WitnessCosignature {
                    tree_size,
                    root_hash: root.to_string(),
                    network_id: network_id.to_string(),
                    author_created_at: created,
                    witness_key_id: c["witnessKeyId"].as_str().unwrap().to_string(),
                    observed_at: ts(c["observedAtUnixSeconds"].as_i64().unwrap()),
                    signature: c["signatureHex"].as_str().unwrap().to_string(),
                })
                .collect(),
        }
    };
    // The vector names witnesses by label; the label is the cosignature's key id.
    let known_of = |input: &Value| -> Vec<(String, VerifyingKey)> {
        input["knownList"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| {
                let name = n.as_str().unwrap();
                (name.to_string(), key_of(keys[name].as_str().unwrap()))
            })
            .collect()
    };
    for vector in doc["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let input = &vector["input"];
        let known = known_of(input);
        let cutoff = ts(input["freshnessCutoffUnixSeconds"].as_i64().unwrap());
        let now = ts(input["nowUnixSeconds"].as_i64().unwrap());
        let expected = &vector["expected"];
        if input.get("headA").is_some() {
            let (a, b) = (head_of(&input["headA"]), head_of(&input["headB"]));
            assert_eq!(
                verify_cosigned_tree_head(&author_key, &a, &known, cutoff, now),
                expected["headAAccepted"].as_bool().unwrap(),
                "[{name}] head A"
            );
            assert_eq!(
                verify_cosigned_tree_head(&author_key, &b, &known, cutoff, now),
                expected["headBAccepted"].as_bool().unwrap(),
                "[{name}] head B"
            );
            let want: Vec<String> = expected["equivocatingWitnesses"]
                .as_array()
                .unwrap()
                .iter()
                .map(|w| w.as_str().unwrap().to_string())
                .collect();
            assert_eq!(
                find_equivocating_witnesses(&author_key, &known, cutoff, now, &a, &b),
                want,
                "[{name}] equivocating witnesses"
            );
        } else {
            assert_eq!(
                verify_cosigned_tree_head(&author_key, &head_of(input), &known, cutoff, now),
                expected["accepted"].as_bool().unwrap(),
                "[{name}]"
            );
        }
    }
}

#[test]
fn session_continuation_token_signing_is_a_known_rust_sdk_gap() {
    let doc = load("session-continuation.json");
    if supported_in(&doc, "rust") {
        panic!(
            "session-continuation.json now lists rust in supportedIn, but this test only \
             documents the gap — implement real assertions here (mirroring \
             cross_node_login_grant_signing_matches_shared_vectors above) before flipping supportedIn"
        );
    }
    let gap = doc["notSupported"]["rust"]
        .as_str()
        .expect("notSupported.rust must explain why rust is missing");
    println!(
        "SKIP conformance/vectors/session-continuation.json for rust: {gap}\n\
         (the server-side construction is still checked against this same vector by \
         crates/protocol/tests/conformance.rs — nothing in rust exposes client-side \
         minting yet)"
    );
}

#[test]
fn websocket_interest_claim_signing_is_a_known_rust_sdk_gap() {
    let doc = load("websocket-interest-claim.json");
    if supported_in(&doc, "rust") {
        panic!(
            "websocket-interest-claim.json now lists rust in supportedIn, but this test only \
             documents the gap — implement real assertions here before flipping supportedIn"
        );
    }
    let gap = doc["notSupported"]["rust"]
        .as_str()
        .expect("notSupported.rust must explain why rust is missing");
    println!(
        "SKIP conformance/vectors/websocket-interest-claim.json for rust: {gap}\n\
         (the server-side construction is still checked against this same vector by \
         crates/protocol/tests/conformance.rs — rust itself has no interest-claim \
         handshake yet)"
    );
}

#[test]
fn bip39_mnemonic_derivation_is_a_known_rust_sdk_gap() {
    let doc = load("bip39-mnemonic.json");
    assert!(
        !supported_in(&doc, "rust"),
        "bip39-mnemonic.json now lists rust in supportedIn, but rust has no BIP39 \
         dependency or derivation code — add a real implementation and real assertions here \
         before flipping supportedIn, don't just relabel the vector file"
    );
    let gap = doc["notSupported"]["rust"]
        .as_str()
        .expect("notSupported.rust must explain why rust is missing");
    println!("SKIP conformance/vectors/bip39-mnemonic.json for rust: {gap}");
}

#[test]
fn witness_announce_matches_shared_vectors() {
    use avalon_sdk::witness::{verify_witness_announce, witness_announce_message};
    let doc = load("witness-announce.json");
    let parse =
        |s: &str| OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).unwrap();
    for vector in doc["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let input = &vector["input"];
        let base_url = input["baseUrl"].as_str().unwrap();
        let key_id = input["witnessKeyId"].as_str().unwrap();
        let announced_at = parse(input["announcedAt"].as_str().unwrap());
        if let Some(message_hex) = input.get("messageHex").and_then(Value::as_str) {
            assert_eq!(
                hex::encode(witness_announce_message(base_url, key_id, announced_at)),
                message_hex,
                "[{name}] message bytes"
            );
        }
        assert_eq!(
            verify_witness_announce(
                base_url,
                key_id,
                announced_at,
                input["proofHex"].as_str().unwrap(),
                parse(input["now"].as_str().unwrap()),
            ),
            vector["expected"]["accepted"].as_bool().unwrap(),
            "[{name}]"
        );
    }
}

#[test]
fn known_list_selection_matches_shared_vectors() {
    use avalon_sdk::known_list::{diversity_prefix_for_url, select_known_list, Candidate};
    let doc = load("known-list-selection.json");
    for vector in doc["prefixVectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        assert_eq!(
            diversity_prefix_for_url(vector["input"]["baseUrl"].as_str().unwrap()),
            vector["expected"]["prefix"].as_str().map(str::to_string),
            "[{name}]"
        );
    }
    for vector in doc["selectionVectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let input = &vector["input"];
        let candidates: Vec<Candidate> = input["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| Candidate {
                witness_key_id: c["witnessKeyId"].as_str().unwrap().to_string(),
                base_url: c["baseUrl"].as_str().unwrap().to_string(),
                is_anchor: c["isAnchor"].as_bool().unwrap(),
            })
            .collect();
        let want: Vec<String> = vector["expected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            select_known_list(
                &candidates,
                input["capacity"].as_u64().unwrap() as usize,
                input["anchorCapacity"].as_u64().unwrap() as usize,
                input["maxPerPrefix"].as_u64().unwrap() as usize,
            ),
            want,
            "[{name}]"
        );
    }
}

#[test]
fn self_certifying_tree_head_matches_shared_vectors() {
    use avalon_sdk::self_certifying::{
        self_certifying_id, shard_check, verify_self_certifying_head, ShardCheck,
    };
    let doc = load("self-certifying-tree-head.json");
    assert!(supported_in(&doc, "rust"));
    let signing = SigningKey::from_bytes(
        &hex::decode(doc["signingKeySeedHex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        self_certifying_id(&signing.verifying_key()),
        doc["selfCertifyingId"].as_str().unwrap()
    );
    for vector in doc["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let input = &vector["input"];
        let shard_id = input["shardId"].as_str().unwrap();
        let head = &input["head"];
        let sth = avalon_sdk::sth::SignedTreeHead {
            tree_size: match &head["treeSize"] {
                Value::String(decimal) => decimal.parse().unwrap(),
                number => number.as_i64().unwrap(),
            },
            root_hash: head["rootHashHex"].as_str().unwrap().to_string(),
            network_id: head["networkId"].as_str().unwrap().to_string(),
            signing_key_id: head["signingKeyId"].as_str().unwrap().to_string(),
            signature: head["signatureHex"].as_str().unwrap().to_string(),
            created_at: OffsetDateTime::from_unix_timestamp(
                head["createdAtUnixSeconds"].as_i64().unwrap(),
            )
            .unwrap(),
        };
        let rfc3339 = OffsetDateTime::parse(
            head["createdAtRfc3339"].as_str().unwrap(),
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        assert_eq!(
            rfc3339.unix_timestamp(),
            sth.created_at.unix_timestamp(),
            "[{name}] createdAtRfc3339 floors to createdAtUnixSeconds"
        );
        let expected = &vector["expected"];
        let check = match shard_check(shard_id) {
            ShardCheck::SelfCertifying => "self_certifying",
            ShardCheck::CoreNetwork => "core_network",
            ShardCheck::Unsupported => "unsupported",
        };
        assert_eq!(check, expected["check"].as_str().unwrap(), "[{name}] check");
        let outcome = verify_self_certifying_head(
            shard_id,
            &sth,
            input.get("signingPublicKeyHex").and_then(Value::as_str),
        );
        assert_eq!(
            outcome.is_ok(),
            expected["verified"].as_bool().unwrap(),
            "[{name}] verified"
        );
        assert_eq!(
            outcome.err().map(|f| f.as_str()),
            expected["failure"].as_str(),
            "[{name}] failure"
        );
    }
}

fn family_head(v: &Value) -> avalon_sdk::shard_family::FamilyHead {
    avalon_sdk::shard_family::FamilyHead {
        shard_id: v["shardId"].as_str().unwrap().to_string(),
        tree_size: match &v["treeSize"] {
            Value::String(decimal) => decimal.parse().unwrap(),
            number => number.as_i64().unwrap(),
        },
        root_hash: v["rootHashHex"].as_str().unwrap().to_string(),
        signing_key_id: v["signingKeyId"].as_str().unwrap().to_string(),
        signature: v["signatureHex"].as_str().unwrap().to_string(),
    }
}

#[test]
fn shard_family_head_matches_shared_vectors() {
    use avalon_sdk::shard_family::{
        family_root, is_family_member, is_family_owner_id, shard_family_owner,
        verify_family_inclusion, FamilyProof,
    };
    let doc = load("shard-family-head.json");
    assert!(supported_in(&doc, "rust"));
    for v in doc["familyVectors"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let heads: Vec<_> = v["input"]["heads"]
            .as_array()
            .unwrap()
            .iter()
            .map(family_head)
            .collect();
        let root = family_root(v["input"]["owner"].as_str().unwrap(), &heads);
        assert_eq!(
            root,
            v["expected"]["rootHashHex"].as_str().unwrap(),
            "[{name}]"
        );
    }
    for v in doc["proofVectors"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let input = &v["input"];
        let mut head = family_head(&input["head"]);
        head.shard_id = input["shardId"].as_str().unwrap().to_string();
        let proof = FamilyProof {
            shard_id: head.shard_id.clone(),
            leaf_index: input["proof"]["leafIndex"].as_u64().unwrap() as usize,
            tree_size: input["proof"]["treeSize"].as_u64().unwrap() as usize,
            path: input["proof"]["pathHex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p.as_str().unwrap().to_string())
                .collect(),
        };
        let verified = verify_family_inclusion(
            input["owner"].as_str().unwrap(),
            input["rootHashHex"].as_str().unwrap(),
            &proof,
            &head,
        );
        assert_eq!(
            verified,
            v["expected"]["verified"].as_bool().unwrap(),
            "[{name}]"
        );
    }
    for v in doc["familyOwnerVectors"].as_array().unwrap() {
        let id = v["shardId"].as_str().unwrap();
        assert_eq!(
            shard_family_owner(id).as_deref(),
            v["expectedOwner"].as_str(),
            "[{id:?}]"
        );
    }
    for v in doc["ownerIdVectors"].as_array().unwrap() {
        let id = v["owner"].as_str().unwrap();
        assert_eq!(
            is_family_owner_id(id),
            v["expected"].as_bool().unwrap(),
            "[{id:?}]"
        );
    }
    for v in doc["memberVectors"].as_array().unwrap() {
        let (owner, id) = (v["owner"].as_str().unwrap(), v["shardId"].as_str().unwrap());
        assert_eq!(
            is_family_member(owner, id),
            v["expected"].as_bool().unwrap(),
            "[{owner:?} {id:?}]"
        );
    }
}

#[test]
fn shard_sibling_routing_matches_shared_vectors() {
    use avalon_sdk::shard_family::{route_weight, route_write};
    let doc = load("shard-sibling-routing.json");
    assert!(supported_in(&doc, "rust"));
    let strings = |v: &Value| -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect()
    };
    for v in doc["weightVectors"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let i = &v["input"];
        let weight = route_weight(
            i["owner"].as_str().unwrap(),
            i["key"].as_str().unwrap(),
            i["shardId"].as_str().unwrap(),
        );
        assert_eq!(
            hex::encode(weight),
            v["expected"]["weightHex"].as_str().unwrap(),
            "[{name}]"
        );
    }
    for v in doc["routeVectors"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let i = &v["input"];
        let siblings = strings(&i["siblings"]);
        let routed = route_write(
            i["owner"].as_str().unwrap(),
            i["key"].as_str().unwrap(),
            &siblings,
        );
        assert_eq!(routed, v["expected"]["shardId"].as_str(), "[{name}]");
    }
    for v in doc["movementVectors"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let i = &v["input"];
        let owner = i["owner"].as_str().unwrap();
        let (before, after) = (strings(&i["before"]), strings(&i["after"]));
        let keys = strings(&i["keys"]);
        let (want_before, want_after) = (&v["expected"]["before"], &v["expected"]["after"]);
        for (n, key) in keys.iter().enumerate() {
            let b = route_write(owner, key, &before);
            let a = route_write(owner, key, &after);
            assert_eq!(b, want_before[n].as_str(), "[{name}] before {key:?}");
            assert_eq!(a, want_after[n].as_str(), "[{name}] after {key:?}");
            // A key only moves onto a sibling that was added, or off one that was removed.
            if a != b {
                assert!(
                    !before.iter().any(|s| Some(s.as_str()) == a)
                        || !after.iter().any(|s| Some(s.as_str()) == b),
                    "[{name}] {key:?} moved between siblings present in both sets"
                );
            }
        }
    }
}
