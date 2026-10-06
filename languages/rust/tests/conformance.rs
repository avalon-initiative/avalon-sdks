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
use avalon_sdk::identity_signing::{
    device_grant_approval_signing_bytes, identity_created_signing_bytes, is_acceptable_ed25519_key,
    signing_key_revoked_signing_bytes, verify_strict,
};
use avalon_sdk::sth::signing_message as sth_signing_message;
use avalon_sdk::types::ids::IdentityId;
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

fn parse_identity_id(v: &Value, field: &str) -> IdentityId {
    v[field]
        .as_str()
        .unwrap_or_else(|| panic!("missing {field}"))
        .parse()
        .unwrap_or_else(|e| panic!("invalid identity id in {field}: {e}"))
}

fn key32(hex_key: &str) -> [u8; 32] {
    hex::decode(hex_key)
        .expect("valid hex key")
        .try_into()
        .expect("32-byte key")
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
            &parse_identity_id(input, "identityId"),
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
                &parse_identity_id(input, "subject"),
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
                    &parse_identity_id(input, "subject"),
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
fn identity_id_matches_shared_vectors() {
    let doc = load("identity-id.json");
    assert!(supported_in(&doc, "rust"));
    for vector in doc["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let input = &vector["input"];
        let expected = &vector["expected"];
        match vector["kind"].as_str().unwrap() {
            "derive" => {
                let seed: [u8; 32] = key32(input["seedHex"].as_str().unwrap());
                let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
                assert_eq!(to_hex(&public_key), input["publicKeyHex"].as_str().unwrap());
                let mut preimage = b"avalon-identity-id-v1".to_vec();
                preimage.extend_from_slice(&public_key);
                assert_eq!(to_hex(&preimage), expected["preimageHex"].as_str().unwrap());
                let id = IdentityId::derive(&public_key);
                assert_eq!(
                    id.to_string(),
                    expected["identityId"].as_str().unwrap(),
                    "[{name}]"
                );
                assert!(id.matches_key(&public_key));
            }
            "parse" => {
                let text = input["identityId"].as_str().unwrap();
                assert_eq!(
                    text.parse::<IdentityId>().is_ok(),
                    expected["valid"].as_bool().unwrap(),
                    "[{name}]"
                );
            }
            "key_acceptability" => {
                let bytes = key32(input["publicKeyHex"].as_str().unwrap());
                let acceptable = VerifyingKey::from_bytes(&bytes)
                    .map(|key| is_acceptable_ed25519_key(&key))
                    .unwrap_or(false);
                assert_eq!(
                    acceptable,
                    expected["acceptable"].as_bool().unwrap(),
                    "[{name}]"
                );
            }
            "distinct_from_shard_id" => {
                let bytes = key32(input["publicKeyHex"].as_str().unwrap());
                let key = VerifyingKey::from_bytes(&bytes).unwrap();
                let id = IdentityId::derive(&bytes);
                assert_eq!(id.to_string(), expected["identityId"].as_str().unwrap());
                let node_id = avalon_sdk::self_certifying::self_certifying_id(&key);
                assert_eq!(
                    node_id,
                    expected["nodeShardId"].as_str().unwrap(),
                    "[{name}]"
                );
                assert_ne!(node_id, id.to_string());
                assert!(!expected["equal"].as_bool().unwrap());
            }
            "strict_verify" => {
                let key = VerifyingKey::from_bytes(&key32(input["publicKeyHex"].as_str().unwrap()));
                let signature: [u8; 64] = hex::decode(input["signatureHex"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
                let message = hex::decode(input["messageHex"].as_str().unwrap()).unwrap();
                let valid = key
                    .map(|key| verify_strict(&key, &message, &signature))
                    .unwrap_or(false);
                assert_eq!(valid, expected["valid"].as_bool().unwrap(), "[{name}]");
            }
            other => panic!("[{name}] unknown kind {other}"),
        }
    }
}

/// The chain position a key-event vector signs: `seq` is a decimal string, `prevHashHex` null or hex.
fn parse_position(input: &Value) -> (u64, Option<[u8; 32]>) {
    let seq = input["seq"].as_str().expect("seq string").parse().unwrap();
    let prev = input["prevHashHex"].as_str().map(key32);
    (seq, prev)
}

/// Runs one identity key-event vector file: `vectors` must reproduce bytes and signature,
/// `replayVectors` and `legacyLayoutVectors` carry a signature that must not verify for the input.
fn run_key_event_vectors(
    file: &str,
    doc: &Value,
    bytes_for: &dyn Fn(&Value, &Value) -> Vec<u8>,
) -> usize {
    let signing_key = signing_key_from_seed_hex(doc["signingKeySeedHex"].as_str().unwrap());
    assert_eq!(
        to_hex(signing_key.verifying_key().as_bytes()),
        doc["signingPublicKeyHex"].as_str().unwrap()
    );
    let verifies = |bytes: &[u8], signature_hex: &str| {
        let signature: [u8; 64] = hex::decode(signature_hex).unwrap().try_into().unwrap();
        verify_strict(&signing_key.verifying_key(), bytes, &signature)
    };
    let mut count = 0;
    for vector in doc["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let bytes = bytes_for(doc, &vector["input"]);
        let expected = &vector["expected"];
        assert_eq!(
            to_hex(&bytes),
            expected["signingBytesHex"].as_str().unwrap(),
            "[{file} {name}]"
        );
        assert_signature_matches(
            name,
            &signing_key,
            &bytes,
            expected["signatureHex"].as_str().unwrap(),
        );
        count += 1;
    }
    for group in ["replayVectors", "legacyLayoutVectors"] {
        let cases = doc[group].as_array().unwrap();
        assert!(!cases.is_empty(), "{file} {group}");
        for vector in cases {
            let name = vector["name"].as_str().unwrap();
            let bytes = bytes_for(doc, &vector["input"]);
            let signature_hex = vector["signatureHex"].as_str().unwrap();
            if let Some(legacy) = vector["legacySigningBytesUtf8"].as_str() {
                assert_ne!(legacy.as_bytes(), &bytes[..], "[{file} {name}]");
                assert!(
                    verifies(legacy.as_bytes(), signature_hex),
                    "[{file} {name}] the legacy signature is valid over the retired text"
                );
            }
            assert_eq!(
                verifies(&bytes, signature_hex),
                vector["expected"]["valid"].as_bool().unwrap(),
                "[{file} {name}]"
            );
            count += 1;
        }
    }
    count
}

#[test]
fn identity_created_signing_matches_shared_vectors() {
    let count = run_key_event_vectors(
        "identity-created-signing.json",
        &load("identity-created-signing.json"),
        &|doc, input| {
            let public_key = key32(doc["signingPublicKeyHex"].as_str().unwrap());
            let identity_id = parse_identity_id(doc, "identityId");
            assert!(identity_id.matches_key(&public_key));
            identity_created_signing_bytes(
                input["networkId"].as_str().unwrap(),
                input["shardId"].as_str().unwrap(),
                parse_uuid(input, "ticketId"),
                &identity_id,
                &public_key,
                input["displayName"].as_str().unwrap(),
            )
        },
    );
    println!("identity-created-signing.json: {count} vectors");
}

#[test]
fn device_grant_approval_signing_matches_shared_vectors() {
    let doc = load("device-grant-approval.json");
    let requested = signing_key_from_seed_hex(doc["requestedKeySeedHex"].as_str().unwrap());
    assert_eq!(
        to_hex(requested.verifying_key().as_bytes()),
        doc["requestedPublicKeyHex"].as_str().unwrap()
    );
    let count = run_key_event_vectors("device-grant-approval.json", &doc, &|_, input| {
        let (seq, prev_hash) = parse_position(input);
        device_grant_approval_signing_bytes(
            parse_uuid(input, "grantId"),
            &parse_identity_id(input, "identityId"),
            parse_uuid(input, "approverSigningKeyId"),
            &key32(input["requestedPublicKeyHex"].as_str().unwrap()),
            seq,
            prev_hash.as_ref(),
        )
    });
    println!("device-grant-approval.json: {count} vectors");
}

#[test]
fn signing_key_revoked_signing_matches_shared_vectors() {
    let count = run_key_event_vectors(
        "signing-key-revoked.json",
        &load("signing-key-revoked.json"),
        &|_, input| {
            let (seq, prev_hash) = parse_position(input);
            signing_key_revoked_signing_bytes(
                &parse_identity_id(input, "identityId"),
                parse_uuid(input, "signingKeyId"),
                parse_uuid(input, "revokedBySigningKeyId"),
                seq,
                prev_hash.as_ref(),
            )
        },
    );
    println!("signing-key-revoked.json: {count} vectors");
}

fn conformance_tag(doc_tag: &str) -> avalon_sdk::signing_bytes::DomainTag {
    *avalon_sdk::signing_bytes::tags::ALL
        .iter()
        .find(|t| t.as_str() == doc_tag)
        .unwrap_or_else(|| panic!("tag {doc_tag} is not in the registry"))
}

/// The bytes a vector field stands for: text, hex, or a repeated unit for the 65536-byte cases.
fn field_bytes(field: &Value) -> Vec<u8> {
    let repeat = |unit: Vec<u8>| unit.repeat(field["count"].as_u64().unwrap() as usize);
    match field["type"].as_str().unwrap() {
        "str" => match field["utf8"].as_str() {
            Some(s) => s.as_bytes().to_vec(),
            None => repeat(field["repeatUtf8"].as_str().unwrap().as_bytes().to_vec()),
        },
        "bytes" => match field["hex"].as_str() {
            Some(h) => hex::decode(h).unwrap(),
            None => repeat(hex::decode(field["repeatByteHex"].as_str().unwrap()).unwrap()),
        },
        _ => hex::decode(field["hex"].as_str().unwrap()).unwrap(),
    }
}

fn field_int(field: &Value) -> String {
    field["value"].as_str().unwrap().to_string()
}

#[test]
fn structured_signing_bytes_build_and_read_back_per_shared_vectors() {
    use avalon_sdk::signing_bytes::{Builder, Reader};
    use sha2::{Digest, Sha256};
    let doc = load("structured-signing-bytes.json");
    let vectors = doc["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let input = &vector["input"];
        let tag = conformance_tag(input["tag"].as_str().unwrap());
        let version = input["version"].as_u64().unwrap() as u16;
        let fields = input["fields"].as_array().unwrap();

        let mut builder = Builder::new(tag, version);
        for f in fields {
            builder = match f["type"].as_str().unwrap() {
                "str" => builder.str(std::str::from_utf8(&field_bytes(f)).unwrap()),
                "bytes" => builder.bytes(&field_bytes(f)),
                "key" => builder.key(&field_bytes(f).try_into().unwrap()),
                "hash" => builder.hash(&field_bytes(f).try_into().unwrap()),
                "fixed" => builder.fixed::<4>(&field_bytes(f).try_into().unwrap()),
                "uuid" => builder.uuid(Uuid::parse_str(f["value"].as_str().unwrap()).unwrap()),
                "u8" => builder.u8(field_int(f).parse().unwrap()),
                "u16" => builder.u16(field_int(f).parse().unwrap()),
                "u32" => builder.u32(field_int(f).parse().unwrap()),
                "u64" => builder.u64(field_int(f).parse().unwrap()),
                "i64" => builder.i64(field_int(f).parse().unwrap()),
                other => panic!("[{name}] unknown field type {other}"),
            };
        }
        let message = builder.finish().unwrap();

        let expected = &vector["expected"];
        match expected["signingBytesHex"].as_str() {
            Some(h) => assert_eq!(to_hex(&message), h, "[{name}] bytes diverged"),
            None => {
                assert_eq!(
                    message.len() as u64,
                    expected["signingBytesLength"].as_u64().unwrap(),
                    "[{name}] length diverged"
                );
                assert_eq!(
                    to_hex(&Sha256::digest(&message)),
                    expected["signingBytesSha256Hex"].as_str().unwrap(),
                    "[{name}] digest diverged"
                );
            }
        }

        let mut reader = Reader::new(tag, &message).unwrap();
        assert_eq!(reader.version(), version, "[{name}]");
        for f in fields {
            match f["type"].as_str().unwrap() {
                "str" => assert_eq!(reader.str().unwrap().as_bytes(), field_bytes(f), "[{name}]"),
                "bytes" => assert_eq!(reader.bytes().unwrap(), field_bytes(f), "[{name}]"),
                "key" | "hash" => {
                    assert_eq!(reader.fixed::<32>().unwrap().to_vec(), field_bytes(f))
                }
                "fixed" => assert_eq!(reader.fixed::<4>().unwrap().to_vec(), field_bytes(f)),
                "uuid" => assert_eq!(reader.uuid().unwrap().to_string(), f["value"]),
                "u8" => assert_eq!(reader.u8().unwrap().to_string(), field_int(f)),
                "u16" => assert_eq!(reader.u16().unwrap().to_string(), field_int(f)),
                "u32" => assert_eq!(reader.u32().unwrap().to_string(), field_int(f)),
                "u64" => assert_eq!(reader.u64().unwrap().to_string(), field_int(f)),
                "i64" => assert_eq!(reader.i64().unwrap().to_string(), field_int(f)),
                other => panic!("[{name}] unknown field type {other}"),
            }
        }
        reader.finish().unwrap_or_else(|e| panic!("[{name}] {e}"));
    }
    println!(
        "structured-signing-bytes.json: {} build vectors",
        vectors.len()
    );
}

#[test]
fn structured_signing_bytes_reject_per_shared_vectors() {
    use avalon_sdk::signing_bytes::{Reader, SigningBytesError};
    let doc = load("structured-signing-bytes.json");
    let vectors = doc["rejectVectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let input = &vector["input"];
        let message = hex::decode(input["messageHex"].as_str().unwrap()).unwrap();
        let read = || -> Result<(), SigningBytesError> {
            let mut r = Reader::new(conformance_tag(input["tag"].as_str().unwrap()), &message)?;
            for ty in input["read"].as_array().unwrap() {
                match ty.as_str().unwrap() {
                    "str" => drop(r.str()?),
                    "bytes" => drop(r.bytes()?),
                    "u32" => drop(r.u32()?),
                    other => panic!("[{name}] unknown read type {other}"),
                }
            }
            r.finish()
        };
        let code = match read().unwrap_err() {
            SigningBytesError::TagMismatch => "tag_mismatch",
            SigningBytesError::Truncated => "truncated",
            SigningBytesError::InvalidUtf8 => "invalid_utf8",
            SigningBytesError::TrailingBytes => "trailing_bytes",
            SigningBytesError::FieldTooLong => "field_too_long",
        };
        assert_eq!(
            code,
            vector["expected"]["error"].as_str().unwrap(),
            "[{name}]"
        );
    }
    println!(
        "structured-signing-bytes.json: {} reject vectors",
        vectors.len()
    );
}

#[test]
fn domain_tag_registry_matches_shared_vectors() {
    let doc = load("domain-tags.json");
    let want: Vec<&str> = doc["tags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["tag"].as_str().unwrap())
        .collect();
    let have: Vec<&str> = avalon_sdk::signing_bytes::tags::ALL
        .iter()
        .map(|t| t.as_str())
        .collect();
    assert_eq!(have, want, "registry diverged from domain-tags.json");
}

#[test]
fn canonical_payload_matches_shared_vectors() {
    use avalon_sdk::canonical_payload::{canonicalize_str, CanonicalPayloadError};
    let doc = load("canonical-payload.json");
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(vectors.len() > 50, "vectors file looks truncated");
    for v in vectors {
        let name = v["name"].as_str().expect("name");
        let got = canonicalize_str(v["input"]["jsonUtf8"].as_str().expect("jsonUtf8"));
        match v["expected"]["error"].as_str() {
            None => assert_eq!(
                got.as_deref(),
                Ok(v["expected"]["canonicalUtf8"].as_str().unwrap()),
                "{name}"
            ),
            Some(code) => {
                let got_code = match got {
                    Ok(out) => panic!("{name}: expected {code}, got {out}"),
                    Err(CanonicalPayloadError::InvalidNumber { .. }) => "invalid_number",
                    Err(CanonicalPayloadError::DuplicateKey { .. }) => "duplicate_key",
                    Err(CanonicalPayloadError::Malformed(_)) => "malformed",
                    Err(CanonicalPayloadError::TooDeep) => "too_deep",
                };
                assert_eq!(got_code, code, "{name}");
            }
        }
    }
    println!("canonical-payload.json: {} vectors", vectors.len());
}

/// Builds the entry bytes and hash from a ledger vector input, the way an SDK would.
fn build_ledger_entry(
    input: &Value,
) -> Result<(Vec<u8>, [u8; 32]), avalon_sdk::ledger_entry::EntryHashError> {
    use avalon_sdk::ledger_entry::{
        entry_hash, entry_signing_bytes, parse_hash, payload_hash, EntryHashError, EntryHashInput,
    };
    let text = |k: &str| input[k].as_str().unwrap().to_string();
    let prev = parse_hash("prev_hash", &text("prevHashHex"))?;
    let payload_hash = match input["payloadHashHex"].as_str() {
        Some(h) => parse_hash("payload_hash", h)?,
        None => payload_hash(
            &avalon_sdk::canonical_payload::parse_strict(&text("payloadJsonUtf8")).unwrap(),
        )
        .unwrap(),
    };
    let seq: u64 = text("seq")
        .parse()
        .map_err(|_| EntryHashError::OutOfRange("seq"))?;
    let version = u16::try_from(input["version"].as_i64().unwrap())
        .map_err(|_| EntryHashError::OutOfRange("version"))?;
    let entry = EntryHashInput {
        network_id: &text("networkId"),
        shard_id: &text("shardId"),
        seq,
        prev_hash: &prev,
        event_id: Uuid::parse_str(&text("eventId")).unwrap(),
        kind: &text("kind"),
        issuer: &text("issuer"),
        subject: &text("subject"),
        payload_hash: &payload_hash,
        timestamp_micros: text("timestampUnixMicros").parse().unwrap(),
        version,
    };
    Ok((entry_signing_bytes(&entry)?, entry_hash(&entry)?))
}

#[test]
fn ledger_entry_hash_matches_shared_vectors() {
    use avalon_sdk::canonical_payload::{canonicalize, parse_strict};
    use avalon_sdk::ledger_entry::{floor_to_micros, payload_hash, timestamp_micros};
    use time::format_description::well_known::Rfc3339;
    let doc = load("ledger-entry-hash.json");
    let vectors = doc["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let (input, expected) = (&v["input"], &v["expected"]);
        if let Some(json) = input["payloadJsonUtf8"].as_str() {
            let value = parse_strict(json).unwrap();
            assert_eq!(
                canonicalize(&value).unwrap(),
                expected["payloadCanonicalUtf8"].as_str().unwrap(),
                "[{name}] canonical payload"
            );
            assert_eq!(
                to_hex(&payload_hash(&value).unwrap()),
                expected["payloadHashHex"].as_str().unwrap(),
                "[{name}] payload hash"
            );
        }
        let (message, hash) = build_ledger_entry(input).unwrap_or_else(|e| panic!("[{name}] {e}"));
        assert_eq!(
            to_hex(&message),
            expected["signingBytesHex"].as_str().unwrap(),
            "[{name}] bytes"
        );
        assert_eq!(
            to_hex(&hash),
            expected["entryHashHex"].as_str().unwrap(),
            "[{name}] hash"
        );
        let time =
            OffsetDateTime::parse(input["eventTimestampRfc3339"].as_str().unwrap(), &Rfc3339)
                .unwrap();
        let micros = timestamp_micros(time).unwrap();
        assert_eq!(
            micros.to_string(),
            input["timestampUnixMicros"].as_str().unwrap(),
            "[{name}] timestamp micros"
        );
        assert_eq!(
            timestamp_micros(floor_to_micros(time).unwrap()).unwrap(),
            micros,
            "[{name}] floor_to_micros"
        );
    }
    println!("ledger-entry-hash.json: {} vectors", vectors.len());
}

#[test]
fn ledger_entry_hash_rejects_per_shared_vectors() {
    use avalon_sdk::ledger_entry::EntryHashError;
    let doc = load("ledger-entry-hash.json");
    let vectors = doc["rejectVectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let got = match build_ledger_entry(&v["input"]) {
            Err(EntryHashError::InvalidHash(_)) => "invalid_hash",
            Err(EntryHashError::OutOfRange(_)) => "out_of_range",
            Err(other) => panic!("[{name}] unexpected {other}"),
            Ok(_) => panic!("[{name}] accepted"),
        };
        assert_eq!(got, v["expected"]["error"].as_str().unwrap(), "[{name}]");
    }
    println!("ledger-entry-hash.json: {} reject vectors", vectors.len());
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

/// Vector files with no runner in this SDK yet, each with the reason it is skipped.
const NO_RUNNER: &[(&str, &str)] = &[
    (
        "identity-chain.json",
        "identity chain resolution is protocol-side only",
    ),
    (
        "node-request.json",
        "node-to-node route, not in OpenAPI; supportedIn is empty",
    ),
];

/// Every vector file is either asserted above (by file name) or listed in `NO_RUNNER`, so a new
/// protocol vector cannot be synced in and silently go untested.
#[test]
fn every_vector_file_is_accounted_for() {
    let source =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/conformance.rs"))
            .expect("read this runner");
    for entry in std::fs::read_dir(vectors_dir()).expect("vectors dir") {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if !name.ends_with(".json") {
            continue;
        }
        let loaded = source.contains(&format!("load(\"{name}\")"));
        match NO_RUNNER.iter().find(|(file, _)| *file == name) {
            Some((_, reason)) => {
                assert!(!loaded, "{name} has a runner now; drop it from NO_RUNNER");
                println!("skipping {name}: {reason}");
            }
            None => assert!(
                loaded,
                "{name} has no runner and is not listed in NO_RUNNER"
            ),
        }
    }
}
