//! `AvalonClient::fetch_shard_family` against a mock node, with the response checked by the
//! family helpers. Heads and proofs come from the shared conformance vectors.

use avalon_sdk::{AvalonClient, AvalonConfig};
use serde_json::{json, Value};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const VECTORS: &str = include_str!("../../../conformance/vectors/shard-family-head.json");

fn client(url: String) -> AvalonClient {
    AvalonClient::new(AvalonConfig {
        server_url: url,
        integrator_credential_key_id: "test-key".to_string(),
        integrator_slug: None,
        signing_key: None,
        retry: avalon_sdk::RetryConfig {
            max_retries: 0,
            ..Default::default()
        },
    })
}

/// The server's JSON for the vector named `name`, with a proof for `member` when given.
fn body(name: &str, member: Option<&str>) -> (Value, String) {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    let fam = doc["familyVectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap();
    let owner = fam["input"]["owner"].as_str().unwrap().to_string();
    let members: Vec<Value> = fam["expected"]["memberShardIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| {
            let h = fam["input"]["heads"]
                .as_array()
                .unwrap()
                .iter()
                .find(|h| h["shardId"] == *id)
                .unwrap();
            json!({
                "shard_id": h["shardId"], "tree_size": h["treeSize"],
                "root_hash": h["rootHashHex"], "signing_key_id": h["signingKeyId"],
                "signature": h["signatureHex"], "created_at": "2023-11-14T22:13:20Z",
            })
        })
        .collect();
    let mut out = json!({
        "owner": owner, "root_hash": fam["expected"]["rootHashHex"],
        "shard_count": members.len(), "partial": false, "missing_shard_ids": [],
        "members": members,
    });
    if let Some(m) = member {
        let proof = doc["proofVectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| {
                v["input"]["owner"] == owner.as_str()
                    && v["input"]["shardId"] == m
                    && v["input"]["rootHashHex"] == fam["expected"]["rootHashHex"]
                    && v["expected"]["verified"] == true
            })
            .unwrap();
        out["proof"] = json!({
            "shard_id": m, "leaf_index": proof["input"]["proof"]["leafIndex"],
            "tree_size": proof["input"]["proof"]["treeSize"],
            "path": proof["input"]["proof"]["pathHex"],
        });
    }
    (out, owner)
}

#[tokio::test]
async fn fetched_family_recomputes_and_verifies_its_proof() {
    let (body, owner) = body("two members", Some("game:x/2"));
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ledger/shard-family"))
        .and(query_param("owner", owner.as_str()))
        .and(query_param("member", "game:x/2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .expect(1)
        .mount(&server)
        .await;
    let family = client(server.uri())
        .fetch_shard_family(&owner, Some("game:x/2"))
        .await
        .unwrap();
    assert_eq!(family.shard_count, 2);
    assert!(family.root_matches());
    assert!(family.proof_verifies());
}

#[tokio::test]
async fn fetched_family_without_a_member_has_no_proof_and_detects_tampering() {
    let (mut body, owner) = body("two members", None);
    body["members"][0]["signature"] = json!("00");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ledger/shard-family"))
        .and(query_param("owner", owner.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .mount(&server)
        .await;
    let family = client(server.uri())
        .fetch_shard_family(&owner, None)
        .await
        .unwrap();
    assert!(family.proof.is_none());
    assert!(!family.proof_verifies());
    assert!(!family.root_matches());
}

#[tokio::test]
async fn an_unknown_member_is_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ledger/shard-family"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"error": "no", "code": "x"})))
        .mount(&server)
        .await;
    let err = client(server.uri())
        .fetch_shard_family("game:x", Some("game:x/9"))
        .await
        .unwrap_err();
    assert!(matches!(err, avalon_sdk::SdkError::NotFound(_)), "{err:?}");
}
