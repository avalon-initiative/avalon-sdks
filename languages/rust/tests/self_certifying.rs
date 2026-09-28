//! `AvalonClient::fetch_shard_tree_head` against a mock node, verified with the
//! self-certifying check. Head and key come from the shared conformance vectors.

use avalon_sdk::self_certifying::SelfCertifyingFailure;
use avalon_sdk::{AvalonClient, AvalonConfig};
use serde_json::{json, Value};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const VECTORS: &str = include_str!("../../../conformance/vectors/self-certifying-tree-head.json");

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

/// The first vector: a valid head, its shard id and key, as the server's JSON body.
fn valid_case() -> (String, Value, String) {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    let input = &doc["vectors"][0]["input"];
    let head = &input["head"];
    let body = json!({
        "tree_size": head["treeSize"],
        "root_hash": head["rootHashHex"],
        "network_id": head["networkId"],
        "signing_key_id": head["signingKeyId"],
        "signature": head["signatureHex"],
        "created_at": head["createdAtRfc3339"],
        "protocol_version": "0.1",
    });
    (
        input["shardId"].as_str().unwrap().to_string(),
        body,
        input["signingPublicKeyHex"].as_str().unwrap().to_string(),
    )
}

fn json_response(body: &Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(body)
}

#[tokio::test]
async fn fetched_latest_head_verifies_with_the_served_key() {
    let (shard_id, mut body, key) = valid_case();
    body["signing_public_key"] = json!(key);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ledger/sth/latest"))
        .and(query_param("shard_id", shard_id.as_str()))
        .respond_with(json_response(&body))
        .expect(1)
        .mount(&server)
        .await;
    let head = client(server.uri())
        .fetch_shard_tree_head(&shard_id, None)
        .await
        .unwrap();
    assert_eq!(head.signing_public_key.as_deref(), Some(key.as_str()));
    assert_eq!(head.verify(&shard_id), Ok(()));
}

#[tokio::test]
async fn fetched_head_by_size_without_a_key_reports_a_missing_key() {
    let (shard_id, body, _) = valid_case();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ledger/sth/12"))
        .and(query_param("shard_id", shard_id.as_str()))
        .respond_with(json_response(&body))
        .expect(1)
        .mount(&server)
        .await;
    let head = client(server.uri())
        .fetch_shard_tree_head(&shard_id, Some(12))
        .await
        .unwrap();
    assert_eq!(head.signing_public_key, None);
    assert_eq!(
        head.verify(&shard_id),
        Err(SelfCertifyingFailure::MissingKey)
    );
}

#[tokio::test]
async fn fetched_head_with_a_tampered_field_fails_the_signature_check() {
    let (shard_id, mut body, key) = valid_case();
    body["signing_public_key"] = json!(key);
    body["tree_size"] = json!(13);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ledger/sth/latest"))
        .respond_with(json_response(&body))
        .mount(&server)
        .await;
    let head = client(server.uri())
        .fetch_shard_tree_head(&shard_id, None)
        .await
        .unwrap();
    assert_eq!(
        head.verify(&shard_id),
        Err(SelfCertifyingFailure::BadSignature)
    );
}
