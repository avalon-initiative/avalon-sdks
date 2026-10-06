//! Client-side checks on device grant approval and signing key revocation, against a mocked server.

use avalon_sdk::identity_signing::{
    device_grant_approval_signing_bytes, signing_key_revoked_signing_bytes, verify_strict,
};
use avalon_sdk::types::ids::IdentityId;
use avalon_sdk::{AvalonClient, AvalonConfig, SdkError};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A session with `key` as its local signing key; also its identity id and the key's row id.
async fn session(
    server: &MockServer,
    key: &SigningKey,
) -> (avalon_sdk::AccountSession, IdentityId, Uuid) {
    let identity_id = IdentityId::random_for_tests();
    let key_id = Uuid::new_v4();
    let client = AvalonClient::new(AvalonConfig {
        server_url: server.uri(),
        integrator_credential_key_id: "test".to_string(),
        integrator_slug: None,
        signing_key: None,
        retry: Default::default(),
    });
    Mock::given(method("GET"))
        .and(path("/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "identity_id": identity_id,
            "identity_created_at": "2023-01-01T00:00:00Z",
            "display_name": "t",
            "favorite_genres": [],
            "links": [],
            "discoverable": false,
            "presence_visibility": "friends",
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/me/devices"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                "id": key_id,
                "public_key": BASE64.encode(key.verifying_key().to_bytes()),
                "added_at": "2023-01-01T00:00:00Z",
            }])),
        )
        .mount(server)
        .await;
    let session = client
        .resume_account_session_with_signing_key("tok", key.to_bytes())
        .await
        .expect("resume");
    (session, identity_id, key_id)
}

#[tokio::test]
async fn approve_refuses_an_unacceptable_requested_key_before_any_request() {
    let server = MockServer::start().await;
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (s, ..) = session(&server, &key).await;
    // The identity point (y = 1) is of small order.
    let mut identity_point = [0u8; 32];
    identity_point[0] = 1;
    let err = s
        .approve_device_grant(Uuid::new_v4(), &BASE64.encode(identity_point))
        .await
        .unwrap_err();
    assert!(matches!(err, SdkError::Protocol(m) if m.contains("acceptable")));
}

const HEAD_HASH: &str = "a102d9b032710b8e61fe255b559f5cbc831adb3bd7efdd37c289bc7dde6f88f5";

fn stale(head_seq: u64, head_hash: Option<&str>) -> ResponseTemplate {
    ResponseTemplate::new(409).set_body_json(json!({
        "error": "stale",
        "code": "IDENTITY_CHAIN_POSITION_STALE",
        "head_seq": head_seq,
        "head_hash": head_hash,
    }))
}

fn device_body(id: Uuid, key: &SigningKey) -> Value {
    json!({
        "id": id,
        "public_key": BASE64.encode(key.verifying_key().to_bytes()),
        "added_at": "2023-01-01T00:00:00Z",
    })
}

async fn posts_to(server: &MockServer, suffix: &str) -> Vec<Value> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.path().ends_with(suffix))
        .map(|r| r.body_json().unwrap())
        .collect()
}

fn hash32(hex_text: &str) -> [u8; 32] {
    hex::decode(hex_text).unwrap().try_into().unwrap()
}

fn signature_verifies(key: &SigningKey, message: &[u8], body: &Value) -> bool {
    let signature: [u8; 64] = BASE64
        .decode(body["signature"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    verify_strict(&key.verifying_key(), message, &signature)
}

#[tokio::test]
async fn approve_signs_at_a_new_chain_and_sends_the_position() {
    let server = MockServer::start().await;
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (s, identity_id, key_id) = session(&server, &key).await;
    let grant = Uuid::new_v4();
    let requested = SigningKey::from_bytes(&[9u8; 32]);
    Mock::given(method("POST"))
        .and(path(format!("/me/devices/grants/{grant}/approve")))
        .respond_with(ResponseTemplate::new(200).set_body_json(device_body(grant, &requested)))
        .mount(&server)
        .await;
    let requested_b64 = BASE64.encode(requested.verifying_key().to_bytes());
    let device = s.approve_device_grant(grant, &requested_b64).await.unwrap();
    assert_eq!(device.id, grant);

    let sent = posts_to(&server, "/approve").await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["seq"], 1);
    assert!(sent[0].get("prev_hash").is_none());
    assert_eq!(sent[0]["approver_signing_key_id"], key_id.to_string());
    let bytes = device_grant_approval_signing_bytes(
        grant,
        &identity_id,
        key_id,
        &requested.verifying_key().to_bytes(),
        1,
        None,
    );
    assert!(signature_verifies(&key, &bytes, &sent[0]));
}

#[tokio::test]
async fn approve_re_signs_once_at_the_head_a_stale_409_returns() {
    let server = MockServer::start().await;
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (s, identity_id, key_id) = session(&server, &key).await;
    let grant = Uuid::new_v4();
    let requested = SigningKey::from_bytes(&[9u8; 32]);
    let approve_path = format!("/me/devices/grants/{grant}/approve");
    Mock::given(method("POST"))
        .and(path(approve_path.clone()))
        .respond_with(stale(4, Some(HEAD_HASH)))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(approve_path))
        .respond_with(ResponseTemplate::new(200).set_body_json(device_body(grant, &requested)))
        .mount(&server)
        .await;
    let requested_b64 = BASE64.encode(requested.verifying_key().to_bytes());
    s.approve_device_grant(grant, &requested_b64).await.unwrap();

    let sent = posts_to(&server, "/approve").await;
    assert_eq!(sent.len(), 2);
    assert_eq!(
        (&sent[0]["seq"], sent[0].get("prev_hash")),
        (&json!(1), None)
    );
    assert_eq!(sent[1]["seq"], 5);
    assert_eq!(sent[1]["prev_hash"], HEAD_HASH);
    let bytes = device_grant_approval_signing_bytes(
        grant,
        &identity_id,
        key_id,
        &requested.verifying_key().to_bytes(),
        5,
        Some(&hash32(HEAD_HASH)),
    );
    assert!(signature_verifies(&key, &bytes, &sent[1]));
}

#[tokio::test]
async fn approve_gives_up_when_the_head_moves_again() {
    let server = MockServer::start().await;
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (s, ..) = session(&server, &key).await;
    let grant = Uuid::new_v4();
    Mock::given(method("POST"))
        .and(path(format!("/me/devices/grants/{grant}/approve")))
        .respond_with(stale(1, Some(HEAD_HASH)))
        .mount(&server)
        .await;
    let requested = BASE64.encode(
        SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes(),
    );
    let err = s.approve_device_grant(grant, &requested).await.unwrap_err();
    assert!(
        matches!(&err, SdkError::Conflict(m) if m.contains("moved again")),
        "{err:?}"
    );
    assert_eq!(posts_to(&server, "/approve").await.len(), 2);
}

#[tokio::test]
async fn revoke_signs_the_position_and_retries_once_on_stale() {
    let server = MockServer::start().await;
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (s, identity_id, key_id) = session(&server, &key).await;
    let target = Uuid::new_v4();
    let revoke_path = format!("/me/devices/{target}/revoke");
    Mock::given(method("POST"))
        .and(path(revoke_path.clone()))
        .respond_with(stale(2, Some(HEAD_HASH)))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(revoke_path))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    s.revoke_device(target).await.unwrap();

    let sent = posts_to(&server, "/revoke").await;
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1]["seq"], 3);
    assert_eq!(sent[1]["prev_hash"], HEAD_HASH);
    assert_eq!(sent[1]["revoked_by_signing_key_id"], key_id.to_string());
    let bytes = signing_key_revoked_signing_bytes(
        &identity_id,
        target,
        key_id,
        3,
        Some(&hash32(HEAD_HASH)),
    );
    assert!(signature_verifies(&key, &bytes, &sent[1]));
    let first = signing_key_revoked_signing_bytes(&identity_id, target, key_id, 1, None);
    assert!(signature_verifies(&key, &first, &sent[0]));
}

#[tokio::test]
async fn a_conflict_that_is_not_a_stale_position_is_not_retried() {
    let server = MockServer::start().await;
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (s, ..) = session(&server, &key).await;
    let target = Uuid::new_v4();
    Mock::given(method("POST"))
        .and(path(format!("/me/devices/{target}/revoke")))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "error": "last key",
            "code": "LAST_SIGNING_KEY",
        })))
        .mount(&server)
        .await;
    let err = s.revoke_device(target).await.unwrap_err();
    assert!(
        matches!(&err, SdkError::Conflict(m) if m == "LAST_SIGNING_KEY"),
        "{err:?}"
    );
    assert_eq!(posts_to(&server, "/revoke").await.len(), 1);
}
