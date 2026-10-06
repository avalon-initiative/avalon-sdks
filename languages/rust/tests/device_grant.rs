//! Client-side checks on device grant approval and signing key revocation, against a mocked server.

use avalon_sdk::types::ids::IdentityId;
use avalon_sdk::{AvalonClient, AvalonConfig, SdkError};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::SigningKey;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn session(server: &MockServer, key: &SigningKey) -> avalon_sdk::AccountSession {
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
            "identity_id": IdentityId::random_for_tests(),
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
                "id": Uuid::new_v4(),
                "public_key": BASE64.encode(key.verifying_key().to_bytes()),
                "added_at": "2023-01-01T00:00:00Z",
            }])),
        )
        .mount(server)
        .await;
    client
        .resume_account_session_with_signing_key("tok", key.to_bytes())
        .await
        .expect("resume")
}

#[tokio::test]
async fn approve_refuses_an_unacceptable_requested_key_before_any_request() {
    let server = MockServer::start().await;
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let s = session(&server, &key).await;
    // The identity point (y = 1) is of small order.
    let mut identity_point = [0u8; 32];
    identity_point[0] = 1;
    let err = s
        .approve_device_grant(Uuid::new_v4(), &BASE64.encode(identity_point))
        .await
        .unwrap_err();
    assert!(matches!(err, SdkError::Protocol(m) if m.contains("acceptable")));
}

#[tokio::test]
async fn revoke_and_approve_fail_loudly_until_v3_signing_lands() {
    let server = MockServer::start().await;
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let s = session(&server, &key).await;
    let err = s.revoke_device(Uuid::new_v4()).await.unwrap_err();
    assert!(matches!(err, SdkError::Protocol(m) if m.contains("not supported until v3")));
    let point = key.verifying_key().to_bytes();
    let err = s
        .approve_device_grant(Uuid::new_v4(), &BASE64.encode(point))
        .await
        .unwrap_err();
    assert!(matches!(err, SdkError::Protocol(m) if m.contains("not supported until v3")));
}
