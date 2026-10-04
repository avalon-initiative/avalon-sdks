//! Session list, revoke and logout against a mocked server.

use avalon_sdk::types::ids::IdentityId;
use avalon_sdk::{AccountSession, AvalonClient, AvalonConfig, SdkError};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::SigningKey;
use uuid::Uuid;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn session(server: &MockServer) -> AccountSession {
    let key = SigningKey::from_bytes(&[7u8; 32]);
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
    AvalonClient::new(AvalonConfig {
        server_url: server.uri(),
        integrator_credential_key_id: "test".to_string(),
        integrator_slug: None,
        signing_key: None,
        retry: Default::default(),
    })
    .resume_account_session_with_signing_key("tok", key.to_bytes())
    .await
    .expect("resume")
}

#[tokio::test]
async fn list_sessions_decodes_and_marks_the_current_one() {
    let server = MockServer::start().await;
    let s = session(&server).await;
    let (a, b, passkey, key) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    Mock::given(method("GET"))
        .and(path("/me/sessions"))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sessions": [
                {"id": a, "created_at": "2026-10-02T00:00:00Z", "expires_at": "2026-11-01T00:00:00Z",
                 "current": true, "origin_passkey_id": passkey, "origin_signing_key_id": null},
                {"id": b, "created_at": "2026-10-01T00:00:00Z", "expires_at": "2026-10-31T00:00:00Z",
                 "current": false, "origin_signing_key_id": key},
            ]
        })))
        .mount(&server)
        .await;
    let out = s.list_sessions().await.unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].id, a);
    assert!(out[0].current);
    assert_eq!(out[0].origin_passkey_id, Some(passkey));
    assert_eq!(out[0].origin_signing_key_id, None);
    assert_eq!(out[0].created_at.unix_timestamp(), 1_790_899_200);
    assert!(!out[1].current);
    assert_eq!(out[1].origin_passkey_id, None);
    assert_eq!(out[1].origin_signing_key_id, Some(key));
}

#[tokio::test]
async fn revoke_session_posts_to_the_session_and_maps_not_found() {
    let server = MockServer::start().await;
    let s = session(&server).await;
    let id = Uuid::new_v4();
    Mock::given(method("POST"))
        .and(path(format!("/me/sessions/{id}/revoke")))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    s.revoke_session(id).await.unwrap();

    let missing = Uuid::new_v4();
    Mock::given(method("POST"))
        .and(path(format!("/me/sessions/{missing}/revoke")))
        .respond_with(ResponseTemplate::new(404).set_body_json(
            serde_json::json!({"error": "session not found", "code": "SESSION_NOT_FOUND"}),
        ))
        .mount(&server)
        .await;
    let err = s.revoke_session(missing).await.unwrap_err();
    assert!(matches!(err, SdkError::NotFound(_)), "{err:?}");
}

#[tokio::test]
async fn logout_posts_with_the_session_token() {
    let server = MockServer::start().await;
    let s = session(&server).await;
    Mock::given(method("POST"))
        .and(path("/sessions/logout"))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    s.logout().await.unwrap();
}
