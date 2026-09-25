//! `AccountSession` rollback surface against a mocked server, plus one
//! opt-in live test (`--ignored`) against a real `avalon-server`.

use avalon_sdk::{AccountSession, AvalonClient, AvalonConfig, SdkError};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature, SigningKey, Verifier};
use time::OffsetDateTime;
use uuid::Uuid;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client(url: String) -> AvalonClient {
    AvalonClient::new(AvalonConfig {
        server_url: url,
        integrator_credential_key_id: "test".to_string(),
        integrator_slug: None,
        signing_key: None,
        retry: Default::default(),
    })
}

fn since() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
}

const SINCE_STR: &str = "2023-11-14T22:13:20Z";

async fn session(server: &MockServer, key: &SigningKey, key_id: Uuid) -> (AccountSession, Uuid) {
    let identity_id = Uuid::new_v4();
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
    let s = client(server.uri())
        .resume_account_session_with_signing_key("tok", key.to_bytes())
        .await
        .expect("resume");
    (s, identity_id)
}

#[tokio::test]
async fn candidates_decode() {
    let server = MockServer::start().await;
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (s, _) = session(&server, &key, Uuid::new_v4()).await;
    let ev = Uuid::new_v4();
    let rr = Uuid::new_v4();
    Mock::given(method("GET"))
        .and(path("/me/rollback/candidates"))
        .and(query_param("since", SINCE_STR))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "recovery_request_id": rr,
            "recovery_completed_at": "2023-11-15T00:00:00Z",
            "candidates": [
                {"event_id": ev, "kind": "guild.created", "occurred_at": "2023-11-14T23:00:00Z",
                 "summary": "made a guild", "reversible": true, "reason": null, "already_reversed": false},
                {"event_id": Uuid::new_v4(), "kind": "x", "occurred_at": "2023-11-14T23:00:00Z",
                 "summary": "s", "reversible": false, "reason": "no inverse", "already_reversed": true},
            ],
        })))
        .mount(&server)
        .await;
    let out = s.rollback_candidates(since()).await.unwrap();
    assert_eq!(out.recovery_request_id, rr);
    assert_eq!(out.candidates.len(), 2);
    assert_eq!(out.candidates[0].event_id, ev);
    assert!(out.candidates[0].reversible && out.candidates[0].reason.is_none());
    assert_eq!(out.candidates[1].reason.as_deref(), Some("no inverse"));
    assert!(out.candidates[1].already_reversed);
}

#[tokio::test]
async fn reverse_sends_signed_body() {
    let server = MockServer::start().await;
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let key_id = Uuid::new_v4();
    let (s, identity_id) = session(&server, &key, key_id).await;
    let ev = Uuid::new_v4();
    let rev = Uuid::new_v4();
    Mock::given(method("POST"))
        .and(path(format!("/me/rollback/{ev}/reverse")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"reversal_event_id": rev})),
        )
        .mount(&server)
        .await;
    assert_eq!(s.reverse_rollback_event(ev, since()).await.unwrap(), rev);

    let reqs = server.received_requests().await.unwrap();
    let req = reqs.iter().find(|r| r.method.as_str() == "POST").unwrap();
    let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(body["since"], SINCE_STR);
    assert_eq!(body["signing_key_id"], key_id.to_string());
    let sig_bytes = BASE64.decode(body["signature"].as_str().unwrap()).unwrap();
    let sig = Signature::from_slice(&sig_bytes).unwrap();
    let msg = format!("avalon:rollback.reverse:v1:{ev}:{identity_id}:{SINCE_STR}");
    key.verifying_key().verify(msg.as_bytes(), &sig).unwrap();
}

#[tokio::test]
async fn error_codes_map_to_status_buckets() {
    let server = MockServer::start().await;
    let key = SigningKey::from_bytes(&[3u8; 32]);
    let (s, _) = session(&server, &key, Uuid::new_v4()).await;
    let cases = [
        (409, "ROLLBACK_NO_COMPLETED_RECOVERY"),
        (400, "INVALID_ROLLBACK_WINDOW"),
        (404, "ROLLBACK_EVENT_NOT_ELIGIBLE"),
        (409, "ROLLBACK_NOT_REVERSIBLE"),
        (409, "ROLLBACK_ALREADY_REVERSED"),
    ];
    for (status, code) in cases {
        server.reset().await;
        // reset() drops the session mocks; only the endpoint under test is needed now.
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_json(serde_json::json!({"error": "m", "code": code})),
            )
            .mount(&server)
            .await;
        let err = s
            .reverse_rollback_event(Uuid::new_v4(), since())
            .await
            .unwrap_err();
        match (status, err) {
            (409, SdkError::Conflict(c)) | (404, SdkError::NotFound(c)) => assert_eq!(c, code),
            (400, SdkError::Rejected { reason }) => assert_eq!(reason, code),
            (_, other) => panic!("{code}: unexpected {other:?}"),
        }
    }
}

fn live_url() -> String {
    std::env::var("AVALON_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string())
}

#[tokio::test]
#[ignore]
async fn live_candidates_without_recovery_is_no_completed_recovery() {
    let session = client(live_url())
        .register(&format!("sdk-rollback-{}", Uuid::new_v4()))
        .await
        .expect("register");
    let err = session
        .rollback_candidates(OffsetDateTime::now_utc() - time::Duration::hours(1))
        .await
        .unwrap_err();
    match err {
        SdkError::Conflict(code) => assert_eq!(code, "ROLLBACK_NO_COMPLETED_RECOVERY"),
        other => panic!("unexpected {other:?}"),
    }
}
