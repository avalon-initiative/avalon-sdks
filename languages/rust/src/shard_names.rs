//! Shard names: domain-proven names bound to self-certifying shard ids.

pub use crate::generated::{NameClaimRequest, NameClaimResponse as NameClaim};
use crate::nodes::decode;
use crate::{AvalonClient, SdkError};

/// Percent-encodes everything but RFC 3986 unreserved characters, so user text cannot alter the path.
fn encode_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn endpoint(base: &str, template: &str, param: &str, value: &str) -> String {
    let path = crate::account::path(template, &[(param, &encode_segment(value))]);
    format!("{}{path}", base.trim_end_matches('/'))
}

impl AvalonClient {
    /// `GET /shards/name/{name}` on `node_url`, or on this client's configured server when
    /// `None`: the shard whose owner has proven control of `name`. Unauthenticated.
    pub async fn resolve_name(
        &self,
        node_url: Option<&str>,
        name: &str,
    ) -> Result<NameClaim, SdkError> {
        let url = endpoint(
            node_url.unwrap_or(&self.config.server_url),
            crate::generated::paths::shard_identity::RESOLVE_NAME,
            "name",
            name,
        );
        let response =
            crate::http::send(&self.http, &self.config.retry, true, |c| c.get(url.clone())).await?;
        decode(response).await
    }

    /// `GET /shards/{id}/name-claims`: the names bound to a self-certifying shard id.
    pub async fn list_shard_names(
        &self,
        node_url: Option<&str>,
        self_certifying_id: &str,
    ) -> Result<Vec<NameClaim>, SdkError> {
        let url = endpoint(
            node_url.unwrap_or(&self.config.server_url),
            crate::generated::paths::shard_identity::LIST_NAMES_FOR_SHARD,
            "self_certifying_id",
            self_certifying_id,
        );
        let response =
            crate::http::send(&self.http, &self.config.retry, true, |c| c.get(url.clone())).await?;
        decode(response).await
    }

    /// `POST /shards/{id}/name-claims`: submits an already-signed claim binding `claim.name` to
    /// the shard. The claim must be signed with the shard's own key; the node checks the proof.
    pub async fn submit_name_claim(
        &self,
        node_url: Option<&str>,
        claim: &NameClaimRequest,
    ) -> Result<NameClaim, SdkError> {
        let url = endpoint(
            node_url.unwrap_or(&self.config.server_url),
            crate::generated::paths::shard_identity::SUBMIT_NAME_CLAIM,
            "self_certifying_id",
            &claim.self_certifying_id,
        );
        let response = crate::http::send(&self.http, &self.config.retry, false, |c| {
            c.post(url.clone()).json(claim)
        })
        .await?;
        decode(response).await
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::AvalonConfig;

    fn claim_body() -> serde_json::Value {
        serde_json::json!({
            "name": "example.org",
            "self_certifying_id": "node:ab12",
            "proof_method": "dns-txt",
            "verified_at": "2026-09-25T00:00:00Z"
        })
    }

    fn client(server: &MockServer) -> AvalonClient {
        AvalonClient::new(AvalonConfig {
            server_url: server.uri(),
            integrator_credential_key_id: "test-key".to_string(),
            integrator_slug: None,
            signing_key: None,
            retry: Default::default(),
        })
    }

    #[tokio::test]
    async fn resolves_a_name() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/shards/name/example.org"))
            .respond_with(ResponseTemplate::new(200).set_body_json(claim_body()))
            .mount(&server)
            .await;
        let got = client(&server)
            .resolve_name(None, "example.org")
            .await
            .unwrap();
        assert_eq!(got.self_certifying_id, "node:ab12");
    }

    #[tokio::test]
    async fn lists_names_for_a_shard_encoding_the_id() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/shards/node%3Aab12/name-claims"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vec![claim_body()]))
            .mount(&server)
            .await;
        let got = client(&server)
            .list_shard_names(None, "node:ab12")
            .await
            .unwrap();
        assert_eq!(got.len(), 1);
    }

    #[tokio::test]
    async fn a_missing_name_is_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/shards/name/missing.example"))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(serde_json::json!({"code": "not_found"})),
            )
            .mount(&server)
            .await;
        let err = client(&server)
            .resolve_name(None, "missing.example")
            .await
            .unwrap_err();
        assert!(matches!(err, SdkError::NotFound(_)), "{err:?}");
    }

    #[tokio::test]
    async fn submits_a_signed_claim() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/shards/node%3Aab12/name-claims"))
            .and(body_partial_json(
                serde_json::json!({"name": "example.org"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(claim_body()))
            .mount(&server)
            .await;
        let request: NameClaimRequest = serde_json::from_value(serde_json::json!({
            "self_certifying_id": "node:ab12",
            "public_key": "aa".repeat(32),
            "name": "example.org",
            "created_at": "2026-09-25T00:00:00Z",
            "signature": "bb".repeat(64)
        }))
        .unwrap();
        let got = client(&server)
            .submit_name_claim(None, &request)
            .await
            .unwrap();
        assert_eq!(got.name, "example.org");
    }
}
