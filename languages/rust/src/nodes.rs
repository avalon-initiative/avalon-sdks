//! Node status/capability reporting.

use serde::Deserialize;

use crate::{AvalonClient, SdkError};

/// `GET /nodes/status`'s wire response — matches
/// `crates/server/src/nodes.rs::NodeStatusResponse`. Only the fields this
/// SDK exposes; the real response also carries `resources` and
/// `own_shard_replication`, omitted here since nothing in this SDK reads
/// them.
#[derive(Debug, Clone, Deserialize)]
pub struct NodeStatus {
    /// This node's own build version (`crate::version::PROTOCOL_VERSION`
    /// server-side).
    pub protocol_version: String,
    /// The network this node is configured for.
    pub network_id: String,
    /// This node's configured `AVALON_NODE_ROLES` — `combined` reported
    /// as-is, not expanded.
    pub roles: Vec<String>,
    /// `true` when a known peer reports a newer `protocol_version` than
    /// this node's own.
    pub stale: bool,
    /// The newest `protocol_version` any known peer currently reports, if
    /// any.
    pub newest_known_peer_version: Option<String>,
}

impl AvalonClient {
    /// `GET /nodes/status` for this client's configured server — `roles`
    /// reports which of settlement/indexer/realtime/gateway this node
    /// runs.
    pub async fn node_status(&self) -> Result<NodeStatus, SdkError> {
        let response = crate::http::send(&self.http, &self.config.retry, true, |c| {
            c.get(format!("{}/nodes/status", self.config.server_url))
        })
        .await?;

        if !response.status().is_success() {
            return Err(crate::http::map_error_response(response).await);
        }

        response
            .json()
            .await
            .map_err(|e| SdkError::Protocol(e.to_string()))
    }
}

pub use crate::generated::{
    Coordinate, KnownPeer, MirrorSource, Neighbor, ObservedLatency, ProbeResponse as ProbeResult,
    StopReason, TopologyResponse as Topology, TraceHop, TraceResponse as TraceResult,
};

/// `POST` bodies for probe/trace, kept internal so callers pass plain arguments.
use crate::generated::{ProbeRequest, TraceRequest};

impl AvalonClient {
    /// `GET /nodes/topology` on `node_url`, or on this client's configured
    /// server when `None`. Unauthenticated and read-only; the view is what
    /// that node reports about itself and its peers.
    pub async fn topology(&self, node_url: Option<&str>) -> Result<Topology, SdkError> {
        let base = node_url
            .unwrap_or(&self.config.server_url)
            .trim_end_matches('/');
        let response = crate::http::send(&self.http, &self.config.retry, true, |c| {
            c.get(format!("{base}/nodes/topology"))
        })
        .await?;
        decode(response).await
    }

    /// `POST /nodes/probe`: this node measures its round trip to `target`,
    /// which must be in its peer table. `samples` is 1 to 3 (server default 1).
    pub async fn probe(&self, target: &str, samples: Option<u32>) -> Result<ProbeResult, SdkError> {
        let body = ProbeRequest {
            target: target.to_string(),
            samples: samples.map(|s| s as i32),
        };
        let response = crate::http::send(&self.http, &self.config.retry, false, |c| {
            c.post(format!("{}/nodes/probe", self.config.server_url))
                .json(&body)
        })
        .await?;
        decode(response).await
    }

    /// `POST /nodes/trace`: the overlay route from this node to `target`.
    /// Every hop is self-reported by the node it names, so the path is
    /// advisory and not verified. `ttl` is 1 to 16 (server default 12).
    pub async fn trace(&self, target: &str, ttl: Option<u32>) -> Result<TraceResult, SdkError> {
        let body = TraceRequest {
            target: target.to_string(),
            ttl: ttl.map(|t| t as i32),
            budget_ms: None,
            trace_id: None,
            visited: None,
        };
        let response = crate::http::send(&self.http, &self.config.retry, false, |c| {
            c.post(format!("{}/nodes/trace", self.config.server_url))
                .json(&body)
        })
        .await?;
        decode(response).await
    }
}

async fn decode<R: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<R, SdkError> {
    if !response.status().is_success() {
        return Err(crate::http::map_error_response(response).await);
    }
    response
        .json()
        .await
        .map_err(|e| SdkError::Protocol(e.to_string()))
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::AvalonConfig;

    #[tokio::test]
    async fn node_status_reports_roles() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/nodes/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "protocol_version": "0.1.0",
                "network_id": "avalon-dev-local",
                "roles": ["combined"],
                "stale": false,
                "newest_known_peer_version": "0.1.0",
            })))
            .mount(&server)
            .await;

        let client = AvalonClient::new(AvalonConfig {
            server_url: server.uri(),
            integrator_credential_key_id: "test-key".to_string(),
            integrator_slug: None,
            signing_key: None,
            retry: Default::default(),
        });

        let status = client.node_status().await.expect("request should succeed");
        assert_eq!(status.roles, vec!["combined".to_string()]);
        assert_eq!(status.protocol_version, "0.1.0");
    }
}
