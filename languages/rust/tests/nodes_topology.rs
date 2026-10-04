use std::time::Duration;

use avalon_sdk::nodes::{Connectivity, PathType};
use avalon_sdk::{AvalonClient, AvalonConfig, SdkError, StopReason};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOPOLOGY: &str = include_str!("../../../conformance/fixtures/nodes/topology.json");
const PROBE: &str = include_str!("../../../conformance/fixtures/nodes/probe.json");
const TRACE: &str = include_str!("../../../conformance/fixtures/nodes/trace.json");

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

fn json(body: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("content-type", "application/json")
        .set_body_string(body)
}

#[tokio::test]
async fn topology_decodes_recorded_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/nodes/topology"))
        .respond_with(json(TOPOLOGY))
        .mount(&server)
        .await;
    let topology = client(server.uri()).topology(None).await.unwrap();
    assert_eq!(topology.self_.network_id, "avalon-dev-local");
    assert!(!topology.neighbors.is_empty());
    assert!(topology
        .neighbors
        .iter()
        .any(|n| n.latency.is_some() && n.coordinate.is_some()));
    assert_eq!(topology.self_.coordinate.vector.len(), 3);
    assert_eq!(topology.mirrors.len(), 1);
}

#[tokio::test]
async fn topology_targets_an_explicit_node_url() {
    let configured = MockServer::start().await;
    let other = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/nodes/topology"))
        .respond_with(json(TOPOLOGY))
        .expect(1)
        .mount(&other)
        .await;
    let topology = client(configured.uri())
        .topology(Some(&other.uri()))
        .await
        .unwrap();
    assert!(!topology.neighbors.is_empty());
}

#[tokio::test]
async fn probe_decodes_recorded_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/nodes/probe"))
        .and(body_json(
            serde_json::json!({"target": "http://n:1", "samples": 3}),
        ))
        .respond_with(json(PROBE))
        .mount(&server)
        .await;
    let result = client(server.uri())
        .probe("http://n:1", Some(3))
        .await
        .unwrap();
    assert!(result.ok);
    assert_eq!(result.samples_ms.len(), 3);
    assert!(result.median_ms.is_some());
}

#[tokio::test]
async fn trace_decodes_recorded_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/nodes/trace"))
        .and(body_json(
            serde_json::json!({"target": "http://n:1", "ttl": 4}),
        ))
        .respond_with(json(TRACE))
        .mount(&server)
        .await;
    let result = client(server.uri())
        .trace("http://n:1", Some(4))
        .await
        .unwrap();
    assert!(result.reached);
    assert_eq!(result.hops.len(), 2);
    assert_eq!(result.hops[0].index, 0);
    assert!(result.hops[0].to_next_ms.is_some());
    assert!(result.hops[1].to_next_ms.is_none());
    assert!(result.stopped_reason.is_none());
}

#[tokio::test]
async fn trace_decodes_stop_reason() {
    let server = MockServer::start().await;
    let body = serde_json::json!({
        "trace_id": "05bb8d86-a667-45e6-a95c-743b160e7b2b", "target": "http://n:1",
        "reached": false, "total_ms": 1.0, "hops": [], "stopped_reason": "no_route", "detail": "x"
    });
    Mock::given(method("POST"))
        .and(path("/nodes/trace"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    let result = client(server.uri())
        .trace("http://n:1", None)
        .await
        .unwrap();
    assert!(matches!(result.stopped_reason, Some(StopReason::NoRoute)));
}

#[tokio::test]
async fn rate_limited_responses_carry_retry_after() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/nodes/topology"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "7"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/nodes/probe"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "3"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/nodes/trace"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&server)
        .await;
    let c = client(server.uri());

    let err = c.topology(None).await.unwrap_err();
    assert!(matches!(err, SdkError::RateLimited { .. }));
    assert_eq!(err.retry_after(), Some(Duration::from_secs(7)));
    assert_eq!(
        c.probe("http://n:1", None).await.unwrap_err().retry_after(),
        Some(Duration::from_secs(3))
    );
    let err = c.trace("http://n:1", None).await.unwrap_err();
    assert!(matches!(err, SdkError::RateLimited { retry_after: None }));
}

#[tokio::test]
async fn malformed_bodies_surface_as_protocol_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/nodes/topology"))
        .respond_with(json("{\"neighbors\": 5}"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/nodes/probe"))
        .respond_with(json("not json"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/nodes/trace"))
        .respond_with(json("{}"))
        .mount(&server)
        .await;
    let c = client(server.uri());
    assert!(matches!(c.topology(None).await, Err(SdkError::Protocol(_))));
    assert!(matches!(
        c.probe("http://n:1", None).await,
        Err(SdkError::Protocol(_))
    ));
    assert!(matches!(
        c.trace("http://n:1", None).await,
        Err(SdkError::Protocol(_))
    ));
}

#[tokio::test]
async fn topology_tolerates_unknown_connectivity_and_path_values() {
    let mut body: serde_json::Value = serde_json::from_str(TOPOLOGY).unwrap();
    let neighbor = body["neighbors"][0].clone();
    let with = |connectivity: &str, path: &str| {
        let mut n = neighbor.clone();
        n["connectivity"] = connectivity.into();
        n["latency"]["path"] = path.into();
        n
    };
    body["neighbors"] = serde_json::json!([
        with("nat_traversed", "traversed"),
        with("outbound_only", "relayed"),
        with("made_up_value", "made_up_path"),
    ]);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/nodes/topology"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    let topology = client(server.uri()).topology(None).await.unwrap();
    let connectivity: Vec<_> = topology
        .neighbors
        .iter()
        .map(|n| n.connectivity.clone().unwrap())
        .collect();
    assert_eq!(
        connectivity,
        [
            Connectivity::NatTraversed,
            Connectivity::OutboundOnly,
            Connectivity::Unknown("made_up_value".to_string())
        ]
    );
    let paths: Vec<_> = topology
        .neighbors
        .iter()
        .map(|n| n.latency.clone().unwrap().path)
        .collect();
    assert_eq!(
        paths,
        [
            PathType::Traversed,
            PathType::Relayed,
            PathType::Unknown("made_up_path".to_string())
        ]
    );
}

#[tokio::test]
async fn probe_and_trace_decode_new_path_fields_and_tolerate_unknown_values() {
    let server = MockServer::start().await;
    let mut probe: serde_json::Value = serde_json::from_str(PROBE).unwrap();
    probe["path"] = "traversed".into();
    let mut trace: serde_json::Value = serde_json::from_str(TRACE).unwrap();
    trace["hops"][0]["path_to_next"] = "made_up_path".into();
    Mock::given(method("POST"))
        .and(path("/nodes/probe"))
        .respond_with(ResponseTemplate::new(200).set_body_json(probe))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/nodes/trace"))
        .respond_with(ResponseTemplate::new(200).set_body_json(trace))
        .mount(&server)
        .await;
    let client = client(server.uri());
    let probed = client.probe("http://n:1", None).await.unwrap();
    assert_eq!(probed.path, Some(PathType::Traversed));
    let traced = client.trace("http://n:1", None).await.unwrap();
    assert_eq!(
        traced.hops[0].path_to_next,
        Some(PathType::Unknown("made_up_path".to_string()))
    );
    assert_eq!(traced.hops[1].path_to_next, None);
}
