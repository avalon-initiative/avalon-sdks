use avalon_sdk::{with_trace, AvalonClient, AvalonConfig, TraceProblem};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const FIXTURE: &str = include_str!("../../../conformance/fixtures/nodes/op-trace.json");

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

fn status_body() -> Value {
    json!({"protocol_version": "0.1.0", "network_id": "n", "roles": ["combined"], "stale": false})
}

/// Answers like a tracing node, building the hops header from the request's trace id
/// with `make` (or leaving it out when `make` returns `None`).
type Make = fn(&str) -> Option<String>;
struct Node(Make);

impl Respond for Node {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let sent = req
            .headers
            .get("x-avalon-trace")
            .map(|v| v.to_str().unwrap().to_string());
        let mut r = ResponseTemplate::new(200).set_body_json(status_body());
        if let Some(header) = sent.as_deref().and_then(self.0) {
            r = r.insert_header("x-avalon-trace-hops", header.as_str());
        }
        r
    }
}

fn encode(v: &Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
}

fn valid(id: &str) -> Option<String> {
    let mut hop = json!({"index": 0, "base_url": "http://n", "roles": ["combined"],
        "protocol_version": "0.1.0", "processing_ms": 2.0, "path_type": "direct"});
    hop["extra_future_field"] = json!({"a": 1});
    Some(encode(
        &json!({"trace_id": id, "branches": [{"target": "", "outcome": "ok", "hops": [hop]}]}),
    ))
}

async fn node(f: fn(&str) -> Option<String>) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/nodes/status"))
        .respond_with(Node(f))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn traced_call_returns_result_and_hops() {
    let server = node(valid).await;
    let out = with_trace(client(server.uri()).node_status()).await;
    assert_eq!(out.value.unwrap().network_id, "n");
    assert_eq!(out.requests.len(), 1);
    let trace = out.requests[0].trace.as_ref().unwrap();
    assert_eq!(trace.trace_id, out.requests[0].trace_id);
    let hop = &trace.branches[0].hops[0];
    assert_eq!(hop.base_url, "http://n");
    assert_eq!(hop.extra["path_type"], "direct");
    assert_eq!(hop.extra["extra_future_field"], json!({"a": 1}));
    assert!(out.requests[0].problem.is_none());
}

#[tokio::test]
async fn untraced_call_sends_no_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/nodes/status"))
        .respond_with(|req: &Request| {
            assert!(req.headers.get("x-avalon-trace").is_none());
            ResponseTemplate::new(200).set_body_json(status_body())
        })
        .mount(&server)
        .await;
    client(server.uri()).node_status().await.unwrap();
}

#[tokio::test]
async fn missing_header_leaves_the_call_intact() {
    // Also the browser case: a header the platform does not expose reads as absent.
    let server = node(|_| None).await;
    let out = with_trace(client(server.uri()).node_status()).await;
    assert!(out.value.is_ok());
    assert!(out.requests[0].trace.is_none());
    assert_eq!(out.requests[0].problem, Some(TraceProblem::Missing));
}

#[tokio::test]
async fn bad_headers_never_fail_the_call() {
    let cases: [(Make, TraceProblem); 5] = [
        (|_| Some("***".into()), TraceProblem::Malformed),
        (
            |_| Some(URL_SAFE_NO_PAD.encode("not json")),
            TraceProblem::Malformed,
        ),
        (
            |_| Some(encode(&json!({"trace_id": "x"}))),
            TraceProblem::Malformed,
        ),
        (|_| Some("A".repeat(9000)), TraceProblem::Oversized),
        (
            |_| {
                Some(encode(
                    &json!({"trace_id": "6f1c2a4e-3b7d-4e0a-9c15-8d2a7b1e5f33", "branches": []}),
                ))
            },
            TraceProblem::TraceIdMismatch,
        ),
    ];
    for (make, expected) in cases {
        let server = node(make).await;
        let out = with_trace(client(server.uri()).node_status()).await;
        assert!(out.value.is_ok());
        assert_eq!(out.requests[0].problem, Some(expected));
    }
}

#[tokio::test]
async fn recorded_header_decodes_through_a_call() {
    let f: Value = serde_json::from_str(FIXTURE).unwrap();
    let header = f["header"].as_str().unwrap().to_string();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/nodes/status"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(status_body())
                .insert_header("x-avalon-trace-hops", header.as_str()),
        )
        .mount(&server)
        .await;
    // The recorded header names a fixed trace id, so a random request id mismatches;
    // the direct decoder is what checks the payload.
    let id = f["request_trace_id"].as_str().unwrap().parse().unwrap();
    let t = avalon_sdk::op_trace::decode(&header, id).unwrap();
    assert_eq!(t.branches[1].outcome, "timeout");
    let out = with_trace(client(server.uri()).node_status()).await;
    assert!(out.value.is_ok());
    assert_eq!(out.requests[0].problem, Some(TraceProblem::TraceIdMismatch));
}
