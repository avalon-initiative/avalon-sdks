use std::sync::{Arc, Mutex};
use std::time::Duration;

use avalon_sdk::{
    normalize_node_url, AvalonClient, AvalonConfig, WalkEdgeKind, WalkEvent, WalkFailureReason,
    WalkNodeStatus, WalkOptions,
};
use serde_json::{json, Value};
use tokio::sync::watch;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOPOLOGY: &str = include_str!("../../../conformance/fixtures/nodes/topology.json");

fn client() -> AvalonClient {
    AvalonClient::new(AvalonConfig {
        server_url: "http://127.0.0.1:1".to_string(),
        integrator_credential_key_id: "test-key".to_string(),
        integrator_slug: None,
        signing_key: None,
        retry: Default::default(),
    })
}

#[derive(Default, Clone)]
struct Links {
    neighbors: Vec<(String, f64)>,
    known: Vec<String>,
    mirrors: Vec<String>,
}

fn body(url: &str, links: &Links) -> Value {
    let fixture: Value = serde_json::from_str(TOPOLOGY).unwrap();
    let latency = fixture["neighbors"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|n| n.get("latency").filter(|l| !l.is_null()).cloned())
        .unwrap();
    let mut value = fixture.clone();
    value["self"]["base_url"] = json!(url);
    value["neighbors"] = links
        .neighbors
        .iter()
        .map(|(target, ms)| {
            let mut l = latency.clone();
            l["last_ms"] = json!(ms);
            json!({"base_url": target, "bootstrap": false, "roles": [], "last_announced_at": null, "latency": l})
        })
        .collect();
    value["known"] = links
        .known
        .iter()
        .map(|k| json!({"base_url": k, "last_announced_at": "2026-01-01T00:00:00Z", "protocol_version": "0.1.0", "roles": []}))
        .collect();
    let mirror = fixture["mirrors"][0].clone();
    value["mirrors"] = links
        .mirrors
        .iter()
        .map(|m| {
            let mut v = mirror.clone();
            v["source_url"] = json!(m);
            v
        })
        .collect();
    value
}

async fn node() -> MockServer {
    MockServer::start().await
}

async fn serve(server: &MockServer, links: &Links) {
    Mock::given(method("GET"))
        .and(path("/nodes/topology"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body(&server.uri(), links)))
        .mount(server)
        .await;
}

fn links(neighbors: &[&MockServer]) -> Links {
    Links {
        neighbors: neighbors.iter().map(|s| (s.uri(), 2.0)).collect(),
        ..Default::default()
    }
}

fn status_of(graph: &avalon_sdk::TopologyGraph, url: &str) -> WalkNodeStatus {
    graph.nodes.iter().find(|n| n.url == url).unwrap().status
}

async fn requests(server: &MockServer) -> usize {
    server.received_requests().await.unwrap().len()
}

#[tokio::test]
async fn walks_a_connected_graph_with_typed_edges_and_per_reporter_latency() {
    let (a, b, c) = (node().await, node().await, node().await);
    serve(
        &a,
        &Links {
            neighbors: vec![(b.uri(), 3.0)],
            known: vec![c.uri()],
            mirrors: vec![b.uri()],
        },
    )
    .await;
    serve(
        &b,
        &Links {
            neighbors: vec![(a.uri(), 4.0), (c.uri(), 5.0)],
            ..Default::default()
        },
    )
    .await;
    serve(&c, &Links::default()).await;

    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    let graph = client()
        .walk_topology(
            &[&a.uri()],
            WalkOptions {
                on_progress: Some(Box::new(move |e| sink.lock().unwrap().push(e.clone()))),
                ..Default::default()
            },
        )
        .await;

    assert_eq!(
        graph
            .nodes
            .iter()
            .map(|n| (n.url.clone(), n.depth))
            .collect::<Vec<_>>(),
        vec![(a.uri(), 0), (b.uri(), 1), (c.uri(), 1)]
    );
    assert!(graph
        .nodes
        .iter()
        .all(|n| n.status == WalkNodeStatus::Visited));
    assert!(!graph.cancelled);
    assert!(!graph.truncated.max_nodes && !graph.truncated.max_depth);
    assert_eq!(graph.edges.len(), 5);
    let ab = graph
        .edges
        .iter()
        .find(|e| e.from == a.uri() && e.to == b.uri() && e.kind == WalkEdgeKind::Active)
        .unwrap();
    let ba = graph
        .edges
        .iter()
        .find(|e| e.from == b.uri() && e.to == a.uri())
        .unwrap();
    assert_eq!(
        ab.latency.as_ref().unwrap().observed_by.as_deref(),
        Some(a.uri().as_str())
    );
    assert_eq!(ab.latency.as_ref().unwrap().last_ms, Some(3.0));
    assert_eq!(
        ba.latency.as_ref().unwrap().observed_by.as_deref(),
        Some(b.uri().as_str())
    );
    assert_eq!(ba.latency.as_ref().unwrap().last_ms, Some(4.0));
    assert!(graph
        .edges
        .iter()
        .any(|e| e.kind == WalkEdgeKind::Mirror && e.mirror.is_some() && e.to == b.uri()));
    assert!(graph
        .edges
        .iter()
        .any(|e| e.kind == WalkEdgeKind::Known && e.to == c.uri()));
    let mut reporters = graph.nodes[2].reported_by.clone();
    reporters.sort();
    let mut expected = vec![a.uri(), b.uri()];
    expected.sort();
    assert_eq!(reporters, expected);
    let events = events.lock().unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, WalkEvent::Discovered(_)))
            .count(),
        3
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, WalkEvent::Visited { .. }))
            .count(),
        3
    );
}

#[tokio::test]
async fn a_partitioned_graph_yields_the_reachable_component_and_seeds_cover_both() {
    let (a, b, c, d) = (node().await, node().await, node().await, node().await);
    serve(&a, &links(&[&b])).await;
    serve(&b, &Links::default()).await;
    serve(&c, &links(&[&d])).await;
    serve(&d, &Links::default()).await;

    let single = client()
        .walk_topology(&[&a.uri()], WalkOptions::default())
        .await;
    assert_eq!(single.nodes.len(), 2);
    let both = client()
        .walk_topology(&[&a.uri(), &c.uri()], WalkOptions::default())
        .await;
    assert_eq!(both.nodes.len(), 4);
    assert_eq!(both.seeds, vec![a.uri(), c.uri()]);
}

#[tokio::test]
async fn an_unreachable_node_is_recorded_and_the_walk_continues() {
    let (a, c) = (node().await, node().await);
    let dead = "http://127.0.0.1:1".to_string();
    serve(
        &a,
        &Links {
            neighbors: vec![(dead.clone(), 1.0), (c.uri(), 1.0)],
            ..Default::default()
        },
    )
    .await;
    serve(&c, &Links::default()).await;
    let graph = client()
        .walk_topology(&[&a.uri()], WalkOptions::default())
        .await;
    let failed = graph.nodes.iter().find(|n| n.url == dead).unwrap();
    assert_eq!(failed.status, WalkNodeStatus::Unreachable);
    assert_eq!(
        failed.failure.as_ref().unwrap().reason,
        WalkFailureReason::Network
    );
    assert_eq!(status_of(&graph, &c.uri()), WalkNodeStatus::Visited);
}

#[tokio::test]
async fn classifies_http_status_and_malformed_bodies() {
    let (a, b, c) = (node().await, node().await, node().await);
    serve(&a, &links(&[&b, &c])).await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500).set_body_string("{\"error\":\"boom\"}"))
        .mount(&b)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&c)
        .await;
    let graph = client()
        .walk_topology(&[&a.uri()], WalkOptions::default())
        .await;
    let failure = |url: String| {
        graph
            .nodes
            .iter()
            .find(|n| n.url == url)
            .unwrap()
            .failure
            .clone()
            .unwrap()
    };
    assert_eq!(failure(b.uri()).reason, WalkFailureReason::HttpStatus);
    assert_eq!(failure(b.uri()).status, Some(500));
    assert_eq!(failure(c.uri()).reason, WalkFailureReason::ProtocolError);
}

#[tokio::test]
async fn a_node_that_times_out_is_recorded_without_stopping_the_walk() {
    let (a, b, c) = (node().await, node().await, node().await);
    serve(&a, &links(&[&b, &c])).await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&b)
        .await;
    serve(&c, &Links::default()).await;
    let graph = client()
        .walk_topology(
            &[&a.uri()],
            WalkOptions {
                request_timeout: Duration::from_millis(100),
                ..Default::default()
            },
        )
        .await;
    let failed = graph.nodes.iter().find(|n| n.url == b.uri()).unwrap();
    assert_eq!(
        failed.failure.as_ref().unwrap().reason,
        WalkFailureReason::Timeout
    );
    assert_eq!(status_of(&graph, &c.uri()), WalkNodeStatus::Visited);
    assert!(!graph.cancelled);
}

#[tokio::test]
async fn honors_retry_after_once_and_then_succeeds() {
    let (a, b) = (node().await, node().await);
    serve(&a, &links(&[&b])).await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
        .up_to_n_times(1)
        .mount(&b)
        .await;
    serve(&b, &Links::default()).await;
    let graph = client()
        .walk_topology(&[&a.uri()], WalkOptions::default())
        .await;
    assert_eq!(requests(&b).await, 2);
    assert_eq!(status_of(&graph, &b.uri()), WalkNodeStatus::Visited);
}

#[tokio::test]
async fn records_rate_limited_when_the_wait_exceeds_the_budget_or_a_second_429_follows() {
    let (a, b, c) = (node().await, node().await, node().await);
    serve(&a, &links(&[&b, &c])).await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "3600"))
        .mount(&b)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
        .mount(&c)
        .await;
    let graph = client()
        .walk_topology(&[&a.uri()], WalkOptions::default())
        .await;
    assert_eq!(requests(&b).await, 1);
    let f = graph
        .nodes
        .iter()
        .find(|n| n.url == b.uri())
        .unwrap()
        .failure
        .clone()
        .unwrap();
    assert_eq!(f.reason, WalkFailureReason::RateLimited);
    assert_eq!(f.status, Some(429));
    assert_eq!(f.retry_after_seconds, Some(3600));
    assert_eq!(requests(&c).await, 2);
    let f = graph
        .nodes
        .iter()
        .find(|n| n.url == c.uri())
        .unwrap()
        .failure
        .clone()
        .unwrap();
    assert_eq!(f.reason, WalkFailureReason::RateLimited);
}

#[tokio::test]
async fn stops_at_max_nodes() {
    let (a, b, c, d) = (node().await, node().await, node().await, node().await);
    serve(&a, &links(&[&b, &c, &d])).await;
    for s in [&b, &c, &d] {
        serve(s, &Links::default()).await;
    }
    let graph = client()
        .walk_topology(
            &[&a.uri()],
            WalkOptions {
                max_nodes: 2,
                concurrency: 1,
                ..Default::default()
            },
        )
        .await;
    assert_eq!(graph.nodes.len(), 2);
    assert!(graph.truncated.max_nodes);
    assert!(graph
        .edges
        .iter()
        .all(|e| e.to != c.uri() && e.to != d.uri()));
}

#[tokio::test]
async fn stops_at_max_depth_and_leaves_deeper_nodes_unvisited() {
    let (a, b, c, d) = (node().await, node().await, node().await, node().await);
    serve(&a, &links(&[&b])).await;
    serve(&b, &links(&[&c])).await;
    serve(&c, &links(&[&d])).await;
    serve(&d, &Links::default()).await;
    let graph = client()
        .walk_topology(
            &[&a.uri()],
            WalkOptions {
                max_depth: 1,
                ..Default::default()
            },
        )
        .await;
    assert_eq!(requests(&c).await, 0);
    assert_eq!(graph.nodes.len(), 3);
    assert_eq!(status_of(&graph, &c.uri()), WalkNodeStatus::Unvisited);
    assert!(graph.truncated.max_depth);
}

#[tokio::test]
async fn dedupes_url_variants_of_the_same_node() {
    let (a, b) = (node().await, node().await);
    let a_variant = format!("{}/", a.uri().replace("http://", "HTTP://"));
    let b_variant = format!("{}//", b.uri());
    serve(
        &a,
        &Links {
            neighbors: vec![(b_variant.clone(), 1.0), (b.uri(), 1.0)],
            known: vec![b_variant],
            ..Default::default()
        },
    )
    .await;
    serve(
        &b,
        &Links {
            neighbors: vec![(a_variant.clone(), 1.0)],
            ..Default::default()
        },
    )
    .await;
    let graph = client()
        .walk_topology(
            &[&format!("{}/", a.uri()), &a_variant],
            WalkOptions::default(),
        )
        .await;
    assert_eq!(graph.nodes.len(), 2);
    assert_eq!(graph.seeds, vec![a.uri()]);
    assert_eq!(requests(&a).await, 1);
    assert_eq!(requests(&b).await, 1);
    assert_eq!(graph.nodes[1].reported_by, vec![a.uri()]);
}

#[tokio::test]
async fn cancellation_returns_the_partial_graph() {
    let (a, b, c) = (node().await, node().await, node().await);
    serve(&a, &links(&[&b, &c])).await;
    for s in [&b, &c] {
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(s)
            .await;
    }
    let (tx, rx) = watch::channel(false);
    let a_url = a.uri();
    let graph = client()
        .walk_topology(
            &[&a.uri()],
            WalkOptions {
                cancel: Some(rx),
                on_progress: Some(Box::new(move |e| {
                    if let WalkEvent::Visited { node, .. } = e {
                        if node.url == a_url {
                            let _ = tx.send(true);
                        }
                    }
                })),
                ..Default::default()
            },
        )
        .await;
    assert!(graph.cancelled);
    assert_eq!(status_of(&graph, &a.uri()), WalkNodeStatus::Visited);
    assert_eq!(status_of(&graph, &b.uri()), WalkNodeStatus::Unvisited);
}

#[tokio::test]
async fn an_already_cancelled_walk_makes_no_request() {
    let a = node().await;
    serve(&a, &Links::default()).await;
    let (_tx, rx) = watch::channel(true);
    let graph = client()
        .walk_topology(
            &[&a.uri()],
            WalkOptions {
                cancel: Some(rx),
                ..Default::default()
            },
        )
        .await;
    assert!(graph.cancelled);
    assert_eq!(requests(&a).await, 0);
}

#[tokio::test]
async fn default_limits_bound_an_unbounded_chain() {
    // Every node reports three fresh hosts, so only the default limits end the walk.
    let a = node().await;
    let mut chain: Vec<String> = Vec::new();
    for i in 0..200 {
        chain.push(format!("http://n{i}.invalid"));
    }
    serve(
        &a,
        &Links {
            neighbors: chain.iter().map(|u| (u.clone(), 1.0)).collect(),
            ..Default::default()
        },
    )
    .await;
    let graph = client()
        .walk_topology(
            &[&a.uri()],
            WalkOptions {
                request_timeout: Duration::from_millis(200),
                ..Default::default()
            },
        )
        .await;
    assert_eq!(graph.nodes.len(), 64);
    assert!(graph.truncated.max_nodes);
}

#[test]
fn normalizes_urls() {
    assert_eq!(
        normalize_node_url("HTTP://A.Test:8080/").as_deref(),
        Some("http://a.test:8080")
    );
    assert_eq!(
        normalize_node_url("http://a.test:80//").as_deref(),
        Some("http://a.test")
    );
    assert_eq!(normalize_node_url("ftp://a.test"), None);
    assert_eq!(normalize_node_url("nonsense"), None);
}
