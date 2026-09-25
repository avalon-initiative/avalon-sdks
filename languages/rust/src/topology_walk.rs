//! Bounded breadth-first walk of the overlay, assembled from each node's own
//! `GET /nodes/topology` view. Read-only; limits apply even with default options.

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use futures_util::stream::{self, StreamExt};
use reqwest::StatusCode;
use tokio::sync::watch;

use crate::generated::{Coordinate, MirrorSource, ObservedLatency, SelfView};
use crate::{AvalonClient, Topology};

const CEILING_MAX_NODES: usize = 1_000;
const CEILING_MAX_DEPTH: u32 = 16;
const CEILING_CONCURRENCY: usize = 32;
const CEILING_DURATION: Duration = Duration::from_secs(120);
/// Wait applied to a 429 that carries no usable `Retry-After`.
const FALLBACK_RETRY_AFTER: Duration = Duration::from_secs(1);

/// How a reporting node relates to the node it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkEdgeKind {
    /// An active link (neighbor).
    Active,
    /// The reporter mirrors a shard from the target.
    Mirror,
    /// The reporter only knows the target from its peer table.
    Known,
}

/// Why a node could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkFailureReason {
    /// No response within the request timeout.
    Timeout,
    /// A non-success status other than 429.
    HttpStatus,
    /// 429, and no retry was possible within the wait budget or the retry also got 429.
    RateLimited,
    /// A success response whose body is not a topology view.
    ProtocolError,
    /// Connection-level failure.
    Network,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Whether a node was read.
pub enum WalkNodeStatus {
    /// Its topology view was read.
    Visited,
    /// Every attempt failed; see the node's `failure`.
    Unreachable,
    /// Discovered but not queried: a limit was reached or the walk was cancelled.
    Unvisited,
}

#[derive(Debug, Clone, PartialEq)]
/// A node that could not be read, and why.
pub struct WalkFailure {
    /// Failure class.
    pub reason: WalkFailureReason,
    /// HTTP status for `HttpStatus` and `RateLimited`.
    pub status: Option<u16>,
    /// `Retry-After` the node sent, for `RateLimited`.
    pub retry_after_seconds: Option<u64>,
    /// Human-readable detail.
    pub message: String,
}

/// One observation: `from` reported `to`. Latency and coordinate are as measured and
/// reported by `from`, not a symmetric property of the link.
#[derive(Debug, Clone)]
pub struct WalkEdge {
    /// Normalized URL of the reporting node.
    pub from: String,
    /// Normalized URL of the reported node.
    pub to: String,
    /// Relationship the reporter has to the target.
    pub kind: WalkEdgeKind,
    /// Round-trip stats measured by `from`, labeled with it as `observed_by`.
    pub latency: Option<ObservedLatency>,
    /// The target's coordinate as reported by `from`.
    pub coordinate: Option<Coordinate>,
    /// Present on `Mirror` edges: the shard mirrored from `to`.
    pub mirror: Option<MirrorSource>,
}

#[derive(Debug, Clone)]
/// One node in the graph.
pub struct WalkNode {
    /// Normalized base URL, the node's identity in the graph.
    pub url: String,
    /// Hops from the nearest seed.
    pub depth: u32,
    /// Whether the node was read, could not be, or was never queried.
    pub status: WalkNodeStatus,
    /// The node's own view of itself, when it was visited.
    pub self_view: Option<SelfView>,
    /// Set when `status` is `Unreachable`.
    pub failure: Option<WalkFailure>,
    /// Every node that reported this one, in report order.
    pub reported_by: Vec<String>,
}

/// Which limits cut the walk short.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalkTruncation {
    /// Nodes were dropped because the graph was full.
    pub max_nodes: bool,
    /// Nodes beyond the depth limit were left unvisited.
    pub max_depth: bool,
}

/// The graph assembled by a walk.
#[derive(Debug, Clone)]
pub struct TopologyGraph {
    /// Distinct normalized seed URLs.
    pub seeds: Vec<String>,
    /// Every discovered node, in discovery order.
    pub nodes: Vec<WalkNode>,
    /// Every observation; a node reported by several neighbors appears in several edges.
    pub edges: Vec<WalkEdge>,
    /// Limits that were hit.
    pub truncated: WalkTruncation,
    /// The walk stopped because it was cancelled.
    pub cancelled: bool,
}

/// Progress reported while a walk runs.
#[derive(Debug, Clone)]
pub enum WalkEvent {
    /// A node was first seen.
    Discovered(WalkNode),
    /// A node's visit finished, with the edges it reported.
    Visited {
        /// The node, now `Visited` or `Unreachable`.
        node: WalkNode,
        /// Edges reported by this node.
        edges: Vec<WalkEdge>,
    },
}

/// Receives [`WalkEvent`]s as the walk progresses.
pub type ProgressCallback = Box<dyn FnMut(&WalkEvent) + Send>;

/// Limits and hooks for [`AvalonClient::walk_topology`]. Every limit has a default and a
/// hard ceiling.
pub struct WalkOptions {
    /// Most distinct nodes kept in the graph (default 64, ceiling 1000).
    pub max_nodes: usize,
    /// Deepest hop count queried; seeds are depth 0 (default 4, ceiling 16).
    pub max_depth: u32,
    /// Simultaneous requests (default 4, ceiling 32).
    pub concurrency: usize,
    /// Timeout of each request (default 10 s).
    pub request_timeout: Duration,
    /// Longest `Retry-After` honored before one retry; a longer one is recorded as
    /// `RateLimited` (default 10 s).
    pub max_retry_after: Duration,
    /// Setting the watched value to `true` stops the walk; it returns the partial graph
    /// with `cancelled` set.
    pub cancel: Option<watch::Receiver<bool>>,
    /// Called as nodes are discovered and as each visit completes.
    pub on_progress: Option<ProgressCallback>,
}

impl Default for WalkOptions {
    fn default() -> Self {
        Self {
            max_nodes: 64,
            max_depth: 4,
            concurrency: 4,
            request_timeout: Duration::from_secs(10),
            max_retry_after: Duration::from_secs(10),
            cancel: None,
            on_progress: None,
        }
    }
}

/// Lowercased scheme and host, default port dropped, no trailing slash; `None` when not
/// an http(s) URL.
pub fn normalize_node_url(raw: &str) -> Option<String> {
    let url = url::Url::parse(raw.trim()).ok()?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return None;
    }
    let origin = url.origin().ascii_serialization();
    Some(format!("{origin}{}", url.path().trim_end_matches('/')))
}

enum Outcome {
    Reached(Box<Topology>),
    Failed(WalkFailure),
    Cancelled,
}

async fn cancelled(cancel: &Option<watch::Receiver<bool>>) {
    let Some(rx) = cancel else {
        return std::future::pending().await;
    };
    let mut rx = rx.clone();
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            return std::future::pending().await;
        }
    }
}

/// Runs `work` unless the walk is cancelled first.
async fn unless_cancelled<T>(
    cancel: &Option<watch::Receiver<bool>>,
    work: impl Future<Output = T>,
) -> Option<T> {
    tokio::select! {
        biased;
        _ = cancelled(cancel) => None,
        value = work => Some(value),
    }
}

fn failure(reason: WalkFailureReason, message: impl Into<String>) -> WalkFailure {
    WalkFailure {
        reason,
        status: None,
        retry_after_seconds: None,
        message: message.into(),
    }
}

async fn fetch(
    http: &reqwest::Client,
    url: &str,
    timeout: Duration,
) -> Result<Topology, WalkFailure> {
    let request = async {
        let response = http
            .get(format!("{url}/nodes/topology"))
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    failure(WalkFailureReason::Timeout, e.to_string())
                } else {
                    failure(WalkFailureReason::Network, e.to_string())
                }
            })?;
        let status = response.status();
        if !status.is_success() {
            let retry_after = crate::http::parse_retry_after(response.headers());
            return Err(if status == StatusCode::TOO_MANY_REQUESTS {
                WalkFailure {
                    status: Some(429),
                    retry_after_seconds: retry_after.map(|d| d.as_secs()),
                    ..failure(WalkFailureReason::RateLimited, "rate limited")
                }
            } else {
                WalkFailure {
                    status: Some(status.as_u16()),
                    ..failure(WalkFailureReason::HttpStatus, status.to_string())
                }
            });
        }
        response
            .json::<Topology>()
            .await
            .map_err(|e| failure(WalkFailureReason::ProtocolError, e.to_string()))
    };
    match tokio::time::timeout(timeout, request).await {
        Ok(result) => result,
        Err(_) => Err(failure(
            WalkFailureReason::Timeout,
            format!("no response within {} ms", timeout.as_millis()),
        )),
    }
}

/// Fetches one node's topology, retrying once after a bounded `Retry-After` wait on 429.
async fn visit(
    http: &reqwest::Client,
    url: &str,
    options: &Limits,
    cancel: &Option<watch::Receiver<bool>>,
) -> Outcome {
    let mut retried = false;
    loop {
        let Some(result) =
            unless_cancelled(cancel, fetch(http, url, options.request_timeout)).await
        else {
            return Outcome::Cancelled;
        };
        match result {
            Ok(topology) => return Outcome::Reached(Box::new(topology)),
            Err(f) if f.reason == WalkFailureReason::RateLimited && !retried => {
                let wait = f
                    .retry_after_seconds
                    .map(Duration::from_secs)
                    .unwrap_or(FALLBACK_RETRY_AFTER);
                if wait > options.max_retry_after {
                    return Outcome::Failed(f);
                }
                if unless_cancelled(cancel, tokio::time::sleep(wait))
                    .await
                    .is_none()
                {
                    return Outcome::Cancelled;
                }
                retried = true;
            }
            Err(f) => return Outcome::Failed(f),
        }
    }
}

struct Limits {
    max_nodes: usize,
    max_depth: u32,
    request_timeout: Duration,
    max_retry_after: Duration,
}

struct Walk {
    nodes: Vec<WalkNode>,
    index: HashMap<String, usize>,
    edges: Vec<WalkEdge>,
    truncated: WalkTruncation,
    max_nodes: usize,
    on_progress: Option<ProgressCallback>,
}

impl Walk {
    fn emit(&mut self, event: WalkEvent) {
        if let Some(callback) = self.on_progress.as_mut() {
            callback(&event);
        }
    }

    fn discover(&mut self, raw: &str, depth: u32, reporter: Option<&str>) -> Option<usize> {
        let url = normalize_node_url(raw)?;
        let idx = match self.index.get(&url) {
            Some(&idx) => idx,
            None => {
                if self.nodes.len() >= self.max_nodes {
                    self.truncated.max_nodes = true;
                    return None;
                }
                let idx = self.nodes.len();
                let node = WalkNode {
                    url: url.clone(),
                    depth,
                    status: WalkNodeStatus::Unvisited,
                    self_view: None,
                    failure: None,
                    reported_by: Vec::new(),
                };
                self.index.insert(url, idx);
                self.nodes.push(node.clone());
                self.emit(WalkEvent::Discovered(node));
                idx
            }
        };
        if let Some(reporter) = reporter {
            let node = &mut self.nodes[idx];
            if !node.reported_by.iter().any(|r| r == reporter) {
                node.reported_by.push(reporter.to_string());
            }
        }
        Some(idx)
    }

    fn report(
        &mut self,
        from: usize,
        target: &str,
        next: &mut Vec<usize>,
        max_depth: u32,
        edge: (
            WalkEdgeKind,
            Option<ObservedLatency>,
            Option<Coordinate>,
            Option<MirrorSource>,
        ),
        produced: &mut Vec<WalkEdge>,
    ) {
        let from_url = self.nodes[from].url.clone();
        let depth = self.nodes[from].depth + 1;
        let Some(child) = self.discover(target, depth, Some(&from_url)) else {
            return;
        };
        if child == from {
            return;
        }
        let (kind, latency, coordinate, mirror) = edge;
        let full = WalkEdge {
            from: from_url,
            to: self.nodes[child].url.clone(),
            kind,
            latency,
            coordinate,
            mirror,
        };
        produced.push(full.clone());
        self.edges.push(full);
        let node = &self.nodes[child];
        if node.status == WalkNodeStatus::Unvisited && node.depth == depth && !next.contains(&child)
        {
            if depth > max_depth {
                self.truncated.max_depth = true;
            } else {
                next.push(child);
            }
        }
    }

    fn apply(&mut self, idx: usize, topology: Topology, next: &mut Vec<usize>, max_depth: u32) {
        let url = self.nodes[idx].url.clone();
        self.nodes[idx].status = WalkNodeStatus::Visited;
        self.nodes[idx].self_view = Some(topology.self_.clone());
        let mut produced = Vec::new();
        for n in &topology.neighbors {
            let latency = n.latency.clone().map(|mut l| {
                l.observed_by = Some(url.clone());
                l
            });
            self.report(
                idx,
                &n.base_url,
                next,
                max_depth,
                (WalkEdgeKind::Active, latency, n.coordinate.clone(), None),
                &mut produced,
            );
        }
        for m in &topology.mirrors {
            self.report(
                idx,
                &m.source_url,
                next,
                max_depth,
                (WalkEdgeKind::Mirror, None, None, Some(m.clone())),
                &mut produced,
            );
        }
        for k in &topology.known {
            self.report(
                idx,
                &k.base_url,
                next,
                max_depth,
                (WalkEdgeKind::Known, None, None, None),
                &mut produced,
            );
        }
        let node = self.nodes[idx].clone();
        self.emit(WalkEvent::Visited {
            node,
            edges: produced,
        });
    }
}

impl AvalonClient {
    /// Walks the overlay outward from `seeds`, breadth-first, by asking each node for its own
    /// `GET /nodes/topology` view. No node holds the whole graph, so the result is the union of
    /// what the reachable nodes report. Read-only and always bounded. An unreachable node is
    /// recorded with a reason and never stops the walk; a 429 is retried once after its
    /// `Retry-After` when that wait is within `max_retry_after`.
    pub async fn walk_topology(&self, seeds: &[&str], options: WalkOptions) -> TopologyGraph {
        let limits = Limits {
            max_nodes: options.max_nodes.clamp(1, CEILING_MAX_NODES),
            max_depth: options.max_depth.min(CEILING_MAX_DEPTH),
            request_timeout: options
                .request_timeout
                .clamp(Duration::from_millis(1), CEILING_DURATION),
            max_retry_after: options.max_retry_after.min(CEILING_DURATION),
        };
        let concurrency = options.concurrency.clamp(1, CEILING_CONCURRENCY);
        let cancel = options.cancel;
        let mut walk = Walk {
            nodes: Vec::new(),
            index: HashMap::new(),
            edges: Vec::new(),
            truncated: WalkTruncation::default(),
            max_nodes: limits.max_nodes,
            on_progress: options.on_progress,
        };

        let mut seed_urls: Vec<String> = Vec::new();
        let mut level: Vec<usize> = Vec::new();
        for seed in seeds {
            if let Some(idx) = walk.discover(seed, 0, None) {
                if !seed_urls.contains(&walk.nodes[idx].url) {
                    seed_urls.push(walk.nodes[idx].url.clone());
                }
                if !level.contains(&idx) {
                    level.push(idx);
                }
            } else if normalize_node_url(seed).is_none() {
                let raw = seed.trim().to_string();
                if !walk.index.contains_key(&raw) && walk.nodes.len() < limits.max_nodes {
                    let node = WalkNode {
                        url: raw.clone(),
                        depth: 0,
                        status: WalkNodeStatus::Unreachable,
                        self_view: None,
                        failure: Some(failure(
                            WalkFailureReason::ProtocolError,
                            "not an http(s) URL",
                        )),
                        reported_by: Vec::new(),
                    };
                    walk.index.insert(raw.clone(), walk.nodes.len());
                    walk.nodes.push(node.clone());
                    seed_urls.push(raw);
                    walk.emit(WalkEvent::Discovered(node.clone()));
                    walk.emit(WalkEvent::Visited {
                        node,
                        edges: Vec::new(),
                    });
                }
            }
        }

        let mut was_cancelled = false;
        while !level.is_empty() && !was_cancelled {
            let jobs: Vec<(usize, String)> = level
                .iter()
                .filter(|&&i| {
                    walk.nodes[i].status == WalkNodeStatus::Unvisited
                        && walk.nodes[i].depth <= limits.max_depth
                })
                .map(|&i| (i, walk.nodes[i].url.clone()))
                .collect();
            let mut next: Vec<usize> = Vec::new();
            let http = &self.http;
            let limits_ref = &limits;
            let cancel_ref = &cancel;
            let mut results =
                stream::iter(jobs)
                    .map(|(idx, url)| async move {
                        (idx, visit(http, &url, limits_ref, cancel_ref).await)
                    })
                    .buffer_unordered(concurrency);
            while let Some((idx, outcome)) = results.next().await {
                match outcome {
                    Outcome::Cancelled => was_cancelled = true,
                    Outcome::Failed(f) => {
                        walk.nodes[idx].status = WalkNodeStatus::Unreachable;
                        walk.nodes[idx].failure = Some(f);
                        let node = walk.nodes[idx].clone();
                        walk.emit(WalkEvent::Visited {
                            node,
                            edges: Vec::new(),
                        });
                    }
                    Outcome::Reached(topology) => {
                        walk.apply(idx, *topology, &mut next, limits.max_depth)
                    }
                }
            }
            level = next;
        }

        let cancelled_now = was_cancelled || cancel.as_ref().is_some_and(|rx| *rx.borrow());
        TopologyGraph {
            seeds: seed_urls,
            nodes: walk.nodes,
            edges: walk.edges,
            truncated: walk.truncated,
            cancelled: cancelled_now,
        }
    }
}
