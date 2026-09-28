//! Opt-in path tracing for real SDK calls.
//!
//! Inside [`with_trace`], every request the SDK sends through its shared request
//! path carries `X-Avalon-Trace` and the decoded `X-Avalon-Trace-Hops` answer is
//! returned next to the call's result. Hops are self-reported by the nodes on the
//! path and are advisory. A missing, oversized or malformed header never fails the call.

use std::future::Future;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::generated::TraceHop;

pub(crate) const TRACE_HEADER: &str = "x-avalon-trace";
const HOPS_HEADER: &str = "x-avalon-trace-hops";
const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_BRANCHES: usize = 8;
const MAX_HOPS_PER_BRANCH: usize = 8;

/// One node on a traced path: the same fields `trace()` returns, plus any field a
/// newer node adds (for example a path type), kept in `extra`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathHop {
    /// The fields `trace()` returns for a hop.
    #[serde(flatten)]
    pub hop: TraceHop,
    /// Fields this SDK version does not model, unchanged.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl std::ops::Deref for PathHop {
    type Target = TraceHop;
    fn deref(&self) -> &TraceHop {
        &self.hop
    }
}

/// One path from the originating node to a node that handled the request.
/// `outcome` is `"ok"`, `"timeout"` or `"unreachable"`; unknown values pass through.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceBranch {
    /// Base URL the originating node sent to; empty for the node's own record.
    #[serde(default)]
    pub target: String,
    /// How the branch ended.
    #[serde(default = "ok_outcome")]
    pub outcome: String,
    /// Nodes in the order traveled.
    pub hops: Vec<PathHop>,
}

fn ok_outcome() -> String {
    "ok".to_string()
}

/// The decoded `X-Avalon-Trace-Hops` value. A fan-out reports one branch per target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationTrace {
    /// The id the request carried.
    pub trace_id: Uuid,
    /// One path per target.
    pub branches: Vec<TraceBranch>,
    /// Set when the node dropped branches or hops to stay within its size caps.
    #[serde(default)]
    pub truncated: bool,
}

/// Why a request has no decoded path. Non-fatal: the call itself is unaffected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceProblem {
    /// No hops header: the node did not trace the request, or the header is not
    /// readable (a browser without CORS exposure).
    Missing,
    /// The header exceeds the size cap.
    Oversized,
    /// The header is not valid unpadded base64url JSON of the expected shape.
    Malformed,
    /// The header names a different trace id than the request sent.
    TraceIdMismatch,
}

/// The traced path of one HTTP request made inside [`with_trace`].
#[derive(Debug, Clone)]
pub struct RequestTrace {
    /// The id sent in `X-Avalon-Trace`.
    pub trace_id: Uuid,
    /// The decoded path, when the response carried a valid one.
    pub trace: Option<OperationTrace>,
    /// Why `trace` is absent.
    pub problem: Option<TraceProblem>,
}

/// A call's result and the traced path of each request it made, in order.
#[derive(Debug, Clone)]
pub struct Traced<T> {
    /// What the wrapped future returned.
    pub value: T,
    /// One entry per request sent while tracing was on.
    pub requests: Vec<RequestTrace>,
}

tokio::task_local! {
    static SCOPE: Arc<Mutex<Vec<RequestTrace>>>;
}

/// Runs `fut` with tracing on. Only requests made on the same task are traced, so a
/// call that spawns its own tasks is not.
pub async fn with_trace<F: Future>(fut: F) -> Traced<F::Output> {
    let scope = Arc::new(Mutex::new(Vec::new()));
    let value = SCOPE.scope(scope.clone(), fut).await;
    let requests = std::mem::take(&mut *scope.lock().unwrap_or_else(|e| e.into_inner()));
    Traced { value, requests }
}

/// The trace id to send for a new request when a scope is active.
pub(crate) fn begin() -> Option<Uuid> {
    SCOPE.try_with(|_| Uuid::new_v4()).ok()
}

/// Records the decoded outcome of a response to the request sent with `id`.
pub(crate) fn record(id: Uuid, headers: &HeaderMap) {
    let (trace, problem) = match decode_header(headers, id) {
        Ok(t) => (Some(t), None),
        Err(p) => (None, Some(p)),
    };
    let entry = RequestTrace {
        trace_id: id,
        trace,
        problem,
    };
    let _ = SCOPE.try_with(|scope| {
        let mut all = scope.lock().unwrap_or_else(|e| e.into_inner());
        match all.iter_mut().find(|r| r.trace_id == id) {
            Some(existing) => *existing = entry,
            None => all.push(entry),
        }
    });
}

fn decode_header(headers: &HeaderMap, expected: Uuid) -> Result<OperationTrace, TraceProblem> {
    let value = headers.get(HOPS_HEADER).ok_or(TraceProblem::Missing)?;
    let text = value.to_str().map_err(|_| TraceProblem::Malformed)?;
    decode(text, expected)
}

/// Decodes an `X-Avalon-Trace-Hops` value for the request sent with `expected`.
pub fn decode(value: &str, expected: Uuid) -> Result<OperationTrace, TraceProblem> {
    if value.len() > MAX_HEADER_BYTES {
        return Err(TraceProblem::Oversized);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value.trim())
        .map_err(|_| TraceProblem::Malformed)?;
    let mut trace: OperationTrace =
        serde_json::from_slice(&bytes).map_err(|_| TraceProblem::Malformed)?;
    if trace.trace_id != expected {
        return Err(TraceProblem::TraceIdMismatch);
    }
    if trace.branches.len() > MAX_BRANCHES {
        trace.branches.truncate(MAX_BRANCHES);
        trace.truncated = true;
    }
    for branch in &mut trace.branches {
        if branch.hops.len() > MAX_HOPS_PER_BRANCH {
            branch.hops.truncate(MAX_HOPS_PER_BRANCH);
            trace.truncated = true;
        }
    }
    Ok(trace)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../../conformance/fixtures/nodes/op-trace.json");

    fn b64(v: &Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
    }

    fn hop(i: u32) -> Value {
        serde_json::json!({"index": i, "base_url": "http://n", "roles": ["combined"],
            "protocol_version": "0.1.0", "processing_ms": 1.5})
    }

    #[test]
    fn recorded_fixture_decodes() {
        let f: Value = serde_json::from_str(FIXTURE).unwrap();
        let id: Uuid = f["request_trace_id"].as_str().unwrap().parse().unwrap();
        let t = decode(f["header"].as_str().unwrap(), id).unwrap();
        assert_eq!(t.branches.len(), 2);
        assert_eq!(t.branches[0].hops.len(), 2);
        assert_eq!(t.branches[0].hops[1].base_url, "http://192.168.7.183:8080");
        assert!((t.branches[0].hops[0].to_next_ms.unwrap() - 234.655411).abs() < 1e-6);
        assert_eq!(t.branches[1].outcome, "timeout");
        assert!(!t.truncated);
    }

    #[test]
    fn unknown_hop_and_trace_fields_pass_through() {
        let id = Uuid::new_v4();
        let mut h = hop(0);
        h["path_type"] = "relayed".into();
        let v = serde_json::json!({"trace_id": id, "branches": [{"hops": [h]}], "future": 1});
        let t = decode(&b64(&v), id).unwrap();
        assert_eq!(t.branches[0].hops[0].extra["path_type"], "relayed");
        assert_eq!(t.branches[0].outcome, "ok");
        assert_eq!(t.branches[0].hops[0].processing_ms, 1.5);
    }

    #[test]
    fn malformed_inputs_are_classified() {
        let id = Uuid::new_v4();
        assert_eq!(
            decode("!!not base64!!", id).unwrap_err(),
            TraceProblem::Malformed
        );
        assert_eq!(
            decode(&URL_SAFE_NO_PAD.encode("nope"), id).unwrap_err(),
            TraceProblem::Malformed
        );
        let wrong = serde_json::json!({"trace_id": id, "branches": "x"});
        assert_eq!(
            decode(&b64(&wrong), id).unwrap_err(),
            TraceProblem::Malformed
        );
        let other = serde_json::json!({"trace_id": Uuid::new_v4(), "branches": []});
        assert_eq!(
            decode(&b64(&other), id).unwrap_err(),
            TraceProblem::TraceIdMismatch
        );
        assert_eq!(
            decode(&"a".repeat(MAX_HEADER_BYTES + 1), id).unwrap_err(),
            TraceProblem::Oversized
        );
    }

    #[test]
    fn excess_branches_and_hops_are_capped() {
        let id = Uuid::new_v4();
        let hops: Vec<Value> = (0..12).map(hop).collect();
        let v = serde_json::json!({"trace_id": id, "branches": [{"hops": hops}]});
        let t = decode(&b64(&v), id).unwrap();
        assert_eq!(t.branches[0].hops.len(), MAX_HOPS_PER_BRANCH);
        assert!(t.truncated);
        let branches: Vec<Value> = (0..10)
            .map(|_| serde_json::json!({"hops": [hop(0)]}))
            .collect();
        let v = serde_json::json!({"trace_id": id, "branches": branches});
        let t = decode(&b64(&v), id).unwrap();
        assert_eq!(t.branches.len(), MAX_BRANCHES);
        assert!(t.truncated);
    }
}
