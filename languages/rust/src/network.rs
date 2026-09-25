//! STH-based network trust verification — issue #482, porting the model
//! `apps/hub/src/network/verifyNetwork.ts`/`trustAnchors.ts` already
//! implement for the Hub to the Rust SDK. See
//! `docs/architecture/network-trust-anchors.md` for the full model:
//! `network_id` alone is never sufficient to trust a server, since it's a
//! plain string with zero cryptographic authority — only a Signed Tree
//! Head (`GET /ledger/sth/latest`) that verifies against the claimed
//! network's pinned `verify_key` actually establishes which network a
//! server is.
//!
//! `docs/trusted-networks.json` in `avalon-protocol` is the single canonical
//! trust-anchor list, fetched at runtime from [`TRUST_ANCHORS_URL`] — no copy
//! the same non-duplication invariant `apps/hub/src/network/trustAnchors.ts`
//! keeps via its own build-time mirror).

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

use crate::{AvalonClient, AvalonConfig, SdkError};

/// Which deployment tier a [`TrustAnchorEntry`] pins, matching
/// `docs/trusted-networks.json`'s `environment` field and
/// `docs/architecture/network-trust-anchors.md`'s tier descriptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkEnvironment {
    /// No real deployment — a freely-generated key checked in only to
    /// exercise the trust-anchor mechanism end to end.
    LocalDev,
    /// A real, non-production, single-node deployment.
    Dev,
    /// A real, non-production, 1-5 node interconnected test bed used to
    /// verify changes actually integrate across nodes before mainnet.
    Int,
    /// A real mainnet deployment.
    Prod,
}

/// One entry of `docs/trusted-networks.json`, mirroring
/// `apps/hub/src/network/trustAnchors.ts::TrustAnchorEntry` field-for-field.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TrustAnchorEntry {
    /// Human-readable name for the network.
    pub label: String,
    /// The exact string a server sets `AVALON_NETWORK_ID` to.
    pub network_id: String,
    /// Lowercase hex-encoded Ed25519 public key — the settlement
    /// operator's STH verify key for this network (`crates/chain/src/sth.rs`).
    pub verify_key: String,
    /// Which key generation this is, matching `SignedTreeHead::signing_key_id`.
    pub signing_key_id: String,
    /// The server URL this network is reachable at, if published.
    #[serde(default)]
    pub server_url: Option<String>,
    /// Which deployment tier this is.
    pub environment: NetworkEnvironment,
    /// Issue #362: base URLs of this network's always-on anchor node(s) —
    /// the default bootstrap peers a node configured for this `network_id`
    /// announces to when it has no `AVALON_BOOTSTRAP_PEERS` of its own set.
    /// Reuses this file rather than a second committed list, since an
    /// anchor node is exactly the "always-on node(s) each real deployment
    /// already plans to run" this file's own entries already describe —
    /// same governance story (a normal reviewed PR adds/rotates one, never
    /// a live-writable directory). Empty for a network with no anchor yet,
    /// or for the network's own anchor entry itself (nothing to seed from).
    #[serde(default)]
    pub seed_nodes: Vec<String>,
    /// Free-text notes.
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TrustedNetworksFile {
    networks: Vec<TrustAnchorEntry>,
}

/// Where the canonical trust-anchor list is published.
pub const TRUST_ANCHORS_URL: &str =
    "https://raw.githubusercontent.com/avalon-initiative/avalon-protocol/main/docs/trusted-networks.json";

/// Fetches and parses the published trust-anchor list from `url`.
pub async fn fetch_trust_anchors(
    http: &reqwest::Client,
    url: &str,
) -> Result<Vec<TrustAnchorEntry>, reqwest::Error> {
    let file: TrustedNetworksFile = http
        .get(url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(file.networks)
}

/// `GET /ledger/sth/latest`'s wire shape — mirrors
/// `crates/server/src/settlement.rs::SignedTreeHeadResponse` field-for-field.
#[derive(Debug, Clone, Deserialize)]
struct SignedTreeHeadWire {
    tree_size: i64,
    root_hash: String,
    network_id: String,
    signing_key_id: String,
    signature: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: time::OffsetDateTime,
}

impl From<SignedTreeHeadWire> for crate::sth::SignedTreeHead {
    fn from(wire: SignedTreeHeadWire) -> Self {
        Self {
            tree_size: wire.tree_size,
            root_hash: wire.root_hash,
            network_id: wire.network_id,
            signing_key_id: wire.signing_key_id,
            signature: wire.signature,
            created_at: wire.created_at,
        }
    }
}

/// The invariant this module exists for: `network_id` alone is never
/// sufficient. Given a fetched Signed Tree Head and every network this
/// build has a pinned key for, exactly one of these four states applies —
/// a caller must never treat anything but `Verified` as "connected to the
/// real network." Mirrors `apps/hub/src/network/verifyNetwork.ts`'s
/// `NetworkTrustStatus`, plus `Unreachable` for the fetch-failure case the
/// Hub's `useNetworkTrust` composable handles separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkTrustStatus {
    /// The claimed `network_id` is pinned and the STH signature checks
    /// out — this really is the network it says it is.
    Verified {
        /// The pinned trust-anchor entry the server's STH verified against.
        entry: TrustAnchorEntry,
    },
    /// The claimed `network_id` is pinned, but the signature does NOT
    /// verify against the pinned key — the impostor case this exists to
    /// catch. Never silently downgraded to `UnknownNetwork`.
    Mismatch {
        /// The pinned entry for the claimed network — its key rejected
        /// the server's actual STH signature.
        entry: TrustAnchorEntry,
        /// The `network_id` the server's STH claimed.
        claimed_network_id: String,
    },
    /// The claimed `network_id` isn't in the published trust-anchor list at
    /// all.
    UnknownNetwork {
        /// The `network_id` the server's STH claimed.
        claimed_network_id: String,
    },
    /// Fetching or parsing the server's latest Signed Tree Head itself
    /// failed.
    Unreachable {
        /// A human-readable description of what went wrong.
        detail: String,
    },
}

/// Verifies `verify_key_hex` (lowercase hex, 32 bytes) against `sth`'s
/// signature — `false` for any malformed input (bad hex, wrong-length key)
/// as well as an outright-invalid signature, never panics. The exact
/// Rust-side counterpart to `apps/hub/src/network/verifyNetwork.ts::verifyTreeHead`.
fn verify_tree_head_hex(verify_key_hex: &str, sth: &crate::sth::SignedTreeHead) -> bool {
    let Ok(key_bytes) = hex::decode(verify_key_hex) else {
        return false;
    };
    let Ok(key_array) = <[u8; 32]>::try_from(key_bytes.as_slice()) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&key_array) else {
        return false;
    };
    crate::sth::verify_tree_head(&verifying_key, sth)
}

/// Decides which of [`NetworkTrustStatus`]'s first three states applies to
/// `sth` against `anchors`. Split out from [`AvalonClient::verify_network`]
/// so the pure decision logic (unlike the network fetch around it) is
/// directly unit-testable.
fn evaluate_network_trust(
    anchors: &[TrustAnchorEntry],
    sth: crate::sth::SignedTreeHead,
) -> NetworkTrustStatus {
    let Some(entry) = anchors
        .iter()
        .find(|candidate| candidate.network_id == sth.network_id)
    else {
        return NetworkTrustStatus::UnknownNetwork {
            claimed_network_id: sth.network_id,
        };
    };
    if !verify_tree_head_hex(&entry.verify_key, &sth) {
        return NetworkTrustStatus::Mismatch {
            entry: entry.clone(),
            claimed_network_id: sth.network_id,
        };
    }
    NetworkTrustStatus::Verified {
        entry: entry.clone(),
    }
}

/// One of the three real deployment tiers a caller can declare intent for
/// without spelling out an exact `network_id` (issue #483) — resolved
/// against whichever pinned entry the server's STH actually verified
/// against, never guessed from the server URL alone. Deliberately only
/// three variants: `LocalDev` (the milestone-1 placeholder network with no
/// real deployment behind it — see [`NetworkEnvironment::LocalDev`]) isn't
/// one of them, so a caller targeting it declares its exact `network_id`
/// via [`TargetNetwork::NetworkId`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetNetworkTier {
    /// A real, non-production, single-node deployment.
    Dev,
    /// A real, non-production, 1-5 node interconnected test bed.
    Int,
    /// The real mainnet deployment.
    Mainnet,
}

impl TargetNetworkTier {
    fn matches(self, environment: NetworkEnvironment) -> bool {
        matches!(
            (self, environment),
            (TargetNetworkTier::Dev, NetworkEnvironment::Dev)
                | (TargetNetworkTier::Int, NetworkEnvironment::Int)
                | (TargetNetworkTier::Mainnet, NetworkEnvironment::Prod)
        )
    }
}

impl std::fmt::Display for TargetNetworkTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            TargetNetworkTier::Dev => "dev",
            TargetNetworkTier::Int => "int",
            TargetNetworkTier::Mainnet => "mainnet",
        };
        f.write_str(label)
    }
}

/// The network a caller must explicitly declare intent for before a write
/// that's gated by network identity (issue #483, per #479/#480's ADR) —
/// registering an issuer, most immediately. No implicit default is ever
/// inferred from the server URL alone; see [`check_target_network`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetNetwork {
    /// The exact `network_id` string the caller expects the server to be.
    NetworkId(String),
    /// A deployment-tier shorthand, resolved against the verified entry's
    /// [`NetworkEnvironment`] rather than a literal string.
    Env(TargetNetworkTier),
}

impl std::fmt::Display for TargetNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetNetwork::NetworkId(network_id) => f.write_str(network_id),
            TargetNetwork::Env(tier) => write!(f, "{tier} (declared by tier)"),
        }
    }
}

/// Why a declared [`TargetNetwork`] failed [`check_target_network`] — never
/// a silent proceed, per #483's own invariant.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetworkTargetError {
    /// The server's network was independently verified, but it isn't the
    /// one the caller declared intent for.
    #[error(
        "declared target network {declared} does not match the server's verified network {actual}"
    )]
    Mismatch {
        /// What the caller declared.
        declared: String,
        /// The `network_id` the server actually, verifiably is.
        actual: String,
    },
    /// The server's claimed network couldn't be independently verified at
    /// all (unknown, key mismatch, or unreachable) — refused regardless of
    /// what was declared, since there's nothing to compare it against.
    #[error("server's network could not be independently verified: {reason}")]
    Unverified {
        /// A human-readable description of why verification didn't succeed.
        reason: String,
    },
}

/// The check #483 exists for: a declared [`TargetNetwork`] only ever
/// proceeds against a server whose [`NetworkTrustStatus`] is `Verified`
/// *and* whose verified entry matches what was declared — belt-and-
/// suspenders on top of, not instead of, the server-side
/// `declared_network_id` check (#481). Returns the matching
/// [`TrustAnchorEntry`] on success so a caller can read back the exact
/// `network_id` it just confirmed it's talking to.
pub fn check_target_network<'a>(
    status: &'a NetworkTrustStatus,
    target: &TargetNetwork,
) -> Result<&'a TrustAnchorEntry, NetworkTargetError> {
    let entry = match status {
        NetworkTrustStatus::Verified { entry } => entry,
        NetworkTrustStatus::Mismatch {
            claimed_network_id, ..
        } => {
            return Err(NetworkTargetError::Unverified {
                reason: format!(
                "the server's STH does not verify against the pinned key for {claimed_network_id}"
            ),
            })
        }
        NetworkTrustStatus::UnknownNetwork { claimed_network_id } => {
            return Err(NetworkTargetError::Unverified {
                reason: format!("{claimed_network_id} is not a pinned/known network"),
            })
        }
        NetworkTrustStatus::Unreachable { detail } => {
            return Err(NetworkTargetError::Unverified {
                reason: detail.clone(),
            })
        }
    };
    let matches = match target {
        TargetNetwork::NetworkId(expected) => &entry.network_id == expected,
        TargetNetwork::Env(tier) => tier.matches(entry.environment),
    };
    if matches {
        Ok(entry)
    } else {
        Err(NetworkTargetError::Mismatch {
            declared: target.to_string(),
            actual: entry.network_id.clone(),
        })
    }
}

/// Fetches `GET /ledger/sth/latest` from `server_url` and evaluates it
/// against the published trust-anchor list — the shared fetch-then-evaluate path
/// behind both [`AvalonClient::verify_network`] (a known server) and
/// [`discover`] (candidate servers with no known-good one yet).
async fn fetch_network_trust_status(
    anchors: &[TrustAnchorEntry],
    http: &reqwest::Client,
    retry: &crate::RetryConfig,
    server_url: &str,
) -> NetworkTrustStatus {
    let response = match crate::http::send(http, retry, true, |c| {
        c.get(format!("{server_url}/ledger/sth/latest"))
    })
    .await
    {
        Ok(response) => response,
        Err(err) => {
            return NetworkTrustStatus::Unreachable {
                detail: err.to_string(),
            }
        }
    };
    if !response.status().is_success() {
        let err: SdkError = crate::http::map_error_response(response).await;
        return NetworkTrustStatus::Unreachable {
            detail: err.to_string(),
        };
    }
    let wire: SignedTreeHeadWire = match response.json().await {
        Ok(wire) => wire,
        Err(err) => {
            return NetworkTrustStatus::Unreachable {
                detail: err.to_string(),
            }
        }
    };
    evaluate_network_trust(anchors, wire.into())
}

impl AvalonClient {
    /// Fetches `GET /ledger/sth/latest` from this client's configured
    /// server and verifies it against the published trust-anchor list — the
    /// check an integrator should run before registering an issuer or
    /// submitting any write (#479/#480), so a call never lands on a
    /// server merely claiming to be the network it targets.
    ///
    /// Never returns an `Err`: an unreachable/unparseable server is itself
    /// [`NetworkTrustStatus::Unreachable`], since "is this the real
    /// network" is a question with an answer even when that answer is "no
    /// signal at all."
    pub async fn verify_network(&self) -> NetworkTrustStatus {
        self.verify_network_with(TRUST_ANCHORS_URL).await
    }

    async fn verify_network_with(&self, anchors_url: &str) -> NetworkTrustStatus {
        let anchors = match fetch_trust_anchors(&self.http, anchors_url).await {
            Ok(anchors) => anchors,
            Err(err) => {
                return NetworkTrustStatus::Unreachable {
                    detail: format!("trust-anchor list unavailable: {err}"),
                }
            }
        };
        fetch_network_trust_status(
            &anchors,
            &self.http,
            &self.config.retry,
            &self.config.server_url,
        )
        .await
    }
}

/// Everything [`AvalonClient::connect`] needs besides the server URL
/// itself, since discovery is what supplies that field.
pub struct DiscoveryConfig {
    /// This integrator's own registered credential key id — see
    /// [`crate::AvalonConfig::integrator_credential_key_id`].
    pub integrator_credential_key_id: String,
    /// See [`crate::AvalonConfig::integrator_slug`].
    pub integrator_slug: Option<String>,
    /// See [`crate::AvalonConfig::signing_key`].
    pub signing_key: Option<[u8; 32]>,
    /// See [`crate::AvalonConfig::retry`].
    pub retry: crate::RetryConfig,
}

/// Why [`discover`]/[`AvalonClient::connect`] couldn't resolve `target` to
/// a live, verified server.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DiscoveryError {
    /// No published trust anchor matches `target` at all, so there was
    /// nothing to even attempt a connection to.
    #[error("no published trust anchor matches target network {target}")]
    NoCandidates {
        /// The target that had no matching entry.
        target: String,
    },
    /// The published trust-anchor list couldn't be fetched, so there was
    /// nothing to resolve `target` against.
    #[error("trust-anchor list unavailable: {detail}")]
    TrustAnchorsUnavailable {
        /// Why the fetch failed.
        detail: String,
    },
    /// At least one candidate URL was tried, but none of them verified as
    /// `target` — carries every attempt's outcome so a caller can surface
    /// something more useful than "it didn't work."
    #[error("no candidate server for target network {target} verified: {attempts:?}")]
    NoneVerified {
        /// The target none of the candidates satisfied.
        target: String,
        /// `(candidate URL, human-readable outcome)` for every URL tried.
        attempts: Vec<(String, String)>,
    },
}

/// Bounds on the latency ranking applied among verified candidates.
#[derive(Debug, Clone, Copy)]
pub struct RankConfig {
    /// At most this many verified candidates are collected and timed.
    pub max_timed: usize,
    /// Timeout for each timing request.
    pub probe_timeout: std::time::Duration,
    /// How long verification continues after the first candidate verifies.
    pub collect_window: std::time::Duration,
}

impl Default for RankConfig {
    fn default() -> Self {
        Self {
            max_timed: 5,
            probe_timeout: std::time::Duration::from_secs(2),
            collect_window: std::time::Duration::from_secs(2),
        }
    }
}

/// A verified candidate and its measured `GET /nodes/status` round trip;
/// `latency` is `None` when it was not measured or the probe failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCandidate {
    /// The candidate's base URL.
    pub server_url: String,
    /// The measured round trip, if any.
    pub latency: Option<std::time::Duration>,
}

/// The outcome of [`discover_ranked`].
#[derive(Debug, Clone, PartialEq)]
pub struct Discovered {
    /// The selected server.
    pub server_url: String,
    /// The pinned entry the selected server verified against.
    pub entry: TrustAnchorEntry,
    /// Every verified candidate in selection order: measured fastest first,
    /// then unmeasured ones in candidate order.
    pub verified: Vec<VerifiedCandidate>,
}

/// Resolves `target` to a live, independently-verified `(server_url,
/// entry)` with no server URL supplied up front: a caller who only knows
/// which network they want to join, not which of its nodes to talk to.
///
/// See [`discover_ranked`] for how candidates are verified and ranked.
pub async fn discover(
    target: &TargetNetwork,
    retry: &crate::RetryConfig,
) -> Result<(String, TrustAnchorEntry), DiscoveryError> {
    let found = discover_ranked(target, retry, &RankConfig::default()).await?;
    Ok((found.server_url, found.entry))
}

/// Like [`discover`], also reporting every verified candidate's measured latency.
///
/// Candidates come only from the published trust-anchor list's own
/// `server_url`/`seed_nodes` fields for every entry matching `target`, so
/// discovery can't be tricked into contacting an unpinned host. They are
/// verified exactly like [`AvalonClient::verify_network`] would, in list
/// order (each entry's `server_url` before its `seed_nodes`). Only verified
/// candidates are eligible; up to `max_timed` (5) of them are timed with one
/// `GET /nodes/status` each, in parallel, and the lowest round trip wins. A
/// failed or timed-out probe ranks after measured ones and ties keep
/// candidate order. With one verified candidate no extra request is made.
/// The extra time over first-verified selection is bounded by
/// `collect_window` (2s of further verification after the first success)
/// plus `probe_timeout` (2s).
pub async fn discover_ranked(
    target: &TargetNetwork,
    retry: &crate::RetryConfig,
    rank: &RankConfig,
) -> Result<Discovered, DiscoveryError> {
    discover_from(TRUST_ANCHORS_URL, target, retry, rank).await
}

async fn discover_from(
    anchors_url: &str,
    target: &TargetNetwork,
    retry: &crate::RetryConfig,
    rank: &RankConfig,
) -> Result<Discovered, DiscoveryError> {
    let anchors = fetch_trust_anchors(&reqwest::Client::new(), anchors_url)
        .await
        .map_err(|err| DiscoveryError::TrustAnchorsUnavailable {
            detail: err.to_string(),
        })?;
    discover_among(&anchors, target, retry, rank).await
}

async fn time_probe(
    http: &reqwest::Client,
    server_url: &str,
    timeout: std::time::Duration,
) -> Option<std::time::Duration> {
    let start = std::time::Instant::now();
    let request = http.get(format!("{server_url}/nodes/status")).send();
    match tokio::time::timeout(timeout, request).await {
        Ok(Ok(response)) if response.status().is_success() => Some(start.elapsed()),
        _ => None,
    }
}

/// [`discover_ranked`]'s actual logic, taking `anchors` explicitly rather
/// than always fetching the published list, so tests can supply a mock
/// server's own key instead of forging a signature for a real entry.
async fn discover_among(
    anchors: &[TrustAnchorEntry],
    target: &TargetNetwork,
    retry: &crate::RetryConfig,
    rank: &RankConfig,
) -> Result<Discovered, DiscoveryError> {
    let http = reqwest::Client::new();
    let mut attempts = Vec::new();
    let mut tried_any = false;
    let mut verified: Vec<(String, TrustAnchorEntry)> = Vec::new();
    let mut first_verified_at: Option<std::time::Instant> = None;

    'collect: for entry in anchors {
        let entry_matches = match target {
            TargetNetwork::NetworkId(expected) => &entry.network_id == expected,
            TargetNetwork::Env(tier) => tier.matches(entry.environment),
        };
        if !entry_matches {
            continue;
        }
        let candidates = entry.server_url.iter().chain(entry.seed_nodes.iter());
        for candidate in candidates {
            if verified.len() >= rank.max_timed {
                break 'collect;
            }
            tried_any = true;
            let check = fetch_network_trust_status(anchors, &http, retry, candidate);
            let status = match first_verified_at {
                None => check.await,
                Some(start) => {
                    let remaining = rank.collect_window.saturating_sub(start.elapsed());
                    match tokio::time::timeout(remaining, check).await {
                        Ok(status) => status,
                        Err(_) => break 'collect,
                    }
                }
            };
            match check_target_network(&status, target) {
                Ok(verified_entry) => {
                    first_verified_at.get_or_insert_with(std::time::Instant::now);
                    verified.push((candidate.clone(), verified_entry.clone()));
                }
                Err(err) => attempts.push((candidate.clone(), err.to_string())),
            }
        }
    }

    match verified.len() {
        0 if !tried_any => Err(DiscoveryError::NoCandidates {
            target: target.to_string(),
        }),
        0 => Err(DiscoveryError::NoneVerified {
            target: target.to_string(),
            attempts,
        }),
        1 => {
            let (server_url, entry) = verified.remove(0);
            Ok(Discovered {
                verified: vec![VerifiedCandidate {
                    server_url: server_url.clone(),
                    latency: None,
                }],
                server_url,
                entry,
            })
        }
        _ => {
            let latencies = futures_util::future::join_all(
                verified
                    .iter()
                    .map(|(url, _)| time_probe(&http, url, rank.probe_timeout)),
            )
            .await;
            let mut ranked: Vec<_> = verified.into_iter().zip(latencies).collect();
            // Stable sort: measured before unmeasured, ties keep candidate order.
            ranked.sort_by_key(|(_, latency)| (latency.is_none(), *latency));
            let summary = ranked
                .iter()
                .map(|((url, _), latency)| VerifiedCandidate {
                    server_url: url.clone(),
                    latency: *latency,
                })
                .collect();
            let ((server_url, entry), _) = ranked.remove(0);
            Ok(Discovered {
                server_url,
                entry,
                verified: summary,
            })
        }
    }
}

impl AvalonClient {
    /// Builds and returns a client with no server URL supplied up front —
    /// resolves `target` to a live, verified server via [`discover`], then
    /// constructs exactly as [`AvalonClient::new`] would with the
    /// discovered URL. See [`discover`] for how candidates are chosen and
    /// verified.
    pub async fn connect(
        target: TargetNetwork,
        config: DiscoveryConfig,
    ) -> Result<Self, DiscoveryError> {
        let (server_url, _entry) = discover(&target, &config.retry).await?;
        Ok(Self::new(AvalonConfig {
            server_url,
            integrator_credential_key_id: config.integrator_credential_key_id,
            integrator_slug: config.integrator_slug,
            signing_key: config.signing_key,
            retry: config.retry,
        }))
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use time::OffsetDateTime;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::{AvalonConfig, RetryConfig};

    fn anchor(network_id: &str, verify_key_hex: String) -> TrustAnchorEntry {
        TrustAnchorEntry {
            label: network_id.to_string(),
            network_id: network_id.to_string(),
            verify_key: verify_key_hex,
            signing_key_id: "test-key".to_string(),
            server_url: None,
            environment: NetworkEnvironment::LocalDev,
            seed_nodes: Vec::new(),
            notes: None,
        }
    }

    fn anchors_json() -> serde_json::Value {
        serde_json::json!({"networks": [{
            "label": "avalon-dev-local",
            "network_id": "avalon-dev-local",
            "verify_key": "ab".repeat(32),
            "signing_key_id": "k",
            "environment": "local-dev",
        }]})
    }

    fn signed_sth(signing_key: &SigningKey, network_id: &str) -> crate::sth::SignedTreeHead {
        crate::sth::sign_tree_head(
            signing_key,
            "test-key",
            42,
            &"ab".repeat(32),
            network_id,
            OffsetDateTime::UNIX_EPOCH,
        )
    }

    #[test]
    fn valid_sth_against_its_pinned_key_verifies() {
        let signing_key = SigningKey::generate(&mut rand::rng());
        let entry = anchor(
            "avalon-test",
            hex::encode(signing_key.verifying_key().to_bytes()),
        );
        let sth = signed_sth(&signing_key, "avalon-test");

        let status = evaluate_network_trust(std::slice::from_ref(&entry), sth);
        assert_eq!(status, NetworkTrustStatus::Verified { entry });
    }

    #[test]
    fn sth_signed_by_a_different_key_is_flagged_as_mismatch_not_silently_trusted() {
        let real_key = SigningKey::generate(&mut rand::rng());
        let impostor_key = SigningKey::generate(&mut rand::rng());
        let entry = anchor(
            "avalon-test",
            hex::encode(real_key.verifying_key().to_bytes()),
        );
        // A server signing under the real network's name, but with a
        // different key — the exact impostor case this module exists for.
        let forged_sth = signed_sth(&impostor_key, "avalon-test");

        let status = evaluate_network_trust(std::slice::from_ref(&entry), forged_sth);
        assert_eq!(
            status,
            NetworkTrustStatus::Mismatch {
                entry,
                claimed_network_id: "avalon-test".to_string(),
            }
        );
    }

    #[test]
    fn unpinned_network_id_reports_unknown_not_trusted_by_default() {
        let signing_key = SigningKey::generate(&mut rand::rng());
        let sth = signed_sth(&signing_key, "avalon-unpinned");

        let status = evaluate_network_trust(&[], sth);
        assert_eq!(
            status,
            NetworkTrustStatus::UnknownNetwork {
                claimed_network_id: "avalon-unpinned".to_string(),
            }
        );
    }

    fn client_for(server_url: String) -> AvalonClient {
        AvalonClient::new(AvalonConfig {
            server_url,
            integrator_credential_key_id: "test-integrator".to_string(),
            integrator_slug: None,
            signing_key: None,
            retry: RetryConfig {
                max_retries: 0,
                base_delay: std::time::Duration::from_millis(1),
                request_timeout: std::time::Duration::from_secs(5),
            },
        })
    }

    #[tokio::test]
    async fn verify_network_fetches_and_verifies_a_real_sth_end_to_end() {
        let signing_key = SigningKey::generate(&mut rand::rng());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ledger/sth/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tree_size": 42,
                "root_hash": "ab".repeat(32),
                "network_id": "avalon-test",
                "signing_key_id": "test-key",
                "signature": signed_sth(&signing_key, "avalon-test").signature,
                "created_at": "1970-01-01T00:00:00Z",
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/trusted-networks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(anchors_json()))
            .mount(&server)
            .await;

        let client = client_for(server.uri());
        // "avalon-test" has no entry in the published list, so the full path
        // (fetch anchors -> fetch STH -> evaluate) reports unknown.
        let status = client
            .verify_network_with(&format!("{}/trusted-networks.json", server.uri()))
            .await;
        assert_eq!(
            status,
            NetworkTrustStatus::UnknownNetwork {
                claimed_network_id: "avalon-test".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn fetch_trust_anchors_parses_the_published_file() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/trusted-networks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(anchors_json()))
            .mount(&server)
            .await;
        let url = format!("{}/trusted-networks.json", server.uri());
        let anchors = fetch_trust_anchors(&reqwest::Client::new(), &url)
            .await
            .unwrap();
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors[0].network_id, "avalon-dev-local");
    }

    #[tokio::test]
    async fn discover_reports_unavailable_anchors_when_the_list_cannot_be_fetched() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let target = TargetNetwork::NetworkId("avalon-dev-local".to_string());
        let err = discover_from(
            &server.uri(),
            &target,
            &RetryConfig::default(),
            &RankConfig::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            DiscoveryError::TrustAnchorsUnavailable { .. }
        ));
    }

    #[tokio::test]
    async fn fetch_trust_anchors_errors_on_a_failing_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        assert!(fetch_trust_anchors(&reqwest::Client::new(), &server.uri())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn verify_network_reports_unreachable_when_the_server_is_down() {
        let anchors = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(anchors_json()))
            .mount(&anchors)
            .await;
        let client = client_for("http://127.0.0.1:1".to_string());
        let status = client.verify_network_with(&anchors.uri()).await;
        assert!(matches!(status, NetworkTrustStatus::Unreachable { .. }));
    }

    fn verified_dev(network_id: &str) -> NetworkTrustStatus {
        NetworkTrustStatus::Verified {
            entry: TrustAnchorEntry {
                label: network_id.to_string(),
                network_id: network_id.to_string(),
                verify_key: "ab".repeat(32),
                signing_key_id: "test-key".to_string(),
                server_url: None,
                environment: NetworkEnvironment::Dev,
                seed_nodes: Vec::new(),
                notes: None,
            },
        }
    }

    #[test]
    fn check_target_network_proceeds_when_the_declared_network_id_matches() {
        let status = verified_dev("avalon-dev-1");
        let target = TargetNetwork::NetworkId("avalon-dev-1".to_string());
        assert_eq!(
            check_target_network(&status, &target).unwrap().network_id,
            "avalon-dev-1"
        );
    }

    #[test]
    fn check_target_network_proceeds_when_the_declared_tier_matches() {
        let status = verified_dev("avalon-dev-1");
        let target = TargetNetwork::Env(TargetNetworkTier::Dev);
        assert!(check_target_network(&status, &target).is_ok());
    }

    #[test]
    fn check_target_network_rejects_a_mismatched_network_id() {
        let status = verified_dev("avalon-dev-1");
        let target = TargetNetwork::NetworkId("avalon-mainnet-1".to_string());
        assert_eq!(
            check_target_network(&status, &target).unwrap_err(),
            NetworkTargetError::Mismatch {
                declared: "avalon-mainnet-1".to_string(),
                actual: "avalon-dev-1".to_string(),
            }
        );
    }

    #[test]
    fn check_target_network_rejects_a_mismatched_tier() {
        let status = verified_dev("avalon-dev-1");
        let target = TargetNetwork::Env(TargetNetworkTier::Mainnet);
        assert!(matches!(
            check_target_network(&status, &target),
            Err(NetworkTargetError::Mismatch { .. })
        ));
    }

    #[test]
    fn check_target_network_never_proceeds_against_an_unverified_network() {
        let target = TargetNetwork::NetworkId("avalon-dev-1".to_string());

        let unknown = NetworkTrustStatus::UnknownNetwork {
            claimed_network_id: "avalon-dev-1".to_string(),
        };
        assert!(matches!(
            check_target_network(&unknown, &target),
            Err(NetworkTargetError::Unverified { .. })
        ));

        let unreachable = NetworkTrustStatus::Unreachable {
            detail: "connection refused".to_string(),
        };
        assert!(matches!(
            check_target_network(&unreachable, &target),
            Err(NetworkTargetError::Unverified { .. })
        ));

        let mismatch = NetworkTrustStatus::Mismatch {
            entry: match verified_dev("avalon-dev-1") {
                NetworkTrustStatus::Verified { entry } => entry,
                _ => unreachable!(),
            },
            claimed_network_id: "avalon-dev-1".to_string(),
        };
        assert!(matches!(
            check_target_network(&mismatch, &target),
            Err(NetworkTargetError::Unverified { .. })
        ));
    }

    async fn mock_sth_server(signing_key: &SigningKey, network_id: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ledger/sth/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tree_size": 42,
                "root_hash": "ab".repeat(32),
                "network_id": network_id,
                "signing_key_id": "test-key",
                "signature": signed_sth(signing_key, network_id).signature,
                "created_at": "1970-01-01T00:00:00Z",
            })))
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn discover_finds_the_first_verified_seed_node() {
        let signing_key = SigningKey::generate(&mut rand::rng());
        let dead = "http://127.0.0.1:1".to_string();
        let live = mock_sth_server(&signing_key, "avalon-test").await;
        let mut entry = anchor(
            "avalon-test",
            hex::encode(signing_key.verifying_key().to_bytes()),
        );
        entry.seed_nodes = vec![dead, live.uri()];

        let target = TargetNetwork::NetworkId("avalon-test".to_string());
        let retry = RetryConfig {
            max_retries: 0,
            base_delay: std::time::Duration::from_millis(1),
            request_timeout: std::time::Duration::from_secs(5),
        };
        let found = discover_among(
            std::slice::from_ref(&entry),
            &target,
            &retry,
            &RankConfig::default(),
        )
        .await
        .expect("the live seed node should verify");
        assert_eq!(found.server_url, live.uri());
        assert_eq!(found.entry, entry);
    }

    #[tokio::test]
    async fn discover_reports_no_candidates_for_an_unpinned_target() {
        let target = TargetNetwork::NetworkId("avalon-nowhere".to_string());
        let retry = RetryConfig::default();
        let err = discover_among(&[], &target, &retry, &RankConfig::default())
            .await
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::NoCandidates { .. }));
    }

    #[tokio::test]
    async fn discover_reports_none_verified_when_every_candidate_fails() {
        let signing_key = SigningKey::generate(&mut rand::rng());
        // Pinned entry's key won't match this server's forged STH.
        let impostor_key = SigningKey::generate(&mut rand::rng());
        let live = mock_sth_server(&impostor_key, "avalon-test").await;
        let mut entry = anchor(
            "avalon-test",
            hex::encode(signing_key.verifying_key().to_bytes()),
        );
        entry.seed_nodes = vec![live.uri()];

        let target = TargetNetwork::NetworkId("avalon-test".to_string());
        let retry = RetryConfig {
            max_retries: 0,
            base_delay: std::time::Duration::from_millis(1),
            request_timeout: std::time::Duration::from_secs(5),
        };
        let err = discover_among(
            std::slice::from_ref(&entry),
            &target,
            &retry,
            &RankConfig::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DiscoveryError::NoneVerified { .. }));
    }

    struct Node {
        server: MockServer,
        status_hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    /// `status`: `Some(delay_ms)` answers `/nodes/status` after the delay, `None` answers 500.
    async fn node(key: &SigningKey, sth_delay_ms: u64, status: Option<u64>) -> Node {
        let server = mock_sth_server_delayed(key, sth_delay_ms).await;
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = hits.clone();
        let template = match status {
            Some(ms) => ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({}))
                .set_delay(std::time::Duration::from_millis(ms)),
            None => ResponseTemplate::new(500),
        };
        Mock::given(method("GET"))
            .and(path("/nodes/status"))
            .respond_with(move |_: &wiremock::Request| {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                template.clone()
            })
            .mount(&server)
            .await;
        Node {
            server,
            status_hits: hits,
        }
    }

    async fn mock_sth_server_delayed(key: &SigningKey, delay_ms: u64) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ledger/sth/latest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "tree_size": 42,
                        "root_hash": "ab".repeat(32),
                        "network_id": "avalon-test",
                        "signing_key_id": "test-key",
                        "signature": signed_sth(key, "avalon-test").signature,
                        "created_at": "1970-01-01T00:00:00Z",
                    }))
                    .set_delay(std::time::Duration::from_millis(delay_ms)),
            )
            .mount(&server)
            .await;
        server
    }

    fn quick_retry() -> RetryConfig {
        RetryConfig {
            max_retries: 0,
            base_delay: std::time::Duration::from_millis(1),
            request_timeout: std::time::Duration::from_secs(5),
        }
    }

    fn rank_config() -> RankConfig {
        RankConfig {
            max_timed: 5,
            probe_timeout: std::time::Duration::from_millis(300),
            collect_window: std::time::Duration::from_millis(300),
        }
    }

    fn entry_for(key: &SigningKey, urls: Vec<String>) -> TrustAnchorEntry {
        let mut entry = anchor("avalon-test", hex::encode(key.verifying_key().to_bytes()));
        entry.seed_nodes = urls;
        entry
    }

    async fn rank(
        entry: &TrustAnchorEntry,
        cfg: &RankConfig,
    ) -> Result<Discovered, DiscoveryError> {
        let target = TargetNetwork::NetworkId("avalon-test".to_string());
        discover_among(std::slice::from_ref(entry), &target, &quick_retry(), cfg).await
    }

    #[tokio::test]
    async fn ranking_chooses_the_fastest_verified_candidate() {
        let key = SigningKey::generate(&mut rand::rng());
        let slow = node(&key, 0, Some(120)).await;
        let fast = node(&key, 0, Some(1)).await;
        let mid = node(&key, 0, Some(50)).await;
        let entry = entry_for(
            &key,
            vec![slow.server.uri(), fast.server.uri(), mid.server.uri()],
        );
        let found = rank(&entry, &rank_config()).await.unwrap();
        assert_eq!(found.server_url, fast.server.uri());
        let order: Vec<_> = found
            .verified
            .iter()
            .map(|v| v.server_url.clone())
            .collect();
        assert_eq!(
            order,
            vec![fast.server.uri(), mid.server.uri(), slow.server.uri()]
        );
        assert!(found.verified.iter().all(|v| v.latency.is_some()));
    }

    #[tokio::test]
    async fn ranking_never_chooses_an_unverified_fast_candidate() {
        let key = SigningKey::generate(&mut rand::rng());
        let impostor = SigningKey::generate(&mut rand::rng());
        let forged = node(&impostor, 0, Some(1)).await;
        let slow = node(&key, 0, Some(60)).await;
        let ok = node(&key, 0, Some(20)).await;
        let entry = entry_for(
            &key,
            vec![forged.server.uri(), slow.server.uri(), ok.server.uri()],
        );
        let found = rank(&entry, &rank_config()).await.unwrap();
        assert_eq!(found.server_url, ok.server.uri());
        assert_eq!(
            forged.status_hits.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn a_single_verified_candidate_makes_no_extra_request() {
        let key = SigningKey::generate(&mut rand::rng());
        let impostor = SigningKey::generate(&mut rand::rng());
        let forged = node(&impostor, 0, Some(1)).await;
        let only = node(&key, 0, Some(1)).await;
        let entry = entry_for(&key, vec![forged.server.uri(), only.server.uri()]);
        let found = rank(&entry, &rank_config()).await.unwrap();
        assert_eq!(found.server_url, only.server.uri());
        assert_eq!(
            only.status_hits.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn failed_probes_fall_back_to_candidate_order_and_stay_eligible() {
        let key = SigningKey::generate(&mut rand::rng());
        let a = node(&key, 0, None).await;
        let b = node(&key, 0, None).await;
        let entry = entry_for(&key, vec![a.server.uri(), b.server.uri()]);
        let found = rank(&entry, &rank_config()).await.unwrap();
        assert_eq!(found.server_url, a.server.uri());
        assert!(found.verified.iter().all(|v| v.latency.is_none()));

        let c = node(&key, 0, None).await;
        let d = node(&key, 0, Some(5)).await;
        let entry = entry_for(&key, vec![c.server.uri(), d.server.uri()]);
        let found = rank(&entry, &rank_config()).await.unwrap();
        assert_eq!(found.server_url, d.server.uri());
        assert_eq!(found.verified[1].server_url, c.server.uri());
    }

    #[tokio::test]
    async fn ranking_bounds_timed_candidates_and_probe_time() {
        let key = SigningKey::generate(&mut rand::rng());
        let a = node(&key, 0, Some(5_000)).await;
        let b = node(&key, 0, Some(5_000)).await;
        let c = node(&key, 0, Some(5_000)).await;
        let entry = entry_for(&key, vec![a.server.uri(), b.server.uri(), c.server.uri()]);
        let cfg = RankConfig {
            max_timed: 2,
            probe_timeout: std::time::Duration::from_millis(50),
            collect_window: std::time::Duration::from_millis(300),
        };
        let start = std::time::Instant::now();
        let found = rank(&entry, &cfg).await.unwrap();
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
        assert_eq!(found.server_url, a.server.uri());
        assert_eq!(c.status_hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn collection_stops_after_the_window_following_the_first_verification() {
        let key = SigningKey::generate(&mut rand::rng());
        let first = node(&key, 0, Some(5)).await;
        let laggard = node(&key, 2_000, Some(1)).await;
        let entry = entry_for(&key, vec![first.server.uri(), laggard.server.uri()]);
        let cfg = RankConfig {
            collect_window: std::time::Duration::from_millis(50),
            ..rank_config()
        };
        let start = std::time::Instant::now();
        let found = rank(&entry, &cfg).await.unwrap();
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(found.server_url, first.server.uri());
        assert_eq!(found.verified.len(), 1);
    }
}
