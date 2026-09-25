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

/// Resolves `target` to a live, independently-verified `(server_url,
/// entry)` with no server URL supplied up front — the zero-URL bootstrap
/// case (#91): a caller who only knows which network they want to join,
/// not which of its nodes to talk to.
///
/// Candidates come only from the published trust-anchor list' own `server_url`/
/// `seed_nodes` fields for every entry matching `target` — never anywhere
/// else, so discovery can't be tricked into contacting an unpinned host.
/// Each candidate is fetched and verified exactly like
/// [`AvalonClient::verify_network`] would; the first one whose STH
/// verifies against `target`'s own matching entry wins. Entries are tried
/// in the published trust-anchor list' order, and each entry's `server_url`
/// before its `seed_nodes`, so results are deterministic across runs of
/// the same SDK build.
pub async fn discover(
    target: &TargetNetwork,
    retry: &crate::RetryConfig,
) -> Result<(String, TrustAnchorEntry), DiscoveryError> {
    discover_from(TRUST_ANCHORS_URL, target, retry).await
}

async fn discover_from(
    anchors_url: &str,
    target: &TargetNetwork,
    retry: &crate::RetryConfig,
) -> Result<(String, TrustAnchorEntry), DiscoveryError> {
    let anchors = fetch_trust_anchors(&reqwest::Client::new(), anchors_url)
        .await
        .map_err(|err| DiscoveryError::TrustAnchorsUnavailable {
            detail: err.to_string(),
        })?;
    discover_among(&anchors, target, retry).await
}

/// [`discover`]'s actual logic, taking `anchors` explicitly rather than
/// always fetching the published list — split out the same way
/// [`evaluate_network_trust`] is, so tests can supply a mock server's own
/// key instead of needing to forge a signature for a real published entry.
async fn discover_among(
    anchors: &[TrustAnchorEntry],
    target: &TargetNetwork,
    retry: &crate::RetryConfig,
) -> Result<(String, TrustAnchorEntry), DiscoveryError> {
    let http = reqwest::Client::new();
    let mut attempts = Vec::new();
    let mut tried_any = false;

    for entry in anchors {
        let entry_matches = match target {
            TargetNetwork::NetworkId(expected) => &entry.network_id == expected,
            TargetNetwork::Env(tier) => tier.matches(entry.environment),
        };
        if !entry_matches {
            continue;
        }
        let candidates = entry.server_url.iter().chain(entry.seed_nodes.iter());
        for candidate in candidates {
            tried_any = true;
            let status = fetch_network_trust_status(anchors, &http, retry, candidate).await;
            match check_target_network(&status, target) {
                Ok(verified_entry) => return Ok((candidate.clone(), verified_entry.clone())),
                Err(err) => attempts.push((candidate.clone(), err.to_string())),
            }
        }
    }

    if !tried_any {
        return Err(DiscoveryError::NoCandidates {
            target: target.to_string(),
        });
    }
    Err(DiscoveryError::NoneVerified {
        target: target.to_string(),
        attempts,
    })
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
        let err = discover_from(&server.uri(), &target, &RetryConfig::default())
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
        let (server_url, resolved) = discover_among(std::slice::from_ref(&entry), &target, &retry)
            .await
            .expect("the live seed node should verify");
        assert_eq!(server_url, live.uri());
        assert_eq!(resolved, entry);
    }

    #[tokio::test]
    async fn discover_reports_no_candidates_for_an_unpinned_target() {
        let target = TargetNetwork::NetworkId("avalon-nowhere".to_string());
        let retry = RetryConfig::default();
        let err = discover_among(&[], &target, &retry).await.unwrap_err();
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
        let err = discover_among(std::slice::from_ref(&entry), &target, &retry)
            .await
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::NoneVerified { .. }));
    }
}
