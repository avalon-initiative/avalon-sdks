//! A client-built witness known list: candidates come from the trust-anchor seed nodes'
//! discovery responses, are admitted only with a verifying advert proof, probed for liveness,
//! and selected under an anchor reservation and a per-prefix cap that needs no DNS lookup.
//! Many domains pointing at one machine look diverse to the prefix rule; the seeds are the floor.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use time::OffsetDateTime;

use crate::network::TrustAnchorEntry;
use crate::witness::{
    find_equivocating_witnesses, verify_witness_announce, CosignedTreeHead, CosignedTreeHeadWire,
};

/// Default capacity of a client's known list.
pub const DEFAULT_CAPACITY: usize = 5;
/// Default number of slots reserved for anchors.
pub const DEFAULT_ANCHOR_CAPACITY: usize = 2;
/// Default cap on slots sharing one diversity prefix.
pub const DEFAULT_MAX_PER_PREFIX: usize = 2;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_IN_FLIGHT: usize = 4;

/// One member of a known list; `key_id` is the lowercase hex of `key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownWitness {
    /// Lowercase hex Ed25519 public key.
    pub key_id: String,
    /// The parsed key.
    pub key: VerifyingKey,
    /// Where the witness advertised itself, when the list was built by discovery.
    pub base_url: Option<String>,
}

impl KnownWitness {
    /// A witness known only by its key.
    pub fn from_key(key: VerifyingKey) -> Self {
        Self {
            key_id: hex::encode(key.as_bytes()),
            key,
            base_url: None,
        }
    }
}

/// The `(key id, key)` pairs the round-one verification functions take.
pub fn known_pairs(list: &[KnownWitness]) -> Vec<(String, VerifyingKey)> {
    list.iter().map(|w| (w.key_id.clone(), w.key)).collect()
}

/// How a client obtains the witness list for network verification.
#[derive(Debug, Clone, Default)]
pub enum WitnessPolicy {
    /// Build the list from the trust-anchor seeds' discovery, once per client.
    #[default]
    Auto,
    /// Use exactly this list.
    Explicit(Vec<(String, VerifyingKey)>),
    /// Plain author-signature check only.
    None,
}

/// One discovered witness whose advert proof verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The witness key id the advert proved.
    pub witness_key_id: String,
    /// The advertised base url.
    pub base_url: String,
    /// Whether the url is one of the network's seed nodes.
    pub is_anchor: bool,
}

fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u32>().is_ok_and(|p| (1..=65535).contains(&p))
}

fn valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.split('.').all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes
                    .iter()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
                && bytes[0] != b'-'
                && bytes[bytes.len() - 1] != b'-'
        })
}

/// The diversity prefix for `base_url` (IPv4 `v4:a.b.c.0/24`, IPv6 `v6:g1:g2:g3::/48`, hostname
/// `host:` plus its last two labels), or `None` when the URL is not an acceptable node URL.
pub fn diversity_prefix_for_url(base_url: &str) -> Option<String> {
    if !base_url.is_ascii()
        || base_url
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return None;
    }
    let lower = base_url.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))?;
    let authority = match rest.find(['/', '?', '#']) {
        Some(i) => {
            if &rest[i..] != "/" {
                return None;
            }
            &rest[..i]
        }
        None => rest,
    };
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = if let Some(after) = authority.strip_prefix('[') {
        let close = after.find(']')?;
        let host = &after[..close];
        let port = match &after[close + 1..] {
            "" => None,
            t => Some(t.strip_prefix(':')?),
        };
        (format!("[{host}]"), port)
    } else {
        let mut parts = authority.split(':');
        let host = parts.next()?;
        let port = parts.next();
        if parts.next().is_some() {
            return None;
        }
        (host.to_string(), port)
    };
    if let Some(port) = port {
        if !valid_port(port) {
            return None;
        }
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        if inner.contains('.') {
            return None;
        }
        let addr: Ipv6Addr = inner.parse().ok()?;
        let s = addr.segments();
        return Some(format!("v6:{:x}:{:x}:{:x}::/48", s[0], s[1], s[2]));
    }
    let host = host.strip_suffix('.').unwrap_or(&host).to_string();
    if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') && host.contains('.') {
        let addr: Ipv4Addr = host.parse().ok()?;
        let o = addr.octets();
        return Some(format!("v4:{}.{}.{}.0/24", o[0], o[1], o[2]));
    }
    if !valid_hostname(&host) {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let keep = if labels.len() >= 2 {
        &labels[labels.len() - 2..]
    } else {
        &labels[..]
    };
    Some(format!("host:{}", keep.join(".")))
}

/// Selects the admitted key ids from `candidates`: anchors first in the given order, then the
/// rest in the given order. A candidate is refused when its URL has no prefix, its key id is
/// already present, the anchor cap or the capacity is reached, or its prefix is at the cap.
pub fn select_known_list(
    candidates: &[Candidate],
    capacity: usize,
    anchor_capacity: usize,
    max_per_prefix: usize,
) -> Vec<String> {
    let anchor_capacity = anchor_capacity.min(capacity);
    let mut admitted: Vec<(String, String, bool)> = Vec::new();
    for pass_anchor in [true, false] {
        for c in candidates.iter().filter(|c| c.is_anchor == pass_anchor) {
            let Some(prefix) = diversity_prefix_for_url(&c.base_url) else {
                continue;
            };
            if admitted.iter().any(|(id, _, _)| *id == c.witness_key_id)
                || (c.is_anchor && admitted.iter().filter(|a| a.2).count() >= anchor_capacity)
                || admitted.len() >= capacity
                || admitted.iter().filter(|a| a.1 == prefix).count() >= max_per_prefix
            {
                continue;
            }
            admitted.push((c.witness_key_id.clone(), prefix, c.is_anchor));
        }
    }
    admitted.into_iter().map(|a| a.0).collect()
}

#[derive(Debug, Deserialize)]
struct DiscoverResponse {
    #[serde(default)]
    peers: Vec<DiscoverPeer>,
}

#[derive(Debug, Deserialize)]
struct DiscoverPeer {
    base_url: String,
    network_id: String,
    #[serde(default)]
    witness: Option<DiscoverWitness>,
}

#[derive(Debug, Deserialize)]
struct DiscoverWitness {
    key_id: String,
    announced_at: String,
    proof: String,
}

fn normalize_url(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => return url.strip_suffix('/').unwrap_or(url).to_string(),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let path = path.strip_suffix('/').unwrap_or(path);
    format!("{scheme}://{}{path}", authority.to_ascii_lowercase())
}

async fn fetch_seed_peers(http: &reqwest::Client, seed: &str) -> Vec<DiscoverPeer> {
    let url = format!("{}/nodes/discover", seed.trim_end_matches('/'));
    let Ok(response) = http.get(url).timeout(REQUEST_TIMEOUT).send().await else {
        return Vec::new();
    };
    if !response.status().is_success() {
        return Vec::new();
    }
    response
        .json::<DiscoverResponse>()
        .await
        .map(|d| d.peers)
        .unwrap_or_default()
}

/// Queries every seed's `/nodes/discover` and returns the admitted candidates: same network,
/// verifying advert proof, deduplicated by key id (first seen wins). Anchors come first in seed
/// order; the rest keep discovery order. A failed seed is skipped.
pub async fn discover_candidates(
    http: &reqwest::Client,
    network_id: &str,
    seed_nodes: &[String],
    now: OffsetDateTime,
) -> Vec<Candidate> {
    let responses =
        futures_util::future::join_all(seed_nodes.iter().map(|seed| fetch_seed_peers(http, seed)))
            .await;
    let seeds: Vec<String> = seed_nodes.iter().map(|s| normalize_url(s)).collect();
    let mut candidates: Vec<Candidate> = Vec::new();
    for peer in responses.into_iter().flatten() {
        let Some(advert) = peer.witness else { continue };
        if peer.network_id != network_id {
            continue;
        }
        let Ok(announced_at) = OffsetDateTime::parse(
            &advert.announced_at,
            &time::format_description::well_known::Rfc3339,
        ) else {
            continue;
        };
        if !verify_witness_announce(
            &peer.base_url,
            &advert.key_id,
            announced_at,
            &advert.proof,
            now,
        ) || candidates.iter().any(|c| c.witness_key_id == advert.key_id)
        {
            continue;
        }
        let is_anchor = seeds.contains(&normalize_url(&peer.base_url));
        candidates.push(Candidate {
            witness_key_id: advert.key_id,
            base_url: peer.base_url,
            is_anchor,
        });
    }
    let seed_index = |c: &Candidate| seeds.iter().position(|s| *s == normalize_url(&c.base_url));
    candidates
        .sort_by_key(|c| if c.is_anchor { seed_index(c) } else { None }.unwrap_or(usize::MAX));
    candidates
}

/// Whether `base_url` serves `network_id`: its latest core tree head answers 200 with that network.
async fn serves_network(http: &reqwest::Client, base_url: &str, network_id: &str) -> bool {
    let url = format!(
        "{}/ledger/sth/latest?shard_id=core",
        base_url.trim_end_matches('/')
    );
    let Ok(response) = http.get(url).timeout(REQUEST_TIMEOUT).send().await else {
        return false;
    };
    if response.status() != reqwest::StatusCode::OK {
        return false;
    }
    response
        .json::<serde_json::Value>()
        .await
        .is_ok_and(|v| v["network_id"].as_str() == Some(network_id))
}

/// Reorders the non-anchor candidates in place.
pub type Shuffle = Arc<dyn Fn(&mut [Candidate]) + Send + Sync>;

/// Inputs for [`build_known_list`].
#[derive(Clone)]
pub struct BuildKnownListOptions {
    /// The target network.
    pub network_id: String,
    /// The network's trust-anchor seed nodes.
    pub seed_nodes: Vec<String>,
    /// Maximum list size.
    pub capacity: usize,
    /// Slots reserved for anchors.
    pub anchor_capacity: usize,
    /// Cap on slots sharing one diversity prefix.
    pub max_per_prefix: usize,
    /// Clock used to check advert freshness; `None` is the current time.
    pub now: Option<OffsetDateTime>,
    /// Shuffle for the non-anchor candidates; `None` is a cryptographically secure shuffle.
    pub shuffle: Option<Shuffle>,
}

impl BuildKnownListOptions {
    /// Default limits for `network_id` and its seeds.
    pub fn new(network_id: impl Into<String>, seed_nodes: Vec<String>) -> Self {
        Self {
            network_id: network_id.into(),
            seed_nodes,
            capacity: DEFAULT_CAPACITY,
            anchor_capacity: DEFAULT_ANCHOR_CAPACITY,
            max_per_prefix: DEFAULT_MAX_PER_PREFIX,
            now: None,
            shuffle: None,
        }
    }

    /// Options for a trust-anchor entry.
    pub fn for_entry(entry: &TrustAnchorEntry) -> Self {
        Self::new(entry.network_id.clone(), entry.seed_nodes.clone())
    }
}

fn secure_shuffle(candidates: &mut [Candidate]) {
    use rand::seq::SliceRandom;
    candidates.shuffle(&mut rand::rng());
}

/// Builds the known list: discover, order (anchors in seed order, the rest shuffled), probe
/// liveness in that order until the list cannot change, then select.
pub async fn build_known_list(
    http: &reqwest::Client,
    options: &BuildKnownListOptions,
) -> Vec<KnownWitness> {
    let now = options.now.unwrap_or_else(OffsetDateTime::now_utc);
    let mut candidates =
        discover_candidates(http, &options.network_id, &options.seed_nodes, now).await;
    let split = candidates.iter().take_while(|c| c.is_anchor).count();
    let mut rest = candidates.split_off(split);
    match &options.shuffle {
        Some(shuffle) => shuffle(&mut rest),
        None => secure_shuffle(&mut rest),
    }
    candidates.extend(rest);
    candidates.retain(|c| diversity_prefix_for_url(&c.base_url).is_some());

    let budget = options.capacity.saturating_mul(3);
    let mut reachable: Vec<Candidate> = Vec::new();
    let mut selected: Vec<String> = Vec::new();
    let mut probed = 0;
    while probed < budget.min(candidates.len()) && selected.len() < options.capacity {
        let end = (probed + MAX_IN_FLIGHT).min(budget).min(candidates.len());
        let chunk = &candidates[probed..end];
        let alive = futures_util::future::join_all(
            chunk
                .iter()
                .map(|c| serves_network(http, &c.base_url, &options.network_id)),
        )
        .await;
        reachable.extend(
            chunk
                .iter()
                .zip(alive)
                .filter(|(_, a)| *a)
                .map(|(c, _)| c.clone()),
        );
        probed = end;
        selected = select_known_list(
            &reachable,
            options.capacity,
            options.anchor_capacity,
            options.max_per_prefix,
        );
    }
    selected
        .into_iter()
        .filter_map(|id| {
            let candidate = reachable.iter().find(|c| c.witness_key_id == id)?;
            let key = hex::decode(&id)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .and_then(|a| VerifyingKey::from_bytes(&a).ok())?;
            Some(KnownWitness {
                key_id: id,
                key,
                base_url: Some(candidate.base_url.clone()),
            })
        })
        .collect()
}

/// Two author-signed heads for one size and network with different roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivocationEvidence {
    /// The tree size both heads claim.
    pub tree_size: i64,
    /// Root of the accepted head.
    pub root_a: String,
    /// Root of the conflicting head.
    pub root_b: String,
    /// Base urls that served the conflicting head.
    pub sources: Vec<String>,
    /// Witnesses that validly and freshly cosigned both heads.
    pub witnesses: Vec<String>,
}

/// Asks each known witness with a base url for the head at the accepted head's size and reports
/// author-signed heads with a different root. Reports only; never affects verification.
pub async fn cross_check_head(
    http: &reqwest::Client,
    known: &[KnownWitness],
    accepted: &CosignedTreeHead,
    author_key: &VerifyingKey,
    freshness_cutoff: OffsetDateTime,
    now: OffsetDateTime,
) -> Vec<EquivocationEvidence> {
    let fetches = known
        .iter()
        .filter_map(|w| w.base_url.as_ref())
        .map(|base| {
            let url = format!(
                "{}/ledger/sth/{}?shard_id=core&witnesses=1",
                base.trim_end_matches('/'),
                accepted.sth.tree_size
            );
            async move {
                let response = http.get(url).timeout(REQUEST_TIMEOUT).send().await.ok()?;
                if !response.status().is_success() {
                    return None;
                }
                let wire: CosignedTreeHeadWire = response.json().await.ok()?;
                Some((base.clone(), CosignedTreeHead::from(wire)))
            }
        });
    let mut fetched = Vec::new();
    let fetches: Vec<_> = fetches.collect();
    let mut pending = fetches.into_iter().peekable();
    while pending.peek().is_some() {
        let batch: Vec<_> = pending.by_ref().take(MAX_IN_FLIGHT).collect();
        fetched.extend(futures_util::future::join_all(batch).await);
    }
    let pairs = known_pairs(known);
    let mut evidence: Vec<EquivocationEvidence> = Vec::new();
    for (base, other) in fetched.into_iter().flatten() {
        if other.sth.network_id != accepted.sth.network_id
            || other.sth.tree_size != accepted.sth.tree_size
            || other.sth.root_hash == accepted.sth.root_hash
            || !crate::sth::verify_tree_head(author_key, &other.sth)
        {
            continue;
        }
        if let Some(e) = evidence
            .iter_mut()
            .find(|e| e.root_b == other.sth.root_hash)
        {
            e.sources.push(base);
            continue;
        }
        evidence.push(EquivocationEvidence {
            tree_size: accepted.sth.tree_size,
            root_a: accepted.sth.root_hash.clone(),
            root_b: other.sth.root_hash.clone(),
            sources: vec![base],
            witnesses: find_equivocating_witnesses(
                author_key,
                &pairs,
                freshness_cutoff,
                now,
                accepted,
                &other,
            ),
        });
    }
    evidence
}
