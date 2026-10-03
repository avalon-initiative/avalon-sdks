//! The shard family head: one owner's sibling shards (`{namespace}:{slug}` and
//! `{namespace}:{slug}/{instance}`) committed under a single recomputable root, served by
//! `GET /ledger/shard-family`. Nothing signs the root; anyone recomputes it from the member heads.
//! `conformance/vectors/shard-family-head.json` is the shared arbiter.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::{AvalonClient, SdkError};

const LEAF_TAG: &[u8] = b"avalon-shard-family-leaf-v1";
const EMPTY_TAG: &[u8] = b"avalon-shard-family-empty-v1";
const MAX_INSTANCE_LEN: usize = 64;

/// The owner id (`{namespace}:{slug}`) a shard id belongs to; `core`, `node:` ids and anything
/// that does not parse have no family.
pub fn shard_family_owner(shard_id: &str) -> Option<String> {
    let (namespace, rest) = shard_id.split_once(':')?;
    if !matches!(namespace, "game" | "app" | "service") {
        return None;
    }
    let (owner, instance) = match rest.split_once('/') {
        Some((owner, instance)) => (owner, Some(instance)),
        None => (rest, None),
    };
    if owner.is_empty()
        || owner
            .chars()
            .any(|c| c.is_whitespace() || c == ':' || c == '/')
    {
        return None;
    }
    if instance.is_some_and(|i| !valid_instance(i)) {
        return None;
    }
    Some(format!("{namespace}:{owner}"))
}

fn valid_instance(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    s.len() <= MAX_INSTANCE_LEN
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Whether `owner` is a well-formed family owner id: an owned shard id with no instance.
pub fn is_family_owner_id(owner: &str) -> bool {
    shard_family_owner(owner).is_some_and(|o| o == owner)
}

/// Whether `shard_id` belongs to the family owned by `owner`.
pub fn is_family_member(owner: &str, shard_id: &str) -> bool {
    shard_family_owner(shard_id).is_some_and(|o| o == owner)
}

const ROUTE_TAG: &[u8] = b"avalon-shard-route-v1";

/// The rendezvous weight of `shard_id` for `key` under `owner`: SHA-256 of `avalon-shard-route-v1`
/// then owner, key and shard id, each as a u32 big-endian byte length and its UTF-8 bytes.
pub fn route_weight(owner: &str, key: &str, shard_id: &str) -> [u8; 32] {
    let mut bytes = ROUTE_TAG.to_vec();
    put(&mut bytes, owner);
    put(&mut bytes, key);
    put(&mut bytes, shard_id);
    Sha256::digest(&bytes).into()
}

/// The sibling of `owner`'s family a write for `key` should go to, or `None` when no candidate is
/// a family member. Highest-random-weight hashing over [`route_weight`], so the same key and set
/// always give the same sibling and adding or removing one only moves the keys that must move.
/// Ids outside the family are ignored, duplicates count once, and the order of `siblings` does
/// not matter. Equal weights (only possible for equal ids) go to the bytewise smaller id. This is
/// routing only: writes to different siblings are never atomic together.
pub fn route_write<'a, S: AsRef<str>>(
    owner: &str,
    key: &str,
    siblings: &'a [S],
) -> Option<&'a str> {
    pick_sibling(owner, key, siblings.iter().map(AsRef::as_ref))
}

fn pick_sibling<'a>(owner: &str, key: &str, ids: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    ids.filter(|id| is_family_member(owner, id))
        .map(|id| (route_weight(owner, key, id), id))
        .max_by(|(wa, a), (wb, b)| wa.cmp(wb).then_with(|| b.as_bytes().cmp(a.as_bytes())))
        .map(|(_, id)| id)
}

/// The fields of a member's head that its leaf commits to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FamilyHead {
    /// The member shard id.
    pub shard_id: String,
    /// Entries in the member's log.
    pub tree_size: i64,
    /// The member's own Merkle root, lowercase hex.
    pub root_hash: String,
    /// Label of the key that signed the member's head.
    pub signing_key_id: String,
    /// The member head's signature, lowercase hex.
    pub signature: String,
}

/// A member head as the node serves it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FamilyMember {
    #[serde(flatten)]
    /// The fields the family leaf commits to.
    pub head: FamilyHead,
    /// Head timestamp; not part of the leaf.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// An RFC 6962 inclusion proof of one member head against the family root.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FamilyProof {
    /// The member the proof is for.
    pub shard_id: String,
    /// Position of the member in shard id order.
    pub leaf_index: usize,
    /// Number of members the root commits to.
    pub tree_size: usize,
    /// Hex sibling hashes, leaf to root.
    pub path: Vec<String>,
}

/// `GET /ledger/shard-family` response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ShardFamilyResponse {
    /// The family owner id.
    pub owner: String,
    /// Family root, lowercase hex.
    pub root_hash: String,
    /// Number of members in `members`.
    pub shard_count: usize,
    /// A known family member has no head here, so `members` may be incomplete.
    pub partial: bool,
    /// Known family members without a head here.
    pub missing_shard_ids: Vec<String>,
    /// The exact heads `root_hash` commits to, in shard id order.
    pub members: Vec<FamilyMember>,
    /// Present only when a `member` was requested.
    #[serde(default)]
    /// Inclusion proof for the requested member.
    pub proof: Option<FamilyProof>,
}

impl ShardFamilyResponse {
    /// The served members' shard ids, in shard id order.
    pub fn sibling_ids(&self) -> impl Iterator<Item = &str> {
        self.members.iter().map(|m| m.head.shard_id.as_str())
    }

    /// The sibling a write for `key` should go to among the served members (see [`route_write`]).
    /// A `partial` response omits siblings that have no head here, so it can route differently
    /// from the full set.
    pub fn route_write(&self, key: &str) -> Option<&str> {
        pick_sibling(&self.owner, key, self.sibling_ids())
    }

    /// Whether `root_hash` is what [`family_root`] gives for the served members.
    pub fn root_matches(&self) -> bool {
        let heads: Vec<FamilyHead> = self.members.iter().map(|m| m.head.clone()).collect();
        family_root(&self.owner, &heads) == self.root_hash
    }

    /// Whether the served proof verifies for its member against `root_hash`; false when absent.
    pub fn proof_verifies(&self) -> bool {
        let Some(proof) = &self.proof else {
            return false;
        };
        self.members
            .iter()
            .find(|m| m.head.shard_id == proof.shard_id)
            .is_some_and(|m| verify_family_inclusion(&self.owner, &self.root_hash, proof, &m.head))
    }
}

fn put(bytes: &mut Vec<u8>, text: &str) {
    bytes.extend_from_slice(&(text.len() as u32).to_be_bytes());
    bytes.extend_from_slice(text.as_bytes());
}

fn leaf_bytes(owner: &str, head: &FamilyHead) -> Vec<u8> {
    let mut bytes = LEAF_TAG.to_vec();
    put(&mut bytes, owner);
    put(&mut bytes, &head.shard_id);
    bytes.extend_from_slice(&head.tree_size.to_be_bytes());
    put(&mut bytes, &head.root_hash);
    put(&mut bytes, &head.signing_key_id);
    put(&mut bytes, &head.signature);
    bytes
}

fn leaf_hash(data: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update([0u8])
        .chain_update(data)
        .finalize()
        .into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update([1u8])
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .into()
}

/// The largest power of two strictly below `n` (`n` >= 2).
fn split_point(n: usize) -> usize {
    1usize << (usize::BITS - 1 - (n - 1).leading_zeros())
}

fn mth(leaves: &[Vec<u8>]) -> [u8; 32] {
    if leaves.len() == 1 {
        return leaf_hash(&leaves[0]);
    }
    let k = split_point(leaves.len());
    node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
}

/// The family root over `heads`: heads of other owners are ignored, the rest are ordered by
/// shard id bytes, so the input order does not matter. Lowercase hex.
pub fn family_root(owner: &str, heads: &[FamilyHead]) -> String {
    let mut members: Vec<&FamilyHead> = heads
        .iter()
        .filter(|h| is_family_member(owner, &h.shard_id))
        .collect();
    members.sort_by(|a, b| a.shard_id.cmp(&b.shard_id));
    if members.is_empty() {
        let mut hasher = Sha256::new().chain_update(EMPTY_TAG);
        hasher.update((owner.len() as u32).to_be_bytes());
        hasher.update(owner.as_bytes());
        return hex::encode(hasher.finalize());
    }
    let leaves: Vec<Vec<u8>> = members.iter().map(|h| leaf_bytes(owner, h)).collect();
    hex::encode(mth(&leaves))
}

fn decode32(text: &str) -> Option<[u8; 32]> {
    hex::decode(text).ok()?.try_into().ok()
}

fn verify_path(m: usize, n: usize, leaf: [u8; 32], proof: &[[u8; 32]]) -> Option<[u8; 32]> {
    if n <= 1 {
        return proof.is_empty().then_some(leaf);
    }
    let k = split_point(n);
    let (last, rest) = proof.split_last()?;
    if m < k {
        Some(node_hash(&verify_path(m, k, leaf, rest)?, last))
    } else {
        Some(node_hash(last, &verify_path(m - k, n - k, leaf, rest)?))
    }
}

/// Verifies that `head` (a head of `head.shard_id`) is a member of `owner`'s family whose root
/// is `root_hash`. Any malformed input is a failure, never a panic.
pub fn verify_family_inclusion(
    owner: &str,
    root_hash: &str,
    proof: &FamilyProof,
    head: &FamilyHead,
) -> bool {
    if !is_family_member(owner, &head.shard_id) || proof.leaf_index >= proof.tree_size {
        return false;
    }
    let Some(root) = decode32(root_hash) else {
        return false;
    };
    let Some(path) = proof
        .path
        .iter()
        .map(|p| decode32(p))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    verify_path(
        proof.leaf_index,
        proof.tree_size,
        leaf_hash(&leaf_bytes(owner, head)),
        &path,
    )
    .is_some_and(|reconstructed| reconstructed == root)
}

impl AvalonClient {
    /// Fetches `owner`'s family head, with an inclusion proof for `member` when given. Nothing
    /// here verifies the result; see [`ShardFamilyResponse::root_matches`] and
    /// [`ShardFamilyResponse::proof_verifies`].
    pub async fn fetch_shard_family(
        &self,
        owner: &str,
        member: Option<&str>,
    ) -> Result<ShardFamilyResponse, SdkError> {
        let url = format!("{}/ledger/shard-family", self.config.server_url);
        let mut query = vec![("owner", owner)];
        query.extend(member.map(|m| ("member", m)));
        let response = crate::http::send(&self.http, &self.config.retry, true, |c| {
            c.get(&url).query(&query)
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
