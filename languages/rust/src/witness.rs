//! Witness-cosigned tree head verification: an author-signed tree head is
//! accepted once a majority of the verifier's own known witness list has
//! cosigned it. The known list is always supplied by the caller.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Deserialize;
use time::OffsetDateTime;

use crate::signing_bytes::{tags, Builder, HashAlgo, SigningBytesError};
use crate::sth::{verify_tree_head, SignedTreeHead};

/// Default freshness window for cosignatures, in seconds.
pub const DEFAULT_FRESHNESS_SECONDS: i64 = 600;

/// One witness's cosignature over an author-signed tree head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessCosignature {
    /// Entries in the log at signing time.
    pub tree_size: i64,
    /// Lowercase hex Merkle root.
    pub root_hash: String,
    /// Network the head claims.
    pub network_id: String,
    /// Author head timestamp the cosignature covers.
    pub author_created_at: OffsetDateTime,
    /// The author head's `signing_key_id`, covered by the cosignature.
    pub author_key_id: String,
    /// The author head's signature (128 hex characters), covered by the cosignature.
    pub author_signature: String,
    /// Lowercase hex Ed25519 public key of the witness.
    pub witness_key_id: String,
    /// When the witness observed the head.
    pub observed_at: OffsetDateTime,
    /// Lowercase hex Ed25519 signature (64 bytes).
    pub signature: String,
}

/// An author-signed tree head plus the cosignatures that came with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignedTreeHead {
    /// The author-signed head.
    pub sth: SignedTreeHead,
    /// Cosignatures served with the head.
    pub cosignatures: Vec<WitnessCosignature>,
}

/// One cosignature as served by `?witnesses=1`; the tuple fields it signs
/// are taken from the head it accompanies.
#[derive(Debug, Clone, Deserialize)]
pub struct WitnessCosignatureWire {
    /// Lowercase hex Ed25519 public key of the witness.
    pub witness_key_id: String,
    /// When the witness observed the head.
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
    /// Lowercase hex Ed25519 signature.
    pub signature: String,
}

/// `GET /ledger/sth/latest?witnesses=1` (or `/ledger/sth/{n}`) wire shape.
#[derive(Debug, Clone, Deserialize)]
pub struct CosignedTreeHeadWire {
    /// Entries in the log at signing time.
    pub tree_size: i64,
    /// Lowercase hex Merkle root.
    pub root_hash: String,
    /// Network the head claims.
    pub network_id: String,
    /// Label of the author key.
    pub signing_key_id: String,
    /// Lowercase hex Ed25519 signature.
    pub signature: String,
    /// Author head timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Cosignatures served with the head.
    #[serde(default)]
    pub cosignatures: Vec<WitnessCosignatureWire>,
}

impl From<CosignedTreeHeadWire> for CosignedTreeHead {
    fn from(wire: CosignedTreeHeadWire) -> Self {
        let cosignatures = wire
            .cosignatures
            .into_iter()
            .map(|c| WitnessCosignature {
                tree_size: wire.tree_size,
                root_hash: wire.root_hash.clone(),
                network_id: wire.network_id.clone(),
                author_created_at: wire.created_at,
                author_key_id: wire.signing_key_id.clone(),
                author_signature: wire.signature.clone(),
                witness_key_id: c.witness_key_id,
                observed_at: c.observed_at,
                signature: c.signature,
            })
            .collect();
        Self {
            sth: SignedTreeHead {
                tree_size: wire.tree_size,
                root_hash: wire.root_hash,
                network_id: wire.network_id,
                signing_key_id: wire.signing_key_id,
                signature: wire.signature,
                created_at: wire.created_at,
            },
            cosignatures,
        }
    }
}

/// Why a cosignature or announce message could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WitnessSigningError {
    /// The root hash is not 64 lowercase hex characters.
    #[error("root_hash is not 64 lowercase hex characters")]
    InvalidRootHash,
    /// The author signature is not 64 bytes of hex.
    #[error("author_signature is not 64 bytes of hex")]
    InvalidAuthorSignature,
    /// The witness key id is not 64 lowercase hex characters.
    #[error("witness key id is not 64 lowercase hex characters")]
    InvalidKeyId,
    /// The structured layout failed.
    #[error(transparent)]
    Layout(#[from] SigningBytesError),
}

fn decode_author_signature(hex_text: &str) -> Result<[u8; 64], WitnessSigningError> {
    let bytes = hex::decode(hex_text).map_err(|_| WitnessSigningError::InvalidAuthorSignature)?;
    <[u8; 64]>::try_from(bytes.as_slice()).map_err(|_| WitnessSigningError::InvalidAuthorSignature)
}

/// The exact bytes a witness cosignature covers (tag `avalon.witness.cosign`, layout version 1):
/// `tree_size` i64, `network_id` str, `author_created_at` i64 unix seconds, `author_key_id` str,
/// the author signature (algorithm byte, 64 raw), `witness_key_id` str, the witness key
/// (algorithm byte, 32 raw), `observed_at` i64, then `hash_algo` u8 and the root hash (32 raw).
/// The `signature` field of `cosig` is not read.
pub fn witness_signing_message(
    cosig: &WitnessCosignature,
    witness_key: &[u8; 32],
) -> Result<Vec<u8>, WitnessSigningError> {
    let root = crate::ledger_entry::parse_hash("root_hash", &cosig.root_hash)
        .map_err(|_| WitnessSigningError::InvalidRootHash)?;
    let author_signature = decode_author_signature(&cosig.author_signature)?;
    Ok(Builder::new(tags::WITNESS_COSIGN, 1)
        .i64(cosig.tree_size)
        .str(&cosig.network_id)
        .i64(cosig.author_created_at.unix_timestamp())
        .str(&cosig.author_key_id)
        .signature(&author_signature)
        .str(&cosig.witness_key_id)
        .key(witness_key)
        .i64(cosig.observed_at.unix_timestamp())
        .hash_algo(HashAlgo::Sha256)
        .hash(&root)
        .finish()?)
}

/// Signs a cosignature over the author-signed `head`; used by tests and witness tooling.
pub fn sign_witness_cosignature(
    key: &SigningKey,
    head: &SignedTreeHead,
    observed_at: OffsetDateTime,
) -> Result<WitnessCosignature, WitnessSigningError> {
    let mut cosig = WitnessCosignature {
        tree_size: head.tree_size,
        root_hash: head.root_hash.clone(),
        network_id: head.network_id.clone(),
        author_created_at: head.created_at,
        author_key_id: head.signing_key_id.clone(),
        // Normalised to lowercase hex so equal bytes compare equal.
        author_signature: hex::encode(decode_author_signature(&head.signature)?),
        witness_key_id: hex::encode(key.verifying_key().as_bytes()),
        observed_at,
        signature: String::new(),
    };
    let message = witness_signing_message(&cosig, &key.verifying_key().to_bytes())?;
    let signature: Signature = key.sign(&message);
    cosig.signature = hex::encode(signature.to_bytes());
    Ok(cosig)
}

/// `false` for bad hex, wrong length or an invalid signature; never panics.
pub fn verify_witness_cosignature(key: &VerifyingKey, cosig: &WitnessCosignature) -> bool {
    let Ok(message) = witness_signing_message(cosig, &key.to_bytes()) else {
        return false;
    };
    let Ok(bytes) = hex::decode(&cosig.signature) else {
        return false;
    };
    let Ok(array) = <[u8; 64]>::try_from(bytes.as_slice()) else {
        return false;
    };
    key.verify(&message, &Signature::from_bytes(&array)).is_ok()
}

/// How far `announced_at` may differ from the verifier's clock for an advert proof to verify.
pub const WITNESS_ANNOUNCE_MAX_SKEW: time::Duration = time::Duration::hours(1);

/// The exact bytes a witness advert proof covers (tag `avalon.witness.announce`, layout version 1):
/// the base url str, the witness key (algorithm byte, 32 raw) and `announced_at` i64 unix seconds.
/// `witness_key_id` must be the lowercase hex of the key.
pub fn witness_announce_message(
    base_url: &str,
    witness_key_id: &str,
    announced_at: OffsetDateTime,
) -> Result<Vec<u8>, WitnessSigningError> {
    let key = crate::ledger_entry::parse_hash("witness_key_id", witness_key_id)
        .map_err(|_| WitnessSigningError::InvalidKeyId)?;
    Ok(Builder::new(tags::WITNESS_ANNOUNCE, 1)
        .str(base_url)
        .key(&key)
        .i64(announced_at.unix_timestamp())
        .finish()?)
}

/// Verifies that the holder of `witness_key_id` advertised `base_url` at `announced_at`, within
/// [`WITNESS_ANNOUNCE_MAX_SKEW`] of `now`. `false` for any malformed input; never panics.
pub fn verify_witness_announce(
    base_url: &str,
    witness_key_id: &str,
    announced_at: OffsetDateTime,
    proof_hex: &str,
    now: OffsetDateTime,
) -> bool {
    if (now - announced_at).abs() > WITNESS_ANNOUNCE_MAX_SKEW {
        return false;
    }
    let Ok(message) = witness_announce_message(base_url, witness_key_id, announced_at) else {
        return false;
    };
    let Some(key) = hex::decode(witness_key_id)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .and_then(|a| VerifyingKey::from_bytes(&a).ok())
    else {
        return false;
    };
    let Some(signature) = hex::decode(proof_hex)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
    else {
        return false;
    };
    key.verify(&message, &Signature::from_bytes(&signature))
        .is_ok()
}

/// Cosignatures needed for a known list of `list_size`: 0 for an empty list, else `n/2 + 1`.
pub fn majority_threshold(list_size: usize) -> usize {
    if list_size == 0 {
        0
    } else {
        list_size / 2 + 1
    }
}

/// Whether `distinct_witnesses` reaches [`majority_threshold`] for the list size.
pub fn is_cosigned_by_majority(list_size: usize, distinct_witnesses: usize) -> bool {
    distinct_witnesses >= majority_threshold(list_size)
}

fn valid_fresh_witness_ids(
    author_key: &VerifyingKey,
    head: &CosignedTreeHead,
    known_list: &[(String, VerifyingKey)],
    freshness_cutoff: OffsetDateTime,
    now: OffsetDateTime,
) -> BTreeSet<String> {
    let mut verified = BTreeSet::new();
    for (id, key) in known_list {
        if key == author_key {
            verified.insert(id.clone());
        }
    }
    for cosig in &head.cosignatures {
        // Timestamps compare at the second precision the signed bytes carry.
        if cosig.tree_size != head.sth.tree_size
            || cosig.root_hash != head.sth.root_hash
            || cosig.network_id != head.sth.network_id
            || cosig.author_created_at.unix_timestamp() != head.sth.created_at.unix_timestamp()
            || cosig.author_key_id != head.sth.signing_key_id
            || !cosig
                .author_signature
                .eq_ignore_ascii_case(&head.sth.signature)
        {
            continue;
        }
        if cosig.observed_at < freshness_cutoff || cosig.observed_at > now {
            continue;
        }
        let Some((_, key)) = known_list
            .iter()
            .find(|(id, _)| *id == cosig.witness_key_id)
        else {
            continue;
        };
        if verify_witness_cosignature(key, cosig) {
            verified.insert(cosig.witness_key_id.clone());
        }
    }
    verified
}

/// Accepts `head` when the author signature verifies and, for a known list of two or more,
/// a majority of the list cosigned it (see the module docs).
pub fn verify_cosigned_tree_head(
    author_key: &VerifyingKey,
    head: &CosignedTreeHead,
    known_list: &[(String, VerifyingKey)],
    freshness_cutoff: OffsetDateTime,
    now: OffsetDateTime,
) -> bool {
    if !verify_tree_head(author_key, &head.sth) {
        return false;
    }
    if known_list.len() <= 1 {
        return true;
    }
    let verified = valid_fresh_witness_ids(author_key, head, known_list, freshness_cutoff, now);
    is_cosigned_by_majority(known_list.len(), verified.len())
}

/// Witness ids that validly and freshly cosigned two independently accepted heads with
/// different roots at the same size on the same network; empty otherwise.
pub fn find_equivocating_witnesses(
    author_key: &VerifyingKey,
    known_list: &[(String, VerifyingKey)],
    freshness_cutoff: OffsetDateTime,
    now: OffsetDateTime,
    head_a: &CosignedTreeHead,
    head_b: &CosignedTreeHead,
) -> Vec<String> {
    if head_a.sth.network_id != head_b.sth.network_id
        || head_a.sth.tree_size != head_b.sth.tree_size
        || head_a.sth.root_hash == head_b.sth.root_hash
    {
        return Vec::new();
    }
    if !verify_cosigned_tree_head(author_key, head_a, known_list, freshness_cutoff, now)
        || !verify_cosigned_tree_head(author_key, head_b, known_list, freshness_cutoff, now)
    {
        return Vec::new();
    }
    let a = valid_fresh_witness_ids(author_key, head_a, known_list, freshness_cutoff, now);
    let b = valid_fresh_witness_ids(author_key, head_b, known_list, freshness_cutoff, now);
    a.intersection(&b).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sth::sign_tree_head;

    fn t(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(secs).unwrap()
    }

    fn setup() -> (SigningKey, Vec<SigningKey>, SignedTreeHead) {
        let author = SigningKey::from_bytes(&[1; 32]);
        let ws: Vec<_> = (2u8..5).map(|b| SigningKey::from_bytes(&[b; 32])).collect();
        let head = sign_tree_head(&author, "a", 5, &"ab".repeat(32), "net", t(1000)).unwrap();
        (author, ws, head)
    }

    fn list(ws: &[SigningKey]) -> Vec<(String, VerifyingKey)> {
        ws.iter()
            .map(|k| (hex::encode(k.verifying_key().as_bytes()), k.verifying_key()))
            .collect()
    }

    #[test]
    fn majority_values() {
        assert_eq!(majority_threshold(0), 0);
        assert_eq!(majority_threshold(1), 1);
        assert_eq!(majority_threshold(3), 2);
        assert_eq!(majority_threshold(10), 6);
        assert!(is_cosigned_by_majority(0, 0));
        assert!(!is_cosigned_by_majority(10, 5));
    }

    #[test]
    fn empty_and_single_lists_need_only_the_author_signature() {
        let (author, ws, head) = setup();
        let cosigned = CosignedTreeHead {
            sth: head,
            cosignatures: vec![],
        };
        let vk = author.verifying_key();
        assert!(verify_cosigned_tree_head(
            &vk,
            &cosigned,
            &[],
            t(0),
            t(2000)
        ));
        assert!(verify_cosigned_tree_head(
            &vk,
            &cosigned,
            &list(&ws)[..1],
            t(0),
            t(2000)
        ));
        let other = SigningKey::from_bytes(&[9; 32]).verifying_key();
        assert!(!verify_cosigned_tree_head(
            &other,
            &cosigned,
            &[],
            t(0),
            t(2000)
        ));
    }

    #[test]
    fn majority_accepts_and_future_dated_is_rejected() {
        let (author, ws, head) = setup();
        let known = list(&ws);
        let cosigs: Vec<_> = ws[..2]
            .iter()
            .map(|k| sign_witness_cosignature(k, &head, t(1500)).unwrap())
            .collect();
        let cosigned = CosignedTreeHead {
            sth: head,
            cosignatures: cosigs,
        };
        let vk = author.verifying_key();
        assert!(verify_cosigned_tree_head(
            &vk,
            &cosigned,
            &known,
            t(1000),
            t(1500)
        ));
        assert!(!verify_cosigned_tree_head(
            &vk,
            &cosigned,
            &known,
            t(1000),
            t(1499)
        ));
        assert!(!verify_cosigned_tree_head(
            &vk,
            &cosigned,
            &known,
            t(1501),
            t(2000)
        ));
    }

    #[test]
    fn duplicate_cosignatures_count_once() {
        let (author, ws, head) = setup();
        let c = sign_witness_cosignature(&ws[0], &head, t(1500)).unwrap();
        let cosigned = CosignedTreeHead {
            sth: head,
            cosignatures: vec![c.clone(), c],
        };
        assert!(!verify_cosigned_tree_head(
            &author.verifying_key(),
            &cosigned,
            &list(&ws),
            t(0),
            t(2000)
        ));
    }

    #[test]
    fn malformed_signatures_never_verify() {
        let (_, ws, head) = setup();
        let vk = ws[0].verifying_key();
        let good = sign_witness_cosignature(&ws[0], &head, t(1500)).unwrap();
        assert!(verify_witness_cosignature(&vk, &good));
        for bad in [
            "",
            "zz",
            "ab",
            &good.signature[..126],
            &format!("{}00", good.signature),
        ] {
            let mut c = good.clone();
            c.signature = bad.to_string();
            assert!(!verify_witness_cosignature(&vk, &c));
        }
        let mut wrong = good.clone();
        wrong.observed_at = t(1501);
        assert!(!verify_witness_cosignature(&vk, &wrong));
    }

    #[test]
    fn wire_conversion_carries_head_fields_into_cosignatures() {
        let wire: CosignedTreeHeadWire = serde_json::from_value(serde_json::json!({
            "tree_size": 3, "root_hash": "ab", "network_id": "n", "signing_key_id": "k",
            "signature": "00", "created_at": "2026-09-27T03:40:14.36239Z",
            "cosignatures": [{"witness_key_id": "w", "observed_at": "2026-09-27T04:07:52Z", "signature": "11"}]
        }))
        .unwrap();
        let head: CosignedTreeHead = wire.into();
        assert_eq!(head.cosignatures[0].tree_size, 3);
        assert_eq!(head.cosignatures[0].author_created_at, head.sth.created_at);
    }
}
