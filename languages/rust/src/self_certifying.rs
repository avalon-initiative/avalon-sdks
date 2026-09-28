//! Verification of tree heads of self-certifying `node:<sha256-of-key>` shards.
//!
//! The shard id is `node:` plus the lowercase hex SHA-256 of the raw 32-byte Ed25519
//! public key that signs the shard's heads. A node serves that key as the optional
//! `signing_public_key` next to a head (outside the signed bytes), so a verifier needs
//! nothing else: the key must hash to the id and must have signed the head. No trust
//! anchor, registry or witness list is involved.
//! `conformance/vectors/self-certifying-tree-head.json` is the shared arbiter.

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::sth::{verify_tree_head, SignedTreeHead};
use crate::{AvalonClient, SdkError};

const NODE_PREFIX: &str = "node:";

/// Why a self-certifying head was not verified. Checks run in this order and the first
/// failure is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SelfCertifyingFailure {
    /// The shard id is not a valid `node:<64 lowercase hex>` id.
    #[error("shard id is not a self-certifying node: id")]
    NotSelfCertifying,
    /// No signing key was presented with the head.
    #[error("no signing public key was presented with the head")]
    MissingKey,
    /// The key is not exactly 64 lowercase hex characters decoding to a canonical Ed25519 point
    /// of non-small order.
    #[error("presented signing public key is malformed")]
    MalformedKey,
    /// SHA-256 of the key does not equal the hash in the shard id.
    #[error("presented signing public key does not hash to the shard id")]
    KeyIdMismatch,
    /// The key did not sign this head.
    #[error("head signature does not verify under the presented key")]
    BadSignature,
}

impl SelfCertifyingFailure {
    /// The stable name used by the shared conformance vectors.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotSelfCertifying => "not_self_certifying",
            Self::MissingKey => "missing_key",
            Self::MalformedKey => "malformed_key",
            Self::KeyIdMismatch => "key_id_mismatch",
            Self::BadSignature => "bad_signature",
        }
    }
}

/// Which verification applies to a shard id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardCheck {
    /// `node:<hash>`: [`verify_self_certifying_head`].
    SelfCertifying,
    /// `core`: the network and witness verification ([`AvalonClient::verify_network`] and
    /// [`AvalonClient::verify_network_with_witnesses`]).
    CoreNetwork,
    /// Any other id kind, and any malformed id. Nothing here verifies these.
    Unsupported,
}

/// The lowercase hex key hash of a valid `node:` id.
fn key_hash_of(shard_id: &str) -> Option<&str> {
    let hash = shard_id.strip_prefix(NODE_PREFIX)?;
    let valid = hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    valid.then_some(hash)
}

/// Which check applies to `shard_id`; an unsupported kind is reported, never passed.
pub fn shard_check(shard_id: &str) -> ShardCheck {
    if shard_id == "core" {
        ShardCheck::CoreNetwork
    } else if key_hash_of(shard_id).is_some() {
        ShardCheck::SelfCertifying
    } else {
        ShardCheck::Unsupported
    }
}

/// The `node:` id a signing key certifies.
pub fn self_certifying_id(key: &VerifyingKey) -> String {
    format!(
        "{NODE_PREFIX}{}",
        hex::encode(Sha256::digest(key.as_bytes()))
    )
}

fn parse_key(key_hex: &str) -> Option<VerifyingKey> {
    let lowercase_hex = key_hex.len() == 64
        && key_hex
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !lowercase_hex {
        return None;
    }
    let bytes: [u8; 32] = hex::decode(key_hex).ok()?.try_into().ok()?;
    let key = VerifyingKey::from_bytes(&bytes).ok()?;
    // p = 2^255 - 19, so y >= p iff the low 255 bits are ff..ff with a first byte >= 0xed.
    let non_canonical_y =
        bytes[0] >= 0xed && bytes[1..31].iter().all(|b| *b == 0xff) && bytes[31] & 0x7f == 0x7f;
    // Small order covers x = 0 with the sign bit set, which only occurs at the order-1 and order-2 points.
    (!non_canonical_y && !key.is_weak()).then_some(key)
}

/// Verifies `sth` as a head of the self-certifying shard `shard_id` using only
/// `signing_public_key`, the key presented alongside it. Malformed input is a failure,
/// never a panic.
pub fn verify_self_certifying_head(
    shard_id: &str,
    sth: &SignedTreeHead,
    signing_public_key: Option<&str>,
) -> Result<(), SelfCertifyingFailure> {
    let hash = key_hash_of(shard_id).ok_or(SelfCertifyingFailure::NotSelfCertifying)?;
    let key_hex = signing_public_key.ok_or(SelfCertifyingFailure::MissingKey)?;
    let key = parse_key(key_hex).ok_or(SelfCertifyingFailure::MalformedKey)?;
    if hex::encode(Sha256::digest(key.as_bytes())) != hash {
        return Err(SelfCertifyingFailure::KeyIdMismatch);
    }
    if !verify_tree_head(&key, sth) {
        return Err(SelfCertifyingFailure::BadSignature);
    }
    Ok(())
}

/// A tree head together with the optional signing key a node served with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfCertifyingTreeHead {
    /// The signed head.
    pub sth: SignedTreeHead,
    /// Lowercase hex Ed25519 public key that signed the head; absent from older nodes and
    /// from shards that are not self-certifying. Not part of the signed bytes.
    pub signing_public_key: Option<String>,
}

impl SelfCertifyingTreeHead {
    /// [`verify_self_certifying_head`] on this head and its own key.
    pub fn verify(&self, shard_id: &str) -> Result<(), SelfCertifyingFailure> {
        verify_self_certifying_head(shard_id, &self.sth, self.signing_public_key.as_deref())
    }
}

/// `GET /ledger/sth/latest` and `/ledger/sth/{tree_size}` wire shape, including the optional
/// `signing_public_key`. Unknown fields are ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct SelfCertifyingTreeHeadWire {
    /// Entries in the log at signing time.
    pub tree_size: i64,
    /// Lowercase hex Merkle root.
    pub root_hash: String,
    /// Network the head claims.
    pub network_id: String,
    /// Label of the signing key.
    pub signing_key_id: String,
    /// Lowercase hex Ed25519 signature.
    pub signature: String,
    /// Head timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Lowercase hex Ed25519 public key, when the node serves one.
    #[serde(default)]
    pub signing_public_key: Option<String>,
}

impl From<SelfCertifyingTreeHeadWire> for SelfCertifyingTreeHead {
    fn from(wire: SelfCertifyingTreeHeadWire) -> Self {
        Self {
            sth: SignedTreeHead {
                tree_size: wire.tree_size,
                root_hash: wire.root_hash,
                network_id: wire.network_id,
                signing_key_id: wire.signing_key_id,
                signature: wire.signature,
                created_at: wire.created_at,
            },
            signing_public_key: wire.signing_public_key,
        }
    }
}

impl AvalonClient {
    /// Fetches a head of `shard_id` (the latest, or `tree_size` when given) with the signing
    /// key the node serves. Nothing here verifies the result; see
    /// [`SelfCertifyingTreeHead::verify`].
    pub async fn fetch_shard_tree_head(
        &self,
        shard_id: &str,
        tree_size: Option<i64>,
    ) -> Result<SelfCertifyingTreeHead, SdkError> {
        let path = match tree_size {
            Some(n) => format!("/ledger/sth/{n}"),
            None => "/ledger/sth/latest".to_string(),
        };
        let url = format!("{}{path}", self.config.server_url);
        let response = crate::http::send(&self.http, &self.config.retry, true, |c| {
            c.get(&url).query(&[("shard_id", shard_id)])
        })
        .await?;
        if !response.status().is_success() {
            return Err(crate::http::map_error_response(response).await);
        }
        let wire: SelfCertifyingTreeHeadWire = response
            .json()
            .await
            .map_err(|e| SdkError::Protocol(e.to_string()))?;
        Ok(wire.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sth::sign_tree_head;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn head(signing: &SigningKey) -> SignedTreeHead {
        sign_tree_head(
            signing,
            "node-key-1",
            9,
            &"ab".repeat(32),
            "avalon-test",
            OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1_780_000_000),
        )
    }

    fn key_hex(signing: &SigningKey) -> String {
        hex::encode(signing.verifying_key().as_bytes())
    }

    #[test]
    fn accepts_a_matching_key_and_head() {
        let signing = key(1);
        let id = self_certifying_id(&signing.verifying_key());
        assert_eq!(
            verify_self_certifying_head(&id, &head(&signing), Some(&key_hex(&signing))),
            Ok(())
        );
    }

    #[test]
    fn rejects_a_key_that_does_not_hash_to_the_id() {
        let id = self_certifying_id(&key(1).verifying_key());
        assert_eq!(
            verify_self_certifying_head(&id, &head(&key(2)), Some(&key_hex(&key(2)))),
            Err(SelfCertifyingFailure::KeyIdMismatch)
        );
    }

    #[test]
    fn rejects_a_head_signed_by_a_different_key() {
        let id = self_certifying_id(&key(1).verifying_key());
        assert_eq!(
            verify_self_certifying_head(&id, &head(&key(2)), Some(&key_hex(&key(1)))),
            Err(SelfCertifyingFailure::BadSignature)
        );
    }

    #[test]
    fn rejects_a_tampered_head() {
        let signing = key(1);
        let id = self_certifying_id(&signing.verifying_key());
        let mut sth = head(&signing);
        sth.tree_size += 1;
        assert_eq!(
            verify_self_certifying_head(&id, &sth, Some(&key_hex(&signing))),
            Err(SelfCertifyingFailure::BadSignature)
        );
    }

    #[test]
    fn reports_missing_and_malformed_keys() {
        let signing = key(1);
        let id = self_certifying_id(&signing.verifying_key());
        let sth = head(&signing);
        assert_eq!(
            verify_self_certifying_head(&id, &sth, None),
            Err(SelfCertifyingFailure::MissingKey)
        );
        for bad in [
            key_hex(&signing).to_uppercase(),
            key_hex(&signing)[2..].to_string(),
            format!("{}00", key_hex(&signing)),
            String::new(),
            "zz".repeat(32),
        ] {
            assert_eq!(
                verify_self_certifying_head(&id, &sth, Some(&bad)),
                Err(SelfCertifyingFailure::MalformedKey),
                "{bad}"
            );
        }
    }

    #[test]
    fn rejects_weak_and_non_canonical_keys_even_when_they_hash_to_the_id() {
        let sth = head(&key(1));
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut order_two_signed = [0xffu8; 32];
        order_two_signed[0] = 0xec;
        let mut wrapped_y3 = [0xffu8; 32];
        wrapped_y3[0] = 0xed + 3;
        wrapped_y3[31] = 0x7f;
        for bytes in [identity, [0u8; 32], order_two_signed, wrapped_y3] {
            let id = format!("node:{}", hex::encode(Sha256::digest(bytes)));
            assert_eq!(
                verify_self_certifying_head(&id, &sth, Some(&hex::encode(bytes))),
                Err(SelfCertifyingFailure::MalformedKey),
                "{bytes:02x?}"
            );
        }
    }

    #[test]
    fn rejects_ids_that_are_not_self_certifying() {
        let signing = key(1);
        let sth = head(&signing);
        let good = self_certifying_id(&signing.verifying_key());
        for id in [
            "core",
            "game:wow-demo/1",
            "node:",
            "node:ab",
            &good.to_uppercase(),
            "",
        ] {
            assert_eq!(
                verify_self_certifying_head(id, &sth, Some(&key_hex(&signing))),
                Err(SelfCertifyingFailure::NotSelfCertifying),
                "{id}"
            );
        }
    }

    #[test]
    fn shard_check_names_the_verification_that_applies() {
        let id = self_certifying_id(&key(1).verifying_key());
        assert_eq!(shard_check(&id), ShardCheck::SelfCertifying);
        assert_eq!(shard_check("core"), ShardCheck::CoreNetwork);
        for other in ["game:wow-demo/1", "app:notes", "service:x", "node:ab", ""] {
            assert_eq!(shard_check(other), ShardCheck::Unsupported, "{other}");
        }
    }

    #[test]
    fn wire_parsing_tolerates_a_missing_key_and_unknown_fields() {
        let base = |extra: &str| {
            format!(
                r#"{{"tree_size":1,"root_hash":"{}","network_id":"n","signing_key_id":"k","signature":"{}","created_at":"2026-05-28T20:26:40Z","protocol_version":"1","cosignatures":[]{extra}}}"#,
                "ab".repeat(32),
                "cd".repeat(64)
            )
        };
        let without: SelfCertifyingTreeHeadWire = serde_json::from_str(&base("")).unwrap();
        assert_eq!(without.signing_public_key, None);
        let with: SelfCertifyingTreeHeadWire =
            serde_json::from_str(&base(r#","signing_public_key":"aa""#)).unwrap();
        assert_eq!(with.signing_public_key.as_deref(), Some("aa"));
    }
}
