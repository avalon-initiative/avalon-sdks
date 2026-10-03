//! Self-certifying identity ids and the v2 signing bytes that carry them.
//!
//! A public key is lowercase hex inside every signing-byte string here and standard base64 on the
//! wire. Pinned by `conformance/vectors/identity-id.json`, `identity-created-signing.json`,
//! `device-grant-approval.json` and `signing-key-revoked.json`.

use ed25519_dalek::{Signature, VerifyingKey};
use uuid::Uuid;

use crate::types::ids::IdentityId;

/// Whether `key` is an acceptable id-committed key: canonical encoding and not of small order.
pub fn is_acceptable_ed25519_key(key: &VerifyingKey) -> bool {
    let bytes = key.as_bytes();
    // p = 2^255 - 19, so y >= p iff the low 255 bits are ff..ff with a first byte >= 0xed.
    let non_canonical_y =
        bytes[0] >= 0xed && bytes[1..31].iter().all(|b| *b == 0xff) && bytes[31] & 0x7f == 0x7f;
    // Small order covers x = 0 with the sign bit set, which only occurs at the order-1 and order-2 points.
    !non_canonical_y && !key.is_weak()
}

/// Strict Ed25519 verification: rejects non-canonical S and small-order keys or R.
pub fn verify_strict(key: &VerifyingKey, message: &[u8], signature: &[u8; 64]) -> bool {
    key.verify_strict(message, &Signature::from_bytes(signature))
        .is_ok()
}

/// Bytes signed for `identity.created` v2:
/// `avalon:identity.created:v2:{len(network_id)}:{network_id}:{len(shard_id)}:{shard_id}:{ticket_id}:{identity_id}:{public_key_hex}:{display_name}`
/// with `len` the decimal UTF-8 byte length.
pub fn identity_created_signing_bytes_v2(
    network_id: &str,
    shard_id: &str,
    ticket_id: Uuid,
    identity_id: &IdentityId,
    public_key: &[u8; 32],
    display_name: &str,
) -> Vec<u8> {
    format!(
        "avalon:identity.created:v2:{}:{network_id}:{}:{shard_id}:{ticket_id}:{identity_id}:{}:{display_name}",
        network_id.len(),
        shard_id.len(),
        hex::encode(public_key)
    )
    .into_bytes()
}

/// Bytes the approving device signs for a grant:
/// `avalon:device_grant.approved:v2:{grant_id}:{identity_id}:{requested_public_key_hex}`.
pub fn device_grant_approval_signing_bytes_v2(
    grant_id: Uuid,
    identity_id: &IdentityId,
    requested_public_key: &[u8; 32],
) -> Vec<u8> {
    format!(
        "avalon:device_grant.approved:v2:{grant_id}:{identity_id}:{}",
        hex::encode(requested_public_key)
    )
    .into_bytes()
}

/// Bytes a signing-key revocation signs:
/// `avalon:identity.signing_key_revoked:v2:{identity_id}:{signing_key_id}:{revoked_by_signing_key_id}`.
pub fn signing_key_revoked_signing_bytes_v2(
    identity_id: &IdentityId,
    signing_key_id: Uuid,
    revoked_by_signing_key_id: Uuid,
) -> Vec<u8> {
    format!(
        "avalon:identity.signing_key_revoked:v2:{identity_id}:{signing_key_id}:{revoked_by_signing_key_id}"
    )
    .into_bytes()
}
