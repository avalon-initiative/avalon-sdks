//! Key acceptability, strict verification and the v3 identity key-event signing bytes.
//!
//! Layouts are the structured form of [`crate::signing_bytes`] (keys and ids raw); a public key is
//! standard base64 on the wire. Pinned by `conformance/vectors/identity-id.json`, `identity-created-signing.json`,
//! `device-grant-approval.json` and `signing-key-revoked.json`.

use ed25519_dalek::{Signature, VerifyingKey};
use uuid::Uuid;

use crate::signing_bytes::{tags, Builder};
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

/// Bytes signed for `identity.created`: tag, version 1, then `network_id` str, `shard_id` str,
/// `ticket_id` uuid, `identity_id` raw, inception key raw, `display_name` str.
pub fn identity_created_signing_bytes(
    network_id: &str,
    shard_id: &str,
    ticket_id: Uuid,
    identity_id: &IdentityId,
    public_key: &[u8; 32],
    display_name: &str,
) -> Vec<u8> {
    Builder::new(tags::IDENTITY_CREATED, 1)
        .str(network_id)
        .str(shard_id)
        .uuid(ticket_id)
        .fixed(&identity_id.to_bytes())
        .key(public_key)
        .str(display_name)
        .finish()
        .expect("identity.created fields fit a u32 length")
}

/// The chain position a key event signs: `seq` u64, then `prev_hash` as a flag byte (0, or 1 and 32 raw bytes).
fn with_position(builder: Builder, seq: u64, prev_hash: Option<&[u8; 32]>) -> Builder {
    let builder = builder.u64(seq);
    match prev_hash {
        Some(hash) => builder.u8(1).hash(hash),
        None => builder.u8(0),
    }
}

/// Bytes the approving device signs for a grant: tag, version 1, then `grant_id` uuid, `identity_id`
/// raw, `approver_signing_key_id` uuid, requested key raw, and the chain position.
pub fn device_grant_approval_signing_bytes(
    grant_id: Uuid,
    identity_id: &IdentityId,
    approver_signing_key_id: Uuid,
    requested_public_key: &[u8; 32],
    seq: u64,
    prev_hash: Option<&[u8; 32]>,
) -> Vec<u8> {
    let builder = Builder::new(tags::DEVICE_GRANT_APPROVED, 1)
        .uuid(grant_id)
        .fixed(&identity_id.to_bytes())
        .uuid(approver_signing_key_id)
        .key(requested_public_key);
    with_position(builder, seq, prev_hash)
        .finish()
        .expect("device grant fields fit a u32 length")
}

/// Bytes a signing-key revocation signs: tag, version 1, then `identity_id` raw, `signing_key_id`
/// uuid, `revoked_by_signing_key_id` uuid, and the chain position.
pub fn signing_key_revoked_signing_bytes(
    identity_id: &IdentityId,
    signing_key_id: Uuid,
    revoked_by_signing_key_id: Uuid,
    seq: u64,
    prev_hash: Option<&[u8; 32]>,
) -> Vec<u8> {
    let builder = Builder::new(tags::IDENTITY_SIGNING_KEY_REVOKED, 1)
        .fixed(&identity_id.to_bytes())
        .uuid(signing_key_id)
        .uuid(revoked_by_signing_key_id);
    with_position(builder, seq, prev_hash)
        .finish()
        .expect("signing key revocation fields fit a u32 length")
}
