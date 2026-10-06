// Ed25519 event-signing primitives — reimplemented here rather
// than imported from packages/api-client/src/crypto/signingKey.ts, since
// this SDK's hard invariant is zero dependency on that package. Same library
// (@noble/curves), same wire shapes.
import { ed25519 } from '@noble/curves/ed25519.js'
import { hexToBytes } from '@noble/hashes/utils.js'
import { parseIdentityId, type IdentityId } from '../identityId.js'
import { Builder, tags } from './signingBytes.js'

export interface SigningKeyPair {
  secretKey: Uint8Array
  publicKey: Uint8Array
}

export function generateSigningKey(): SigningKeyPair {
  return ed25519.keygen()
}

export function publicKeyFromSecretKey(secretKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(secretKey)
}

export function sign(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, secretKey)
}

export function verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  return ed25519.verify(signature, message, publicKey)
}

// btoa/atob (not Buffer, which browsers don't have) so this module works
// unmodified in both a browser and Node — both provide these globals.
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
}

export function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

/**
 * Builds the canonical `avalon:<action_tag>:v1:<field1>:<field2>:...` byte
 * string a signature-required action signs — must match
 * `signature_gate::canonical_message` in `crates/server/src/signature_gate.rs`
 * byte-for-byte (see docs/architecture/identity.md's #697/#698 sections).
 */
export function canonicalMessage(actionTag: string, fields: string[]): Uint8Array {
  const parts = [`avalon:${actionTag}:v1`, ...fields]
  return new TextEncoder().encode(parts.join(':'))
}

/** The `signing_key_id`/`signature` pair every signature-required request
 * body carries — both `undefined` (serialized as JSON `null`) when the
 * session holds no local signing key. */
export interface SignatureFields {
  signing_key_id: string | null
  signature: string | null
}

function identityIdBytes(identityId: IdentityId): Uint8Array {
  return hexToBytes(parseIdentityId(identityId))
}

/** Appends the identity-chain position a key event claims: `seq` u64, then `prev_hash` as a flag byte
 * (0, or 1 followed by 32 raw bytes). `prevHash` is null for the first chained event. */
function withPosition(builder: Builder, seq: bigint | number, prevHash: Uint8Array | null): Builder {
  builder.u64(seq)
  return prevHash === null ? builder.u8(0) : builder.u8(1).hash(prevHash)
}

/** Bytes signed for `identity.created` (tag `avalon.identity.created`, version 1): network id and shard id
 * as `str`, the ticket id as uuid (also the inception key's id), the identity id and inception public key
 * as 32 raw bytes each, then the display name as `str`. */
export function identityCreatedSigningBytes(
  networkId: string,
  shardId: string,
  ticketId: string,
  identityId: IdentityId,
  publicKey: Uint8Array,
  displayName: string,
): Uint8Array {
  return new Builder(tags.IDENTITY_CREATED, 1)
    .str(networkId)
    .str(shardId)
    .uuid(ticketId)
    .fixed(identityIdBytes(identityId), 32)
    .key(publicKey)
    .str(displayName)
    .finish()
}

/** Bytes the approving device signs for a grant (tag `avalon.device_grant.approved`, version 1): grant id
 * uuid (also the new key's id), identity id (32 raw), approver key id uuid, the requested public key (32 raw),
 * then the chain position the approval will occupy. */
export function deviceGrantApprovalSigningBytes(
  grantId: string,
  identityId: IdentityId,
  approverSigningKeyId: string,
  requestedPublicKey: Uint8Array,
  seq: bigint | number,
  prevHash: Uint8Array | null,
): Uint8Array {
  const builder = new Builder(tags.DEVICE_GRANT_APPROVED, 1)
    .uuid(grantId)
    .fixed(identityIdBytes(identityId), 32)
    .uuid(approverSigningKeyId)
    .key(requestedPublicKey)
  return withPosition(builder, seq, prevHash).finish()
}

/** Bytes a signing-key revocation signs (tag `avalon.identity.signing_key_revoked`, version 1): identity id
 * (32 raw), the revoked key id uuid, the revoking key id uuid, then the chain position. */
export function signingKeyRevokedSigningBytes(
  identityId: IdentityId,
  signingKeyId: string,
  revokedBySigningKeyId: string,
  seq: bigint | number,
  prevHash: Uint8Array | null,
): Uint8Array {
  const builder = new Builder(tags.IDENTITY_SIGNING_KEY_REVOKED, 1)
    .fixed(identityIdBytes(identityId), 32)
    .uuid(signingKeyId)
    .uuid(revokedBySigningKeyId)
  return withPosition(builder, seq, prevHash).finish()
}

/** Strictly decodes a standard-base64 32-byte Ed25519 public key; throws otherwise. */
export function decodePublicKey(publicKeyB64: string): Uint8Array {
  let bytes: Uint8Array
  try {
    bytes = base64ToBytes(publicKeyB64)
  } catch {
    throw new TypeError('public key must be standard base64 of exactly 32 bytes')
  }
  if (bytes.length !== 32 || bytesToBase64(bytes) !== publicKeyB64) {
    throw new TypeError('public key must be standard base64 of exactly 32 bytes')
  }
  return bytes
}
