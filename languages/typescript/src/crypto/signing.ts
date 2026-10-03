// Ed25519 event-signing primitives — reimplemented here rather
// than imported from packages/api-client/src/crypto/signingKey.ts, since
// this SDK's hard invariant is zero dependency on that package. Same library
// (@noble/curves), same wire shapes.
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { parseIdentityId, type IdentityId } from '../identityId.js'

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

const encoder = new TextEncoder()

function requireKey(key: Uint8Array): string {
  if (key.length !== 32) {
    throw new TypeError('an Ed25519 public key is exactly 32 bytes')
  }
  return bytesToHex(key)
}

/** Bytes signed for `identity.created` v2:
 * `avalon:identity.created:v2:{len(networkId)}:{networkId}:{len(shardId)}:{shardId}:{ticketId}:{identityId}:{publicKeyHex}:{displayName}`
 * with `len` the decimal UTF-8 byte length (not the UTF-16 length). The public key is lowercase hex here and
 * base64 on the wire. */
export function identityCreatedSigningBytes(
  networkId: string,
  shardId: string,
  ticketId: string,
  identityId: IdentityId,
  publicKey: Uint8Array,
  displayName: string,
): Uint8Array {
  const networkLen = encoder.encode(networkId).length
  const shardLen = encoder.encode(shardId).length
  return encoder.encode(
    `avalon:identity.created:v2:${networkLen}:${networkId}:${shardLen}:${shardId}:${ticketId}:${parseIdentityId(identityId)}:${requireKey(publicKey)}:${displayName}`,
  )
}

/** Bytes the approving device signs for a grant:
 * `avalon:device_grant.approved:v2:{grantId}:{identityId}:{requestedPublicKeyHex}`. */
export function deviceGrantApprovalSigningBytes(
  grantId: string,
  identityId: IdentityId,
  requestedPublicKey: Uint8Array,
): Uint8Array {
  return encoder.encode(
    `avalon:device_grant.approved:v2:${grantId}:${parseIdentityId(identityId)}:${requireKey(requestedPublicKey)}`,
  )
}

/** Bytes a signing-key revocation signs:
 * `avalon:identity.signing_key_revoked:v2:{identityId}:{signingKeyId}:{revokedBySigningKeyId}`. */
export function signingKeyRevokedSigningBytes(
  identityId: IdentityId,
  signingKeyId: string,
  revokedBySigningKeyId: string,
): Uint8Array {
  return encoder.encode(
    `avalon:identity.signing_key_revoked:v2:${parseIdentityId(identityId)}:${signingKeyId}:${revokedBySigningKeyId}`,
  )
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
