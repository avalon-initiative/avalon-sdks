// Self-certifying identity ids: lowercase hex SHA-256 of "avalon-identity-id-v1" and the
// identity's inception Ed25519 public key. Parsing is strict and never normalises.
// conformance/vectors/identity-id.json is the shared arbiter.
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, concatBytes } from '@noble/hashes/utils.js'

/** A validated identity id: exactly 64 lowercase hex characters. Obtain one with `parseIdentityId`,
 * `deriveIdentityId` or from a validated server response; a plain string does not satisfy it. */
export type IdentityId = string & { readonly __brand: 'IdentityId' }

const IDENTITY_ID_PATTERN = /^[0-9a-f]{64}$/
const DOMAIN_TAG = new TextEncoder().encode('avalon-identity-id-v1')

/** Whether `text` is a canonical identity id (uppercase, other lengths, `id:`/`node:` prefixes, UUID text
 * and surrounding whitespace or newlines are all rejected). */
export function isIdentityId(text: unknown): text is IdentityId {
  return typeof text === 'string' && IDENTITY_ID_PATTERN.test(text)
}

/** Strictly parses an identity id; throws a `TypeError` for anything but the canonical form. */
export function parseIdentityId(text: unknown): IdentityId {
  if (!isIdentityId(text)) {
    throw new TypeError('identity id must be exactly 64 lowercase hex characters')
  }
  return text
}

/** Derives the id of the identity whose inception key is `publicKey` (32 raw bytes). A pure hash: it
 * does not check key acceptability, see `isAcceptableIdentityKey`. */
export function deriveIdentityId(publicKey: Uint8Array): IdentityId {
  if (publicKey.length !== 32) {
    throw new TypeError('an Ed25519 public key is exactly 32 bytes')
  }
  return bytesToHex(sha256(concatBytes(DOMAIN_TAG, publicKey))) as IdentityId
}

/** Whether `id` is the one derived from `publicKey`. */
export function identityIdMatchesKey(id: IdentityId, publicKey: Uint8Array): boolean {
  return deriveIdentityId(publicKey) === id
}
