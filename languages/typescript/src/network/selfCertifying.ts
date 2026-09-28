// Verification of tree heads of self-certifying `node:<sha256-of-key>` shards. The id is
// `node:` plus the lowercase hex SHA-256 of the raw 32-byte Ed25519 public key that signs the
// shard's heads; a node serves that key as the optional `signing_public_key` next to a head
// (outside the signed bytes). The key must hash to the id and must have signed the head: no
// trust anchor, registry or witness list is involved.
// conformance/vectors/self-certifying-tree-head.json is the shared arbiter.
import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import type { SignedTreeHeadResponse } from '../types.js'
import { verifyTreeHead } from './verifyNetwork.js'

/** Why a self-certifying head was not verified; checks run in this order and the first failure is reported. */
export type SelfCertifyingFailure =
  // The shard id is not a valid `node:<64 lowercase hex>` id.
  | 'not_self_certifying'
  // No signing key was presented with the head.
  | 'missing_key'
  // The key is not exactly 64 lowercase hex characters decoding to a valid Ed25519 point.
  | 'malformed_key'
  // SHA-256 of the key does not equal the hash in the shard id.
  | 'key_id_mismatch'
  // The key did not sign this head.
  | 'bad_signature'

export type SelfCertifyingResult = { verified: true } | { verified: false; failure: SelfCertifyingFailure }

/** Which verification applies to a shard id. `core` uses the network and witness verification
 * (`AvalonClient.verifyNetwork`); every other kind, and any malformed id, is `unsupported` and never verifies here. */
export type ShardCheck = 'self_certifying' | 'core_network' | 'unsupported'

const NODE_ID = /^node:([0-9a-f]{64})$/
const LOWERCASE_KEY = /^[0-9a-f]{64}$/

/** Which check applies to `shardId`; an unsupported kind is reported, never passed. */
export function shardCheck(shardId: string): ShardCheck {
  if (shardId === 'core') return 'core_network'
  return NODE_ID.test(shardId) ? 'self_certifying' : 'unsupported'
}

/** The `node:` id a 32-byte Ed25519 public key certifies. */
export function selfCertifyingId(publicKey: Uint8Array): string {
  return `node:${bytesToHex(sha256(publicKey))}`
}

function parseKey(keyHex: string): Uint8Array | null {
  if (!LOWERCASE_KEY.test(keyHex)) return null
  try {
    const key = hexToBytes(keyHex)
    ed25519.Point.fromBytes(key)
    return key
  } catch {
    return null
  }
}

/**
 * Verifies `sth` as a head of the self-certifying shard `shardId` using only the presented key:
 * `signingPublicKey` when given, otherwise `sth.signing_public_key`. Never throws.
 */
export function verifySelfCertifyingTreeHead(
  shardId: string,
  sth: SignedTreeHeadResponse,
  signingPublicKey?: string | null,
): SelfCertifyingResult {
  const fail = (failure: SelfCertifyingFailure): SelfCertifyingResult => ({ verified: false, failure })
  const match = NODE_ID.exec(shardId)
  if (!match) return fail('not_self_certifying')
  const keyHex = signingPublicKey ?? sth.signing_public_key
  if (keyHex === undefined || keyHex === null) return fail('missing_key')
  const key = parseKey(keyHex)
  if (!key) return fail('malformed_key')
  if (bytesToHex(sha256(key)) !== match[1]) return fail('key_id_mismatch')
  if (!verifyTreeHead(keyHex, sth)) return fail('bad_signature')
  return { verified: true }
}
