// Witness cosignature primitives and cosigned tree head verification. Mirrors
// the protocol crate's witness and cosigned_sth modules; malformed input fails closed.
import { ed25519 } from '@noble/curves/ed25519.js'
import { concatBytes } from '@noble/hashes/utils.js'
import type { CosignedTreeHead, KnownWitness, WitnessCosignature } from '../types.js'
import { i64BigEndian, u32BigEndian, unixSecondsFromRfc3339 } from './sthMessage.js'
import { verifyTreeHead } from './verifyNetwork.js'

const DOMAIN_TAG = new TextEncoder().encode('avalon-witness-cosign-v1')
const encoder = new TextEncoder()

function hexToBytes(hex: string): Uint8Array | null {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) return null
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

function lengthPrefixed(value: string): Uint8Array {
  const bytes = encoder.encode(value)
  return concatBytes(u32BigEndian(bytes.length), bytes)
}

/** The exact bytes a witness signs. Timestamps are RFC 3339 strings, floored to unix seconds. */
export function witnessSigningMessage(cosig: Omit<WitnessCosignature, 'signature'>): Uint8Array {
  return concatBytes(
    DOMAIN_TAG,
    i64BigEndian(BigInt(cosig.tree_size)),
    lengthPrefixed(cosig.root_hash),
    lengthPrefixed(cosig.network_id),
    i64BigEndian(unixSecondsFromRfc3339(cosig.author_created_at)),
    lengthPrefixed(cosig.witness_key_id),
    i64BigEndian(unixSecondsFromRfc3339(cosig.observed_at)),
  )
}

/** Verifies one cosignature under `keyHex` (32-byte hex). False for any malformed input; never throws. */
export function verifyWitnessCosignature(keyHex: string, cosig: WitnessCosignature): boolean {
  try {
    const key = hexToBytes(keyHex)
    const signature = hexToBytes(cosig.signature)
    if (!key || key.length !== 32 || !signature || signature.length !== 64) return false
    return ed25519.verify(signature, witnessSigningMessage(cosig), key)
  } catch {
    return false
  }
}

/** Smallest strict majority of `listSize`; 0 for an empty list. */
export function majorityThreshold(listSize: number): number {
  return listSize === 0 ? 0 : Math.floor(listSize / 2) + 1
}

export function isCosignedByMajority(listSize: number, distinctWitnesses: number): boolean {
  return distinctWitnesses >= majorityThreshold(listSize)
}

function seconds(timestamp: string): bigint | null {
  try {
    return unixSecondsFromRfc3339(timestamp)
  } catch {
    return null
  }
}

function ms(timestamp: string): number {
  return Date.parse(timestamp)
}

function validFreshWitnessIds(
  authorKeyHex: string,
  head: CosignedTreeHead,
  knownList: KnownWitness[],
  freshnessCutoff: Date,
  now: Date,
): Set<string> {
  const verified = new Set<string>()
  const author = authorKeyHex.toLowerCase()
  for (const witness of knownList) {
    if (witness.key.toLowerCase() === author) verified.add(witness.witnessKeyId)
  }
  const authorTime = seconds(head.sth.created_at)
  const cutoff = freshnessCutoff.getTime()
  const latest = now.getTime()
  for (const cosig of head.cosignatures) {
    if (
      cosig.tree_size !== head.sth.tree_size ||
      cosig.root_hash !== head.sth.root_hash ||
      cosig.network_id !== head.sth.network_id ||
      authorTime === null ||
      seconds(cosig.author_created_at) !== authorTime
    ) {
      continue
    }
    const observed = ms(cosig.observed_at)
    if (Number.isNaN(observed) || observed < cutoff || observed > latest) continue
    const witness = knownList.find((candidate) => candidate.witnessKeyId === cosig.witness_key_id)
    if (witness && verifyWitnessCosignature(witness.key, cosig)) verified.add(cosig.witness_key_id)
  }
  return verified
}

/**
 * Accepts a head when the author's signature verifies and, for a known list of two or more,
 * a majority of distinct known witnesses vouch for it (a witness holding the author key counts
 * without a cosignature). A list of zero or one is the author check alone. Never throws.
 */
export function verifyCosignedTreeHead(
  authorKeyHex: string,
  head: CosignedTreeHead,
  knownList: KnownWitness[],
  freshnessCutoff: Date,
  now: Date,
): boolean {
  if (!verifyTreeHead(authorKeyHex, head.sth)) return false
  if (knownList.length <= 1) return true
  const verified = validFreshWitnessIds(authorKeyHex, head, knownList, freshnessCutoff, now)
  return isCosignedByMajority(knownList.length, verified.size)
}

/** Witness ids valid and fresh on two accepted heads with different roots at the same size; else empty. */
export function findEquivocatingWitnesses(
  authorKeyHex: string,
  knownList: KnownWitness[],
  freshnessCutoff: Date,
  now: Date,
  headA: CosignedTreeHead,
  headB: CosignedTreeHead,
): string[] {
  if (
    headA.sth.network_id !== headB.sth.network_id ||
    headA.sth.tree_size !== headB.sth.tree_size ||
    headA.sth.root_hash === headB.sth.root_hash
  ) {
    return []
  }
  if (
    !verifyCosignedTreeHead(authorKeyHex, headA, knownList, freshnessCutoff, now) ||
    !verifyCosignedTreeHead(authorKeyHex, headB, knownList, freshnessCutoff, now)
  ) {
    return []
  }
  const a = validFreshWitnessIds(authorKeyHex, headA, knownList, freshnessCutoff, now)
  const b = validFreshWitnessIds(authorKeyHex, headB, knownList, freshnessCutoff, now)
  return [...a].filter((id) => b.has(id)).sort()
}

/** How far `announced_at` may differ from the verifier's clock for an advert proof to be accepted. */
export const WITNESS_ANNOUNCE_MAX_SKEW_MS = 3_600_000

/** The exact bytes a witness announce proof covers; `announcedAt` is floored to unix seconds. */
export function witnessAnnounceMessage(baseUrl: string, witnessKeyId: string, announcedAt: Date): Uint8Array {
  return concatBytes(
    new TextEncoder().encode('avalon-witness-announce-v1'),
    lengthPrefixed(baseUrl),
    lengthPrefixed(witnessKeyId),
    i64BigEndian(BigInt(Math.floor(announcedAt.getTime() / 1000))),
  )
}

/** Verifies a witness advert proof for exactly this address and time. False for any malformed input; never throws. */
export function verifyWitnessAnnounce(
  baseUrl: string,
  witnessKeyId: string,
  announcedAt: Date,
  proofHex: string,
  now: Date,
): boolean {
  try {
    const skew = Math.abs(now.getTime() - announcedAt.getTime())
    if (Number.isNaN(skew) || skew > WITNESS_ANNOUNCE_MAX_SKEW_MS) return false
    const key = hexToBytes(witnessKeyId)
    const proof = hexToBytes(proofHex)
    if (!key || key.length !== 32 || !proof || proof.length !== 64) return false
    return ed25519.verify(proof, witnessAnnounceMessage(baseUrl, witnessKeyId, announcedAt), key)
  } catch {
    return false
  }
}
