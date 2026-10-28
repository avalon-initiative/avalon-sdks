// Witness cosignature primitives and cosigned tree head verification. Mirrors
// the protocol crate's witness and cosigned_sth modules; malformed input fails closed.
import { Builder, envelopeFromWire, tags } from '../crypto/signingBytes.js'
import type { CosignedTreeHead, KnownWitness, SignedTreeHeadResponse, WitnessCosignature } from '../types.js'
import { hexBytes, unixSecondsFromRfc3339 } from './sthMessage.js'
import { verifyStrict } from './strictEd25519.js'
import { verifyTreeHead } from './verifyNetwork.js'

function hexToBytes(hex: string): Uint8Array | null {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) return null
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

/**
 * The exact bytes a witness signs (tag `avalon.witness.cosign`): the head's tree size, network id, created_at,
 * author key id and signature, the witness key id and key, `observed_at`, the head's `hash_algo` and root hash,
 * then the extensions region. Timestamps are RFC 3339 strings, floored to unix seconds. `witnessKeyHex` is the
 * witness's 32-byte verifying key. Throws on a malformed field or an envelope this SDK cannot read.
 */
export function witnessSigningMessage(cosig: Omit<WitnessCosignature, 'signature'>, witnessKeyHex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(cosig.root_hash)) throw new TypeError('root_hash is not 64 lowercase hex characters')
  const authorSignature = hexToBytes(cosig.author_signature)
  const witnessKey = hexToBytes(witnessKeyHex)
  if (!authorSignature || authorSignature.length !== 64) throw new TypeError('author_signature is not 64 bytes of hex')
  if (!witnessKey || witnessKey.length !== 32) throw new TypeError('witness key is not 32 bytes of hex')
  const envelope = envelopeFromWire(tags.WITNESS_COSIGN, cosig)
  return Builder.withEnvelope(tags.WITNESS_COSIGN, envelope)
    .i64(BigInt(cosig.tree_size))
    .str(cosig.network_id)
    .i64(unixSecondsFromRfc3339(cosig.author_created_at))
    .str(cosig.author_key_id)
    .signature(authorSignature)
    .str(cosig.witness_key_id)
    .key(witnessKey)
    .i64(unixSecondsFromRfc3339(cosig.observed_at))
    .hashAlgo(envelope.hashAlgo)
    .hash(hexBytes(cosig.root_hash))
    .finish()
}

/** Verifies one cosignature under `keyHex` (32-byte hex). False for any malformed input; never throws. */
export function verifyWitnessCosignature(keyHex: string, cosig: WitnessCosignature): boolean {
  try {
    const key = hexToBytes(keyHex)
    const signature = hexToBytes(cosig.signature)
    if (!key || key.length !== 32 || !signature || signature.length !== 64) return false
    return verifyStrict(key, witnessSigningMessage(cosig, keyHex), signature)
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

// A cosignature this SDK cannot read, or over another hash algorithm than the head's, never counts.
function sameHashAlgo(cosig: WitnessCosignature, sth: SignedTreeHeadResponse): boolean {
  try {
    return envelopeFromWire(tags.WITNESS_COSIGN, cosig).hashAlgo === envelopeFromWire(tags.SETTLEMENT_STH, sth).hashAlgo
  } catch {
    return false
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
      cosig.author_key_id !== head.sth.signing_key_id ||
      cosig.author_signature.toLowerCase() !== head.sth.signature.toLowerCase() ||
      authorTime === null ||
      seconds(cosig.author_created_at) !== authorTime ||
      !sameHashAlgo(cosig, head.sth)
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

/** The exact bytes a witness announce proof covers (tag `avalon.witness.announce`): the base url as a string,
 * the witness key (algorithm byte, 32 raw bytes) and `announced_at` as i64 unix seconds. `witnessKeyId` must be
 * the 64 lowercase hex characters of the key; throws otherwise. */
export function witnessAnnounceMessage(baseUrl: string, witnessKeyId: string, announcedAt: Date): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(witnessKeyId)) throw new TypeError('witness key id is not 64 lowercase hex characters')
  return new Builder(tags.WITNESS_ANNOUNCE, 1)
    .str(baseUrl)
    .key(hexBytes(witnessKeyId))
    .i64(BigInt(Math.floor(announcedAt.getTime() / 1000)))
    .finish()
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
    return verifyStrict(key, witnessAnnounceMessage(baseUrl, witnessKeyId, announcedAt), proof)
  } catch {
    return false
  }
}
