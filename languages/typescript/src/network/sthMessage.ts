// Byte-for-byte reconstruction of the message an STH's signature covers: the structured layout with
// tag `avalon.settlement.sth`. conformance/vectors/signed-tree-head.json is the shared arbiter.
import { Builder, envelopeFromWire, tags } from '../crypto/signingBytes.js'
import type { SignedTreeHeadResponse } from '../types.js'

const ROOT_HASH = /^[0-9a-f]{64}$/

/** Lowercase hex text to raw bytes; the caller has checked it is well formed. */
export function hexBytes(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../g) ?? [], (h) => parseInt(h, 16))
}

/**
 * `OffsetDateTime::unix_timestamp()` on the Rust side is whole seconds,
 * truncating any sub-second component — an RFC 3339 string with fractional
 * seconds must be floored the same way here, not rounded, so a signature
 * produced from a timestamp with a fractional part still verifies.
 */
export function unixSecondsFromRfc3339(createdAt: string): bigint {
  const ms = Date.parse(createdAt)
  if (Number.isNaN(ms)) {
    throw new Error(`Not a valid RFC 3339 timestamp: ${createdAt}`)
  }
  return BigInt(Math.floor(ms / 1000))
}

/**
 * The exact bytes an STH's signature covers (tag `avalon.settlement.sth`): `tree_size` i64, `network_id` and
 * `signing_key_id` as strings, `created_at` as i64 unix seconds, the `hash_algo` byte of the tree and the root
 * hash as 32 raw bytes, then the extensions region. Throws for a root hash that is not exactly 64 lowercase hex
 * characters, or an envelope this SDK cannot read (`SigningBytesError`).
 */
export function signingMessage(sth: SignedTreeHeadResponse): Uint8Array {
  if (!ROOT_HASH.test(sth.root_hash)) throw new TypeError('root_hash is not 64 lowercase hex characters')
  const envelope = envelopeFromWire(tags.SETTLEMENT_STH, sth)
  return Builder.withEnvelope(tags.SETTLEMENT_STH, envelope)
    .i64(BigInt(sth.tree_size))
    .str(sth.network_id)
    .str(sth.signing_key_id)
    .i64(unixSecondsFromRfc3339(sth.created_at))
    .hashAlgo(envelope.hashAlgo)
    .hash(hexBytes(sth.root_hash))
    .finish()
}
