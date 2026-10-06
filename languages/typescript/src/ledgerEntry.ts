// The ledger entry hash: tag `avalon.ledger.entry`, the entry's own `version` in the u16 slot, then
// network id, shard id, seq u64, prev hash (32 raw), event id (16 raw), kind, issuer, subject, payload
// hash (32 raw), event time as i64 unix microseconds. Matches avalon_protocol::ledger_entry;
// conformance/vectors/ledger-entry-hash.json is the shared arbiter.
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { canonicalize } from './canonicalPayload.js'
import { Builder, tags } from './crypto/signingBytes.js'

export type EntryHashErrorCode = 'invalid_hash' | 'out_of_range'

/** Why an entry hash could not be computed; `code` is the shared vector error code. */
export class EntryHashError extends Error {
  constructor(
    public readonly code: EntryHashErrorCode,
    message: string,
  ) {
    super(message)
    this.name = 'EntryHashError'
  }
}

/** Every field the entry hash covers. */
export interface EntryHashInput {
  networkId: string
  shardId: string
  seq: bigint | number
  /** 32 raw bytes; use `parseHash` for lowercase hex text. */
  prevHash: Uint8Array
  /** Canonical UUID text. */
  eventId: string
  kind: string
  issuer: string
  subject: string
  /** 32 raw bytes: `payloadHash` of the canonical payload, or a skeleton row's stored hash. */
  payloadHash: Uint8Array
  timestampMicros: bigint | number
  version: number
}

/** SHA-256 of the canonical payload bytes: what an entry commits to in place of the payload. */
export function payloadHash(payload: unknown): Uint8Array {
  return sha256(new TextEncoder().encode(canonicalize(payload)))
}

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$/

/** Unix microseconds of an RFC 3339 instant, truncated toward negative infinity (the precision the
 * ledger stores). A JS `Date` only carries milliseconds, so the text is parsed directly. */
export function timestampMicrosFromRfc3339(text: string): bigint {
  const m = RFC3339.exec(text)
  if (!m) throw new EntryHashError('out_of_range', 'timestamp is not an RFC 3339 instant')
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number)
  const zone = m[8]
  const zoneHour = zone.length === 6 ? Number(zone.slice(1, 3)) : 0
  const zoneMinute = zone.length === 6 ? Number(zone.slice(4, 6)) : 0
  // A leap second counts as 23:59:59.999999999 UTC on a month's last day, like Rust's time crate; else invalid.
  const leap = second === 60
  const date = new Date(0)
  date.setUTCFullYear(year, month - 1, day)
  date.setUTCHours(hour, minute, leap ? 59 : second, 0)
  if (
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day ||
    hour > 23 ||
    minute > 59 ||
    second > 60 ||
    zoneHour > 23 ||
    zoneMinute > 59
  ) {
    throw new EntryHashError('out_of_range', 'timestamp is not a valid calendar instant')
  }
  let seconds = BigInt(date.getTime() / 1000)
  if (zone !== 'Z' && zone !== 'z') {
    const offset = (zoneHour * 60 + zoneMinute) * 60
    seconds -= BigInt(zone[0] === '-' ? -offset : offset)
  }
  if (leap) {
    const utc = new Date(Number(seconds) * 1000)
    const nextDay = new Date(utc.getTime() + 1000)
    if (utc.getUTCHours() !== 23 || utc.getUTCMinutes() !== 59 || nextDay.getUTCDate() !== 1) {
      throw new EntryHashError('out_of_range', 'a leap second is only valid at the end of a UTC month')
    }
  }
  const micros = leap ? 999_999n : BigInt((m[7] ?? '').padEnd(6, '0').slice(0, 6))
  return checkI64(seconds * 1_000_000n + micros, 'timestamp')
}

function checkI64(value: bigint, name: string): bigint {
  if (BigInt.asIntN(64, value) !== value) {
    throw new EntryHashError('out_of_range', `${name} is out of range for the entry layout`)
  }
  return value
}

function toBigInt(value: bigint | number, name: string): bigint {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) {
    throw new EntryHashError('out_of_range', `${name} is out of range for the entry layout`)
  }
  return BigInt(value)
}

/** Parses a 64-character lowercase hex hash into its raw bytes. */
export function parseHash(name: string, text: string): Uint8Array {
  if (typeof text !== 'string' || !/^[0-9a-f]{64}$/.test(text)) {
    throw new EntryHashError('invalid_hash', `${name} is not a 32-byte lowercase hex hash`)
  }
  const out = new Uint8Array(32)
  for (let i = 0; i < 32; i += 1) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16)
  return out
}

/** The exact bytes the entry hash is the SHA-256 of. */
export function entrySigningBytes(input: EntryHashInput): Uint8Array {
  const seq = toBigInt(input.seq, 'seq')
  if (seq < 0n || seq >= 1n << 64n) {
    throw new EntryHashError('out_of_range', 'seq is out of range for the entry layout')
  }
  if (!Number.isInteger(input.version) || input.version < 0 || input.version > 0xffff) {
    throw new EntryHashError('out_of_range', 'version is out of range for the entry layout')
  }
  const micros = checkI64(toBigInt(input.timestampMicros, 'timestamp'), 'timestamp')
  return new Builder(tags.LEDGER_ENTRY, input.version)
    .str(input.networkId)
    .str(input.shardId)
    .u64(seq)
    .hash(input.prevHash)
    .uuid(input.eventId)
    .str(input.kind)
    .str(input.issuer)
    .str(input.subject)
    .hash(input.payloadHash)
    .i64(micros)
    .finish()
}

/** The entry hash: SHA-256 of `entrySigningBytes`. */
export function entryHash(input: EntryHashInput): Uint8Array {
  return sha256(entrySigningBytes(input))
}

/** Lowercase hex of `entryHash`. */
export function entryHashHex(input: EntryHashInput): string {
  return bytesToHex(entryHash(input))
}
