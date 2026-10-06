// Structured signing bytes: one fixed binary layout for every signed or hashed message, matching
// avalon_protocol::signing_bytes. Layout: tag (ASCII, no length) | version u16 BE | fields in order.
// conformance/vectors/structured-signing-bytes.json and domain-tags.json are the shared arbiters.
import { concatBytes } from '@noble/hashes/utils.js'

export type SigningBytesErrorCode = 'field_too_long' | 'tag_mismatch' | 'truncated' | 'invalid_utf8' | 'trailing_bytes'

/** Why building or reading structured signing bytes failed; `code` is the shared vector error code. */
export class SigningBytesError extends Error {
  constructor(
    public readonly code: SigningBytesErrorCode,
    message: string,
  ) {
    super(message)
    this.name = 'SigningBytesError'
  }
}

const TAG_PATTERN = /^[a-z0-9._]{1,255}$/

/** A registered domain tag. Only the `tags` registry below constructs one. */
export class DomainTag {
  readonly bytes: Uint8Array

  /** @internal */
  constructor(readonly name: string) {
    if (!TAG_PATTERN.test(name)) {
      throw new TypeError('a domain tag is 1 to 255 bytes of [a-z0-9._]')
    }
    this.bytes = new TextEncoder().encode(name)
  }
}

/** The registry of domain tags: one distinct tag per signed kind. */
export const tags = {
  IDENTITY_CREATED: new DomainTag('avalon.identity.created'),
  DEVICE_GRANT_APPROVED: new DomainTag('avalon.device_grant.approved'),
  IDENTITY_SIGNING_KEY_REVOKED: new DomainTag('avalon.identity.signing_key_revoked'),
  CROSS_NODE_LOGIN: new DomainTag('avalon.cross_node_login'),
  SESSION_CONTINUATION: new DomainTag('avalon.session_continuation'),
  INTEREST_CLAIM: new DomainTag('avalon.interest_claim'),
  ATTESTATION_ISSUE: new DomainTag('avalon.attestation.issue'),
  ATTESTATION_BULK_ISSUE: new DomainTag('avalon.attestation.bulk_issue'),
  ATTESTATION_REVOKE: new DomainTag('avalon.attestation.revoke'),
  ISSUER_REGISTERED: new DomainTag('avalon.issuer.registered'),
  SIGNATURE_GATE_ACTION: new DomainTag('avalon.signature_gate.action'),
  INTEGRATOR_NONCE_CHALLENGE: new DomainTag('avalon.integrator.nonce_challenge'),
  LEDGER_ENTRY: new DomainTag('avalon.ledger.entry'),
  /** Reserved for conformance vectors; no key ever signs it in production. */
  CONFORMANCE: new DomainTag('avalon.conformance.vector'),
} as const

/** Every registered tag, in registry order. */
export const ALL_TAGS: readonly DomainTag[] = Object.values(tags)

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const U32_MAX = 0xffff_ffff
const U64_MAX = (1n << 64n) - 1n
const I64_MIN = -(1n << 63n)
const I64_MAX = (1n << 63n) - 1n

const encoder = new TextEncoder()
// fatal: no lossy decoding; ignoreBOM: a leading U+FEFF is data, not a marker to strip.
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

function toBigInt(value: bigint | number, name: string): bigint {
  if (typeof value === 'bigint') return value
  if (!Number.isSafeInteger(value)) throw new RangeError(`${name} must be an integer`)
  return BigInt(value)
}

function checkRange(value: bigint, min: bigint, max: bigint, name: string): bigint {
  if (value < min || value > max) throw new RangeError(`${name} is out of range`)
  return value
}

function requireWidth(value: Uint8Array, width: number, name: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== width) {
    throw new TypeError(`${name} must be exactly ${width} bytes`)
  }
  return value
}

/** Parses canonical UUID text (lowercase, hyphenated) into its 16 raw bytes; throws otherwise. */
export function uuidToBytes(text: string, name = 'uuid'): Uint8Array {
  if (typeof text !== 'string' || !UUID_PATTERN.test(text)) {
    throw new TypeError(`${name} must be a lowercase hyphenated UUID`)
  }
  const hex = text.replace(/-/g, '')
  const bytes = new Uint8Array(16)
  for (let i = 0; i < 16; i += 1) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return bytes
}

function bytesToUuid(bytes: Uint8Array): string {
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

// TextEncoder replaces a lone surrogate with U+FFFD, which would silently change signed bytes.
function utf8(value: string, name: string): Uint8Array {
  if (typeof value !== 'string') throw new TypeError(`${name} must be a string`)
  for (let i = 0; i < value.length; i += 1) {
    const c = value.charCodeAt(i)
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = value.charCodeAt(i + 1)
      if (next >= 0xdc00 && next <= 0xdfff) {
        i += 1
        continue
      }
      throw new TypeError(`${name} contains a lone surrogate`)
    }
    if (c >= 0xdc00 && c <= 0xdfff) throw new TypeError(`${name} contains a lone surrogate`)
  }
  return encoder.encode(value)
}

function be(value: bigint, width: number): Uint8Array {
  const out = new Uint8Array(width)
  let rest = BigInt.asUintN(width * 8, value)
  for (let i = width - 1; i >= 0; i -= 1) {
    out[i] = Number(rest & 0xffn)
    rest >>= 8n
  }
  return out
}

/** Writes fields after the tag and version, in call order. */
export class Builder {
  private readonly chunks: Uint8Array[]

  constructor(tag: DomainTag, version: number) {
    this.chunks = [tag.bytes, be(checkRange(toBigInt(version, 'version'), 0n, 0xffffn, 'version'), 2)]
  }

  private push(chunk: Uint8Array): this {
    this.chunks.push(chunk)
    return this
  }

  /** UTF-8 text, `u32 BE` length then bytes. */
  str(value: string): this {
    return this.bytes(utf8(value, 'string field'))
  }

  /** Variable-length bytes, `u32 BE` length then bytes. */
  bytes(value: Uint8Array): this {
    if (!(value instanceof Uint8Array)) throw new TypeError('bytes field must be a Uint8Array')
    if (value.length > U32_MAX) {
      throw new SigningBytesError('field_too_long', 'a field is longer than u32::MAX bytes')
    }
    this.push(be(BigInt(value.length), 4))
    return this.push(value)
  }

  /** A fixed-width field written raw with no length; `width` is part of the layout, never caller data. */
  fixed(value: Uint8Array, width: number): this {
    return this.push(requireWidth(value, width, 'fixed field'))
  }

  /** A 32-byte public key, raw. */
  key(value: Uint8Array): this {
    return this.push(requireWidth(value, 32, 'key'))
  }

  /** A 32-byte hash, raw. */
  hash(value: Uint8Array): this {
    return this.push(requireWidth(value, 32, 'hash'))
  }

  /** A UUID (canonical text) as its 16 raw bytes. */
  uuid(value: string): this {
    return this.push(uuidToBytes(value))
  }

  u8(value: bigint | number): this {
    return this.push(be(checkRange(toBigInt(value, 'u8'), 0n, 0xffn, 'u8'), 1))
  }

  u16(value: bigint | number): this {
    return this.push(be(checkRange(toBigInt(value, 'u16'), 0n, 0xffffn, 'u16'), 2))
  }

  u32(value: bigint | number): this {
    return this.push(be(checkRange(toBigInt(value, 'u32'), 0n, 0xffff_ffffn, 'u32'), 4))
  }

  u64(value: bigint | number): this {
    return this.push(be(checkRange(toBigInt(value, 'u64'), 0n, U64_MAX, 'u64'), 8))
  }

  i64(value: bigint | number): this {
    return this.push(be(checkRange(toBigInt(value, 'i64'), I64_MIN, I64_MAX, 'i64'), 8))
  }

  finish(): Uint8Array {
    return concatBytes(...this.chunks)
  }
}

/** Reads fields in the order the layout defines. Checks a declared length against the remaining bytes first. */
export class Reader {
  private rest: Uint8Array
  /** The reader accepts any version; the caller must check it before reading fields. */
  readonly version: number

  /** Checks the tag and reads the version. */
  constructor(tag: DomainTag, message: Uint8Array) {
    const tagBytes = tag.bytes
    if (message.length < tagBytes.length || !tagBytes.every((b, i) => message[i] === b)) {
      throw new SigningBytesError('tag_mismatch', 'message does not start with the expected domain tag')
    }
    this.rest = message.subarray(tagBytes.length)
    const v = this.take(2)
    this.version = (v[0] << 8) | v[1]
  }

  private take(len: number): Uint8Array {
    if (this.rest.length < len) {
      throw new SigningBytesError('truncated', 'message ends before the field does')
    }
    const head = this.rest.subarray(0, len)
    this.rest = this.rest.subarray(len)
    return head
  }

  private takeUint(width: number): bigint {
    let value = 0n
    for (const b of this.take(width)) value = (value << 8n) | BigInt(b)
    return value
  }

  bytes(): Uint8Array {
    return this.take(Number(this.takeUint(4)))
  }

  str(): string {
    const raw = this.bytes()
    try {
      return decoder.decode(raw)
    } catch {
      throw new SigningBytesError('invalid_utf8', 'string field is not valid UTF-8')
    }
  }

  fixed(width: number): Uint8Array {
    return this.take(width)
  }

  key(): Uint8Array {
    return this.take(32)
  }

  hash(): Uint8Array {
    return this.take(32)
  }

  uuid(): string {
    return bytesToUuid(this.take(16))
  }

  u8(): number {
    return Number(this.takeUint(1))
  }

  u16(): number {
    return Number(this.takeUint(2))
  }

  u32(): number {
    return Number(this.takeUint(4))
  }

  u64(): bigint {
    return this.takeUint(8)
  }

  i64(): bigint {
    return BigInt.asIntN(64, this.takeUint(8))
  }

  /** Errors when any bytes remain, so a message cannot carry hidden trailing data. */
  finish(): void {
    if (this.rest.length !== 0) {
      throw new SigningBytesError('trailing_bytes', 'bytes remain after the last field')
    }
  }
}
