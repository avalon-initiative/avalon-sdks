// Structured signing bytes: one fixed binary layout for every signed or hashed message, matching
// avalon_protocol::signing_bytes. Layout: tag | layout u16 | rules u32 | fields | extensions region.
// conformance/vectors/{structured-signing-bytes,envelope,domain-tags}.json are the shared arbiters.
import { concatBytes } from '@noble/hashes/utils.js'

export type SigningBytesErrorCode =
  | 'field_too_long'
  | 'tag_mismatch'
  | 'truncated'
  | 'invalid_utf8'
  | 'trailing_bytes'
  | 'needs_newer_version'
  | 'unsupported_version'
  | 'extensions_unsorted'
  | 'extension_duplicate'
  | 'extension_reserved_flags'
  | 'extensions_too_large'

/** Which part of a message needs a newer (or is below the supported) version. */
export type VersionKind = 'layout' | 'rules' | 'hash_algo' | 'sig_algo' | 'critical_extension'

/** Why building or reading structured signing bytes failed; `code` is the shared vector error code. */
export class SigningBytesError extends Error {
  constructor(
    public readonly code: SigningBytesErrorCode,
    message: string,
    /** For `needs_newer_version` and `unsupported_version`: the part concerned. */
    public readonly what?: VersionKind,
    /** The version, algorithm id or extension type that is required (newer) or was found (below range). */
    public readonly value?: number,
  ) {
    super(message)
    this.name = 'SigningBytesError'
  }
}

/** The rules version this SDK authors under, and the range it verifies. */
export const RULES_VERSION = 1
export const RULES_VERSION_MIN = 1
export const RULES_VERSION_MAX = 1
/** `hash_algo` byte for SHA-256, the only hash algorithm defined. */
export const HASH_ALGO_SHA256 = 1
/** Algorithm byte written in front of every key and signature (Ed25519). */
export const SIG_ALGO_ED25519 = 1

const EXTENSION_ENTRY_HEADER = 7
const CRITICAL_FLAG = 0x01
/** `[first rules version, extension byte cap]` rows, ascending; a cap is only ever raised for newer rules. */
const EXTENSION_CAPS: readonly (readonly [number, number])[] = [[1, 4096]]

/** The size cap of a message's extension entries (7 header bytes plus the value each). */
export function maxExtensionBytes(rulesVersion: number): number {
  const row = [...EXTENSION_CAPS].reverse().find(([from]) => from <= rulesVersion) ?? EXTENSION_CAPS[0]
  return row[1]
}

/** One extension entry. */
export interface Extension {
  type: number
  critical: boolean
  value: Uint8Array
}

function needsNewer(what: VersionKind, required: number): SigningBytesError {
  return new SigningBytesError('needs_newer_version', `needs a newer version: ${what} ${required}`, what, required)
}

function checkHashAlgo(id: number): number {
  if (id !== HASH_ALGO_SHA256) throw needsNewer('hash_algo', id)
  return id
}

function checkSigAlgo(id: number): void {
  if (id !== SIG_ALGO_ED25519) throw needsNewer('sig_algo', id)
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
  IDENTITY_CHAIN_EVENT: new DomainTag('avalon.identity.chain_event'),
  IDENTITY_KEY_EVENT: new DomainTag('avalon.identity.key_event'),
  SETTLEMENT_STH: new DomainTag('avalon.settlement.sth'),
  WITNESS_COSIGN: new DomainTag('avalon.witness.cosign'),
  WITNESS_ANNOUNCE: new DomainTag('avalon.witness.announce'),
  /** Reserved for conformance vectors; no key ever signs it in production. */
  CONFORMANCE: new DomainTag('avalon.conformance.vector'),
} as const

/** Every registered tag, in registry order. */
export const ALL_TAGS: readonly DomainTag[] = Object.values(tags)

/** Supported layout versions of a tag; the conformance tag spans 1..2 so an older layout can verify beside the newest. */
export function layoutVersions(tag: DomainTag): { min: number; max: number } {
  return tag === tags.CONFORMANCE ? { min: 1, max: 2 } : { min: 1, max: 1 }
}

function checkLayout(tag: DomainTag, version: number): void {
  const { min, max } = layoutVersions(tag)
  if (version > max) throw needsNewer('layout', version)
  if (version < min) {
    throw new SigningBytesError('unsupported_version', `unsupported layout ${version}`, 'layout', version)
  }
}

function checkRules(version: number): void {
  if (version > RULES_VERSION_MAX) throw needsNewer('rules', version)
  if (version < RULES_VERSION_MIN) {
    throw new SigningBytesError('unsupported_version', `unsupported rules ${version}`, 'rules', version)
  }
}

/** Validates a region's entries in the shared order: size per entry, then order and duplicates. */
function checkExtensions(entries: readonly Extension[], rulesVersion: number): void {
  const max = maxExtensionBytes(rulesVersion)
  let total = 0
  for (const e of entries) {
    total += EXTENSION_ENTRY_HEADER + e.value.length
    if (total > max) throw new SigningBytesError('extensions_too_large', 'extensions exceed the size bound')
  }
  if (entries.length > 0xffff) throw new SigningBytesError('extensions_too_large', 'too many extensions')
  for (let i = 1; i < entries.length; i += 1) {
    if (entries[i - 1].type === entries[i].type) {
      throw new SigningBytesError('extension_duplicate', `duplicate extension type ${entries[i].type}`)
    }
    if (entries[i - 1].type > entries[i].type) {
      throw new SigningBytesError('extensions_unsorted', 'extensions are not in ascending ext_type order')
    }
  }
}

// No critical extension is defined for any tag yet.
function requireUnderstood(entries: readonly Extension[]): void {
  const unknown = entries.find((e) => e.critical)
  if (unknown) throw needsNewer('critical_extension', unknown.type)
}

function encodeExtensions(entries: readonly Extension[]): Uint8Array {
  const chunks: Uint8Array[] = [be(BigInt(entries.length), 2)]
  for (const e of entries) {
    chunks.push(be(BigInt(e.type), 2), Uint8Array.of(e.critical ? CRITICAL_FLAG : 0), be(BigInt(e.value.length), 4), e.value)
  }
  return concatBytes(...chunks)
}

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

/** Writes the header, then fields in call order, then the extensions region on `finish`. */
export class Builder {
  private readonly chunks: Uint8Array[]
  private readonly extensions: Extension[] = []

  constructor(
    tag: DomainTag,
    layoutVersion: number,
    private readonly rulesVersion: number = RULES_VERSION,
  ) {
    const layout = checkRange(toBigInt(layoutVersion, 'layout version'), 0n, 0xffffn, 'layout version')
    const rules = checkRange(toBigInt(rulesVersion, 'rules version'), 0n, 0xffff_ffffn, 'rules version')
    checkLayout(tag, Number(layout))
    checkRules(Number(rules))
    this.chunks = [tag.bytes, be(layout, 2), be(rules, 4)]
  }

  private push(chunk: Uint8Array): this {
    this.chunks.push(chunk)
    return this
  }

  /** The `hash_algo` byte; write it immediately before the first hash-valued field. */
  hashAlgo(id: number = HASH_ALGO_SHA256): this {
    return this.u8(checkHashAlgo(id))
  }

  /** Adds an extension; entries must be added in ascending type order. */
  extension(type: number, critical: boolean, value: Uint8Array): this {
    this.extensions.push({
      type: Number(checkRange(toBigInt(type, 'extension type'), 0n, 0xffffn, 'extension type')),
      critical,
      value,
    })
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

  /** An Ed25519 public key: algorithm byte, then 32 raw bytes. */
  key(value: Uint8Array): this {
    return this.u8(SIG_ALGO_ED25519).push(requireWidth(value, 32, 'key'))
  }

  /** An Ed25519 signature: algorithm byte, then 64 raw bytes. */
  signature(value: Uint8Array): this {
    return this.u8(SIG_ALGO_ED25519).push(requireWidth(value, 64, 'signature'))
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

  /** Appends the extensions region and returns the bytes; throws on an invalid or not understood extension. */
  finish(): Uint8Array {
    checkExtensions(this.extensions, this.rulesVersion)
    requireUnderstood(this.extensions)
    return concatBytes(...this.chunks, encodeExtensions(this.extensions))
  }
}

/** Reads fields in the order the layout defines. Checks a declared length against the remaining bytes first. */
export class Reader {
  private rest: Uint8Array
  readonly layoutVersion: number
  readonly rulesVersion: number

  /** Checks the tag, then the layout and rules versions against the supported ranges. */
  constructor(tag: DomainTag, message: Uint8Array) {
    const tagBytes = tag.bytes
    if (message.length < tagBytes.length || !tagBytes.every((b, i) => message[i] === b)) {
      throw new SigningBytesError('tag_mismatch', 'message does not start with the expected domain tag')
    }
    this.rest = message.subarray(tagBytes.length)
    this.layoutVersion = Number(this.takeUint(2))
    checkLayout(tag, this.layoutVersion)
    this.rulesVersion = Number(this.takeUint(4))
    checkRules(this.rulesVersion)
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

  /** A public key; an unknown algorithm byte is `needs_newer_version`. */
  key(): Uint8Array {
    checkSigAlgo(this.u8())
    return this.take(32)
  }

  /** A signature; an unknown algorithm byte is `needs_newer_version`. */
  signature(): Uint8Array {
    checkSigAlgo(this.u8())
    return this.take(64)
  }

  hash(): Uint8Array {
    return this.take(32)
  }

  /** The `hash_algo` byte; an unknown value is `needs_newer_version`. */
  hashAlgo(): number {
    return checkHashAlgo(this.u8())
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

  /** Reads the extensions region, which must be all that remains, and returns its entries (unknown non-critical kept). */
  finish(): Extension[] {
    const max = maxExtensionBytes(this.rulesVersion)
    const count = Number(this.takeUint(2))
    const entries: Extension[] = []
    let total = 0
    for (let i = 0; i < count; i += 1) {
      const type = Number(this.takeUint(2))
      const flags = this.u8()
      if ((flags & ~CRITICAL_FLAG) !== 0) {
        throw new SigningBytesError('extension_reserved_flags', `extension flags ${flags} set a reserved bit`)
      }
      const len = Number(this.takeUint(4))
      total += EXTENSION_ENTRY_HEADER + len
      if (total > max) throw new SigningBytesError('extensions_too_large', 'extensions exceed the size bound')
      entries.push({ type, critical: (flags & CRITICAL_FLAG) !== 0, value: this.take(len).slice() })
    }
    checkExtensions(entries, this.rulesVersion)
    if (this.rest.length !== 0) {
      throw new SigningBytesError('trailing_bytes', 'bytes remain after the last field')
    }
    requireUnderstood(entries)
    return entries
  }
}
