// Canonical encoding of free-form payloads: RFC 8785 (JCS) restricted so every SDK reproduces it byte
// for byte, matching avalon_protocol::canonical_payload. A number is valid only if its decimal text
// survives a round trip through an IEEE double (integers within +/-2^53, other numbers with at most
// 15 significant digits written exactly as ECMAScript prints them); duplicate keys are rejected.
// conformance/vectors/canonical-payload.json is the shared arbiter.

/** Largest integer magnitude an IEEE double represents exactly. */
export const MAX_SAFE_INTEGER = 2 ** 53
/** Most significant digits a non-integer number may carry. */
export const MAX_SIGNIFICANT_DIGITS = 15
/** Deepest object/array nesting a payload may have. */
export const MAX_DEPTH = 128

export type CanonicalPayloadErrorCode = 'invalid_number' | 'duplicate_key' | 'malformed' | 'too_deep'

/** Why a payload has no canonical encoding; `code` is the shared vector error code. */
export class CanonicalPayloadError extends Error {
  constructor(
    public readonly code: CanonicalPayloadErrorCode,
    message: string,
  ) {
    super(message)
    this.name = 'CanonicalPayloadError'
  }
}

function invalidNumber(text: string): CanonicalPayloadError {
  return new CanonicalPayloadError(
    'invalid_number',
    `number \`${text}\` is not exactly representable as an IEEE double; use a string`,
  )
}

/** ECMAScript `Number::toString` of `f`, or null when `f` is not a valid payload number (non-finite,
 * integral beyond 2^53, or over 15 significant digits when not integral). */
function floatText(f: number): string | null {
  if (!Number.isFinite(f)) return null
  if (f === 0) return '0'
  const integral = Number.isInteger(f)
  if (integral && Math.abs(f) > MAX_SAFE_INTEGER) return null
  if (!integral) {
    // toExponential() with no argument prints as many digits as the shortest round trip needs.
    const digits = f.toExponential().split('e')[0].replace(/[-.]/g, '')
    if (digits.length > MAX_SIGNIFICANT_DIGITS) return null
  }
  return String(f)
}

function compareUtf16(a: string, b: string): number {
  // Relational comparison of JS strings is by UTF-16 code unit.
  return a < b ? -1 : a > b ? 1 : 0
}

function writeString(s: string, out: string[]): void {
  out.push('"')
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i)
    if (c >= 0xd800 && c <= 0xdfff) {
      const pair = c <= 0xdbff && s.charCodeAt(i + 1) >= 0xdc00 && s.charCodeAt(i + 1) <= 0xdfff
      if (!pair) throw new TypeError('payload string contains a lone surrogate')
      out.push(s.slice(i, i + 2))
      i += 1
      continue
    }
    switch (c) {
      case 0x22:
        out.push('\\"')
        break
      case 0x5c:
        out.push('\\\\')
        break
      case 0x08:
        out.push('\\b')
        break
      case 0x09:
        out.push('\\t')
        break
      case 0x0a:
        out.push('\\n')
        break
      case 0x0c:
        out.push('\\f')
        break
      case 0x0d:
        out.push('\\r')
        break
      default:
        out.push(c < 0x20 ? `\\u${c.toString(16).padStart(4, '0')}` : s[i])
    }
  }
  out.push('"')
}

function writeValue(value: unknown, out: string[], depth: number): void {
  if (depth > MAX_DEPTH) {
    throw new CanonicalPayloadError('too_deep', `payload nests deeper than ${MAX_DEPTH} levels`)
  }
  if (value === null) {
    out.push('null')
  } else if (typeof value === 'boolean') {
    out.push(value ? 'true' : 'false')
  } else if (typeof value === 'number') {
    const text = floatText(value)
    if (text === null) throw invalidNumber(String(value))
    out.push(text)
  } else if (typeof value === 'string') {
    writeString(value, out)
  } else if (Array.isArray(value)) {
    out.push('[')
    value.forEach((item, i) => {
      if (i > 0) out.push(',')
      writeValue(item, out, depth + 1)
    })
    out.push(']')
  } else if (typeof value === 'object' && value !== undefined) {
    const entries = Object.keys(value).sort(compareUtf16)
    out.push('{')
    entries.forEach((key, i) => {
      if (i > 0) out.push(',')
      writeString(key, out)
      out.push(':')
      writeValue((value as Record<string, unknown>)[key], out, depth + 1)
    })
    out.push('}')
  } else {
    throw new TypeError(`a ${typeof value} has no JSON encoding`)
  }
}

/** Canonical encoding of `value`, or throws the first restriction it violates. Judges numbers by value
 * (`1.0` is `1`); only `parseStrict` checks the number text. */
export function canonicalize(value: unknown): string {
  const out: string[] = []
  writeValue(value, out, 0)
  return out.join('')
}

/** Canonical encoding of the JSON document `text`, under the full restrictions of `parseStrict`. */
export function canonicalizeStr(text: string): string {
  return canonicalize(parseStrict(text))
}

/** Parses JSON `text` under the full restrictions, including the exact decimal text of every number and
 * duplicate keys, which a parsed value no longer carries. */
export function parseStrict(text: string): unknown {
  return new Parser(text).document()
}

const HEX4 = /^[0-9a-fA-F]{4}$/

class Parser {
  private pos = 0

  constructor(private readonly text: string) {}

  document(): unknown {
    this.skipWs()
    const value = this.value(0)
    this.skipWs()
    if (this.pos !== this.text.length) throw this.malformed('trailing characters')
    return value
  }

  private malformed(what: string): CanonicalPayloadError {
    return new CanonicalPayloadError('malformed', `malformed JSON: ${what} at offset ${this.pos}`)
  }

  private skipWs(): void {
    while (' \t\n\r'.includes(this.text[this.pos] ?? 'x')) this.pos += 1
  }

  private eat(literal: string): boolean {
    if (this.text.startsWith(literal, this.pos)) {
      this.pos += literal.length
      return true
    }
    return false
  }

  private value(depth: number): unknown {
    if (depth > MAX_DEPTH) {
      throw new CanonicalPayloadError('too_deep', `payload nests deeper than ${MAX_DEPTH} levels`)
    }
    const c = this.text[this.pos]
    if (c === '{') return this.object(depth)
    if (c === '[') return this.array(depth)
    if (c === '"') return this.string()
    if (c === 't' && this.eat('true')) return true
    if (c === 'f' && this.eat('false')) return false
    if (c === 'n' && this.eat('null')) return null
    if (c === '-' || (c !== undefined && c >= '0' && c <= '9')) return this.number()
    throw this.malformed('unexpected token')
  }

  private object(depth: number): unknown {
    this.pos += 1
    const map: Record<string, unknown> = {}
    const seen = new Set<string>()
    this.skipWs()
    if (this.eat('}')) return map
    for (;;) {
      this.skipWs()
      if (this.text[this.pos] !== '"') throw this.malformed('expected object key')
      const key = this.string()
      this.skipWs()
      if (!this.eat(':')) throw this.malformed('expected `:`')
      this.skipWs()
      const value = this.value(depth + 1)
      if (seen.has(key)) {
        throw new CanonicalPayloadError('duplicate_key', `duplicate object key ${JSON.stringify(key)}`)
      }
      seen.add(key)
      // defineProperty so a `__proto__` key stays an own property instead of setting the prototype.
      Object.defineProperty(map, key, { value, enumerable: true, writable: true, configurable: true })
      this.skipWs()
      if (this.eat(',')) continue
      if (this.eat('}')) return map
      throw this.malformed('expected `,` or `}`')
    }
  }

  private array(depth: number): unknown {
    this.pos += 1
    const items: unknown[] = []
    this.skipWs()
    if (this.eat(']')) return items
    for (;;) {
      this.skipWs()
      items.push(this.value(depth + 1))
      this.skipWs()
      if (this.eat(',')) continue
      if (this.eat(']')) return items
      throw this.malformed('expected `,` or `]`')
    }
  }

  private hex4(): number {
    const digits = this.text.slice(this.pos, this.pos + 4)
    if (!HEX4.test(digits)) throw this.malformed('bad \\u escape')
    this.pos += 4
    return parseInt(digits, 16)
  }

  private string(): string {
    this.pos += 1
    let out = ''
    for (;;) {
      if (this.pos >= this.text.length) throw this.malformed('unterminated string')
      const c = this.text.charCodeAt(this.pos)
      this.pos += 1
      if (c === 0x22) return out
      if (c === 0x5c) {
        const esc = this.text[this.pos]
        this.pos += 1
        switch (esc) {
          case '"':
            out += '"'
            break
          case '\\':
            out += '\\'
            break
          case '/':
            out += '/'
            break
          case 'b':
            out += '\b'
            break
          case 'f':
            out += '\f'
            break
          case 'n':
            out += '\n'
            break
          case 'r':
            out += '\r'
            break
          case 't':
            out += '\t'
            break
          case 'u': {
            const hi = this.hex4()
            if (hi >= 0xd800 && hi < 0xdc00) {
              if (!this.eat('\\u')) throw this.malformed('lone surrogate')
              const lo = this.hex4()
              if (lo < 0xdc00 || lo >= 0xe000) throw this.malformed('lone surrogate')
              out += String.fromCharCode(hi, lo)
            } else if (hi >= 0xdc00 && hi < 0xe000) {
              throw this.malformed('lone surrogate')
            } else {
              out += String.fromCharCode(hi)
            }
            break
          }
          default:
            throw this.malformed('bad escape')
        }
      } else if (c < 0x20) {
        throw this.malformed('raw control character')
      } else if (c >= 0xd800 && c <= 0xdfff) {
        // A raw surrogate must be a well-formed pair; a lone one is not text.
        const next = this.text.charCodeAt(this.pos)
        if (c <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) {
          out += String.fromCharCode(c, next)
          this.pos += 1
        } else {
          throw this.malformed('lone surrogate')
        }
      } else {
        out += String.fromCharCode(c)
      }
    }
  }

  private digits(): number {
    const from = this.pos
    while (this.text[this.pos] !== undefined && this.text[this.pos] >= '0' && this.text[this.pos] <= '9') {
      this.pos += 1
    }
    return this.pos - from
  }

  private number(): number {
    const start = this.pos
    this.eat('-')
    if (this.text[this.pos] === '0') {
      this.pos += 1
    } else if (this.digits() === 0) {
      throw this.malformed('bad number')
    }
    let integerForm = true
    if (this.eat('.')) {
      integerForm = false
      if (this.digits() === 0) throw this.malformed('bad number')
    }
    if (this.text[this.pos] === 'e' || this.text[this.pos] === 'E') {
      integerForm = false
      this.pos += 1
      if (this.text[this.pos] === '+' || this.text[this.pos] === '-') this.pos += 1
      if (this.digits() === 0) throw this.malformed('bad number')
    }
    const token = this.text.slice(start, this.pos)
    if (integerForm) {
      if (token === '-0') throw invalidNumber(token)
      const n = BigInt(token)
      if ((n < 0n ? -n : n) > BigInt(MAX_SAFE_INTEGER)) throw invalidNumber(token)
      return Number(n)
    }
    const f = Number(token)
    if (floatText(f) !== token) throw invalidNumber(token)
    return f
  }
}
