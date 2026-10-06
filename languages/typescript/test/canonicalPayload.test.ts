import { describe, expect, it } from 'vitest'
import { CanonicalPayloadError, MAX_DEPTH, canonicalize, canonicalizeStr, parseStrict } from '../src/canonicalPayload.js'

function codeOf(fn: () => unknown): string | undefined {
  try {
    fn()
  } catch (e) {
    if (e instanceof CanonicalPayloadError) return e.code
    throw e
  }
  return undefined
}

describe('canonicalize (values)', () => {
  it('sorts keys by UTF-16 code unit and escapes only what JCS requires', () => {
    expect(canonicalize({ '': 1, '\u{10000}': 2 })).toBe('{"\u{10000}":2,"":1}')
    expect(canonicalize(['\u0001\u001f\b\t\n\f\r"\\/\u007f'])).toBe('["\\u0001\\u001f\\b\\t\\n\\f\\r\\"\\\\/\u007f"]')
  })

  it('prints numbers as ECMAScript does and rejects what a double cannot carry exactly', () => {
    expect(canonicalize([0, -0, 1.5, 1e-7, 2 ** 53, -(2 ** 53), 0.1])).toBe('[0,0,1.5,1e-7,9007199254740992,-9007199254740992,0.1]')
    expect(codeOf(() => canonicalize(2 ** 53 + 2))).toBe('invalid_number')
    expect(codeOf(() => canonicalize(Infinity))).toBe('invalid_number')
    expect(codeOf(() => canonicalize(NaN))).toBe('invalid_number')
    expect(codeOf(() => canonicalize(0.1 + 0.2))).toBe('invalid_number')
    expect(codeOf(() => canonicalize(1e21))).toBe('invalid_number')
  })

  it('throws a TypeError for values with no JSON form', () => {
    expect(() => canonicalize(undefined)).toThrow(TypeError)
    expect(() => canonicalize({ a: 1n })).toThrow(TypeError)
    expect(() => canonicalize('\ud800')).toThrow(TypeError)
  })

  it('caps nesting depth', () => {
    let deep: unknown = 1
    for (let i = 0; i < MAX_DEPTH; i += 1) deep = [deep]
    expect(() => canonicalize(deep)).not.toThrow()
    expect(codeOf(() => canonicalize([deep]))).toBe('too_deep')
  })
})

describe('parseStrict', () => {
  it('judges the number text, not the value', () => {
    for (const text of ['1.0', '0.10', '1e2', '1E-7', '-0', '0.1000000000000000055511151231257827', '9007199254740993']) {
      expect(codeOf(() => parseStrict(text)), text).toBe('invalid_number')
    }
    for (const [text, out] of [['1e-7', '1e-7'], ['0.000001', '0.000001'], ['-9007199254740992', '-9007199254740992']]) {
      expect(canonicalizeStr(text)).toBe(out)
    }
  })

  it('rejects duplicate keys after unescaping, and reports the first problem in document order', () => {
    expect(codeOf(() => parseStrict('{"a":1,"\\u0061":2}'))).toBe('duplicate_key')
    expect(codeOf(() => parseStrict('{"a":1.0,"a":2}'))).toBe('invalid_number')
  })

  it('keeps a __proto__ key as data', () => {
    const value = parseStrict('{"__proto__":{"x":1}}') as Record<string, unknown>
    expect(Object.getPrototypeOf(value)).toBe(Object.prototype)
    expect(canonicalize(value)).toBe('{"__proto__":{"x":1}}')
  })

  it('caps nesting depth in the parser', () => {
    expect(() => parseStrict('['.repeat(MAX_DEPTH + 1) + ']'.repeat(MAX_DEPTH + 1))).not.toThrow()
    expect(codeOf(() => parseStrict('['.repeat(MAX_DEPTH + 2) + ']'.repeat(MAX_DEPTH + 2)))).toBe('too_deep')
  })

  it('rejects malformed documents', () => {
    for (const text of ['', ' ', '[1,]', '{"a"}', '01', '+1', '.5', '1.', '[1] x', '"\ud800"', '"\\ud800"', 'tru']) {
      expect(codeOf(() => parseStrict(text)), JSON.stringify(text)).toBe('malformed')
    }
  })

  it('accepts a surrogate pair written raw or escaped', () => {
    expect(parseStrict('"\u{1F600}"')).toBe('\u{1F600}')
    expect(parseStrict('"\\ud83d\\ude00"')).toBe('\u{1F600}')
  })
})
