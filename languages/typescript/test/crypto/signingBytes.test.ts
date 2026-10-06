import { describe, expect, it } from 'vitest'
import { ALL_TAGS, Builder, DomainTag, Reader, SigningBytesError, tags, uuidToBytes } from '../../src/crypto/signingBytes.js'

const enc = new TextEncoder()

describe('tag registry', () => {
  it('is unique and prefix-free', () => {
    ALL_TAGS.forEach((a, i) => {
      for (const b of ALL_TAGS.slice(i + 1)) {
        expect(a.name.startsWith(b.name) || b.name.startsWith(a.name), `${a.name} / ${b.name}`).toBe(false)
      }
    })
  })

  it('only accepts [a-z0-9._] of 1 to 255 bytes', () => {
    expect(() => new DomainTag('')).toThrow(TypeError)
    expect(() => new DomainTag('Avalon.x')).toThrow(TypeError)
    expect(() => new DomainTag('a-b')).toThrow(TypeError)
    expect(() => new DomainTag('a'.repeat(256))).toThrow(TypeError)
    expect(new DomainTag('a'.repeat(255)).bytes.length).toBe(255)
  })
})

describe('Builder and Reader', () => {
  it('round-trips every field type', () => {
    const id = '00000000-0000-0000-0000-000000000007'
    const msg = new Builder(tags.CONFORMANCE, 3)
      .str('a:b,c\0d')
      .bytes(new Uint8Array(0))
      .key(new Uint8Array(32).fill(9))
      .uuid(id)
      .u8(1)
      .u16(2)
      .u32(3)
      .u64(2n ** 64n - 1n)
      .i64(-(2n ** 63n))
      .finish()
    const r = new Reader(tags.CONFORMANCE, msg)
    expect(r.version).toBe(3)
    expect(r.str()).toBe('a:b,c\0d')
    expect(r.bytes()).toEqual(new Uint8Array(0))
    expect(r.key()).toEqual(new Uint8Array(32).fill(9))
    expect(r.uuid()).toBe(id)
    expect([r.u8(), r.u16(), r.u32()]).toEqual([1, 2, 3])
    expect(r.u64()).toBe(2n ** 64n - 1n)
    expect(r.i64()).toBe(-(2n ** 63n))
    r.finish()
  })

  it('moving a delimiter between fields changes the bytes', () => {
    const a = new Builder(tags.CONFORMANCE, 1).str('a:b').str('c').finish()
    const b = new Builder(tags.CONFORMANCE, 1).str('a').str('b:c').finish()
    expect(a).not.toEqual(b)
  })

  it('rejects out-of-range integers, wrong widths and lone surrogates when building', () => {
    const b = () => new Builder(tags.CONFORMANCE, 1)
    expect(() => b().u8(256)).toThrow(RangeError)
    expect(() => b().u16(-1)).toThrow(RangeError)
    expect(() => b().u32(2 ** 32)).toThrow(RangeError)
    expect(() => b().u64(-1n)).toThrow(RangeError)
    expect(() => b().i64(2n ** 63n)).toThrow(RangeError)
    expect(() => b().u8(1.5)).toThrow(RangeError)
    expect(() => new Builder(tags.CONFORMANCE, 65536)).toThrow(RangeError)
    expect(() => b().key(new Uint8Array(31))).toThrow(TypeError)
    expect(() => b().fixed(new Uint8Array(3), 4)).toThrow(TypeError)
    expect(() => b().str('\ud800')).toThrow(TypeError)
    expect(() => b().str('\udc00x')).toThrow(TypeError)
    expect(() => b().uuid('0B7A2C1E-5D4F-4A3B-9C8D-1E2F3A4B5C6D')).toThrow(TypeError)
  })

  it('encodes non-BMP text as UTF-8', () => {
    const msg = new Builder(tags.CONFORMANCE, 1).str('\u{1F600}').finish()
    expect(msg.slice(-8)).toEqual(new Uint8Array([0, 0, 0, 4, 0xf0, 0x9f, 0x98, 0x80]))
  })

  it('reads a leading U+FEFF as data, not a byte order mark', () => {
    const msg = new Builder(tags.CONFORMANCE, 1).str('﻿x').finish()
    expect(new Reader(tags.CONFORMANCE, msg).str()).toBe('﻿x')
  })

  it('reports each malformed shape with its code', () => {
    const codeOf = (fn: () => void): string | undefined => {
      try {
        fn()
      } catch (e) {
        if (e instanceof SigningBytesError) return e.code
        throw e
      }
      return undefined
    }
    const ok = new Builder(tags.CONFORMANCE, 1).str('ab').finish()
    expect(codeOf(() => new Reader(tags.INTEREST_CLAIM, ok))).toBe('tag_mismatch')
    expect(codeOf(() => new Reader(tags.CONFORMANCE, tags.CONFORMANCE.bytes))).toBe('truncated')
    expect(codeOf(() => new Reader(tags.CONFORMANCE, ok.subarray(0, ok.length - 1)).str())).toBe('truncated')
    expect(codeOf(() => new Reader(tags.CONFORMANCE, ok).finish())).toBe('trailing_bytes')
    const bad = new Builder(tags.CONFORMANCE, 1).bytes(new Uint8Array([0xff])).finish()
    expect(codeOf(() => new Reader(tags.CONFORMANCE, bad).str())).toBe('invalid_utf8')
    const huge = new Uint8Array([...tags.CONFORMANCE.bytes, 0, 1, 0xff, 0xff, 0xff, 0xff, 0x78])
    expect(codeOf(() => new Reader(tags.CONFORMANCE, huge).bytes())).toBe('truncated')
  })
})

describe('uuidToBytes', () => {
  it('parses canonical text to 16 raw bytes', () => {
    expect(uuidToBytes('0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b')).toEqual(
      new Uint8Array([0x01, 0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0x7e, 0x5f, 0x8a, 0x9b, 0x0c, 0x1d, 0x2e, 0x3f, 0x4a, 0x5b]),
    )
    expect(enc.encode('x').length).toBe(1)
  })
})
