import { describe, expect, it } from 'vitest'
import { EntryHashError, entryHash, parseHash, timestampMicrosFromRfc3339, type EntryHashInput } from '../src/ledgerEntry.js'

const base = (): EntryHashInput => ({
  networkId: 'net',
  shardId: 'core',
  seq: 1,
  prevHash: new Uint8Array(32),
  eventId: '00000000-0000-0000-0000-000000000001',
  kind: 'k',
  issuer: 'i',
  subject: 's',
  payloadHash: new Uint8Array(32).fill(1),
  timestampMicros: 1,
  version: 1,
})

describe('entryHash', () => {
  it('changes with every field', () => {
    const h = (patch: Partial<EntryHashInput>) => Buffer.from(entryHash({ ...base(), ...patch })).toString('hex')
    const want = h({})
    const variants: Partial<EntryHashInput>[] = [
      { networkId: 'net2' },
      { shardId: 'core2' },
      { seq: 2 },
      { prevHash: new Uint8Array(32).fill(9) },
      { eventId: '00000000-0000-0000-0000-000000000002' },
      { kind: 'k2' },
      { issuer: 'i2' },
      { subject: 's2' },
      { payloadHash: new Uint8Array(32).fill(9) },
      { timestampMicros: 2 },
      { version: 2 },
    ]
    for (const v of variants) expect(h(v)).not.toBe(want)
  })

  it('rejects out-of-range fields with out_of_range', () => {
    for (const patch of [{ seq: -1 }, { seq: 2n ** 64n }, { version: 65536 }, { version: -1 }, { timestampMicros: 2n ** 63n }]) {
      expect(() => entryHash({ ...base(), ...patch })).toThrow(EntryHashError)
    }
  })
})

describe('parseHash', () => {
  it('accepts 64 lowercase hex characters only', () => {
    expect(parseHash('h', 'ab'.repeat(32))).toEqual(new Uint8Array(32).fill(0xab))
    for (const bad of ['AB'.repeat(32), 'ab'.repeat(31), 'ab'.repeat(33), 'zz'.repeat(32), `${'ab'.repeat(32)}\n`]) {
      expect(() => parseHash('h', bad)).toThrow(EntryHashError)
    }
  })
})

describe('timestampMicrosFromRfc3339', () => {
  it('floors to microseconds, honours offsets and handles pre-epoch instants', () => {
    expect(timestampMicrosFromRfc3339('1970-01-01T00:00:00Z')).toBe(0n)
    expect(timestampMicrosFromRfc3339('1970-01-01T00:00:00.0000019Z')).toBe(1n)
    expect(timestampMicrosFromRfc3339('1969-12-31T23:59:59.9999995Z')).toBe(-1n)
    expect(timestampMicrosFromRfc3339('1970-01-01T01:00:00+01:00')).toBe(0n)
    expect(timestampMicrosFromRfc3339('1969-12-31T19:00:00-05:00')).toBe(0n)
  })

  it('range-checks the offset like the time crate', () => {
    for (const bad of ['+99:99', '+24:00', '+00:60', '-24:00']) {
      expect(() => timestampMicrosFromRfc3339(`2026-01-02T03:04:05${bad}`), bad).toThrow(EntryHashError)
    }
    expect(timestampMicrosFromRfc3339('1970-01-01T23:59:59+23:59')).toBe(59_000_000n)
  })

  it('treats a leap second as the last microsecond of a UTC month, else rejects it', () => {
    expect(timestampMicrosFromRfc3339('2016-12-31T23:59:60Z')).toBe(timestampMicrosFromRfc3339('2016-12-31T23:59:59.999999Z'))
    expect(timestampMicrosFromRfc3339('2017-01-01T01:59:60+02:00')).toBe(timestampMicrosFromRfc3339('2016-12-31T23:59:59.999999Z'))
    for (const bad of ['2016-12-30T23:59:60Z', '2016-12-31T23:58:60Z', '2016-12-31T22:59:60Z']) {
      expect(() => timestampMicrosFromRfc3339(bad), bad).toThrow(EntryHashError)
    }
  })

  it('rejects text that is not an instant', () => {
    for (const bad of ['', '2026-01-02', '2026-02-30T00:00:00Z', '2026-01-02T24:00:00Z', '2026-01-02T03:04:05']) {
      expect(() => timestampMicrosFromRfc3339(bad), bad).toThrow(EntryHashError)
    }
  })
})
