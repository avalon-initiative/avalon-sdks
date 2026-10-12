import { describe, expect, it } from 'vitest'
import { canonicalMessage, generateSigningKey, sign, verify } from '../../src/crypto/signing.js'

describe('canonicalMessage', () => {
  it('matches the server shape byte-for-byte', () => {
    const message = canonicalMessage('guild.transfer_ownership', ['g1', 'from1', 'to1'])
    expect(new TextDecoder().decode(message)).toBe('avalon:guild.transfer_ownership:v1:g1:from1:to1')
  })

  it('with no fields is just the tag', () => {
    const message = canonicalMessage('integration.connect', [])
    expect(new TextDecoder().decode(message)).toBe('avalon:integration.connect:v1')
  })
})

describe('sign/verify', () => {
  it('produces a signature that verifies against the same canonical message', () => {
    const { secretKey, publicKey } = generateSigningKey()
    const message = canonicalMessage('passkey.revoke_last', ['p1', 'i1'])
    const signature = sign(secretKey, message)
    expect(verify(publicKey, message, signature)).toBe(true)
  })

  it('does not verify against a different message', () => {
    const { secretKey, publicKey } = generateSigningKey()
    const signature = sign(secretKey, canonicalMessage('passkey.revoke_last', ['p1', 'i1']))
    expect(verify(publicKey, canonicalMessage('passkey.revoke_last', ['p2', 'i1']), signature)).toBe(false)
  })
})

import {
  deviceGrantApprovalSigningBytes,
  identityCreatedSigningBytes,
  signingKeyRevokedSigningBytes,
} from '../../src/crypto/signing.js'
import { deriveIdentityId } from '../../src/identityId.js'

describe('identity key event signing bytes', () => {
  const key = new Uint8Array(32).fill(3)
  const id = deriveIdentityId(key)
  const uuid = '0b7a2c1e-5d4f-4a3b-9c8d-1e2f3a4b5c6d'
  const prev = new Uint8Array(32).fill(9)
  const bad = [uuid.toUpperCase(), uuid.replace(/-/g, ''), `${uuid} `, '', 'x:y']

  it('accepts canonical UUIDs', () => {
    expect(() => identityCreatedSigningBytes('n', uuid, id, key, 'a')).not.toThrow()
    expect(() => deviceGrantApprovalSigningBytes('n', uuid, id, uuid, key, 1, null)).not.toThrow()
    expect(() => signingKeyRevokedSigningBytes('n', id, uuid, uuid, 1, prev)).not.toThrow()
  })

  for (const value of bad) {
    it(`rejects ${JSON.stringify(value)}`, () => {
      expect(() => identityCreatedSigningBytes('n', value, id, key, 'a')).toThrow(TypeError)
      expect(() => deviceGrantApprovalSigningBytes('n', value, id, uuid, key, 1, null)).toThrow(TypeError)
      expect(() => deviceGrantApprovalSigningBytes('n', uuid, id, value, key, 1, null)).toThrow(TypeError)
      expect(() => signingKeyRevokedSigningBytes('n', id, value, uuid, 1, null)).toThrow(TypeError)
      expect(() => signingKeyRevokedSigningBytes('n', id, uuid, value, 1, null)).toThrow(TypeError)
    })
  }

  it('rejects a malformed identity id, short keys and hashes, and an out-of-range seq', () => {
    expect(() => signingKeyRevokedSigningBytes('n', 'abc' as typeof id, uuid, uuid, 1, null)).toThrow(TypeError)
    expect(() => identityCreatedSigningBytes('n', uuid, id, new Uint8Array(31), 'a')).toThrow(TypeError)
    expect(() => deviceGrantApprovalSigningBytes('n', uuid, id, uuid, key, 1, new Uint8Array(31))).toThrow(TypeError)
    expect(() => signingKeyRevokedSigningBytes('n', id, uuid, uuid, -1, null)).toThrow(RangeError)
    expect(() => signingKeyRevokedSigningBytes('n', id, uuid, uuid, 1n << 64n, null)).toThrow(RangeError)
  })

  it('encodes the position as seq u64, the hash algorithm byte, then a prev_hash flag byte', () => {
    const none = signingKeyRevokedSigningBytes('n', id, uuid, uuid, 1, null)
    const some = signingKeyRevokedSigningBytes('n', id, uuid, uuid, 1, prev)
    // seq u64, hash_algo 01, flag byte, [prev hash], then the empty extensions region
    expect(none.slice(-12)).toEqual(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0]))
    expect(some.length).toBe(none.length + 32)
    expect(some.slice(-35, -2)).toEqual(new Uint8Array([1, ...prev]))
  })
})
