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

describe('v2 signing bytes require canonical UUID text', () => {
  const key = new Uint8Array(32).fill(3)
  const id = deriveIdentityId(key)
  const uuid = '0b7a2c1e-5d4f-4a3b-9c8d-1e2f3a4b5c6d'
  const bad = [uuid.toUpperCase(), uuid.replace(/-/g, ''), `${uuid} `, '', 'x:y']

  it('accepts a canonical UUID', () => {
    expect(() => identityCreatedSigningBytes('n', 's', uuid, id, key, 'a')).not.toThrow()
    expect(() => deviceGrantApprovalSigningBytes(uuid, id, key)).not.toThrow()
    expect(() => signingKeyRevokedSigningBytes(id, uuid, uuid)).not.toThrow()
  })

  for (const value of bad) {
    it(`rejects ${JSON.stringify(value)}`, () => {
      expect(() => identityCreatedSigningBytes('n', 's', value, id, key, 'a')).toThrow(TypeError)
      expect(() => deviceGrantApprovalSigningBytes(value, id, key)).toThrow(TypeError)
      expect(() => signingKeyRevokedSigningBytes(id, value, uuid)).toThrow(TypeError)
      expect(() => signingKeyRevokedSigningBytes(id, uuid, value)).toThrow(TypeError)
    })
  }
})
