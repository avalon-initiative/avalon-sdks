import { afterEach, describe, expect, it, vi } from 'vitest'
import { randomIdentityId } from '../testIds.js'
import type { IdentityId } from '../../src/identityId.js'
import { AccountSession } from '../../src/accountSession/core.js'
import { bytesToBase64, generateSigningKey } from '../../src/crypto/signing.js'
import { NoLocalSigningKeyError } from '../../src/errors.js'
import '../../src/accountSession/devices.js'

function testProfile(identityId: IdentityId) {
  return {
    identityId,
    displayName: 'test',
    avatarUrl: null,
    bio: null,
    favoriteGenres: [],
    pronouns: null,
    bannerUrl: null,
    status: null,
    links: [],
    timezone: null,
    themeColor: null,
    location: null,
    mainGuild: null,
    effectiveMainGuild: null,
    discoverable: false,
    presenceVisibility: 'public',
  }
}

function testSession(signing?: { secretKey: Uint8Array; publicKey: Uint8Array; signingKeyId: string }): AccountSession {
  const identity = {
    id: randomIdentityId(),
    createdAt: new Date().toISOString(),
  }
  return new AccountSession({
    identity,
    profile: testProfile(identity.id),
    serverUrl: 'http://127.0.0.1:1',
    token: 'test-token',
    signing,
  })
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('AccountSession.approveDeviceGrant', () => {
  it('throws NoLocalSigningKeyError when this session holds no local key', async () => {
    const session = testSession()
    await expect(session.approveDeviceGrant('grant-1', 'requested-key')).rejects.toBeInstanceOf(NoLocalSigningKeyError)
  })

  it('fails loudly without sending a request until v3 signing lands', async () => {
    const { secretKey, publicKey } = generateSigningKey()
    const session = testSession({
      secretKey,
      publicKey,
      signingKeyId: 'approver-key-id',
    })
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    await expect(
      session.approveDeviceGrant(crypto.randomUUID(), bytesToBase64(generateSigningKey().publicKey)),
    ).rejects.toThrow(/not supported until v3/)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('AccountSession.approveDeviceGrant key handling', () => {
  it('rejects a requested key that is not canonical base64 of 32 bytes', async () => {
    const { secretKey, publicKey } = generateSigningKey()
    const session = testSession({
      secretKey,
      publicKey,
      signingKeyId: 'approver-key-id',
    })
    await expect(session.approveDeviceGrant(crypto.randomUUID(), 'AAAA')).rejects.toBeInstanceOf(TypeError)
  })
})

describe('AccountSession.revokeDevice', () => {
  it('throws NoLocalSigningKeyError when this session holds no local key', async () => {
    await expect(testSession().revokeDevice('key-1')).rejects.toBeInstanceOf(NoLocalSigningKeyError)
  })

  it('fails loudly without sending a request until v3 signing lands', async () => {
    const { secretKey, publicKey } = generateSigningKey()
    const session = testSession({
      secretKey,
      publicKey,
      signingKeyId: crypto.randomUUID(),
    })
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    await expect(session.revokeDevice(crypto.randomUUID())).rejects.toThrow(/not supported until v3/)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('device grant and revocation input validation', () => {
  it('approveDeviceGrant rejects a small-order requested key', async () => {
    const { secretKey, publicKey } = generateSigningKey()
    const session = testSession({
      secretKey,
      publicKey,
      signingKeyId: 'approver-key-id',
    })
    const identityPoint = new Uint8Array(32)
    identityPoint[0] = 1
    await expect(session.approveDeviceGrant(crypto.randomUUID(), bytesToBase64(identityPoint))).rejects.toBeInstanceOf(
      TypeError,
    )
  })
})
