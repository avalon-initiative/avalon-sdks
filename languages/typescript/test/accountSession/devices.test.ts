import { afterEach, describe, expect, it, vi } from 'vitest'
import { randomIdentityId } from '../testIds.js'
import type { IdentityId } from '../../src/identityId.js'
import { AccountSession } from '../../src/accountSession/core.js'
import {
  base64ToBytes,
  bytesToBase64,
  deviceGrantApprovalSigningBytes,
  generateSigningKey,
  signingKeyRevokedSigningBytes,
  verify,
} from '../../src/crypto/signing.js'
import { parseHash } from '../../src/ledgerEntry.js'
import { IdentityChainPositionStaleError, NoLocalSigningKeyError, ProtocolError } from '../../src/errors.js'
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

function deviceRow(id: string) {
  return { id, label: null, public_key: 'k', added_at: '2026-01-01T00:00:00Z', revoked_at: null }
}

function mockResponses(responses: { status: number; body: unknown }[]) {
  const queue = [...responses]
  return vi.fn().mockImplementation(async () => {
    const next = queue.shift()
    if (!next) throw new Error('unexpected extra request')
    const text = next.body === undefined ? '' : JSON.stringify(next.body)
    return {
      ok: next.status < 400,
      status: next.status,
      headers: new Headers(),
      json: () => Promise.resolve(next.body),
      text: () => Promise.resolve(text),
    }
  })
}

function sent(fetchMock: ReturnType<typeof vi.fn>, call: number): { url: string; body: Record<string, unknown> } {
  const [url, init] = fetchMock.mock.calls[call] as [string, { body: string }]
  return { url, body: JSON.parse(init.body) }
}

describe('AccountSession.approveDeviceGrant', () => {
  it('throws NoLocalSigningKeyError when this session holds no local key', async () => {
    const session = testSession()
    await expect(session.approveDeviceGrant('grant-1', 'requested-key')).rejects.toBeInstanceOf(NoLocalSigningKeyError)
  })

  it('signs the v3 bytes at an empty chain position and sends seq, prev_hash and the approver key id', async () => {
    const { secretKey, publicKey } = generateSigningKey()
    const approverKeyId = crypto.randomUUID()
    const session = testSession({ secretKey, publicKey, signingKeyId: approverKeyId })
    const requested = generateSigningKey().publicKey
    const grantId = crypto.randomUUID()
    const fetchMock = mockResponses([{ status: 200, body: deviceRow(grantId) }])
    vi.stubGlobal('fetch', fetchMock)

    const device = await session.approveDeviceGrant(grantId, bytesToBase64(requested))

    expect(device.id).toBe(grantId)
    const { url, body } = sent(fetchMock, 0)
    expect(url).toMatch(new RegExp(`/me/devices/grants/${grantId}/approve$`))
    expect(body).toMatchObject({ approver_signing_key_id: approverKeyId, seq: 1, prev_hash: null })
    const bytes = deviceGrantApprovalSigningBytes(grantId, session.identity().id, approverKeyId, requested, 1, null)
    expect(verify(publicKey, bytes, base64ToBytes(body.signature as string))).toBe(true)
  })

  it('re-signs once at the head a stale 409 returns, then succeeds', async () => {
    const { secretKey, publicKey } = generateSigningKey()
    const approverKeyId = crypto.randomUUID()
    const session = testSession({ secretKey, publicKey, signingKeyId: approverKeyId })
    const requested = generateSigningKey().publicKey
    const grantId = crypto.randomUUID()
    const head = 'ab'.repeat(32)
    const fetchMock = mockResponses([
      { status: 409, body: { error: 'stale', code: 'IDENTITY_CHAIN_POSITION_STALE', head_seq: 4, head_hash: head } },
      { status: 200, body: deviceRow(grantId) },
    ])
    vi.stubGlobal('fetch', fetchMock)

    await session.approveDeviceGrant(grantId, bytesToBase64(requested))

    expect(fetchMock).toHaveBeenCalledTimes(2)
    const retry = sent(fetchMock, 1).body
    expect(retry).toMatchObject({ seq: 5, prev_hash: head })
    const bytes = deviceGrantApprovalSigningBytes(grantId, session.identity().id, approverKeyId, requested, 5, parseHash('h', head))
    expect(verify(publicKey, bytes, base64ToBytes(retry.signature as string))).toBe(true)
  })

  it('exposes a clear error when the position is still stale after one re-sign', async () => {
    const { secretKey, publicKey } = generateSigningKey()
    const session = testSession({ secretKey, publicKey, signingKeyId: crypto.randomUUID() })
    const stale = (seq: number) => ({
      status: 409,
      body: { error: 'stale', code: 'IDENTITY_CHAIN_POSITION_STALE', head_seq: seq, head_hash: 'cd'.repeat(32) },
    })
    const fetchMock = mockResponses([stale(2), stale(3)])
    vi.stubGlobal('fetch', fetchMock)

    const error = await session
      .approveDeviceGrant(crypto.randomUUID(), bytesToBase64(generateSigningKey().publicKey))
      .catch((e: unknown) => e)

    expect(error).toBeInstanceOf(IdentityChainPositionStaleError)
    expect((error as IdentityChainPositionStaleError).headSeq).toBe(3)
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('does not retry other conflicts', async () => {
    const { secretKey, publicKey } = generateSigningKey()
    const session = testSession({ secretKey, publicKey, signingKeyId: crypto.randomUUID() })
    const fetchMock = mockResponses([{ status: 409, body: { error: 'forked', code: 'IDENTITY_CHAIN_FORKED' } }])
    vi.stubGlobal('fetch', fetchMock)
    await expect(
      session.approveDeviceGrant(crypto.randomUUID(), bytesToBase64(generateSigningKey().publicKey)),
    ).rejects.toMatchObject({ code: 'IDENTITY_CHAIN_FORKED' })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})

describe('AccountSession.approveDeviceGrant key handling', () => {
  it('rejects a requested key that is not canonical base64 of 32 bytes', async () => {
    const { secretKey, publicKey } = generateSigningKey()
    const session = testSession({
      secretKey,
      publicKey,
      signingKeyId: crypto.randomUUID(),
    })
    await expect(session.approveDeviceGrant(crypto.randomUUID(), 'AAAA')).rejects.toBeInstanceOf(TypeError)
  })
})

describe('AccountSession.revokeDevice', () => {
  it('throws NoLocalSigningKeyError when this session holds no local key', async () => {
    await expect(testSession().revokeDevice('key-1')).rejects.toBeInstanceOf(NoLocalSigningKeyError)
  })

  it('signs the v3 revocation bytes at the returned head after a stale 409', async () => {
    const { secretKey, publicKey } = generateSigningKey()
    const revokerKeyId = crypto.randomUUID()
    const session = testSession({ secretKey, publicKey, signingKeyId: revokerKeyId })
    const revokedKeyId = crypto.randomUUID()
    const fetchMock = mockResponses([
      { status: 409, body: { error: 'stale', code: 'IDENTITY_CHAIN_POSITION_STALE', head_seq: 0, head_hash: null } },
      { status: 200, body: undefined },
    ])
    vi.stubGlobal('fetch', fetchMock)

    await session.revokeDevice(revokedKeyId)

    const first = sent(fetchMock, 0)
    expect(first.url).toMatch(new RegExp(`/me/devices/${revokedKeyId}/revoke$`))
    expect(first.body).toMatchObject({ revoked_by_signing_key_id: revokerKeyId, seq: 1, prev_hash: null })
    const retry = sent(fetchMock, 1).body
    expect(retry).toMatchObject({ seq: 1, prev_hash: null })
    const bytes = signingKeyRevokedSigningBytes(session.identity().id, revokedKeyId, revokerKeyId, 1, null)
    expect(verify(publicKey, bytes, base64ToBytes(retry.signature as string))).toBe(true)
  })

  it('rejects a stale 409 with a malformed head_hash as a protocol error', async () => {
    for (const head_hash of [5, '', 'zz', 'AB'.repeat(32)]) {
      const { secretKey, publicKey } = generateSigningKey()
      const session = testSession({ secretKey, publicKey, signingKeyId: crypto.randomUUID() })
      vi.stubGlobal(
        'fetch',
        mockResponses([{ status: 409, body: { error: 'x', code: 'IDENTITY_CHAIN_POSITION_STALE', head_seq: 1, head_hash } }]),
      )
      await expect(session.revokeDevice(crypto.randomUUID()), JSON.stringify(head_hash)).rejects.toBeInstanceOf(ProtocolError)
    }
  })

  it('rejects a stale 409 without a usable head as a protocol error', async () => {
    const { secretKey, publicKey } = generateSigningKey()
    const session = testSession({ secretKey, publicKey, signingKeyId: crypto.randomUUID() })
    vi.stubGlobal('fetch', mockResponses([{ status: 409, body: { error: 'x', code: 'IDENTITY_CHAIN_POSITION_STALE' } }]))
    await expect(session.revokeDevice(crypto.randomUUID())).rejects.toBeInstanceOf(ProtocolError)
  })
})

describe('device grant and revocation input validation', () => {
  it('approveDeviceGrant rejects a small-order requested key', async () => {
    const { secretKey, publicKey } = generateSigningKey()
    const session = testSession({
      secretKey,
      publicKey,
      signingKeyId: crypto.randomUUID(),
    })
    const identityPoint = new Uint8Array(32)
    identityPoint[0] = 1
    await expect(session.approveDeviceGrant(crypto.randomUUID(), bytesToBase64(identityPoint))).rejects.toBeInstanceOf(
      TypeError,
    )
  })
})
