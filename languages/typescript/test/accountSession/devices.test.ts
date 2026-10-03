import { afterEach, describe, expect, it, vi } from 'vitest'
import { randomIdentityId } from '../testIds.js'
import type { IdentityId } from '../../src/identityId.js'
import { AccountSession } from '../../src/accountSession/core.js'
import { bytesToBase64, generateSigningKey } from '../../src/crypto/signing.js'
import { NoLocalSigningKeyError } from '../../src/errors.js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToHex } from '@noble/hashes/utils.js'
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
  const identity = { id: randomIdentityId(), createdAt: new Date().toISOString() }
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
    await expect(session.approveDeviceGrant('grant-1', 'requested-key')).rejects.toBeInstanceOf(
      NoLocalSigningKeyError,
    )
  })

  it('signs the exact grant being approved with the approving key', async () => {
    const { secretKey, publicKey } = generateSigningKey()
    const requested = generateSigningKey()
    const session = testSession({ secretKey, publicKey, signingKeyId: 'approver-key-id' })

    let capturedBody: Record<string, unknown> | undefined
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
        capturedBody = JSON.parse(init!.body as string)
        return new Response(
          JSON.stringify({ id: 'new-device', label: null, public_key: 'x', added_at: 'now' }),
          { status: 200 },
        )
      }),
    )

    const grantId = crypto.randomUUID()
    const requestedPublicKeyB64 = bytesToBase64(requested.publicKey)
    await session.approveDeviceGrant(grantId, requestedPublicKeyB64)

    expect(capturedBody!.approver_signing_key_id).toBe('approver-key-id')

    // The signature must verify against the exact bytes
    // crates/server/src/devices.rs independently reconstructs.
    const signingBytes = new TextEncoder().encode(
      `avalon:device_grant.approved:v2:${grantId}:${session.identity().id}:${bytesToHex(requested.publicKey)}`,
    )
    const signature = Uint8Array.from(atob(capturedBody!.signature as string), (c) => c.charCodeAt(0))
    expect(ed25519.verify(signature, signingBytes, publicKey)).toBe(true)
  })
})

describe('AccountSession.approveDeviceGrant key handling', () => {
  it('rejects a requested key that is not canonical base64 of 32 bytes', async () => {
    const { secretKey, publicKey } = generateSigningKey()
    const session = testSession({ secretKey, publicKey, signingKeyId: 'approver-key-id' })
    await expect(session.approveDeviceGrant('grant-1', 'AAAA')).rejects.toBeInstanceOf(TypeError)
  })
})

describe('AccountSession.revokeDevice', () => {
  it('throws NoLocalSigningKeyError when this session holds no local key', async () => {
    await expect(testSession().revokeDevice('key-1')).rejects.toBeInstanceOf(NoLocalSigningKeyError)
  })

  it('signs the v2 revocation bytes with the session key', async () => {
    const { secretKey, publicKey } = generateSigningKey()
    const session = testSession({ secretKey, publicKey, signingKeyId: 'revoker-key-id' })
    let captured: { url: string; body: Record<string, unknown> } | undefined
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
        captured = { url, body: JSON.parse(init!.body as string) }
        return new Response(null, { status: 200 })
      }),
    )

    await session.revokeDevice('old-key-id')

    expect(captured!.url).toContain('/me/devices/old-key-id/revoke')
    expect(captured!.body.revoked_by_signing_key_id).toBe('revoker-key-id')
    const message = new TextEncoder().encode(
      `avalon:identity.signing_key_revoked:v2:${session.identity().id}:old-key-id:revoker-key-id`,
    )
    const signature = Uint8Array.from(atob(captured!.body.signature as string), (c) => c.charCodeAt(0))
    expect(ed25519.verify(signature, message, publicKey)).toBe(true)
  })
})
