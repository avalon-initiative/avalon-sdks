import { afterEach, describe, expect, it, vi } from 'vitest'
import { randomIdentityId } from '../testIds.js'
import type { IdentityId } from '../../src/identityId.js'
import { AccountSession } from '../../src/accountSession/core.js'
import { NotFoundError } from '../../src/errors.js'
import '../../src/accountSession/sessions.js'

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

function testSession(): AccountSession {
  const identity = { id: randomIdentityId(), createdAt: new Date().toISOString() }
  return new AccountSession({
    identity,
    profile: testProfile(identity.id),
    serverUrl: 'http://127.0.0.1:1',
    token: 'test-token',
  })
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('AccountSession.listSessions', () => {
  it('decodes the envelope and marks the current session', async () => {
    const a = crypto.randomUUID()
    const b = crypto.randomUUID()
    const passkey = crypto.randomUUID()
    const key = crypto.randomUUID()
    let captured: { url: string; init?: RequestInit } | undefined
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
        captured = { url, init }
        return new Response(
          JSON.stringify({
            sessions: [
              {
                id: a,
                created_at: '2026-10-02T00:00:00Z',
                expires_at: '2026-11-01T00:00:00Z',
                current: true,
                origin_passkey_id: passkey,
                origin_signing_key_id: null,
              },
              {
                id: b,
                created_at: '2026-10-01T00:00:00Z',
                expires_at: '2026-10-31T00:00:00Z',
                current: false,
                origin_signing_key_id: key,
              },
            ],
          }),
          { status: 200 },
        )
      }),
    )

    const sessions = await testSession().listSessions()

    expect(captured!.url).toBe('http://127.0.0.1:1/me/sessions')
    expect(new Headers(captured!.init!.headers).get('authorization')).toBe('Bearer test-token')
    expect(sessions).toEqual([
      {
        id: a,
        createdAt: '2026-10-02T00:00:00Z',
        expiresAt: '2026-11-01T00:00:00Z',
        current: true,
        originPasskeyId: passkey,
        originSigningKeyId: null,
      },
      {
        id: b,
        createdAt: '2026-10-01T00:00:00Z',
        expiresAt: '2026-10-31T00:00:00Z',
        current: false,
        originPasskeyId: null,
        originSigningKeyId: key,
      },
    ])
  })
})

describe('AccountSession.revokeSession', () => {
  it('posts to the session revoke route', async () => {
    const id = crypto.randomUUID()
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    await testSession().revokeSession(id)

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe(`http://127.0.0.1:1/me/sessions/${id}/revoke`)
    expect(init.method).toBe('POST')
  })

  it('maps SESSION_NOT_FOUND to NotFoundError', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue(
          new Response(JSON.stringify({ error: 'session not found', code: 'SESSION_NOT_FOUND' }), { status: 404 }),
        ),
    )
    await expect(testSession().revokeSession(crypto.randomUUID())).rejects.toBeInstanceOf(NotFoundError)
  })
})

describe('AccountSession.logout', () => {
  it('posts to the logout route with the session token', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    await testSession().logout()

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('http://127.0.0.1:1/sessions/logout')
    expect(init.method).toBe('POST')
    expect(new Headers(init.headers).get('authorization')).toBe('Bearer test-token')
  })
})
