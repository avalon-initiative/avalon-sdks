import { afterEach, describe, expect, it, vi } from 'vitest'
import { AccountSession } from '../../src/accountSession/core.js'
import { canonicalMessage, generateSigningKey } from '../../src/crypto/signing.js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { ConflictError, NotFoundError, RejectedError } from '../../src/errors.js'
import '../../src/accountSession/rollback.js'

function testSession(signing?: { secretKey: Uint8Array; publicKey: Uint8Array; signingKeyId: string }): AccountSession {
  const identity = { id: crypto.randomUUID(), createdAt: new Date().toISOString() }
  return new AccountSession({
    identity,
    profile: {
      identityId: identity.id,
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
    },
    serverUrl: 'http://127.0.0.1:1',
    token: 'test-token',
    signing,
  })
}

function mockFetch(body: unknown, status = 200) {
  return vi.fn().mockImplementation(async () => ({
    ok: status < 400,
    status,
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  }))
}

afterEach(() => {
  vi.unstubAllGlobals()
})

const SINCE = '2026-09-01T00:00:00Z'

describe('AccountSession.rollbackCandidates', () => {
  it('sends since as a query param and decodes candidates to camelCase', async () => {
    const fetchMock = mockFetch({
      recovery_request_id: 'r1',
      recovery_completed_at: '2026-09-02T00:00:00Z',
      candidates: [
        { event_id: 'e1', kind: 'guild.create', occurred_at: '2026-09-01T01:00:00Z', summary: 's', reversible: true, reason: null, already_reversed: false },
        { event_id: 'e2', kind: 'x', occurred_at: '2026-09-01T02:00:00Z', summary: 't', reversible: false, reason: 'nope', already_reversed: true },
      ],
    })
    vi.stubGlobal('fetch', fetchMock)
    const result = await testSession().rollbackCandidates(SINCE)
    expect(String(fetchMock.mock.calls[0][0])).toContain('/me/rollback/candidates?since=')
    expect(result.recoveryRequestId).toBe('r1')
    expect(result.recoveryCompletedAt).toBe('2026-09-02T00:00:00Z')
    expect(result.candidates[0]).toMatchObject({ eventId: 'e1', reversible: true, reason: null, alreadyReversed: false })
    expect(result.candidates[1]).toMatchObject({ eventId: 'e2', reversible: false, reason: 'nope', alreadyReversed: true })
  })
})

describe('AccountSession.reverseRollbackEvent', () => {
  it('signs rollback.reverse over [eventId, identityId, since] and returns the reversal id', async () => {
    const { secretKey, publicKey } = generateSigningKey()
    const session = testSession({ secretKey, publicKey, signingKeyId: 'key-1' })
    const fetchMock = mockFetch({ reversal_event_id: 'rev-1' })
    vi.stubGlobal('fetch', fetchMock)

    const id = await session.reverseRollbackEvent('evt-1', SINCE)

    expect(id).toBe('rev-1')
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toContain('/me/rollback/evt-1/reverse')
    expect(init.method).toBe('POST')
    const body = JSON.parse(init.body)
    expect(body.since).toBe(SINCE)
    expect(body.signing_key_id).toBe('key-1')
    const message = canonicalMessage('rollback.reverse', ['evt-1', session.identity().id, SINCE])
    const sig = Uint8Array.from(atob(body.signature), (c) => c.charCodeAt(0))
    expect(ed25519.verify(sig, message, publicKey)).toBe(true)
  })

  it('sends null signature fields without a local key', async () => {
    const fetchMock = mockFetch({ reversal_event_id: 'rev-1' })
    vi.stubGlobal('fetch', fetchMock)
    await testSession().reverseRollbackEvent('evt-1', SINCE)
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ since: SINCE, signing_key_id: null, signature: null })
  })
})

describe('rollback error mapping', () => {
  const cases: [string, number, new (...a: never[]) => Error][] = [
    ['ROLLBACK_NO_COMPLETED_RECOVERY', 409, ConflictError],
    ['INVALID_ROLLBACK_WINDOW', 400, RejectedError],
    ['ROLLBACK_EVENT_NOT_ELIGIBLE', 404, NotFoundError],
    ['ROLLBACK_NOT_REVERSIBLE', 409, ConflictError],
    ['ROLLBACK_ALREADY_REVERSED', 409, ConflictError],
  ]
  it.each(cases)('%s (%i) maps to its status-driven typed error', async (code, status, cls) => {
    vi.stubGlobal('fetch', mockFetch({ error: 'msg', code }, status))
    const err = await testSession().reverseRollbackEvent('e', SINCE).catch((e) => e)
    expect(err).toBeInstanceOf(cls)
    expect((err as { code?: string }).code).toBe(code)
    expect((err as Error).message).toContain(code)
  })
})
