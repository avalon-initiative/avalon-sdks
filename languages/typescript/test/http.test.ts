import { afterEach, describe, expect, it } from 'vitest'
import { request } from '../src/http.js'
import { AvalonSdkError, ProtocolError, RateLimitedError, UnauthorizedError, UnavailableError } from '../src/errors.js'

const originalFetch = globalThis.fetch

afterEach(() => {
  globalThis.fetch = originalFetch
})

describe('request 401 reconnect (issue #525)', () => {
  it('retries once with the token onUnauthorized mints, and never calls it again on success', async () => {
    let calls = 0
    let onUnauthorizedCalls = 0
    globalThis.fetch = (async (_url: string, init?: RequestInit) => {
      calls += 1
      const auth = (init?.headers as Record<string, string>)?.authorization
      if (auth === 'Bearer stale-token') {
        return new Response('', { status: 401 })
      }
      expect(auth).toBe('Bearer fresh-token')
      return new Response(JSON.stringify({ ok: true }), { status: 200 })
    }) as typeof fetch

    const result = await request<{ ok: boolean }>('http://127.0.0.1:1', '/me', {
      token: 'stale-token',
      onUnauthorized: async (failedToken) => {
        onUnauthorizedCalls += 1
        expect(failedToken).toBe('stale-token')
        return 'fresh-token'
      },
    })

    expect(result).toEqual({ ok: true })
    expect(calls).toBe(2)
    expect(onUnauthorizedCalls).toBe(1)
  })

  it('propagates the 401 when onUnauthorized resolves to null', async () => {
    globalThis.fetch = (async () => new Response('', { status: 401 })) as typeof fetch

    await expect(
      request('http://127.0.0.1:1', '/me', { token: 'stale-token', onUnauthorized: async () => null }),
    ).rejects.toBeInstanceOf(UnauthorizedError)
  })

  it('propagates the 401 as-is when no onUnauthorized hook is given', async () => {
    let calls = 0
    globalThis.fetch = (async () => {
      calls += 1
      return new Response('', { status: 401 })
    }) as typeof fetch

    await expect(request('http://127.0.0.1:1', '/me', { token: 'stale-token' })).rejects.toBeInstanceOf(
      UnauthorizedError,
    )
    expect(calls).toBe(1)
  })

  it('never fires onUnauthorized for a non-401 error', async () => {
    let onUnauthorizedCalls = 0
    globalThis.fetch = (async () => new Response('', { status: 404 })) as typeof fetch

    await expect(
      request('http://127.0.0.1:1', '/me', {
        token: 'stale-token',
        onUnauthorized: async () => {
          onUnauthorizedCalls += 1
          return 'fresh-token'
        },
      }),
    ).rejects.toThrow()
    expect(onUnauthorizedCalls).toBe(0)
  })
})

const caught = async (): Promise<AvalonSdkError> => {
  try {
    await request('http://127.0.0.1:1', '/x')
  } catch (e) {
    return e as AvalonSdkError
  }
  throw new Error('expected request to throw')
}

describe('429 rate limiting', () => {
  const rateLimited = (headers: Record<string, string>) =>
    (async () =>
      new Response(JSON.stringify({ error: 'slow down', code: 'RATE_LIMITED' }), {
        status: 429,
        headers,
      })) as typeof fetch

  it('maps 429 with a numeric Retry-After', async () => {
    globalThis.fetch = rateLimited({ 'Retry-After': '7' })
    const err = await caught()
    expect(err).toBeInstanceOf(RateLimitedError)
    expect(err).toBeInstanceOf(ProtocolError)
    expect(err.status).toBe(429)
    expect(err.retryAfterSeconds).toBe(7)
    expect(err.code).toBe('RATE_LIMITED')
  })

  it('maps 429 without Retry-After', async () => {
    globalThis.fetch = rateLimited({})
    const err = await caught()
    expect(err).toBeInstanceOf(RateLimitedError)
    expect(err.status).toBe(429)
    expect(err.retryAfterSeconds).toBeUndefined()
  })

  it('ignores non-numeric and HTTP-date Retry-After', async () => {
    for (const value of ['soon', 'Wed, 21 Oct 2026 07:28:00 GMT', '-3', '1.5']) {
      globalThis.fetch = rateLimited({ 'Retry-After': value })
      const err = await caught()
      expect(err).toBeInstanceOf(RateLimitedError)
      expect(err.retryAfterSeconds).toBeUndefined()
    }
  })

  it('leaves other statuses on their existing classes', async () => {
    globalThis.fetch = (async () => new Response('', { status: 503, headers: { 'Retry-After': '5' } })) as typeof fetch
    const unavailable = await caught()
    expect(unavailable).toBeInstanceOf(UnavailableError)
    expect(unavailable).not.toBeInstanceOf(RateLimitedError)
    expect(unavailable.status).toBe(503)

    globalThis.fetch = (async () => new Response('', { status: 401 })) as typeof fetch
    const unauthorized = await caught()
    expect(unauthorized).toBeInstanceOf(UnauthorizedError)
    expect(unauthorized.status).toBe(401)
  })
})
