import { afterEach, describe, expect, it } from 'vitest'
import { listShardNames, resolveName, submitNameClaim } from '../src/shardNames.js'
import { NotFoundError } from '../src/errors.js'

const originalFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = originalFetch
})

interface Seen {
  url: string
  init?: RequestInit
}

function mockFetch(respond: () => Response): Seen[] {
  const seen: Seen[] = []
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    seen.push({ url: String(url), init })
    return respond()
  }) as typeof fetch
  return seen
}

const claim = {
  name: 'example.org',
  self_certifying_id: 'node:ab12',
  proof_method: 'dns-txt',
  verified_at: '2026-09-25T00:00:00Z',
}

describe('shard names', () => {
  it('resolves a name and sends no credentials', async () => {
    const seen = mockFetch(() => new Response(JSON.stringify(claim), { status: 200 }))
    const got = await resolveName('http://node.test:8080', 'example.org')
    expect(seen[0].url).toBe('http://node.test:8080/shards/name/example.org')
    expect(seen[0].init?.method).toBe('GET')
    expect(Object.keys((seen[0].init?.headers as Record<string, string>) ?? {})).not.toContain('authorization')
    expect(got.self_certifying_id).toBe('node:ab12')
  })

  it('lists the names bound to a shard, encoding the id', async () => {
    const seen = mockFetch(() => new Response(JSON.stringify([claim]), { status: 200 }))
    const got = await listShardNames('http://node.test:8080', 'node:ab12')
    expect(seen[0].url).toBe('http://node.test:8080/shards/node%3Aab12/name-claims')
    expect(got).toHaveLength(1)
  })

  it('submits a signed claim as JSON', async () => {
    const seen = mockFetch(() => new Response(JSON.stringify(claim), { status: 200 }))
    const request = {
      self_certifying_id: 'node:ab12',
      public_key: 'aa'.repeat(32),
      name: 'example.org',
      created_at: '2026-09-25T00:00:00Z',
      signature: 'bb'.repeat(64),
    }
    await submitNameClaim('http://node.test:8080', request)
    expect(seen[0].url).toBe('http://node.test:8080/shards/node%3Aab12/name-claims')
    expect(seen[0].init?.method).toBe('POST')
    expect(JSON.parse(String(seen[0].init?.body))).toEqual(request)
  })

  it('maps a 404 to NotFoundError', async () => {
    mockFetch(() => new Response('{"code":"not_found"}', { status: 404 }))
    await expect(resolveName('http://node.test:8080', 'missing.example')).rejects.toBeInstanceOf(NotFoundError)
  })
})
