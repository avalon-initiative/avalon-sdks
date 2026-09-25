import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it } from 'vitest'
import { getTopology, probeNode, traceRoute } from '../src/nodeTopology.js'
import { RateLimitedError } from '../src/errors.js'

const originalFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = originalFetch
})

function fixture(name: string): string {
  return readFileSync(fileURLToPath(new URL(`../../../conformance/fixtures/nodes/${name}.json`, import.meta.url)), 'utf-8')
}

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

describe('getTopology', () => {
  it('decodes a recorded node response and sends no credentials', async () => {
    const seen = mockFetch(() => new Response(fixture('topology'), { status: 200 }))
    const topology = await getTopology('http://node.test:8080', { limit: 5 })
    expect(seen[0].url).toBe('http://node.test:8080/nodes/topology?limit=5')
    expect(seen[0].init?.method).toBe('GET')
    expect(seen[0].init?.credentials).toBeUndefined()
    expect(Object.keys((seen[0].init?.headers as Record<string, string>) ?? {})).not.toContain('authorization')
    expect(topology.self.network_id).toBe('avalon-dev-local')
    expect(topology.self.coordinate.vector).toHaveLength(3)
    expect(topology.neighbors.some((n) => n.latency && n.coordinate)).toBe(true)
    expect(topology.mirrors).toHaveLength(1)
  })

  it('surfaces 429 with Retry-After', async () => {
    mockFetch(() => new Response('{"code":"rate_limited"}', { status: 429, headers: { 'retry-after': '7' } }))
    const error = await getTopology('http://node.test:8080').catch((e) => e)
    expect(error).toBeInstanceOf(RateLimitedError)
    expect(error.status).toBe(429)
    expect(error.retryAfterSeconds).toBe(7)
  })

  it('rejects a malformed body', async () => {
    mockFetch(() => new Response('not json', { status: 200 }))
    await expect(getTopology('http://node.test:8080')).rejects.toThrow()
  })
})

describe('probeNode', () => {
  it('posts the target and samples and decodes a recorded response', async () => {
    const seen = mockFetch(() => new Response(fixture('probe'), { status: 200 }))
    const result = await probeNode('http://node.test:8080', 'http://other.test:8080', 3)
    expect(seen[0].url).toBe('http://node.test:8080/nodes/probe')
    expect(JSON.parse(seen[0].init?.body as string)).toEqual({ target: 'http://other.test:8080', samples: 3 })
    expect(result.ok).toBe(true)
    expect(result.samples_ms).toHaveLength(3)
    expect(result.median_ms).toBeTypeOf('number')
  })

  it('omits samples when not given and surfaces 429 with Retry-After', async () => {
    const seen = mockFetch(() => new Response('', { status: 429, headers: { 'retry-after': '3' } }))
    const error = await probeNode('http://node.test:8080', 'http://other.test:8080').catch((e) => e)
    expect(JSON.parse(seen[0].init?.body as string)).toEqual({ target: 'http://other.test:8080' })
    expect(error).toBeInstanceOf(RateLimitedError)
    expect(error.retryAfterSeconds).toBe(3)
  })

  it('rejects a malformed body', async () => {
    mockFetch(() => new Response('{"target":', { status: 200 }))
    await expect(probeNode('http://node.test:8080', 'http://o:1')).rejects.toThrow()
  })
})

describe('traceRoute', () => {
  it('posts the target and ttl and decodes a recorded response', async () => {
    const seen = mockFetch(() => new Response(fixture('trace'), { status: 200 }))
    const result = await traceRoute('http://node.test:8080', 'http://other.test:8080', { ttl: 4 })
    expect(JSON.parse(seen[0].init?.body as string)).toEqual({ target: 'http://other.test:8080', ttl: 4 })
    expect(result.reached).toBe(true)
    expect(result.hops.map((h) => h.index)).toEqual([0, 1])
    expect(result.hops[0].to_next_ms).toBeTypeOf('number')
    expect(result.hops[1].to_next_ms).toBeUndefined()
  })

  it('surfaces 429 with Retry-After', async () => {
    mockFetch(() => new Response('', { status: 429, headers: { 'retry-after': '11' } }))
    const error = await traceRoute('http://node.test:8080', 'http://o:1').catch((e) => e)
    expect(error).toBeInstanceOf(RateLimitedError)
    expect(error.retryAfterSeconds).toBe(11)
  })

  it('rejects a malformed body', async () => {
    mockFetch(() => new Response('<html>', { status: 200 }))
    await expect(traceRoute('http://node.test:8080', 'http://o:1')).rejects.toThrow()
  })
})
