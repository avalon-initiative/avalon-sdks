import { afterEach, describe, expect, it } from 'vitest'
import { normalizeNodeUrl, walkTopology, WALK_DEFAULT_MAX_NODES } from '../src/topologyWalk.js'
import type { WalkEvent } from '../src/topologyWalk.js'

const originalFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = originalFetch
})

interface Links {
  neighbors?: Array<string | { url: string; ms: number }>
  known?: string[]
  mirrors?: string[]
}

type Handler = (call: number, signal?: AbortSignal | null) => Response | Promise<Response>

function topologyBody(url: string, links: Links): string {
  return JSON.stringify({
    self: { base_url: url, network_id: 'test-net', protocol_version: '0.1.0', roles: ['combined'], stale: false, shards: [], coordinate: { vector: [0, 0, 0], height: 0, error: 1 } },
    neighbors: (links.neighbors ?? []).map((n) => {
      const target = typeof n === 'string' ? n : n.url
      return {
        base_url: target,
        bootstrap: false,
        roles: [],
        last_announced_at: null,
        ...(typeof n === 'string' ? {} : { latency: { observed_by: 'ignored', last_ms: n.ms, ewma_ms: n.ms, min_ms: n.ms, jitter_ms: 0, samples: 1, failed_recent: 0, attempts_recent: 1, loss_ratio: 0, measurement: 'application_round_trip' } }),
      }
    }),
    known: (links.known ?? []).map((k) => ({ base_url: k, last_announced_at: '2026-01-01T00:00:00Z', protocol_version: '0.1.0', roles: [] })),
    known_total: (links.known ?? []).length,
    mirrors: (links.mirrors ?? []).map((m) => ({ source_url: m, shard_id: 'core', mirrored_entries: 1, last_mirrored_at: null, last_observed_at: null, open_equivocations: [] })),
    generated_at: '2026-01-01T00:00:00Z',
  })
}

/** Serves `graph` by request origin; a function entry handles that node itself. */
function mockNetwork(graph: Record<string, Links | Handler>): { calls: Record<string, number> } {
  const calls: Record<string, number> = {}
  globalThis.fetch = (async (input: string, init?: RequestInit) => {
    const url = new URL(String(input))
    const origin = url.origin
    calls[origin] = (calls[origin] ?? 0) + 1
    const entry = graph[origin]
    if (entry === undefined) throw new TypeError('connection refused')
    if (typeof entry === 'function') return entry(calls[origin], init?.signal)
    return new Response(topologyBody(origin, entry), { status: 200 })
  }) as typeof fetch
  return { calls }
}

const A = 'http://a.test:8080'
const B = 'http://b.test:8080'
const C = 'http://c.test:8080'
const D = 'http://d.test:8080'

describe('normalizeNodeUrl', () => {
  it('lowercases scheme and host and trims trailing slashes', () => {
    expect(normalizeNodeUrl('HTTP://A.Test:8080/')).toBe(A)
    expect(normalizeNodeUrl(' http://a.test:8080// ')).toBe(A)
    expect(normalizeNodeUrl('http://a.test:80/')).toBe('http://a.test')
    expect(normalizeNodeUrl('ftp://a.test')).toBeUndefined()
    expect(normalizeNodeUrl('nonsense')).toBeUndefined()
  })
})

describe('walkTopology', () => {
  it('walks a connected graph with typed edges and per-reporter latency', async () => {
    mockNetwork({
      [A]: { neighbors: [{ url: B, ms: 3 }], known: [C], mirrors: [B] },
      [B]: { neighbors: [{ url: A, ms: 4 }, { url: C, ms: 5 }] },
      [C]: {},
    })
    const events: WalkEvent[] = []
    const graph = await walkTopology([A], { onProgress: (e) => events.push(e) })

    expect(graph.nodes.map((n) => [n.url, n.depth, n.status])).toEqual([
      [A, 0, 'visited'],
      [B, 1, 'visited'],
      [C, 1, 'visited'],
    ])
    expect(graph.cancelled).toBe(false)
    expect(graph.truncated).toEqual({ maxNodes: false, maxDepth: false })
    const kinds = graph.edges.map((e) => `${e.from}>${e.to}:${e.kind}`).sort()
    expect(kinds).toEqual([`${A}>${B}:active`, `${A}>${B}:mirror`, `${A}>${C}:known`, `${B}>${A}:active`, `${B}>${C}:active`].sort())
    const ab = graph.edges.find((e) => e.from === A && e.to === B && e.kind === 'active')
    const ba = graph.edges.find((e) => e.from === B && e.to === A)
    expect(ab?.latency?.observed_by).toBe(A)
    expect(ab?.latency?.last_ms).toBe(3)
    expect(ba?.latency?.observed_by).toBe(B)
    expect(ba?.latency?.last_ms).toBe(4)
    expect(graph.nodes.find((n) => n.url === C)?.reportedBy.sort()).toEqual([A, B])
    expect(graph.nodes[0].self?.network_id).toBe('test-net')
    expect(events.filter((e) => e.type === 'discovered')).toHaveLength(3)
    expect(events.filter((e) => e.type === 'visited')).toHaveLength(3)
  })

  it('reports a partitioned graph as only the reachable component, and seeds cover both', async () => {
    mockNetwork({ [A]: { neighbors: [B] }, [B]: {}, [C]: { neighbors: [D] }, [D]: {} })
    const single = await walkTopology([A])
    expect(single.nodes.map((n) => n.url)).toEqual([A, B])
    const both = await walkTopology([A, C])
    expect(both.nodes.map((n) => n.url).sort()).toEqual([A, B, C, D])
    expect(both.seeds).toEqual([A, C])
  })

  it('records an unreachable node and keeps walking', async () => {
    mockNetwork({ [A]: { neighbors: [B, C] }, [C]: {} })
    const graph = await walkTopology([A])
    const b = graph.nodes.find((n) => n.url === B)
    expect(b?.status).toBe('unreachable')
    expect(b?.failure?.reason).toBe('network')
    expect(graph.nodes.find((n) => n.url === C)?.status).toBe('visited')
  })

  it('classifies http status and malformed bodies', async () => {
    mockNetwork({
      [A]: { neighbors: [B, C] },
      [B]: () => new Response('{"error":"boom"}', { status: 500 }),
      [C]: () => new Response('not json', { status: 200 }),
    })
    const graph = await walkTopology([A])
    expect(graph.nodes.find((n) => n.url === B)?.failure).toMatchObject({ reason: 'http_status', status: 500 })
    expect(graph.nodes.find((n) => n.url === C)?.failure?.reason).toBe('protocol_error')
  })

  it('records a node that times out without stopping the walk', async () => {
    mockNetwork({
      [A]: { neighbors: [B, C] },
      [B]: (_call, signal) => new Promise<Response>((_resolve, reject) => signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))),
      [C]: {},
    })
    const graph = await walkTopology([A], { requestTimeoutMs: 30 })
    expect(graph.nodes.find((n) => n.url === B)?.failure?.reason).toBe('timeout')
    expect(graph.nodes.find((n) => n.url === C)?.status).toBe('visited')
    expect(graph.cancelled).toBe(false)
  })

  it('honors Retry-After once and then succeeds', async () => {
    const { calls } = mockNetwork({
      [A]: { neighbors: [B] },
      [B]: (call) => (call === 1 ? new Response('', { status: 429, headers: { 'retry-after': '0' } }) : new Response(topologyBody(B, {}), { status: 200 })),
    })
    const graph = await walkTopology([A])
    expect(calls[B]).toBe(2)
    expect(graph.nodes.find((n) => n.url === B)?.status).toBe('visited')
  })

  it('records rate_limited when Retry-After exceeds the budget, or a second 429 follows', async () => {
    const { calls } = mockNetwork({
      [A]: { neighbors: [B, C] },
      [B]: () => new Response('', { status: 429, headers: { 'retry-after': '3600' } }),
      [C]: () => new Response('', { status: 429, headers: { 'retry-after': '0' } }),
    })
    const graph = await walkTopology([A])
    expect(calls[B]).toBe(1)
    expect(graph.nodes.find((n) => n.url === B)?.failure).toMatchObject({ reason: 'rate_limited', status: 429, retryAfterSeconds: 3600 })
    expect(calls[C]).toBe(2)
    expect(graph.nodes.find((n) => n.url === C)?.failure?.reason).toBe('rate_limited')
  })

  it('stops at maxNodes and marks the rest as dropped', async () => {
    mockNetwork({ [A]: { neighbors: [B, C, D] }, [B]: {}, [C]: {}, [D]: {} })
    const graph = await walkTopology([A], { maxNodes: 2, concurrency: 1 })
    expect(graph.nodes.map((n) => n.url)).toEqual([A, B])
    expect(graph.truncated.maxNodes).toBe(true)
    expect(graph.edges.every((e) => e.to !== C && e.to !== D)).toBe(true)
  })

  it('stops at maxDepth and leaves deeper nodes unvisited', async () => {
    const { calls } = mockNetwork({ [A]: { neighbors: [B] }, [B]: { neighbors: [C] }, [C]: { neighbors: [D] }, [D]: {} })
    const graph = await walkTopology([A], { maxDepth: 1 })
    expect(calls[C]).toBeUndefined()
    expect(graph.nodes.map((n) => [n.url, n.status])).toEqual([[A, 'visited'], [B, 'visited'], [C, 'unvisited']])
    expect(graph.truncated.maxDepth).toBe(true)
  })

  it('applies default limits when no options are given', async () => {
    const hosts = Array.from({ length: 200 }, (_, i) => `http://n${i}.test:8080`)
    globalThis.fetch = (async (input: string) => {
      const origin = new URL(String(input)).origin
      const i = hosts.indexOf(origin)
      return new Response(topologyBody(origin, { neighbors: hosts.slice(i + 1, i + 4) }), { status: 200 })
    }) as typeof fetch
    const graph = await walkTopology([hosts[0]])
    expect(graph.nodes.length).toBeLessThanOrEqual(WALK_DEFAULT_MAX_NODES)
    expect(Math.max(...graph.nodes.map((n) => n.depth))).toBeLessThanOrEqual(5)
    expect(graph.truncated.maxDepth || graph.truncated.maxNodes).toBe(true)
  })

  it('dedupes URL variants of the same node', async () => {
    const { calls } = mockNetwork({ [A]: { neighbors: ['HTTP://B.test:8080/', 'http://b.test:8080'], known: ['http://b.test:8080//'] }, [B]: { neighbors: ['http://A.TEST:8080/'] } })
    const graph = await walkTopology([`${A}/`, 'HTTP://A.TEST:8080'])
    expect(graph.nodes.map((n) => n.url)).toEqual([A, B])
    expect(graph.seeds).toEqual([A])
    expect(calls[A]).toBe(1)
    expect(calls[B]).toBe(1)
    expect(graph.nodes[1].reportedBy).toEqual([A])
  })

  it('resolves with the partial graph when cancelled', async () => {
    const controller = new AbortController()
    mockNetwork({
      [A]: { neighbors: [B, C] },
      [B]: (_call, signal) => new Promise<Response>((_resolve, reject) => signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))),
      [C]: (_call, signal) => new Promise<Response>((_resolve, reject) => signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))),
    })
    const walking = walkTopology([A], {
      signal: controller.signal,
      onProgress: (e) => {
        if (e.type === 'visited' && e.node.url === A) setTimeout(() => controller.abort(), 10)
      },
    })
    const graph = await walking
    expect(graph.cancelled).toBe(true)
    expect(graph.nodes.find((n) => n.url === A)?.status).toBe('visited')
    expect(graph.nodes.find((n) => n.url === B)?.status).toBe('unvisited')
  })

  it('returns immediately when already aborted, without any request', async () => {
    const { calls } = mockNetwork({ [A]: {} })
    const controller = new AbortController()
    controller.abort()
    const graph = await walkTopology([A], { signal: controller.signal })
    expect(graph.cancelled).toBe(true)
    expect(calls[A]).toBeUndefined()
  })

  it('records an invalid seed as unreachable', async () => {
    mockNetwork({})
    const graph = await walkTopology(['not a url'])
    expect(graph.nodes[0]).toMatchObject({ url: 'not a url', status: 'unreachable' })
  })
})
