import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it } from 'vitest'
import { getNodeStatus } from '../src/nodeStatus.js'
import { decodeTraceHeader, withTrace } from '../src/opTrace.js'

const originalFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = originalFetch
})

const fixture = JSON.parse(
  readFileSync(fileURLToPath(new URL('../../../conformance/fixtures/nodes/op-trace.json', import.meta.url)), 'utf-8'),
) as { request_trace_id: string; header: string; decoded: unknown }

const STATUS = JSON.stringify({ protocol_version: '0.1.0', network_id: 'n', roles: ['combined'], stale: false })

const b64 = (v: unknown): string => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url')

function hop(index: number, extra: Record<string, unknown> = {}) {
  return { index, base_url: 'http://n', roles: ['combined'], protocol_version: '0.1.0', processing_ms: 1.5, ...extra }
}

// Answers like a tracing node: `make` builds the hops header from the request's trace id.
function mockNode(make: (id: string) => string | null): { sent: (string | undefined)[] } {
  const sent: (string | undefined)[] = []
  globalThis.fetch = (async (_url: string, init?: RequestInit) => {
    const id = (init?.headers as Record<string, string>)['x-avalon-trace']
    sent.push(id)
    const headers: Record<string, string> = {}
    const value = id === undefined ? null : make(id)
    if (value !== null) headers['x-avalon-trace-hops'] = value
    return new Response(STATUS, { status: 200, headers })
  }) as typeof fetch
  return { sent }
}

describe('withTrace', () => {
  it('returns the result with the decoded hops, extra fields included', async () => {
    const { sent } = mockNode((id) =>
      b64({ trace_id: id, branches: [{ target: '', outcome: 'ok', hops: [hop(0, { path_type: 'relayed' })] }], future: 1 }),
    )
    const out = await withTrace(() => getNodeStatus('http://node.test:8080'), { sendHeader: true })
    expect(out.value.network_id).toBe('n')
    expect(out.requests).toHaveLength(1)
    expect(out.requests[0].trace_id).toBe(sent[0])
    expect(out.requests[0].problem).toBeUndefined()
    expect(out.requests[0].trace?.branches[0].hops[0].path_type).toBe('relayed')
    expect(out.requests[0].trace?.branches[0].hops[0].base_url).toBe('http://n')
  })

  it('sends no header outside withTrace', async () => {
    const { sent } = mockNode(() => null)
    await getNodeStatus('http://node.test:8080')
    expect(sent).toEqual([undefined])
  })

  it('does not send the header by default in a browser', async () => {
    const g = globalThis as Record<string, unknown>
    g.window = {}
    g.document = {}
    try {
      const { sent } = mockNode(() => null)
      const out = await withTrace(() => getNodeStatus('http://node.test:8080'))
      expect(sent).toEqual([undefined])
      expect(out.requests).toEqual([])
      expect(out.value.network_id).toBe('n')
    } finally {
      delete g.window
      delete g.document
    }
  })

  it('reports a missing or unreadable header without failing the call', async () => {
    mockNode(() => null)
    const out = await withTrace(() => getNodeStatus('http://node.test:8080'), { sendHeader: true })
    expect(out.value.network_id).toBe('n')
    expect(out.requests[0].trace).toBeUndefined()
    expect(out.requests[0].problem).toBe('missing')
  })

  it('never fails the call on a bad header', async () => {
    const cases: [string, string][] = [
      ['***', 'malformed'],
      [b64('not json'), 'malformed'],
      [b64({ trace_id: 'x', branches: 'no' }), 'malformed'],
      [b64({ trace_id: 'x', branches: [{ hops: [{ index: 0 }] }] }), 'malformed'],
      ['A'.repeat(9000), 'oversized'],
      [b64({ trace_id: '6f1c2a4e-3b7d-4e0a-9c15-8d2a7b1e5f33', branches: [] }), 'trace_id_mismatch'],
    ]
    for (const [header, problem] of cases) {
      mockNode(() => header)
      const out = await withTrace(() => getNodeStatus('http://node.test:8080'), { sendHeader: true })
      expect(out.value.network_id).toBe('n')
      expect(out.requests[0].problem).toBe(problem)
    }
  })

  it('keeps concurrent traced operations apart', async () => {
    mockNode((id) => b64({ trace_id: id, branches: [{ hops: [hop(0)] }] }))
    const [a, b] = await Promise.all([
      withTrace(() => getNodeStatus('http://a.test'), { sendHeader: true }),
      withTrace(() => getNodeStatus('http://b.test'), { sendHeader: true }),
    ])
    expect(a.requests).toHaveLength(1)
    expect(b.requests).toHaveLength(1)
    expect(a.requests[0].trace_id).not.toBe(b.requests[0].trace_id)
  })
})

describe('decodeTraceHeader', () => {
  it('decodes the recorded header', () => {
    const result = decodeTraceHeader(fixture.header, fixture.request_trace_id)
    if (!('trace' in result)) throw new Error(result.problem)
    expect(result.trace.branches).toHaveLength(2)
    expect(result.trace.branches[0].hops[1].base_url).toBe('http://192.168.7.183:8080')
    expect(result.trace.branches[0].hops[0].to_next_ms).toBeCloseTo(234.655411, 6)
    expect(result.trace.branches[1].outcome).toBe('timeout')
    expect(result.trace.truncated).toBe(false)
  })

  it('caps branches and hops and flags truncation', () => {
    const id = 'a'
    const hops = Array.from({ length: 12 }, (_, i) => hop(i))
    let r = decodeTraceHeader(b64({ trace_id: id, branches: [{ hops }] }), id)
    if (!('trace' in r)) throw new Error(r.problem)
    expect(r.trace.branches[0].hops).toHaveLength(8)
    expect(r.trace.truncated).toBe(true)
    r = decodeTraceHeader(b64({ trace_id: id, branches: Array.from({ length: 10 }, () => ({ hops: [hop(0)] })) }), id)
    if (!('trace' in r)) throw new Error(r.problem)
    expect(r.trace.branches).toHaveLength(8)
  })
})
