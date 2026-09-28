// Opt-in path tracing for real SDK calls. Inside `withTrace`, every request made through
// the shared request path carries `X-Avalon-Trace`, and the decoded `X-Avalon-Trace-Hops`
// answer is returned next to the call's result. Hops are self-reported by the nodes on
// the path and are advisory; a missing, oversized or malformed header never fails a call.
import type { TraceHop } from './nodeTopology.js'

export const TRACE_HEADER = 'x-avalon-trace'
const HOPS_HEADER = 'x-avalon-trace-hops'
const MAX_HEADER_BYTES = 8 * 1024
const MAX_BRANCHES = 8
const MAX_HOPS_PER_BRANCH = 8

/** A hop as `traceRoute` returns it; fields a newer node adds are kept as they arrived. */
export type PathHop = TraceHop & Record<string, unknown>

/** One path from the originating node to a node that handled the request. `outcome` is
 * `"ok"`, `"timeout"` or `"unreachable"`; other values pass through. */
export interface TraceBranch {
  target: string
  outcome: string
  hops: PathHop[]
}

/** The decoded `X-Avalon-Trace-Hops` value. A fan-out reports one branch per target. */
export interface OperationTrace {
  trace_id: string
  branches: TraceBranch[]
  /** Set when the node dropped branches or hops to stay within its size caps. */
  truncated: boolean
}

/** Why a request has no decoded path. `missing` also covers a header the platform does
 * not expose (a browser without CORS exposure). */
export type TraceProblem = 'missing' | 'oversized' | 'malformed' | 'trace_id_mismatch'

/** The traced path of one HTTP request made inside `withTrace`. */
export interface RequestTrace {
  /** The id sent in `X-Avalon-Trace`. */
  trace_id: string
  trace?: OperationTrace
  problem?: TraceProblem
}

/** A call's result and the traced path of each request it made, in order. */
export interface Traced<T> {
  value: T
  requests: RequestTrace[]
}

export interface WithTraceOptions {
  /** Send the trace header. Defaults to false in a browser, where a cross-origin request
   * carrying it needs the node to allow it and the answer is unreadable until the node
   * exposes it; true elsewhere. */
  sendHeader?: boolean
}

interface Scope {
  requests: RequestTrace[]
  sendHeader: boolean
}

interface Storage {
  run<R>(scope: Scope, fn: () => R): R
  getStore(): Scope | undefined
}

function createStorage(): Storage | undefined {
  try {
    const proc = (globalThis as { process?: { getBuiltinModule?: (id: string) => unknown } }).process
    const mod = proc?.getBuiltinModule?.('node:async_hooks') as
      | { AsyncLocalStorage: new () => Storage }
      | undefined
    return mod ? new mod.AsyncLocalStorage() : undefined
  } catch {
    return undefined
  }
}

// Where AsyncLocalStorage is unavailable the scope is process-wide, so overlapping traced
// operations share it.
const storage = createStorage()
let fallback: Scope | undefined

function current(): Scope | undefined {
  return storage ? storage.getStore() : fallback
}

function inBrowser(): boolean {
  return typeof window !== 'undefined' && typeof document !== 'undefined'
}

/** Runs `fn` with tracing on and returns its result with the traced path of each request. */
export async function withTrace<T>(fn: () => Promise<T>, options: WithTraceOptions = {}): Promise<Traced<T>> {
  const scope: Scope = { requests: [], sendHeader: options.sendHeader ?? !inBrowser() }
  let value: T
  if (storage) {
    value = await storage.run(scope, fn)
  } else {
    const previous = fallback
    fallback = scope
    try {
      value = await fn()
    } finally {
      fallback = previous
    }
  }
  return { value, requests: scope.requests }
}

/** The trace id to send for a new request, when tracing is on. */
export function beginRequestTrace(): string | undefined {
  const scope = current()
  return scope?.sendHeader ? globalThis.crypto.randomUUID() : undefined
}

/** Records the decoded outcome of the response to the request sent with `id`. */
export function recordRequestTrace(id: string, headers: Headers): void {
  const scope = current()
  if (!scope) return
  const entry: RequestTrace = { trace_id: id }
  try {
    const raw = headers.get(HOPS_HEADER)
    const result = raw === null ? { problem: 'missing' as const } : decodeTraceHeader(raw, id)
    if ('trace' in result) entry.trace = result.trace
    else entry.problem = result.problem
  } catch {
    entry.problem = 'malformed'
  }
  const at = scope.requests.findIndex((r) => r.trace_id === id)
  if (at >= 0) scope.requests[at] = entry
  else scope.requests.push(entry)
}

/** Decodes an `X-Avalon-Trace-Hops` value for the request sent with `expected`. */
export function decodeTraceHeader(
  value: string,
  expected: string,
): { trace: OperationTrace } | { problem: TraceProblem } {
  if (value.length > MAX_HEADER_BYTES) return { problem: 'oversized' }
  const text = value.trim()
  if (!/^[A-Za-z0-9_-]*$/.test(text)) return { problem: 'malformed' }
  let parsed: unknown
  try {
    const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/'))
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0))
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    return { problem: 'malformed' }
  }
  const trace = shape(parsed)
  if (!trace) return { problem: 'malformed' }
  if (trace.trace_id.toLowerCase() !== expected.toLowerCase()) return { problem: 'trace_id_mismatch' }
  if (trace.branches.length > MAX_BRANCHES) {
    trace.branches.length = MAX_BRANCHES
    trace.truncated = true
  }
  for (const branch of trace.branches) {
    if (branch.hops.length > MAX_HOPS_PER_BRANCH) {
      branch.hops.length = MAX_HOPS_PER_BRANCH
      trace.truncated = true
    }
  }
  return { trace }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function shape(v: unknown): OperationTrace | undefined {
  if (!isObject(v) || typeof v.trace_id !== 'string' || !Array.isArray(v.branches)) return undefined
  const branches: TraceBranch[] = []
  for (const b of v.branches) {
    if (!isObject(b) || !Array.isArray(b.hops) || !b.hops.every(isHop)) return undefined
    branches.push({
      target: typeof b.target === 'string' ? b.target : '',
      outcome: typeof b.outcome === 'string' ? b.outcome : 'ok',
      hops: b.hops as PathHop[],
    })
  }
  return { trace_id: v.trace_id, branches, truncated: v.truncated === true }
}

function isHop(h: unknown): h is PathHop {
  return (
    isObject(h) &&
    typeof h.index === 'number' &&
    typeof h.base_url === 'string' &&
    Array.isArray(h.roles) &&
    typeof h.protocol_version === 'string' &&
    typeof h.processing_ms === 'number'
  )
}
