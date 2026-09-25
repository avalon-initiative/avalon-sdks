import { getTopology } from './nodeTopology.js'
import type { Topology, ObservedLatency, NetworkCoordinate, MirrorSource } from './nodeTopology.js'
import { ProtocolError, RateLimitedError } from './errors.js'

export const WALK_DEFAULT_MAX_NODES = 64
export const WALK_DEFAULT_MAX_DEPTH = 4
export const WALK_DEFAULT_CONCURRENCY = 4
export const WALK_DEFAULT_REQUEST_TIMEOUT_MS = 10_000
export const WALK_DEFAULT_MAX_RETRY_AFTER_MS = 10_000
/** Wait applied to a 429 that carries no usable `Retry-After`. */
const WALK_FALLBACK_RETRY_AFTER_MS = 1_000
const WALK_CEILING_MAX_NODES = 1_000
const WALK_CEILING_MAX_DEPTH = 16
const WALK_CEILING_CONCURRENCY = 32

export type WalkEdgeKind = 'active' | 'mirror' | 'known'
export type WalkFailureReason = 'timeout' | 'http_status' | 'rate_limited' | 'protocol_error' | 'network'
export type WalkNodeStatus = 'visited' | 'unreachable' | 'unvisited'

export interface WalkFailure {
  reason: WalkFailureReason
  /** HTTP status for `http_status` and `rate_limited`. */
  status?: number
  /** `Retry-After` the node sent, for `rate_limited`. */
  retryAfterSeconds?: number
  message: string
}

/** One observation: `from` reported `to`. Latency and coordinate are as measured and
 * reported by `from`, not a symmetric property of the link. */
export interface WalkEdge {
  from: string
  to: string
  kind: WalkEdgeKind
  latency?: ObservedLatency
  coordinate?: NetworkCoordinate
  /** Present on `mirror` edges: the shard mirrored from `to`. */
  mirror?: MirrorSource
}

export interface WalkNode {
  /** Normalized base URL, the node's identity in the graph. */
  url: string
  /** Hops from the nearest seed. */
  depth: number
  /** `unvisited`: discovered but not queried (limit reached or walk cancelled). */
  status: WalkNodeStatus
  /** The node's own view of itself, when it was visited. */
  self?: Topology['self']
  failure?: WalkFailure
  /** Every node that reported this one, in report order. */
  reportedBy: string[]
}

export interface TopologyGraph {
  seeds: string[]
  nodes: WalkNode[]
  edges: WalkEdge[]
  truncated: { maxNodes: boolean; maxDepth: boolean }
  cancelled: boolean
}

export type WalkEvent =
  | { type: 'discovered'; node: WalkNode }
  | { type: 'visited'; node: WalkNode; edges: WalkEdge[] }

export interface WalkOptions {
  /** Most distinct nodes kept in the graph (default 64, ceiling 1000). */
  maxNodes?: number
  /** Deepest hop count queried; seeds are depth 0 (default 4, ceiling 16). */
  maxDepth?: number
  /** Simultaneous requests (default 4, ceiling 32). */
  concurrency?: number
  /** Timeout of each request in milliseconds (default 10000). */
  requestTimeoutMs?: number
  /** Longest `Retry-After` honored before one retry; a longer one is recorded as `rate_limited` (default 10000). */
  maxRetryAfterMs?: number
  /** Aborting stops the walk and resolves with the partial graph, `cancelled: true`. */
  signal?: AbortSignal
  /** Called as nodes are discovered and as each visit completes. */
  onProgress?: (event: WalkEvent) => void
}

/** Lowercased scheme and host, default port dropped, no trailing slash; `undefined` when not an http(s) URL. */
export function normalizeNodeUrl(raw: string): string | undefined {
  let url: URL
  try {
    url = new URL(raw.trim())
  } catch {
    return undefined
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return undefined
  return url.origin + url.pathname.replace(/\/+$/, '')
}

function clamp(value: number | undefined, fallback: number, min: number, max: number): number {
  if (value === undefined || !Number.isFinite(value)) return fallback
  return Math.min(max, Math.max(min, Math.floor(value)))
}

class Cancelled extends Error {}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Cancelled())
    const onAbort = () => {
      clearTimeout(timer)
      reject(new Cancelled())
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}

function classify(error: unknown): WalkFailure {
  const message = error instanceof Error ? error.message : String(error)
  if (error instanceof RateLimitedError) {
    return { reason: 'rate_limited', status: 429, retryAfterSeconds: error.retryAfterSeconds, message }
  }
  const status = (error as { status?: number } | null)?.status
  if (typeof status === 'number') return { reason: 'http_status', status, message }
  if (error instanceof ProtocolError) return { reason: 'protocol_error', message }
  return { reason: 'network', message }
}

async function fetchOnce(url: string, timeoutMs: number, outer?: AbortSignal): Promise<Topology> {
  const controller = new AbortController()
  let timedOut = false
  const timer = setTimeout(() => {
    timedOut = true
    controller.abort()
  }, timeoutMs)
  const onOuterAbort = () => controller.abort()
  outer?.addEventListener('abort', onOuterAbort, { once: true })
  try {
    if (outer?.aborted) throw new Cancelled()
    const topology = await getTopology(url, { signal: controller.signal })
    if (topology === null || typeof topology !== 'object' || Array.isArray(topology)) {
      throw new ProtocolError('topology response is not an object')
    }
    return topology
  } catch (error) {
    if (outer?.aborted) throw new Cancelled()
    if (timedOut) throw Object.assign(new Error(`no response within ${timeoutMs} ms`), { walkTimeout: true })
    throw error
  } finally {
    clearTimeout(timer)
    outer?.removeEventListener('abort', onOuterAbort)
  }
}

/** Fetches one node's topology, retrying once after a bounded `Retry-After` wait on 429. */
async function visitNode(url: string, options: Required<Pick<WalkOptions, 'requestTimeoutMs' | 'maxRetryAfterMs'>>, signal?: AbortSignal): Promise<{ topology?: Topology; failure?: WalkFailure }> {
  for (let attempt = 0; ; attempt++) {
    try {
      return { topology: await fetchOnce(url, options.requestTimeoutMs, signal) }
    } catch (error) {
      if (error instanceof Cancelled) throw error
      if ((error as { walkTimeout?: boolean }).walkTimeout) {
        return { failure: { reason: 'timeout', message: (error as Error).message } }
      }
      const failure = classify(error)
      if (failure.reason !== 'rate_limited' || attempt > 0) return { failure }
      const waitMs = failure.retryAfterSeconds === undefined ? WALK_FALLBACK_RETRY_AFTER_MS : failure.retryAfterSeconds * 1000
      if (waitMs > options.maxRetryAfterMs) return { failure }
      await sleep(waitMs, signal)
    }
  }
}

/**
 * Walks the overlay outward from `seeds`, breadth-first, by asking each node for its own
 * `GET /nodes/topology` view. No node holds the whole graph, so the result is the union of what
 * the reachable nodes report. Read-only and always bounded: limits apply even with no options.
 * Unreachable nodes are recorded with a reason and never stop the walk.
 */
export async function walkTopology(seeds: string[], options: WalkOptions = {}): Promise<TopologyGraph> {
  const maxNodes = clamp(options.maxNodes, WALK_DEFAULT_MAX_NODES, 1, WALK_CEILING_MAX_NODES)
  const maxDepth = clamp(options.maxDepth, WALK_DEFAULT_MAX_DEPTH, 0, WALK_CEILING_MAX_DEPTH)
  const concurrency = clamp(options.concurrency, WALK_DEFAULT_CONCURRENCY, 1, WALK_CEILING_CONCURRENCY)
  const requestOptions = {
    requestTimeoutMs: clamp(options.requestTimeoutMs, WALK_DEFAULT_REQUEST_TIMEOUT_MS, 1, 120_000),
    maxRetryAfterMs: clamp(options.maxRetryAfterMs, WALK_DEFAULT_MAX_RETRY_AFTER_MS, 0, 120_000),
  }
  const signal = options.signal

  const nodes = new Map<string, WalkNode>()
  const edges: WalkEdge[] = []
  const truncated = { maxNodes: false, maxDepth: false }
  const seedUrls: string[] = []

  const discover = (raw: string, depth: number, reporter?: string): WalkNode | undefined => {
    const url = normalizeNodeUrl(raw)
    if (url === undefined) return undefined
    let node = nodes.get(url)
    if (node === undefined) {
      if (nodes.size >= maxNodes) {
        truncated.maxNodes = true
        return undefined
      }
      node = { url, depth, status: 'unvisited', reportedBy: [] }
      nodes.set(url, node)
      options.onProgress?.({ type: 'discovered', node })
    }
    if (reporter !== undefined && !node.reportedBy.includes(reporter)) node.reportedBy.push(reporter)
    return node
  }

  let level: WalkNode[] = []
  for (const seed of seeds) {
    const node = discover(seed, 0)
    if (node !== undefined) {
      if (!seedUrls.includes(node.url)) seedUrls.push(node.url)
      if (!level.includes(node)) level.push(node)
    } else if (normalizeNodeUrl(seed) === undefined) {
      const raw = seed.trim()
      if (!nodes.has(raw) && nodes.size < maxNodes) {
        const invalid: WalkNode = { url: raw, depth: 0, status: 'unreachable', reportedBy: [], failure: { reason: 'protocol_error', message: 'not an http(s) URL' } }
        nodes.set(raw, invalid)
        seedUrls.push(raw)
        options.onProgress?.({ type: 'discovered', node: invalid })
        options.onProgress?.({ type: 'visited', node: invalid, edges: [] })
      }
    }
  }

  const visit = async (node: WalkNode, next: WalkNode[]): Promise<void> => {
    const outcome = await visitNode(node.url, requestOptions, signal)
    if (outcome.failure !== undefined || outcome.topology === undefined) {
      node.status = 'unreachable'
      node.failure = outcome.failure
      options.onProgress?.({ type: 'visited', node, edges: [] })
      return
    }
    const topology = outcome.topology
    node.status = 'visited'
    node.self = topology.self
    const produced: WalkEdge[] = []
    const report = (target: string, edge: Omit<WalkEdge, 'from' | 'to'>) => {
      const child = discover(target, node.depth + 1, node.url)
      if (child === undefined || child.url === node.url) return
      const full: WalkEdge = { from: node.url, to: child.url, ...edge }
      produced.push(full)
      edges.push(full)
      if (child.status === 'unvisited' && child.depth === node.depth + 1 && !next.includes(child)) {
        if (child.depth > maxDepth) truncated.maxDepth = true
        else next.push(child)
      }
    }
    for (const n of topology.neighbors ?? []) {
      report(n.base_url, {
        kind: 'active',
        ...(n.latency ? { latency: { ...n.latency, observed_by: node.url } } : {}),
        ...(n.coordinate ? { coordinate: n.coordinate } : {}),
      })
    }
    for (const m of topology.mirrors ?? []) report(m.source_url, { kind: 'mirror', mirror: m })
    for (const k of topology.known ?? []) report(k.base_url, { kind: 'known' })
    options.onProgress?.({ type: 'visited', node, edges: produced })
  }

  let cancelled = false
  try {
    while (level.length > 0) {
      const queue = level.filter((n) => n.status === 'unvisited' && n.depth <= maxDepth)
      const next: WalkNode[] = []
      let cursor = 0
      const worker = async () => {
        while (cursor < queue.length) {
          if (signal?.aborted) throw new Cancelled()
          await visit(queue[cursor++], next)
        }
      }
      const settled = await Promise.allSettled(Array.from({ length: Math.min(concurrency, queue.length) }, worker))
      for (const result of settled) {
        if (result.status === 'rejected') throw result.reason
      }
      level = next
    }
  } catch (error) {
    if (!(error instanceof Cancelled)) throw error
    cancelled = true
  }

  return { seeds: seedUrls, nodes: [...nodes.values()], edges, truncated, cancelled: cancelled || signal?.aborted === true }
}
