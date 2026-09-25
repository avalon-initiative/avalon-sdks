// Zero-URL bootstrap: a caller who only knows which network they want to
// join, not which of its nodes to talk to.
import { fetchTrustAnchors } from './trustAnchors.js'
import type { TrustAnchorEntry } from './trustAnchors.js'
import { fetchNetworkTrustStatus } from './verifyNetwork.js'
import type { NetworkTrustStatus } from './verifyNetwork.js'
import { checkTargetNetwork, NetworkTargetMismatchError, type TargetNetwork } from './targetNetwork.js'

/** Why `discover` couldn't resolve `target` to a live, verified server. */
export type DiscoveryError =
  // No published trust anchor matches `target` at all, so there was nothing
  // to even attempt a connection to.
  | { kind: 'no-candidates'; target: string }
  // The published trust-anchor list couldn't be fetched.
  | { kind: 'anchors-unavailable'; target: string; reason: string }
  // At least one candidate URL was tried, but none of them verified as
  // `target` — carries every attempt's outcome so a caller can surface
  // something more useful than "it didn't work."
  | { kind: 'none-verified'; target: string; attempts: Array<{ url: string; reason: string }> }

export class DiscoveryFailedError extends Error {
  readonly detail: DiscoveryError
  constructor(detail: DiscoveryError) {
    const message =
      detail.kind === 'anchors-unavailable'
        ? `trust-anchor list unavailable: ${detail.reason}`
        : detail.kind === 'no-candidates'
          ? `no published trust anchor matches target network ${detail.target}`
          : `no candidate server for target network ${detail.target} verified: ${JSON.stringify(detail.attempts)}`
    super(message)
    this.name = 'DiscoveryFailedError'
    this.detail = detail
  }
}

function describeTarget(target: TargetNetwork): string {
  return target.kind === 'network-id' ? target.networkId : `${target.tier} (declared by tier)`
}

function entryMatchesTarget(entry: TrustAnchorEntry, target: TargetNetwork): boolean {
  if (target.kind === 'network-id') return entry.network_id === target.networkId
  return (
    (target.tier === 'dev' && entry.environment === 'dev') ||
    (target.tier === 'int' && entry.environment === 'int') ||
    (target.tier === 'mainnet' && entry.environment === 'prod')
  )
}

/** Bounds on the latency ranking `discover` applies among verified candidates. */
export interface DiscoverOptions {
  /** At most this many verified candidates are collected and timed. Default 5. */
  maxTimed?: number
  /** Timeout for each timing request, in milliseconds. Default 2000. */
  probeTimeoutMs?: number
  /** After the first candidate verifies, how long to keep verifying further ones. Default 2000. */
  collectWindowMs?: number
}

/** A verified candidate and its measured `GET /nodes/status` round trip; `null` when not measured or the probe failed. */
export interface VerifiedCandidate {
  serverUrl: string
  latencyMs: number | null
}

export interface DiscoverResult {
  serverUrl: string
  entry: TrustAnchorEntry
  /** Every verified candidate, in selection order (measured fastest first, then unmeasured in candidate order). */
  verified: VerifiedCandidate[]
}

async function timeProbe(serverUrl: string, timeoutMs: number): Promise<number | null> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  const start = performance.now()
  try {
    const response = await fetch(new URL('/nodes/status', serverUrl).toString(), { signal: controller.signal })
    if (!response.ok) return null
    return performance.now() - start
  } catch {
    return null
  } finally {
    clearTimeout(timer)
  }
}

function withinMs<T>(promise: Promise<T>, ms: number): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => resolve(undefined), ms)
    promise.then(
      (v) => {
        clearTimeout(timer)
        resolve(v)
      },
      (e) => {
        clearTimeout(timer)
        reject(e)
      },
    )
  })
}

/**
 * `discover`'s actual logic, taking `anchors` explicitly rather than always
 * reading the published trust-anchor list, so tests can supply a mock server's
 * own key instead of needing to forge a signature for a real published entry.
 */
export async function discoverAmong(
  anchors: TrustAnchorEntry[],
  target: TargetNetwork,
  options: DiscoverOptions = {},
): Promise<DiscoverResult> {
  const maxTimed = options.maxTimed ?? 5
  const probeTimeoutMs = options.probeTimeoutMs ?? 2000
  const collectWindowMs = options.collectWindowMs ?? 2000
  const attempts: Array<{ url: string; reason: string }> = []
  const verified: Array<{ serverUrl: string; entry: TrustAnchorEntry }> = []
  let triedAny = false
  let firstVerifiedAt = 0

  collect: for (const entry of anchors) {
    if (!entryMatchesTarget(entry, target)) continue
    const candidates = [...(entry.server_url ? [entry.server_url] : []), ...(entry.seed_nodes ?? [])]
    for (const candidate of candidates) {
      if (verified.length >= maxTimed) break collect
      triedAny = true
      const pending = fetchNetworkTrustStatus(anchors, candidate)
      let status: NetworkTrustStatus | undefined
      if (verified.length === 0) {
        status = await pending
      } else {
        const remaining = collectWindowMs - (performance.now() - firstVerifiedAt)
        if (remaining <= 0) break collect
        status = await withinMs(pending, remaining)
        if (status === undefined) break collect
      }
      try {
        const verifiedEntry = checkTargetNetwork(status, target)
        if (verified.length === 0) firstVerifiedAt = performance.now()
        verified.push({ serverUrl: candidate, entry: verifiedEntry })
      } catch (err) {
        const reason = err instanceof NetworkTargetMismatchError ? err.message : String(err)
        attempts.push({ url: candidate, reason })
      }
    }
  }

  if (verified.length === 1) {
    const only = verified[0]!
    return { ...only, verified: [{ serverUrl: only.serverUrl, latencyMs: null }] }
  }
  if (verified.length > 1) {
    const latencies = await Promise.all(verified.map((v) => timeProbe(v.serverUrl, probeTimeoutMs)))
    const ranked = verified
      .map((v, index) => ({ ...v, index, latencyMs: latencies[index]! }))
      .sort((a, b) => {
        if (a.latencyMs === null || b.latencyMs === null) {
          if (a.latencyMs === b.latencyMs) return a.index - b.index
          return a.latencyMs === null ? 1 : -1
        }
        return a.latencyMs - b.latencyMs || a.index - b.index
      })
    const best = ranked[0]!
    return {
      serverUrl: best.serverUrl,
      entry: best.entry,
      verified: ranked.map((r) => ({ serverUrl: r.serverUrl, latencyMs: r.latencyMs })),
    }
  }

  if (!triedAny) {
    throw new DiscoveryFailedError({ kind: 'no-candidates', target: describeTarget(target) })
  }
  throw new DiscoveryFailedError({ kind: 'none-verified', target: describeTarget(target), attempts })
}

/**
 * Resolves `target` to a live, independently-verified `{ serverUrl, entry }`
 * with no server URL supplied up front. Candidates come only from
 * the published trust-anchor list's own `server_url`/`seed_nodes` fields for
 * every entry matching `target` — never anywhere else, so discovery can't
 * be tricked into contacting an unpinned host. Each candidate is fetched
 * and verified exactly like `AvalonClient.verifyNetwork` would, in the
 * published trust-anchor list's order (each entry's `server_url` before its
 * `seed_nodes`). Only candidates whose STH verifies against `target`'s own
 * matching entry are eligible; of those, up to `maxTimed` (5) are timed with
 * one `GET /nodes/status` each, in parallel, and the lowest round trip wins.
 * A failed or timed-out probe ranks after measured ones and ties keep
 * candidate order. With one verified candidate no extra request is made.
 * Extra time over plain first-verified selection is bounded by
 * `collectWindowMs` (2s of further verification after the first success)
 * plus `probeTimeoutMs` (2s).
 */
export async function discover(
  target: TargetNetwork,
  options: DiscoverOptions = {},
): Promise<DiscoverResult> {
  let anchors: TrustAnchorEntry[]
  try {
    anchors = await fetchTrustAnchors()
  } catch (err) {
    throw new DiscoveryFailedError({ kind: 'anchors-unavailable', target: describeTarget(target), reason: String(err) })
  }
  return discoverAmong(anchors, target, options)
}
