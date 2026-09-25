// Zero-URL bootstrap: a caller who only knows which network they want to
// join, not which of its nodes to talk to.
import { fetchTrustAnchors } from './trustAnchors.js'
import type { TrustAnchorEntry } from './trustAnchors.js'
import { fetchNetworkTrustStatus } from './verifyNetwork.js'
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

/**
 * `discover`'s actual logic, taking `anchors` explicitly rather than always
 * reading the published trust-anchor list, so tests can supply a mock server's
 * own key instead of needing to forge a signature for a real published entry.
 */
export async function discoverAmong(
  anchors: TrustAnchorEntry[],
  target: TargetNetwork,
): Promise<{ serverUrl: string; entry: TrustAnchorEntry }> {
  const attempts: Array<{ url: string; reason: string }> = []
  let triedAny = false

  for (const entry of anchors) {
    if (!entryMatchesTarget(entry, target)) continue
    const candidates = [...(entry.server_url ? [entry.server_url] : []), ...(entry.seed_nodes ?? [])]
    for (const candidate of candidates) {
      triedAny = true
      const status = await fetchNetworkTrustStatus(anchors, candidate)
      try {
        const verifiedEntry = checkTargetNetwork(status, target)
        return { serverUrl: candidate, entry: verifiedEntry }
      } catch (err) {
        const reason = err instanceof NetworkTargetMismatchError ? err.message : String(err)
        attempts.push({ url: candidate, reason })
      }
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
 * and verified exactly like `AvalonClient.verifyNetwork` would; the first
 * one whose STH verifies against `target`'s own matching entry wins.
 * Entries are tried in the published trust-anchor list's order, and each
 * entry's `server_url` before its `seed_nodes`, so results are
 * deterministic across runs of the same SDK build.
 */
export async function discover(target: TargetNetwork): Promise<{ serverUrl: string; entry: TrustAnchorEntry }> {
  let anchors: TrustAnchorEntry[]
  try {
    anchors = await fetchTrustAnchors()
  } catch (err) {
    throw new DiscoveryFailedError({ kind: 'anchors-unavailable', target: describeTarget(target), reason: String(err) })
  }
  return discoverAmong(anchors, target)
}
