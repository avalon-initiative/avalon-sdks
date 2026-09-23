// A caller must explicitly declare intent for which network it expects
// before a write that's gated by network identity — no implicit default is
// ever inferred from the server URL alone; see `checkTargetNetwork`.
import type { NetworkTrustStatus } from './verifyNetwork.js'
import type { TrustAnchorEntry } from './trustAnchors.js'

/** One of the three real deployment tiers a caller can declare intent for
 * without spelling out an exact `network_id` — resolved against whichever
 * pinned entry the server's STH actually verified against, never guessed
 * from the server URL alone. Deliberately only three variants: `'local-dev'`
 * (no real deployment behind it) isn't one of them, so a caller targeting
 * it declares its exact `network_id` via `TargetNetwork.NetworkId` instead. */
export type TargetNetworkTier = 'dev' | 'int' | 'mainnet'

function tierMatches(tier: TargetNetworkTier, environment: TrustAnchorEntry['environment']): boolean {
  return (
    (tier === 'dev' && environment === 'dev') ||
    (tier === 'int' && environment === 'int') ||
    (tier === 'mainnet' && environment === 'prod')
  )
}

/** The network a caller must explicitly declare intent for before a write
 * that's gated by network identity — registering an issuer, most
 * immediately. */
export type TargetNetwork =
  // The exact `network_id` string the caller expects the server to be.
  | { kind: 'network-id'; networkId: string }
  // A deployment-tier shorthand, resolved against the verified entry's
  // `environment` rather than a literal string.
  | { kind: 'tier'; tier: TargetNetworkTier }

function describeTarget(target: TargetNetwork): string {
  return target.kind === 'network-id' ? target.networkId : `${target.tier} (declared by tier)`
}

function targetMatchesEntry(target: TargetNetwork, entry: TrustAnchorEntry): boolean {
  return target.kind === 'network-id' ? entry.network_id === target.networkId : tierMatches(target.tier, entry.environment)
}

/** Why a declared `TargetNetwork` failed `checkTargetNetwork` — never a
 * silent proceed. */
export type NetworkTargetError =
  // The server's network was independently verified, but it isn't the one
  // the caller declared intent for.
  | { kind: 'mismatch'; declared: string; actual: string }
  // The server's claimed network couldn't be independently verified at all
  // (unknown, key mismatch, or unreachable) — refused regardless of what
  // was declared, since there's nothing to compare it against.
  | { kind: 'unverified'; reason: string }

export class NetworkTargetMismatchError extends Error {
  readonly detail: NetworkTargetError
  constructor(detail: NetworkTargetError) {
    const message =
      detail.kind === 'mismatch'
        ? `declared target network ${detail.declared} does not match the server's verified network ${detail.actual}`
        : `server's network could not be independently verified: ${detail.reason}`
    super(message)
    this.name = 'NetworkTargetMismatchError'
    this.detail = detail
  }
}

/**
 * The check this module exists for: a declared `TargetNetwork` only ever
 * proceeds against a server whose `NetworkTrustStatus` is `'verified'`
 * *and* whose verified entry matches what was declared. Returns the
 * matching `TrustAnchorEntry` on success so a caller can read back the
 * exact `network_id` it just confirmed it's talking to; throws
 * `NetworkTargetMismatchError` otherwise.
 */
export function checkTargetNetwork(status: NetworkTrustStatus, target: TargetNetwork): TrustAnchorEntry {
  let entry: TrustAnchorEntry
  switch (status.kind) {
    case 'verified':
      entry = status.entry
      break
    case 'mismatch':
      throw new NetworkTargetMismatchError({
        kind: 'unverified',
        reason: `the server's STH does not verify against the pinned key for ${status.claimedNetworkId}`,
      })
    case 'unknown-network':
      throw new NetworkTargetMismatchError({
        kind: 'unverified',
        reason: `${status.claimedNetworkId} is not a pinned/known network`,
      })
    case 'unreachable':
      throw new NetworkTargetMismatchError({ kind: 'unverified', reason: status.detail })
  }

  if (targetMatchesEntry(target, entry)) {
    return entry
  }
  throw new NetworkTargetMismatchError({
    kind: 'mismatch',
    declared: describeTarget(target),
    actual: entry.network_id,
  })
}
