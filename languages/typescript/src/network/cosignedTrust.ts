// Network verification that requires a witness majority from the caller's own known list.
import { getCosignedTreeHead } from '../ledger.js'
import { verifyCosignedTreeHead } from './witness.js'
import { fetchNetworkTrustStatus, evaluateNetworkTrust, type NetworkTrustStatus } from './verifyNetwork.js'
import type { TrustAnchorEntry } from './trustAnchors.js'
import type { KnownWitness } from '../types.js'

export const DEFAULT_COSIGN_FRESHNESS_SECONDS = 600

export interface CosignedVerifyOptions {
  /** Witnesses the caller trusts. Never derive this from the node being checked. Fewer than two behaves as no known list. */
  knownWitnesses?: KnownWitness[]
  /** How old a cosignature may be, in seconds. Default 600. */
  freshnessSeconds?: number
  /** Clock override for tests. */
  now?: Date
}

/**
 * Like `fetchNetworkTrustStatus`, but with two or more known witnesses the head must also carry a
 * cosigned majority of them; otherwise the result is `mismatch`. Never throws.
 */
export async function fetchCosignedNetworkTrustStatus(
  anchors: TrustAnchorEntry[],
  serverUrl: string,
  options: CosignedVerifyOptions = {},
): Promise<NetworkTrustStatus> {
  const known = options.knownWitnesses ?? []
  if (known.length < 2) return fetchNetworkTrustStatus(anchors, serverUrl)
  try {
    const head = await getCosignedTreeHead(serverUrl)
    const status = evaluateNetworkTrust(anchors, head.sth)
    if (status.kind !== 'verified') return status
    const now = options.now ?? new Date()
    const cutoff = new Date(now.getTime() - (options.freshnessSeconds ?? DEFAULT_COSIGN_FRESHNESS_SECONDS) * 1000)
    if (!verifyCosignedTreeHead(status.entry.verify_key, head, known, cutoff, now)) {
      return { kind: 'mismatch', entry: status.entry, claimedNetworkId: head.sth.network_id }
    }
    return status
  } catch (err) {
    return { kind: 'unreachable', detail: err instanceof Error ? err.message : String(err) }
  }
}
