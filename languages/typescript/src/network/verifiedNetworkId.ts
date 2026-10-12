// The network id a session signs into messages, from the verified trust path and never from the node's own claim.
import { fetchPolicyNetworkTrustStatus, type KnownListCache } from './cosignedTrust.js'
import { fetchTrustAnchors, type TrustAnchorEntry } from './trustAnchors.js'
import type { NetworkTrustStatus } from './verifyNetwork.js'

/** The node's network could not be verified, so nothing was signed or sent. `status` carries the outcome. */
export class NetworkNotVerifiedError extends Error {
  constructor(public readonly status: NetworkTrustStatus) {
    super(`network not verified: ${describe(status)}`)
    this.name = 'NetworkNotVerifiedError'
  }
}

function describe(status: NetworkTrustStatus): string {
  switch (status.kind) {
    case 'verified':
      return 'verified'
    case 'mismatch':
      return `signed tree head does not verify for ${status.claimedNetworkId}`
    case 'unknown-network':
      return `${status.claimedNetworkId} is not a pinned network`
    case 'unreachable':
      return status.detail
  }
}

/** Verifies `serverUrl` against the published trust anchors (default witness policy) and returns the verified
 * network id. Throws `NetworkNotVerifiedError` for a mismatch, an unknown network or an unreachable node. */
export async function resolveVerifiedNetworkId(serverUrl: string, knownLists?: KnownListCache): Promise<string> {
  let anchors: TrustAnchorEntry[]
  try {
    anchors = await fetchTrustAnchors()
  } catch (err) {
    throw new NetworkNotVerifiedError({ kind: 'unreachable', detail: `trust-anchor list unavailable: ${String(err)}` })
  }
  const status = await fetchPolicyNetworkTrustStatus(anchors, serverUrl, { knownLists })
  if (status.kind !== 'verified') throw new NetworkNotVerifiedError(status)
  return status.entry.network_id
}
