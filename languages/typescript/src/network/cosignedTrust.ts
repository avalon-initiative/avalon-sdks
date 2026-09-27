// Network verification that requires a witness majority from the caller's own known list.
import { getCosignedTreeHead } from '../ledger.js'
import { verifyCosignedTreeHead } from './witness.js'
import { fetchNetworkTrustStatus, evaluateNetworkTrust, type NetworkTrustStatus } from './verifyNetwork.js'
import type { TrustAnchorEntry } from './trustAnchors.js'
import { buildKnownList, type BuildKnownListOptions } from './knownList.js'
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

/** `'auto'` builds the known list from discovery, `'none'` is the plain author check, an array is the caller's own list. */
export type WitnessPolicy = 'auto' | 'none' | KnownWitness[]

/** Built known lists keyed by network id, shared so a list is built once per caller. */
export type KnownListCache = Map<string, Promise<KnownWitness[]>>

export interface PolicyVerifyOptions extends CosignedVerifyOptions {
  witnessPolicy?: WitnessPolicy
  /** Tuning for the automatic list (capacity, anchor slots, prefix cap, random source). */
  knownListOptions?: Omit<BuildKnownListOptions, 'entry'>
  /** Defaults to a fresh cache, so a list is only reused when the caller passes one. */
  knownLists?: KnownListCache
}

/**
 * Trust check under a witness policy. An explicit `knownWitnesses` wins over `witnessPolicy`, which
 * defaults to `'auto'`. A list of fewer than two is exactly the plain author check; two or more
 * require the cosigned majority and fail closed as `mismatch`. Never throws.
 */
export async function fetchPolicyNetworkTrustStatus(
  anchors: TrustAnchorEntry[],
  serverUrl: string,
  options: PolicyVerifyOptions = {},
): Promise<NetworkTrustStatus> {
  const { witnessPolicy, knownListOptions, knownLists, ...cosigned } = options
  const policy = cosigned.knownWitnesses ?? witnessPolicy ?? 'auto'
  if (Array.isArray(policy)) {
    return fetchCosignedNetworkTrustStatus(anchors, serverUrl, { ...cosigned, knownWitnesses: policy })
  }
  if (policy === 'none') return fetchNetworkTrustStatus(anchors, serverUrl)
  const plain = await fetchNetworkTrustStatus(anchors, serverUrl)
  if (plain.kind !== 'verified') return plain
  const cache = knownLists ?? new Map()
  const networkId = plain.entry.network_id
  let list = cache.get(networkId)
  if (!list) {
    list = buildKnownList({ ...knownListOptions, entry: plain.entry })
    cache.set(networkId, list)
  }
  const known = await list
  if (known.length < 2) return plain
  return fetchCosignedNetworkTrustStatus(anchors, serverUrl, { ...cosigned, knownWitnesses: known })
}
