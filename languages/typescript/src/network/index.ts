export { fetchTrustAnchors, TRUST_ANCHORS_URL } from './trustAnchors.js'
export type { TrustAnchorEntry } from './trustAnchors.js'

export { signingMessage, unixSecondsFromRfc3339 } from './sthMessage.js'

export { verifyTreeHead, evaluateNetworkTrust, fetchNetworkTrustStatus } from './verifyNetwork.js'
export type { NetworkTrustStatus } from './verifyNetwork.js'

export { checkTargetNetwork, NetworkTargetMismatchError } from './targetNetwork.js'
export type { TargetNetwork, TargetNetworkTier, NetworkTargetError } from './targetNetwork.js'

export { discover, discoverAmong, DiscoveryFailedError } from './discover.js'
export type { DiscoveryError, DiscoverOptions, DiscoverResult, VerifiedCandidate } from './discover.js'

export {
  witnessSigningMessage,
  verifyWitnessCosignature,
  majorityThreshold,
  isCosignedByMajority,
  verifyCosignedTreeHead,
  findEquivocatingWitnesses,
} from './witness.js'
export { fetchCosignedNetworkTrustStatus, DEFAULT_COSIGN_FRESHNESS_SECONDS } from './cosignedTrust.js'
export type { CosignedVerifyOptions } from './cosignedTrust.js'
