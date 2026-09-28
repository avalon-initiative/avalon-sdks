// The invariant this module exists for: `network_id` alone is never
// sufficient to trust a server, since it's a plain string with zero
// cryptographic authority — only a Signed Tree Head that verifies against
// the claimed network's pinned `verify_key` actually establishes which
// network a server is. Mirrors `crates/chain/src/sth.rs::verify_tree_head`'s
// own contract: malformed hex or a wrong-length signature/key fails closed
// (`false`/a rejected status), never throws.
import type { SignedTreeHeadResponse } from '../types.js'
import { getLatestSth } from '../ledger.js'
import { signingMessage } from './sthMessage.js'
import { strictHexToBytes, verifyCofactorless } from './strictEd25519.js'
import type { TrustAnchorEntry } from './trustAnchors.js'

/**
 * Verifies `sth`'s Ed25519 signature against `verifyKeyHex` (lowercase hex,
 * 32 bytes) — `false` for any malformed input (bad hex, wrong-length
 * signature or key) as well as an outright-invalid signature, never throws. The check is
 * cofactorless with S below the group order and R compared byte for byte, the same rule the
 * server applies.
 */
export function verifyTreeHead(verifyKeyHex: string, sth: SignedTreeHeadResponse): boolean {
  try {
    const verifyKey = strictHexToBytes(verifyKeyHex)
    const signature = strictHexToBytes(sth.signature)
    if (!verifyKey || verifyKey.length !== 32) return false
    if (!signature || signature.length !== 64) return false
    return verifyCofactorless(verifyKey, signingMessage(sth), signature)
  } catch {
    // A malformed created_at or tree_size, or anything else attacker-influenced input could
    // throw on, fails closed.
    return false
  }
}

/**
 * Exactly one of these four states applies to any fetch attempt — a caller
 * must never treat anything but `'verified'` as "connected to the real
 * network."
 */
export type NetworkTrustStatus =
  // The claimed network_id is pinned and the STH signature checks out —
  // this really is the network it says it is.
  | { kind: 'verified'; entry: TrustAnchorEntry }
  // The claimed network_id is pinned, but the signature does NOT verify
  // against the pinned key — the impostor case this exists to catch.
  // Never silently downgraded to "unknown-network".
  | { kind: 'mismatch'; entry: TrustAnchorEntry; claimedNetworkId: string }
  // The claimed network_id isn't in the bundled trust-anchor list at all.
  | { kind: 'unknown-network'; claimedNetworkId: string }
  // Fetching or parsing the server's latest Signed Tree Head itself failed.
  | { kind: 'unreachable'; detail: string }

/**
 * The invariant this module is for: `network_id` alone is never sufficient.
 * Given the STH a server actually returned and every network this build
 * has a pinned key for, decides which of `NetworkTrustStatus`'s first
 * three states applies. Split out from the network-fetch layer so this
 * pure decision logic is directly unit-testable.
 */
export function evaluateNetworkTrust(
  anchors: TrustAnchorEntry[],
  sth: SignedTreeHeadResponse,
): NetworkTrustStatus {
  const entry = anchors.find((candidate) => candidate.network_id === sth.network_id)
  if (!entry) {
    return { kind: 'unknown-network', claimedNetworkId: sth.network_id }
  }
  if (!verifyTreeHead(entry.verify_key, sth)) {
    return { kind: 'mismatch', entry, claimedNetworkId: sth.network_id }
  }
  return { kind: 'verified', entry }
}

/**
 * Fetches `GET /ledger/sth/latest` from `serverUrl` and evaluates it
 * against `anchors` — the shared fetch-then-evaluate path behind both
 * `AvalonClient.verifyNetwork` (a known server) and `discover` (candidate
 * servers with no known-good one yet). Never throws: an unreachable or
 * unparseable server resolves to `{ kind: 'unreachable' }` instead.
 */
export async function fetchNetworkTrustStatus(
  anchors: TrustAnchorEntry[],
  serverUrl: string,
): Promise<NetworkTrustStatus> {
  try {
    const sth = await getLatestSth(serverUrl)
    return evaluateNetworkTrust(anchors, sth)
  } catch (err) {
    return { kind: 'unreachable', detail: err instanceof Error ? err.message : String(err) }
  }
}
