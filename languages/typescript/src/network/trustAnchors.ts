// Trust anchors come from the single canonical `docs/trusted-networks.json`
// in `avalon-protocol`, fetched at runtime from `TRUST_ANCHORS_URL`. A fork
// running its own network repoints that constant at its own repo.

export interface TrustAnchorEntry {
  label: string
  network_id: string
  // Lowercase hex-encoded Ed25519 public key — the settlement operator's
  // STH verify key for this network.
  verify_key: string
  signing_key_id: string
  // The server URL this network is reachable at. Optional: a trust-anchor
  // entry's *key* is what matters for verification, so an entry can be
  // published to pin a key ahead of its deployment having a known public
  // URL yet.
  server_url?: string
  // Which tier this deployment is: 'local-dev' (no real deployment, a
  // freely-generated key checked in to exercise the mechanism end to end),
  // 'dev' (a real but non-production single-node deployment), 'int' (a
  // real, non-production multi-node deployment used to test that changes
  // actually integrate across nodes), or 'prod' (a real mainnet
  // deployment).
  environment: 'local-dev' | 'dev' | 'int' | 'prod'
  // Base URLs of this network's always-on anchor node(s) — the default
  // bootstrap peers a node for this network_id announces to when it has
  // no bootstrap peers of its own configured.
  seed_nodes?: string[]
  notes?: string
}

interface TrustedNetworksFile {
  version: number
  notes?: string
  networks: TrustAnchorEntry[]
}

/** Where the canonical trust-anchor list is published. */
export const TRUST_ANCHORS_URL =
  'https://raw.githubusercontent.com/avalon-initiative/avalon-protocol/main/docs/trusted-networks.json'

/** Fetches and parses the published trust-anchor list from `url`. */
export async function fetchTrustAnchors(
  url: string = TRUST_ANCHORS_URL,
  fetchImpl: typeof fetch = fetch,
): Promise<TrustAnchorEntry[]> {
  const response = await fetchImpl(url, { signal: AbortSignal.timeout(5000) })
  if (!response.ok) throw new Error(`trust-anchor fetch failed: ${response.status}`)
  const file = (await response.json()) as TrustedNetworksFile
  return file.networks
}
