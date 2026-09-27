import { request } from './http.js'
import type { components } from './generated.js'

export type NameClaim = components['schemas']['NameClaimResponse']
export type NameClaimRequest = components['schemas']['NameClaimRequest']

/** `GET /shards/name/{name}` on `nodeUrl`: the shard whose owner has proven control of
 * `name` (for example a domain). Public, unauthenticated, no credentials sent. */
export function resolveName(nodeUrl: string, name: string, options: { signal?: AbortSignal } = {}): Promise<NameClaim> {
  return request<NameClaim>(nodeUrl, `/shards/name/${encodeURIComponent(name)}`, { signal: options.signal })
}

/** `GET /shards/{id}/name-claims`: the names bound to a self-certifying shard id. */
export function listShardNames(nodeUrl: string, selfCertifyingId: string, options: { signal?: AbortSignal } = {}): Promise<NameClaim[]> {
  return request<NameClaim[]>(nodeUrl, `/shards/${encodeURIComponent(selfCertifyingId)}/name-claims`, { signal: options.signal })
}

/** `POST /shards/{id}/name-claims`: submits an already-signed claim binding `claim.name` to the
 * shard. The claim must be signed with the shard's own key; the node checks the proof itself. */
export function submitNameClaim(nodeUrl: string, claim: NameClaimRequest, options: { signal?: AbortSignal } = {}): Promise<NameClaim> {
  return request<NameClaim>(nodeUrl, `/shards/${encodeURIComponent(claim.self_certifying_id)}/name-claims`, {
    method: 'POST',
    body: claim,
    signal: options.signal,
  })
}
