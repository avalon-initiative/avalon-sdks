// Public, unauthenticated ledger reads — free-standing
// functions, not session methods, since `GET /ledger/sth/latest` needs no
// session at all. See crates/server/src/settlement.rs::latest_sth.
import { request } from './http.js'
import type { CosignedTreeHead, CosignedTreeHeadResponse, SignedTreeHeadResponse } from './types.js'

/** `GET /ledger/sth/latest` — the network's current Signed Tree Head.
 * This just fetches the wire shape; see `./network/verifyNetwork.js` and
 * `AvalonClient.verifyNetwork` for verifying the returned signature/root
 * hash against a pinned trust anchor. */
export function getLatestSth(serverUrl: string): Promise<SignedTreeHeadResponse> {
  return request<SignedTreeHeadResponse>(serverUrl, '/ledger/sth/latest')
}

/** `GET /ledger/sth/latest?shard_id=…` or `/ledger/sth/{treeSize}?shard_id=…`: a head of one shard,
 * with `signing_public_key` when the node serves one. Unverified; see `verifySelfCertifyingTreeHead`. */
export function getShardTreeHead(
  serverUrl: string,
  shardId: string,
  options: { treeSize?: number; signal?: AbortSignal } = {},
): Promise<SignedTreeHeadResponse> {
  const path = options.treeSize === undefined ? '/ledger/sth/latest' : `/ledger/sth/${options.treeSize}`
  return request<SignedTreeHeadResponse>(serverUrl, path, { query: { shard_id: shardId }, signal: options.signal })
}

/** `GET /ledger/sth/latest` or `/ledger/sth/{treeSize}` with `?witnesses=1`: the head plus the
 * cosignatures the node holds, each bound to that head. Unverified; see `verifyCosignedTreeHead`. */
export async function getCosignedTreeHead(
  serverUrl: string,
  options: { shardId?: string; treeSize?: number; signal?: AbortSignal } = {},
): Promise<CosignedTreeHead> {
  const query: Record<string, string> = { witnesses: '1' }
  if (options.shardId !== undefined) query.shard_id = options.shardId
  const path = options.treeSize === undefined ? '/ledger/sth/latest' : `/ledger/sth/${options.treeSize}`
  const { cosignatures, ...sth } = await request<CosignedTreeHeadResponse>(serverUrl, path, {
    query,
    signal: options.signal,
  })
  return {
    sth,
    cosignatures: (cosignatures ?? []).map((cosig) => ({
      tree_size: sth.tree_size,
      root_hash: sth.root_hash,
      network_id: sth.network_id,
      author_created_at: sth.created_at,
      witness_key_id: cosig.witness_key_id,
      observed_at: cosig.observed_at,
      signature: cosig.signature,
    })),
  }
}
