// Public, unauthenticated ledger reads — free-standing
// functions, not session methods, since `GET /ledger/sth/latest` needs no
// session at all. See crates/server/src/settlement.rs::latest_sth.
import { request } from './http.js'
import type { SignedTreeHeadResponse } from './types.js'

/** `GET /ledger/sth/latest` — the network's current Signed Tree Head.
 * This just fetches the wire shape; see `./network/verifyNetwork.js` and
 * `AvalonClient.verifyNetwork` for verifying the returned signature/root
 * hash against a pinned trust anchor. */
export function getLatestSth(serverUrl: string): Promise<SignedTreeHeadResponse> {
  return request<SignedTreeHeadResponse>(serverUrl, '/ledger/sth/latest')
}
