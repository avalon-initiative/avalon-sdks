// The shard family head: one owner's sibling shards (`{namespace}:{slug}` and
// `{namespace}:{slug}/{instance}`) committed under a single recomputable root, served by
// `GET /ledger/shard-family`. Nothing signs the root; anyone recomputes it from the member heads.
// conformance/vectors/shard-family-head.json is the shared arbiter.
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils.js'

const LEAF_TAG = 'avalon-shard-family-leaf-v1'
const EMPTY_TAG = 'avalon-shard-family-empty-v1'
const MAX_INSTANCE_LEN = 64
const INSTANCE = /^[a-z0-9][a-z0-9-]*$/
// Unicode White_Space, as in Rust `char::is_whitespace`.
const WHITESPACE = /[\t-\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/u
const encoder = new TextEncoder()

/** The fields of a member's head that its leaf commits to. `treeSize` is a bigint beyond 2^53. */
export interface FamilyHead {
  shard_id: string
  tree_size: number | bigint
  // The member's own Merkle root, lowercase hex.
  root_hash: string
  signing_key_id: string
  signature: string
}

/** A member head as the node serves it. */
export interface FamilyMember extends FamilyHead {
  // RFC 3339; not part of the leaf.
  created_at: string
}

/** An RFC 6962 inclusion proof of one member head against the family root. */
export interface FamilyProof {
  shard_id: string
  // Position of the member in shard id order.
  leaf_index: number
  // Number of members the root commits to.
  tree_size: number
  // Hex sibling hashes, leaf to root.
  path: string[]
}

/** `GET /ledger/shard-family` response. */
export interface ShardFamilyResponse {
  owner: string
  root_hash: string
  shard_count: number
  // A known family member has no head here, so `members` may be incomplete.
  partial: boolean
  missing_shard_ids: string[]
  // The exact heads `root_hash` commits to, in shard id order.
  members: FamilyMember[]
  // Present only when a `member` was requested.
  proof?: FamilyProof
}

/** The owner id (`{namespace}:{slug}`) a shard id belongs to; `core`, `node:` ids and anything
 * that does not parse have no family. */
export function shardFamilyOwner(shardId: string): string | null {
  if (typeof shardId !== 'string') return null
  const colon = shardId.indexOf(':')
  if (colon < 0) return null
  const namespace = shardId.slice(0, colon)
  if (namespace !== 'game' && namespace !== 'app' && namespace !== 'service') return null
  const rest = shardId.slice(colon + 1)
  const slash = rest.indexOf('/')
  const owner = slash < 0 ? rest : rest.slice(0, slash)
  if (owner === '' || WHITESPACE.test(owner) || owner.includes(':')) return null
  if (slash >= 0) {
    const instance = rest.slice(slash + 1)
    if (instance.length > MAX_INSTANCE_LEN || !INSTANCE.test(instance)) return null
  }
  return `${namespace}:${owner}`
}

/** Whether `owner` is a well-formed family owner id: an owned shard id with no instance. */
export function isFamilyOwnerId(owner: string): boolean {
  return shardFamilyOwner(owner) === owner
}

/** Whether `shardId` belongs to the family owned by `owner`. */
export function isFamilyMember(owner: string, shardId: string): boolean {
  const found = shardFamilyOwner(shardId)
  return found !== null && found === owner
}

function u32(n: number): Uint8Array {
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, n)
  return out
}

function text(value: string): Uint8Array {
  const bytes = encoder.encode(value)
  return concatBytes(u32(bytes.length), bytes)
}

function leafBytes(owner: string, head: FamilyHead): Uint8Array {
  const size = new Uint8Array(8)
  new DataView(size.buffer).setBigInt64(0, BigInt(head.tree_size))
  return concatBytes(
    encoder.encode(LEAF_TAG),
    text(owner),
    text(head.shard_id),
    size,
    text(head.root_hash),
    text(head.signing_key_id),
    text(head.signature),
  )
}

const leafHash = (data: Uint8Array): Uint8Array => sha256(concatBytes(Uint8Array.of(0), data))
const nodeHash = (left: Uint8Array, right: Uint8Array): Uint8Array =>
  sha256(concatBytes(Uint8Array.of(1), left, right))

// The largest power of two strictly below n (n >= 2).
function splitPoint(n: number): number {
  let k = 1
  while (k * 2 < n) k *= 2
  return k
}

function mth(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 1) return leafHash(leaves[0])
  const k = splitPoint(leaves.length)
  return nodeHash(mth(leaves.slice(0, k)), mth(leaves.slice(k)))
}

function compareBytes(a: string, b: string): number {
  const x = encoder.encode(a)
  const y = encoder.encode(b)
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i]
  return x.length - y.length
}

/** The family root over `heads`: heads of other owners are ignored, the rest are ordered by
 * shard id bytes, so the input order does not matter. Lowercase hex. */
export function familyRoot(owner: string, heads: FamilyHead[]): string {
  const members = heads
    .filter((h) => isFamilyMember(owner, h.shard_id))
    .sort((a, b) => compareBytes(a.shard_id, b.shard_id))
  if (members.length === 0) return bytesToHex(sha256(concatBytes(encoder.encode(EMPTY_TAG), text(owner))))
  return bytesToHex(mth(members.map((h) => leafBytes(owner, h))))
}

function decode32(hex: unknown): Uint8Array | null {
  if (typeof hex !== 'string' || hex.length !== 64) return null
  try {
    return hexToBytes(hex)
  } catch {
    return null
  }
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i])
}

function verifyPath(m: number, n: number, leaf: Uint8Array, proof: Uint8Array[]): Uint8Array | null {
  if (n <= 1) return proof.length === 0 ? leaf : null
  const k = splitPoint(n)
  if (proof.length === 0) return null
  const last = proof[proof.length - 1]
  const rest = proof.slice(0, -1)
  if (m < k) {
    const left = verifyPath(m, k, leaf, rest)
    return left && nodeHash(left, last)
  }
  const right = verifyPath(m - k, n - k, leaf, rest)
  return right && nodeHash(last, right)
}

/** Verifies that `head` (a head of `head.shard_id`) is a member of `owner`'s family whose root
 * is `rootHash`. Any malformed input is a failure; never throws. */
export function verifyFamilyInclusion(owner: string, rootHash: string, proof: FamilyProof, head: FamilyHead): boolean {
  try {
    if (!isFamilyMember(owner, head.shard_id)) return false
    const { leaf_index: index, tree_size: size } = proof
    if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || index < 0 || index >= size) return false
    const root = decode32(rootHash)
    if (!root) return false
    const path = proof.path.map(decode32)
    if (path.some((p) => p === null)) return false
    const rebuilt = verifyPath(index, size, leafHash(leafBytes(owner, head)), path as Uint8Array[])
    return rebuilt !== null && equal(rebuilt, root)
  } catch {
    return false
  }
}

/** Whether `response.root_hash` is what `familyRoot` gives for the served members. */
export function familyRootMatches(response: ShardFamilyResponse): boolean {
  return familyRoot(response.owner, response.members) === response.root_hash
}

/** Whether the served proof verifies for its member against `root_hash`; false when absent. */
export function familyProofVerifies(response: ShardFamilyResponse): boolean {
  const proof = response.proof
  if (!proof) return false
  const member = response.members.find((m) => m.shard_id === proof.shard_id)
  return member !== undefined && verifyFamilyInclusion(response.owner, response.root_hash, proof, member)
}

const ROUTE_TAG = 'avalon-shard-route-v1'

/** The rendezvous weight of `shardId` for `key` under `owner`: SHA-256 of `avalon-shard-route-v1`
 * then owner, key and shard id, each as a u32 big-endian byte length and its UTF-8 bytes. */
export function routeWeight(owner: string, key: string, shardId: string): Uint8Array {
  return sha256(concatBytes(encoder.encode(ROUTE_TAG), text(owner), text(key), text(shardId)))
}

function compareWeights(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i]
  return 0
}

/** The sibling of `owner`'s family a write for `key` should go to, or null when no candidate is a
 * family member. Highest-random-weight hashing over `routeWeight`, so the same key and set always
 * give the same sibling and adding or removing one only moves the keys that must move. Ids outside
 * the family are ignored, duplicates count once and the order of `siblings` does not matter. Equal
 * weights (only possible for equal ids) go to the bytewise smaller id. This is routing only: writes
 * to different siblings are never atomic together. */
export function routeWrite(owner: string, key: string, siblings: readonly string[]): string | null {
  let best: { id: string; weight: Uint8Array } | null = null
  for (const id of siblings) {
    if (!isFamilyMember(owner, id)) continue
    const weight = routeWeight(owner, key, id)
    const order = best === null ? 1 : compareWeights(weight, best.weight) || compareBytes(best.id, id)
    if (order > 0) best = { id, weight }
  }
  return best === null ? null : best.id
}

/** The served members' shard ids, in shard id order. */
export function familySiblingIds(response: ShardFamilyResponse): string[] {
  return response.members.map((m) => m.shard_id)
}

/** The sibling a write for `key` should go to among the served members (see `routeWrite`). A
 * `partial` response omits siblings that have no head here, so it can route differently from the
 * full set. */
export function familyRouteWrite(response: ShardFamilyResponse, key: string): string | null {
  return routeWrite(response.owner, key, familySiblingIds(response))
}
