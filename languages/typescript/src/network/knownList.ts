// Builds a witness known list from discovery: seed nodes are asked for their peers, adverts are
// proof-checked, candidates are probed for liveness and then selected under the diversity rules.
import { getCosignedTreeHead } from '../ledger.js'
import type { CosignedTreeHead, KnownWitness } from '../types.js'
import type { TrustAnchorEntry } from './trustAnchors.js'
import {
  DEFAULT_KNOWN_LIST_ANCHOR_CAPACITY,
  DEFAULT_KNOWN_LIST_CAPACITY,
  DEFAULT_KNOWN_LIST_MAX_PER_PREFIX,
  selectKnownList,
  type KnownListCandidate,
} from './knownListRules.js'
import { verifyTreeHead } from './verifyNetwork.js'
import { DEFAULT_COSIGN_FRESHNESS_SECONDS } from './cosignedTrust.js'
import { findEquivocatingWitnesses, verifyWitnessAnnounce } from './witness.js'

const REQUEST_TIMEOUT_MS = 5000
const MAX_IN_FLIGHT = 4

/** The `GET /nodes/discover` peer shape this module consumes. */
export interface DiscoveredPeer {
  base_url: string
  network_id: string
  witness?: { key_id: string; announced_at: string; proof: string }
}

export interface BuildKnownListOptions {
  /** The network's trust-anchor entry: its id and `seed_nodes` are the only discovery roots. */
  entry: Pick<TrustAnchorEntry, 'network_id' | 'seed_nodes'>
  capacity?: number
  anchorCapacity?: number
  maxPerPrefix?: number
  /** Uniform integer in [0, maxExclusive); defaults to a `crypto.getRandomValues` source. */
  randomInt?: (maxExclusive: number) => number
  now?: Date
  timeoutMs?: number
}

function secureRandomInt(maxExclusive: number): number {
  const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive
  const buf = new Uint32Array(1)
  do {
    crypto.getRandomValues(buf)
  } while (buf[0] >= limit)
  return buf[0] % maxExclusive
}

function normalizeUrl(url: string): string {
  const lower = url.toLowerCase()
  return lower.endsWith('/') ? lower.slice(0, -1) : lower
}

async function fetchJson(url: string, timeoutMs: number): Promise<unknown | null> {
  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) })
    return response.status === 200 ? await response.json() : null
  } catch {
    return null
  }
}

/** Every seed's advertised witnesses that pass the network and advert-proof checks, deduped by key id. */
export async function gatherCandidates(options: BuildKnownListOptions): Promise<KnownListCandidate[]> {
  const seeds = options.entry.seed_nodes ?? []
  const anchorUrls = new Set(seeds.map(normalizeUrl))
  const now = options.now ?? new Date()
  const timeout = options.timeoutMs ?? REQUEST_TIMEOUT_MS
  const responses = await Promise.all(
    seeds.map((seed) => fetchJson(`${seed.replace(/\/$/, '')}/nodes/discover`, timeout)),
  )
  const seen = new Set<string>()
  const candidates: KnownListCandidate[] = []
  for (const body of responses) {
    const peers = (body as { peers?: unknown } | null)?.peers
    if (!Array.isArray(peers)) continue
    for (const peer of peers as DiscoveredPeer[]) {
      const advert = peer?.witness
      if (!advert || typeof peer.base_url !== 'string' || peer.network_id !== options.entry.network_id) continue
      if (typeof advert.key_id !== 'string' || typeof advert.proof !== 'string') continue
      const announced = new Date(String(advert.announced_at))
      if (!verifyWitnessAnnounce(peer.base_url, advert.key_id, announced, advert.proof, now)) continue
      if (seen.has(advert.key_id)) continue
      seen.add(advert.key_id)
      candidates.push({
        witnessKeyId: advert.key_id,
        baseUrl: peer.base_url,
        isAnchor: anchorUrls.has(normalizeUrl(peer.base_url)),
      })
    }
  }
  return candidates
}

async function reachable(baseUrl: string, networkId: string, timeoutMs: number): Promise<boolean> {
  const body = await fetchJson(`${baseUrl.replace(/\/$/, '')}/ledger/sth/latest?shard_id=core`, timeoutMs)
  return (body as { network_id?: unknown } | null)?.network_id === networkId
}

/**
 * Gathers, orders (anchors in seed order, the rest securely shuffled), liveness-probes and selects the
 * known list. Never throws; unreachable seeds yield an empty list.
 */
export async function buildKnownList(options: BuildKnownListOptions): Promise<KnownWitness[]> {
  const capacity = options.capacity ?? DEFAULT_KNOWN_LIST_CAPACITY
  const timeout = options.timeoutMs ?? REQUEST_TIMEOUT_MS
  const randomInt = options.randomInt ?? secureRandomInt
  const gathered = await gatherCandidates(options)
  const seeds = (options.entry.seed_nodes ?? []).map(normalizeUrl)
  const anchors = gathered
    .filter((c) => c.isAnchor)
    .sort((a, b) => seeds.indexOf(normalizeUrl(a.baseUrl)) - seeds.indexOf(normalizeUrl(b.baseUrl)))
  const others = gathered.filter((c) => !c.isAnchor)
  for (let i = others.length - 1; i > 0; i -= 1) {
    const j = randomInt(i + 1)
    ;[others[i], others[j]] = [others[j], others[i]]
  }
  const ordered = [...anchors, ...others].slice(0, 3 * capacity)

  const live: KnownListCandidate[] = []
  const select = () =>
    selectKnownList(
      live,
      capacity,
      options.anchorCapacity ?? DEFAULT_KNOWN_LIST_ANCHOR_CAPACITY,
      options.maxPerPrefix ?? DEFAULT_KNOWN_LIST_MAX_PER_PREFIX,
    )
  for (let i = 0; i < ordered.length && select().length < capacity; i += MAX_IN_FLIGHT) {
    const batch = ordered.slice(i, i + MAX_IN_FLIGHT)
    const results = await Promise.all(batch.map((c) => reachable(c.baseUrl, options.entry.network_id, timeout)))
    batch.forEach((c, k) => {
      if (results[k]) live.push(c)
    })
  }
  const byId = new Map(live.map((c) => [c.witnessKeyId, c]))
  return select().map((id) => ({ witnessKeyId: id, key: id, baseUrl: byId.get(id)?.baseUrl }))
}

export interface EquivocationEvidence {
  treeSize: number
  rootA: string
  rootB: string
  /** Base URLs that served the conflicting head. */
  sources: string[]
  /** Known witnesses whose valid, fresh cosignatures appear on both heads. */
  witnesses: string[]
}

export interface CrossCheckOptions {
  freshnessSeconds?: number
  now?: Date
  timeoutMs?: number
}

/**
 * Asks each known witness with an address for the head at the accepted head's size and reports any
 * author-signed head with a different root. Reports only; never throws and changes no verification result.
 */
export async function crossCheckHead(
  authorKeyHex: string,
  knownList: KnownWitness[],
  accepted: CosignedTreeHead,
  options: CrossCheckOptions = {},
): Promise<EquivocationEvidence[]> {
  const now = options.now ?? new Date()
  const cutoff = new Date(now.getTime() - (options.freshnessSeconds ?? DEFAULT_COSIGN_FRESHNESS_SECONDS) * 1000)
  const timeout = options.timeoutMs ?? REQUEST_TIMEOUT_MS
  const targets = knownList.filter((w) => w.baseUrl)
  const found = new Map<string, { head: CosignedTreeHead; sources: string[] }>()
  for (let i = 0; i < targets.length; i += MAX_IN_FLIGHT) {
    const batch = await Promise.all(
      targets.slice(i, i + MAX_IN_FLIGHT).map(async (w) => {
        try {
          const head = await getCosignedTreeHead(w.baseUrl as string, {
            shardId: 'core',
            treeSize: accepted.sth.tree_size,
            signal: AbortSignal.timeout(timeout),
          })
          return { url: w.baseUrl as string, head }
        } catch {
          return null
        }
      }),
    )
    for (const result of batch) {
      if (!result) continue
      const sth = result.head.sth
      if (
        sth.network_id !== accepted.sth.network_id ||
        sth.tree_size !== accepted.sth.tree_size ||
        sth.root_hash === accepted.sth.root_hash ||
        !verifyTreeHead(authorKeyHex, sth)
      ) {
        continue
      }
      const entry = found.get(sth.root_hash) ?? { head: result.head, sources: [] }
      entry.sources.push(result.url)
      found.set(sth.root_hash, entry)
    }
  }
  return [...found.values()].map(({ head, sources }) => ({
    treeSize: accepted.sth.tree_size,
    rootA: accepted.sth.root_hash,
    rootB: head.sth.root_hash,
    sources,
    witnesses: findEquivocatingWitnesses(authorKeyHex, knownList, cutoff, now, accepted, head),
  }))
}
