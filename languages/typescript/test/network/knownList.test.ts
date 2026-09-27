import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AvalonClient } from '../../src/client.js'
import type { CosignedTreeHead, KnownWitness, SignedTreeHeadResponse } from '../../src/types.js'
import { signingMessage } from '../../src/network/sthMessage.js'
import { buildKnownList, crossCheckHead, gatherCandidates } from '../../src/network/knownList.js'
import { witnessAnnounceMessage, witnessSigningMessage } from '../../src/network/witness.js'

const seed = (n: number) => new Uint8Array(32).fill(n)
const hexKey = (n: number) => bytesToHex(ed25519.getPublicKey(seed(n)))
const NOW = new Date()
const NET = 'net'

function advert(n: number, baseUrl: string, network = NET, announced = NOW) {
  const id = hexKey(n)
  const proof = bytesToHex(ed25519.sign(witnessAnnounceMessage(baseUrl, id, announced), seed(n)))
  return { base_url: baseUrl, network_id: network, witness: { key_id: id, announced_at: announced.toISOString(), proof } }
}

function makeHead(root: string, size = 7): SignedTreeHeadResponse {
  const unsigned = {
    tree_size: size,
    root_hash: root,
    network_id: NET,
    signing_key_id: 'op',
    created_at: NOW.toISOString(),
    protocol_version: 'v1',
  }
  return { ...unsigned, signature: bytesToHex(ed25519.sign(signingMessage({ ...unsigned, signature: '' }), seed(1))) }
}

function cosignWire(w: number, sth: SignedTreeHeadResponse) {
  const base = {
    tree_size: sth.tree_size,
    root_hash: sth.root_hash,
    network_id: sth.network_id,
    author_created_at: sth.created_at,
    witness_key_id: hexKey(w),
    observed_at: new Date(NOW.getTime() - 1000).toISOString(),
  }
  return { witness_key_id: base.witness_key_id, observed_at: base.observed_at, signature: bytesToHex(ed25519.sign(witnessSigningMessage(base), seed(w))) }
}

interface World {
  discover: Record<string, unknown>
  down?: Set<string>
  head?: (url: string, size: string | null) => unknown
}
const calls: string[] = []
let inFlight = 0
let maxInFlight = 0

function stub(world: World) {
  calls.length = 0
  inFlight = 0
  maxInFlight = 0
  vi.stubGlobal('fetch', async (input: string | URL) => {
    const url = String(input)
    calls.push(url)
    inFlight += 1
    maxInFlight = Math.max(maxInFlight, inFlight)
    await new Promise((r) => setTimeout(r, 1))
    inFlight -= 1
    const u = new URL(url)
    if (world.down?.has(u.origin)) throw new Error('down')
    if (u.pathname === '/nodes/discover') {
      const body = world.discover[u.origin]
      return body ? new Response(JSON.stringify(body), { status: 200 }) : new Response('no', { status: 500 })
    }
    if (u.pathname.startsWith('/ledger/sth/')) {
      const size = u.pathname.endsWith('latest') ? null : u.pathname.split('/').pop()!
      const body = world.head ? world.head(u.origin, size) : makeHead('aa'.repeat(32))
      return new Response(JSON.stringify(body), { status: 200 })
    }
    return new Response('?', { status: 404 })
  })
}

afterEach(() => vi.unstubAllGlobals())
const entry = { network_id: NET, seed_nodes: ['http://10.0.0.1:8080', 'http://10.0.1.1:8080'] }
const noShuffle = { randomInt: (max: number) => max - 1 }

describe('discovery', () => {
  it('unions seeds, dedupes by key id, filters network and bad proofs, flags anchors', async () => {
    stub({
      discover: {
        'http://10.0.0.1:8080': {
          peers: [
            advert(2, 'http://10.0.1.1:8080/'),
            advert(3, 'http://a.example.com'),
            advert(4, 'http://b.example.com', 'other-net'),
            { ...advert(5, 'http://c.example.com'), base_url: 'http://evil.example.com' },
            advert(6, 'http://d.example.com', NET, new Date(NOW.getTime() - 7_200_000)),
            { base_url: 'http://plain.example.com', network_id: NET },
          ],
        },
        'http://10.0.1.1:8080': { peers: [advert(3, 'http://a.example.com'), advert(7, 'http://e.example.com')] },
      },
    })
    const got = await gatherCandidates({ entry })
    expect(got.map((c) => [c.witnessKeyId, c.isAnchor])).toEqual([
      [hexKey(2), true],
      [hexKey(3), false],
      [hexKey(7), false],
    ])
  })

  it('skips a failed seed and returns empty when all fail', async () => {
    stub({ discover: { 'http://10.0.1.1:8080': { peers: [advert(2, 'http://a.example.com')] } } })
    expect(await gatherCandidates({ entry })).toHaveLength(1)
    stub({ discover: {} })
    expect(await gatherCandidates({ entry })).toEqual([])
    expect(await buildKnownList({ entry })).toEqual([])
  })
})

describe('buildKnownList', () => {
  const peers = (n: number) => Array.from({ length: n }, (_, i) => advert(10 + i, `http://n${i}.d${i}.example`))

  it('drops unreachable candidates and keeps base urls', async () => {
    stub({ discover: { 'http://10.0.0.1:8080': { peers: peers(3) } }, down: new Set(['http://n1.d1.example']) })
    const list = await buildKnownList({ entry, ...noShuffle })
    expect(list.map((w) => w.witnessKeyId)).toEqual([hexKey(10), hexKey(12)])
    expect(list[0]).toEqual({ witnessKeyId: hexKey(10), key: hexKey(10), baseUrl: 'http://n0.d0.example' })
  })

  it('probes at most 3 x capacity, 4 in flight, and stops once full', async () => {
    stub({ discover: { 'http://10.0.0.1:8080': { peers: peers(40) } } })
    const list = await buildKnownList({ entry, ...noShuffle })
    expect(list).toHaveLength(5)
    const probes = calls.filter((u) => u.includes('/ledger/sth/latest'))
    expect(probes.length).toBeLessThanOrEqual(8)
    expect(maxInFlight).toBeLessThanOrEqual(4)

    stub({ discover: { 'http://10.0.0.1:8080': { peers: peers(40) } }, down: new Set(peers(40).map((p) => new URL(p.base_url).origin)) })
    expect(await buildKnownList({ entry, capacity: 3, ...noShuffle })).toEqual([])
    expect(calls.filter((u) => u.includes('/ledger/sth/latest')).length).toBe(9)
  })

  it('shuffles non-anchors with the injected source and keeps anchors first', async () => {
    stub({
      discover: {
        'http://10.0.0.1:8080': { peers: [advert(2, 'http://10.0.1.1:8080'), advert(3, 'http://a.x1.example'), advert(4, 'http://b.x2.example')] },
      },
    })
    const list = await buildKnownList({ entry, randomInt: () => 0 })
    expect(list.map((w) => w.witnessKeyId)).toEqual([hexKey(2), hexKey(4), hexKey(3)])
  })
})

describe('verifyNetwork witness policy', () => {
  const author = hexKey(1)
  const anchorEntry = { label: 'x', network_id: NET, verify_key: author, signing_key_id: 'op', environment: 'dev', seed_nodes: ['http://10.0.0.1:8080'] }
  const sth = makeHead('aa'.repeat(32))
  const witnessPeers = [2, 3, 4].map((n) => advert(n, `http://w${n}.net${n}.example`))

  function world(cosigs: number[]) {
    stub({
      discover: { 'http://10.0.0.1:8080': { peers: witnessPeers } },
      head: () => ({ ...sth, cosignatures: cosigs.map((w) => cosignWire(w, sth)) }),
    })
    const original = globalThis.fetch
    vi.stubGlobal('fetch', async (input: string | URL) => {
      if (String(input).includes('trusted-networks')) return new Response(JSON.stringify({ version: 1, networks: [anchorEntry] }), { status: 200 })
      return original(input)
    })
  }
  const client = () => new AvalonClient({ serverUrl: 'http://server.example' })
  const discoverCalls = () => calls.filter((u) => u.includes('/nodes/discover')).length

  it('auto builds once, caches, and requires a majority', async () => {
    world([])
    const c = client()
    expect((await c.verifyNetwork()).kind).toBe('mismatch')
    expect((await c.verifyNetwork()).kind).toBe('mismatch')
    expect(discoverCalls()).toBe(1)
    world([2, 3])
    expect((await client().verifyNetwork()).kind).toBe('verified')
  })

  it('none is the plain check and an explicit list behaves as before', async () => {
    world([])
    const c = client()
    expect((await c.verifyNetwork({ witnessPolicy: 'none' })).kind).toBe('verified')
    expect(discoverCalls()).toBe(0)
    const explicit: KnownWitness[] = [2, 3, 4].map((n) => ({ witnessKeyId: hexKey(n), key: hexKey(n) }))
    expect((await c.verifyNetwork({ knownWitnesses: explicit })).kind).toBe('mismatch')
    expect((await c.verifyNetwork({ witnessPolicy: explicit.slice(0, 1) })).kind).toBe('verified')
    expect(discoverCalls()).toBe(0)
  })

  it('a built list of one or zero is the plain check', async () => {
    stub({ discover: { 'http://10.0.0.1:8080': { peers: [witnessPeers[0]] } }, head: () => ({ ...sth, cosignatures: [] }) })
    const original = globalThis.fetch
    vi.stubGlobal('fetch', async (input: string | URL) =>
      String(input).includes('trusted-networks')
        ? new Response(JSON.stringify({ version: 1, networks: [anchorEntry] }), { status: 200 })
        : original(input),
    )
    expect((await client().verifyNetwork()).kind).toBe('verified')
  })
})

describe('crossCheckHead', () => {
  const author = hexKey(1)
  const good = makeHead('aa'.repeat(32))
  const accepted: CosignedTreeHead = { sth: good, cosignatures: [] }
  const list: KnownWitness[] = [2, 3, 4].map((n) => ({ witnessKeyId: hexKey(n), key: hexKey(n), baseUrl: `http://w${n}.example` }))

  it('reports a conflicting author-signed head with shared witnesses', async () => {
    const forked = makeHead('bb'.repeat(32))
    const acceptedWithCosigs: CosignedTreeHead = {
      sth: good,
      cosignatures: [2, 3].map((w) => ({ ...cosignWire(w, good), tree_size: good.tree_size, root_hash: good.root_hash, network_id: NET, author_created_at: good.created_at })),
    }
    stub({
      discover: {},
      head: (origin, size) => {
        expect(size).toBe('7')
        return origin === 'http://w3.example'
          ? { ...forked, cosignatures: [3, 4].map((w) => cosignWire(w, forked)) }
          : { ...good, cosignatures: [] }
      },
    })
    const evidence = await crossCheckHead(author, list, acceptedWithCosigs)
    expect(evidence).toEqual([
      { treeSize: 7, rootA: good.root_hash, rootB: forked.root_hash, sources: ['http://w3.example'], witnesses: [hexKey(3)] },
    ])
  })

  it('is empty when nothing conflicts, is unsigned, or nothing is fetchable', async () => {
    stub({ discover: {}, head: () => ({ ...good, cosignatures: [] }) })
    expect(await crossCheckHead(author, list, accepted)).toEqual([])
    stub({ discover: {}, head: () => ({ ...makeHead('cc'.repeat(32)), signature: '00'.repeat(64), cosignatures: [] }) })
    expect(await crossCheckHead(author, list, accepted)).toEqual([])
    stub({ discover: {}, down: new Set(list.map((w) => w.baseUrl!)) })
    expect(await crossCheckHead(author, list, accepted)).toEqual([])
  })
})
