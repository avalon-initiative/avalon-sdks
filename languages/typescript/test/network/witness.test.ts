import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { CosignedTreeHead, KnownWitness, SignedTreeHeadResponse, WitnessCosignature } from '../../src/types.js'
import { signingMessage } from '../../src/network/sthMessage.js'
import {
  findEquivocatingWitnesses,
  isCosignedByMajority,
  majorityThreshold,
  verifyCosignedTreeHead,
  verifyWitnessCosignature,
  witnessSigningMessage,
} from '../../src/network/witness.js'
import { fetchCosignedNetworkTrustStatus } from '../../src/network/cosignedTrust.js'
import { getCosignedTreeHead } from '../../src/ledger.js'

const seed = (n: number) => new Uint8Array(32).fill(n)
const hexKey = (n: number) => bytesToHex(ed25519.getPublicKey(seed(n)))
const NOW = new Date('2026-09-27T12:00:00Z')
const CUTOFF = new Date(NOW.getTime() - 600_000)

function head(root = 'ab'.repeat(32)): SignedTreeHeadResponse {
  const unsigned = {
    tree_size: 7,
    root_hash: root,
    network_id: 'net',
    signing_key_id: 'op',
    created_at: '2026-09-27T11:59:00Z',
    protocol_version: 'v1',
  }
  const signature = bytesToHex(ed25519.sign(signingMessage({ ...unsigned, signature: '' }), seed(1)))
  return { ...unsigned, signature }
}

function cosign(w: number, sth: SignedTreeHeadResponse, observed = '2026-09-27T11:59:30Z'): WitnessCosignature {
  const base = {
    tree_size: sth.tree_size,
    root_hash: sth.root_hash,
    network_id: sth.network_id,
    author_created_at: sth.created_at,
    witness_key_id: hexKey(w),
    observed_at: observed,
  }
  return { ...base, signature: bytesToHex(ed25519.sign(witnessSigningMessage(base), seed(w))) }
}

const list = (...ws: number[]): KnownWitness[] => ws.map((w) => ({ witnessKeyId: hexKey(w), key: hexKey(w) }))
const author = hexKey(1)

describe('witness primitives', () => {
  it('thresholds', () => {
    expect([0, 1, 2, 3, 10].map(majorityThreshold)).toEqual([0, 1, 2, 2, 6])
    expect(isCosignedByMajority(3, 2)).toBe(true)
    expect(isCosignedByMajority(3, 1)).toBe(false)
  })

  it('verifies and rejects malformed input without throwing', () => {
    const c = cosign(2, head())
    expect(verifyWitnessCosignature(hexKey(2), c)).toBe(true)
    expect(verifyWitnessCosignature(hexKey(3), c)).toBe(false)
    expect(verifyWitnessCosignature('zz', c)).toBe(false)
    expect(verifyWitnessCosignature('', c)).toBe(false)
    expect(verifyWitnessCosignature(hexKey(2).slice(2), c)).toBe(false)
    expect(verifyWitnessCosignature(hexKey(2), { ...c, signature: c.signature.slice(2) })).toBe(false)
    expect(verifyWitnessCosignature(hexKey(2), { ...c, signature: 'nothex' })).toBe(false)
    expect(verifyWitnessCosignature(hexKey(2), { ...c, observed_at: 'garbage' })).toBe(false)
    expect(verifyWitnessCosignature(hexKey(2), { ...c, tree_size: 8 })).toBe(false)
  })
})

describe('verifyCosignedTreeHead', () => {
  const sth = head()
  const accept = (cosigs: WitnessCosignature[], known: KnownWitness[]) =>
    verifyCosignedTreeHead(author, { sth, cosignatures: cosigs }, known, CUTOFF, NOW)

  it('empty and single lists are the author check only', () => {
    expect(accept([], [])).toBe(true)
    expect(accept([], list(2))).toBe(true)
    expect(verifyCosignedTreeHead(hexKey(9), { sth, cosignatures: [] }, [], CUTOFF, NOW)).toBe(false)
  })

  it('requires a majority of distinct valid fresh known witnesses', () => {
    const known = list(2, 3, 4)
    expect(accept([cosign(2, sth)], known)).toBe(false)
    expect(accept([cosign(2, sth), cosign(2, sth)], known)).toBe(false)
    expect(accept([cosign(2, sth), cosign(3, sth)], known)).toBe(true)
    expect(accept([cosign(2, sth), cosign(5, sth)], known)).toBe(false)
  })

  it('bounds freshness inclusively and rejects future-dated', () => {
    const known = list(2, 3)
    expect(accept([cosign(2, sth, CUTOFF.toISOString()), cosign(3, sth, NOW.toISOString())], known)).toBe(true)
    expect(accept([cosign(2, sth, '2026-09-27T11:49:59Z'), cosign(3, sth)], known)).toBe(false)
    expect(accept([cosign(2, sth, '2026-09-27T12:00:01Z'), cosign(3, sth)], known)).toBe(false)
  })

  it('rejects cosignatures for a different head and bad signatures', () => {
    const known = list(2, 3)
    const other = cosign(3, head('cd'.repeat(32)))
    expect(accept([cosign(2, sth), { ...other, signature: cosign(3, sth).signature }], known)).toBe(false)
    expect(accept([cosign(2, sth), { ...cosign(3, sth), signature: 'ff' }], known)).toBe(false)
  })

  it('binds a cosignature to the head by whole seconds and rejects an unparseable time', () => {
    const known = list(2, 3)
    const sameSecond = { ...cosign(3, sth), author_created_at: sth.created_at.replace(/(\.\d+)?Z$/, '.500Z') }
    expect(accept([cosign(2, sth), sameSecond], known)).toBe(true)
    const garbage = { ...cosign(3, sth), author_created_at: 'not-a-time' }
    expect(accept([cosign(2, sth), garbage], known)).toBe(false)
  })

  it('counts the author key as a known witness', () => {
    const known: KnownWitness[] = [{ witnessKeyId: 'author', key: author }, ...list(2)]
    expect(accept([], known)).toBe(false)
    expect(accept([cosign(2, sth)], known)).toBe(true)
  })

  it('finds equivocating witnesses', () => {
    const a = head('ab'.repeat(32))
    const b = head('cd'.repeat(32))
    const known = list(2, 3, 4)
    const ha: CosignedTreeHead = { sth: a, cosignatures: [cosign(2, a), cosign(3, a)] }
    const hb: CosignedTreeHead = { sth: b, cosignatures: [cosign(3, b), cosign(4, b)] }
    expect(findEquivocatingWitnesses(author, known, CUTOFF, NOW, ha, hb)).toEqual([hexKey(3)])
    expect(findEquivocatingWitnesses(author, known, CUTOFF, NOW, ha, ha)).toEqual([])
    expect(findEquivocatingWitnesses(author, known, CUTOFF, NOW, ha, { sth: b, cosignatures: [] })).toEqual([])
  })
})

describe('cosigned network verification', () => {
  afterEach(() => vi.unstubAllGlobals())
  const anchors = [{ network_id: 'net', verify_key: author }] as never
  const sth = head()
  const serve = (cosigs: WitnessCosignature[]) => {
    const calls: string[] = []
    vi.stubGlobal('fetch', async (url: string) => {
      calls.push(url)
      return new Response(
        JSON.stringify({
          ...sth,
          cosignatures: cosigs.map(({ witness_key_id, observed_at, signature }) => ({ witness_key_id, observed_at, signature })),
        }),
        { status: 200 },
      )
    })
    return calls
  }

  it('fetches with witnesses=1 and rebinds cosignatures to the head', async () => {
    const calls = serve([cosign(2, sth)])
    const got = await getCosignedTreeHead('http://n', { shardId: 'core', treeSize: 7 })
    expect(calls[0]).toBe('http://n/ledger/sth/7?witnesses=1&shard_id=core')
    expect(got.cosignatures[0].root_hash).toBe(sth.root_hash)
    expect(verifyWitnessCosignature(hexKey(2), got.cosignatures[0])).toBe(true)
  })

  it('fails closed without a majority, passes with one, and ignores lists under two', async () => {
    const opts = { knownWitnesses: list(2, 3, 4), now: NOW, freshnessSeconds: 600 }
    serve([cosign(2, sth)])
    expect((await fetchCosignedNetworkTrustStatus(anchors, 'http://n', opts)).kind).toBe('mismatch')
    serve([cosign(2, sth), cosign(3, sth)])
    expect((await fetchCosignedNetworkTrustStatus(anchors, 'http://n', opts)).kind).toBe('verified')
    const calls = serve([])
    const plain = await fetchCosignedNetworkTrustStatus(anchors, 'http://n', { knownWitnesses: list(2) })
    expect(plain.kind).toBe('verified')
    expect(calls[0]).toBe('http://n/ledger/sth/latest')
  })
})
