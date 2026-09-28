import { afterEach, describe, expect, it } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { getShardTreeHead } from '../../src/ledger.js'
import { signingMessage } from '../../src/network/sthMessage.js'
import { selfCertifyingId, shardCheck, verifySelfCertifyingTreeHead } from '../../src/network/selfCertifying.js'
import type { SignedTreeHeadResponse } from '../../src/types.js'

function keypair(seed: number) {
  const secret = new Uint8Array(32).fill(seed)
  return { secret, publicKey: ed25519.getPublicKey(secret) }
}

function signedHead(secret: Uint8Array): SignedTreeHeadResponse {
  const unsigned: SignedTreeHeadResponse = {
    tree_size: 9,
    root_hash: 'ab'.repeat(32),
    network_id: 'avalon-test',
    signing_key_id: 'node-key-1',
    signature: '',
    created_at: '2026-05-28T20:26:40Z',
    protocol_version: '0.1',
  }
  return { ...unsigned, signature: bytesToHex(ed25519.sign(signingMessage(unsigned), secret)) }
}

const a = keypair(1)
const b = keypair(2)
const idA = selfCertifyingId(a.publicKey)
const keyA = bytesToHex(a.publicKey)

describe('verifySelfCertifyingTreeHead', () => {
  it('accepts a matching key and head, with the key given or carried on the head', () => {
    const sth = signedHead(a.secret)
    expect(verifySelfCertifyingTreeHead(idA, sth, keyA)).toEqual({ verified: true })
    expect(verifySelfCertifyingTreeHead(idA, { ...sth, signing_public_key: keyA })).toEqual({ verified: true })
  })

  it('rejects a key that does not hash to the id', () => {
    expect(verifySelfCertifyingTreeHead(idA, signedHead(b.secret), bytesToHex(b.publicKey))).toEqual({
      verified: false,
      failure: 'key_id_mismatch',
    })
  })

  it('rejects a head signed by a different key', () => {
    expect(verifySelfCertifyingTreeHead(idA, signedHead(b.secret), keyA)).toEqual({
      verified: false,
      failure: 'bad_signature',
    })
  })

  it('rejects a tampered head', () => {
    const sth = { ...signedHead(a.secret), tree_size: 10 }
    expect(verifySelfCertifyingTreeHead(idA, sth, keyA)).toEqual({ verified: false, failure: 'bad_signature' })
  })

  it('reports a missing or malformed key', () => {
    const sth = signedHead(a.secret)
    expect(verifySelfCertifyingTreeHead(idA, sth)).toEqual({ verified: false, failure: 'missing_key' })
    expect(verifySelfCertifyingTreeHead(idA, sth, null)).toEqual({ verified: false, failure: 'missing_key' })
    for (const bad of [keyA.toUpperCase(), keyA.slice(2), `${keyA}00`, '', 'zz'.repeat(32)]) {
      expect(verifySelfCertifyingTreeHead(idA, sth, bad)).toEqual({ verified: false, failure: 'malformed_key' })
    }
  })

  it('rejects ids that are not self-certifying', () => {
    const sth = signedHead(a.secret)
    for (const id of ['core', 'game:wow-demo/1', 'node:', 'node:ab', idA.toUpperCase(), '']) {
      expect(verifySelfCertifyingTreeHead(id, sth, keyA)).toEqual({ verified: false, failure: 'not_self_certifying' })
    }
  })
})

describe('shardCheck', () => {
  it('names the verification that applies', () => {
    expect(shardCheck(idA)).toBe('self_certifying')
    expect(shardCheck('core')).toBe('core_network')
    for (const other of ['game:wow-demo/1', 'app:notes', 'service:x', 'node:ab', '']) {
      expect(shardCheck(other)).toBe('unsupported')
    }
  })
})

describe('getShardTreeHead', () => {
  const originalFetch = globalThis.fetch
  afterEach(() => {
    globalThis.fetch = originalFetch
  })

  it('requests the shard and returns the served key', async () => {
    const seen: string[] = []
    const body = { ...signedHead(a.secret), signing_public_key: keyA }
    globalThis.fetch = (async (url: string) => {
      seen.push(String(url))
      return new Response(JSON.stringify(body), { status: 200 })
    }) as typeof fetch
    const latest = await getShardTreeHead('http://node.test:8080', idA)
    await getShardTreeHead('http://node.test:8080', idA, { treeSize: 9 })
    expect(seen[0]).toBe(`http://node.test:8080/ledger/sth/latest?shard_id=${encodeURIComponent(idA)}`)
    expect(seen[1]).toBe(`http://node.test:8080/ledger/sth/9?shard_id=${encodeURIComponent(idA)}`)
    expect(verifySelfCertifyingTreeHead(idA, latest)).toEqual({ verified: true })
  })

  it('tolerates a node that serves no key', async () => {
    globalThis.fetch = (async () => new Response(JSON.stringify(signedHead(a.secret)), { status: 200 })) as typeof fetch
    const head = await getShardTreeHead('http://node.test:8080', idA)
    expect(head.signing_public_key).toBeUndefined()
    expect(verifySelfCertifyingTreeHead(idA, head)).toEqual({ verified: false, failure: 'missing_key' })
  })
})
