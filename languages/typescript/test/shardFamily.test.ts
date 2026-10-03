import { afterEach, describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { getShardFamily } from '../src/ledger.js'
import { familyProofVerifies, familyRootMatches, type ShardFamilyResponse } from '../src/shardFamily.js'

const VECTORS = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../conformance/vectors/shard-family-head.json')
const doc = JSON.parse(readFileSync(VECTORS, 'utf-8'))

// The server's JSON for the "two members" vector, with the proof for `member` when given.
function body(member?: string): ShardFamilyResponse {
  const fam = doc.familyVectors.find((v: { name: string }) => v.name === 'two members')
  const members = fam.expected.memberShardIds.map((id: string) => {
    const h = fam.input.heads.find((x: { shardId: string }) => x.shardId === id)
    return {
      shard_id: h.shardId,
      tree_size: h.treeSize,
      root_hash: h.rootHashHex,
      signing_key_id: h.signingKeyId,
      signature: h.signatureHex,
      created_at: '2023-11-14T22:13:20Z',
    }
  })
  const out: ShardFamilyResponse = {
    owner: fam.input.owner,
    root_hash: fam.expected.rootHashHex,
    shard_count: members.length,
    partial: false,
    missing_shard_ids: [],
    members,
  }
  if (member) {
    const p = doc.proofVectors.find(
      (v: { input: { owner: string; shardId: string; rootHashHex: string }; expected: { verified: boolean } }) =>
        v.input.owner === out.owner &&
        v.input.shardId === member &&
        v.input.rootHashHex === out.root_hash &&
        v.expected.verified,
    )
    out.proof = { shard_id: member, leaf_index: p.input.proof.leafIndex, tree_size: p.input.proof.treeSize, path: p.input.proof.pathHex }
  }
  return out
}

describe('getShardFamily', () => {
  const originalFetch = globalThis.fetch
  afterEach(() => {
    globalThis.fetch = originalFetch
  })

  it('requests the owner and member and the response verifies', async () => {
    const seen: string[] = []
    globalThis.fetch = (async (url: string) => {
      seen.push(String(url))
      return new Response(JSON.stringify(body('game:x/2')), { status: 200 })
    }) as typeof fetch
    const family = await getShardFamily('http://node.test:8080', 'game:x', { member: 'game:x/2' })
    await getShardFamily('http://node.test:8080', 'game:x')
    expect(seen[0]).toBe('http://node.test:8080/ledger/shard-family?owner=game%3Ax&member=game%3Ax%2F2')
    expect(seen[1]).toBe('http://node.test:8080/ledger/shard-family?owner=game%3Ax')
    expect(familyRootMatches(family)).toBe(true)
    expect(familyProofVerifies(family)).toBe(true)
  })

  it('detects a tampered member and reports no proof when none was requested', async () => {
    const tampered = body()
    tampered.members[0].signature = '00'
    globalThis.fetch = (async () => new Response(JSON.stringify(tampered), { status: 200 })) as typeof fetch
    const family = await getShardFamily('http://node.test:8080', 'game:x')
    expect(family.proof).toBeUndefined()
    expect(familyProofVerifies(family)).toBe(false)
    expect(familyRootMatches(family)).toBe(false)
  })
})
