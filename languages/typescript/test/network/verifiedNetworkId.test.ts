import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { randomIdentityId } from '../testIds.js'
import { IntegratorSession } from '../../src/integratorSession.js'
import { AvalonClient } from '../../src/client.js'
import { NetworkNotVerifiedError } from '../../src/network/verifiedNetworkId.js'
import { signingMessage } from '../../src/network/sthMessage.js'
import { TRUST_ANCHORS_URL } from '../../src/network/trustAnchors.js'
import type { SignedTreeHeadResponse } from '../../src/types.js'

const SERVER = 'http://node.invalid'
const NETWORK = 'avalon-verified-net'
const KEY = ed25519.keygen()

function signedHead(networkId: string, secretKey: Uint8Array): SignedTreeHeadResponse {
  const unsigned = {
    tree_size: 7,
    root_hash: 'ab'.repeat(32),
    network_id: networkId,
    signing_key_id: 'test-key',
    created_at: '2026-09-09T12:00:00Z',
    protocol_version: 'v1',
    signature: '',
  }
  return { ...unsigned, signature: bytesToHex(ed25519.sign(signingMessage(unsigned), secretKey)) }
}

function anchors(networkId = NETWORK) {
  return {
    networks: [
      { label: 'x', network_id: networkId, verify_key: bytesToHex(KEY.publicKey), signing_key_id: 'test-key', environment: 'dev' },
    ],
  }
}

// `head` is what the node serves; `trust` is the anchors file (or null for an unreachable list).
function stubNode(head: SignedTreeHeadResponse | 'down', trust: unknown = anchors()) {
  const calls: string[] = []
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    calls.push(url)
    if (url === TRUST_ANCHORS_URL) {
      return trust === null ? new Response('no', { status: 500 }) : new Response(JSON.stringify(trust))
    }
    if (url.includes('/ledger/sth/latest')) {
      return head === 'down' ? new Response('no', { status: 503 }) : new Response(JSON.stringify(head))
    }
    if (url.includes('/challenge')) return new Response(JSON.stringify({ challenge_id: 'c', nonce: 'AAAA' }))
    return new Response(JSON.stringify({ id: 'att-1' }))
  })
  vi.stubGlobal('fetch', fetchMock)
  return calls
}

function session(networkId?: string): IntegratorSession {
  const id = randomIdentityId()
  return new IntegratorSession({
    identity: { id, createdAt: new Date().toISOString() },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    profile: { identityId: id, displayName: 't', links: [], favoriteGenres: [] } as any,
    granted: ['achievements.issue'],
    serverUrl: SERVER,
    token: 't',
    integratorKeyId: '3f2b8c1a-9d4e-4f6a-8b7c-0a1b2c3d4e5f',
    integratorSlug: 'game-x',
    signingKey: new Uint8Array(32).fill(5),
    networkId,
  })
}

const signedCalls = (calls: string[]) => calls.filter((u) => u.includes('/integrations/'))
const verifyCalls = (calls: string[]) => calls.filter((u) => u === TRUST_ANCHORS_URL)

afterEach(() => vi.unstubAllGlobals())

describe('session network id', () => {
  it('uses a declared id with no verification call', async () => {
    const calls = stubNode(signedHead(NETWORK, KEY.secretKey))
    await session('declared-net').issueAchievement('first')
    expect(verifyCalls(calls)).toHaveLength(0)
    expect(calls.some((u) => u.includes('/ledger/sth'))).toBe(false)
    expect(signedCalls(calls).length).toBeGreaterThan(0)
  })

  it('verifies once and caches it across signed calls', async () => {
    const calls = stubNode(signedHead(NETWORK, KEY.secretKey))
    const s = session()
    await s.issueAchievement('a')
    await s.issueAchievement('b')
    await s.issueAchievement('c')
    expect(verifyCalls(calls)).toHaveLength(1)
    expect(signedCalls(calls).length).toBeGreaterThan(2)
  })

  const failures: [string, SignedTreeHeadResponse | 'down', unknown, string][] = [
    ['mismatch', signedHead(NETWORK, ed25519.keygen().secretKey), anchors(), 'mismatch'],
    ['unknown-network', signedHead('other-net', KEY.secretKey), anchors(), 'unknown-network'],
    ['unreachable node', 'down', anchors(), 'unreachable'],
    ['unreachable trust anchors', signedHead(NETWORK, KEY.secretKey), null, 'unreachable'],
  ]
  for (const [name, head, trust, kind] of failures) {
    it(`throws NetworkNotVerifiedError on ${name} and sends no signed request`, async () => {
      const calls = stubNode(head, trust)
      const error = await session().issueAchievement('a').catch((e: unknown) => e)
      expect(error).toBeInstanceOf(NetworkNotVerifiedError)
      expect((error as NetworkNotVerifiedError).status.kind).toBe(kind)
      expect(signedCalls(calls)).toHaveLength(0)
    })
  }

  it('AvalonClient passes its declared network id to the sessions it builds', async () => {
    const calls = stubNode(signedHead(NETWORK, KEY.secretKey))
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        calls.push(url)
        if (url.endsWith('/me')) return new Response(JSON.stringify({ identity_id: randomIdentityId(), created_at: '2026-01-01T00:00:00Z', display_name: 't' }))
        if (url.endsWith('/me/grants')) return new Response(JSON.stringify({ capabilities: ['achievements.issue'] }))
        if (url.includes('/challenge')) return new Response(JSON.stringify({ challenge_id: 'c', nonce: 'AAAA' }))
        return new Response(JSON.stringify({ id: 'att-1' }))
      }),
    )
    const client = new AvalonClient({ serverUrl: SERVER, networkId: 'declared-net' })
    const s = await client.authenticate({
      identityToken: 't',
      integratorCredentialKeyId: '3f2b8c1a-9d4e-4f6a-8b7c-0a1b2c3d4e5f',
      integratorSlug: 'game-x',
      signingKey: new Uint8Array(32).fill(5),
    })
    await s.issueAchievement('first')
    expect(verifyCalls(calls)).toHaveLength(0)
  })
})
