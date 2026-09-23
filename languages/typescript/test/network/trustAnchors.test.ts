import { describe, expect, it } from 'vitest'
import { fetchTrustAnchors, findTrustAnchor, getBundledTrustAnchors, resolveTrustAnchors } from '../../src/network/trustAnchors.js'

describe('getBundledTrustAnchors', () => {
  it('parses the real checked-in docs/trusted-networks.json', () => {
    // The mirrored src/generated/trustedNetworks.json must always at least
    // parse — a broken generate step would otherwise only surface at
    // verifyNetwork call time in production.
    const anchors = getBundledTrustAnchors()
    expect(anchors.some((entry) => entry.network_id === 'avalon-dev-local')).toBe(true)
  })
})

describe('findTrustAnchor', () => {
  it('finds a pinned entry by network_id', () => {
    expect(findTrustAnchor('avalon-dev-local')?.network_id).toBe('avalon-dev-local')
  })

  it('returns undefined for an unpinned network_id', () => {
    expect(findTrustAnchor('avalon-nowhere')).toBeUndefined()
  })
})

describe('published trust anchors', () => {
  const body = { networks: [{ network_id: 'n', label: 'n', verify_key: 'ab', signing_key_id: 'k', environment: 'dev' }] }
  const ok = (async () => new Response(JSON.stringify(body))) as unknown as typeof fetch
  const fail = (async () => new Response('', { status: 500 })) as unknown as typeof fetch

  it('fetchTrustAnchors parses the published file', async () => {
    expect((await fetchTrustAnchors('http://x', ok))[0]?.network_id).toBe('n')
  })

  it('resolveTrustAnchors falls back to the bundled copy on failure', async () => {
    expect(await resolveTrustAnchors('http://x', fail)).toEqual(getBundledTrustAnchors())
  })
})
