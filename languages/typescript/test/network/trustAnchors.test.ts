import { describe, expect, it } from 'vitest'
import { findTrustAnchor, getBundledTrustAnchors } from '../../src/network/trustAnchors.js'

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
