import { ed25519 } from '@noble/curves/ed25519'
import { bytesToHex } from '@noble/hashes/utils'
import { afterEach, describe, expect, it } from 'vitest'
import type { SignedTreeHeadResponse } from '../../src/types.js'
import { signingMessage } from '../../src/network/sthMessage.js'
import { discoverAmong, DiscoveryFailedError } from '../../src/network/discover.js'
import type { TrustAnchorEntry } from '../../src/network/trustAnchors.js'

function sthFixture(networkId: string): Omit<SignedTreeHeadResponse, 'signature'> {
  return {
    tree_size: 42,
    root_hash: 'ab'.repeat(32),
    network_id: networkId,
    signing_key_id: 'test-key',
    created_at: '2026-09-09T12:00:00Z',
    protocol_version: 'v1',
  }
}

function signSth(secretKey: Uint8Array, networkId: string): SignedTreeHeadResponse {
  const unsigned = { ...sthFixture(networkId), signature: '' }
  const signature = ed25519.sign(signingMessage(unsigned), secretKey)
  return { ...unsigned, signature: bytesToHex(signature) }
}

function anchor(networkId: string, verifyKey: Uint8Array, seedNodes: string[]): TrustAnchorEntry {
  return {
    label: networkId,
    network_id: networkId,
    verify_key: bytesToHex(verifyKey),
    signing_key_id: 'test-key',
    environment: 'dev',
    seed_nodes: seedNodes,
  }
}

const originalFetch = globalThis.fetch

afterEach(() => {
  globalThis.fetch = originalFetch
})

describe('discoverAmong', () => {
  it('finds the first verified candidate, skipping a dead one', async () => {
    const { secretKey, publicKey } = ed25519.keygen()
    const dead = 'http://dead.invalid'
    const live = 'http://live.invalid'
    const sth = signSth(secretKey, 'avalon-test')

    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.startsWith(dead)) {
        throw new Error('connection refused')
      }
      return new Response(JSON.stringify(sth), { status: 200 })
    }) as typeof fetch

    const entry = anchor('avalon-test', publicKey, [dead, live])
    const result = await discoverAmong([entry], { kind: 'network-id', networkId: 'avalon-test' })

    expect(result.serverUrl).toBe(live)
    expect(result.entry).toEqual(entry)
  })

  it('reports no-candidates for a target with no matching bundled entry', async () => {
    await expect(discoverAmong([], { kind: 'network-id', networkId: 'avalon-nowhere' })).rejects.toThrow(
      DiscoveryFailedError,
    )
    try {
      await discoverAmong([], { kind: 'network-id', networkId: 'avalon-nowhere' })
      expect.unreachable()
    } catch (err) {
      expect((err as DiscoveryFailedError).detail.kind).toBe('no-candidates')
    }
  })

  it('reports none-verified when every candidate fails verification', async () => {
    const real = ed25519.keygen()
    const impostor = ed25519.keygen()
    const live = 'http://live.invalid'
    // Server actually signs with a different key than the one pinned.
    const forgedSth = signSth(impostor.secretKey, 'avalon-test')

    globalThis.fetch = (async () => new Response(JSON.stringify(forgedSth), { status: 200 })) as typeof fetch

    const entry = anchor('avalon-test', real.publicKey, [live])
    try {
      await discoverAmong([entry], { kind: 'network-id', networkId: 'avalon-test' })
      expect.unreachable()
    } catch (err) {
      expect(err).toBeInstanceOf(DiscoveryFailedError)
      expect((err as DiscoveryFailedError).detail.kind).toBe('none-verified')
    }
  })
})
