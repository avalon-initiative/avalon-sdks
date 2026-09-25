import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToHex } from '@noble/hashes/utils.js'
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

  it('reports no-candidates for a target with no matching entry', async () => {
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

  describe('latency ranking', () => {
    const keys = ed25519.keygen()
    const impostor = ed25519.keygen()
    const target = { kind: 'network-id', networkId: 'avalon-test' } as const
    const good = signSth(keys.secretKey, 'avalon-test')
    const forged = signSth(impostor.secretKey, 'avalon-test')
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

    // host -> { sth kind, status delay ms | 'fail' , sth delay }
    type Spec = { sth: 'good' | 'forged'; status: number | 'fail'; sthDelay?: number }
    function mock(specs: Record<string, Spec>) {
      const calls: string[] = []
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input))
        const spec = specs[url.origin]!
        calls.push(url.origin + url.pathname)
        if (url.pathname === '/ledger/sth/latest') {
          if (spec.sthDelay) await sleep(spec.sthDelay)
          return new Response(JSON.stringify(spec.sth === 'good' ? good : forged), { status: 200 })
        }
        if (spec.status === 'fail') throw new Error('refused')
        await new Promise<void>((resolve, reject) => {
          const t = setTimeout(resolve, spec.status as number)
          init?.signal?.addEventListener('abort', () => {
            clearTimeout(t)
            reject(new Error('aborted'))
          })
        })
        return new Response('{}', { status: 200 })
      }) as typeof fetch
      return calls
    }
    const hosts = ['http://a.invalid', 'http://b.invalid', 'http://c.invalid']
    const entry = (n: string[]) => anchor('avalon-test', keys.publicKey, n)

    it('chooses the fastest verified candidate', async () => {
      mock({ [hosts[0]!]: { sth: 'good', status: 60 }, [hosts[1]!]: { sth: 'good', status: 5 }, [hosts[2]!]: { sth: 'good', status: 30 } })
      const r = await discoverAmong([entry(hosts)], target)
      expect(r.serverUrl).toBe(hosts[1])
      expect(r.verified.map((v) => v.serverUrl)).toEqual([hosts[1], hosts[2], hosts[0]])
      expect(r.verified[0]!.latencyMs).not.toBeNull()
    })

    it('never chooses an unverified fast candidate', async () => {
      mock({ [hosts[0]!]: { sth: 'forged', status: 1 }, [hosts[1]!]: { sth: 'good', status: 40 }, [hosts[2]!]: { sth: 'good', status: 20 } })
      const r = await discoverAmong([entry(hosts)], target)
      expect(r.serverUrl).toBe(hosts[2])
      expect(r.verified.map((v) => v.serverUrl)).not.toContain(hosts[0])
    })

    it('makes no extra request for a single verified candidate', async () => {
      const calls = mock({ [hosts[0]!]: { sth: 'forged', status: 1 }, [hosts[1]!]: { sth: 'good', status: 1 } })
      const r = await discoverAmong([entry(hosts.slice(0, 2))], target)
      expect(r.serverUrl).toBe(hosts[1])
      expect(calls.some((c) => c.endsWith('/nodes/status'))).toBe(false)
    })

    it('falls back to candidate order when probes fail', async () => {
      mock({ [hosts[0]!]: { sth: 'good', status: 'fail' }, [hosts[1]!]: { sth: 'good', status: 'fail' } })
      const r = await discoverAmong([entry(hosts.slice(0, 2))], target)
      expect(r.serverUrl).toBe(hosts[0])
      expect(r.verified.every((v) => v.latencyMs === null)).toBe(true)
    })

    it('ranks a failed probe after a measured one but keeps it eligible', async () => {
      mock({ [hosts[0]!]: { sth: 'good', status: 'fail' }, [hosts[1]!]: { sth: 'good', status: 10 } })
      const r = await discoverAmong([entry(hosts.slice(0, 2))], target, { probeTimeoutMs: 50 })
      expect(r.serverUrl).toBe(hosts[1])
      expect(r.verified.map((v) => v.serverUrl)).toEqual([hosts[1], hosts[0]])
    })

    it('bounds probe time and the number of timed candidates', async () => {
      const calls = mock({ [hosts[0]!]: { sth: 'good', status: 5000 }, [hosts[1]!]: { sth: 'good', status: 5000 }, [hosts[2]!]: { sth: 'good', status: 5000 } })
      const t0 = performance.now()
      const r = await discoverAmong([entry(hosts)], target, { probeTimeoutMs: 40, maxTimed: 2 })
      expect(performance.now() - t0).toBeLessThan(1000)
      expect(r.serverUrl).toBe(hosts[0])
      expect(calls.filter((c) => c.endsWith('/nodes/status')).length).toBe(2)
    })

    it('stops collecting once the window after the first verification has passed', async () => {
      mock({ [hosts[0]!]: { sth: 'good', status: 10 }, [hosts[1]!]: { sth: 'good', status: 1, sthDelay: 500 }, [hosts[2]!]: { sth: 'good', status: 1 } })
      const t0 = performance.now()
      const r = await discoverAmong([entry(hosts)], target, { collectWindowMs: 40 })
      expect(performance.now() - t0).toBeLessThan(400)
      expect(r.serverUrl).toBe(hosts[0])
      expect(r.verified).toHaveLength(1)
    })
  })
})
