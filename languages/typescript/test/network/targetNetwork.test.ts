import { describe, expect, it } from 'vitest'
import { checkTargetNetwork, NetworkTargetMismatchError } from '../../src/network/targetNetwork.js'
import type { NetworkTrustStatus } from '../../src/network/verifyNetwork.js'
import type { TrustAnchorEntry } from '../../src/network/trustAnchors.js'

function verifiedDev(networkId: string): NetworkTrustStatus {
  const entry: TrustAnchorEntry = {
    label: networkId,
    network_id: networkId,
    verify_key: 'ab'.repeat(32),
    signing_key_id: 'test-key',
    environment: 'dev',
  }
  return { kind: 'verified', entry }
}

describe('checkTargetNetwork', () => {
  it('proceeds when the declared network_id matches', () => {
    const status = verifiedDev('avalon-dev-1')
    expect(checkTargetNetwork(status, { kind: 'network-id', networkId: 'avalon-dev-1' }).network_id).toBe(
      'avalon-dev-1',
    )
  })

  it('proceeds when the declared tier matches', () => {
    const status = verifiedDev('avalon-dev-1')
    expect(() => checkTargetNetwork(status, { kind: 'tier', tier: 'dev' })).not.toThrow()
  })

  it('rejects a mismatched network_id', () => {
    const status = verifiedDev('avalon-dev-1')
    try {
      checkTargetNetwork(status, { kind: 'network-id', networkId: 'avalon-mainnet-1' })
      expect.unreachable()
    } catch (err) {
      expect(err).toBeInstanceOf(NetworkTargetMismatchError)
      expect((err as NetworkTargetMismatchError).detail).toEqual({
        kind: 'mismatch',
        declared: 'avalon-mainnet-1',
        actual: 'avalon-dev-1',
      })
    }
  })

  it('rejects a mismatched tier', () => {
    const status = verifiedDev('avalon-dev-1')
    expect(() => checkTargetNetwork(status, { kind: 'tier', tier: 'mainnet' })).toThrow(NetworkTargetMismatchError)
  })

  it('never proceeds against an unverified network', () => {
    const target = { kind: 'network-id' as const, networkId: 'avalon-dev-1' }

    expect(() =>
      checkTargetNetwork({ kind: 'unknown-network', claimedNetworkId: 'avalon-dev-1' }, target),
    ).toThrow(NetworkTargetMismatchError)

    expect(() => checkTargetNetwork({ kind: 'unreachable', detail: 'connection refused' }, target)).toThrow(
      NetworkTargetMismatchError,
    )

    const entry: TrustAnchorEntry = {
      label: 'avalon-dev-1',
      network_id: 'avalon-dev-1',
      verify_key: 'ab'.repeat(32),
      signing_key_id: 'test-key',
      environment: 'dev',
    }
    expect(() =>
      checkTargetNetwork({ kind: 'mismatch', entry, claimedNetworkId: 'avalon-dev-1' }, target),
    ).toThrow(NetworkTargetMismatchError)
  })
})
