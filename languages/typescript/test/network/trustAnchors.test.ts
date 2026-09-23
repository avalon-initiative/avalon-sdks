import { describe, expect, it } from 'vitest'
import { fetchTrustAnchors } from '../../src/network/trustAnchors.js'

describe('fetchTrustAnchors', () => {
  const body = { networks: [{ network_id: 'n', label: 'n', verify_key: 'ab', signing_key_id: 'k', environment: 'dev' }] }

  it('parses the published file', async () => {
    const ok = (async () => new Response(JSON.stringify(body))) as unknown as typeof fetch
    expect((await fetchTrustAnchors('http://x', ok))[0]?.network_id).toBe('n')
  })

  it('rejects on a failing response', async () => {
    const fail = (async () => new Response('', { status: 500 })) as unknown as typeof fetch
    await expect(fetchTrustAnchors('http://x', fail)).rejects.toThrow()
  })
})
