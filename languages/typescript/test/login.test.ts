import { describe, expect, it } from 'vitest'
import { AvalonClient } from '../src/client.js'
import { bytesToBase64, generateSigningKey } from '../src/crypto/signing.js'
import { randomIdentityId } from './testIds.js'

describe('AvalonClient.login', () => {
  it('fails before any request when the stored key does not derive to the identity id', async () => {
    const client = new AvalonClient({ serverUrl: 'http://127.0.0.1:1' })
    await expect(
      client.login({
        identityId: randomIdentityId(),
        signingKeySecretBase64: bytesToBase64(generateSigningKey().secretKey),
      }),
    ).rejects.toThrow(/does not derive/)
  })

  it('rejects a malformed identity id', async () => {
    const client = new AvalonClient({ serverUrl: 'http://127.0.0.1:1' })
    await expect(
      client.login({
        identityId: 'not-an-id' as never,
        signingKeySecretBase64: bytesToBase64(generateSigningKey().secretKey),
      }),
    ).rejects.toBeInstanceOf(TypeError)
  })
})
