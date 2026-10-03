import { deriveIdentityId, type IdentityId } from '../src/identityId.js'

/** A fresh, valid identity id for fixtures that never verify a signature against it. */
export function randomIdentityId(): IdentityId {
  return deriveIdentityId(crypto.getRandomValues(new Uint8Array(32)))
}
