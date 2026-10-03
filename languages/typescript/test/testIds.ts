import { deriveIdentityId, type IdentityId } from '../src/identityId.js'

/** A fresh, valid identity id for fixtures that never verify a signature against it. */
export function randomIdentityId(): IdentityId {
  return deriveIdentityId(crypto.getRandomValues(new Uint8Array(32)))
}

/** A fresh random inception key and the id derived from it, for seeding `identities` rows. */
export function randomIdentityWithKey(): { identityId: IdentityId; inceptionKey: Uint8Array } {
  const inceptionKey = crypto.getRandomValues(new Uint8Array(32))
  return { identityId: deriveIdentityId(inceptionKey), inceptionKey }
}
