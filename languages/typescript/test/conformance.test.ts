// Cross-SDK conformance suite — loads the shared
// test vectors under conformance/vectors/ (repo root) and asserts this
// SDK's real implementation produces byte-for-byte identical output.
// Offline, no server needed — runs in the default `npm test` (vitest) job
// alongside every other unit test here.
//
// See conformance/vectors/SCHEMA.md for the vector format and the
// standing "add a vector when you add smart-client behavior" requirement.
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

import { signingBytes as crossNodeLoginSigningBytes } from '../src/crypto/crossNodeLogin.js'
import { signingBytes as continuationSigningBytes } from '../src/crypto/continuation.js'
import { signingBytes as interestClaimSigningBytes, type ClaimedScope } from '../src/crypto/interestClaim.js'
import { deriveSigningKeyFromMnemonic, isValidMnemonic } from '../src/crypto/mnemonic.js'
import {
  attestationSigningBytes,
  bulkAttestationSigningBytes,
} from '../src/integratorSession.js'
import { revocationSigningBytes } from '../src/integratorAccount.js'
import { sign, verify } from '../src/crypto/signing.js'
import { signingMessage } from '../src/network/sthMessage.js'
import type { CosignedTreeHead, KnownWitness, SignedTreeHeadResponse } from '../src/types.js'
import {
  findEquivocatingWitnesses,
  verifyCosignedTreeHead,
  verifyWitnessAnnounce,
  witnessAnnounceMessage,
} from '../src/network/witness.js'
import { diversityPrefixForUrl, selectKnownList } from '../src/network/knownListRules.js'
import { selfCertifyingId, shardCheck, verifySelfCertifyingTreeHead } from '../src/network/selfCertifying.js'
import {
  familyRoot,
  isFamilyMember,
  isFamilyOwnerId,
  routeWeight,
  routeWrite,
  shardFamilyOwner,
  verifyFamilyInclusion,
  type FamilyHead,
} from '../src/shardFamily.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const VECTORS_DIR = path.resolve(__dirname, '../../../conformance/vectors')

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function loadVector(name: string): any {
  return JSON.parse(readFileSync(path.join(VECTORS_DIR, name), 'utf-8'))
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

function toUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes)
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function requireSupported(doc: any, lang: string): void {
  expect(doc.supportedIn, `${lang} must be listed in supportedIn for this vector file`).toContain(lang)
}

describe('conformance: cross-node-login grant signing (#623/#707)', () => {
  const doc = loadVector('cross-node-login.json')

  it('lists typescript as supported', () => {
    requireSupported(doc, 'typescript')
  })

  it('derives the shared test keypair public key correctly', () => {
    const secretKey = hexToBytes(doc.signingKeySeedHex)
    const publicKey = hexToBytes(doc.signingPublicKeyHex)
    // Round-trip: sign something with secretKey and verify with publicKey.
    const probe = new TextEncoder().encode('probe')
    expect(verify(publicKey, probe, sign(secretKey, probe))).toBe(true)
  })

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  for (const vector of doc.vectors as any[]) {
    it(`matches the shared vector: ${vector.name}`, () => {
      const secretKey = hexToBytes(doc.signingKeySeedHex)
      const { input, expected } = vector

      const bytes = crossNodeLoginSigningBytes(
        input.identityId,
        input.signingKeyId,
        input.destinationBaseUrl,
        input.requestingContext,
        input.nonce,
        new Date(input.issuedAtUnixSeconds * 1000),
        new Date(input.expiresAtUnixSeconds * 1000),
      )

      expect(toUtf8(bytes)).toBe(expected.signingBytesUtf8)

      const signature = sign(secretKey, bytes)
      expect(bytesToHex(signature)).toBe(expected.signatureHex)
    })
  }
})

describe('conformance: session-continuation token minting (#525)', () => {
  const doc = loadVector('session-continuation.json')

  it('lists typescript as supported', () => {
    requireSupported(doc, 'typescript')
  })

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  for (const vector of doc.vectors as any[]) {
    it(`matches the shared vector: ${vector.name}`, () => {
      const secretKey = hexToBytes(doc.signingKeySeedHex)
      const { input, expected } = vector

      const bytes = continuationSigningBytes(
        input.identityId,
        input.signingKeyId,
        input.nonce,
        new Date(input.issuedAtUnixSeconds * 1000),
        new Date(input.expiresAtUnixSeconds * 1000),
      )
      expect(toUtf8(bytes)).toBe(expected.signingBytesUtf8)

      const signature = sign(secretKey, bytes)
      expect(bytesToHex(signature)).toBe(expected.signatureHex)
      expect(expected.wireToken.startsWith(expected.wireTokenPrefix)).toBe(true)
    })
  }
})

describe('conformance: websocket interest-claim minting (#610/#712)', () => {
  const doc = loadVector('websocket-interest-claim.json')

  it('lists typescript as supported', () => {
    requireSupported(doc, 'typescript')
  })

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  for (const vector of doc.vectors as any[]) {
    it(`matches the shared vector: ${vector.name}`, () => {
      const secretKey = hexToBytes(doc.signingKeySeedHex)
      const { input, expected } = vector
      const scope: ClaimedScope = { kind: 'channel', channelId: input.scope.channelId }

      const bytes = interestClaimSigningBytes(
        input.identityId,
        input.signingKeyId,
        scope,
        input.baseUrl,
        input.nonce,
        new Date(input.issuedAtUnixSeconds * 1000),
        new Date(input.expiresAtUnixSeconds * 1000),
      )
      expect(toUtf8(bytes)).toBe(expected.signingBytesUtf8)

      const signature = sign(secretKey, bytes)
      expect(bytesToHex(signature)).toBe(expected.signatureHex)
    })
  }
})

describe('conformance: BIP39 mnemonic-derived signing keys (#134/#712)', () => {
  const doc = loadVector('bip39-mnemonic.json')

  it('lists typescript as supported', () => {
    requireSupported(doc, 'typescript')
  })

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  for (const vector of doc.vectors as any[]) {
    it(`matches the shared vector: ${vector.name}`, () => {
      const { input, expected } = vector
      if (expected.isValid === false) {
        expect(isValidMnemonic(input.mnemonic)).toBe(false)
        return
      }
      const derived = deriveSigningKeyFromMnemonic(input.mnemonic)
      expect(bytesToHex(derived.secretKey)).toBe(expected.derivedSecretKeyHex)
      expect(bytesToHex(derived.publicKey)).toBe(expected.derivedPublicKeyHex)
    })
  }
})

describe('conformance: attestation issuance/bulk-issuance/revocation signing (#774)', () => {
  const doc = loadVector('attestation-signing.json')

  it('lists typescript as supported', () => {
    requireSupported(doc, 'typescript')
  })

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  for (const vector of doc.vectors as any[]) {
    it(`matches the shared vector: ${vector.name}`, () => {
      const secretKey = hexToBytes(doc.signingKeySeedHex)
      const { input, expected } = vector
      const claimKind = input.claimKind as 'achievement' | 'milestone'

      let bytes: Uint8Array
      switch (input.operation) {
        case 'issue':
          bytes = attestationSigningBytes(claimKind, input.issuerRef, input.subject, input.achievement)
          break
        case 'bulk_issue':
          bytes = bulkAttestationSigningBytes(claimKind, input.issuerRef, input.subject, input.achievements)
          break
        case 'revoke':
          bytes = revocationSigningBytes(claimKind, input.issuerRef, input.attestationId, input.reasonCode)
          break
        default:
          throw new Error(`unknown operation ${input.operation}`)
      }

      expect(bytesToHex(bytes)).toBe(expected.signingBytesHex)
      expect(bytesToHex(sign(secretKey, bytes))).toBe(expected.signatureHex)
    })
  }
})

describe('conformance: Signed Tree Head signing', () => {
  const doc = loadVector('signed-tree-head.json')
  const publicKey = hexToBytes(doc.signingPublicKeyHex)

  it('lists typescript in supportedIn', () => {
    expect(doc.supportedIn).toContain('typescript')
  })

  for (const vector of doc.vectors) {
    it(`matches the shared vector: ${vector.name}`, () => {
      const { input, expected } = vector
      const bytes = signingMessage({
        tree_size: input.treeSize,
        root_hash: input.rootHashHex,
        network_id: input.networkId,
        created_at: new Date(input.createdAtUnixSeconds * 1000).toISOString(),
      } as SignedTreeHeadResponse)

      expect(bytesToHex(bytes)).toBe(expected.signingBytesHex)
      expect(verify(publicKey, bytes, hexToBytes(expected.signatureHex))).toBe(true)
    })
  }
})

describe('conformance: witness-cosigned tree head', () => {
  const doc = loadVector('witness-cosigned-tree-head.json')
  const keys: Record<string, string> = doc.witnessVerifyingKeysHex
  const iso = (seconds: number) => new Date(seconds * 1000).toISOString()

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  function toHead(raw: any): CosignedTreeHead {
    const sth: SignedTreeHeadResponse = {
      tree_size: raw.sth.treeSize,
      root_hash: raw.sth.rootHashHex,
      network_id: doc.networkId,
      signing_key_id: 'author',
      signature: raw.sth.signatureHex,
      created_at: iso(raw.sth.createdAtUnixSeconds),
      protocol_version: 'v1',
    }
    return {
      sth,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      cosignatures: raw.cosignatures.map((c: any) => ({
        tree_size: sth.tree_size,
        root_hash: sth.root_hash,
        network_id: sth.network_id,
        author_created_at: sth.created_at,
        witness_key_id: c.witnessKeyId,
        observed_at: iso(c.observedAtUnixSeconds),
        signature: c.signatureHex,
      })),
    }
  }

  const known = (ids: string[]): KnownWitness[] => ids.map((id) => ({ witnessKeyId: id, key: keys[id] }))

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  for (const vector of doc.vectors as any[]) {
    it(`matches the shared vector: ${vector.name}`, () => {
      const { input, expected } = vector
      const cutoff = new Date(input.freshnessCutoffUnixSeconds * 1000)
      const now = new Date(input.nowUnixSeconds * 1000)
      const list = known(input.knownList)
      if (input.headA) {
        const a = toHead(input.headA)
        const b = toHead(input.headB)
        expect(verifyCosignedTreeHead(doc.authorVerifyingKeyHex, a, list, cutoff, now)).toBe(expected.headAAccepted)
        expect(verifyCosignedTreeHead(doc.authorVerifyingKeyHex, b, list, cutoff, now)).toBe(expected.headBAccepted)
        expect(findEquivocatingWitnesses(doc.authorVerifyingKeyHex, list, cutoff, now, a, b)).toEqual(
          expected.equivocatingWitnesses,
        )
      } else {
        expect(verifyCosignedTreeHead(doc.authorVerifyingKeyHex, toHead(input), list, cutoff, now)).toBe(
          expected.accepted,
        )
      }
    })
  }
})

describe('conformance: witness announce proofs', () => {
  const doc = loadVector('witness-announce.json')
  for (const vector of doc.vectors) {
    it(vector.name, () => {
      const { baseUrl, witnessKeyId, announcedAt, proofHex, now, messageHex } = vector.input
      const announced = new Date(announcedAt)
      if (/^[0-9a-f]{64}$/.test(witnessKeyId)) {
        expect(bytesToHex(witnessAnnounceMessage(baseUrl, witnessKeyId, announced))).toBe(messageHex)
      }
      expect(verifyWitnessAnnounce(baseUrl, witnessKeyId, announced, proofHex, new Date(now))).toBe(
        vector.expected.accepted,
      )
    })
  }
})

describe('conformance: known-list selection', () => {
  const doc = loadVector('known-list-selection.json')
  for (const vector of doc.prefixVectors) {
    it(`prefix: ${vector.name}`, () => {
      expect(diversityPrefixForUrl(vector.input.baseUrl)).toBe(vector.expected.prefix)
    })
  }
  for (const vector of doc.selectionVectors) {
    it(`selection: ${vector.name}`, () => {
      const { candidates, capacity, anchorCapacity, maxPerPrefix } = vector.input
      expect(selectKnownList(candidates, capacity, anchorCapacity, maxPerPrefix)).toEqual(vector.expected)
    })
  }
})

describe('conformance: self-certifying tree heads', () => {
  const doc = loadVector('self-certifying-tree-head.json')

  it('lists typescript as supported', () => {
    requireSupported(doc, 'typescript')
  })

  it('derives the shared keys and ids', () => {
    expect(selfCertifyingId(hexToBytes(doc.signingPublicKeyHex))).toBe(doc.selfCertifyingId)
    expect(selfCertifyingId(hexToBytes(doc.otherPublicKeyHex))).toBe(doc.otherSelfCertifyingId)
  })

  for (const vector of doc.vectors) {
    it(vector.name, () => {
      const { shardId, signingPublicKeyHex, head } = vector.input
      const sth: SignedTreeHeadResponse = {
        // Decimal strings carry tree sizes beyond 2^53, which a JSON double cannot hold.
        tree_size: (typeof head.treeSize === 'string' ? BigInt(head.treeSize) : head.treeSize) as number,
        root_hash: head.rootHashHex,
        network_id: head.networkId,
        signing_key_id: head.signingKeyId,
        signature: head.signatureHex,
        created_at: head.createdAtRfc3339,
        protocol_version: '0.1',
      }
      expect(shardCheck(shardId)).toBe(vector.expected.check)
      const result = verifySelfCertifyingTreeHead(shardId, sth, signingPublicKeyHex)
      expect(result.verified).toBe(vector.expected.verified)
      expect(result.verified ? null : result.failure).toBe(vector.expected.failure)
    })
  }
})

describe('conformance: shard family head', () => {
  const doc = loadVector('shard-family-head.json')
  // Decimal strings carry tree sizes beyond 2^53, which a JSON double cannot hold.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const head = (h: any): FamilyHead => ({
    shard_id: h.shardId,
    tree_size: typeof h.treeSize === 'string' ? BigInt(h.treeSize) : h.treeSize,
    root_hash: h.rootHashHex,
    signing_key_id: h.signingKeyId,
    signature: h.signatureHex,
  })

  it('lists typescript as supported', () => {
    requireSupported(doc, 'typescript')
  })

  for (const v of doc.familyVectors) {
    it(`root: ${v.name}`, () => {
      expect(familyRoot(v.input.owner, v.input.heads.map(head))).toBe(v.expected.rootHashHex)
    })
  }

  for (const v of doc.proofVectors) {
    it(`proof: ${v.name}`, () => {
      const { owner, rootHashHex, shardId, proof } = v.input
      const claimed = { ...head(v.input.head), shard_id: shardId }
      const wire = { shard_id: shardId, leaf_index: proof.leafIndex, tree_size: proof.treeSize, path: proof.pathHex }
      expect(verifyFamilyInclusion(owner, rootHashHex, wire, claimed)).toBe(v.expected.verified)
    })
  }

  it('maps shard ids to owners', () => {
    for (const v of doc.familyOwnerVectors) expect([v.shardId, shardFamilyOwner(v.shardId)]).toEqual([v.shardId, v.expectedOwner])
  })

  it('recognizes owner ids', () => {
    for (const v of doc.ownerIdVectors) expect([v.owner, isFamilyOwnerId(v.owner)]).toEqual([v.owner, v.expected])
  })

  it('decides membership', () => {
    for (const v of doc.memberVectors) {
      expect([v.owner, v.shardId, isFamilyMember(v.owner, v.shardId)]).toEqual([v.owner, v.shardId, v.expected])
    }
  })
})

describe('conformance: shard sibling routing', () => {
  const doc = loadVector('shard-sibling-routing.json')

  it('lists typescript as supported', () => {
    requireSupported(doc, 'typescript')
  })

  for (const v of doc.weightVectors) {
    it(`weight: ${v.name}`, () => {
      const { owner, key, shardId } = v.input
      expect(bytesToHex(routeWeight(owner, key, shardId))).toBe(v.expected.weightHex)
    })
  }

  for (const v of doc.routeVectors) {
    it(`route: ${v.name}`, () => {
      expect(routeWrite(v.input.owner, v.input.key, v.input.siblings)).toBe(v.expected.shardId)
    })
  }

  for (const v of doc.movementVectors) {
    it(`movement: ${v.name}`, () => {
      const { owner, keys, before, after } = v.input
      keys.forEach((key: string, n: number) => {
        const b = routeWrite(owner, key, before)
        const a = routeWrite(owner, key, after)
        expect([key, b, a]).toEqual([key, v.expected.before[n], v.expected.after[n]])
        // A key only moves onto a sibling that was added, or off one that was removed.
        if (a !== b) expect(!before.includes(a) || !after.includes(b)).toBe(true)
      })
    })
  }
})
