// Cross-SDK conformance suite — loads the shared
// test vectors under conformance/vectors/ (repo root) and asserts this
// SDK's real implementation produces byte-for-byte identical output.
// Offline, no server needed — runs in the default `npm test` (vitest) job
// alongside every other unit test here.
//
// See conformance/vectors/SCHEMA.md for the vector format and the
// standing "add a vector when you add smart-client behavior" requirement.
import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

import { signingBytes as crossNodeLoginSigningBytes } from '../src/crypto/crossNodeLogin.js'
import { signingBytes as continuationSigningBytes } from '../src/crypto/continuation.js'
import { signingBytes as interestClaimSigningBytes, type ClaimedScope } from '../src/crypto/interestClaim.js'
import { deriveSigningKeyFromMnemonic, isValidMnemonic } from '../src/crypto/mnemonic.js'
import { attestationSigningBytes, bulkAttestationSigningBytes } from '../src/integratorSession.js'
import { revocationSigningBytes } from '../src/integratorAccount.js'
import {
  deviceGrantApprovalSigningBytes,
  identityCreatedSigningBytes,
  publicKeyFromSecretKey,
  sign,
  signingKeyRevokedSigningBytes,
  verify,
} from '../src/crypto/signing.js'
import { ALL_TAGS, Builder, Reader, SigningBytesError, tags, type DomainTag } from '../src/crypto/signingBytes.js'
import { CanonicalPayloadError, canonicalize, canonicalizeStr, parseStrict } from '../src/canonicalPayload.js'
import {
  EntryHashError,
  entryHashHex,
  entrySigningBytes,
  parseHash,
  payloadHash,
  timestampMicrosFromRfc3339,
  type EntryHashInput,
} from '../src/ledgerEntry.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { UnknownIdSchemeError, deriveIdentityId, identityIdMatchesKey, isIdentityId, parseIdentityId } from '../src/identityId.js'
import { isAcceptableShardKey, verifyStrict } from '../src/network/strictEd25519.js'
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

// Files a runner loaded, so the accounted-for check cannot be satisfied by a stray mention.
const LOADED_VECTOR_FILES = new Set<string>()

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function loadVector(name: string): any {
  LOADED_VECTOR_FILES.add(name)
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
      const scope: ClaimedScope = {
        kind: 'channel',
        channelId: input.scope.channelId,
      }

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
      const wire = {
        shard_id: shardId,
        leaf_index: proof.leafIndex,
        tree_size: proof.treeSize,
        path: proof.pathHex,
      }
      expect(verifyFamilyInclusion(owner, rootHashHex, wire, claimed)).toBe(v.expected.verified)
    })
  }

  it('maps shard ids to owners', () => {
    for (const v of doc.familyOwnerVectors)
      expect([v.shardId, shardFamilyOwner(v.shardId)]).toEqual([v.shardId, v.expectedOwner])
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

function catchError(run: () => unknown): unknown {
  try {
    run()
  } catch (error) {
    return error
  }
  return undefined
}

describe('conformance: identity ids', () => {
  const doc = loadVector('identity-id.json')

  it('lists typescript as supported', () => {
    requireSupported(doc, 'typescript')
  })

  for (const vector of doc.vectors) {
    it(`${vector.kind}: ${vector.name}`, () => {
      const { input, expected } = vector
      switch (vector.kind) {
        case 'derive': {
          const publicKey = publicKeyFromSecretKey(hexToBytes(input.seedHex))
          expect(bytesToHex(publicKey)).toBe(input.publicKeyHex)
          const id = deriveIdentityId(publicKey)
          expect(id).toBe(expected.identityId)
          expect(identityIdMatchesKey(id, publicKey)).toBe(true)
          break
        }
        case 'parse':
          expect(isIdentityId(input.identityId)).toBe(expected.valid)
          if (expected.result === 'valid') {
            expect(parseIdentityId(input.identityId)).toBe(input.identityId)
          } else if (expected.result === 'unknown_id_scheme') {
            const thrown = catchError(() => parseIdentityId(input.identityId))
            expect(thrown).toBeInstanceOf(UnknownIdSchemeError)
            expect((thrown as UnknownIdSchemeError).length).toBe(expected.length)
          } else {
            expect(expected.result).toBe('invalid_id')
            const thrown = catchError(() => parseIdentityId(input.identityId))
            expect(thrown).toBeInstanceOf(TypeError)
            expect(thrown).not.toBeInstanceOf(UnknownIdSchemeError)
          }
          break
        case 'key_acceptability':
          expect(isAcceptableShardKey(hexToBytes(input.publicKeyHex))).toBe(expected.acceptable)
          break
        case 'distinct_from_shard_id': {
          const key = hexToBytes(input.publicKeyHex)
          expect(deriveIdentityId(key)).toBe(expected.identityId)
          expect(selfCertifyingId(key)).toBe(expected.nodeShardId)
          expect(deriveIdentityId(key)).not.toBe(selfCertifyingId(key))
          expect(expected.equal).toBe(false)
          break
        }
        case 'strict_verify':
          expect(
            verifyStrict(hexToBytes(input.publicKeyHex), hexToBytes(input.messageHex), hexToBytes(input.signatureHex)),
          ).toBe(expected.valid)
          break
        default:
          throw new Error(`unknown identity-id vector kind ${vector.kind}`)
      }
    })
  }

  it('rejects a trailing newline and non-strings', () => {
    const id = deriveIdentityId(new Uint8Array(32).fill(7))
    expect(isIdentityId(`${id}\n`)).toBe(false)
    expect(isIdentityId(undefined)).toBe(false)
    expect(isIdentityId(null)).toBe(false)
  })
})

// The runners below execute every vector in their file; they do not gate on supportedIn.
function seqOf(input: { seq: string }): bigint {
  return BigInt(input.seq)
}

function prevHashOf(input: { prevHashHex: string | null }): Uint8Array | null {
  return input.prevHashHex === null ? null : hexToBytes(input.prevHashHex)
}

// Shared checks for the three identity key event files: exact bytes, exact signature, strict verify, and
// replay/legacy signatures that must not verify for the rebuilt bytes.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function runIdentityKeyEventVectors(file: string, build: (doc: any, input: any) => Uint8Array): void {
  describe(`conformance: ${file}`, () => {
    const doc = loadVector(file)
    const secretKey = hexToBytes(doc.signingKeySeedHex)
    const publicKey = hexToBytes(doc.signingPublicKeyHex)

    it('derives the shared public key from the seed', () => {
      expect(bytesToHex(publicKeyFromSecretKey(secretKey))).toBe(doc.signingPublicKeyHex)
    })

    for (const v of doc.vectors) {
      it(`signs the shared vector: ${v.name}`, () => {
        const bytes = build(doc, v.input)
        expect(bytesToHex(bytes)).toBe(v.expected.signingBytesHex)
        const signature = sign(secretKey, bytes)
        expect(bytesToHex(signature)).toBe(v.expected.signatureHex)
        expect(verifyStrict(publicKey, bytes, signature)).toBe(true)
      })
    }

    for (const group of ['replayVectors', 'legacyLayoutVectors']) {
      expect(doc[group].length, `${file} ${group}`).toBeGreaterThan(0)
      for (const r of doc[group]) {
        it(`${group}: ${r.name}`, () => {
          const bytes = build(doc, r.input)
          if (r.legacySigningBytesUtf8 !== undefined) {
            const legacy = new TextEncoder().encode(r.legacySigningBytesUtf8)
            expect(bytes).not.toEqual(legacy)
            expect(verifyStrict(publicKey, legacy, hexToBytes(r.signatureHex))).toBe(true)
          }
          expect(verifyStrict(publicKey, bytes, hexToBytes(r.signatureHex))).toBe(r.expected.valid)
        })
      }
    }
  })
}

runIdentityKeyEventVectors('identity-created-signing.json', (doc, input) =>
  identityCreatedSigningBytes(
    input.networkId,
    input.shardId,
    input.ticketId,
    doc.identityId,
    hexToBytes(doc.signingPublicKeyHex),
    input.displayName,
  ),
)

runIdentityKeyEventVectors('device-grant-approval.json', (_doc, input) =>
  deviceGrantApprovalSigningBytes(
    input.grantId,
    input.identityId,
    input.approverSigningKeyId,
    hexToBytes(input.requestedPublicKeyHex),
    seqOf(input),
    prevHashOf(input),
  ),
)

runIdentityKeyEventVectors('signing-key-revoked.json', (_doc, input) =>
  signingKeyRevokedSigningBytes(
    input.identityId,
    input.signingKeyId,
    input.revokedBySigningKeyId,
    seqOf(input),
    prevHashOf(input),
  ),
)

function tagByName(name: string): DomainTag {
  const tag = ALL_TAGS.find((t) => t.name === name)
  if (!tag) throw new Error(`tag ${name} is not in the registry`)
  return tag
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function fieldBytes(field: any): Uint8Array {
  const repeat = (unit: Uint8Array): Uint8Array => {
    const out = new Uint8Array(unit.length * field.count)
    for (let i = 0; i < field.count; i += 1) out.set(unit, i * unit.length)
    return out
  }
  switch (field.type) {
    case 'str':
      return field.utf8 !== undefined
        ? new TextEncoder().encode(field.utf8)
        : repeat(new TextEncoder().encode(field.repeatUtf8))
    case 'bytes':
      return field.hex !== undefined ? hexToBytes(field.hex) : repeat(hexToBytes(field.repeatByteHex))
    default:
      return hexToBytes(field.hex)
  }
}

describe('conformance: structured-signing-bytes.json', () => {
  const doc = loadVector('structured-signing-bytes.json')

  for (const v of doc.vectors) {
    it(`builds and reads back: ${v.name}`, () => {
      const tag = tagByName(v.input.tag)
      const builder = new Builder(tag, v.input.version)
      for (const f of v.input.fields) {
        switch (f.type) {
          case 'str':
            builder.str(toUtf8(fieldBytes(f)))
            break
          case 'bytes':
            builder.bytes(fieldBytes(f))
            break
          case 'key':
            builder.key(fieldBytes(f))
            break
          case 'hash':
            builder.hash(fieldBytes(f))
            break
          case 'fixed':
            builder.fixed(fieldBytes(f), 4)
            break
          case 'uuid':
            builder.uuid(f.value)
            break
          case 'u8':
          case 'u16':
          case 'u32':
          case 'u64':
          case 'i64':
            builder[f.type as 'u8'](BigInt(f.value))
            break
          default:
            throw new Error(`unknown field type ${f.type}`)
        }
      }
      const message = builder.finish()

      if (v.expected.signingBytesHex !== undefined) {
        expect(bytesToHex(message)).toBe(v.expected.signingBytesHex)
      } else {
        expect(message.length).toBe(v.expected.signingBytesLength)
        expect(bytesToHex(sha256(message))).toBe(v.expected.signingBytesSha256Hex)
      }

      const reader = new Reader(tag, message)
      expect(reader.version).toBe(v.input.version)
      for (const f of v.input.fields) {
        switch (f.type) {
          case 'str':
            expect(reader.str()).toBe(toUtf8(fieldBytes(f)))
            break
          case 'bytes':
            expect(reader.bytes()).toEqual(fieldBytes(f))
            break
          case 'key':
            expect(reader.key()).toEqual(fieldBytes(f))
            break
          case 'hash':
            expect(reader.hash()).toEqual(fieldBytes(f))
            break
          case 'fixed':
            expect(reader.fixed(4)).toEqual(fieldBytes(f))
            break
          case 'uuid':
            expect(reader.uuid()).toBe(f.value)
            break
          case 'u8':
          case 'u16':
          case 'u32':
            expect(String(reader[f.type as 'u8']())).toBe(f.value)
            break
          case 'u64':
          case 'i64':
            expect(reader[f.type as 'u64']().toString()).toBe(f.value)
            break
          default:
            throw new Error(`unknown field type ${f.type}`)
        }
      }
      reader.finish()
    })
  }

  expect(doc.rejectVectors.length).toBeGreaterThan(0)
  for (const v of doc.rejectVectors) {
    it(`rejects: ${v.name}`, () => {
      const message = hexToBytes(v.input.messageHex)
      const read = (): void => {
        const reader = new Reader(tagByName(v.input.tag), message)
        for (const ty of v.input.read) {
          if (ty === 'str') reader.str()
          else if (ty === 'bytes') reader.bytes()
          else if (ty === 'u32') reader.u32()
          else throw new Error(`unknown read type ${ty}`)
        }
        reader.finish()
      }
      let code: string | undefined
      try {
        read()
      } catch (error) {
        if (!(error instanceof SigningBytesError)) throw error
        code = error.code
      }
      expect(code).toBe(v.expected.error)
    })
  }
})

describe('conformance: domain-tags.json', () => {
  const doc = loadVector('domain-tags.json')

  it('the registry matches the shared list, in order', () => {
    const have = Object.entries(tags).map(([kind, tag]) => ({ kind: kind.toLowerCase(), tag: tag.name }))
    expect(have).toEqual(doc.tags)
    expect(ALL_TAGS.map((t) => t.name)).toEqual(doc.tags.map((t: { tag: string }) => t.tag))
  })
})

describe('conformance: canonical-payload.json', () => {
  const doc = loadVector('canonical-payload.json')

  it('loads the full vector set', () => {
    expect(doc.vectors.length).toBeGreaterThan(50)
  })

  for (const v of doc.vectors) {
    it(`${v.expected.error ? 'rejects' : 'encodes'}: ${v.name}`, () => {
      if (v.expected.error === undefined) {
        expect(canonicalizeStr(v.input.jsonUtf8)).toBe(v.expected.canonicalUtf8)
        return
      }
      let code: string | undefined
      try {
        canonicalizeStr(v.input.jsonUtf8)
      } catch (error) {
        if (!(error instanceof CanonicalPayloadError)) throw error
        code = error.code
      }
      expect(code).toBe(v.expected.error)
    })
  }
})

describe('conformance: ledger-entry-hash.json', () => {
  const doc = loadVector('ledger-entry-hash.json')

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  function inputOf(input: any): EntryHashInput {
    return {
      networkId: input.networkId,
      shardId: input.shardId,
      seq: BigInt(input.seq),
      prevHash: parseHash('prev_hash', input.prevHashHex),
      eventId: input.eventId,
      kind: input.kind,
      issuer: input.issuer,
      subject: input.subject,
      payloadHash:
        input.payloadHashHex !== undefined
          ? parseHash('payload_hash', input.payloadHashHex)
          : payloadHash(parseStrict(input.payloadJsonUtf8)),
      timestampMicros: BigInt(input.timestampUnixMicros),
      version: input.version,
    }
  }

  for (const v of doc.vectors) {
    it(`hashes: ${v.name}`, () => {
      const { input, expected } = v
      if (input.payloadJsonUtf8 !== undefined) {
        const value = parseStrict(input.payloadJsonUtf8)
        expect(canonicalize(value)).toBe(expected.payloadCanonicalUtf8)
        expect(bytesToHex(payloadHash(value))).toBe(expected.payloadHashHex)
      }
      const bytes = entrySigningBytes(inputOf(input))
      expect(bytesToHex(bytes)).toBe(expected.signingBytesHex)
      expect(bytesToHex(sha256(bytes))).toBe(expected.entryHashHex)
      expect(entryHashHex(inputOf(input))).toBe(expected.entryHashHex)
      expect(timestampMicrosFromRfc3339(input.eventTimestampRfc3339).toString()).toBe(input.timestampUnixMicros)
    })
  }

  expect(doc.rejectVectors.length).toBeGreaterThan(0)
  for (const v of doc.rejectVectors) {
    it(`rejects: ${v.name}`, () => {
      let code: string | undefined
      try {
        entrySigningBytes(inputOf(v.input))
      } catch (error) {
        if (!(error instanceof EntryHashError)) throw error
        code = error.code
      }
      expect(code).toBe(v.expected.error)
    })
  }
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

// Vector files with no runner in this SDK yet, each with the reason it is skipped.
const NO_RUNNER: Record<string, string> = {
  'identity-chain.json': 'identity chain resolution is protocol-side only',
  'node-request.json': 'node-to-node route, not in OpenAPI; supportedIn is empty',
}

describe('conformance: every vector file is accounted for', () => {
  for (const file of readdirSync(VECTORS_DIR).filter((f) => f.endsWith('.json'))) {
    const reason = NO_RUNNER[file]
    if (reason) {
      it.skip(`${file}: ${reason}`, () => {})
    } else {
      it(`${file} has a runner`, () => {
        expect(LOADED_VECTOR_FILES.has(file)).toBe(true)
      })
    }
  }
})
