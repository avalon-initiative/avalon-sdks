// IntegratorSession — mirrors the Rust `Session`/C# `Session`
// capability-gated integrator model (crates/sdk/src/lib.rs). Distinct from
// AccountSession: no shared base class, no conversion in either direction
// — an integrator credential must never yield account-level power.
//
// Obtained via `AvalonClient.authenticate(identityToken)`, which exchanges
// an identity's existing session token for a Session scoped to this
// integrator's own granted capabilities (`GET /me` + `GET /me/grants`).
// Every read/write method checks its own required capability client-side
// before making a request — `require()` below — the same fast-fail
// convention every other SDK in this repo uses; the server enforces the
// same thing independently, this is not the security boundary.
import { request } from './http.js'
import { CapabilityNotGrantedError, MissingIssuerCredentialsError } from './errors.js'
import { fromMeResponse, type Identity, type Profile, type MeResponseWire } from './types.js'
import { hexToBytes } from '@noble/hashes/utils.js'
import { sign as ed25519Sign, bytesToBase64, base64ToBytes } from './crypto/signing.js'
import { Builder, tags, type DomainTag } from './crypto/signingBytes.js'
import { parseIdentityId, type IdentityId } from './identityId.js'
import { resolveVerifiedNetworkId } from './network/verifiedNetworkId.js'
import type { components } from './generated.js'

export type Capability =
  | 'identity.read'
  | 'profile.read'
  | 'friends.read'
  | 'presence.read'
  | 'presence.publish'
  | 'guilds.read'
  | 'guilds.chat'
  | 'guilds.issue'
  | 'achievements.read'
  | 'achievements.issue'
  | 'milestones.issue'
  | 'assets.read'
  | 'assets.issue'
  | 'wallet.read'
  | 'wallet.write'
  | 'messages.read'
  | 'messages.send'
  | (string & {})

export interface IntegratorSessionInit {
  identity: Identity
  profile: Profile
  granted: Capability[]
  serverUrl: string
  token: string
  integratorKeyId: string
  integratorSlug?: string
  signingKey?: Uint8Array
  /** The network id to sign into attestations; when omitted it is verified against the trust anchors on first use. */
  networkId?: string
}

export interface Friend {
  identityId: string
  since: string
}
interface FriendWire {
  identity_id: string
  since: string
}

export interface GuildMembership {
  guildId: string
  roleIndex: number
}
interface GuildMembershipWire {
  guild_id: string
  role_index: number
}

export interface ConversationSummary {
  id: string
  participants: string[]
}

export interface Authenticity {
  status: string
  [key: string]: unknown
}

/** An identity's own attestation, as returned by `GET /me/achievements` —
 * this SDK's copy of the wire shape (no dependency on avalon-chain). */
export interface VerifiedAttestation {
  id: string
  issuer: string
  subject: string
  achievement: string
  issuedAt: string
  authenticity: Authenticity
  validity: { status: string; [key: string]: unknown }
}
interface VerifiedAttestationWire {
  id: string
  issuer: string
  subject: string
  achievement: string
  issued_at: string
  authenticity: Authenticity
  validity: { status: string; [key: string]: unknown }
}

interface ListMyAchievementsResponseWire {
  achievements: VerifiedAttestationWire[]
  next_cursor: string | null
}

interface ChallengeResponseWire {
  challenge_id: string
  nonce: string
}

/** The fields every attestation layout starts with: network id, claim kind, issuer ref and the signing key's id. */
function attestationHeader(
  tag: DomainTag,
  networkId: string,
  claimKind: 'achievement' | 'milestone',
  issuerRef: string,
  signingKeyId: string,
): Builder {
  return new Builder(tag, 1).str(networkId).str(claimKind).str(issuerRef).uuid(signingKeyId)
}

/** The exact bytes an issuer's key signs to authorize an attestation (tag `avalon.attestation.issue`, layout 1):
 * network id, claim kind, issuer ref, signing key id (uuid), subject (32 raw), achievement id and `issued_at` as
 * i64 unix microseconds. Must stay byte-for-byte identical to
 * `avalon_protocol::achievements::attestation_signing_bytes`; `conformance/vectors/attestation-signing.json`
 * proves it. Exported for that conformance runner, not part of the public SDK surface. */
export function attestationSigningBytes(
  networkId: string,
  claimKind: 'achievement' | 'milestone',
  issuerRef: string,
  signingKeyId: string,
  subject: IdentityId,
  achievement: string,
  issuedAtMicros: bigint | number,
): Uint8Array {
  return attestationHeader(tags.ATTESTATION_ISSUE, networkId, claimKind, issuerRef, signingKeyId)
    .fixed(hexToBytes(parseIdentityId(subject)), 32)
    .str(achievement)
    .i64(issuedAtMicros)
    .finish()
}

/** Must match `avalon_protocol::achievements::bulk_attestation_signing_bytes` byte-for-byte (tag
 * `avalon.attestation.bulk_issue`, layout 1): the issue header and subject, one `issued_at` for every claim,
 * the claim count as u32, then each achievement id in order. Checked against
 * `conformance/vectors/attestation-signing.json`; exported for that runner, not part of the public SDK surface. */
export function bulkAttestationSigningBytes(
  networkId: string,
  claimKind: 'achievement' | 'milestone',
  issuerRef: string,
  signingKeyId: string,
  subject: IdentityId,
  issuedAtMicros: bigint | number,
  achievements: string[],
): Uint8Array {
  const builder = attestationHeader(tags.ATTESTATION_BULK_ISSUE, networkId, claimKind, issuerRef, signingKeyId)
    .fixed(hexToBytes(parseIdentityId(subject)), 32)
    .i64(issuedAtMicros)
    .u32(achievements.length)
  for (const achievement of achievements) builder.str(achievement)
  return builder.finish()
}

interface ClaimProof {
  keyId: string
  algorithm: string
  bytes: string
}

export interface Attestation {
  id: string
  issuer: string
  subject: string
  achievement: string
  issuedAt: string
  proof: ClaimProof
}
type AttestationWire = components['schemas']['AttestationResponse']
function attestationFromWire(w: AttestationWire): Attestation {
  return {
    id: w.id,
    issuer: w.issuer,
    subject: w.subject,
    achievement: w.achievement,
    issuedAt: w.issued_at,
    proof: { keyId: w.proof.key_id, algorithm: w.proof.algorithm, bytes: w.proof.bytes },
  }
}

export type BulkClaimOutcome =
  | { status: 'issued'; key: string; attestation: Attestation }
  | { status: 'failed'; key: string; code: string; error: string }
type BulkClaimResultWire = components['schemas']['BulkClaimResult']
function bulkClaimOutcomeFromWire(w: BulkClaimResultWire): BulkClaimOutcome {
  if (w.status === 'issued') {
    return { status: 'issued', key: w.key, attestation: attestationFromWire(w.attestation) }
  }
  return { status: 'failed', key: w.key, code: w.code, error: w.error }
}

export interface BulkClaimInput {
  key: string
  evidence?: Record<string, unknown>
}

export class IntegratorSession {
  /** @internal */ private readonly identityValue: Identity
  /** @internal */ private readonly profileValue: Profile
  /** @internal */ private readonly granted: Set<Capability>
  /** @internal */ private readonly serverUrl: string
  /** @internal */ private readonly token: string
  /** @internal */ private readonly integratorKeyId: string
  /** @internal */ private readonly integratorSlug?: string
  /** @internal */ private readonly signingKey?: Uint8Array
  /** @internal */ private networkIdValue?: string

  constructor(init: IntegratorSessionInit) {
    this.identityValue = init.identity
    this.profileValue = init.profile
    this.granted = new Set(init.granted)
    this.serverUrl = init.serverUrl
    this.token = init.token
    this.integratorKeyId = init.integratorKeyId
    this.integratorSlug = init.integratorSlug
    this.signingKey = init.signingKey
    this.networkIdValue = init.networkId
  }

  /** This session's own identity — no network call, populated once by
   * `AvalonClient.authenticate`. */
  identity(): Identity {
    return this.identityValue
  }

  /** This session's own profile, as it was when `authenticate` ran — not
   * re-fetched automatically after a later edit made through another
   * client. */
  profile(): Profile {
    return this.profileValue
  }

  /** Whether `capability` was actually granted to this integrator for this
   * identity. */
  hasCapability(capability: Capability): boolean {
    return this.granted.has(capability)
  }

  /** The network id signed into every attestation: the declared one, else verified once against the trust anchors.
   * Throws `NetworkNotVerifiedError` when it cannot be verified. */
  private async networkId(): Promise<string> {
    this.networkIdValue ??= await resolveVerifiedNetworkId(this.serverUrl)
    return this.networkIdValue
  }

  /** Every capability-gated method calls this first — throws
   * `CapabilityNotGrantedError` without making a request when the
   * capability isn't present in `GET /me/grants`'s response. */
  private require(capability: Capability): void {
    if (!this.granted.has(capability)) {
      throw new CapabilityNotGrantedError(capability)
    }
  }

  private get<T>(path: string): Promise<T> {
    return request<T>(this.serverUrl, path, { token: this.token })
  }

  private getQuery<T>(path: string, query: Record<string, string>): Promise<T> {
    return request<T>(this.serverUrl, path, { token: this.token, query })
  }

  private post<T>(path: string, body: unknown): Promise<T> {
    return request<T>(this.serverUrl, path, { method: 'POST', token: this.token, body })
  }

  /** `friends.read`-gated — `GET /friends`. */
  async friends(): Promise<Friend[]> {
    this.require('friends.read')
    const w = await this.get<FriendWire[]>('/friends')
    return w.map((f) => ({ identityId: f.identity_id, since: f.since }))
  }

  /** `presence.read`-gated — `GET /presence?ids=`. */
  async presenceOf(ids: string[]): Promise<{ identityId: string; status: string }[]> {
    this.require('presence.read')
    if (ids.length === 0) return []
    return this.getQuery('/presence', { ids: ids.join(',') })
  }

  /** `presence.publish`-gated — `PUT /me/presence`. */
  async updatePresence(status: string): Promise<void> {
    this.require('presence.publish')
    await request(this.serverUrl, '/me/presence', {
      method: 'PUT',
      token: this.token,
      body: { status },
    })
  }

  /** `guilds.read`-gated — `GET /me/guilds`. */
  async guilds(): Promise<GuildMembership[]> {
    this.require('guilds.read')
    const w = await this.get<GuildMembershipWire[]>('/me/guilds')
    return w.map((g) => ({ guildId: g.guild_id, roleIndex: g.role_index }))
  }

  /** `guilds.chat`-gated — `GET /guilds/{id}/channels/{channelId}/messages`. */
  async guildMessages(guildId: string, channelId: string, before?: string, limit?: number) {
    this.require('guilds.chat')
    const query: Record<string, string> = {}
    if (before) query.before = before
    if (limit !== undefined) query.limit = String(limit)
    return this.getQuery(`/guilds/${guildId}/channels/${channelId}/messages`, query)
  }

  /** `guilds.chat`-gated — `POST /guilds/{id}/channels/{channelId}/messages`. */
  async sendGuildMessage(guildId: string, channelId: string, body: string) {
    this.require('guilds.chat')
    return this.post(`/guilds/${guildId}/channels/${channelId}/messages`, { body })
  }

  /** `messages.read`-gated — `GET /conversations`. */
  async conversations(): Promise<ConversationSummary[]> {
    this.require('messages.read')
    return this.get('/conversations')
  }

  /** `messages.send`-gated — `POST /conversations`. */
  async dm(participants: string[]): Promise<ConversationSummary> {
    this.require('messages.send')
    return this.post('/conversations', { participants })
  }

  /** `achievements.read`-gated — this identity's own attestation history.
   * No `recognition` field: that's computed by this integrator against its
   * own trust policy, never by this SDK on the caller's
   * behalf. */
  async achievements(): Promise<VerifiedAttestation[]> {
    this.require('achievements.read')
    const page = await this.get<ListMyAchievementsResponseWire>('/me/achievements?limit=200')
    return page.achievements.map((a) => ({
      id: a.id,
      issuer: a.issuer,
      subject: a.subject,
      achievement: a.achievement,
      issuedAt: a.issued_at,
      authenticity: a.authenticity,
      validity: a.validity,
    }))
  }

  /** `achievements.issue`-gated — issues `key` (defined by this
   * integrator) to this session's own identity, signed locally with the
   * integrator's own signing key. Two independent proofs go out: an
   * ephemeral challenge-response proving this key is making this call
   * right now, and a signature embedded in the request body over the
   * attestation's own canonical bytes. Throws `MissingIssuerCredentialsError`
   * without any HTTP call if this integrator has no slug/signingKey
   * configured. */
  async issueAchievement(key: string): Promise<string> {
    const claim = await this.prepareClaimIssuance('achievement', key)
    const response = await request<{ id: string }>(this.serverUrl, `/integrations/${claim.slug}/achievements/${key}/issue`, {
      method: 'POST',
      headers: claim.headers,
      body: claim.body,
    })
    return response.id
  }

  /** `milestones.issue`-gated — same shape as `issueAchievement`, against
   * the `milestones` claim vocabulary instead. */
  async issueMilestone(key: string): Promise<string> {
    const claim = await this.prepareClaimIssuance('milestone', key)
    const response = await request<{ id: string }>(this.serverUrl, `/integrations/${claim.slug}/milestones/${key}/issue`, {
      method: 'POST',
      headers: claim.headers,
      body: claim.body,
    })
    return response.id
  }

  /** Shared core of `issueAchievement`/`issueMilestone` — the challenge-
   * response + embedded-signature proofs both need, decoupled from the
   * final request itself so each caller's own `request()` call still
   * carries a literal path template (`scripts/check-sdk-coverage.py`
   * matches call sites by literal path, not by tracing a dynamic one back
   * to its route). See `issueAchievement`'s own doc comment for the
   * two-proof shape. */
  private async prepareClaimIssuance(
    claimKind: 'achievement' | 'milestone',
    key: string,
  ): Promise<{
    slug: string
    headers: Record<string, string>
    body: { key_id: string; signature: string; issued_at_micros: number }
  }> {
    this.require(claimKind === 'achievement' ? 'achievements.issue' : 'milestones.issue')
    if (!this.integratorSlug || !this.signingKey) {
      throw new MissingIssuerCredentialsError()
    }
    const slug = this.integratorSlug
    const networkId = await this.networkId()

    const challenge = await request<ChallengeResponseWire>(this.serverUrl, `/integrations/${slug}/challenge`, {
      method: 'POST',
    })
    const nonce = base64ToBytes(challenge.nonce)
    const challengeSignature = ed25519Sign(this.signingKey, nonce)

    const subject = this.identityValue.id
    const issuerRef = `game:${slug}`
    const achievement = `game:${slug}:${claimKind}:${key}`
    const issuedAtMicros = Date.now() * 1000
    const signature = ed25519Sign(
      this.signingKey,
      attestationSigningBytes(
        networkId,
        claimKind,
        issuerRef,
        this.integratorKeyId,
        subject,
        achievement,
        issuedAtMicros,
      ),
    )

    return {
      slug,
      headers: {
        'x-avalon-integrator-key-id': this.integratorKeyId,
        'x-avalon-integrator-challenge-id': challenge.challenge_id,
        'x-avalon-integrator-signature': bytesToBase64(challengeSignature),
        'x-avalon-identity-id': subject,
        'idempotency-key': crypto.randomUUID(),
      },
      body: { key_id: this.integratorKeyId, signature: bytesToBase64(signature), issued_at_micros: issuedAtMicros },
    }
  }

  /** `achievements.issue`-gated — `POST /integrations/{slug}/achievements/bulk-issue`.
   * One challenge-response proof, plus **one** signature over the
   * whole ordered `claims` list — never a per-claim signature. Never
   * all-or-nothing: a claim referencing an unknown/retired definition fails
   * on its own, every other claim in the same call still succeeds — check
   * each result's own `status`. */
  async bulkIssueAchievements(claims: BulkClaimInput[]): Promise<BulkClaimOutcome[]> {
    const bulk = await this.prepareBulkClaimIssuance('achievement', claims)
    const response = await request<components['schemas']['BulkIssueAttestationResponse']>(
      this.serverUrl,
      `/integrations/${bulk.slug}/achievements/bulk-issue`,
      { method: 'POST', headers: bulk.headers, body: bulk.body },
    )
    return response.results.map(bulkClaimOutcomeFromWire)
  }

  /** `milestones.issue`-gated — same shape as `bulkIssueAchievements`,
   * against the `milestones` claim vocabulary instead. */
  async bulkIssueMilestones(claims: BulkClaimInput[]): Promise<BulkClaimOutcome[]> {
    const bulk = await this.prepareBulkClaimIssuance('milestone', claims)
    const response = await request<components['schemas']['BulkIssueAttestationResponse']>(
      this.serverUrl,
      `/integrations/${bulk.slug}/milestones/bulk-issue`,
      { method: 'POST', headers: bulk.headers, body: bulk.body },
    )
    return response.results.map(bulkClaimOutcomeFromWire)
  }

  /** Shared core of `bulkIssueAchievements`/`bulkIssueMilestones` — see
   * `prepareClaimIssuance`'s own doc comment for why the final `request()`
   * call stays in each caller rather than here. */
  private async prepareBulkClaimIssuance(
    claimKind: 'achievement' | 'milestone',
    claims: BulkClaimInput[],
  ): Promise<{
    slug: string
    headers: Record<string, string>
    body: {
      key_id: string
      signature: string
      issued_at_micros: number
      claims: { key: string; evidence: unknown }[]
    }
  }> {
    this.require(claimKind === 'achievement' ? 'achievements.issue' : 'milestones.issue')
    if (!this.integratorSlug || !this.signingKey) {
      throw new MissingIssuerCredentialsError()
    }
    const slug = this.integratorSlug
    const networkId = await this.networkId()

    const challenge = await request<ChallengeResponseWire>(this.serverUrl, `/integrations/${slug}/challenge`, {
      method: 'POST',
    })
    const nonce = base64ToBytes(challenge.nonce)
    const challengeSignature = ed25519Sign(this.signingKey, nonce)

    const subject = this.identityValue.id
    const issuerRef = `game:${slug}`
    const achievementRefs = claims.map((c) => `game:${slug}:${claimKind}:${c.key}`)
    const issuedAtMicros = Date.now() * 1000
    const signature = ed25519Sign(
      this.signingKey,
      bulkAttestationSigningBytes(
        networkId,
        claimKind,
        issuerRef,
        this.integratorKeyId,
        subject,
        issuedAtMicros,
        achievementRefs,
      ),
    )

    return {
      slug,
      headers: {
        'x-avalon-integrator-key-id': this.integratorKeyId,
        'x-avalon-integrator-challenge-id': challenge.challenge_id,
        'x-avalon-integrator-signature': bytesToBase64(challengeSignature),
        'x-avalon-identity-id': subject,
        'idempotency-key': crypto.randomUUID(),
      },
      body: {
        key_id: this.integratorKeyId,
        signature: bytesToBase64(signature),
        issued_at_micros: issuedAtMicros,
        claims: claims.map((c) => ({ key: c.key, evidence: c.evidence ?? null })),
      },
    }
  }

  /** `presence.publish`-gated — `PUT /presence/{identityId}`: an integrator
   * publishing presence on behalf of this session's own identity, distinct
   * from `updatePresence`'s `PUT /me/presence` (a user acting for
   * themselves). Authenticated the same challenge-response way as
   * `issueAchievement`, never with this session's bearer token — the
   * server rejects a bearer-authenticated caller here outright, since this
   * route requires an integrator caller specifically. Throws
   * `MissingIssuerCredentialsError` without any HTTP call if this
   * integrator has no slug/signingKey configured. */
  async updateIntegratorPresence(status: string, activeIn?: string): Promise<void> {
    this.require('presence.publish')
    if (!this.integratorSlug || !this.signingKey) {
      throw new MissingIssuerCredentialsError()
    }
    const slug = this.integratorSlug
    const networkId = await this.networkId()

    const challenge = await request<ChallengeResponseWire>(this.serverUrl, `/integrations/${slug}/challenge`, {
      method: 'POST',
    })
    const nonce = base64ToBytes(challenge.nonce)
    const challengeSignature = ed25519Sign(this.signingKey, nonce)

    const subject = this.identityValue.id
    await request(this.serverUrl, `/presence/${subject}`, {
      method: 'PUT',
      headers: {
        'x-avalon-integrator-key-id': this.integratorKeyId,
        'x-avalon-integrator-challenge-id': challenge.challenge_id,
        'x-avalon-integrator-signature': bytesToBase64(challengeSignature),
        'x-avalon-identity-id': subject,
      },
      body: { status, active_in: activeIn ?? null },
    })
  }

  /** `GET /me/grants` — this integrator's full granted-capability set for
   * this session's own identity, straight from the server (`authenticate`
   * already fetches this once internally to populate `hasCapability`, but
   * discards the raw response — this is that same call, exposed). */
  async myGrants(): Promise<{ integratorId: string; capabilities: Capability[] }> {
    const w = await request<components['schemas']['MyGrantsResponse']>(this.serverUrl, '/me/grants', {
      token: this.token,
      headers: { 'x-avalon-integrator-key-id': this.integratorKeyId },
    })
    return { integratorId: w.integrator_id, capabilities: w.capabilities }
  }
}

export interface AuthenticateOptions {
  serverUrl: string
  identityToken: string
  integratorCredentialKeyId: string
  integratorSlug?: string
  signingKey?: Uint8Array
  networkId?: string
}

/** Exchanges an identity's existing session token for an `IntegratorSession`
 * scoped to this integrator — `GET /me` + `GET /me/grants`. Mirrors
 * `AvalonClient::authenticate` in the Rust SDK. */
export async function authenticate(options: AuthenticateOptions): Promise<IntegratorSession> {
  const body = await request<MeResponseWire>(options.serverUrl, '/me', { token: options.identityToken })
  const { identity, profile } = fromMeResponse(body)

  let granted: Capability[] = []
  try {
    const grants = await request<{ capabilities: string[] }>(options.serverUrl, '/me/grants', {
      token: options.identityToken,
      headers: { 'x-avalon-integrator-key-id': options.integratorCredentialKeyId },
    })
    granted = grants.capabilities
  } catch {
    // An unrecognized/placeholder key id, or no grants yet — treated as
    // "no grants," not an authentication failure (the token already
    // proved who the identity is).
  }

  return new IntegratorSession({
    identity,
    profile,
    granted,
    serverUrl: options.serverUrl,
    token: options.identityToken,
    integratorKeyId: options.integratorCredentialKeyId,
    integratorSlug: options.integratorSlug,
    signingKey: options.signingKey,
    networkId: options.networkId,
  })
}
