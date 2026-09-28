// Core identity/profile wire shapes shared by AccountSession and
// IntegratorSession — mirrors avalon_protocol::identity::{Identity, Profile}
// and both Rust/C# SDKs' own `MeResponse` mapping.

import type { components } from './generated'

export type Genre = components['schemas']['Genre']

export interface Identity {
  id: string
  createdAt: string
}

export interface Profile {
  identityId: string
  displayName: string
  avatarUrl: string | null
  bio: string | null
  favoriteGenres: Genre[]
  pronouns: string | null
  bannerUrl: string | null
  status: string | null
  links: string[]
  timezone: string | null
  themeColor: string | null
  location: string | null
  // `null` means "not explicitly set," not "no guild" — see
  // `effectiveMainGuild` for the resolved value to build a single-guild UI
  // around.
  mainGuild: string | null
  // `mainGuild` if explicitly set, otherwise the guild this identity
  // joined earliest, computed server-side at read time and never stored.
  // `null` only when the identity has no guild memberships at all.
  effectiveMainGuild: string | null
  // Issue #205's opt-in global search toggle.
  discoverable: boolean
  // Issue #87 — who can see this identity's presence status: "public" |
  // "authenticated_only" | "friends" | "guild_members" | "private".
  presenceVisibility: string
}

/** `GET /me`'s wire response, field-for-field — generated from
 * `docs/generated/openapi.json` rather than hand-written. */
export type MeResponseWire = components['schemas']['ProfileResponse']

export function fromMeResponse(body: MeResponseWire): { identity: Identity; profile: Profile } {
  return {
    identity: { id: body.identity_id, createdAt: body.identity_created_at },
    profile: {
      identityId: body.identity_id,
      displayName: body.display_name,
      avatarUrl: body.avatar_url ?? null,
      bio: body.bio ?? null,
      favoriteGenres: body.favorite_genres,
      pronouns: body.pronouns ?? null,
      bannerUrl: body.banner_url ?? null,
      status: body.status ?? null,
      links: body.links,
      timezone: body.timezone ?? null,
      themeColor: body.theme_color ?? null,
      location: body.location ?? null,
      mainGuild: body.main_guild ?? null,
      effectiveMainGuild: body.effective_main_guild ?? null,
      discoverable: body.discoverable ?? false,
      presenceVisibility: body.presence_visibility ?? 'public',
    },
  }
}

export interface DeviceRowWire {
  id: string
  public_key: string
}

/** `GET /ledger/sth/latest`'s wire response, field-for-field — matches
 * `crates/server/src/settlement.rs::SignedTreeHeadResponse`. See
 * `./network/sthMessage.js` for reconstructing the signing message this
 * type's signature covers, and `./network/verifyNetwork.js`/
 * `AvalonClient.verifyNetwork` for verifying it. */
export interface SignedTreeHeadResponse {
  tree_size: number
  // Lowercase hex-encoded RFC 6962 Merkle Tree Hash.
  root_hash: string
  network_id: string
  signing_key_id: string
  // Lowercase hex-encoded Ed25519 signature (64 bytes).
  signature: string
  // RFC 3339.
  created_at: string
  protocol_version: string
  // Lowercase hex Ed25519 public key that signed the head, served for self-certifying `node:` shards
  // only (older nodes omit it). Not part of the signed bytes; see `verifySelfCertifyingTreeHead`.
  signing_public_key?: string
}

/** One witness cosignature as served by `?witnesses=1`: it is over the head
 * it is attached to, so the head's own fields are not repeated. */
export interface WitnessCosignatureWire {
  // Lowercase hex Ed25519 public key of the witness.
  witness_key_id: string
  // RFC 3339.
  observed_at: string
  // Lowercase hex Ed25519 signature (64 bytes).
  signature: string
}

/** `GET /ledger/sth/latest?witnesses=1` (or `/ledger/sth/{n}`): the signed tree head plus its cosignatures. */
export interface CosignedTreeHeadResponse extends SignedTreeHeadResponse {
  cosignatures: WitnessCosignatureWire[]
}

/** A cosignature bound to the exact head fields it covers. */
export interface WitnessCosignature {
  tree_size: number
  root_hash: string
  network_id: string
  // RFC 3339; the author's own head timestamp.
  author_created_at: string
  // Lowercase hex Ed25519 public key of the witness.
  witness_key_id: string
  // RFC 3339.
  observed_at: string
  // Lowercase hex Ed25519 signature (64 bytes).
  signature: string
}

/** An author-signed tree head with the cosignatures backing it. */
export interface CosignedTreeHead {
  sth: SignedTreeHeadResponse
  cosignatures: WitnessCosignature[]
}

/** A witness the verifier trusts, chosen by the verifier and never taken from the node being checked. */
export interface KnownWitness {
  witnessKeyId: string
  // Lowercase hex Ed25519 public key (32 bytes).
  key: string
  /** The address the witness advertised, set for witnesses found through discovery. */
  baseUrl?: string
}

/** `GET /nodes/status`'s wire response — matches
 * `crates/server/src/nodes.rs::NodeStatusResponse`. Only the fields this
 * SDK consumes; the real response also carries `resources` and
 * `own_shard_replication`, omitted here since nothing in this SDK reads
 * them. */
export interface NodeStatusResponse {
  protocol_version: string
  network_id: string
  roles: string[]
  stale: boolean
  newest_known_peer_version: string | null
}
