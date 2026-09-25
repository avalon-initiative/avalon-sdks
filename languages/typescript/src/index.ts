// TypeScript reference SDK for Avalon Protocol. Self-contained: no
// dependency on avalon-protocol's own apps/packages workspace. See
// avalon-protocol's docs/projects/sdks/architecture/sdk.md for the full
// surface.
export { AvalonClient } from './client.js'
export type { AvalonClientConfig } from './client.js'

export { AccountSession, AccountDeviceLogin } from './accountSession/index.js'
export type {
  AccountCredentials,
  AccountSigningKey,
  ProfileUpdate,
  Passkey,
  Device,
  DeviceGrant,
  GuardianSettings,
  RollbackCandidate,
  RollbackCandidates,
  RecoveryRequest,
  GuardianRequest,
  GuardianOf,
  PresenceStatus,
  Friendship,
  FriendRequest,
  Block,
  PublicProfile,
  DiscoveryCandidate,
  SearchResultIdentity,
  Presence,
  HistoryEntry,
  PublicIdentityProfile,
  GuildAnnouncementAlert,
  Conversation,
  ConversationMessage,
  IntegratorConnection,
  ConnectionGrant,
  MyConnection,
  Guild,
  GuildLink,
  DiscoverGuildSummary,
  DiscoverGuildsPage,
  FavoriteGameEntry,
  FavoriteGames,
  Role,
  RoleBadge,
  RoleBadgeUpdate,
  PermissionOverride,
  GuildMember,
  MyGuildMembership,
  GuildInvite,
  MyGuildInvite,
  GuildJoinRequest,
  GuildChannel,
  GuildMessage,
  RsvpCounts,
  GuildEvent,
  RsvpStatus,
  Rsvp,
  RsvpRosterEntry,
  GuildUpdate,
  ChannelUpdate,
  EventFields,
  PresenceStatusWire,
  PresenceUpdate,
  PresenceSubscription,
  ChannelMessageUpdate,
  ConversationMessageUpdate,
  RealtimeSubscription,
  GameBreakdown,
  GameBreakdownEntry,
  ArchivedMessage,
  AttestationProof,
  AttestationAuthenticity,
  AttestationValidity,
  AttestationHistoryEntry,
  Attestation,
} from './accountSession/index.js'

export { IntegratorSession } from './integratorSession.js'
export type {
  Capability,
  Friend,
  GuildMembership,
  ConversationSummary,
  VerifiedAttestation,
  Attestation as IssuedAttestation,
  BulkClaimOutcome,
  BulkClaimInput,
} from './integratorSession.js'

export type { Identity, Profile, Genre, SignedTreeHeadResponse, NodeStatusResponse } from './types.js'

// Issue #735: the info.version of the openapi.json schema this build's
// generated types were built from, so a caller can report/log which
// schema version this SDK build targets.
export { OPENAPI_SCHEMA_VERSION } from './generated.js'

export { getLatestSth } from './ledger.js'
export { getNodeStatus } from './nodeStatus.js'
export { getTopology, probeNode, traceRoute } from './nodeTopology.js'
export {
  walkTopology,
  normalizeNodeUrl,
  WALK_DEFAULT_MAX_NODES,
  WALK_DEFAULT_MAX_DEPTH,
  WALK_DEFAULT_CONCURRENCY,
  WALK_DEFAULT_REQUEST_TIMEOUT_MS,
  WALK_DEFAULT_MAX_RETRY_AFTER_MS,
} from './topologyWalk.js'
export type {
  WalkOptions,
  WalkEvent,
  WalkEdge,
  WalkEdgeKind,
  WalkNode,
  WalkNodeStatus,
  WalkFailure,
  WalkFailureReason,
  TopologyGraph,
} from './topologyWalk.js'
export type {
  Topology,
  Neighbor,
  KnownPeer,
  MirrorSource,
  NetworkCoordinate,
  ObservedLatency,
  ProbeResult,
  TraceResult,
  TraceHop,
  TraceStopReason,
} from './nodeTopology.js'

export {
  fetchTrustAnchors,
  TRUST_ANCHORS_URL,
  verifyTreeHead,
  evaluateNetworkTrust,
  fetchNetworkTrustStatus,
  checkTargetNetwork,
  NetworkTargetMismatchError,
  discover,
  discoverAmong,
  DiscoveryFailedError,
} from './network/index.js'
export type {
  TrustAnchorEntry,
  NetworkTrustStatus,
  TargetNetwork,
  TargetNetworkTier,
  NetworkTargetError,
  DiscoveryError,
  DiscoverOptions,
  DiscoverResult,
  VerifiedCandidate,
} from './network/index.js'

export {
  listAchievementDefinitions,
  listMilestoneDefinitions,
  getIntegrator,
  listIntegrators,
  getIntegratorRegistry,
  listIssuerKeys,
  getAttestation,
  listSchemaVersions,
  getSchemaVersion,
  listMappings,
  getMapping,
  listRecognitions,
  listRecognizedBy,
} from './integratorDirectory.js'
export type {
  IntegratorCategory,
  AchievementDefinition,
  Integrator,
  IntegratorSummary,
  IntegratorsPage,
  RegistryMetric,
  IntegratorRegistry,
  IssuerKey,
  AttestationDetail,
  SchemaVersion,
  SchemaMapping,
  Recognition,
} from './integratorDirectory.js'

export { getIdentityIntegratorData, getLocations } from './identityData.js'
export type { VisibleIntegratorDataInstance } from './identityData.js'

export {
  startRecoveryRequest,
  finishRecoveryRequest,
  getRecoveryRequest,
  finalizeRecoveryRequest,
  getIdentityRecoveryStatus,
} from './recovery.js'
export type { StartRecoveryRequest, RecoveryStartResult, FinishRecoveryRequest } from './recovery.js'

export {
  lookupCrossNodeLogin,
  denyCrossNodeLogin,
  submitCrossNodeLoginGrant,
  startCrossNodeLogin,
  pollCrossNodeLogin,
} from './crossNodeLogin.js'
export type { CrossNodeLoginLookup, CrossNodeLoginStart, CrossNodeLoginPoll } from './crossNodeLogin.js'
export { mintCrossNodeLoginGrant } from './crypto/crossNodeLogin.js'
export type { CrossNodeLoginGrant } from './crypto/crossNodeLogin.js'

export {
  registerIntegrator,
  integratorWhoami,
  addIssuerKey,
  revokeIssuerKey,
  createAchievementDefinition,
  updateAchievementDefinition,
  createMilestoneDefinition,
  updateMilestoneDefinition,
  publishSchemaVersion,
  publishMapping,
  publishInstance,
  deleteInstance,
  publishRecognition,
  revokeRecognition,
  revokeAttestation,
  createRegistrationChallenge,
  registerIssuer,
} from './integratorAccount.js'
export type {
  RegisterIntegratorInput,
  RegisteredIntegrator,
  IssuerKeyDetail,
  AchievementDefinitionDetail,
  CreateClaimDefinitionInput,
  UpdateClaimDefinitionInput,
  PublishSchemaVersionInput,
  PublishMappingInput,
  RevokeAttestationResult,
  IssuerRegistration,
} from './integratorAccount.js'

export * from './errors.js'

export {
  canonicalMessage,
  generateSigningKey,
  publicKeyFromSecretKey,
  sign,
  verify,
  bytesToBase64,
  base64ToBytes,
} from './crypto/signing.js'
export type { SigningKeyPair, SignatureFields } from './crypto/signing.js'

export { runRegistrationCeremony, runAuthenticationCeremony } from './crypto/webauthn.js'

export {
  deriveSigningKeyFromMnemonic,
  generateMnemonicSigningKey,
  isValidMnemonic,
} from './crypto/mnemonic.js'
export type { GeneratedSigningKey } from './crypto/mnemonic.js'
