// Device-registration / linked-device grant model and
// cross-device pairing approval on AccountSession —
// identity_signing_keys rows (event-authorship keys), distinct from
// passkeys.ts (WebAuthn login credentials). See
// crates/server/src/devices.rs/device_pairing.rs.
import { AccountSession } from './core.js'
import { isAcceptableShardKey } from '../network/strictEd25519.js'
import { decodePublicKey, deviceGrantApprovalSigningBytes, signingKeyRevokedSigningBytes } from '../crypto/signing.js'
import { parseHash } from '../ledgerEntry.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { ConflictError, IdentityChainPositionStaleError, NoLocalSigningKeyError, ProtocolError } from '../errors.js'
import type { components } from '../generated.js'

export interface Device {
  id: string
  label: string | null
  publicKey: string
  addedAt: string
  revokedAt: string | null
}

type StaleBody = components['schemas']['ChainPositionStaleBody']

interface ChainPosition {
  seq: number
  prevHash: Uint8Array | null
}

// No route reports the chain head, so the first attempt assumes an empty chain and a 409 carries the real head.
const EMPTY_CHAIN: ChainPosition = { seq: 1, prevHash: null }

function staleHead(error: unknown): StaleBody | undefined {
  if (!(error instanceof ConflictError) || error.code !== 'IDENTITY_CHAIN_POSITION_STALE') return undefined
  const body = error.body as Partial<StaleBody> | undefined
  if (!body || !Number.isSafeInteger(body.head_seq) || (body.head_seq as number) < 0) {
    throw new ProtocolError('IDENTITY_CHAIN_POSITION_STALE carried no valid head_seq')
  }
  return body as StaleBody
}

/** Runs `send` (which signs and posts the event) at `EMPTY_CHAIN`; on a stale-position 409 re-signs once at the returned
 * head and retries, then throws `IdentityChainPositionStaleError` if the chain moved again. */
async function submitChainedEvent<T>(send: (position: ChainPosition) => Promise<T>): Promise<T> {
  let position = EMPTY_CHAIN
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await send(position)
    } catch (error) {
      const head = staleHead(error)
      if (!head) throw error
      const prevHash = head.head_hash ? parseHash('head_hash', head.head_hash) : null
      if (attempt > 0) throw new IdentityChainPositionStaleError(head.head_seq, head.head_hash ?? null)
      position = { seq: head.head_seq + 1, prevHash }
    }
  }
}

function prevHashWire(prevHash: Uint8Array | null): string | null {
  return prevHash === null ? null : bytesToHex(prevHash)
}

type DeviceWire = components['schemas']['DeviceResponse']

function fromWire(w: DeviceWire): Device {
  return {
    id: w.id,
    label: w.label ?? null,
    publicKey: w.public_key,
    addedAt: w.added_at,
    revokedAt: w.revoked_at ?? null,
  }
}

export interface DeviceGrant {
  id: string
  status: string
  deviceLabel: string | null
  requestedSigningPublicKey: string
  requestedAt: string
  expiresAt: string
}

type DeviceGrantWire = components['schemas']['DeviceGrantResponse']

function grantFromWire(w: DeviceGrantWire): DeviceGrant {
  return {
    id: w.id,
    status: w.status,
    deviceLabel: w.device_label ?? null,
    requestedSigningPublicKey: w.requested_signing_public_key,
    requestedAt: w.requested_at,
    expiresAt: w.expires_at,
  }
}

declare module './core.js' {
  interface AccountSession {
    /** `GET /me/devices` — every signing-key device registered to this
     * identity, active and revoked alike. */
    listDevices(): Promise<Device[]>
    /** `PATCH /me/devices/{signingKeyId}` — relabels a device. Not
     * signature-required. */
    renameDevice(signingKeyId: string, label: string): Promise<Device>
    /** `POST /me/devices/{signingKeyId}/revoke`, signed by this session's own key at the identity chain
     * position the event will occupy; on a stale position it re-signs once at the head the server returns.
     * Throws `IdentityChainPositionStaleError` if the chain moves again. */
    revokeDevice(signingKeyId: string): Promise<void>
    /** `POST /me/devices/grants` — requests a new device's signing key be
     * added, from the requesting device's own (as-yet unsigned) session. */
    requestDeviceGrant(requestedSigningPublicKeyB64: string, deviceLabel?: string): Promise<DeviceGrant>
    /** `GET /me/devices/grants[?status=]`. */
    listDeviceGrants(status?: string): Promise<DeviceGrant[]>
    /** `GET /me/devices/grants/{id}`. */
    getDeviceGrant(grantId: string): Promise<DeviceGrant>
    /** `POST /me/devices/grants/{id}/approve`, signed by this session's own key at the identity chain
     * position the event will occupy (re-signed once on a stale position, as for `revokeDevice`).
     * Throws `NoLocalSigningKeyError` without a local key. */
    approveDeviceGrant(grantId: string, requestedSigningPublicKeyB64: string): Promise<Device>
    /** `POST /auth/device/approve` — approves a cross-device
     * pairing request by `userCode`, always signed
     * (`device_pairing.approve`, `[identityId, userCode]`). */
    approveDevicePairing(userCode: string): Promise<string>
    /** `POST /auth/device/deny` — declines a pairing request. Not
     * signature-required. */
    denyDevicePairing(userCode: string): Promise<string>
  }
}

AccountSession.prototype.listDevices = async function (this: AccountSession): Promise<Device[]> {
  const wire = await this.get<DeviceWire[]>('/me/devices')
  return wire.map(fromWire)
}

AccountSession.prototype.renameDevice = async function (
  this: AccountSession,
  signingKeyId: string,
  label: string,
): Promise<Device> {
  const wire = await this.patch<DeviceWire>(`/me/devices/${signingKeyId}`, {
    label,
  })
  return fromWire(wire)
}

AccountSession.prototype.revokeDevice = async function (this: AccountSession, signingKeyId: string): Promise<void> {
  const revokerKeyId = this.signingKeyId()
  if (!revokerKeyId) {
    throw new NoLocalSigningKeyError('revokeDevice')
  }
  const identityId = this.identity().id
  await submitChainedEvent(({ seq, prevHash }) =>
    this.postNoResponse(`/me/devices/${signingKeyId}/revoke`, {
      revoked_by_signing_key_id: revokerKeyId,
      seq,
      prev_hash: prevHashWire(prevHash),
      signature: this.signRaw(signingKeyRevokedSigningBytes(identityId, signingKeyId, revokerKeyId, seq, prevHash)),
    }),
  )
}

AccountSession.prototype.requestDeviceGrant = async function (
  this: AccountSession,
  requestedSigningPublicKeyB64: string,
  deviceLabel?: string,
): Promise<DeviceGrant> {
  const wire = await this.post<DeviceGrantWire>('/me/devices/grants', {
    requested_signing_public_key: requestedSigningPublicKeyB64,
    device_label: deviceLabel ?? null,
  })
  return grantFromWire(wire)
}

AccountSession.prototype.listDeviceGrants = async function (
  this: AccountSession,
  status?: string,
): Promise<DeviceGrant[]> {
  const wire = status
    ? await this.getQuery<DeviceGrantWire[]>('/me/devices/grants', { status })
    : await this.get<DeviceGrantWire[]>('/me/devices/grants')
  return wire.map(grantFromWire)
}

AccountSession.prototype.getDeviceGrant = async function (this: AccountSession, grantId: string): Promise<DeviceGrant> {
  const wire = await this.get<DeviceGrantWire>(`/me/devices/grants/${grantId}`)
  return grantFromWire(wire)
}

AccountSession.prototype.approveDeviceGrant = async function (
  this: AccountSession,
  grantId: string,
  requestedSigningPublicKeyB64: string,
): Promise<Device> {
  const approverKeyId = this.signingKeyId()
  if (!approverKeyId) {
    throw new NoLocalSigningKeyError('approveDeviceGrant')
  }
  const requestedKey = decodePublicKey(requestedSigningPublicKeyB64)
  if (!isAcceptableShardKey(requestedKey)) {
    throw new TypeError('the requested key is not an acceptable Ed25519 key')
  }
  const identityId = this.identity().id
  const wire = await submitChainedEvent(({ seq, prevHash }) =>
    this.post<DeviceWire>(`/me/devices/grants/${grantId}/approve`, {
      approver_signing_key_id: approverKeyId,
      seq,
      prev_hash: prevHashWire(prevHash),
      signature: this.signRaw(
        deviceGrantApprovalSigningBytes(grantId, identityId, approverKeyId, requestedKey, seq, prevHash),
      ),
    }),
  )
  return fromWire(wire)
}

AccountSession.prototype.approveDevicePairing = async function (
  this: AccountSession,
  userCode: string,
): Promise<string> {
  const signature = this.sign('device_pairing.approve', [this.identity().id, userCode])
  const response = await this.post<components['schemas']['ResolvePairingResponse']>('/auth/device/approve', {
    user_code: userCode,
    ...signature,
  })
  return response.status
}

AccountSession.prototype.denyDevicePairing = async function (this: AccountSession, userCode: string): Promise<string> {
  const response = await this.post<components['schemas']['ResolvePairingResponse']>('/auth/device/deny', {
    user_code: userCode,
  })
  return response.status
}
