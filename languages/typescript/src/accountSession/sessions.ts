// The caller's own login sessions on AccountSession: list them, end one, or end the one in use.
import { AccountSession } from './core.js'
import type { components } from '../generated.js'

export interface SessionSummary {
  id: string
  createdAt: string
  expiresAt: string
  /** Whether this is the session the listing request authenticated with. */
  current: boolean
  /** The passkey that produced this session, when it came from a passkey login. */
  originPasskeyId: string | null
  /** The signing key that approved this session, when it came from device pairing or a cross-node login. */
  originSigningKeyId: string | null
}

type SessionSummaryWire = components['schemas']['SessionSummary']

function fromWire(w: SessionSummaryWire): SessionSummary {
  return {
    id: w.id,
    createdAt: w.created_at,
    expiresAt: w.expires_at,
    current: w.current,
    originPasskeyId: w.origin_passkey_id ?? null,
    originSigningKeyId: w.origin_signing_key_id ?? null,
  }
}

declare module './core.js' {
  interface AccountSession {
    /** `GET /me/sessions` — this identity's live sessions, newest first; the one this request used has
     * `current` set. */
    listSessions(): Promise<SessionSummary[]>
    /** `POST /me/sessions/{id}/revoke` — ends one of this identity's own sessions. Any other session id is
     * refused with a 404 (`SESSION_NOT_FOUND`). */
    revokeSession(sessionId: string): Promise<void>
    /** `POST /sessions/logout` — ends the session this `AccountSession` authenticates with; the token is
     * unusable afterwards. */
    logout(): Promise<void>
  }
}

AccountSession.prototype.listSessions = async function (this: AccountSession): Promise<SessionSummary[]> {
  const wire = await this.get<components['schemas']['ListSessionsResponse']>('/me/sessions')
  return wire.sessions.map(fromWire)
}

AccountSession.prototype.revokeSession = async function (this: AccountSession, sessionId: string): Promise<void> {
  await this.postEmptyNoResponse(`/me/sessions/${sessionId}/revoke`)
}

AccountSession.prototype.logout = async function (this: AccountSession): Promise<void> {
  await this.postEmptyNoResponse('/sessions/logout')
}
