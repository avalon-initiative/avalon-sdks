// Post-compromise rollback on AccountSession — lists the events authored
// inside a compromise window and appends signed compensating events.
import { AccountSession } from './core.js'
import type { components } from '../generated.js'

export interface RollbackCandidate {
  eventId: string
  kind: string
  occurredAt: string
  summary: string
  reversible: boolean
  /** Why the event cannot be reversed; `null` when reversible. */
  reason: string | null
  alreadyReversed: boolean
}

export interface RollbackCandidates {
  recoveryRequestId: string
  recoveryCompletedAt: string
  candidates: RollbackCandidate[]
}

type RollbackCandidatesWire = components['schemas']['RollbackCandidatesResponse']
type ReverseEventRequestWire = components['schemas']['ReverseEventRequest']
type ReverseEventResponseWire = components['schemas']['ReverseEventResponse']

declare module './core.js' {
  interface AccountSession {
    /** `GET /me/rollback/candidates?since=` — `since` is an RFC 3339
     * timestamp. Requires a completed recovery; otherwise throws a
     * `ConflictError` (`ROLLBACK_NO_COMPLETED_RECOVERY`) or, for a bad
     * window, a `RejectedError` (`INVALID_ROLLBACK_WINDOW`). */
    rollbackCandidates(since: string): Promise<RollbackCandidates>
    /** `POST /me/rollback/{eventId}/reverse` — always signs
     * (`rollback.reverse`, `[eventId, identityId, since]`), with `since`
     * exactly as sent. Returns the compensating event's id. */
    reverseRollbackEvent(eventId: string, since: string): Promise<string>
  }
}

AccountSession.prototype.rollbackCandidates = async function (
  this: AccountSession,
  since: string,
): Promise<RollbackCandidates> {
  const w = await this.getQuery<RollbackCandidatesWire>('/me/rollback/candidates', { since })
  return {
    recoveryRequestId: w.recovery_request_id,
    recoveryCompletedAt: w.recovery_completed_at,
    candidates: w.candidates.map((c) => ({
      eventId: c.event_id,
      kind: c.kind,
      occurredAt: c.occurred_at,
      summary: c.summary,
      reversible: c.reversible,
      reason: c.reason ?? null,
      alreadyReversed: c.already_reversed,
    })),
  }
}

AccountSession.prototype.reverseRollbackEvent = async function (
  this: AccountSession,
  eventId: string,
  since: string,
): Promise<string> {
  const signature = this.sign('rollback.reverse', [eventId, this.identity().id, since])
  const body: ReverseEventRequestWire = { since, ...signature }
  const w = await this.post<ReverseEventResponseWire>(`/me/rollback/${eventId}/reverse`, body)
  return w.reversal_event_id
}
