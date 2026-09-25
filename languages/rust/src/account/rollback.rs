//! Post-compromise rollback on [`super::AccountSession`]: list the events
//! authored inside a compromise window and append signed compensating
//! events for the reversible ones. Available only after a social recovery
//! has completed.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::SdkError;

use super::AccountSession;

/// One event that a rollback could touch.
#[derive(Debug, Clone)]
pub struct RollbackCandidate {
    /// The original event's id; pass to
    /// [`AccountSession::reverse_rollback_event`].
    pub event_id: Uuid,
    /// The event's kind (e.g. `guild.created`).
    pub kind: String,
    /// When the event occurred.
    pub occurred_at: OffsetDateTime,
    /// Human-readable description of the event.
    pub summary: String,
    /// Whether a compensating event can be appended for this event.
    pub reversible: bool,
    /// Why the event cannot be reversed; `None` when `reversible`.
    pub reason: Option<String>,
    /// Whether a compensating event already exists for this event.
    pub already_reversed: bool,
}

/// The result of [`AccountSession::rollback_candidates`].
#[derive(Debug, Clone)]
pub struct RollbackCandidates {
    /// The completed recovery request that bounds the window's upper end.
    pub recovery_request_id: Uuid,
    /// When that recovery completed.
    pub recovery_completed_at: OffsetDateTime,
    /// Events authored in `[since, recovery_completed_at)`.
    pub candidates: Vec<RollbackCandidate>,
}

impl TryFrom<crate::generated::RollbackCandidate> for RollbackCandidate {
    type Error = SdkError;

    fn try_from(body: crate::generated::RollbackCandidate) -> Result<Self, SdkError> {
        Ok(RollbackCandidate {
            event_id: body.event_id,
            kind: body.kind,
            occurred_at: super::parse_rfc3339(&body.occurred_at)?,
            summary: body.summary,
            reversible: body.reversible,
            reason: body.reason,
            already_reversed: body.already_reversed,
        })
    }
}

impl AccountSession {
    /// `GET /me/rollback/candidates?since=` — events this identity authored
    /// between `since` (when the owner believes the compromise began) and
    /// its latest completed recovery, each marked reversible or not.
    ///
    /// Fails with [`SdkError::Conflict`] (`ROLLBACK_NO_COMPLETED_RECOVERY`)
    /// when the identity has no completed recovery, and
    /// [`SdkError::Rejected`] (`INVALID_ROLLBACK_WINDOW`) when `since` is
    /// not a valid window start.
    pub async fn rollback_candidates(
        &self,
        since: OffsetDateTime,
    ) -> Result<RollbackCandidates, SdkError> {
        let since = super::format_rfc3339(since)?;
        let raw: crate::generated::RollbackCandidatesResponse = self
            .get_query(
                crate::generated::paths::devices::LIST_ROLLBACK_CANDIDATES,
                &[("since", &since)],
            )
            .await?;
        Ok(RollbackCandidates {
            recovery_request_id: raw.recovery_request_id,
            recovery_completed_at: super::parse_rfc3339(&raw.recovery_completed_at)?,
            candidates: raw
                .candidates
                .into_iter()
                .map(RollbackCandidate::try_from)
                .collect::<Result<_, _>>()?,
        })
    }

    /// `POST /me/rollback/{event_id}/reverse` — appends the compensating
    /// event for one eligible, reversible candidate and returns its id.
    /// Always signs (`rollback.reverse`, `[event_id, identity_id, since]`);
    /// `since` must be the same value passed to
    /// [`AccountSession::rollback_candidates`].
    ///
    /// Errors: [`SdkError::NotFound`] (`ROLLBACK_EVENT_NOT_ELIGIBLE`),
    /// [`SdkError::Conflict`] (`ROLLBACK_NOT_REVERSIBLE`,
    /// `ROLLBACK_ALREADY_REVERSED`, `ROLLBACK_NO_COMPLETED_RECOVERY`),
    /// [`SdkError::Rejected`] (`INVALID_ROLLBACK_WINDOW`).
    pub async fn reverse_rollback_event(
        &self,
        event_id: Uuid,
        since: OffsetDateTime,
    ) -> Result<Uuid, SdkError> {
        let since = super::format_rfc3339(since)?;
        let signature = self.sign(
            "rollback.reverse",
            &[
                &event_id.to_string(),
                &self.identity().id.0.to_string(),
                &since,
            ],
        );
        let raw: crate::generated::ReverseEventResponse = self
            .post(
                &super::path(
                    crate::generated::paths::devices::REVERSE_EVENT,
                    &[("event_id", &event_id.to_string())],
                ),
                &crate::generated::ReverseEventRequest {
                    since,
                    signature: signature.signature,
                    signing_key_id: signature.signing_key_id,
                },
            )
            .await?;
        Ok(raw.reversal_event_id)
    }
}
