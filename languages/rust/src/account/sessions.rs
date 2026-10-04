//! The caller's own login sessions on [`super::AccountSession`]: list them, end one, or end
//! the one in use.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::SdkError;

use super::AccountSession;

/// One of this identity's live sessions.
#[derive(Debug, Clone)]
pub struct SessionSummary {
    /// The session's id; pass to [`AccountSession::revoke_session`].
    pub id: Uuid,
    /// When the session was created.
    pub created_at: OffsetDateTime,
    /// When the session expires if never ended.
    pub expires_at: OffsetDateTime,
    /// Whether this is the session the listing request authenticated with.
    pub current: bool,
    /// The passkey that produced this session, when it came from a passkey login.
    pub origin_passkey_id: Option<Uuid>,
    /// The signing key that approved this session, when it came from device pairing or a
    /// cross-node login.
    pub origin_signing_key_id: Option<Uuid>,
}

impl TryFrom<crate::generated::SessionSummary> for SessionSummary {
    type Error = SdkError;

    fn try_from(body: crate::generated::SessionSummary) -> Result<Self, SdkError> {
        Ok(SessionSummary {
            id: body.id,
            created_at: super::parse_rfc3339(&body.created_at)?,
            expires_at: super::parse_rfc3339(&body.expires_at)?,
            current: body.current,
            origin_passkey_id: body.origin_passkey_id,
            origin_signing_key_id: body.origin_signing_key_id,
        })
    }
}

impl AccountSession {
    /// `GET /me/sessions` — this identity's live sessions, newest first; the one this request
    /// used has `current` set.
    pub async fn list_sessions(&self) -> Result<Vec<SessionSummary>, SdkError> {
        let raw: crate::generated::ListSessionsResponse = self
            .get(crate::generated::paths::identity::LIST_SESSIONS)
            .await?;
        raw.sessions
            .into_iter()
            .map(SessionSummary::try_from)
            .collect()
    }

    /// `POST /me/sessions/{id}/revoke` — ends one of this identity's own sessions. Any other
    /// session id is refused with a 404 (`SESSION_NOT_FOUND`).
    pub async fn revoke_session(&self, session_id: Uuid) -> Result<(), SdkError> {
        self.post_empty_no_response(&super::path(
            crate::generated::paths::identity::REVOKE_SESSION,
            &[("id", &session_id.to_string())],
        ))
        .await
    }

    /// `POST /sessions/logout` — ends the session this `AccountSession` authenticates with;
    /// the token is unusable afterwards.
    pub async fn logout(&self) -> Result<(), SdkError> {
        self.post_empty_no_response(crate::generated::paths::identity::LOGOUT)
            .await
    }
}
