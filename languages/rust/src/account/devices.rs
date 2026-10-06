//! Device-registration / linked-device grant model (issue #135) and
//! cross-device pairing approval (issue #307/#704) on
//! [`super::AccountSession`] — `identity_signing_keys` rows (event-authorship
//! keys), distinct from `passkeys` (WebAuthn login credentials). See
//! `crates/server/src/devices.rs`/`device_pairing.rs`.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::SdkError;

use super::AccountSession;

/// Where the next identity-chain event goes: the head's `seq` plus one and the head's event hash.
#[derive(Clone, Copy)]
struct ChainPosition {
    seq: u64,
    prev_hash: Option<[u8; 32]>,
}

impl ChainPosition {
    /// The first event of a chain with no events yet, where the first attempt signs.
    const NEW_CHAIN: Self = Self {
        seq: 1,
        prev_hash: None,
    };

    /// The wire `seq`; a position is at most `i64::MAX` because it comes from an `i64` head plus one.
    fn seq_wire(&self) -> i64 {
        i64::try_from(self.seq).expect("chain seq fits the wire's i64")
    }

    fn prev_hash_hex(&self) -> Option<String> {
        self.prev_hash.as_ref().map(hex::encode)
    }

    /// The position after the head a 409 `IDENTITY_CHAIN_POSITION_STALE` reports.
    fn after(head: crate::generated::ChainPositionStaleBody) -> Result<Self, SdkError> {
        let bad_head =
            || SdkError::Protocol("the server returned an invalid chain head".to_string());
        let prev_hash = match head.head_hash {
            Some(text) => {
                Some(crate::ledger_entry::parse_hash("head_hash", &text).map_err(|_| bad_head())?)
            }
            None => None,
        };
        Ok(Self {
            seq: u64::try_from(head.head_seq.checked_add(1).ok_or_else(bad_head)?)
                .map_err(|_| bad_head())?,
            prev_hash,
        })
    }
}

/// One of this identity's registered signing-key devices.
#[derive(Debug, Clone)]
pub struct Device {
    /// The `identity_signing_keys.id` this device is stored under — the
    /// value a signature-required action's `signing_key_id` field names.
    pub id: Uuid,
    /// User-chosen label, if any.
    pub label: Option<String>,
    /// Base64-encoded raw Ed25519 public key.
    pub public_key: String,
    /// When this device's key was registered.
    pub added_at: OffsetDateTime,
    /// `None` while active; set once revoked.
    pub revoked_at: Option<OffsetDateTime>,
}

impl TryFrom<crate::generated::DeviceResponse> for Device {
    type Error = SdkError;

    fn try_from(body: crate::generated::DeviceResponse) -> Result<Self, SdkError> {
        Ok(Device {
            id: body.id,
            label: body.label,
            public_key: body.public_key,
            added_at: super::parse_rfc3339(&body.added_at)?,
            revoked_at: body
                .revoked_at
                .as_deref()
                .map(super::parse_rfc3339)
                .transpose()?,
        })
    }
}

/// A pending or resolved request to add a new device's signing key —
/// `POST /me/devices/grants`.
#[derive(Debug, Clone)]
pub struct DeviceGrant {
    /// This grant's own id.
    pub id: Uuid,
    /// `"pending"`, `"approved"`, `"denied"`, or `"expired"` —
    /// `crates/server/src/devices.rs`'s own stable vocabulary, not
    /// re-modeled as an enum here (see that module for the authoritative
    /// list).
    pub status: String,
    /// The requesting device's own chosen label, if any.
    pub device_label: Option<String>,
    /// Base64-encoded — the exact bytes an approving device must include
    /// in what it signs (see [`AccountSession::approve_device_grant`]).
    pub requested_signing_public_key: String,
    /// When this grant was requested.
    pub requested_at: OffsetDateTime,
    /// When this grant expires if never approved/denied.
    pub expires_at: OffsetDateTime,
}

impl TryFrom<crate::generated::DeviceGrantResponse> for DeviceGrant {
    type Error = SdkError;

    fn try_from(body: crate::generated::DeviceGrantResponse) -> Result<Self, SdkError> {
        Ok(DeviceGrant {
            id: body.id,
            status: body.status,
            device_label: body.device_label,
            requested_signing_public_key: body.requested_signing_public_key,
            requested_at: super::parse_rfc3339(&body.requested_at)?,
            expires_at: super::parse_rfc3339(&body.expires_at)?,
        })
    }
}

/// Strictly decodes a standard-base64 32-byte Ed25519 public key.
fn decode_public_key(public_key_b64: &str) -> Result<[u8; 32], SdkError> {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    BASE64
        .decode(public_key_b64)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            SdkError::Protocol("public key must be standard base64 of exactly 32 bytes".to_string())
        })
}

/// The typed 409 body when it is an `IDENTITY_CHAIN_POSITION_STALE`.
fn stale_head(body: &[u8]) -> Option<crate::generated::ChainPositionStaleBody> {
    let head: crate::generated::ChainPositionStaleBody = serde_json::from_slice(body).ok()?;
    (head.code == "IDENTITY_CHAIN_POSITION_STALE").then_some(head)
}

/// The `code` (else `error`) of a generic error body, like the rest of the SDK's error mapping.
fn conflict_message(body: &[u8]) -> String {
    let value: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    ["code", "error"]
        .iter()
        .find_map(|k| value[*k].as_str())
        .unwrap_or("409 Conflict")
        .to_string()
}

impl AccountSession {
    /// Posts a key event signed at a chain position. Starts at a new chain; on a stale-position 409
    /// re-signs once at the returned head, then fails if the head moved again.
    async fn post_chain_event<B: serde::Serialize>(
        &self,
        path: &str,
        body_at: impl Fn(ChainPosition) -> B,
    ) -> Result<reqwest::Response, SdkError> {
        let mut position = ChainPosition::NEW_CHAIN;
        for attempt in 0..2 {
            let body = body_at(position);
            let response = crate::http::send(&self.http, &self.retry, false, |c| {
                c.post(self.url(path)).bearer_auth(&self.token).json(&body)
            })
            .await?;
            if response.status().is_success() {
                return Ok(response);
            }
            if response.status() != reqwest::StatusCode::CONFLICT {
                return Err(crate::http::map_error_response(response).await);
            }
            let bytes = response
                .bytes()
                .await
                .map_err(|e| SdkError::Protocol(e.to_string()))?;
            let Some(head) = stale_head(&bytes) else {
                return Err(SdkError::Conflict(conflict_message(&bytes)));
            };
            if attempt == 1 {
                return Err(SdkError::Conflict(
                    "IDENTITY_CHAIN_POSITION_STALE: the identity chain head moved again after re-signing; retry"
                        .to_string(),
                ));
            }
            position = ChainPosition::after(head)?;
        }
        unreachable!("the loop returns on both attempts")
    }

    /// `GET /me/devices` — every signing-key device registered to this
    /// identity, active and revoked alike.
    pub async fn list_devices(&self) -> Result<Vec<Device>, SdkError> {
        let raw: Vec<crate::generated::DeviceResponse> = self
            .get(crate::generated::paths::devices::LIST_DEVICES)
            .await?;
        raw.into_iter().map(Device::try_from).collect()
    }

    /// `PATCH /me/devices/{signing_key_id}` — relabels a device. Not
    /// signature-required.
    pub async fn rename_device(
        &self,
        signing_key_id: Uuid,
        label: &str,
    ) -> Result<Device, SdkError> {
        let raw: crate::generated::DeviceResponse = self
            .patch(
                &super::path(
                    crate::generated::paths::devices::RENAME_DEVICE,
                    &[("id", &signing_key_id.to_string())],
                ),
                &crate::generated::RenameDeviceRequest {
                    label: label.to_string(),
                },
            )
            .await?;
        raw.try_into()
    }

    /// `POST /me/devices/{signing_key_id}/revoke`, signed at the identity chain's next position.
    pub async fn revoke_device(&self, signing_key_id: Uuid) -> Result<(), SdkError> {
        let revoker = self.signing_key_id().ok_or_else(|| {
            SdkError::Protocol(
                "revoke_device requires a local signing key — this AccountSession has none"
                    .to_string(),
            )
        })?;
        let identity_id = self.identity().id.clone();
        self.post_chain_event(
            &super::path(
                crate::generated::paths::devices::REVOKE_DEVICE,
                &[("id", &signing_key_id.to_string())],
            ),
            |position| crate::generated::RevokeDeviceRequest {
                revoked_by_signing_key_id: revoker,
                seq: position.seq_wire(),
                prev_hash: position.prev_hash_hex(),
                signature: self.sign_raw(
                    &crate::identity_signing::signing_key_revoked_signing_bytes(
                        &identity_id,
                        signing_key_id,
                        revoker,
                        position.seq,
                        position.prev_hash.as_ref(),
                    ),
                ),
            },
        )
        .await?;
        Ok(())
    }

    /// `POST /me/devices/grants` — requests a new device's signing key be
    /// added, from the *requesting* device's own session (which has no
    /// signing key of its own yet — that's the whole point). Requesting
    /// confers no access by itself; see
    /// [`AccountSession::approve_device_grant`].
    pub async fn request_device_grant(
        &self,
        requested_signing_public_key_b64: &str,
        device_label: Option<&str>,
    ) -> Result<DeviceGrant, SdkError> {
        let raw: crate::generated::DeviceGrantResponse = self
            .post(
                crate::generated::paths::devices::REQUEST_DEVICE_GRANT,
                &crate::generated::RequestDeviceGrantRequest {
                    requested_signing_public_key: requested_signing_public_key_b64.to_string(),
                    device_label: device_label.map(str::to_string),
                },
            )
            .await?;
        raw.try_into()
    }

    /// `GET /me/devices/grants[?status=]`.
    pub async fn list_device_grants(
        &self,
        status: Option<&str>,
    ) -> Result<Vec<DeviceGrant>, SdkError> {
        let raw: Vec<crate::generated::DeviceGrantResponse> = match status {
            Some(status) => {
                self.get_query(
                    crate::generated::paths::devices::LIST_DEVICE_GRANTS,
                    &[("status", status)],
                )
                .await?
            }
            None => {
                self.get(crate::generated::paths::devices::LIST_DEVICE_GRANTS)
                    .await?
            }
        };
        raw.into_iter().map(DeviceGrant::try_from).collect()
    }

    /// `GET /me/devices/grants/{id}`.
    pub async fn get_device_grant(&self, grant_id: Uuid) -> Result<DeviceGrant, SdkError> {
        let raw: crate::generated::DeviceGrantResponse = self
            .get(&super::path(
                crate::generated::paths::devices::GET_DEVICE_GRANT,
                &[("id", &grant_id.to_string())],
            ))
            .await?;
        raw.try_into()
    }

    /// `POST /me/devices/grants/{id}/approve`, signed at the identity chain's next position. The
    /// requested key must be an acceptable Ed25519 key; the new device's key id is the grant id.
    pub async fn approve_device_grant(
        &self,
        grant_id: Uuid,
        requested_signing_public_key_b64: &str,
    ) -> Result<Device, SdkError> {
        let approver = self.signing_key_id().ok_or_else(|| {
            SdkError::Protocol(
                "approve_device_grant requires a local signing key — this AccountSession has none"
                    .to_string(),
            )
        })?;
        let requested_key = decode_public_key(requested_signing_public_key_b64)?;
        let acceptable = ed25519_dalek::VerifyingKey::from_bytes(&requested_key)
            .map(|key| crate::identity_signing::is_acceptable_ed25519_key(&key))
            .unwrap_or(false);
        if !acceptable {
            return Err(SdkError::Protocol(
                "the requested key is not an acceptable Ed25519 key".to_string(),
            ));
        }
        let identity_id = self.identity().id.clone();
        let response = self
            .post_chain_event(
                &super::path(
                    crate::generated::paths::devices::APPROVE_DEVICE_GRANT,
                    &[("id", &grant_id.to_string())],
                ),
                |position| crate::generated::ApproveDeviceGrantRequest {
                    approver_signing_key_id: approver,
                    seq: position.seq_wire(),
                    prev_hash: position.prev_hash_hex(),
                    signature: self.sign_raw(
                        &crate::identity_signing::device_grant_approval_signing_bytes(
                            grant_id,
                            &identity_id,
                            approver,
                            &requested_key,
                            position.seq,
                            position.prev_hash.as_ref(),
                        ),
                    ),
                },
            )
            .await?;
        let device: crate::generated::DeviceResponse = response
            .json()
            .await
            .map_err(|e| SdkError::Protocol(e.to_string()))?;
        device.try_into()
    }

    /// `POST /auth/device/approve` (issue #307/#704) — approves a
    /// cross-device pairing request identified by `user_code`, always
    /// signed (`device_pairing.approve`, `[identity_id, user_code]`).
    pub async fn approve_device_pairing(&self, user_code: &str) -> Result<String, SdkError> {
        let signature = self.sign(
            "device_pairing.approve",
            &[&self.identity().id.to_string(), user_code],
        );
        let response: crate::generated::ResolvePairingResponse = self
            .post(
                crate::generated::paths::devices::APPROVE_PAIRING,
                &crate::generated::ApprovePairingRequest {
                    user_code: user_code.to_string(),
                    signature: signature.signature,
                    signing_key_id: signature.signing_key_id,
                },
            )
            .await?;
        Ok(response.status)
    }

    /// `POST /auth/device/deny` — declines a pairing request. Not
    /// signature-required (no state is granted).
    pub async fn deny_device_pairing(&self, user_code: &str) -> Result<String, SdkError> {
        let response: crate::generated::ResolvePairingResponse = self
            .post(
                crate::generated::paths::devices::DENY_PAIRING,
                &crate::generated::UserCodeRequest {
                    user_code: user_code.to_string(),
                },
            )
            .await?;
        Ok(response.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_public_key_is_strict() {
        let good = "A".repeat(43) + "=";
        assert!(decode_public_key(&good).is_ok());
        // Non-canonical trailing bits, embedded whitespace, wrong length and unpadded text.
        assert!(decode_public_key(&("A".repeat(42) + "B=")).is_err());
        assert!(decode_public_key(&format!("AAAA\n{}", "A".repeat(39) + "=")).is_err());
        assert!(decode_public_key("AAAA").is_err());
        assert!(decode_public_key(&"A".repeat(43)).is_err());
    }
}
