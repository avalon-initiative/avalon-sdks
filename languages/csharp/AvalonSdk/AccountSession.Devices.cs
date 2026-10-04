// Device-registration / linked-device grant model and cross-device pairing
// approval on AccountSession — identity_signing_keys rows (event-authorship
// keys), distinct from AccountSession.Passkeys.cs (WebAuthn login credentials). Mirrors
// crates/sdk/src/account/devices.rs. No WebAuthn ceremony involved anywhere in this file, so
// every method here is fully ported.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace Avalon.Sdk
{
    /// <summary>One of this identity's registered signing-key devices. Mirrors the Rust
    /// SDK's <c>account::devices::Device</c>.</summary>
    public sealed class AccountDevice
    {
        /// <summary>The <c>identity_signing_keys.id</c> this device is stored under — the
        /// value a signature-required action's <c>signing_key_id</c> field names.</summary>
        [JsonPropertyName("id")]
        public Guid Id { get; set; }

        [JsonPropertyName("label")]
        public string? Label { get; set; }

        /// <summary>Base64-encoded raw Ed25519 public key.</summary>
        [JsonPropertyName("public_key")]
        public string PublicKey { get; set; } = "";

        [JsonPropertyName("added_at")]
        public DateTimeOffset AddedAt { get; set; }

        /// <summary><c>null</c> while active; set once revoked.</summary>
        [JsonPropertyName("revoked_at")]
        public DateTimeOffset? RevokedAt { get; set; }
    }

    /// <summary>A pending or resolved request to add a new device's signing key —
    /// <c>POST /me/devices/grants</c>. Mirrors the Rust SDK's
    /// <c>account::devices::DeviceGrant</c>.</summary>
    public sealed class AccountDeviceGrant
    {
        [JsonPropertyName("id")]
        public Guid Id { get; set; }

        /// <summary>"pending", "approved", "denied", or "expired" —
        /// <c>crates/server/src/devices.rs</c>'s own stable vocabulary, not re-modeled as an
        /// enum here.</summary>
        [JsonPropertyName("status")]
        public string Status { get; set; } = "";

        [JsonPropertyName("device_label")]
        public string? DeviceLabel { get; set; }

        /// <summary>Base64-encoded — the exact bytes an approving device must include in
        /// what it signs (see <see cref="AccountSession.ApproveDeviceGrantAsync"/>).</summary>
        [JsonPropertyName("requested_signing_public_key")]
        public string RequestedSigningPublicKey { get; set; } = "";

        [JsonPropertyName("requested_at")]
        public DateTimeOffset RequestedAt { get; set; }

        [JsonPropertyName("expires_at")]
        public DateTimeOffset ExpiresAt { get; set; }
    }

    public sealed partial class AccountSession
    {
        /// <summary><c>GET /me/devices</c> — every signing-key device registered to this
        /// identity, active and revoked alike.</summary>
        public async Task<IReadOnlyList<AccountDevice>> ListDevicesAsync(CancellationToken ct = default) =>
            await GetAsync<List<AccountDevice>>("/me/devices", ct).ConfigureAwait(false);

        /// <summary><c>PATCH /me/devices/{signing_key_id}</c> — relabels a device. Not
        /// signature-required.</summary>
        public async Task<AccountDevice> RenameDeviceAsync(Guid signingKeyId, string label, CancellationToken ct = default) =>
            await PatchAsync<Avalon.Sdk.Generated.RenameDeviceRequest, AccountDevice>(
                $"/me/devices/{signingKeyId}", new Avalon.Sdk.Generated.RenameDeviceRequest { Label = label }, ct).ConfigureAwait(false);

        /// <summary><c>POST /me/devices/{signing_key_id}/revoke</c> — signed by this
        /// session's own local key (which may be the key being revoked); the server refuses to
        /// revoke the last active key. Throws <see cref="InvalidOperationException"/>, without
        /// making any HTTP call, if this session has no local signing key.</summary>
        public async Task RevokeDeviceAsync(Guid signingKeyId, CancellationToken ct = default)
        {
            if (SigningKeyId == null)
            {
                throw new InvalidOperationException("RevokeDeviceAsync requires a local signing key — this AccountSession has none");
            }
            var revokedBy = SigningKeyId.Value;
            var message = IdentitySigning.SigningKeyRevokedSigningBytesV2(OwnIdentityId, signingKeyId, revokedBy);
            await PostNoResponseAsync(
                $"/me/devices/{signingKeyId}/revoke",
                new Avalon.Sdk.Generated.RevokeDeviceRequest { RevokedBySigningKeyId = revokedBy, Signature = SignRaw(message) },
                ct).ConfigureAwait(false);
        }

        /// <summary>Strictly decodes a standard-base64 32-byte Ed25519 public key.</summary>
        private static byte[] DecodePublicKey(string publicKeyB64)
        {
            try
            {
                var bytes = Convert.FromBase64String(publicKeyB64);
                if (bytes.Length == 32 && string.Equals(Convert.ToBase64String(bytes), publicKeyB64, StringComparison.Ordinal))
                {
                    return bytes;
                }
            }
            catch (FormatException)
            {
            }
            throw new ArgumentException("public key must be standard base64 of exactly 32 bytes", nameof(publicKeyB64));
        }

        /// <summary><c>POST /me/devices/grants</c> — requests a new device's signing key be
        /// added, from the *requesting* device's own session (which has no signing key of
        /// its own yet — that's the whole point). Requesting confers no access by itself;
        /// see <see cref="ApproveDeviceGrantAsync"/>.</summary>
        public async Task<AccountDeviceGrant> RequestDeviceGrantAsync(string requestedSigningPublicKeyB64, string? deviceLabel = null, CancellationToken ct = default) =>
            await PostAsync<Avalon.Sdk.Generated.RequestDeviceGrantRequest, AccountDeviceGrant>(
                "/me/devices/grants",
                new Avalon.Sdk.Generated.RequestDeviceGrantRequest { RequestedSigningPublicKey = requestedSigningPublicKeyB64, DeviceLabel = deviceLabel },
                ct).ConfigureAwait(false);

        /// <summary><c>GET /me/devices/grants[?status=]</c>.</summary>
        public async Task<IReadOnlyList<AccountDeviceGrant>> ListDeviceGrantsAsync(string? status = null, CancellationToken ct = default) =>
            status is null
                ? await GetAsync<List<AccountDeviceGrant>>("/me/devices/grants", ct).ConfigureAwait(false)
                : await GetQueryAsync<List<AccountDeviceGrant>>("/me/devices/grants", new[] { ("status", status) }, ct).ConfigureAwait(false);

        /// <summary><c>GET /me/devices/grants/{id}</c>.</summary>
        public async Task<AccountDeviceGrant> GetDeviceGrantAsync(Guid grantId, CancellationToken ct = default) =>
            await GetAsync<AccountDeviceGrant>($"/me/devices/grants/{grantId}", ct).ConfigureAwait(false);

        /// <summary><c>POST /me/devices/grants/{id}/approve</c> — approves someone else's
        /// (or this identity's own, from a different device's) pending grant, signed with
        /// this session's own local key over
        /// <c>device_grant_approval_signing_bytes(grant_id, identity_id,
        /// requested_signing_public_key)</c> — proving the approval came from a device that
        /// once passed a real WebAuthn ceremony. Throws <see cref="InvalidOperationException"/>,
        /// without making any HTTP call, if this session has no local signing key at all
        /// (see <see cref="AccountSession.SigningKeyId"/>).</summary>
        public async Task<AccountDevice> ApproveDeviceGrantAsync(Guid grantId, string requestedSigningPublicKeyB64, CancellationToken ct = default)
        {
            if (SigningKeyId == null)
            {
                throw new InvalidOperationException("ApproveDeviceGrantAsync requires a local signing key — this AccountSession has none");
            }
            var signingKeyId = SigningKeyId.Value;
            var requestedKey = DecodePublicKey(requestedSigningPublicKeyB64);
            if (!IdentitySigning.IsAcceptableKey(requestedKey))
            {
                throw new ArgumentException("the requested key is not an acceptable Ed25519 key", nameof(requestedSigningPublicKeyB64));
            }
            var message = IdentitySigning.DeviceGrantApprovalSigningBytesV2(grantId, OwnIdentityId, requestedKey);
            var signature = SignRaw(message);
            return await PostAsync<Avalon.Sdk.Generated.ApproveDeviceGrantRequest, AccountDevice>(
                $"/me/devices/grants/{grantId}/approve",
                new Avalon.Sdk.Generated.ApproveDeviceGrantRequest { ApproverSigningKeyId = signingKeyId, Signature = signature },
                ct).ConfigureAwait(false);
        }

        /// <summary><c>POST /auth/device/approve</c> — approves a
        /// cross-device pairing request identified by <paramref name="userCode"/>, always
        /// signed (<c>device_pairing.approve</c>, <c>[identity_id, user_code]</c>).</summary>
        public async Task<string> ApproveDevicePairingAsync(string userCode, CancellationToken ct = default)
        {
            var (signingKeyId, signature) = Sign("device_pairing.approve", OwnIdentityId.ToString(), userCode);
            var response = await PostAsync<Avalon.Sdk.Generated.ApprovePairingRequest, Avalon.Sdk.Generated.ResolvePairingResponse>(
                "/auth/device/approve",
                new Avalon.Sdk.Generated.ApprovePairingRequest { UserCode = userCode, SigningKeyId = signingKeyId, Signature = signature },
                ct).ConfigureAwait(false);
            return response.Status;
        }

        /// <summary><c>POST /auth/device/deny</c> — declines a pairing request. Not
        /// signature-required (no state is granted).</summary>
        public async Task<string> DenyDevicePairingAsync(string userCode, CancellationToken ct = default)
        {
            var response = await PostAsync<Avalon.Sdk.Generated.UserCodeRequest, Avalon.Sdk.Generated.ResolvePairingResponse>(
                "/auth/device/deny", new Avalon.Sdk.Generated.UserCodeRequest { UserCode = userCode }, ct).ConfigureAwait(false);
            return response.Status;
        }
    }
}
