// The caller's own login sessions on AccountSession: list them, end one, or end the one in use.

using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace Avalon.Sdk
{
    /// <summary>One of this identity's live sessions.</summary>
    public sealed class AccountSessionSummary
    {
        /// <summary>The session's id; pass to <see cref="AccountSession.RevokeSessionAsync"/>.</summary>
        [JsonPropertyName("id")]
        public Guid Id { get; set; }

        [JsonPropertyName("created_at")]
        public DateTimeOffset CreatedAt { get; set; }

        [JsonPropertyName("expires_at")]
        public DateTimeOffset ExpiresAt { get; set; }

        /// <summary>Whether this is the session the listing request authenticated with.</summary>
        [JsonPropertyName("current")]
        public bool Current { get; set; }

        /// <summary>The passkey that produced this session, when it came from a passkey login.</summary>
        [JsonPropertyName("origin_passkey_id")]
        public Guid? OriginPasskeyId { get; set; }

        /// <summary>The signing key that approved this session, when it came from device pairing
        /// or a cross-node login.</summary>
        [JsonPropertyName("origin_signing_key_id")]
        public Guid? OriginSigningKeyId { get; set; }
    }

    public sealed partial class AccountSession
    {
        /// <summary><c>GET /me/sessions</c> — this identity's live sessions, newest first; the
        /// one this request used has <c>Current</c> set.</summary>
        public async Task<IReadOnlyList<AccountSessionSummary>> ListSessionsAsync(CancellationToken ct = default)
        {
            var response = await GetAsync<Avalon.Sdk.Generated.ListSessionsResponse>("/me/sessions", ct).ConfigureAwait(false);
            var sessions = new List<AccountSessionSummary>();
            foreach (var s in response.Sessions)
            {
                sessions.Add(new AccountSessionSummary
                {
                    Id = s.Id,
                    CreatedAt = s.CreatedAt,
                    ExpiresAt = s.ExpiresAt,
                    Current = s.Current,
                    OriginPasskeyId = s.OriginPasskeyId,
                    OriginSigningKeyId = s.OriginSigningKeyId,
                });
            }
            return sessions;
        }

        /// <summary><c>POST /me/sessions/{id}/revoke</c> — ends one of this identity's own
        /// sessions. Any other session id is refused with a 404 (<c>SESSION_NOT_FOUND</c>).</summary>
        public async Task RevokeSessionAsync(Guid sessionId, CancellationToken ct = default) =>
            await PostEmptyNoResponseAsync($"/me/sessions/{sessionId}/revoke", ct).ConfigureAwait(false);

        /// <summary><c>POST /sessions/logout</c> — ends the session this
        /// <see cref="AccountSession"/> authenticates with; the token is unusable afterwards.</summary>
        public async Task LogoutAsync(CancellationToken ct = default) =>
            await PostEmptyNoResponseAsync("/sessions/logout", ct).ConfigureAwait(false);
    }
}
