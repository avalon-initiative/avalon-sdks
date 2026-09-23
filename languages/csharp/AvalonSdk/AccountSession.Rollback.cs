using System;
using System.Threading;
using System.Threading.Tasks;

namespace Avalon.Sdk
{
    public sealed partial class AccountSession
    {
        /// <summary><c>GET /me/rollback/candidates?since=</c> — events this identity authored in
        /// <c>[since, latest completed recovery)</c> that a rollback could touch, each marked
        /// reversible or not. <paramref name="since"/> is an RFC 3339 timestamp, sent as given.
        /// Failures surface as <see cref="AvalonRequestException"/> carrying the HTTP status
        /// (409 when no recovery has completed, 400 for an invalid window).</summary>
        public async Task<Avalon.Sdk.Generated.RollbackCandidatesResponse> GetRollbackCandidatesAsync(string since, CancellationToken ct = default) =>
            await GetQueryAsync<Avalon.Sdk.Generated.RollbackCandidatesResponse>(
                "/me/rollback/candidates",
                new[] { ("since", since) },
                ct).ConfigureAwait(false);

        /// <summary><c>POST /me/rollback/{event_id}/reverse</c> — appends a signed compensating
        /// event reversing <paramref name="eventId"/> and returns the reversal event's id.
        /// Signs <c>rollback.reverse</c> over <c>[event_id, identity_id, since]</c>;
        /// <paramref name="since"/> must be the exact string passed to
        /// <see cref="GetRollbackCandidatesAsync"/>. Failures surface as
        /// <see cref="AvalonRequestException"/> carrying the HTTP status (404 not eligible,
        /// 409 not reversible or already reversed, 400 invalid window).</summary>
        public async Task<Guid> ReverseRollbackEventAsync(Guid eventId, string since, CancellationToken ct = default)
        {
            var (signingKeyId, signature) = Sign(
                "rollback.reverse", eventId.ToString(), IdentityGuid.ToString(), since);
            var response = await PostAsync<Avalon.Sdk.Generated.ReverseEventRequest, Avalon.Sdk.Generated.ReverseEventResponse>(
                $"/me/rollback/{eventId}/reverse",
                new Avalon.Sdk.Generated.ReverseEventRequest
                {
                    Since = since,
                    SigningKeyId = signingKeyId,
                    Signature = signature,
                },
                ct).ConfigureAwait(false);
            return response.ReversalEventId;
        }
    }
}
